import { app, shell } from 'electron';
import { spawn } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import {
  UpdateActionResult,
  UpdateDeliveryMode,
  UpdateStateSnapshot,
  UpdateStatus,
} from '../src/shared/types';
import {
  BUILTIN_UPDATE_PUBLIC_KEY_SPKI_B64,
  compareSemver,
  DEFAULT_GITHUB_MIRROR_PREFIXES,
  DEFAULT_GITHUB_RELEASE_LATEST_JSON_URL,
  DEFAULT_GITHUB_RELEASES_PAGE_URL,
  normalizeSemverString,
  UpdateReleaseManifest,
  validateUpdateManifestStructure,
} from '../src/shared/updateManifest';
import { ConfigStore } from './configStore';
import { downloadFileViaProxy, requestTextViaProxy } from './netClient';
import { ProbeEngine } from './probeEngine';
import {
  computeFileSha256,
  getRawFs,
  validateAsarArchiveHeader,
  verifyUpdateManifestSignature,
} from './updateCrypto';

const rawFs = getRawFs();

const DEFAULT_STARTUP_CHECK_DELAY_MS = 4000;
const DEFAULT_STARTUP_RETRY_DELAY_MS = 20000;
const DEFAULT_WINDOW_SHOW_COOLDOWN_MS = 30 * 60 * 1000; // 唤起窗口按需检查 30 分钟冷却
const DEFAULT_ERROR_RETRY_COOLDOWN_MS = 2 * 60 * 1000;  // 失败态唤起窗口 2 分钟冷却重试
const MANIFEST_FETCH_TIMEOUT_MS = 12000;
const ASAR_DOWNLOAD_TIMEOUT_MS = 180000;
const FULL_ZIP_DOWNLOAD_TIMEOUT_MS = 15 * 60 * 1000;
const POST_UPDATE_BAK_CLEANUP_DELAY_MS = 15000;
const DEFAULT_BOOT_HANDSHAKE_TIMEOUT_MS = 12000;

interface StagedReadyMetadata {
  version: string;
  deliveryMode: UpdateDeliveryMode;
  includeMmdbUpdate: boolean;
  asarSha256?: string;
  mmdbSha256?: string;
  zipSha256?: string;
  verifiedAt: number;
}

export interface UpdaterServiceOptions {
  configStore: ConfigStore;
  probeEngine: ProbeEngine;
  onQuitForUpdate?: () => void;
  manifestUrlOverride?: string;
  releasePageUrlOverride?: string;
  publicKeyOverride?: string;
  isPackagedOverride?: boolean;
  currentVersionOverride?: string;
  electronVersionOverride?: string;
  nativeShellVersionOverride?: string;
  appDirOverride?: string;
  resourcesDirOverride?: string;
  exePathOverride?: string;
  stagingRootDirOverride?: string;
  allowLocalhostForTest?: boolean;
  targetPidOverride?: number;
  bootHandshakeTimeoutMsOverride?: number;
  waitExitAttemptsOverride?: number;
  startupCheckDelayMsOverride?: number;
  startupRetryDelayMsOverride?: number;
  windowShowCooldownMsOverride?: number;
  errorRetryCooldownMsOverride?: number;
}

export function resolveWindowsPowerShellExe(): string {
  const sysRoot = process.env.SystemRoot || process.env.WINDIR;
  if (sysRoot) {
    const candidate = path.join(
      sysRoot,
      'System32',
      'WindowsPowerShell',
      'v1.0',
      'powershell.exe'
    );
    if (rawFs.existsSync(candidate)) {
      return candidate;
    }
  }
  return 'powershell.exe';
}

export function quoteWindowsArg(value: string): string {
  if (value.length === 0) return '""';
  if (!/[\s"]/.test(value)) return value;
  const escaped = value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/g, '$1$1');
  return `"${escaped}"`;
}

export function quoteWindowsCommandLine(args: readonly string[]): string {
  return args.map(quoteWindowsArg).join(' ');
}

function buildDetachedTrampolineEncodedCommand(): string {
  // 注意：
  // 1) Windows 下直接对 powershell.exe 传 detached: true (DETACHED_PROCESS) 会使其因无控制台宿主立即静默退出 0；
  // 2) 通过短生命周期跳板以 ProcessStartInfo { UseShellExecute = true, WindowStyle = Hidden } 拉起内层 PowerShell：
  //    - ShellExecuteEx 在底层以 bInheritHandles = FALSE 创建新进程，彻底隔绝主进程打开的 asar/pak/dll/pipe 句柄继承锁死；
  //    - 规避 Start-Process -WorkingDirectory 对含 [ ] 方括号路径的通配符解析异常；
  //    - 同时为内层分配独立隐藏控制台并切断与旧主进程的父子链，防止兜底 taskkill /T 误杀更新器自身。
  const trampoline = [
    '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
    '$ProgressPreference = "SilentlyContinue"',
    '$ErrorActionPreference = "Stop"',
    '$psExe = Join-Path $PSHome "powershell.exe"',
    'if (-not (Test-Path -LiteralPath $psExe)) { $psExe = "powershell.exe" }',
    '$safeWorkDir = if ($env:SystemRoot -and (Test-Path -LiteralPath $env:SystemRoot)) { $env:SystemRoot } else { [System.IO.Path]::GetTempPath() }',
    '$psi = New-Object System.Diagnostics.ProcessStartInfo',
    '$psi.FileName = $psExe',
    '$psi.WorkingDirectory = $safeWorkDir',
    '$psi.Arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand " + $env:GUARD_UPD_INNER_ENC',
    '$psi.UseShellExecute = $true',
    '$psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden',
    '[System.Diagnostics.Process]::Start($psi) | Out-Null',
  ].join('\r\n');
  return Buffer.from(trampoline, 'utf16le').toString('base64');
}

async function launchDetachedWindowsUpdater(
  encodedInnerCommand: string,
  updaterEnv: Record<string, string>
): Promise<void> {
  const psExe = resolveWindowsPowerShellExe();
  const trampolineEncoded = buildDetachedTrampolineEncodedCommand();
  const safeCwd =
    process.env.SystemRoot && rawFs.existsSync(process.env.SystemRoot)
      ? process.env.SystemRoot
      : os.tmpdir();

  await new Promise<void>((resolve, reject) => {
    const child = spawn(
      psExe,
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', trampolineEncoded],
      {
        cwd: safeCwd,
        detached: false,
        stdio: ['ignore', 'ignore', 'pipe'],
        windowsHide: true,
        env: {
          ...process.env,
          ...updaterEnv,
          GUARD_UPD_INNER_ENC: encodedInnerCommand,
        },
      }
    );

    let stderrText = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        child.kill();
      } catch {
        // ignore
      }
      child.stderr?.destroy();
      reject(new Error('拉起后台更新器超时'));
    }, 10000);
    timer.unref?.();

    child.stderr?.on('data', (chunk: Buffer | string) => {
      if (stderrText.length < 2048) {
        stderrText += chunk.toString('utf-8');
      }
    });

    child.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.stderr?.destroy();
      reject(err);
    });

    child.once('exit', (code) => {
      if (settled) return;
      if (code === 0) {
        settled = true;
        clearTimeout(timer);
        child.stderr?.destroy();
        resolve();
        return;
      }
      const finalizeNonZero = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        clearTimeout(drainTimer);
        child.stderr?.destroy();
        const detail =
          stderrText.trim() || `更新跳板进程异常退出 (代码 ${String(code)})`;
        reject(new Error(detail));
      };
      const drainTimer = setTimeout(finalizeNonZero, 250);
      drainTimer.unref?.();
      if (!child.stderr || child.stderr.readableEnded || child.stderr.destroyed) {
        finalizeNonZero();
      } else {
        child.stderr.once('end', finalizeNonZero);
        child.stderr.once('close', finalizeNonZero);
      }
    });
  });
}

export function buildEncodedPowerShellLaunch(
  script: string = buildWindowsUpdatePowerShellScript()
): { encodedCommand: string; scriptGzB64: string } {
  const scriptGzB64 = zlib
    .gzipSync(Buffer.from(script, 'utf-8'), { level: 9 })
    .toString('base64');
  const bootstrap = [
    '$ProgressPreference="SilentlyContinue"',
    '$b=[Convert]::FromBase64String($env:GUARD_UPD_SCRIPT_GZ)',
    '$m=New-Object System.IO.MemoryStream(,$b)',
    '$g=New-Object System.IO.Compression.GZipStream($m,[System.IO.Compression.CompressionMode]::Decompress)',
    '$r=New-Object System.IO.StreamReader($g,[System.Text.Encoding]::UTF8)',
    '$code=$r.ReadToEnd()',
    '$r.Dispose();$g.Dispose();$m.Dispose()',
    '& ([scriptblock]::Create($code))',
  ].join(';');
  return {
    encodedCommand: Buffer.from(bootstrap, 'utf16le').toString('base64'),
    scriptGzB64,
  };
}

export function buildWindowsUpdatePowerShellScript(): string {
  return [
    '$ErrorActionPreference = "Stop"',
    '$targetPid = [int]$env:GUARD_UPD_PID',
    '$mode = $env:GUARD_UPD_MODE',
    '$appDir = $env:GUARD_UPD_APP_DIR',
    '$resDir = $env:GUARD_UPD_RES_DIR',
    '$exePath = $env:GUARD_UPD_EXE_PATH',
    '$fromVer = $env:GUARD_UPD_FROM_VER',
    '$toVer = $env:GUARD_UPD_TO_VER',
    '$stagedAsar = $env:GUARD_UPD_STAGED_ASAR',
    '$stagedMmdb = $env:GUARD_UPD_STAGED_MMDB',
    '$stagedZip = $env:GUARD_UPD_STAGED_ZIP',
    '$expectedAsarSha = $env:GUARD_UPD_ASAR_SHA256',
    '$expectedMmdbSha = $env:GUARD_UPD_MMDB_SHA256',
    '$expectedZipSha = $env:GUARD_UPD_ZIP_SHA256',
    '$stageDir = $env:GUARD_UPD_STAGE_DIR',
    '$readyFile = $env:GUARD_UPD_READY_FILE',
    '$skipRelaunch = $env:GUARD_UPD_SKIP_RELAUNCH -eq "1"',
    '$defaultBootMs = if ($readyFile) { 12000 } else { 2200 }',
    '$bootCheckMs = if ($env:GUARD_UPD_BOOT_CHECK_MS) { [int]$env:GUARD_UPD_BOOT_CHECK_MS } else { $defaultBootMs }',
    '$waitExitAttempts = if ($env:GUARD_UPD_WAIT_EXIT_ATTEMPTS) { [int]$env:GUARD_UPD_WAIT_EXIT_ATTEMPTS } else { 48 }',
    '',
    'function Quote-WinArg([string]$Value) {',
    '  if ([string]::IsNullOrEmpty($Value)) { return \'""\' }',
    '  if ($Value -notmatch \'[\\s"]\') { return $Value }',
    '  $escaped = [regex]::Replace($Value, \'(\\\\*)"\', \'$1$1\\"\')',
    '  $escaped = [regex]::Replace($escaped, \'(\\\\+)$\', \'$1$1\')',
    '  return \'"\' + $escaped + \'"\'',
    '}',
    '',
    'function Invoke-SafeTaskkill([int]$ProcId) {',
    '  if ($ProcId -le 0) { return }',
    '  try {',
    '    & cmd.exe /d /c "taskkill.exe /F /T /PID $ProcId >nul 2>&1"',
    '  } catch {}',
    '}',
    '',
    'function Start-GuardProcess([string]$FilePath, [string]$WorkDir, [string[]]$RawArgs, [switch]$PassThru) {',
    '  $psi = New-Object System.Diagnostics.ProcessStartInfo',
    '  $psi.FileName = $FilePath',
    '  if ($WorkDir) { $psi.WorkingDirectory = $WorkDir }',
    '  $psi.UseShellExecute = $true',
    '  if ($RawArgs -and $RawArgs.Count -gt 0) {',
    '    $psi.Arguments = @($RawArgs | ForEach-Object { Quote-WinArg $_ }) -join " "',
    '  }',
    '  try {',
    '    $started = [System.Diagnostics.Process]::Start($psi)',
    '    if ($PassThru) { return $started }',
    '    return $null',
    '  } catch {',
    '    $needsRunAs = $false',
    '    $curEx = $_.Exception',
    '    while ($curEx) {',
    '      if ($curEx -is [System.ComponentModel.Win32Exception] -and $curEx.NativeErrorCode -eq 740) {',
    '        $needsRunAs = $true',
    '        break',
    '      }',
    '      $curEx = $curEx.InnerException',
    '    }',
    '    if ($needsRunAs) {',
    '      $psi.Verb = "runas"',
    '      $started = [System.Diagnostics.Process]::Start($psi)',
    '      if ($PassThru) { return $started }',
    '      return $null',
    '    }',
    '    throw',
    '  }',
    '}',
    '',
    'function Invoke-WithRetry([scriptblock]$Action, [int]$MaxAttempts = 12, [int]$DelayMs = 350) {',
    '  $lastErr = $null',
    '  for ($a = 1; $a -le $MaxAttempts; $a++) {',
    '    try {',
    '      & $Action',
    '      return',
    '    } catch {',
    '      $lastErr = $_',
    '      if ($a -lt $MaxAttempts) { Start-Sleep -Milliseconds $DelayMs }',
    '    }',
    '  }',
    '  throw $lastErr',
    '}',
    '',
    'function Verify-StreamSha256([System.IO.Stream]$Stream, [string]$ExpectedSha, [string]$Label) {',
    '  if (-not $ExpectedSha) { return }',
    '  $Stream.Position = 0',
    '  $sha = [System.Security.Cryptography.SHA256]::Create()',
    '  try {',
    '    $hashBytes = $sha.ComputeHash($Stream)',
    '    $actual = ([System.BitConverter]::ToString($hashBytes)).Replace("-", "").ToLowerInvariant()',
    '  } finally {',
    '    $sha.Dispose()',
    '  }',
    '  if ($actual -ne $ExpectedSha.ToLowerInvariant()) {',
    '    throw "待应用更新文件 SHA-256 校验失败 ($Label)"',
    '  }',
    '  $Stream.Position = 0',
    '}',
    '',
    'function Copy-LockedVerifiedFile([string]$SrcPath, [string]$DestPath, [string]$ExpectedSha, [string]$Label) {',
    '  if (-not (Test-Path -LiteralPath $SrcPath)) {',
    '    throw "缺少待应用更新文件 ($Label): $SrcPath"',
    '  }',
    '  $inStream = [System.IO.File]::Open($SrcPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)',
    '  try {',
    '    Verify-StreamSha256 $inStream $ExpectedSha $Label',
    '    $parent = Split-Path -Parent $DestPath',
    '    if ($parent -and -not (Test-Path -LiteralPath $parent)) {',
    '      [System.IO.Directory]::CreateDirectory($parent) | Out-Null',
    '    }',
    '    Invoke-WithRetry {',
    '      if (Test-Path -LiteralPath $DestPath) {',
    '        $it = Get-Item -LiteralPath $DestPath -Force -ErrorAction SilentlyContinue',
    '        if ($it -and $it.IsReadOnly) { $it.IsReadOnly = $false }',
    '      }',
    '      $inStream.Position = 0',
    '      $outStream = [System.IO.File]::Open($DestPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)',
    '      try {',
    '        $inStream.CopyTo($outStream)',
    '        $outStream.Flush($true)',
    '      } finally {',
    '        $outStream.Dispose()',
    '      }',
    '    }',
    '  } finally {',
    '    $inStream.Dispose()',
    '  }',
    '}',
    '',
    'if ($targetPid -gt 0) {',
    '  for ($i = 0; $i -lt $waitExitAttempts; $i++) {',
    '    $p = Get-Process -Id $targetPid -ErrorAction SilentlyContinue',
    '    if (-not $p) { break }',
    '    Start-Sleep -Milliseconds 250',
    '  }',
    '  $still = Get-Process -Id $targetPid -ErrorAction SilentlyContinue',
    '  if ($still) {',
    '    $myParentId = 0',
    '    try {',
    '      $selfProc = Get-CimInstance Win32_Process -Filter "ProcessId = $PID" -ErrorAction SilentlyContinue',
    '      if ($selfProc) { $myParentId = [int]$selfProc.ParentProcessId }',
    '    } catch {}',
    '    if ($myParentId -eq $targetPid -or $PID -eq $targetPid) {',
    '      Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue',
    '    } else {',
    '      Invoke-SafeTaskkill $targetPid',
    '      Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue',
    '    }',
    '    Start-Sleep -Milliseconds 600',
    '  }',
    '}',
    'Start-Sleep -Milliseconds 250',
    '',
    '$asarTarget = Join-Path $resDir "app.asar"',
    '$asarBak = Join-Path $resDir "app.asar.bak"',
    '$mmdbTarget = Join-Path $resDir "geolite2-country.mmdb"',
    '$mmdbBak = Join-Path $resDir "geolite2-country.mmdb.bak"',
    '$exeBak = "$exePath.bak"',
    '$extractDir = Join-Path $stageDir "_extract_full"',
    '$backupDir = Join-Path $stageDir "_backup_app"',
    '$script:hasFullDirBackup = $false',
    '$script:createdRelFiles = New-Object "System.Collections.Generic.List[string]"',
    '$script:createdRelDirs = New-Object "System.Collections.Generic.List[string]"',
    '',
    'function Cleanup-ExtractArtifact {',
    '  if ($extractDir -and (Test-Path -LiteralPath $extractDir)) {',
    '    Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue',
    '  }',
    '}',
    '',
    'function Cleanup-ReadyFile {',
    '  if ($readyFile -and (Test-Path -LiteralPath $readyFile)) {',
    '    Remove-Item -LiteralPath $readyFile -Force -ErrorAction SilentlyContinue',
    '  }',
    '}',
    '',
    'function Resolve-FullDir([string]$DirPath) {',
    '  if ($DirPath -and (Test-Path -LiteralPath $DirPath)) {',
    '    return (Get-Item -LiteralPath $DirPath -Force).FullName.TrimEnd("\\")',
    '  }',
    '  return [System.IO.Path]::GetFullPath($DirPath).TrimEnd("\\")',
    '}',
    '',
    'function Restore-UpdateBackup {',
    '  $allRestored = $true',
    '  try {',
    '    if ($mode -eq "full-zip" -and $script:hasFullDirBackup -and (Test-Path -LiteralPath $backupDir)) {',
    '      foreach ($addedRel in $script:createdRelFiles) {',
    '        $addedFull = Join-Path $appDir $addedRel',
    '        if (Test-Path -LiteralPath $addedFull) {',
    '          Invoke-WithRetry { Remove-Item -LiteralPath $addedFull -Force }',
    '        }',
    '      }',
    '      $bakNorm = Resolve-FullDir $backupDir',
    '      $bakFiles = @(Get-ChildItem -LiteralPath $bakNorm -Recurse -Force -File)',
    '      foreach ($bf in $bakFiles) {',
    '        $rel = $bf.FullName.Substring($bakNorm.Length + 1)',
    '        $origDest = Join-Path $appDir $rel',
    '        $origParent = Split-Path -Parent $origDest',
    '        if ($origParent -and -not (Test-Path -LiteralPath $origParent)) {',
    '          [System.IO.Directory]::CreateDirectory($origParent) | Out-Null',
    '        }',
    '        Invoke-WithRetry { Copy-Item -LiteralPath $bf.FullName -Destination $origDest -Force }',
    '      }',
    '      for ($idx = $script:createdRelDirs.Count - 1; $idx -ge 0; $idx--) {',
    '        $dirFull = Join-Path $appDir $script:createdRelDirs[$idx]',
    '        if (Test-Path -LiteralPath $dirFull) {',
    '          $rem = @(Get-ChildItem -LiteralPath $dirFull -Force -ErrorAction SilentlyContinue)',
    '          if ($rem.Count -eq 0) {',
    '            Remove-Item -LiteralPath $dirFull -Force -ErrorAction SilentlyContinue',
    '          }',
    '        }',
    '      }',
    '      Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue',
    '    } else {',
    '      if (Test-Path -LiteralPath $asarBak) {',
    '        Invoke-WithRetry { Copy-Item -LiteralPath $asarBak -Destination $asarTarget -Force }',
    '        Remove-Item -LiteralPath $asarBak -Force -ErrorAction SilentlyContinue',
    '      }',
    '      if (Test-Path -LiteralPath $mmdbBak) {',
    '        Invoke-WithRetry { Copy-Item -LiteralPath $mmdbBak -Destination $mmdbTarget -Force }',
    '        Remove-Item -LiteralPath $mmdbBak -Force -ErrorAction SilentlyContinue',
    '      }',
    '      if (Test-Path -LiteralPath $exeBak) {',
    '        Invoke-WithRetry { Copy-Item -LiteralPath $exeBak -Destination $exePath -Force }',
    '        Remove-Item -LiteralPath $exeBak -Force -ErrorAction SilentlyContinue',
    '      }',
    '    }',
    '  } catch {',
    '    $allRestored = $false',
    '  }',
    '  return $allRestored',
    '}',
    '',
    'try {',
    '  if ($mode -eq "asar") {',
    '    if (Test-Path -LiteralPath $asarTarget) {',
    '      Invoke-WithRetry { Copy-Item -LiteralPath $asarTarget -Destination $asarBak -Force }',
    '    }',
    '    Copy-LockedVerifiedFile $stagedAsar $asarTarget $expectedAsarSha "app.asar"',
    '    if ($stagedMmdb) {',
    '      if (Test-Path -LiteralPath $mmdbTarget) {',
    '        Invoke-WithRetry { Copy-Item -LiteralPath $mmdbTarget -Destination $mmdbBak -Force }',
    '      }',
    '      Copy-LockedVerifiedFile $stagedMmdb $mmdbTarget $expectedMmdbSha "geolite2-country.mmdb"',
    '    }',
    '  } elseif ($mode -eq "full-zip") {',
    '    if (-not (Test-Path -LiteralPath $stagedZip)) {',
    '      throw "缺少待应用的全量更新压缩包: $stagedZip"',
    '    }',
    '    Add-Type -AssemblyName System.IO.Compression.FileSystem',
    '    Cleanup-ExtractArtifact',
    '    $zipLock = [System.IO.File]::Open($stagedZip, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)',
    '    try {',
    '      Verify-StreamSha256 $zipLock $expectedZipSha "release.zip"',
    '      [System.IO.Compression.ZipFile]::ExtractToDirectory($stagedZip, $extractDir, [System.Text.Encoding]::UTF8)',
    '    } finally {',
    '      $zipLock.Dispose()',
    '    }',
    '    $extractedRoot = $extractDir',
    '    if (-not (Test-Path -LiteralPath (Join-Path $extractDir "resources\\app.asar"))) {',
    '      $subDirs = @(Get-ChildItem -LiteralPath $extractDir -Directory)',
    '      foreach ($sd in $subDirs) {',
    '        if (Test-Path -LiteralPath (Join-Path $sd.FullName "resources\\app.asar")) {',
    '          $extractedRoot = $sd.FullName',
    '          break',
    '        }',
    '      }',
    '    }',
    '    if (-not (Test-Path -LiteralPath (Join-Path $extractedRoot "resources\\app.asar"))) {',
    '      throw "解压后的完整更新包缺少 resources\\app.asar"',
    '    }',
    '    if (Test-Path -LiteralPath $backupDir) {',
    '      Remove-Item -LiteralPath $backupDir -Recurse -Force',
    '    }',
    '    [System.IO.Directory]::CreateDirectory($backupDir) | Out-Null',
    '    $existingRelSet = New-Object "System.Collections.Generic.HashSet[string]" ([System.StringComparer]::OrdinalIgnoreCase)',
    '    if (Test-Path -LiteralPath $appDir) {',
    '      $appNorm = Resolve-FullDir $appDir',
    '      $curFiles = @(Get-ChildItem -LiteralPath $appNorm -Recurse -Force -File)',
    '      foreach ($cf in $curFiles) {',
    '        $cRel = $cf.FullName.Substring($appNorm.Length + 1)',
    '        if ($cRel.EndsWith(".bak", [System.StringComparison]::OrdinalIgnoreCase)) { continue }',
    '        [void]$existingRelSet.Add($cRel)',
    '        $bakDest = Join-Path $backupDir $cRel',
    '        $bakParent = Split-Path -Parent $bakDest',
    '        if ($bakParent -and -not (Test-Path -LiteralPath $bakParent)) {',
    '          [System.IO.Directory]::CreateDirectory($bakParent) | Out-Null',
    '        }',
    '        Invoke-WithRetry { Copy-Item -LiteralPath $cf.FullName -Destination $bakDest -Force }',
    '      }',
    '    }',
    '    $script:hasFullDirBackup = $true',
    '    $rootNorm = Resolve-FullDir $extractedRoot',
    '    $allEntries = @(Get-ChildItem -LiteralPath $rootNorm -Recurse -Force)',
    '    foreach ($entry in $allEntries) {',
    '      $relPath = $entry.FullName.Substring($rootNorm.Length + 1)',
    '      $destPath = Join-Path $appDir $relPath',
    '      if ($entry.PSIsContainer) {',
    '        if (-not (Test-Path -LiteralPath $destPath)) {',
    '          [System.IO.Directory]::CreateDirectory($destPath) | Out-Null',
    '          $script:createdRelDirs.Add($relPath)',
    '        }',
    '      } else {',
    '        $parentDir = Split-Path -Parent $destPath',
    '        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {',
    '          [System.IO.Directory]::CreateDirectory($parentDir) | Out-Null',
    '        }',
    '        if (-not $existingRelSet.Contains($relPath) -and -not (Test-Path -LiteralPath $destPath)) {',
    '          $script:createdRelFiles.Add($relPath)',
    '        }',
    '        Invoke-WithRetry { Copy-Item -LiteralPath $entry.FullName -Destination $destPath -Force }',
    '      }',
    '    }',
    '    Cleanup-ExtractArtifact',
    '  } else {',
    '    throw "未知的更新应用模式: $mode"',
    '  }',
    '} catch {',
    '  Cleanup-ExtractArtifact',
    '  Cleanup-ReadyFile',
    '  $restoredOk = Restore-UpdateBackup',
    '  if ($restoredOk -and (-not $skipRelaunch) -and (Test-Path -LiteralPath $exePath)) {',
    '    try {',
    '      Start-GuardProcess -FilePath $exePath -WorkDir $appDir -RawArgs @("--update-rolled-back=$toVer")',
    '    } catch {}',
    '  }',
    '  exit 1',
    '}',
    '',
    'if (-not $skipRelaunch) {',
    '  Cleanup-ReadyFile',
    '  $relaunchArgs = @("--updated-from=$fromVer")',
    '  if ($readyFile) {',
    '    $relaunchArgs += "--update-ready-file=$readyFile"',
    '  }',
    '  $proc = $null',
    '  $launchFailed = $false',
    '  try {',
    '    $proc = Start-GuardProcess -FilePath $exePath -WorkDir $appDir -RawArgs $relaunchArgs -PassThru',
    '  } catch {',
    '    $launchFailed = $true',
    '  }',
    '  if ($launchFailed -or ($bootCheckMs -gt 0)) {',
    '    $bootReady = $false',
    '    if ((-not $launchFailed) -and ($bootCheckMs -gt 0)) {',
    '      $deadline = [DateTime]::UtcNow.AddMilliseconds($bootCheckMs)',
    '      while ([DateTime]::UtcNow -lt $deadline) {',
    '        if ($readyFile -and (Test-Path -LiteralPath $readyFile)) {',
    '          $bootReady = $true',
    '          break',
    '        }',
    '        if ($proc) {',
    '          $procExited = $false',
    '          $procExitCode = 0',
    '          try {',
    '            $proc.Refresh()',
    '            $procExited = $proc.HasExited',
    '            if ($procExited) { $procExitCode = $proc.ExitCode }',
    '          } catch {}',
    '          if ($procExited) {',
    '            if ((-not $readyFile) -or ($procExitCode -ne 0)) { break }',
    '          }',
    '        }',
    '        Start-Sleep -Milliseconds 120',
    '      }',
    '      if ((-not $bootReady) -and $readyFile -and (Test-Path -LiteralPath $readyFile)) {',
    '        $bootReady = $true',
    '      }',
    '    }',
    '    $procExitedFinal = $false',
    '    $procExitCodeFinal = 0',
    '    if ($proc) {',
    '      try {',
    '        $proc.Refresh()',
    '        $procExitedFinal = $proc.HasExited',
    '        if ($procExitedFinal) { $procExitCodeFinal = $proc.ExitCode }',
    '      } catch {}',
    '    }',
    '    $shouldRollback = if ($launchFailed) {',
    '      $true',
    '    } elseif ($readyFile) {',
    '      -not $bootReady',
    '    } else {',
    '      ($null -eq $proc) -or ($procExitedFinal -and ($procExitCodeFinal -ne 0))',
    '    }',
    '    if ($shouldRollback) {',
    '      if ($proc -and (-not $procExitedFinal)) {',
    '        $killPid = 0',
    '        try { $killPid = [int]$proc.Id } catch {}',
    '        if ($killPid -gt 0) {',
    '          Invoke-SafeTaskkill $killPid',
    '          Stop-Process -Id $killPid -Force -ErrorAction SilentlyContinue',
    '          Start-Sleep -Milliseconds 500',
    '        }',
    '      }',
    '      Cleanup-ExtractArtifact',
    '      Cleanup-ReadyFile',
    '      $restoredOk = Restore-UpdateBackup',
    '      if ($restoredOk -and (Test-Path -LiteralPath $exePath)) {',
    '        try {',
    '          Start-GuardProcess -FilePath $exePath -WorkDir $appDir -RawArgs @("--update-rolled-back=$toVer")',
    '        } catch {}',
    '      }',
    '      exit 2',
    '    }',
    '  }',
    '}',
    '',
    'Cleanup-ExtractArtifact',
    'Cleanup-ReadyFile',
    'Remove-Item -LiteralPath $asarBak -Force -ErrorAction SilentlyContinue',
    'Remove-Item -LiteralPath $mmdbBak -Force -ErrorAction SilentlyContinue',
    'Remove-Item -LiteralPath $exeBak -Force -ErrorAction SilentlyContinue',
    'if ($stageDir -and (Test-Path -LiteralPath $stageDir)) {',
    '  Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue',
    '}',
    'exit 0',
  ].join('\r\n');
}

async function gunzipFileWithVerification(
  gzFilePath: string,
  destFilePath: string,
  expectedUncompressedSize: number,
  expectedUncompressedSha256: string
): Promise<void> {
  await rawFs.promises.mkdir(path.dirname(destFilePath), { recursive: true });

  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const hash = crypto.createHash('sha256');
    let writtenBytes = 0;
    const maxAllowedBytes = expectedUncompressedSize + 1024;

    const rs = rawFs.createReadStream(gzFilePath);
    const gunzip = zlib.createGunzip();
    const ws = rawFs.createWriteStream(destFilePath, { flags: 'w' });

    const removeDestBestEffort = () => {
      try {
        if (rawFs.existsSync(destFilePath)) {
          rawFs.rmSync(destFilePath, { force: true });
        }
      } catch {
        // ignore
      }
    };

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      rs.destroy();
      gunzip.destroy();
      ws.once('close', removeDestBestEffort);
      ws.destroy();
      reject(err);
    };

    gunzip.on('data', (chunk: Buffer) => {
      writtenBytes += chunk.length;
      if (writtenBytes > maxAllowedBytes) {
        fail(new Error('解压数据超出签名声明体积，已终止解压'));
        return;
      }
      hash.update(chunk);
    });

    rs.on('error', fail);
    gunzip.on('error', (err) => fail(new Error(`解压更新包失败: ${err.message}`)));
    ws.on('error', fail);

    ws.on('close', () => {
      if (settled) return;
      settled = true;
      if (writtenBytes !== expectedUncompressedSize) {
        removeDestBestEffort();
        reject(
          new Error(
            `解压后体积不匹配 (实际 ${writtenBytes} 字节，预期 ${expectedUncompressedSize} 字节)`
          )
        );
        return;
      }
      const actualSha = hash.digest('hex').toLowerCase();
      if (actualSha !== expectedUncompressedSha256.toLowerCase()) {
        removeDestBestEffort();
        reject(new Error('解压后文件 SHA-256 校验不一致，已拦截损坏文件'));
        return;
      }
      resolve();
    });

    rs.pipe(gunzip).pipe(ws);
  });
}

export class UpdaterService {
  private readonly configStore: ConfigStore;
  private readonly probeEngine: ProbeEngine;
  private readonly onQuitForUpdate?: () => void;

  private readonly manifestUrl: string;
  private readonly releasePageUrl: string;
  private readonly publicKey: string;
  private readonly isPackaged: boolean;
  private readonly currentVersion: string;
  private readonly electronVersion: string;
  private readonly nativeShellVersion: string;
  private readonly appDir: string;
  private readonly resourcesDir: string;
  private readonly exePath: string;
  private readonly stagingRootDir: string;
  private readonly allowLocalhostForTest: boolean;
  private readonly targetPidOverride?: number;
  private readonly bootHandshakeTimeoutMs: number;
  private readonly waitExitAttemptsOverride?: number;
  private readonly startupCheckDelayMs: number;
  private readonly startupRetryDelayMs: number;
  private readonly windowShowCooldownMs: number;
  private readonly errorRetryCooldownMs: number;

  private status: UpdateStatus = 'idle';
  private cachedManifest: UpdateReleaseManifest | null = null;
  private deliveryMode: UpdateDeliveryMode | null = null;
  private includeMmdbUpdate = false;
  private downloadTotalBytes: number | null = null;
  private downloadedBytes = 0;
  private progressPercent: number | null = null;
  private signatureVerified = false;
  private lastCheckedAt: number | null = null;
  private lastSuccessfulCheckAt: number | null = null;
  private lastAttemptAt: number | null = null;
  private lastAttemptSucceeded = false;
  private viaChannel: string | null = null;
  private lastError: string | null = null;

  private startupTimer: NodeJS.Timeout | null = null;
  private startupRetryTimer: NodeJS.Timeout | null = null;
  private initialized = false;
  private startupCheckFailedAt: number | null = null;
  private startupRetryUsed = false;
  private bakCleanupTimer: NodeJS.Timeout | null = null;
  private quitTimer: NodeJS.Timeout | null = null;
  private checkPromise: Promise<UpdateActionResult> | null = null;
  private downloadPromise: Promise<UpdateActionResult> | null = null;
  private applyingInProgress = false;
  private lastProgressEmitAt = 0;

  constructor(options: UpdaterServiceOptions) {
    this.configStore = options.configStore;
    this.probeEngine = options.probeEngine;
    this.onQuitForUpdate = options.onQuitForUpdate;

    this.manifestUrl = options.manifestUrlOverride || DEFAULT_GITHUB_RELEASE_LATEST_JSON_URL;
    this.releasePageUrl = options.releasePageUrlOverride || DEFAULT_GITHUB_RELEASES_PAGE_URL;
    this.publicKey = options.publicKeyOverride || BUILTIN_UPDATE_PUBLIC_KEY_SPKI_B64;
    this.isPackaged = options.isPackagedOverride ?? app.isPackaged;
    this.currentVersion =
      normalizeSemverString(options.currentVersionOverride || app.getVersion()) || '1.0.0';
    this.electronVersion =
      normalizeSemverString(options.electronVersionOverride || process.versions.electron) ||
      '0.0.0';

    this.exePath = options.exePathOverride || process.execPath;
    this.appDir = options.appDirOverride || path.dirname(this.exePath);
    this.resourcesDir =
      options.resourcesDirOverride || process.resourcesPath || path.join(this.appDir, 'resources');
    this.stagingRootDir =
      options.stagingRootDirOverride || path.join(app.getPath('userData'), 'updates');
    this.allowLocalhostForTest = Boolean(options.allowLocalhostForTest);
    this.targetPidOverride = options.targetPidOverride;
    this.bootHandshakeTimeoutMs =
      options.bootHandshakeTimeoutMsOverride ?? DEFAULT_BOOT_HANDSHAKE_TIMEOUT_MS;
    this.waitExitAttemptsOverride = options.waitExitAttemptsOverride;
    this.startupCheckDelayMs =
      options.startupCheckDelayMsOverride ?? DEFAULT_STARTUP_CHECK_DELAY_MS;
    this.startupRetryDelayMs =
      options.startupRetryDelayMsOverride ?? DEFAULT_STARTUP_RETRY_DELAY_MS;
    this.windowShowCooldownMs =
      options.windowShowCooldownMsOverride ?? DEFAULT_WINDOW_SHOW_COOLDOWN_MS;
    this.errorRetryCooldownMs =
      options.errorRetryCooldownMsOverride ?? DEFAULT_ERROR_RETRY_COOLDOWN_MS;
    this.nativeShellVersion =
      normalizeSemverString(options.nativeShellVersionOverride) || this.readNativeShellVersion();

    this.probeEngine.setUpdateStateProvider(() => this.getSnapshot());
  }

  private readNativeShellVersion(): string {
    try {
      const shellMetaPath = path.join(this.resourcesDir, 'shell-meta.json');
      if (rawFs.existsSync(shellMetaPath)) {
        const parsed = JSON.parse(rawFs.readFileSync(shellMetaPath, 'utf-8')) as {
          shellVersion?: unknown;
        };
        if (typeof parsed.shellVersion === 'string') {
          const norm = normalizeSemverString(parsed.shellVersion);
          if (norm) return norm;
        }
      }
    } catch {
      // fallback to 1.0.0
    }
    return '1.0.0';
  }

  private hasVerifiedUpdate(): boolean {
    if (!this.cachedManifest || !this.signatureVerified) {
      return false;
    }
    try {
      return compareSemver(this.cachedManifest.version, this.currentVersion) > 0;
    } catch {
      return false;
    }
  }

  public getSnapshot(): UpdateStateSnapshot {
    const hasUpdate = this.hasVerifiedUpdate();
    return {
      currentVersion: this.currentVersion,
      electronVersion: this.electronVersion,
      isPackaged: this.isPackaged,
      status: this.status,
      hasUpdate,
      latestVersion: this.cachedManifest?.version || null,
      publishedAt: this.cachedManifest?.publishedAt || null,
      releaseNotes: this.cachedManifest?.notes || null,
      deliveryMode: this.deliveryMode,
      includeMmdbUpdate: this.includeMmdbUpdate,
      downloadTotalBytes: this.downloadTotalBytes,
      downloadedBytes: this.downloadedBytes,
      progressPercent: this.progressPercent,
      signatureVerified: this.signatureVerified,
      lastCheckedAt: this.lastCheckedAt,
      lastSuccessfulCheckAt: this.lastSuccessfulCheckAt,
      viaChannel: this.viaChannel,
      error: this.lastError,
      releasePageUrl: this.releasePageUrl,
    };
  }

  private clearStartupTimer(): void {
    if (this.startupTimer) {
      clearTimeout(this.startupTimer);
      this.startupTimer = null;
    }
  }

  private clearStartupRetryTimer(): void {
    if (this.startupRetryTimer) {
      clearTimeout(this.startupRetryTimer);
      this.startupRetryTimer = null;
    }
  }

  public initialize(argv: string[] = process.argv): void {
    this.initialized = true;
    this.handlePostUpdateStartupFlags(argv);
    this.clearStartupTimer();
    this.clearStartupRetryTimer();
    this.startupCheckFailedAt = null;
    this.startupRetryUsed = false;

    if (!this.configStore.get().autoCheckUpdates) {
      return;
    }

    this.startupTimer = setTimeout(() => {
      void this.runStartupAutoCheck();
    }, this.startupCheckDelayMs);
    this.startupTimer.unref?.();
  }

  private async runStartupAutoCheck(): Promise<void> {
    this.startupTimer = null;
    if (!this.configStore.get().autoCheckUpdates) {
      return;
    }
    const res = await this.checkForUpdates({ silent: true });
    if (!res.ok && this.lastSuccessfulCheckAt === null && !this.startupRetryUsed) {
      this.startupCheckFailedAt = Date.now();
      this.clearStartupRetryTimer();
      this.startupRetryTimer = setTimeout(() => {
        this.startupRetryTimer = null;
        if (
          this.startupRetryUsed ||
          this.lastSuccessfulCheckAt !== null ||
          !this.configStore.get().autoCheckUpdates
        ) {
          return;
        }
        this.startupRetryUsed = true;
        void this.checkForUpdates({ silent: true });
      }, this.startupRetryDelayMs);
      this.startupRetryTimer.unref?.();
    }
  }

  public notifyNetworkReady(readyTimestamp?: number): void {
    if (
      this.startupCheckFailedAt === null ||
      this.startupRetryUsed ||
      this.lastSuccessfulCheckAt !== null
    ) {
      return;
    }
    if (readyTimestamp !== undefined && readyTimestamp <= this.startupCheckFailedAt) {
      return;
    }
    if (!this.configStore.get().autoCheckUpdates) {
      return;
    }
    this.clearStartupRetryTimer();
    this.startupRetryUsed = true;
    void this.checkForUpdates({ silent: true });
  }

  public async notifyWindowShown(): Promise<UpdateActionResult | null> {
    if (!this.initialized || !this.configStore.get().autoCheckUpdates) {
      return null;
    }
    // 启动初期定时器尚未触发时交由启动检查统一执行，避免在代理探测初始化前抢跑
    if (this.startupTimer !== null) {
      return null;
    }
    if (
      this.applyingInProgress ||
      this.status === 'applying' ||
      this.checkPromise ||
      this.downloadPromise
    ) {
      return null;
    }

    const now = Date.now();

    // 最近一次检查或预下载尝试失败：统一遵守 errorRetryCooldownMs（默认 2 分钟）短冷却节流，
    // 防止满 30 分钟后处于离线/超时环境时每次切换窗口都触发无节流请求风暴
    if (!this.lastAttemptSucceeded) {
      if (
        this.lastAttemptAt !== null &&
        now - this.lastAttemptAt < this.errorRetryCooldownMs
      ) {
        return null;
      }
      return this.checkForUpdates({ silent: true });
    }

    // 最近一次尝试已成功：严格遵循 windowShowCooldownMs（默认 30 分钟）长冷却节流
    if (
      this.lastSuccessfulCheckAt !== null &&
      now - this.lastSuccessfulCheckAt < this.windowShowCooldownMs
    ) {
      return null;
    }

    return this.checkForUpdates({ silent: true });
  }

  public handleAutoCheckConfigChanged(enabled: boolean): void {
    if (!enabled) {
      this.clearStartupTimer();
      this.clearStartupRetryTimer();
      return;
    }
    void this.notifyWindowShown();
  }

  public stop(): void {
    this.clearStartupTimer();
    this.clearStartupRetryTimer();
    if (this.bakCleanupTimer) {
      clearTimeout(this.bakCleanupTimer);
      this.bakCleanupTimer = null;
    }
    if (this.quitTimer) {
      clearTimeout(this.quitTimer);
      this.quitTimer = null;
    }
  }

  private handlePostUpdateStartupFlags(argv: string[]): void {
    let readyFilePath = '';
    for (const arg of argv) {
      if (arg.startsWith('--update-ready-file=')) {
        readyFilePath = arg
          .slice('--update-ready-file='.length)
          .trim()
          .replace(/^"+|"+$/g, '');
      } else if (arg.startsWith('--updated-from=')) {
        const fromVer = arg.slice('--updated-from='.length).trim();
        if (fromVer && fromVer !== this.currentVersion) {
          this.probeEngine.recordExternalLog(
            'success',
            `🎉 已成功完成版本更新：v${fromVer} → v${this.currentVersion}`
          );
        }
      } else if (arg.startsWith('--update-rolled-back=')) {
        const failedVer = arg.slice('--update-rolled-back='.length).trim();
        this.probeEngine.recordExternalLog(
          'danger',
          `⚠️ 更新至 v${failedVer || '新版本'} 后启动自检未通过，已自动安全回滚至 v${this.currentVersion}`
        );
      }
    }

    // 写入正向就绪握手标记，通知脱离式 PowerShell 更新脚本新实例已完成核心引导
    if (readyFilePath) {
      try {
        rawFs.mkdirSync(path.dirname(readyFilePath), { recursive: true });
        rawFs.writeFileSync(readyFilePath, `${process.pid}:${Date.now()}\n`, 'utf-8');
      } catch {
        // ignore
      }
    }

    // 推迟兜底清理残留 .bak 与历史暂存目录，避免在后台更新脚本观察/收尾窗口内抢删握手或回滚备份
    if (this.bakCleanupTimer) {
      clearTimeout(this.bakCleanupTimer);
    }
    this.bakCleanupTimer = setTimeout(() => {
      this.bakCleanupTimer = null;
      for (const bakPath of [
        path.join(this.resourcesDir, 'app.asar.bak'),
        path.join(this.resourcesDir, 'geolite2-country.mmdb.bak'),
        `${this.exePath}.bak`,
      ]) {
        try {
          if (rawFs.existsSync(bakPath)) {
            rawFs.rmSync(bakPath, { force: true });
          }
        } catch {
          // ignore
        }
      }
      void this.cleanupObsoleteStagingDirs();
    }, POST_UPDATE_BAK_CLEANUP_DELAY_MS);
    this.bakCleanupTimer.unref?.();
  }

  private async cleanupObsoleteStagingDirs(): Promise<void> {
    try {
      if (!rawFs.existsSync(this.stagingRootDir)) return;
      const entries = await rawFs.promises.readdir(this.stagingRootDir, {
        withFileTypes: true,
      });
      const now = Date.now();
      for (const entry of entries) {
        const fullEntryPath = path.join(this.stagingRootDir, entry.name);
        if (entry.isDirectory() && entry.name.startsWith('v-')) {
          const ver = normalizeSemverString(entry.name.slice(2));
          if (!ver || compareSemver(ver, this.currentVersion) <= 0) {
            await rawFs.promises.rm(fullEntryPath, {
              recursive: true,
              force: true,
            });
          }
        } else if (
          entry.isFile() &&
          entry.name.startsWith('boot-ready-') &&
          entry.name.endsWith('.ok')
        ) {
          try {
            const stat = await rawFs.promises.stat(fullEntryPath);
            if (now - stat.mtimeMs > 60_000) {
              await rawFs.promises.rm(fullEntryPath, { force: true });
            }
          } catch {
            // ignore
          }
        }
      }
    } catch {
      // ignore cleanup error
    }
  }

  private emitUpdateState(): void {
    this.probeEngine.notifyExternalStateChanged();
  }

  private async buildDownloadAttempts(
    rawUrl: string,
    appendCacheBuster = false
  ): Promise<
    Array<{ url: string; proxyUrl: string | null; label: string; isMirror: boolean }>
  > {
    const proxies = await this.probeEngine.resolveUpdateDownloadProxies(rawUrl);
    const useMirror = this.configStore.get().useUpdateMirrorFallback;

    const withCacheBust = (u: string): string => {
      if (!appendCacheBuster) return u;
      const sep = u.includes('?') ? '&' : '?';
      return `${u}${sep}_t=${Math.floor(Date.now() / 30000)}`;
    };

    const attempts: Array<{
      url: string;
      proxyUrl: string | null;
      label: string;
      isMirror: boolean;
    }> = [];

    // 1. 优先通过已识别代理或直连访问原始 GitHub 地址
    for (const p of proxies) {
      attempts.push({
        url: withCacheBust(rawUrl),
        proxyUrl: p.proxyUrl,
        label: p.label,
        isMirror: false,
      });
    }

    // 2. 开启镜像兜底且目标是 GitHub 官方地址时，追加镜像通道（全程受 Ed25519 公钥签名保护）
    if (useMirror && rawUrl.startsWith('https://github.com/')) {
      const firstLocalProxy = proxies.find((p) => p.proxyUrl !== null) || null;
      for (const prefix of DEFAULT_GITHUB_MIRROR_PREFIXES) {
        const mirroredUrl = withCacheBust(`${prefix}${rawUrl}`);
        attempts.push({
          url: mirroredUrl,
          proxyUrl: null,
          label: `GitHub 加速镜像 (${new URL(prefix).host})`,
          isMirror: true,
        });
        if (firstLocalProxy) {
          attempts.push({
            url: mirroredUrl,
            proxyUrl: firstLocalProxy.proxyUrl,
            label: `GitHub 加速镜像经代理 (${new URL(prefix).host})`,
            isMirror: true,
          });
        }
      }
    }

    return attempts;
  }

  private getVersionStageDir(version: string): string {
    return path.join(this.stagingRootDir, `v-${version}`);
  }

  private async decideDeliveryAndMmdb(manifest: UpdateReleaseManifest): Promise<{
    deliveryMode: UpdateDeliveryMode;
    includeMmdbUpdate: boolean;
    expectedBytes: number;
  }> {
    let localAsarExists = false;
    try {
      const st = rawFs.statSync(path.join(this.resourcesDir, 'app.asar'));
      localAsarExists = st.isFile();
    } catch {
      localAsarExists = false;
    }
    const canUseAsarHotUpdate =
      this.isPackaged &&
      localAsarExists &&
      manifest.electronVersion === this.electronVersion &&
      compareSemver(this.nativeShellVersion, manifest.minNativeShellVersion) >= 0 &&
      rawFs.existsSync(path.join(this.resourcesDir, 'mihomo', 'guard-mihomo.exe')) &&
      (await computeFileSha256(path.join(this.resourcesDir, 'mihomo', 'guard-mihomo.exe'))).sha256 === manifest.mihomo.sha256;

    if (!canUseAsarHotUpdate && this.isPackaged) {
      return {
        deliveryMode: 'full-zip',
        includeMmdbUpdate: false,
        expectedBytes: manifest.fullZip.size,
      };
    }

    // 开发模式下展示增量包信息供预览（不会覆盖本地源码）
    if (!this.isPackaged) {
      const mode: UpdateDeliveryMode =
        manifest.electronVersion === this.electronVersion ? 'asar' : 'full-zip';
      return {
        deliveryMode: mode,
        includeMmdbUpdate: false,
        expectedBytes: mode === 'asar' ? manifest.asar.size : manifest.fullZip.size,
      };
    }

    let needMmdb = false;
    if (manifest.mmdb) {
      const localMmdbPath = path.join(this.resourcesDir, 'geolite2-country.mmdb');
      if (!rawFs.existsSync(localMmdbPath)) {
        needMmdb = true;
      } else {
        try {
          const { sha256 } = await computeFileSha256(localMmdbPath);
          needMmdb = sha256 !== manifest.mmdb.uncompressedSha256.toLowerCase();
        } catch {
          needMmdb = true;
        }
      }
    }

    const totalBytes =
      manifest.asar.size + (needMmdb && manifest.mmdb ? manifest.mmdb.size : 0);

    return {
      deliveryMode: 'asar',
      includeMmdbUpdate: needMmdb,
      expectedBytes: totalBytes,
    };
  }

  private async isStagedUpdateAlreadyVerified(
    manifest: UpdateReleaseManifest,
    deliveryMode: UpdateDeliveryMode,
    includeMmdbUpdate: boolean
  ): Promise<boolean> {
    const stageDir = this.getVersionStageDir(manifest.version);
    const readyFile = path.join(stageDir, 'ready.json');
    if (!rawFs.existsSync(readyFile)) return false;

    try {
      const meta = JSON.parse(
        await rawFs.promises.readFile(readyFile, 'utf-8')
      ) as StagedReadyMetadata;
      if (meta.version !== manifest.version || meta.deliveryMode !== deliveryMode) {
        return false;
      }

      if (deliveryMode === 'asar') {
        const stagedAsar = path.join(stageDir, 'app-payload.bin');
        if (!rawFs.existsSync(stagedAsar)) return false;
        const asarHash = await computeFileSha256(stagedAsar);
        if (
          asarHash.size !== manifest.asar.uncompressedSize ||
          asarHash.sha256 !== manifest.asar.uncompressedSha256.toLowerCase()
        ) {
          return false;
        }
        await validateAsarArchiveHeader(stagedAsar);

        if (includeMmdbUpdate && manifest.mmdb) {
          const stagedMmdb = path.join(stageDir, 'geolite2-country.mmdb.staged');
          if (!rawFs.existsSync(stagedMmdb)) return false;
          const mmdbHash = await computeFileSha256(stagedMmdb);
          if (
            mmdbHash.size !== manifest.mmdb.uncompressedSize ||
            mmdbHash.sha256 !== manifest.mmdb.uncompressedSha256.toLowerCase()
          ) {
            return false;
          }
        }
        return true;
      }

      const stagedZip = path.join(stageDir, 'release.zip.staged');
      if (!rawFs.existsSync(stagedZip)) return false;
      const zipHash = await computeFileSha256(stagedZip);
      return (
        zipHash.size === manifest.fullZip.size &&
        zipHash.sha256 === manifest.fullZip.sha256.toLowerCase()
      );
    } catch {
      return false;
    }
  }

  public async checkForUpdates(
    opts: { silent?: boolean } = {}
  ): Promise<UpdateActionResult> {
    if (this.applyingInProgress || (this.status as UpdateStatus) === 'applying') {
      return {
        ok: false,
        message: '正在准备重启应用更新...',
        state: this.probeEngine.getSnapshot(),
      };
    }
    if (this.downloadPromise) {
      return this.downloadPromise;
    }
    if (this.checkPromise) {
      return this.checkPromise;
    }

    const task = this.executeCheckForUpdates(Boolean(opts.silent));
    this.checkPromise = task;
    try {
      return await task;
    } finally {
      if (this.checkPromise === task) {
        this.checkPromise = null;
      }
    }
  }

  private async executeCheckForUpdates(silent: boolean): Promise<UpdateActionResult> {
    if (this.applyingInProgress || (this.status as UpdateStatus) === 'applying') {
      return {
        ok: false,
        message: '正在准备重启应用更新...',
        state: this.probeEngine.getSnapshot(),
      };
    }

    const prevStatus = this.status;
    const prevManifest = this.cachedManifest;
    const prevSigVerified = this.signatureVerified;
    const prevDeliveryMode = this.deliveryMode;
    const prevIncludeMmdb = this.includeMmdbUpdate;
    const prevTotalBytes = this.downloadTotalBytes;
    const prevProgressPercent = this.progressPercent;
    const prevChannel = this.viaChannel;
    const prevLastError = this.lastError;
    const prevHadVerifiedUpdate =
      Boolean(prevManifest && prevSigVerified) &&
      compareSemver(prevManifest!.version, this.currentVersion) > 0;

    // 当已有验签就绪/可用的新版本且本次仅为后台静默复查时，保持原视觉状态不降级为 checking，
    // 消除右上角标志闪烁并确保用户在静默复查期间随时可点击「立即重启并更新」
    const preserveVisualStatusDuringSilentCheck =
      silent &&
      prevHadVerifiedUpdate &&
      (prevStatus === 'downloaded' || prevStatus === 'available');
    if (!preserveVisualStatusDuringSilentCheck) {
      this.status = 'checking';
      this.lastError = null;
      this.emitUpdateState();
    }

    const attempts = await this.buildDownloadAttempts(this.manifestUrl, true);
    let verifiedManifest: UpdateReleaseManifest | null = null;
    let usedChannel = '';
    let sawSecurityRejection = false;
    let securityRejectionText = '';
    let sawStaleMirrorOnly = false;
    let lastErrText = '无法连接更新服务器';

    for (let idx = 0; idx < attempts.length; idx++) {
      const attempt = attempts[idx];
      try {
        const rawText = await requestTextViaProxy(
          attempt.url,
          attempt.proxyUrl,
          MANIFEST_FETCH_TIMEOUT_MS,
          'application/json, text/plain, */*',
          5,
          this.allowLocalhostForTest
        );
        const parsedJson = JSON.parse(rawText) as unknown;
        const looksLikeManifestObject =
          Boolean(parsedJson) &&
          typeof parsedJson === 'object' &&
          !Array.isArray(parsedJson) &&
          ('schemaVersion' in (parsedJson as Record<string, unknown>) ||
            'asar' in (parsedJson as Record<string, unknown>) ||
            'fullZip' in (parsedJson as Record<string, unknown>) ||
            'signature' in (parsedJson as Record<string, unknown>));

        let manifest: UpdateReleaseManifest;
        try {
          manifest = validateUpdateManifestStructure(
            parsedJson,
            this.allowLocalhostForTest
          );
        } catch (structErr) {
          const structMsg =
            structErr instanceof Error ? structErr.message : String(structErr);
          const rawSchemaVer = looksLikeManifestObject
            ? (parsedJson as Record<string, unknown>).schemaVersion
            : undefined;
          const isUnsupportedFutureSchema =
            typeof rawSchemaVer === 'number' && rawSchemaVer > 1;
          if (looksLikeManifestObject && !isUnsupportedFutureSchema) {
            sawSecurityRejection = true;
            securityRejectionText = `更新清单安全校验未通过，已拦截可疑数据（${structMsg}）`;
            lastErrText = securityRejectionText;
            if (idx < attempts.length - 1) {
              this.probeEngine.recordExternalLog(
                'warn',
                `通道 [${attempt.label}] 返回异常更新清单已被安全拦截（${structMsg}），正在切换备用通道`,
                false
              );
            }
            continue;
          }
          throw structErr;
        }

        if (!verifyUpdateManifestSignature(manifest, this.publicKey)) {
          sawSecurityRejection = true;
          securityRejectionText = '更新清单 Ed25519 数字签名校验失败，已拒绝加载以防篡改';
          lastErrText = securityRejectionText;
          if (idx < attempts.length - 1) {
            this.probeEngine.recordExternalLog(
              'warn',
              `通道 [${attempt.label}] 更新清单 Ed25519 签名校验失败，已拦截并切换备用通道`,
              false
            );
          }
          continue;
        }
        // 防镜像陈旧缓存回退：若本地已持有更高版本验签清单，拒绝被滞后的镜像清单降级覆盖
        if (
          attempt.isMirror &&
          prevManifest &&
          prevSigVerified &&
          compareSemver(manifest.version, prevManifest.version) < 0
        ) {
          sawStaleMirrorOnly = true;
          lastErrText = `镜像节点缓存尚未刷新 (镜像返回 v${manifest.version} < 已发现 v${prevManifest.version})`;
          continue;
        }
        verifiedManifest = manifest;
        usedChannel = attempt.label;
        break;
      } catch (err) {
        lastErrText = err instanceof Error ? err.message : String(err);
      }
    }

    if (this.applyingInProgress || (this.status as UpdateStatus) === 'applying') {
      return {
        ok: false,
        message: '正在准备重启应用更新...',
        state: this.probeEngine.getSnapshot(),
      };
    }

    const checkedNow = Date.now();
    this.lastCheckedAt = checkedNow;
    this.lastAttemptAt = checkedNow;

    if (!verifiedManifest) {
      this.lastAttemptSucceeded = false;

      // 1) 签名伪造或清单资产地址篡改属于最高优先级安全异常：无条件清空缓存并告警（绝不被陈旧镜像覆盖）
      if (sawSecurityRejection) {
        this.cachedManifest = null;
        this.signatureVerified = false;
        this.deliveryMode = null;
        this.includeMmdbUpdate = false;
        this.downloadTotalBytes = null;
        this.downloadedBytes = 0;
        this.progressPercent = null;
        this.status = 'error';
        this.lastError =
          securityRejectionText || '更新清单 Ed25519 数字签名校验失败，已拒绝加载以防篡改';
        this.probeEngine.recordExternalLog('danger', this.lastError, false);
        this.emitUpdateState();
        return {
          ok: false,
          message: this.lastError,
          state: this.probeEngine.getSnapshot(),
        };
      }

      // 2) 纯网络故障或镜像缓存滞后（sawStaleMirrorOnly）时，若此前已验签发现新版本，保持状态粘性
      if ((prevHadVerifiedUpdate || sawStaleMirrorOnly) && prevManifest && prevSigVerified) {
        if (compareSemver(prevManifest.version, this.currentVersion) <= 0) {
          this.cachedManifest = prevManifest;
          this.signatureVerified = true;
          this.status = 'up-to-date';
          this.lastError = silent ? null : `检查更新失败：${lastErrText}`;
          this.emitUpdateState();
          return {
            ok: false,
            message: `检查更新失败：${lastErrText}`,
            state: this.probeEngine.getSnapshot(),
          };
        }

        const stagedPrevValid =
          this.isPackaged && prevDeliveryMode
            ? await this.isStagedUpdateAlreadyVerified(
                prevManifest,
                prevDeliveryMode,
                prevIncludeMmdb
              )
            : false;
        if (this.applyingInProgress || (this.status as UpdateStatus) === 'applying') {
          return {
            ok: false,
            message: '正在准备重启应用更新...',
            state: this.probeEngine.getSnapshot(),
          };
        }
        if (stagedPrevValid) {
          this.cachedManifest = prevManifest;
          this.signatureVerified = true;
          this.deliveryMode = prevDeliveryMode;
          this.includeMmdbUpdate = prevIncludeMmdb;
          this.downloadTotalBytes = prevTotalBytes;
          this.downloadedBytes = prevTotalBytes ?? 0;
          this.progressPercent = 100;
          this.viaChannel = prevChannel;
          this.status = 'downloaded';
          this.lastError = silent
            ? null
            : `联网刷新失败（${lastErrText}），本地已验签就绪的 v${prevManifest.version} 仍可直接重启更新`;
          this.emitUpdateState();
          return {
            ok: false,
            message: `联网刷新失败（${lastErrText}），本地已验签就绪的 v${prevManifest.version} 仍可直接重启更新`,
            state: this.probeEngine.getSnapshot(),
          };
        }

        this.cachedManifest = prevManifest;
        this.signatureVerified = true;
        this.deliveryMode = prevDeliveryMode;
        this.includeMmdbUpdate = prevIncludeMmdb;
        this.downloadTotalBytes = prevTotalBytes;
        this.downloadedBytes = 0;
        this.progressPercent = prevStatus === 'available' ? prevProgressPercent : 0;
        this.viaChannel = prevChannel;
        this.status = prevStatus === 'error' ? 'error' : 'available';
        this.lastError = silent
          ? prevStatus === 'error'
            ? prevLastError
            : null
          : `联网刷新失败（${lastErrText}），已保留新版本 v${prevManifest.version} 更新提示`;
        if (!silent && this.lastError) {
          this.probeEngine.recordExternalLog('warn', this.lastError, false);
        }
        this.emitUpdateState();
        return {
          ok: false,
          message: `联网刷新失败（${lastErrText}），已保留新版本 v${prevManifest.version} 更新提示`,
          state: this.probeEngine.getSnapshot(),
        };
      }

      this.cachedManifest = null;
      this.signatureVerified = false;
      this.deliveryMode = null;
      this.includeMmdbUpdate = false;
      this.downloadTotalBytes = null;
      this.downloadedBytes = 0;
      this.progressPercent = null;
      this.status = 'error';
      this.lastError = `检查更新失败：${lastErrText}`;
      if (!silent) {
        this.probeEngine.recordExternalLog('warn', this.lastError, false);
      }
      this.emitUpdateState();
      return {
        ok: false,
        message: this.lastError,
        state: this.probeEngine.getSnapshot(),
      };
    }

    this.lastAttemptSucceeded = true;
    this.lastSuccessfulCheckAt = checkedNow;
    this.startupCheckFailedAt = null;
    this.startupRetryUsed = true;
    this.clearStartupRetryTimer();

    this.cachedManifest = verifiedManifest;
    this.signatureVerified = true;
    this.viaChannel = usedChannel;

    const cmp = compareSemver(verifiedManifest.version, this.currentVersion);
    if (cmp <= 0) {
      this.status = 'up-to-date';
      this.deliveryMode = null;
      this.includeMmdbUpdate = false;
      this.downloadTotalBytes = null;
      this.downloadedBytes = 0;
      this.progressPercent = null;
      this.lastError = null;
      this.emitUpdateState();
      return {
        ok: true,
        message: `当前已是最新版本 (v${this.currentVersion})`,
        state: this.probeEngine.getSnapshot(),
      };
    }

    const decision = await this.decideDeliveryAndMmdb(verifiedManifest);
    const stagedAlreadyValid = this.isPackaged
      ? await this.isStagedUpdateAlreadyVerified(
          verifiedManifest,
          decision.deliveryMode,
          decision.includeMmdbUpdate
        )
      : false;
    if (this.applyingInProgress || (this.status as UpdateStatus) === 'applying') {
      return {
        ok: false,
        message: '正在准备重启应用更新...',
        state: this.probeEngine.getSnapshot(),
      };
    }

    this.deliveryMode = decision.deliveryMode;
    this.includeMmdbUpdate = decision.includeMmdbUpdate;
    this.downloadTotalBytes = decision.expectedBytes;

    if (stagedAlreadyValid) {
      this.status = 'downloaded';
      this.downloadedBytes = decision.expectedBytes;
      this.progressPercent = 100;
      this.lastError = null;
      this.emitUpdateState();
      return {
        ok: true,
        message: `新版本 v${verifiedManifest.version} 已验签就绪，可随时重启生效`,
        state: this.probeEngine.getSnapshot(),
      };
    }

    this.status = 'available';
    this.downloadedBytes = 0;
    this.progressPercent = this.isPackaged ? 0 : null;
    this.lastError = null;
    this.emitUpdateState();

    // 正式打包环境下，发现轻量 ASAR 增量更新包时自动在后台静默下载并完成验签
    if (this.isPackaged && decision.deliveryMode === 'asar') {
      return this.runTrackedDownload(silent);
    }

    if (!silent || prevManifest?.version !== verifiedManifest.version) {
      this.probeEngine.recordExternalLog(
        'info',
        this.isPackaged
          ? `发现新版本 v${verifiedManifest.version}（完整更新包），可点击右上角更新标志下载升级`
          : `发现新版本 v${verifiedManifest.version}（源码运行模式），可点击右上角更新标志查看详情`,
        false
      );
      this.emitUpdateState();
    }

    return {
      ok: true,
      message: this.isPackaged
        ? `发现新版本 v${verifiedManifest.version}，请点击下载完整更新包`
        : `发现新版本 v${verifiedManifest.version}（当前为源码运行模式，仅正式打包版执行原地替换）`,
      state: this.probeEngine.getSnapshot(),
    };
  }

  private async runTrackedDownload(silent: boolean): Promise<UpdateActionResult> {
    if (this.downloadPromise) {
      return this.downloadPromise;
    }
    const task = this.executeDownloadUpdate(silent);
    this.downloadPromise = task;
    try {
      return await task;
    } finally {
      if (this.downloadPromise === task) {
        this.downloadPromise = null;
      }
    }
  }

  public async downloadUpdate(): Promise<UpdateActionResult> {
    if (this.applyingInProgress || (this.status as UpdateStatus) === 'applying') {
      return {
        ok: false,
        message: '正在准备重启应用更新...',
        state: this.probeEngine.getSnapshot(),
      };
    }
    if (this.downloadPromise) {
      return this.downloadPromise;
    }
    if (this.checkPromise) {
      const checkRes = await this.checkPromise;
      if (this.downloadPromise) {
        return this.downloadPromise;
      }
      if (
        !this.cachedManifest ||
        !this.signatureVerified ||
        this.status === 'up-to-date' ||
        this.status === 'downloaded'
      ) {
        return checkRes;
      }
    }

    return this.runTrackedDownload(false);
  }

  private async downloadSingleVerifiedFile(
    rawUrl: string,
    destPath: string,
    expectedSize: number,
    expectedSha256: string,
    timeoutMs: number,
    progressOffsetBytes: number,
    overallTotalBytes: number
  ): Promise<string> {
    const attempts = await this.buildDownloadAttempts(rawUrl, false);
    let lastErr = '下载连接失败';

    for (let idx = 0; idx < attempts.length; idx++) {
      const attempt = attempts[idx];
      const attemptTmpPath = `${destPath}.attempt-${idx}-${Date.now()}.tmp`;
      try {
        const res = await downloadFileViaProxy({
          targetUrl: attempt.url,
          proxyUrl: attempt.proxyUrl,
          destFilePath: attemptTmpPath,
          timeoutMs,
          maxBytes: expectedSize + 4096,
          allowLocalhost: this.allowLocalhostForTest,
          onProgress: (curBytes) => {
            const now = Date.now();
            this.downloadedBytes = Math.min(
              overallTotalBytes,
              progressOffsetBytes + curBytes
            );
            this.progressPercent =
              overallTotalBytes > 0
                ? Math.min(99, Math.round((this.downloadedBytes / overallTotalBytes) * 100))
                : null;
            if (now - this.lastProgressEmitAt >= 90) {
              this.lastProgressEmitAt = now;
              this.emitUpdateState();
            }
          },
        });

        if (res.size !== expectedSize) {
          throw new Error(`文件字节数不匹配 (${res.size} != ${expectedSize})`);
        }
        if (res.sha256 !== expectedSha256.toLowerCase()) {
          throw new Error('下载文件 SHA-256 哈希与签名清单不一致');
        }
        if (rawFs.existsSync(destPath)) {
          await rawFs.promises.rm(destPath, { force: true });
        }
        await rawFs.promises.rename(attemptTmpPath, destPath);
        return attempt.label;
      } catch (err) {
        lastErr = err instanceof Error ? err.message : String(err);
        try {
          if (rawFs.existsSync(attemptTmpPath)) {
            await rawFs.promises.rm(attemptTmpPath, { force: true });
          }
        } catch {
          // ignore
        }
      }
    }

    throw new Error(lastErr);
  }

  private async executeDownloadUpdate(silent: boolean): Promise<UpdateActionResult> {
    if (!this.cachedManifest || !this.signatureVerified) {
      const checkRes = await this.executeCheckForUpdates(silent);
      if (!checkRes.ok || this.status === 'up-to-date' || this.status === 'downloaded') {
        return checkRes;
      }
    }

    const manifest = this.cachedManifest!;
    if (compareSemver(manifest.version, this.currentVersion) <= 0) {
      return {
        ok: true,
        message: `当前已是最新版本 (v${this.currentVersion})`,
        state: this.probeEngine.getSnapshot(),
      };
    }
    if (!this.isPackaged) {
      return {
        ok: false,
        message: '当前处于源码开发模式，为保护工作区文件不执行原地覆盖，请前往 Release 页面查看',
        state: this.probeEngine.getSnapshot(),
      };
    }

    const decision = await this.decideDeliveryAndMmdb(manifest);
    this.deliveryMode = decision.deliveryMode;
    this.includeMmdbUpdate = decision.includeMmdbUpdate;
    this.downloadTotalBytes = decision.expectedBytes;

    if (
      await this.isStagedUpdateAlreadyVerified(
        manifest,
        decision.deliveryMode,
        decision.includeMmdbUpdate
      )
    ) {
      this.status = 'downloaded';
      this.downloadedBytes = decision.expectedBytes;
      this.progressPercent = 100;
      this.lastError = null;
      this.emitUpdateState();
      return {
        ok: true,
        message: `新版本 v${manifest.version} 已就绪，点击重启即可完成更新`,
        state: this.probeEngine.getSnapshot(),
      };
    }

    this.status = 'downloading';
    this.downloadedBytes = 0;
    this.progressPercent = 0;
    this.lastError = null;
    this.emitUpdateState();

    const stageDir = this.getVersionStageDir(manifest.version);
    try {
      await rawFs.promises.rm(stageDir, { recursive: true, force: true });
      await rawFs.promises.mkdir(stageDir, { recursive: true });

      let channelUsed = this.viaChannel || '';

      if (decision.deliveryMode === 'asar') {
        const asarGzPath = path.join(stageDir, 'app-payload.gz.part');
        const stagedAsarPath = path.join(stageDir, 'app-payload.bin');

        channelUsed = await this.downloadSingleVerifiedFile(
          manifest.asar.url,
          asarGzPath,
          manifest.asar.size,
          manifest.asar.sha256,
          ASAR_DOWNLOAD_TIMEOUT_MS,
          0,
          decision.expectedBytes
        );

        await gunzipFileWithVerification(
          asarGzPath,
          stagedAsarPath,
          manifest.asar.uncompressedSize,
          manifest.asar.uncompressedSha256
        );
        await rawFs.promises.rm(asarGzPath, { force: true });
        await validateAsarArchiveHeader(stagedAsarPath);

        if (decision.includeMmdbUpdate && manifest.mmdb) {
          const mmdbGzPath = path.join(stageDir, 'mmdb.gz.part');
          const stagedMmdbPath = path.join(stageDir, 'geolite2-country.mmdb.staged');

          channelUsed = await this.downloadSingleVerifiedFile(
            manifest.mmdb.url,
            mmdbGzPath,
            manifest.mmdb.size,
            manifest.mmdb.sha256,
            ASAR_DOWNLOAD_TIMEOUT_MS,
            manifest.asar.size,
            decision.expectedBytes
          );

          await gunzipFileWithVerification(
            mmdbGzPath,
            stagedMmdbPath,
            manifest.mmdb.uncompressedSize,
            manifest.mmdb.uncompressedSha256
          );
          await rawFs.promises.rm(mmdbGzPath, { force: true });
        }

        const readyMeta: StagedReadyMetadata = {
          version: manifest.version,
          deliveryMode: 'asar',
          includeMmdbUpdate: decision.includeMmdbUpdate,
          asarSha256: manifest.asar.uncompressedSha256,
          mmdbSha256:
            decision.includeMmdbUpdate && manifest.mmdb
              ? manifest.mmdb.uncompressedSha256
              : undefined,
          verifiedAt: Date.now(),
        };
        await rawFs.promises.writeFile(
          path.join(stageDir, 'ready.json'),
          JSON.stringify(readyMeta, null, 2),
          'utf-8'
        );
      } else {
        const stagedZipPath = path.join(stageDir, 'release.zip.staged');
        channelUsed = await this.downloadSingleVerifiedFile(
          manifest.fullZip.url,
          stagedZipPath,
          manifest.fullZip.size,
          manifest.fullZip.sha256,
          FULL_ZIP_DOWNLOAD_TIMEOUT_MS,
          0,
          decision.expectedBytes
        );

        const readyMeta: StagedReadyMetadata = {
          version: manifest.version,
          deliveryMode: 'full-zip',
          includeMmdbUpdate: false,
          zipSha256: manifest.fullZip.sha256,
          verifiedAt: Date.now(),
        };
        await rawFs.promises.writeFile(
          path.join(stageDir, 'ready.json'),
          JSON.stringify(readyMeta, null, 2),
          'utf-8'
        );
      }

      this.viaChannel = channelUsed;
      this.status = 'downloaded';
      this.downloadedBytes = decision.expectedBytes;
      this.progressPercent = 100;
      this.lastError = null;
      this.lastAttemptAt = Date.now();
      this.lastAttemptSucceeded = true;
      this.probeEngine.recordExternalLog(
        'success',
        `✨ 新版本 v${manifest.version} 更新包已下载并通过 Ed25519 + SHA-256 验签，可点击右上角更新标志立即重启生效`,
        false
      );
      this.emitUpdateState();

      return {
        ok: true,
        message: `新版本 v${manifest.version} 已验签就绪，点击「立即重启并更新」即可生效`,
        state: this.probeEngine.getSnapshot(),
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.status = 'error';
      this.downloadedBytes = 0;
      this.progressPercent = 0;
      this.lastAttemptAt = Date.now();
      this.lastAttemptSucceeded = false;
      this.lastError = `更新包下载或验签失败：${msg}`;
      await rawFs.promises.rm(stageDir, { recursive: true, force: true }).catch(() => {});
      if (!silent) {
        this.probeEngine.recordExternalLog('warn', this.lastError, false);
      }
      this.emitUpdateState();
      return {
        ok: false,
        message: this.lastError,
        state: this.probeEngine.getSnapshot(),
      };
    }
  }

  public async applyDownloadedUpdate(
    allowTerminateClaude = false
  ): Promise<UpdateActionResult> {
    if (this.applyingInProgress || this.status === 'applying') {
      return {
        ok: false,
        message: '正在启动更新助手，请勿重复点击',
        state: this.probeEngine.getSnapshot(),
      };
    }

    if (!this.isPackaged) {
      return {
        ok: false,
        message: '开发调试环境不支持执行原地热替换',
        state: this.probeEngine.getSnapshot(),
      };
    }

    if (
      this.status !== 'downloaded' ||
      !this.cachedManifest ||
      !this.deliveryMode ||
      !this.signatureVerified
    ) {
      return {
        ok: false,
        message: '更新包尚未准备就绪，请先下载并完成签名校验',
        state: this.probeEngine.getSnapshot(),
      };
    }

    // 同步加锁并立即广播 applying 状态，彻底阻断双击或面板/托盘并发拉起多个更新脚本
    this.applyingInProgress = true;
    const manifest = this.cachedManifest;
    const mode = this.deliveryMode;
    const includeMmdb = this.includeMmdbUpdate;
    this.status = 'applying';
    this.lastError = null;
    this.emitUpdateState();

    try {
      const claudeActive = await this.probeEngine.isClaudeActiveForUpdateInterlock();
      if (claudeActive && !allowTerminateClaude) {
        this.applyingInProgress = false;
        this.status = 'downloaded';
        this.emitUpdateState();
        return {
          ok: false,
          message: 'Claude 正在受控守护运行中，请先确认终止 Claude 会话后再执行重启更新',
          state: this.probeEngine.getSnapshot(),
        };
      }

      const stillValid = await this.isStagedUpdateAlreadyVerified(
        manifest,
        mode,
        includeMmdb
      );
      if (!stillValid) {
        this.applyingInProgress = false;
        this.status = 'error';
        this.lastError = '本地暂存更新包完整性复核未通过，请重新下载更新';
        this.emitUpdateState();
        return {
          ok: false,
          message: this.lastError,
          state: this.probeEngine.getSnapshot(),
        };
      }

      if (claudeActive && allowTerminateClaude) {
        const termRes = await this.probeEngine.terminateClaudeManually();
        if (!termRes.ok) {
          this.applyingInProgress = false;
          this.status = 'downloaded';
          this.lastError = `安全终止 Claude 进程未完成，已取消本次重启更新：${termRes.message}`;
          this.emitUpdateState();
          return {
            ok: false,
            message: this.lastError,
            state: this.probeEngine.getSnapshot(),
          };
        }
      }

      const stageDir = this.getVersionStageDir(manifest.version);
      const stagedAsar = path.join(stageDir, 'app-payload.bin');
      const stagedMmdb =
        includeMmdb && manifest.mmdb
          ? path.join(stageDir, 'geolite2-country.mmdb.staged')
          : '';
      const stagedZip = path.join(stageDir, 'release.zip.staged');
      const targetPid = this.targetPidOverride ?? process.pid;
      // 将就绪握手标记置于 stageDir 之外，防止任何暂存目录清理操作误删握手文件导致误判超时回滚
      const readyHandshakeFile = path.join(
        this.stagingRootDir,
        `boot-ready-${manifest.version}-${targetPid}.ok`
      );

      const { encodedCommand, scriptGzB64 } = buildEncodedPowerShellLaunch();

      const updaterEnv: Record<string, string> = {
        GUARD_UPD_SCRIPT_GZ: scriptGzB64,
        GUARD_UPD_PID: String(targetPid),
        GUARD_UPD_MODE: mode,
        GUARD_UPD_APP_DIR: this.appDir,
        GUARD_UPD_RES_DIR: this.resourcesDir,
        GUARD_UPD_EXE_PATH: this.exePath,
        GUARD_UPD_FROM_VER: this.currentVersion,
        GUARD_UPD_TO_VER: manifest.version,
        GUARD_UPD_STAGED_ASAR: stagedAsar,
        GUARD_UPD_STAGED_MMDB: stagedMmdb,
        GUARD_UPD_STAGED_ZIP: stagedZip,
        GUARD_UPD_ASAR_SHA256:
          mode === 'asar' ? manifest.asar.uncompressedSha256.toLowerCase() : '',
        GUARD_UPD_MMDB_SHA256:
          mode === 'asar' && includeMmdb && manifest.mmdb
            ? manifest.mmdb.uncompressedSha256.toLowerCase()
            : '',
        GUARD_UPD_ZIP_SHA256:
          mode === 'full-zip' ? manifest.fullZip.sha256.toLowerCase() : '',
        GUARD_UPD_STAGE_DIR: stageDir,
        GUARD_UPD_READY_FILE: readyHandshakeFile,
        GUARD_UPD_BOOT_CHECK_MS: String(this.bootHandshakeTimeoutMs),
      };
      if (this.waitExitAttemptsOverride !== undefined) {
        updaterEnv.GUARD_UPD_WAIT_EXIT_ATTEMPTS = String(this.waitExitAttemptsOverride);
      }

      try {
        await this.probeEngine.prepareForUpdate();
        await launchDetachedWindowsUpdater(encodedCommand, updaterEnv);
      } catch (error) {
        await this.probeEngine.resumeAfterUpdateFailure();
        throw error;
      }

      const finalState = this.probeEngine.getSnapshot();
      if (this.quitTimer) {
        clearTimeout(this.quitTimer);
      }
      this.quitTimer = setTimeout(() => {
        this.quitTimer = null;
        if (this.onQuitForUpdate) {
          this.onQuitForUpdate();
        } else {
          this.probeEngine.stop();
          app.quit();
        }
      }, 120);

      return {
        ok: true,
        message: `正在重启并应用 v${manifest.version} 更新...`,
        state: finalState,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.applyingInProgress = false;
      this.status = 'downloaded';
      this.lastError = `启动更新助手脚本失败：${msg}`;
      this.emitUpdateState();
      return {
        ok: false,
        message: this.lastError,
        state: this.probeEngine.getSnapshot(),
      };
    }
  }

  public async openReleasePageInBrowser(): Promise<void> {
    const url = this.releasePageUrl;
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.hostname !== 'github.com') {
      throw new Error('不受信任的外部链接');
    }
    await shell.openExternal(url);
  }
}
