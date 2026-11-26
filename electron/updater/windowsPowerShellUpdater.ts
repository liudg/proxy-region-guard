import { spawn } from 'node:child_process';
import * as os from 'node:os';
import * as zlib from 'node:zlib';
import { getRawFs } from '../utils/rawFs';
import {
  quoteWindowsArg,
  quoteWindowsCommandLine,
  resolveWindowsPowerShellExe,
} from '../system/winShell';

export { resolveWindowsPowerShellExe, quoteWindowsArg, quoteWindowsCommandLine };

function buildDetachedTrampolineEncodedCommand(): string {
  // 注意：
  // 1) Windows 下直接对 powershell.exe 传 detached: true (DETACHED_PROCESS) 会使其因无控制台宿主立即静默退出 0；
  // 2) 通过短生命周期跳板以 ProcessStartInfo { UseShellExecute = true, WindowStyle = Hidden } 拉起内层 PowerShell：
  //    - ShellExecuteEx 在底层以 bInheritHandles = FALSE 创建新进程，彻底隔绝主进程打开的 asar/pak/dll/pipe 句柄继承锁死；
  //    - 规避 Start-Process -WorkingDirectory 对含 [ ] 方括号路径的通配符解析异常；
  //    - 为内层分配独立隐藏控制台，使更新器能够在主进程退出后继续运行。
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

export async function launchDetachedWindowsUpdater(
  encodedInnerCommand: string,
  updaterEnv: Record<string, string>
): Promise<void> {
  const rawFs = getRawFs();
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
    '$diagnosticFile = $env:GUARD_UPD_DIAGNOSTIC_FILE',
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
    'function Write-UpdateEvent([string]$Phase, [string]$Message) {',
    '  if (-not $diagnosticFile) { return }',
    '  $entry = @{ time = [DateTime]::UtcNow.ToString("o"); phase = $Phase; message = $Message; pid = $PID } | ConvertTo-Json -Compress',
    '  [System.IO.File]::AppendAllText($diagnosticFile, $entry + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))',
    '}',
    '',
    'trap { Write-UpdateEvent "updater-failed" $_.Exception.ToString(); exit 1 }',
    '',
    'function Stop-GuardProcess([System.Diagnostics.Process]$GuardProcess) {',
    '  if (-not $GuardProcess -or $GuardProcess.HasExited) { return }',
    '  $null = $GuardProcess.Handle',
    '  $actualPath = $GuardProcess.MainModule.FileName',
    '  if (-not [string]::Equals([System.IO.Path]::GetFullPath($actualPath), [System.IO.Path]::GetFullPath($exePath), [StringComparison]::OrdinalIgnoreCase)) {',
    '    throw "拒绝终止可执行文件路径不匹配的进程: $($GuardProcess.Id) $actualPath"',
    '  }',
    '  Write-UpdateEvent "stop-process" "终止卫士进程 PID=$($GuardProcess.Id)，路径=$actualPath"',
    '  $GuardProcess.Kill()',
    '  if (-not $GuardProcess.WaitForExit(4000)) { throw "卫士进程退出超时: $($GuardProcess.Id)" }',
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
    '  $targetProcess = Get-Process -Id $targetPid -ErrorAction SilentlyContinue',
    '  if ($targetProcess) {',
    '    $null = $targetProcess.Handle',
    '    Write-UpdateEvent "wait-old-process" "等待卫士进程退出 PID=$targetPid"',
    '    if (-not $targetProcess.WaitForExit($waitExitAttempts * 250)) { Stop-GuardProcess $targetProcess }',
    '    $targetProcess.Dispose()',
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
    '    Write-UpdateEvent "rollback-failed" $_.Exception.ToString()',
    '  }',
    '  return $allRestored',
    '}',
    '',
    'try {',
    '  Write-UpdateEvent "apply-start" "应用更新 $fromVer -> $toVer"',
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
    '  Write-UpdateEvent "apply-failed" $_.Exception.ToString()',
    '  Cleanup-ExtractArtifact',
    '  Cleanup-ReadyFile',
    '  $restoredOk = Restore-UpdateBackup',
    '  if ($restoredOk) { Write-UpdateEvent "rollback-complete" "已恢复版本 $fromVer" }',
    '  if ($restoredOk -and (-not $skipRelaunch) -and (Test-Path -LiteralPath $exePath)) {',
    '    try {',
    '      Start-GuardProcess -FilePath $exePath -WorkDir $appDir -RawArgs @("--update-rolled-back=$toVer", "--update-diagnostic-file=$diagnosticFile")',
    '    } catch { Write-UpdateEvent "rollback-launch-failed" $_.Exception.ToString(); throw }',
    '  }',
    '  exit 1',
    '}',
    '',
    'if (-not $skipRelaunch) {',
    '  Cleanup-ReadyFile',
    '  $relaunchArgs = @("--updated-from=$fromVer", "--update-diagnostic-file=$diagnosticFile")',
    '  if ($readyFile) {',
    '    $relaunchArgs += "--update-ready-file=$readyFile"',
    '  }',
    '  $proc = $null',
    '  $launchFailed = $false',
    '  try {',
    '    Write-UpdateEvent "launch-start" "启动版本 $toVer"',
    '    $proc = Start-GuardProcess -FilePath $exePath -WorkDir $appDir -RawArgs $relaunchArgs -PassThru',
    '  } catch {',
    '    $launchFailed = $true',
    '    Write-UpdateEvent "launch-failed" $_.Exception.ToString()',
    '  }',
    '  if ($launchFailed -or ($bootCheckMs -gt 0)) {',
    '    $bootReady = $false',
    '    if ((-not $launchFailed) -and ($bootCheckMs -gt 0)) {',
    '      $deadline = [DateTime]::UtcNow.AddMilliseconds($bootCheckMs)',
    '      while ([DateTime]::UtcNow -lt $deadline) {',
    '        if ($readyFile -and (Test-Path -LiteralPath $readyFile -PathType Leaf)) {',
    '          $bootReady = $true',
    '          break',
    '        }',
    '        if ($proc) {',
    '          $procExited = $false',
    '          $procExitCode = 0',
    '          $proc.Refresh()',
    '          $procExited = $proc.HasExited',
    '          if ($procExited) { $procExitCode = $proc.ExitCode }',
    '          if ($procExited) {',
    '            if ((-not $readyFile) -or ($procExitCode -ne 0)) { break }',
    '          }',
    '        }',
    '        Start-Sleep -Milliseconds 120',
    '      }',
    '      if ((-not $bootReady) -and $readyFile -and (Test-Path -LiteralPath $readyFile -PathType Leaf)) {',
    '        $bootReady = $true',
    '      }',
    '    }',
    '    $procExitedFinal = $false',
    '    $procExitCodeFinal = 0',
    '    if ($proc) {',
    '      $proc.Refresh()',
    '      $procExitedFinal = $proc.HasExited',
    '      if ($procExitedFinal) { $procExitCodeFinal = $proc.ExitCode }',
    '    }',
    '    $shouldRollback = if ($launchFailed) {',
    '      $true',
    '    } elseif ($readyFile) {',
    '      (-not $bootReady) -or ($procExitedFinal -and ($procExitCodeFinal -ne 0))',
    '    } else {',
    '      ($null -eq $proc) -or ($procExitedFinal -and ($procExitCodeFinal -ne 0))',
    '    }',
    '    if ($shouldRollback) {',
    '      if (-not $launchFailed) {',
    '        if ($procExitedFinal) { Write-UpdateEvent "boot-exit" "新版本退出，退出代码=$procExitCodeFinal" }',
    '        else { Write-UpdateEvent "boot-timeout" "等待启动就绪文件超时，等待时间=$bootCheckMs ms，文件=$readyFile" }',
    '      }',
    '      if ($proc -and (-not $procExitedFinal)) {',
    '        Stop-GuardProcess $proc',
    '      }',
    '      Cleanup-ExtractArtifact',
    '      Cleanup-ReadyFile',
    '      $restoredOk = Restore-UpdateBackup',
    '      if ($restoredOk) { Write-UpdateEvent "rollback-complete" "已恢复版本 $fromVer" }',
    '      if ($restoredOk -and (Test-Path -LiteralPath $exePath)) {',
    '        try {',
    '          Start-GuardProcess -FilePath $exePath -WorkDir $appDir -RawArgs @("--update-rolled-back=$toVer", "--update-diagnostic-file=$diagnosticFile")',
    '        } catch { Write-UpdateEvent "rollback-launch-failed" $_.Exception.ToString(); throw }',
    '      }',
    '      exit 2',
    '    }',
    '  }',
    '}',
    '',
    'Write-UpdateEvent "complete" "更新完成 $fromVer -> $toVer"',
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
