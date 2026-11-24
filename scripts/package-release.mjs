import { execFileSync } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as zlib from 'node:zlib';
import { build as viteBuild } from 'vite';
import { buildElectronMain } from './build-electron.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getArgValue(flag) {
  const idx = process.argv.indexOf(flag);
  if (idx >= 0 && idx + 1 < process.argv.length) {
    return process.argv[idx + 1];
  }
  return '';
}

function parseSemver(raw) {
  const cleaned = String(raw || '').trim().replace(/^v/i, '');
  const match =
    /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/.exec(cleaned);
  if (!match) {
    throw new Error(`无效的语义化版本号: "${raw}"`);
  }
  if (
    !/^(0|[1-9]\d*)$/.test(match[1]) ||
    !/^(0|[1-9]\d*)$/.test(match[2]) ||
    !/^(0|[1-9]\d*)$/.test(match[3])
  ) {
    throw new Error(`语义化版本号数字段禁止包含前导零: "${raw}"`);
  }

  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (
    !Number.isSafeInteger(major) ||
    !Number.isSafeInteger(minor) ||
    !Number.isSafeInteger(patch)
  ) {
    throw new Error(`语义化版本号超出安全整数范围: "${raw}"`);
  }

  let prerelease = [];
  if (match[4] !== undefined) {
    const parts = match[4].split('.');
    for (const part of parts) {
      if (!part || !/^[0-9A-Za-z-]+$/.test(part)) {
        throw new Error(`预发布版本号标识段非法: "${raw}"`);
      }
      if (/^\d+$/.test(part) && part.length > 1 && part.startsWith('0')) {
        throw new Error(`预发布纯数字标识段禁止前导零: "${raw}"`);
      }
    }
    prerelease = parts;
  }

  if (match[5] !== undefined) {
    const buildParts = match[5].split('.');
    if (buildParts.some((part) => !part || !/^[0-9A-Za-z-]+$/.test(part))) {
      throw new Error(`构建元数据标识段非法: "${raw}"`);
    }
  }

  const base = `${major}.${minor}.${patch}`;
  const normalized = prerelease.length > 0 ? `${base}-${prerelease.join('.')}` : base;
  return {
    normalized,
    windowsNumericVersion: base,
  };
}

function computeFileSha256Sync(filePath) {
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(filePath, 'r');
  const buf = Buffer.allocUnsafe(1024 * 1024);
  let total = 0;
  try {
    while (true) {
      const read = fs.readSync(fd, buf, 0, buf.length, null);
      if (read <= 0) break;
      total += read;
      hash.update(buf.subarray(0, read));
    }
  } finally {
    fs.closeSync(fd);
  }
  return {
    size: total,
    sha256: hash.digest('hex').toLowerCase(),
  };
}

function gzipFileSync(srcPath, destGzPath) {
  const rawBuf = fs.readFileSync(srcPath);
  const uncompressedSha256 = crypto
    .createHash('sha256')
    .update(rawBuf)
    .digest('hex')
    .toLowerCase();
  const gzBuf = zlib.gzipSync(rawBuf, { level: 9 });
  fs.writeFileSync(destGzPath, gzBuf);
  const sha256 = crypto.createHash('sha256').update(gzBuf).digest('hex').toLowerCase();
  return {
    size: gzBuf.length,
    sha256,
    uncompressedSize: rawBuf.length,
    uncompressedSha256,
  };
}

function buildUpdateSignaturePayload(manifest) {
  const mmdbPart = manifest.mmdb
    ? [
        manifest.mmdb.name,
        manifest.mmdb.url,
        manifest.mmdb.size,
        manifest.mmdb.sha256.toLowerCase(),
        manifest.mmdb.uncompressedSize,
        manifest.mmdb.uncompressedSha256.toLowerCase(),
      ].join('|')
    : 'none';

  return [
    'proxy-region-guard-update-v2',
    `schemaVersion=${manifest.schemaVersion}`,
    `version=${manifest.version.trim()}`,
    `publishedAt=${manifest.publishedAt.trim()}`,
    `electronVersion=${manifest.electronVersion.trim()}`,
    `minNativeShellVersion=${manifest.minNativeShellVersion.trim()}`,
    `mihomo=${manifest.mihomo.version}|${manifest.mihomo.sha256.toLowerCase()}`,
    `asar=${[
      manifest.asar.name,
      manifest.asar.url,
      manifest.asar.size,
      manifest.asar.sha256.toLowerCase(),
      manifest.asar.uncompressedSize,
      manifest.asar.uncompressedSha256.toLowerCase(),
    ].join('|')}`,
    `mmdb=${mmdbPart}`,
    `fullZip=${[
      manifest.fullZip.name,
      manifest.fullZip.url,
      manifest.fullZip.size,
      manifest.fullZip.sha256.toLowerCase(),
    ].join('|')}`,
    `notes=${String(manifest.notes ?? '').replace(/\r\n/g, '\n').trim()}`,
  ].join('\n');
}

function assertValidManifestFields(manifest) {
  if (/[\x00-\x20\x7f|]/.test(manifest.publishedAt)) {
    throw new Error('清单 publishedAt 包含非法字符');
  }
  for (const [key, entry] of [
    ['asar', manifest.asar],
    ['mmdb', manifest.mmdb],
    ['fullZip', manifest.fullZip],
  ]) {
    if (!entry) continue;
    if (!/^[A-Za-z0-9._-]+$/.test(entry.name) || entry.name.includes('..')) {
      throw new Error(`清单资产文件名非法 (${key}.name=${entry.name})`);
    }
    if (/[\x00-\x20\x7f|]/.test(entry.url) || !entry.url.startsWith('https://github.com/')) {
      throw new Error(`清单资产下载地址不受信任 (${key}.url=${entry.url})`);
    }
  }
}

function readBuiltinPublicKeyB64() {
  const manifestTsPath = path.join(rootDir, 'src', 'shared', 'updateManifest.ts');
  const content = fs.readFileSync(manifestTsPath, 'utf-8');
  const m = /export const BUILTIN_UPDATE_PUBLIC_KEY_SPKI_B64 =\s*'([^']+)';/.exec(content);
  return m ? m[1].trim() : '';
}

function resolveSigningPrivateKey() {
  const envKey = (process.env.UPDATE_SIGNING_PRIVATE_KEY || '').trim();
  if (envKey) return envKey;

  const localKeyFile = path.join(rootDir, '.keys', 'update-signing-private.key');
  if (fs.existsSync(localKeyFile)) {
    return fs.readFileSync(localKeyFile, 'utf-8').trim();
  }
  return '';
}

function parsePrivateKey(rawKey) {
  const keyObj = rawKey.includes('BEGIN PRIVATE KEY')
    ? crypto.createPrivateKey({ key: rawKey, format: 'pem' })
    : crypto.createPrivateKey({
        key: Buffer.from(rawKey.replace(/\s+/g, ''), 'base64'),
        format: 'der',
        type: 'pkcs8',
      });
  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw new Error(`签名私钥算法必须为 ed25519，实际为 ${String(keyObj.asymmetricKeyType)}`);
  }
  return keyObj;
}

function parsePublicKey(rawKey) {
  const keyObj = rawKey.includes('BEGIN PUBLIC KEY')
    ? crypto.createPublicKey({ key: rawKey, format: 'pem' })
    : crypto.createPublicKey({
        key: Buffer.from(rawKey.replace(/\s+/g, ''), 'base64'),
        format: 'der',
        type: 'spki',
      });
  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw new Error(`签名公钥算法必须为 ed25519，实际为 ${String(keyObj.asymmetricKeyType)}`);
  }
  return keyObj;
}

function resolveWindowsPowerShellExe() {
  const sysRoot = process.env.SystemRoot || process.env.WINDIR;
  if (sysRoot) {
    const candidate = path.join(sysRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return 'powershell.exe';
}

function buildWindowsPowerShellEnv(extra = {}) {
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => key.toLowerCase() !== 'psmodulepath')
  );
  return { ...env, ...extra };
}

function createUtf8ZipArchive(appOutDir, zipPath) {
  if (fs.existsSync(zipPath)) {
    fs.rmSync(zipPath, { force: true });
  }
  try {
    const psScript = [
      '$ErrorActionPreference = "Stop"',
      'Add-Type -AssemblyName System.IO.Compression.FileSystem',
      '[System.IO.Compression.ZipFile]::CreateFromDirectory($env:GUARD_ZIP_SRC, $env:GUARD_ZIP_DEST, [System.IO.Compression.CompressionLevel]::Optimal, $true, [System.Text.Encoding]::UTF8)',
    ].join('; ');

    execFileSync(
      resolveWindowsPowerShellExe(),
      ['-NoProfile', '-NonInteractive', '-Command', psScript],
      {
        stdio: 'inherit',
        windowsHide: true,
        env: buildWindowsPowerShellEnv({
          GUARD_ZIP_SRC: appOutDir,
          GUARD_ZIP_DEST: zipPath,
        }),
      }
    );
  } catch {
    if (fs.existsSync(zipPath)) {
      fs.rmSync(zipPath, { force: true });
    }
    execFileSync(
      'tar.exe',
      [
        '-a',
        '--options',
        'zip:hdrcharset=UTF-8',
        '-cf',
        path.basename(zipPath),
        path.basename(appOutDir),
      ],
      {
        cwd: path.dirname(zipPath),
        stdio: 'inherit',
        windowsHide: true,
      }
    );
  }
}

async function stampExeResourcesWithRetry(
  destExe,
  icoPath,
  winNumericVersion,
  productVersion,
  maxAttempts = 3
) {
  const rceditMod = await import('rcedit');
  const rcedit = rceditMod.rcedit || rceditMod.default;
  if (typeof rcedit !== 'function') {
    throw new Error('rcedit 模块未正确导出可执行函数');
  }

  let lastErr = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await rcedit(destExe, {
        icon: icoPath,
        'requested-execution-level': 'requireAdministrator',
        'version-string': {
          ProductName: '代理地区卫士',
          FileDescription: '代理地区卫士 - 代理 IP 地区变更检测工具',
          CompanyName: 'Proxy Region Guard',
          InternalName: 'ProxyRegionGuard',
          OriginalFilename: '代理地区卫士.exe',
        },
        'file-version': winNumericVersion,
        'product-version': productVersion,
      });
      return;
    } catch (err) {
      lastErr = err;
      if (attempt < maxAttempts) {
        // 等待杀毒软件实时文件扫描释放句柄后重试
        await sleep(350 * attempt);
      }
    }
  }
  throw lastErr;
}

function isFileLockedOnWindows(filePath) {
  if (!fs.existsSync(filePath)) return false;
  try {
    const fd = fs.openSync(filePath, 'r+');
    fs.closeSync(fd);
    return false;
  } catch {
    return true;
  }
}

const CLAUDE_PROCESS_NAMES = new Set([
  'claude.exe',
  'claude-desktop.exe',
  'claude-ssh-proxy.exe',
  'claude-ssh-broker.exe',
  'claude-ssh-askpass.exe',
  'claude-make-data-folder.exe',
  'cowork-svc.exe',
]);

function isClaudeDesktopRunning() {
  if (process.platform !== 'win32') return false;
  try {
    const out = execFileSync('tasklist.exe', ['/FO', 'CSV', '/NH'], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
      timeout: 4000,
    });
    for (const rawLine of out.split(/\r?\n/)) {
      const m = /^"([^"]+)"/.exec(rawLine.trim());
      if (m && CLAUDE_PROCESS_NAMES.has(m[1].trim().toLowerCase())) {
        return true;
      }
    }
  } catch {
    // ignore
  }
  return false;
}

function findPidsInDirectory(targetDir) {
  if (process.platform !== 'win32' || !fs.existsSync(targetDir)) return [];
  try {
    const ps = [
      '$prefix = (Get-Item -LiteralPath $env:GUARD_TARGET_DIR -Force).FullName.TrimEnd("\\") + "\\"',
      'Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and ([System.IO.Path]::GetFullPath($_.Path)).StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { $_.Id }',
    ].join('; ');
    const out = execFileSync(
      resolveWindowsPowerShellExe(),
      ['-NoProfile', '-NonInteractive', '-Command', ps],
      {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'ignore'],
        windowsHide: true,
        timeout: 5000,
        env: buildWindowsPowerShellEnv({ GUARD_TARGET_DIR: targetDir }),
      }
    );
    return out
      .split(/\r?\n/)
      .map((s) => Number(s.trim()))
      .filter((n) => Number.isInteger(n) && n > 0 && n !== process.pid);
  } catch {
    return [];
  }
}

async function stopGuardInDirectory(appOutDir, destExe) {
  const pids = findPidsInDirectory(appOutDir);
  for (const pid of pids) {
    try {
      execFileSync('taskkill.exe', ['/F', '/T', '/PID', String(pid)], {
        stdio: 'ignore',
        windowsHide: true,
        timeout: 4000,
      });
    } catch {
      // 可能子进程已随父进程退出或需提权
    }
  }

  for (let i = 0; i < 12; i++) {
    if (!isFileLockedOnWindows(destExe) && findPidsInDirectory(appOutDir).length === 0) {
      return;
    }
    await sleep(200);
  }

  // 若当前终端非管理员而旧版卫士以管理员运行导致句柄未释放，调用 RunAs 精准结束原目录进程
  if (isFileLockedOnWindows(destExe)) {
    try {
      const innerCmd = [
        `$prefix = ([System.IO.Path]::GetFullPath('${appOutDir.replace(/'/g, "''")}')).TrimEnd('\\') + '\\'`,
        'Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and ([System.IO.Path]::GetFullPath($_.Path)).StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { & taskkill.exe /F /T /PID $_.Id *> $null; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }',
      ].join('; ');
      const encoded = Buffer.from(innerCmd, 'utf16le').toString('base64');
      const outerPs = `Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-NonInteractive','-WindowStyle','Hidden','-EncodedCommand','${encoded}') -Verb RunAs -WindowStyle Hidden -Wait`;
      execFileSync(resolveWindowsPowerShellExe(), ['-NoProfile', '-NonInteractive', '-Command', outerPs], {
        stdio: 'ignore',
        windowsHide: true,
        timeout: 15000,
        env: buildWindowsPowerShellEnv(),
      });
    } catch {
      // 下方做最终文件锁核验
    }

    for (let i = 0; i < 12; i++) {
      if (!isFileLockedOnWindows(destExe)) return;
      await sleep(200);
    }
  }

  if (isFileLockedOnWindows(destExe)) {
    throw new Error(
      `无法释放原目录中的「${destExe}」文件占用，请先在托盘退出代理地区卫士后重试。`
    );
  }
}

async function renameWithRetry(srcPath, destPath, maxAttempts = 10, delayMs = 200) {
  let lastErr = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      fs.renameSync(srcPath, destPath);
      return;
    } catch (err) {
      lastErr = err;
      if (attempt < maxAttempts) {
        await sleep(delayMs);
      }
    }
  }
  throw lastErr;
}

function moveStagedFileSync(stagedPath, finalPath) {
  if (fs.existsSync(finalPath)) {
    fs.rmSync(finalPath, { force: true, maxRetries: 3, retryDelay: 100 });
  }
  fs.renameSync(stagedPath, finalPath);
}

function relaunchGuardInTray(appOutDir, destExe) {
  const ps =
    "Start-Process -FilePath $env:GUARD_RELAUNCH_EXE -WorkingDirectory $env:GUARD_RELAUNCH_CWD -ArgumentList @('--silent-tray')";
  execFileSync(
    resolveWindowsPowerShellExe(),
    ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', ps],
    {
      stdio: 'ignore',
      windowsHide: true,
      timeout: 10000,
      env: buildWindowsPowerShellEnv({
        GUARD_RELAUNCH_EXE: destExe,
        GUARD_RELAUNCH_CWD: appOutDir,
      }),
    }
  );
}

async function main() {
  const requireSignature = process.argv.includes('--require-signature');
  const noKillRunning = process.argv.includes('--no-kill-running');
  const allowKillClaude = process.argv.includes('--allow-kill-claude');
  const noRelaunch = process.argv.includes('--no-relaunch');
  const isCiEnv =
    process.env.CI === 'true' ||
    process.env.GITHUB_ACTIONS === 'true' ||
    process.env.GUARD_CI === '1';

  const rootPkg = JSON.parse(
    fs.readFileSync(path.join(rootDir, 'package.json'), 'utf-8')
  );
  const rawVersion = getArgValue('--version') || rootPkg.version;
  const { normalized: appVersion, windowsNumericVersion } = parseSemver(rawVersion);

  const rawMinShellVer =
    getArgValue('--min-shell-version') || rootPkg.minNativeShellVersion || '1.0.0';
  const { normalized: minNativeShellVersion } = parseSemver(rawMinShellVer);

  const repoSlug =
    getArgValue('--repo') ||
    process.env.GITHUB_REPOSITORY ||
    'liudg/proxy-region-guard';

  const outDirArg = getArgValue('--out-dir');
  const releaseRoot = outDirArg ? path.resolve(outDirArg) : path.join(rootDir, 'release');
  fs.mkdirSync(releaseRoot, { recursive: true });

  const notesFileArg = getArgValue('--notes-file');
  const resolvedNotesFile = notesFileArg ? path.resolve(notesFileArg) : '';
  let releaseNotes = process.env.RELEASE_NOTES || '';
  if (resolvedNotesFile && fs.existsSync(resolvedNotesFile)) {
    releaseNotes = fs.readFileSync(resolvedNotesFile, 'utf-8');
  }

  const icoPath = path.join(rootDir, 'build', 'icon.ico');
  if (!fs.existsSync(icoPath)) {
    throw new Error(`未找到应用图标资源: ${icoPath}`);
  }

  const electronDistDir = path.join(rootDir, 'node_modules', 'electron', 'dist');
  const electronVersionFile = path.join(electronDistDir, 'version');
  const electronVersion = fs.existsSync(electronVersionFile)
    ? parseSemver(fs.readFileSync(electronVersionFile, 'utf-8')).normalized
    : parseSemver(rootPkg.devDependencies?.electron?.replace(/^[^\d]*/, '') || '33.2.1').normalized;

  const buildStagingRoot = path.join(releaseRoot, `.build-staging-${process.pid}`);
  if (fs.existsSync(buildStagingRoot)) {
    fs.rmSync(buildStagingRoot, { recursive: true, force: true });
  }
  fs.mkdirSync(buildStagingRoot, { recursive: true });

  try {
    if (!releaseNotes) {
      const autoNotesPath = path.join(buildStagingRoot, 'auto-release-notes.md');
      try {
        execFileSync(
          process.execPath,
          [
            path.join(__dirname, 'generate-release-notes.mjs'),
            '--tag',
            `v${appVersion}`,
            '--out',
            autoNotesPath,
          ],
          { cwd: rootDir, stdio: 'ignore', windowsHide: true }
        );
        if (fs.existsSync(autoNotesPath)) {
          releaseNotes = fs.readFileSync(autoNotesPath, 'utf-8');
        }
      } catch {
        // ignore fallback empty notes
      }
    }

    console.log(`1/7 正在编译前后端生产代码 (v${appVersion}, Electron ${electronVersion})...`);
    await buildElectronMain();
    await viteBuild({
      root: rootDir,
      configFile: path.join(rootDir, 'vite.config.ts'),
    });

    console.log('2/7 正在暂存区组装 Windows x64 正式发布目录...');
    const stagedAppDir = path.join(buildStagingRoot, '代理地区卫士-win32-x64');
    fs.mkdirSync(stagedAppDir, { recursive: true });

    copyDirFiltered(electronDistDir, stagedAppDir);

    // 移除默认占位应用包
    const defaultAsar = path.join(stagedAppDir, 'resources', 'default_app.asar');
    if (fs.existsSync(defaultAsar)) {
      fs.rmSync(defaultAsar, { force: true });
    }

    // 精简多语言包，仅保留简体中文与美式英语，减小约 35MB 体积
    const localesDir = path.join(stagedAppDir, 'locales');
    if (fs.existsSync(localesDir)) {
      const keepLocales = new Set(['zh-CN.pak', 'en-US.pak']);
      for (const f of fs.readdirSync(localesDir)) {
        if (!keepLocales.has(f)) {
          fs.rmSync(path.join(localesDir, f), { force: true });
        }
      }
    }

    console.log('3/7 正在打包应用核心代码 (app.asar) 与离线 GeoIP 数据库...');
    const stageAsarSrcDir = path.join(buildStagingRoot, '.stage-app');
    fs.mkdirSync(path.join(stageAsarSrcDir, 'dist-electron'), { recursive: true });

    const prodPkg = {
      name: rootPkg.name || 'proxy-region-guard',
      productName: '代理地区卫士',
      version: appVersion,
      description: rootPkg.description || 'Windows 代理 IP 地区变更实时检测与强提醒工具',
      main: 'dist-electron/main.js',
    };
    fs.writeFileSync(
      path.join(stageAsarSrcDir, 'package.json'),
      JSON.stringify(prodPkg, null, 2),
      'utf-8'
    );

    fs.copyFileSync(
      path.join(rootDir, 'dist-electron', 'main.js'),
      path.join(stageAsarSrcDir, 'dist-electron', 'main.js')
    );
    fs.copyFileSync(
      path.join(rootDir, 'dist-electron', 'preload.js'),
      path.join(stageAsarSrcDir, 'dist-electron', 'preload.js')
    );
    copyDirFiltered(path.join(rootDir, 'dist'), path.join(stageAsarSrcDir, 'dist'));

    const targetResourcesDir = path.join(stagedAppDir, 'resources');
    const coreDir = path.join(rootDir, 'resources', 'mihomo');
    const coreManifest = JSON.parse(fs.readFileSync(path.join(coreDir, 'manifest.json'), 'utf8'));
    if (computeFileSha256Sync(path.join(coreDir, 'guard-mihomo.exe')).sha256 !== coreManifest.sha256) {
      throw new Error('私有 Mihomo 文件校验失败，请执行 npm run prepare:core');
    }
    const bundledCoreDir = path.join(targetResourcesDir, 'mihomo');
    fs.mkdirSync(bundledCoreDir, { recursive: true });
    for (const file of ['guard-mihomo.exe', 'manifest.json']) fs.copyFileSync(path.join(coreDir, file), path.join(bundledCoreDir, file));
    const asarOutPath = path.join(targetResourcesDir, 'app.asar');
    const asar = await import('@electron/asar');
    await asar.createPackage(stageAsarSrcDir, asarOutPath);
    fs.rmSync(stageAsarSrcDir, { recursive: true, force: true });

    const mmdbSrc = path.join(rootDir, 'resources', 'geolite2-country.mmdb');
    if (!fs.existsSync(mmdbSrc)) {
      throw new Error(`未找到离线 GeoIP 数据库: ${mmdbSrc}`);
    }
    const mmdbOutPath = path.join(targetResourcesDir, 'geolite2-country.mmdb');
    fs.copyFileSync(mmdbSrc, mmdbOutPath);

    // 写入原生壳元数据，用于热更时精确识别二进制壳与基座兼容性
    fs.writeFileSync(
      path.join(targetResourcesDir, 'shell-meta.json'),
      JSON.stringify(
        {
          shellVersion: appVersion,
          electronVersion,
        },
        null,
        2
      ),
      'utf-8'
    );

    console.log('4/7 正在写入可执行文件名称与图标元数据...');
    const stagedSrcExe = path.join(stagedAppDir, 'electron.exe');
    const stagedDestExe = path.join(stagedAppDir, '代理地区卫士.exe');
    fs.renameSync(stagedSrcExe, stagedDestExe);
    await stampExeResourcesWithRetry(
      stagedDestExe,
      icoPath,
      windowsNumericVersion,
      appVersion
    );

    const zipName = `ProxyRegionGuard-v${appVersion}-win32-x64.zip`;
    const stagedZipPath = path.join(buildStagingRoot, zipName);
    console.log(`5/7 正在压缩生成全量分发包 (${zipName}) 与增量热更包...`);
    createUtf8ZipArchive(stagedAppDir, stagedZipPath);

    const asarGzName = `app-v${appVersion}.asar.gz`;
    const stagedAsarGzPath = path.join(buildStagingRoot, asarGzName);
    const asarStats = gzipFileSync(asarOutPath, stagedAsarGzPath);

    const mmdbGzName = 'geolite2-country.mmdb.gz';
    const stagedMmdbGzPath = path.join(buildStagingRoot, mmdbGzName);
    const mmdbStats = gzipFileSync(mmdbOutPath, stagedMmdbGzPath);

    const zipStats = computeFileSha256Sync(stagedZipPath);

    console.log('6/7 正在生成更新元数据清单 (latest.json) 与 Ed25519 数字签名...');
    const releaseDownloadBase = `https://github.com/${repoSlug}/releases/download/v${appVersion}`;

    const unsignedManifest = {
      schemaVersion: 2,
      version: appVersion,
      publishedAt: new Date().toISOString(),
      electronVersion,
      minNativeShellVersion,
      mihomo: coreManifest,
      notes: String(releaseNotes || '').replace(/\r\n/g, '\n').trim(),
      asar: {
        name: asarGzName,
        url: `${releaseDownloadBase}/${asarGzName}`,
        size: asarStats.size,
        sha256: asarStats.sha256,
        uncompressedSize: asarStats.uncompressedSize,
        uncompressedSha256: asarStats.uncompressedSha256,
      },
      mmdb: {
        name: mmdbGzName,
        url: `${releaseDownloadBase}/${mmdbGzName}`,
        size: mmdbStats.size,
        sha256: mmdbStats.sha256,
        uncompressedSize: mmdbStats.uncompressedSize,
        uncompressedSha256: mmdbStats.uncompressedSha256,
      },
      fullZip: {
        name: zipName,
        url: `${releaseDownloadBase}/${zipName}`,
        size: zipStats.size,
        sha256: zipStats.sha256,
      },
    };

    assertValidManifestFields(unsignedManifest);

    let signature = '';
    const privateKeyText = resolveSigningPrivateKey();
    if (privateKeyText) {
      const privKey = parsePrivateKey(privateKeyText);
      const payloadBuf = Buffer.from(buildUpdateSignaturePayload(unsignedManifest), 'utf-8');
      signature = crypto.sign(null, payloadBuf, privKey).toString('base64');

      const builtinPubKeyB64 = readBuiltinPublicKeyB64();
      if (!builtinPubKeyB64) {
        throw new Error('未在 src/shared/updateManifest.ts 中找到内置公钥常量');
      }
      const pubKey = parsePublicKey(builtinPubKeyB64);
      const sigBuf = Buffer.from(signature, 'base64');
      if (sigBuf.length !== 64) {
        throw new Error(`生成的 Ed25519 签名长度异常 (${sigBuf.length} != 64)`);
      }
      const reparsedManifest = JSON.parse(
        JSON.stringify({ ...unsignedManifest, signature })
      );
      const verifyPayload = Buffer.from(
        buildUpdateSignaturePayload(reparsedManifest),
        'utf-8'
      );
      const ok = crypto.verify(null, verifyPayload, pubKey, sigBuf);
      if (!ok) {
        throw new Error(
          'Ed25519 签名自检不匹配：当前提供的私钥与 src/shared/updateManifest.ts 中的内置公钥不一致！请核对 UPDATE_SIGNING_PRIVATE_KEY。'
        );
      }
      console.log('🔒 已完成 Ed25519 签名并通过内置公钥结构化闭环自检！');
    } else if (requireSignature) {
      throw new Error(
        '未配置 UPDATE_SIGNING_PRIVATE_KEY 私钥，无法生成受信任的签名更新清单！请在 GitHub Secrets 中配置私钥。'
      );
    } else {
      console.warn(
        '⚠️ 未检测到本地私钥 (.keys/update-signing-private.key) 或 UPDATE_SIGNING_PRIVATE_KEY 环境变量，latest.json 未签名（仅供本地测试）。'
      );
    }

    const finalManifest = {
      ...unsignedManifest,
      signature,
    };
    const stagedLatestJsonPath = path.join(buildStagingRoot, 'latest.json');
    fs.writeFileSync(stagedLatestJsonPath, JSON.stringify(finalManifest, null, 2) + '\n', 'utf-8');

    const appOutDir = path.join(releaseRoot, '代理地区卫士-win32-x64');
    const destExe = path.join(appOutDir, '代理地区卫士.exe');
    const zipPath = path.join(releaseRoot, zipName);
    const asarGzPath = path.join(releaseRoot, asarGzName);
    const mmdbGzPath = path.join(releaseRoot, mmdbGzName);
    const latestJsonPath = path.join(releaseRoot, 'latest.json');

    console.log('7/7 正在原地原子切换正式发布目录并清理旧产物...');
    const wasGuardRunning =
      isFileLockedOnWindows(destExe) || findPidsInDirectory(appOutDir).length > 0;

    if (wasGuardRunning) {
      if (noKillRunning) {
        throw new Error(
          `目标输出目录中的「${destExe}」正在运行被占用（已传 --no-kill-running 禁止自动关停）。`
        );
      }
      if (isClaudeDesktopRunning() && !allowKillClaude) {
        throw new Error(
          '检测到 Claude Desktop 当前正在运行！为防止原地重启卫士导致 Claude 短暂脱离保护或中断会话，已取消替换原目录（请先关闭 Claude 后再执行 npm run package，或附加 --allow-kill-claude）。'
        );
      }
      console.log('   ↻ 检测到原目录代理地区卫士正在运行，正在优雅停机以执行毫秒级热替换...');
      await stopGuardInDirectory(appOutDir, destExe);
    }

    const backupDir = path.join(releaseRoot, `代理地区卫士-win32-x64.old-${process.pid}`);
    if (fs.existsSync(backupDir)) {
      fs.rmSync(backupDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    }

    const hadExistingDir = fs.existsSync(appOutDir);
    if (hadExistingDir) {
      await renameWithRetry(appOutDir, backupDir);
    }

    try {
      await renameWithRetry(stagedAppDir, appOutDir);
    } catch (swapErr) {
      if (hadExistingDir && fs.existsSync(backupDir) && !fs.existsSync(appOutDir)) {
        try {
          await renameWithRetry(backupDir, appOutDir, 5, 150);
        } catch {
          // ignore restore failure
        }
      }
      throw swapErr;
    }

    moveStagedFileSync(stagedZipPath, zipPath);
    moveStagedFileSync(stagedAsarGzPath, asarGzPath);
    moveStagedFileSync(stagedMmdbGzPath, mmdbGzPath);
    moveStagedFileSync(stagedLatestJsonPath, latestJsonPath);

    if (fs.existsSync(backupDir)) {
      fs.rmSync(backupDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
    }

    // 默认构建至项目 release/ 目录时，自动清理历史版本残留包与无用目录，保持 release/ 干净整洁
    if (!outDirArg) {
      const keepEntries = new Set([
        '代理地区卫士-win32-x64',
        zipName,
        asarGzName,
        mmdbGzName,
        'latest.json',
        path.basename(buildStagingRoot),
      ]);
      if (
        resolvedNotesFile &&
        path.dirname(resolvedNotesFile).toLowerCase() === releaseRoot.toLowerCase()
      ) {
        keepEntries.add(path.basename(resolvedNotesFile));
      }

      for (const entry of fs.readdirSync(releaseRoot)) {
        if (!keepEntries.has(entry)) {
          fs.rmSync(path.join(releaseRoot, entry), {
            recursive: true,
            force: true,
            maxRetries: 3,
            retryDelay: 100,
          });
        }
      }
    }

    let relaunched = false;
    if (wasGuardRunning && !outDirArg && !noRelaunch && !isCiEnv) {
      try {
        relaunchGuardInTray(appOutDir, destExe);
        await sleep(600);
        relaunched = true;
      } catch (relaunchErr) {
        console.warn('⚠️ 自动重新拉起代理地区卫士失败，请手动通过快捷方式启动:', relaunchErr);
      }
    }

    console.log(
      [
        '\n✅ 正式发布包与增量更新资产构建完成！',
        `   程序目录:   ${appOutDir}${relaunched ? ' (已自动静默重开至系统托盘)' : ''}`,
        `   全量压缩包: ${zipPath} (${(zipStats.size / (1024 * 1024)).toFixed(2)} MB)`,
        `   增量热更包: ${asarGzPath} (${(asarStats.size / 1024).toFixed(1)} KB)`,
        `   离线IP库包: ${mmdbGzPath} (${(mmdbStats.size / (1024 * 1024)).toFixed(2)} MB)`,
        `   更新清单:   ${latestJsonPath}`,
      ].join('\n')
    );
  } finally {
    if (fs.existsSync(buildStagingRoot)) {
      fs.rmSync(buildStagingRoot, {
        recursive: true,
        force: true,
        maxRetries: 5,
        retryDelay: 150,
      });
    }
  }
}

function copyDirFiltered(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (entry.name.endsWith('.pdb') || entry.name === 'LICENSES.chromium.html') {
      continue;
    }
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDirFiltered(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

main().catch((err) => {
  console.error('\n❌ 打包失败:', err);
  process.exit(1);
});
