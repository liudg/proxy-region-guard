import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import * as crypto from 'node:crypto';
import { once } from 'node:events';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { ClashMonitor } from '../electron/clashMonitor';
import { ConfigStore } from '../electron/configStore';
import { GeoIpService } from '../electron/geoipService';
import {
  downloadFileViaProxy,
  requestTextViaProxy,
  resolveSafeRedirectUrl,
} from '../electron/netClient';
import { ProbeEngine } from '../electron/probeEngine';
import {
  computeFileSha256,
  getRawFs,
  parseEd25519PrivateKey,
  parseEd25519PublicKey,
  signUpdateManifest,
  validateAsarArchiveHeader,
  verifyUpdateManifestSignature,
} from '../electron/updateCrypto';
import {
  buildEncodedPowerShellLaunch,
  UpdaterService,
} from '../electron/updaterService';
import {
  BUILTIN_UPDATE_PUBLIC_KEY_SPKI_B64,
  compareSemver,
  parseSemver,
  UpdateReleaseManifest,
  validateUpdateManifestStructure,
} from '../src/shared/updateManifest';

async function createRealTestAsar(workDir: string, version: string): Promise<string> {
  const srcDir = path.join(workDir, `asar-src-${version}`);
  const outAsar = path.join(workDir, `app-${version}.asar`);
  fs.mkdirSync(srcDir, { recursive: true });
  fs.writeFileSync(
    path.join(srcDir, 'package.json'),
    JSON.stringify({ name: 'proxy-region-guard', version, main: 'index.js' }, null, 2),
    'utf-8'
  );
  fs.writeFileSync(
    path.join(srcDir, 'index.js'),
    `module.exports = "${version}";\n`,
    'utf-8'
  );

  const nodeBin = process.env.GUARD_TEST_NODE || 'node';
  execFileSync(
    nodeBin,
    [
      '--input-type=module',
      '-e',
      'import * as asar from "@electron/asar"; await asar.createPackage(process.argv[1], process.argv[2]);',
      srcDir,
      outAsar,
    ],
    {
      cwd: process.cwd(),
      windowsHide: true,
    }
  );
  return outAsar;
}

function createUtf8ZipForTest(sourceDir: string, destZipPath: string): void {
  const ps = [
    '$ErrorActionPreference = "Stop"',
    'Add-Type -AssemblyName System.IO.Compression.FileSystem',
    '[System.IO.Compression.ZipFile]::CreateFromDirectory($env:TEST_ZIP_SRC, $env:TEST_ZIP_DEST, [System.IO.Compression.CompressionLevel]::Fastest, $true, [System.Text.Encoding]::UTF8)',
  ].join('; ');
  execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], {
    windowsHide: true,
    env: {
      ...process.env,
      TEST_ZIP_SRC: sourceDir,
      TEST_ZIP_DEST: destZipPath,
    },
  });
}

export async function runUpdaterRegressionTests(
  baseTempDir: string,
  geo: GeoIpService
): Promise<void> {
  const root = path.join(baseTempDir, 'updater-suite');
  fs.mkdirSync(root, { recursive: true });

  // 1. SemVer 严格规范、密钥算法断言与重定向安全策略校验
  assert.equal(compareSemver('1.0.0', '1.0.0'), 0);
  assert.equal(compareSemver('1.0.1', '1.0.0'), 1);
  assert.equal(compareSemver('1.1.0', '1.0.9'), 1);
  assert.equal(compareSemver('2.0.0', '1.99.99'), 1);
  assert.equal(compareSemver('1.1.0-beta.1', '1.1.0'), -1);
  assert.equal(compareSemver('1.1.0-beta.2', '1.1.0-beta.1'), 1);
  assert.equal(parseSemver('01.0.0'), null, '应拒绝数字段含前导零的非标准版本号');
  assert.equal(parseSemver('1.0.0-01'), null, '应拒绝纯数字预发布段含前导零的版本号');
  assert.equal(parseSemver('1.0.0-beta..1'), null, '应拒绝包含空预发布标识段的版本号');
  assert.ok(BUILTIN_UPDATE_PUBLIC_KEY_SPKI_B64.length > 30, '内置 Ed25519 公钥必须已生成写入');

  // 非 Ed25519 密钥类型必须被显式拒绝
  const ecPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const ecPubPem = ecPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const ecPrivPem = ecPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  assert.throws(() => parseEd25519PublicKey(ecPubPem), /ed25519/);
  assert.throws(() => parseEd25519PrivateKey(ecPrivPem), /ed25519/);

  // 重定向降级与内网 SSRF 拦截校验
  assert.throws(
    () =>
      resolveSafeRedirectUrl(
        new URL('https://gh-proxy.com/https://github.com/a/b'),
        'http://github.com/a/b',
        false
      ),
    /降级/
  );
  assert.throws(
    () =>
      resolveSafeRedirectUrl(
        new URL('https://gh-proxy.com/https://github.com/a/b'),
        'https://127.0.0.1:9097/configs',
        false
      ),
    /本机或内网/
  );
  assert.throws(
    () =>
      resolveSafeRedirectUrl(
        new URL('http://127.0.0.1:8080/a'),
        'http://192.168.1.1/admin',
        true
      ),
    /本机或内网/
  );

  // 2. 生成测试用 Ed25519 密钥对与真实 ASAR / MMDB / ZIP 包
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const privB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');

  const rawFs = getRawFs();
  const v100Asar = await createRealTestAsar(root, '1.0.0');
  const v110Asar = await createRealTestAsar(root, '1.1.0');
  await validateAsarArchiveHeader(v110Asar);

  const v110AsarRaw = rawFs.readFileSync(v110Asar);
  const v110AsarGz = zlib.gzipSync(v110AsarRaw, { level: 9 });

  const oldMmdbRaw = Buffer.from('OLD-MMDB-BINARY-PAYLOAD-V1');
  const newMmdbRaw = Buffer.from('NEW-MMDB-BINARY-PAYLOAD-V2-UPDATED');
  const newMmdbGz = zlib.gzipSync(newMmdbRaw, { level: 9 });

  const zipSourceDir = path.join(root, '代理地区卫士-win32-x64');
  fs.mkdirSync(path.join(zipSourceDir, 'resources'), { recursive: true });
  rawFs.copyFileSync(v110Asar, path.join(zipSourceDir, 'resources', 'app.asar'));
  fs.writeFileSync(path.join(zipSourceDir, 'resources', 'geolite2-country.mmdb'), newMmdbRaw);
  fs.writeFileSync(
    path.join(zipSourceDir, 'resources', 'shell-meta.json'),
    JSON.stringify({ shellVersion: '2.0.0', electronVersion: '34.0.0' }),
    'utf-8'
  );
  fs.writeFileSync(path.join(zipSourceDir, 'ffmpeg.dll'), 'NEW-FFMPEG-DLL-V34', 'utf-8');
  fs.writeFileSync(
    path.join(zipSourceDir, 'v8_context_snapshot.bin'),
    'NEW-V8-SNAPSHOT-V34',
    'utf-8'
  );
  fs.writeFileSync(path.join(zipSourceDir, 'extra-new-v34.dll'), 'EXTRA-V34-ONLY', 'utf-8');
  fs.writeFileSync(path.join(zipSourceDir, '代理地区卫士.exe'), 'DUMMY-EXE-V110', 'utf-8');
  const fullZipPath = path.join(root, 'ProxyRegionGuard-v1.1.0-win32-x64.zip');
  createUtf8ZipForTest(zipSourceDir, fullZipPath);
  const fullZipRaw = fs.readFileSync(fullZipPath);

  const sha256Hex = (buf: Buffer) =>
    crypto.createHash('sha256').update(buf).digest('hex').toLowerCase();

  let servedManifestJson = '';
  let failManifestNetwork = false;
  let manifestDelayMs = 0;
  let corruptAsarResponse = false;
  let mmdbDownloadCount = 0;

  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url || '/', 'http://127.0.0.1').pathname;
    if (pathname === '/latest.json') {
      if (failManifestNetwork) {
        res.writeHead(503);
        res.end('service unavailable');
        return;
      }
      const respond = () => {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(servedManifestJson);
      };
      if (manifestDelayMs > 0) {
        setTimeout(respond, manifestDelayMs);
      } else {
        respond();
      }
      return;
    }
    if (pathname === '/redirect-latest.json') {
      res.writeHead(302, { Location: '/latest.json' });
      res.end();
      return;
    }
    if (pathname === '/redirect-ssrf') {
      res.writeHead(302, { Location: 'http://192.168.1.1/secret' });
      res.end();
      return;
    }
    if (pathname === '/redirect-rst') {
      res.writeHead(302, { Location: '/latest.json' });
      res.flushHeaders();
      res.write('redirecting...');
      setImmediate(() => {
        res.socket?.destroy();
      });
      return;
    }
    if (pathname === '/status-502-rst') {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.flushHeaders();
      res.write('bad gateway...');
      setImmediate(() => {
        res.socket?.destroy();
      });
      return;
    }
    if (pathname === '/app-v1.1.0.asar.gz') {
      const body = corruptAsarResponse
        ? Buffer.concat([v110AsarGz.subarray(0, 12), Buffer.from('TAMPERED')])
        : v110AsarGz;
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(body.length),
      });
      res.end(body);
      return;
    }
    if (pathname === '/geolite2-country.mmdb.gz') {
      mmdbDownloadCount++;
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(newMmdbGz.length),
      });
      res.end(newMmdbGz);
      return;
    }
    if (pathname === '/ProxyRegionGuard-v1.1.0-win32-x64.zip') {
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(fullZipRaw.length),
      });
      res.end(fullZipRaw);
      return;
    }
    res.writeHead(404);
    res.end('not found');
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = (server.address() as { port: number }).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 验证网络层重定向 SSRF 拦截与 302 连接瞬间重置不崩溃
    await assert.rejects(
      () => requestTextViaProxy(`${baseUrl}/redirect-ssrf`, null, 3000, '*/*', 2, true),
      /本机或内网/
    );
    await assert.rejects(
      () =>
        downloadFileViaProxy({
          targetUrl: `${baseUrl}/redirect-latest.json`,
          proxyUrl: null,
          destFilePath: path.join(root, 'should-not-exist.tmp'),
          timeoutMs: 3000,
          allowLocalhost: false,
        }),
      /本机或内网/
    );
    servedManifestJson = '{"ok":true}';
    const rstBody = await requestTextViaProxy(
      `${baseUrl}/redirect-rst`,
      null,
      3000,
      '*/*',
      2,
      true
    );
    assert.equal(rstBody, '{"ok":true}');
    await assert.rejects(
      () => requestTextViaProxy(`${baseUrl}/status-502-rst`, null, 3000, '*/*', 2, true),
      /502|aborted|reset|socket/i
    );

    const makeSignedManifest = (
      overrides: Partial<Omit<UpdateReleaseManifest, 'signature'>> = {}
    ): UpdateReleaseManifest => {
      const unsigned: Omit<UpdateReleaseManifest, 'signature'> = {
        schemaVersion: 1,
        version: '1.1.0',
        publishedAt: '2026-11-15T00:00:00Z',
        electronVersion: '33.2.1',
        minNativeShellVersion: '1.0.0',
        notes: '### ✨ 新增特性\n- 支持 ASAR 秒级增量热更新与 Ed25519 验签',
        asar: {
          name: 'app-v1.1.0.asar.gz',
          url: `${baseUrl}/app-v1.1.0.asar.gz`,
          size: v110AsarGz.length,
          sha256: sha256Hex(v110AsarGz),
          uncompressedSize: v110AsarRaw.length,
          uncompressedSha256: sha256Hex(v110AsarRaw),
        },
        mmdb: {
          name: 'geolite2-country.mmdb.gz',
          url: `${baseUrl}/geolite2-country.mmdb.gz`,
          size: newMmdbGz.length,
          sha256: sha256Hex(newMmdbGz),
          uncompressedSize: newMmdbRaw.length,
          uncompressedSha256: sha256Hex(newMmdbRaw),
        },
        fullZip: {
          name: 'ProxyRegionGuard-v1.1.0-win32-x64.zip',
          url: `${baseUrl}/ProxyRegionGuard-v1.1.0-win32-x64.zip`,
          size: fullZipRaw.length,
          sha256: sha256Hex(fullZipRaw),
        },
        ...overrides,
      };
      return {
        ...unsigned,
        signature: signUpdateManifest(unsigned, privB64),
      };
    };

    const validManifest = makeSignedManifest();
    assert.equal(verifyUpdateManifestSignature(validManifest, pubB64), true);
    assert.equal(
      verifyUpdateManifestSignature({ ...validManifest, notes: '被篡改的钓鱼链接' }, pubB64),
      false,
      '篡改更新日志也必须立即触发 Ed25519 验签失败'
    );
    assert.throws(
      () =>
        validateUpdateManifestStructure(
          {
            ...validManifest,
            asar: { ...validManifest.asar, url: 'https://evil.example.com/app.asar.gz' },
          },
          false
        ),
      /不受信任/
    );
    assert.throws(
      () =>
        validateUpdateManifestStructure(
          {
            ...validManifest,
            asar: { ...validManifest.asar, name: 'bad|name.asar.gz' },
          },
          true
        ),
      /文件名非法/
    );
    assert.throws(
      () =>
        validateUpdateManifestStructure(
          {
            ...validManifest,
            publishedAt: '2026-11-15T00:00:00Z\ninjected=1',
          },
          true
        ),
      /发布时间格式非法/
    );

    const store = new ConfigStore();
    store.update({ proxyMode: 'direct', useUpdateMirrorFallback: false });
    const monitor = new ClashMonitor();
    const engine = new ProbeEngine(store, geo, monitor);

    // 验证 proxyMode === 'direct' 与回环地址均严格仅走直连，不误走系统代理
    const directProxies = await engine.resolveUpdateDownloadProxies(
      'https://github.com/liudg/proxy-region-guard/releases/latest/download/latest.json'
    );
    assert.equal(directProxies.length, 1);
    assert.equal(directProxies[0].proxyUrl, null);
    store.update({ proxyMode: 'auto' });
    const loopbackProxies = await engine.resolveUpdateDownloadProxies(`${baseUrl}/latest.json`);
    assert.equal(loopbackProxies.length, 1);
    assert.equal(loopbackProxies[0].proxyUrl, null);
    store.update({ proxyMode: 'direct' });

    const appInstallDir = path.join(root, 'installed-app');
    const resDir = path.join(appInstallDir, 'resources');
    const stagingDir = path.join(root, 'staging');
    fs.mkdirSync(resDir, { recursive: true });
    rawFs.copyFileSync(v100Asar, path.join(resDir, 'app.asar'));
    // 初始离线库与新版本一致：应智能跳过 mmdb 下载
    fs.writeFileSync(path.join(resDir, 'geolite2-country.mmdb'), newMmdbRaw);
    fs.writeFileSync(
      path.join(resDir, 'shell-meta.json'),
      JSON.stringify({ shellVersion: '1.0.0', electronVersion: '33.2.1' }),
      'utf-8'
    );

    const updater = new UpdaterService({
      configStore: store,
      probeEngine: engine,
      manifestUrlOverride: `${baseUrl}/redirect-latest.json`,
      publicKeyOverride: pubB64,
      isPackagedOverride: true,
      currentVersionOverride: '1.0.0',
      electronVersionOverride: '33.2.1',
      appDirOverride: appInstallDir,
      resourcesDirOverride: resDir,
      exePathOverride: path.join(appInstallDir, '代理地区卫士.exe'),
      stagingRootDirOverride: stagingDir,
      allowLocalhostForTest: true,
    });

    try {
      // 3. 拦截伪造签名的更新清单
      servedManifestJson = JSON.stringify({
        ...validManifest,
        version: '9.9.9',
      });
      const forgedRes = await updater.checkForUpdates({ silent: false });
      assert.equal(forgedRes.ok, false);
      assert.equal(updater.getSnapshot().status, 'error');
      assert.match(forgedRes.message, /签名校验失败/);

      // 4. 拦截下载包字节篡改
      servedManifestJson = JSON.stringify(validManifest);
      corruptAsarResponse = true;
      const corruptRes = await updater.checkForUpdates({ silent: false });
      assert.equal(corruptRes.ok, false);
      assert.equal(updater.getSnapshot().status, 'error');
      corruptAsarResponse = false;

      // 5. 模拟暂存目录残留上次中断解压留下的 _extract_full/resources/app.asar（验证 rawFs 不会报 EROFS 卡死！）
      const leftoverExtractRes = path.join(
        stagingDir,
        'v-1.1.0',
        '_extract_full',
        'resources'
      );
      rawFs.mkdirSync(leftoverExtractRes, { recursive: true });
      rawFs.copyFileSync(v110Asar, path.join(leftoverExtractRes, 'app.asar'));

      mmdbDownloadCount = 0;
      const okRes = await updater.checkForUpdates({ silent: true });
      assert.equal(okRes.ok, true, okRes.message);
      const snapAfterAsar = updater.getSnapshot();
      assert.equal(snapAfterAsar.status, 'downloaded');
      assert.equal(snapAfterAsar.deliveryMode, 'asar');
      assert.equal(snapAfterAsar.includeMmdbUpdate, false);
      assert.equal(mmdbDownloadCount, 0, '本地 mmdb 哈希一致时不应重复下载 mmdb.gz');

      // 5b. 已下载验签就绪后断网点击检查更新：必须保留 downloaded 状态不丢失安装入口！
      failManifestNetwork = true;
      const offlineRecheck = await updater.checkForUpdates({ silent: false });
      assert.equal(offlineRecheck.ok, false);
      assert.equal(
        updater.getSnapshot().status,
        'downloaded',
        '断网重查失败时不得抹除本地已验签就绪的更新状态'
      );
      assert.equal(updater.getSnapshot().signatureVerified, true);
      failManifestNetwork = false;

      // 6. 当本地离线库为旧版时，自动一并下载并校验新 mmdb.gz
      fs.writeFileSync(path.join(resDir, 'geolite2-country.mmdb'), oldMmdbRaw);
      rawFs.rmSync(stagingDir, { recursive: true, force: true });
      const withMmdbRes = await updater.checkForUpdates({ silent: false });
      assert.equal(withMmdbRes.ok, true, withMmdbRes.message);
      assert.equal(updater.getSnapshot().includeMmdbUpdate, true);
      assert.equal(mmdbDownloadCount, 1);

      // 7. Claude 正在受控运行（含 authorizedSession 刚授权的 2 秒窗口期）阻止未经确认的重启更新，且并发调用具备同步互斥锁
      (engine as unknown as { claudeAuthorizedSession: boolean }).claudeAuthorizedSession =
        true;
      const [blocked1, blocked2] = await Promise.all([
        updater.applyDownloadedUpdate(false),
        updater.applyDownloadedUpdate(false),
      ]);
      assert.equal(blocked1.ok, false);
      assert.equal(blocked2.ok, false);
      assert.ok(
        /Claude/.test(blocked1.message) || /请勿重复点击/.test(blocked2.message),
        '并发触发 applyDownloadedUpdate 时第二个请求应被同步互斥锁拦截'
      );
      (engine as unknown as { claudeAuthorizedSession: boolean }).claudeAuthorizedSession =
        false;
      assert.equal(updater.getSnapshot().status, 'downloaded');

      // 8. Electron 基座升级时回退 full-zip，且后台静默 check 进行中手动调用 downloadUpdate() 会自动衔接下载！
      const majorUpgradeManifest = makeSignedManifest({
        version: '2.0.0',
        electronVersion: '34.0.0',
      });
      servedManifestJson = JSON.stringify(majorUpgradeManifest);
      const zipUpdater = new UpdaterService({
        configStore: store,
        probeEngine: engine,
        manifestUrlOverride: `${baseUrl}/latest.json`,
        publicKeyOverride: pubB64,
        isPackagedOverride: true,
        currentVersionOverride: '1.0.0',
        electronVersionOverride: '33.2.1',
        appDirOverride: appInstallDir,
        resourcesDirOverride: resDir,
        exePathOverride: path.join(appInstallDir, '代理地区卫士.exe'),
        stagingRootDirOverride: stagingDir,
        allowLocalhostForTest: true,
      });
      manifestDelayMs = 120;
      const concurrentCheckPromise = zipUpdater.checkForUpdates({ silent: true });
      const chainedDownloadRes = await zipUpdater.downloadUpdate();
      await concurrentCheckPromise;
      manifestDelayMs = 0;
      assert.equal(chainedDownloadRes.ok, true, chainedDownloadRes.message);
      assert.equal(
        zipUpdater.getSnapshot().status,
        'downloaded',
        '后台静默检查期间用户手动触发 downloadUpdate 应衔接完成全量包下载'
      );
      zipUpdater.stop();

      // 9. 真实通过内存压缩 + -EncodedCommand 执行脱离式 PowerShell 更新器（零临时 .ps1 落盘，且命令行极短！）
      const { encodedCommand: encodedScript, scriptGzB64 } = buildEncodedPowerShellLaunch();
      assert.ok(
        encodedScript.length > 100 && encodedScript.length < 2000,
        `EncodedCommand 引导器长度 (${encodedScript.length}) 必须保持极短 (< 2000)`
      );

      // 9a. 验证等待真实进程退出（1200ms）+ SHA-256 锁定复核 + ASAR/MMDB 原子替换
      const stageV110 = path.join(stagingDir, 'v-1.1.0');
      const holdStartedAt = Date.now();
      const dummyHold = spawn(process.env.GUARD_TEST_NODE || process.execPath, [
        '-e',
        'setTimeout(() => process.exit(0), 1200)',
      ]);
      await once(dummyHold, 'spawn');

      execFileSync(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-EncodedCommand', encodedScript],
        {
          windowsHide: true,
          env: {
            ...process.env,
            GUARD_UPD_SCRIPT_GZ: scriptGzB64,
            GUARD_UPD_PID: String(dummyHold.pid),
            GUARD_UPD_MODE: 'asar',
            GUARD_UPD_APP_DIR: appInstallDir,
            GUARD_UPD_RES_DIR: resDir,
            GUARD_UPD_EXE_PATH: path.join(appInstallDir, '代理地区卫士.exe'),
            GUARD_UPD_FROM_VER: '1.0.0',
            GUARD_UPD_TO_VER: '1.1.0',
            GUARD_UPD_STAGED_ASAR: path.join(stageV110, 'app-payload.bin'),
            GUARD_UPD_STAGED_MMDB: path.join(stageV110, 'geolite2-country.mmdb.staged'),
            GUARD_UPD_STAGED_ZIP: '',
            GUARD_UPD_ASAR_SHA256: sha256Hex(v110AsarRaw),
            GUARD_UPD_MMDB_SHA256: sha256Hex(newMmdbRaw),
            GUARD_UPD_ZIP_SHA256: '',
            GUARD_UPD_STAGE_DIR: stageV110,
            GUARD_UPD_SKIP_RELAUNCH: '1',
          },
        }
      );
      assert.ok(
        Date.now() - holdStartedAt >= 1000,
        'PowerShell 更新器必须真实等待旧进程退出后再执行文件替换'
      );

      const replacedAsarHash = await computeFileSha256(path.join(resDir, 'app.asar'));
      assert.equal(replacedAsarHash.sha256, sha256Hex(v110AsarRaw));
      assert.deepEqual(
        fs.readFileSync(path.join(resDir, 'geolite2-country.mmdb')),
        newMmdbRaw
      );
      assert.equal(rawFs.existsSync(stageV110), false, '更新成功后应自动清理暂存目录');

      // 9a-2. 验证 TOCTOU 防掉包：若暂存包在脚本执行前被篡改导致 SHA-256 不符，脚本必须拒绝覆盖并自动还原原版！
      rawFs.copyFileSync(v100Asar, path.join(resDir, 'app.asar'));
      const tamperStage = path.join(root, 'tamper-stage');
      rawFs.mkdirSync(tamperStage, { recursive: true });
      const tamperedPayload = path.join(tamperStage, 'app-payload.bin');
      rawFs.writeFileSync(tamperedPayload, 'EVIL-REPLACED-PAYLOAD');
      let tamperExit = 0;
      try {
        execFileSync(
          'powershell.exe',
          ['-NoProfile', '-NonInteractive', '-EncodedCommand', encodedScript],
          {
            windowsHide: true,
            env: {
              ...process.env,
              GUARD_UPD_SCRIPT_GZ: scriptGzB64,
              GUARD_UPD_PID: '0',
              GUARD_UPD_MODE: 'asar',
              GUARD_UPD_APP_DIR: appInstallDir,
              GUARD_UPD_RES_DIR: resDir,
              GUARD_UPD_EXE_PATH: path.join(appInstallDir, '代理地区卫士.exe'),
              GUARD_UPD_FROM_VER: '1.0.0',
              GUARD_UPD_TO_VER: '1.1.0',
              GUARD_UPD_STAGED_ASAR: tamperedPayload,
              GUARD_UPD_STAGED_MMDB: '',
              GUARD_UPD_STAGED_ZIP: '',
              GUARD_UPD_ASAR_SHA256: sha256Hex(v110AsarRaw),
              GUARD_UPD_STAGE_DIR: tamperStage,
              GUARD_UPD_SKIP_RELAUNCH: '1',
            },
          }
        );
      } catch (e) {
        tamperExit = (e as { status?: number }).status ?? 1;
      }
      assert.equal(tamperExit, 1, '暂存文件哈希不匹配时管理员更新脚本必须立即报错退出 1');
      assert.equal(
        (await computeFileSha256(path.join(resDir, 'app.asar'))).sha256,
        (await computeFileSha256(v100Asar)).sha256,
        '哈希复核拦截后原有 app.asar 必须保持完好无损'
      );

      // 9b. 验证正向就绪握手（Positive Readiness Handshake）：新版卡死（模拟 MessageBox 挂起未退出且未写 readyFile）时自动终止挂起进程并回滚！
      rawFs.copyFileSync(v100Asar, path.join(resDir, 'app.asar'));
      const hangStage = path.join(root, 'hang-stage');
      rawFs.mkdirSync(hangStage, { recursive: true });
      const hangStagedAsar = path.join(hangStage, 'bad-payload.bin');
      rawFs.copyFileSync(v110Asar, hangStagedAsar);
      const readyHandshakePath = path.join(hangStage, 'boot-ready.ok');

      const rollbackMarker = path.join(root, 'rolled-back-arg.txt');
      const fakeHangCmd = path.join(root, 'fake-guard-hang.cmd');
      // 携带 --updated-from= 时挂起睡眠 5 秒且不写 readyFile（模拟阻塞弹窗），回滚拉起时正常退出并记录参数
      fs.writeFileSync(
        fakeHangCmd,
        [
          '@echo off',
          'echo %* | findstr /C:"--updated-from=" >nul',
          'if %errorlevel% equ 0 (',
          '  ping -n 6 127.0.0.1 >nul',
          '  exit /b 0',
          ')',
          `echo %* > "${rollbackMarker}"`,
          'exit /b 0',
        ].join('\r\n'),
        'utf-8'
      );

      let rollbackExitCode = 0;
      try {
        execFileSync(
          'powershell.exe',
          ['-NoProfile', '-NonInteractive', '-EncodedCommand', encodedScript],
          {
            windowsHide: true,
            env: {
              ...process.env,
              GUARD_UPD_SCRIPT_GZ: scriptGzB64,
              GUARD_UPD_PID: '0',
              GUARD_UPD_MODE: 'asar',
              GUARD_UPD_APP_DIR: appInstallDir,
              GUARD_UPD_RES_DIR: resDir,
              GUARD_UPD_EXE_PATH: fakeHangCmd,
              GUARD_UPD_FROM_VER: '1.0.0',
              GUARD_UPD_TO_VER: '1.1.0',
              GUARD_UPD_STAGED_ASAR: hangStagedAsar,
              GUARD_UPD_STAGED_MMDB: '',
              GUARD_UPD_STAGED_ZIP: '',
              GUARD_UPD_ASAR_SHA256: sha256Hex(v110AsarRaw),
              GUARD_UPD_STAGE_DIR: hangStage,
              GUARD_UPD_READY_FILE: readyHandshakePath,
              GUARD_UPD_SKIP_RELAUNCH: '0',
              GUARD_UPD_BOOT_CHECK_MS: '650',
            },
          }
        );
      } catch (e) {
        rollbackExitCode = (e as { status?: number }).status ?? 1;
      }

      assert.equal(
        rollbackExitCode,
        2,
        '新版启动挂起未完成正向就绪握手时更新脚本必须超时强杀并返回回滚状态码 2'
      );
      assert.equal(
        (await computeFileSha256(path.join(resDir, 'app.asar'))).sha256,
        (await computeFileSha256(v100Asar)).sha256,
        '挂起回滚后必须将 app.asar 还原为升级前的 v1.0.0 备份'
      );

      // 9c. 验证 full-zip 全量跨版本升级失败时的【整目录完整回滚】（DLL/V8快照/shell-meta/多余新增文件全部还原，且不残留 _extract_full）
      const fullTargetDir = path.join(root, 'full-zip-install');
      fs.mkdirSync(path.join(fullTargetDir, 'resources'), { recursive: true });
      rawFs.copyFileSync(v100Asar, path.join(fullTargetDir, 'resources', 'app.asar'));
      fs.writeFileSync(
        path.join(fullTargetDir, 'resources', 'shell-meta.json'),
        JSON.stringify({ shellVersion: '1.0.0', electronVersion: '33.2.1' }),
        'utf-8'
      );
      fs.writeFileSync(path.join(fullTargetDir, 'ffmpeg.dll'), 'OLD-FFMPEG-DLL-V33', 'utf-8');
      fs.writeFileSync(
        path.join(fullTargetDir, 'v8_context_snapshot.bin'),
        'OLD-V8-SNAPSHOT-V33',
        'utf-8'
      );
      fs.writeFileSync(path.join(fullTargetDir, '代理地区卫士.exe'), 'OLD-EXE-V100', 'utf-8');

      const crashCmd = path.join(root, 'fake-full-crash.cmd');
      fs.writeFileSync(
        crashCmd,
        [
          '@echo off',
          'echo %* | findstr /C:"--updated-from=" >nul',
          'if %errorlevel% equ 0 exit /b 1',
          'exit /b 0',
        ].join('\r\n'),
        'utf-8'
      );

      const fullFailStage = path.join(root, 'full-zip-fail-stage');
      fs.mkdirSync(fullFailStage, { recursive: true });
      const stagedZipFailCopy = path.join(fullFailStage, 'release.zip.staged');
      fs.copyFileSync(fullZipPath, stagedZipFailCopy);

      let fullRollbackCode = 0;
      try {
        execFileSync(
          'powershell.exe',
          ['-NoProfile', '-NonInteractive', '-EncodedCommand', encodedScript],
          {
            windowsHide: true,
            env: {
              ...process.env,
              GUARD_UPD_SCRIPT_GZ: scriptGzB64,
              GUARD_UPD_PID: '0',
              GUARD_UPD_MODE: 'full-zip',
              GUARD_UPD_APP_DIR: fullTargetDir,
              GUARD_UPD_RES_DIR: path.join(fullTargetDir, 'resources'),
              GUARD_UPD_EXE_PATH: crashCmd,
              GUARD_UPD_FROM_VER: '1.0.0',
              GUARD_UPD_TO_VER: '2.0.0',
              GUARD_UPD_STAGED_ASAR: '',
              GUARD_UPD_STAGED_MMDB: '',
              GUARD_UPD_STAGED_ZIP: stagedZipFailCopy,
              GUARD_UPD_ZIP_SHA256: sha256Hex(fullZipRaw),
              GUARD_UPD_STAGE_DIR: fullFailStage,
              GUARD_UPD_READY_FILE: path.join(fullFailStage, 'boot-ready.ok'),
              GUARD_UPD_SKIP_RELAUNCH: '0',
              GUARD_UPD_BOOT_CHECK_MS: '600',
            },
          }
        );
      } catch (e) {
        fullRollbackCode = (e as { status?: number }).status ?? 1;
      }

      assert.equal(fullRollbackCode, 2, 'full-zip 新版崩溃时必须触发整目录回滚并返回状态码 2');
      assert.equal(
        fs.readFileSync(path.join(fullTargetDir, 'ffmpeg.dll'), 'utf-8'),
        'OLD-FFMPEG-DLL-V33',
        'full-zip 回滚必须完整还原旧版 Chromium/FFmpeg DLL 防止 ABI 混杂变砖'
      );
      assert.equal(
        fs.readFileSync(path.join(fullTargetDir, 'v8_context_snapshot.bin'), 'utf-8'),
        'OLD-V8-SNAPSHOT-V33',
        'full-zip 回滚必须完整还原旧版 V8 快照文件'
      );
      assert.deepEqual(
        JSON.parse(
          fs.readFileSync(path.join(fullTargetDir, 'resources', 'shell-meta.json'), 'utf-8')
        ),
        { shellVersion: '1.0.0', electronVersion: '33.2.1' },
        'full-zip 回滚必须还原旧版 shell-meta.json'
      );
      assert.equal(
        fs.existsSync(path.join(fullTargetDir, 'extra-new-v34.dll')),
        false,
        'full-zip 回滚必须清理新版独有的多余新增文件'
      );
      assert.equal(
        rawFs.existsSync(path.join(fullFailStage, '_extract_full')),
        false,
        'full-zip 异常退出前必须清理 _extract_full 避免残留 app.asar'
      );

      // 9d. 验证 full-zip 正常全量升级成功路径（含正向就绪握手成功 + UTF-8 中文可执行文件无损解压）
      const okReadyScriptCmd = path.join(root, 'fake-full-ok.cmd');
      const fullOkStage = path.join(root, 'full-zip-ok-stage');
      fs.mkdirSync(fullOkStage, { recursive: true });
      const stagedZipOkCopy = path.join(fullOkStage, 'release.zip.staged');
      fs.copyFileSync(fullZipPath, stagedZipOkCopy);
      const okReadyFile = path.join(fullOkStage, 'boot-ready.ok');
      fs.writeFileSync(
        okReadyScriptCmd,
        `@echo off\r\necho ready > "${okReadyFile}"\r\nexit /b 0\r\n`,
        'utf-8'
      );

      execFileSync(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-EncodedCommand', encodedScript],
        {
          windowsHide: true,
          env: {
            ...process.env,
            GUARD_UPD_SCRIPT_GZ: scriptGzB64,
            GUARD_UPD_PID: '0',
            GUARD_UPD_MODE: 'full-zip',
            GUARD_UPD_APP_DIR: fullTargetDir,
            GUARD_UPD_RES_DIR: path.join(fullTargetDir, 'resources'),
            GUARD_UPD_EXE_PATH: okReadyScriptCmd,
            GUARD_UPD_FROM_VER: '1.0.0',
            GUARD_UPD_TO_VER: '2.0.0',
            GUARD_UPD_STAGED_ASAR: '',
            GUARD_UPD_STAGED_MMDB: '',
            GUARD_UPD_STAGED_ZIP: stagedZipOkCopy,
            GUARD_UPD_ZIP_SHA256: sha256Hex(fullZipRaw),
            GUARD_UPD_STAGE_DIR: fullOkStage,
            GUARD_UPD_READY_FILE: okReadyFile,
            GUARD_UPD_SKIP_RELAUNCH: '0',
            GUARD_UPD_BOOT_CHECK_MS: '3000',
          },
        }
      );

      assert.equal(
        fs.readFileSync(path.join(fullTargetDir, '代理地区卫士.exe'), 'utf-8'),
        'DUMMY-EXE-V110',
        'full-zip 全量更新应正确解压 UTF-8 中文可执行文件并完成覆盖'
      );
      assert.equal(
        fs.readFileSync(path.join(fullTargetDir, 'ffmpeg.dll'), 'utf-8'),
        'NEW-FFMPEG-DLL-V34'
      );
      assert.equal(
        fs.existsSync(path.join(fullTargetDir, 'extra-new-v34.dll')),
        true
      );
      const fullAsarHash = await computeFileSha256(
        path.join(fullTargetDir, 'resources', 'app.asar')
      );
      assert.equal(fullAsarHash.sha256, sha256Hex(v110AsarRaw));
      assert.equal(rawFs.existsSync(fullOkStage), false, '全量更新握手成功后应清理暂存目录');
    } finally {
      updater.stop();
      engine.stop();
      monitor.stop();
    }
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}
