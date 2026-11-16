import { app } from 'electron';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as http from 'node:http';
import * as net from 'node:net';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { SocksProxyAgent } from 'socks-proxy-agent';
import * as yaml from 'js-yaml';
import { PrivateProxyService, PrivateKernel, verifyCore } from '../electron/privateKernel';
import { SubscriptionCatalog, NodeSnapshot } from '../electron/subscriptionCatalog';
import { ClashMonitor } from '../electron/clashMonitor';
import { mihomoRequest, MihomoEndpoint } from '../electron/mihomoClient';
import { ConfigStore } from '../electron/configStore';
import { signUpdateManifest, verifyUpdateManifestSignature } from '../electron/updateCrypto';
import { UpdateReleaseManifest, validateUpdateManifestStructure } from '../src/shared/updateManifest';
import { isWindowsLocaleMatchingCountry } from '../src/shared/timezones';
import { getTargetServiceVerificationError, isValidIpAddress } from '../src/shared/probeValidation';
import { createStatusTrayIcon } from '../electron/trayIcon';
import { validateSnapshots } from './snapshotValidation';
import { validateLegacyMigration } from './legacyMigration';

assert.ok(process.env.GUARD_TEST_DATA);
const root = process.env.GUARD_TEST_DATA;
fs.mkdirSync(root, { recursive: true });
app.setPath('userData', root);
const core = path.resolve('resources/mihomo');
const kernelRoot = path.join(root, 'kernels');
const referenceRoot = path.join(root, 'reference');
let service: PrivateProxyService | undefined;
let reference: PrivateKernel | undefined;
let server: http.Server | undefined;
let stream: http.IncomingMessage | undefined;
let monitor: ClashMonitor | undefined;
const sockets = new Set<net.Socket>();

async function until(test: () => boolean, timeout = 30000): Promise<void> {
  const end = Date.now() + timeout;
  while (!test()) { assert.ok(Date.now() < end, '等待状态超时'); await delay(100); }
}

async function freePort(): Promise<number> {
  const listener = net.createServer();
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const port = (listener.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => listener.close(() => resolve()));
  return port;
}

function endpoint(directory: string): MihomoEndpoint {
  return JSON.parse(fs.readFileSync(path.join(directory, 'runtime.json'), 'utf8')).endpoint;
}

async function getThrough(port: number, url: string): Promise<string> {
  const agent = new SocksProxyAgent(`socks5h://127.0.0.1:${port}`);
  try {
    return await new Promise<string>((resolve, reject) => {
      const request = http.get(url, { agent, timeout: 5000 }, (response) => {
        let body = '';
        response.setEncoding('utf8').on('data', (chunk) => body += chunk);
        response.on('end', () => resolve(body)); response.on('error', reject);
      });
      request.on('error', reject); request.on('timeout', () => request.destroy(new Error('真实代理请求超时')));
    });
  } finally { agent.destroy(); }
}

async function run(): Promise<void> {
  if (process.env.GUARD_TEST_ROLE === 'owner') {
    service = new PrivateProxyService(kernelRoot, core);
    await service.restore();
    assert.equal(service.channels.claude.getState().phase, 'ready');
    app.exit(0);
    return;
  }
  const store = new ConfigStore();
  await validateLegacyMigration(root);
  validateSnapshots(root);
  assert.throws(() => store.update({ dedicatedProxyPort: 27898 }), /不同/);
  assert.equal(store.get().dedicatedProxyPort, 27897);
  assert.equal(isWindowsLocaleMatchingCountry('Tokyo Standard Time', 'JP', 'JP'), true);
  assert.equal(isWindowsLocaleMatchingCountry('China Standard Time', 'JP', 'JP'), false);
  assert.equal(isValidIpAddress('not-an-ip'), false);
  assert.ok(getTargetServiceVerificationError(null, 'claude'));
  assert.ok(!createStatusTrayIcon('checking').isEmpty());
  console.log('通过：端口冲突配置拒绝保存，地区与目标服务校验保持拒绝条件');

  const fixture = path.join(root, 'subscriptions');
  fs.mkdirSync(path.join(fixture, 'profiles'), { recursive: true });
  const name = '本地真实转发,#🙂';
  const sourceFile = path.join(fixture, 'profiles', 'local.yaml');
  const source = { proxies: [{ name, type: 'direct', udp: true }], dns: { 'proxy-server-nameserver': ['223.5.5.5'] } };
  fs.writeFileSync(path.join(fixture, 'profiles.yaml'), yaml.dump({ current: 'local', items: [{ uid: 'local', name: '本地协议检查', type: 'local', file: 'local.yaml' }] }));
  fs.writeFileSync(sourceFile, yaml.dump(source));
  const catalog = new SubscriptionCatalog(fixture);
  catalog.refresh();
  const snapshot = catalog.capture('local', name);
  assert.equal(snapshot.proxies.length, 1);
  assert.throws(() => catalog.capture('missing', name), /不存在/);
  const [claudePort, agPort, refPort] = await Promise.all([freePort(), freePort(), freePort()]);
  assert.equal(new Set([claudePort, agPort, refPort]).size, 3);
  service = new PrivateProxyService(kernelRoot, core);
  reference = new PrivateKernel('claude', referenceRoot, verifyCore(core));
  await Promise.all([service.channels.claude.select(snapshot, claudePort), service.channels.antigravity.select(snapshot, agPort), reference.select(snapshot, refPort)]);
  for (const kernel of [...Object.values(service.channels), reference]) assert.equal(kernel.getState().phase, 'ready');
  assert.notEqual(service.channels.claude.getState().pid, service.channels.antigravity.getState().pid);

  const nonce = randomUUID();
  server = http.createServer((request, response) => {
    if (request.url === '/slow') { setTimeout(() => response.end(nonce), 2000); return; }
    if (request.url !== '/stream') { response.end(nonce); return; }
    response.writeHead(200, { 'Content-Type': 'text/plain' });
    let sequence = 0;
    const timer = setInterval(() => response.write(`${++sequence}\n`), 20);
    response.on('close', () => clearInterval(timer));
  });
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`;
  assert.equal(await getThrough(claudePort, origin), nonce);
  assert.equal(await getThrough(agPort, origin), nonce);
  const streamAgent = new SocksProxyAgent(`socks5h://127.0.0.1:${agPort}`);
  stream = await new Promise<http.IncomingMessage>((resolve, reject) => http.get(`${origin}/stream`, { agent: streamAgent }, resolve).on('error', reject));
  let received = 0;
  let closed = false;
  stream.on('data', () => received++); stream.on('close', () => closed = true);
  await until(() => received > 5);
  const agPid = service.channels.antigravity.getState().pid;
  const before = received;
  await reference.restart();
  source.proxies[0].udp = false;
  fs.writeFileSync(sourceFile, yaml.dump(source));
  catalog.refresh();
  service.channels.claude.refreshSource(catalog);
  assert.equal(service.channels.claude.getState().sourceStatus, 'changed');
  const saved = service.channels.claude.getSnapshot()!;
  assert.equal(saved.proxies[0].udp, true);
  await service.channels.claude.select(catalog.capture('local', name), claudePort);
  assert.equal(service.channels.claude.getSnapshot()!.proxies[0].udp, false);
  assert.equal(service.channels.antigravity.getState().pid, agPid);
  assert.ok(received > before); assert.equal(closed, false);
  console.log('通过：独立参考内核重启、Claude 手动更新期间，Antigravity 持续传输连接保持正常');

  const pid = service.channels.claude.getState().pid;
  const invalid: NodeSnapshot = structuredClone(snapshot);
  invalid.proxies[0].type = 'invalid-protocol';
  await assert.rejects(service.channels.claude.select(invalid, claudePort));
  assert.equal(service.channels.claude.getState().pid, pid);
  const occupied = net.createServer(); occupied.listen(0, '127.0.0.1'); await once(occupied, 'listening');
  try { await assert.rejects(service.channels.claude.select(snapshot, (occupied.address() as net.AddressInfo).port), /占用/); }
  finally { await new Promise<void>((resolve) => occupied.close(() => resolve())); }
  assert.equal(service.channels.claude.getState().pid, pid);
  fs.writeFileSync(sourceFile, yaml.dump({ proxies: [] }));
  catalog.refresh(); service.channels.claude.refreshSource(catalog);
  assert.equal(service.channels.claude.getState().sourceStatus, 'missing');
  assert.equal(await getThrough(claudePort, origin), nonce);
  console.log('通过：源节点删除继续使用副本，无效配置和端口占用不会终止当前内核');

  process.kill(pid!);
  await until(() => service!.channels.claude.getState().phase === 'ready' && service!.channels.claude.getState().pid !== pid);
  assert.equal(service.channels.antigravity.getState().pid, agPid);
  assert.equal(closed, false); assert.equal(await getThrough(claudePort, origin), nonce);
  console.log('通过：内核异常退出后自动恢复，另一通道的持续传输连接保持正常');

  // 使用真实网络请求占用串行队列，检查排队恢复与手动选择的交错执行。
  const queuedKernel = service.channels.claude as unknown as { serial<T>(operation: () => Promise<T>): Promise<T> };
  const requestPending = queuedKernel.serial(() => getThrough(agPort, `${origin}/slow`));
  process.kill(service.channels.claude.getState().pid!);
  await until(() => service!.channels.claude.getState().phase === 'recovering');
  const selectionPending = service.channels.claude.select(snapshot, claudePort);
  await requestPending;
  await selectionPending;
  const selectedPid = service.channels.claude.getState().pid;
  await delay(1500);
  assert.equal(service.channels.claude.getState().pid, selectedPid);
  assert.equal(service.channels.claude.getState().phase, 'ready');
  assert.equal(service.channels.claude.getState().restartAttempts, 0);
  assert.equal(closed, false);
  console.log('通过：已经排队的自动恢复不会终止手动选择启动的新内核');
  stream.destroy(); streamAgent.destroy();

  const referenceSaved = JSON.parse(fs.readFileSync(path.join(referenceRoot, 'current.json'), 'utf8'));
  fs.copyFileSync(path.join(referenceRoot, referenceSaved.revision, 'config.yaml'), path.join(fixture, 'clash-verge.yaml'));
  monitor = new ClashMonitor(fixture);
  await monitor.refresh();
  assert.equal(monitor.getRuntimeInfo().connected, true);
  assert.equal(monitor.getRuntimeInfo().tunEnabled, false);
  const refEndpoint = endpoint(referenceRoot);
  const version = await mihomoRequest<{ version: string }>(refEndpoint, '/version');
  assert.equal(version.version, 'v1.19.34');
  if (process.env.GUARD_TEST_TUN === '1') {
    let warnings = 0;
    monitor.on('tun-enabled', () => warnings++);
    const tun = { enable: true, device: `GuardTest${process.pid}`, stack: 'gvisor', 'auto-route': false, 'auto-redirect': false, 'auto-detect-interface': false, 'dns-hijack': [] };
    try {
      await mihomoRequest(refEndpoint, '/configs', 'PATCH', { tun });
      await monitor.refresh(); await monitor.refresh();
      assert.equal(monitor.getRuntimeInfo().tunEnabled, true); assert.equal(warnings, 1);
      await mihomoRequest(refEndpoint, '/configs', 'PATCH', { tun: { enable: false } });
      await monitor.refresh();
      await mihomoRequest(refEndpoint, '/configs', 'PATCH', { tun });
      await monitor.refresh(); assert.equal(warnings, 2);
      console.log('通过：真实参考内核 TUN 开启提醒、重复检测抑制及关闭后重新开启提醒');
    } finally { await mihomoRequest(refEndpoint, '/configs', 'PATCH', { tun: { enable: false } }); }
  }
  await reference.shutdown();
  await monitor.refresh();
  assert.equal(monitor.getRuntimeInfo().tunEnabled, null);
  assert.equal(await getThrough(agPort, origin), nonce);
  console.log('通过：本地命名管道控制接口、未知 TUN 状态、参考内核退出后专属代理继续运行');

  await service.shutdown();
  const owner = spawn(process.execPath, [process.argv[1]], { windowsHide: true, env: { ...process.env, GUARD_TEST_ROLE: 'owner' }, stdio: 'inherit' });
  assert.equal((await once(owner, 'exit'))[0], 0);
  const adoptedPid = JSON.parse(fs.readFileSync(path.join(kernelRoot, 'claude', 'runtime.json'), 'utf8')).pid;
  service = new PrivateProxyService(kernelRoot, core);
  await service.restore();
  assert.equal(service.channels.claude.getState().pid, adoptedPid);
  assert.equal(await getThrough(claudePort, origin), nonce);
  console.log('通过：管理进程退出后内核保持运行，重新启动接管原进程与保存的副本');

  execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-File', path.resolve('tests/suspendKernel.ps1'),
    '-KernelPid', String(adoptedPid), '-ExpectedExecutable', verifyCore(core)], { windowsHide: true, stdio: 'pipe' });
  await assert.rejects(service.channels.claude.checkReady(), /超时/);
  await service.channels.claude.restart();
  assert.notEqual(service.channels.claude.getState().pid, adoptedPid);
  assert.equal(await getThrough(claudePort, origin), nonce);
  console.log('通过：接管内核的真实进程挂起后，控制接口超时仍可手动重启');

  const currentFile = path.join(kernelRoot, 'claude', 'current.json');
  fs.renameSync(currentFile, `${currentFile}.saved`); fs.mkdirSync(currentFile);
  await assert.rejects(service.channels.claude.select(snapshot, claudePort));
  assert.equal(service.channels.claude.getState().phase, 'error');
  assert.equal(service.channels.claude.getState().pid, null);
  fs.rmdirSync(currentFile); fs.renameSync(`${currentFile}.saved`, currentFile);
  await service.channels.claude.restart();
  assert.equal(await getThrough(claudePort, origin), nonce);
  console.log('通过：保存失败准确报告停用状态，修复后可以手动恢复');

  const binary = fs.readFileSync(verifyCore(core));
  const digest = createHash('sha256').update(binary).digest('hex');
  const asset = { name: 'app.asar.gz', url: 'https://github.com/liudg/proxy-region-guard/releases/download/v2.0.0/app.asar.gz', size: binary.length, sha256: digest, uncompressedSize: binary.length, uncompressedSha256: digest };
  const manifest: UpdateReleaseManifest = { schemaVersion: 2, version: '2.0.0', publishedAt: new Date().toISOString(), electronVersion: process.versions.electron!, minNativeShellVersion: '1.0.0', mihomo: { version: '1.19.34', sha256: digest }, notes: '验证', asar: asset, fullZip: { ...asset, name: 'app.zip', url: asset.url.replace('app.asar.gz', 'app.zip') }, signature: '' };
  const keys = generateKeyPairSync('ed25519');
  manifest.signature = signUpdateManifest(manifest, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  assert.equal(verifyUpdateManifestSignature(manifest, publicKey), true);
  assert.equal(validateUpdateManifestStructure(manifest).mihomo.sha256, digest);
  manifest.mihomo.sha256 = '0'.repeat(64);
  assert.equal(verifyUpdateManifestSignature(manifest, publicKey), false);
  console.log('通过：真实 Ed25519 签名覆盖私有内核版本与二进制校验值');
}

async function cleanup(): Promise<void> {
  monitor?.stop(); stream?.destroy();
  await Promise.all([service?.shutdown(), reference?.shutdown()]);
  for (const socket of sockets) socket.destroy();
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
}

app.whenReady().then(run).then(async () => {
  if (process.env.GUARD_TEST_ROLE !== 'owner') await cleanup();
}).then(() => app.exit(0)).catch(async (error) => {
  console.error(error);
  await cleanup();
  app.exit(1);
});
