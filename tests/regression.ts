import { app } from 'electron';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as http from 'node:http';
import * as net from 'node:net';
import { spawn, execFileSync, ChildProcess } from 'node:child_process';
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
import { requestTextViaProxy } from '../electron/netClient';
import { validateSnapshots } from './snapshotValidation';
import { validateLegacyMigration } from './legacyMigration';

assert.ok(process.env.GUARD_TEST_DATA);
const root = process.env.GUARD_TEST_DATA;
fs.mkdirSync(root, { recursive: true });
app.setPath('userData', root);
const core = path.join(root, '中文内核 文件');
const kernelRoot = path.join(root, '代理地区卫士', '内核 配置');
const referenceRoot = path.join(root, 'reference');
let service: PrivateProxyService | undefined;
let reference: PrivateKernel | undefined;
let server: http.Server | undefined;
let stream: http.IncomingMessage | undefined;
let monitor: ClashMonitor | undefined;
let neighbor: ChildProcess | undefined;
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

async function assertPortReleased(port: number): Promise<void> {
  const listener = net.createServer();
  listener.listen(port, '127.0.0.1');
  await once(listener, 'listening');
  await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
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
  if (process.env.GUARD_TEST_ROLE === 'neighbor') {
    server = http.createServer((_request, response) => response.end('同端口服务'));
    server.listen(Number(process.env.GUARD_TEST_PORT), '127.0.0.2');
    await once(server, 'listening');
    process.send!('ready');
    assert.equal((await once(process, 'message'))[0], 'stop');
    return;
  }
  if (process.env.GUARD_TEST_ROLE === 'owner') {
    service = new PrivateProxyService(kernelRoot, core);
    await service.restore();
    assert.equal(service.channels.claude.getState().phase, 'ready');
    app.exit(0);
    return;
  }
  fs.cpSync(path.resolve('resources/mihomo'), core, { recursive: true });
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
  const peerConnections = new Set<net.Socket>();
  server = http.createServer((request, response) => {
    if (request.url === '/peer') {
      peerConnections.add(request.socket);
      response.end(request.socket.remoteAddress);
      return;
    }
    if (request.url === '/slow') { setTimeout(() => response.end(nonce), 3000); return; }
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
  await assertPortReleased(refPort);
  await monitor.refresh();
  assert.equal(monitor.getRuntimeInfo().tunEnabled, null);
  assert.equal(await getThrough(agPort, origin), nonce);
  console.log('通过：本地命名管道控制接口、未知 TUN 状态、参考内核退出后专属代理继续运行');

  await service.shutdown();
  await assertPortReleased(claudePort);
  await assertPortReleased(agPort);
  console.log('通过：真实内核停止后，三个专属端口均可立即重新绑定');
  const owner = spawn(process.execPath, [process.argv[1]], { windowsHide: true, env: { ...process.env, GUARD_TEST_ROLE: 'owner' }, stdio: 'inherit' });
  assert.equal((await once(owner, 'exit'))[0], 0);
  const adoptedPid = JSON.parse(fs.readFileSync(path.join(kernelRoot, 'claude', 'runtime.json'), 'utf8')).pid;
  const runtimeFile = path.join(kernelRoot, 'claude', 'runtime.json');
  const originalRuntime = fs.readFileSync(runtimeFile, 'utf8');
  const otherPid = JSON.parse(fs.readFileSync(path.join(kernelRoot, 'antigravity', 'runtime.json'), 'utf8')).pid;
  const wrongRuntime = JSON.stringify({ ...JSON.parse(originalRuntime), pid: otherPid });
  fs.writeFileSync(runtimeFile, wrongRuntime);
  service = new PrivateProxyService(kernelRoot, core);
  try {
    await service.restore();
    assert.equal(service.channels.claude.getState().phase, 'error');
    assert.match(service.channels.claude.getState().error!, /身份不匹配/);
    await assert.rejects(service.channels.claude.restart(), /身份不匹配/);
    assert.equal(fs.readFileSync(runtimeFile, 'utf8'), wrongRuntime);
    assert.equal(await getThrough(claudePort, origin), nonce);
    assert.equal(await getThrough(agPort, origin), nonce);
  } finally { fs.writeFileSync(runtimeFile, originalRuntime); }
  await service.channels.claude.restart();
  assert.notEqual(service.channels.claude.getState().pid, adoptedPid);
  assert.equal(await getThrough(claudePort, origin), nonce);
  console.log('通过：身份不匹配时保留进程记录和真实监听，修复记录后手动重启成功');
  await service.shutdown();

  const recoveryOwner = spawn(process.execPath, [process.argv[1]], { windowsHide: true, env: { ...process.env, GUARD_TEST_ROLE: 'owner' }, stdio: 'inherit' });
  assert.equal((await once(recoveryOwner, 'exit'))[0], 0);
  const recoveredPid = JSON.parse(fs.readFileSync(runtimeFile, 'utf8')).pid;
  fs.unlinkSync(runtimeFile);
  neighbor = spawn(process.execPath, [process.argv[1]], {
    windowsHide: true,
    env: { ...process.env, GUARD_TEST_ROLE: 'neighbor', GUARD_TEST_PORT: String(claudePort) },
    stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
  });
  const neighborReady = await Promise.race([
    once(neighbor, 'message', { signal: AbortSignal.timeout(15000) }),
    once(neighbor, 'exit').then(([code]) => { throw new Error(`同端口测试服务提前退出：${code}`); }),
  ]);
  assert.equal(neighborReady[0], 'ready');
  service = new PrivateProxyService(kernelRoot, core);
  await service.restore();
  assert.equal(service.channels.claude.getState().phase, 'ready', service.channels.claude.getState().error!);
  assert.equal(service.channels.claude.getState().pid, recoveredPid);
  assert.equal(JSON.parse(fs.readFileSync(runtimeFile, 'utf8')).pid, recoveredPid);
  assert.equal(await getThrough(claudePort, origin), nonce);
  assert.equal(await getThrough(agPort, `http://127.0.0.2:${claudePort}`), '同端口服务');
  const neighborExit = once(neighbor, 'exit');
  neighbor.send('stop');
  assert.equal((await neighborExit)[0], 0);
  neighbor = undefined;
  console.log('通过：中文及空格路径下恢复丢失的进程记录，其他地址的同端口服务保持正常');

  execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-File', path.resolve('tests/suspendKernel.ps1'),
    '-KernelPid', String(recoveredPid), '-ExpectedExecutable', verifyCore(core)], { windowsHide: true, stdio: 'pipe' });
  await assert.rejects(service.channels.claude.checkReady(), /超时/);
  await assert.rejects(requestTextViaProxy('https://example.com', `http://127.0.0.1:${claudePort}`, 700), /超时/);
  const pendingConnections = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    '@(Get-NetTCPConnection -OwningProcess $env:GUARD_CLIENT_PID -RemotePort $env:GUARD_PROXY_PORT -State Established -ErrorAction SilentlyContinue).Count'],
    { windowsHide: true, encoding: 'utf8', env: { ...process.env, GUARD_CLIENT_PID: String(process.pid), GUARD_PROXY_PORT: String(claudePort) } });
  assert.equal(pendingConnections.trim(), '0', 'CONNECT 超时后客户端应关闭代理连接');
  await service.channels.claude.restart();
  assert.notEqual(service.channels.claude.getState().pid, recoveredPid);
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

  const httpProxy = `http://127.0.0.1:${claudePort}`;
  const socksProxy = `socks5h://127.0.0.1:${claudePort}`;
  for (const proxy of [httpProxy, httpProxy, socksProxy, socksProxy]) {
    assert.equal(await requestTextViaProxy(`${origin}/peer`, proxy, 5000), '127.0.0.1');
  }
  assert.equal(peerConnections.size, 4);
  await Promise.all([null, httpProxy, socksProxy].map(async (proxy) => {
    assert.equal(await requestTextViaProxy(`${origin}/slow`, proxy, 5000), nonce);
  }));
  await assert.rejects(requestTextViaProxy('https://example.com', `http://user%2:pass@127.0.0.1:${claudePort}`, 5000), /URI malformed/i);
  console.log('通过：HTTP 与 SOCKS 四次请求建立四条连接，直连和代理均在五秒内收到三秒延迟响应');

  const ipv6Server = http.createServer((request, response) => response.end(request.socket.remoteAddress));
  ipv6Server.listen(0, '::1');
  await once(ipv6Server, 'listening');
  try {
    const ipv6Origin = `http://[::1]:${(ipv6Server.address() as net.AddressInfo).port}`;
    for (const proxy of [httpProxy, socksProxy]) {
      assert.equal(await requestTextViaProxy(ipv6Origin, proxy, 5000), '::1');
    }
    console.log('通过：同一个私有内核可以分别通过 IPv4 和 IPv6 访问本机服务');
  } finally {
    await new Promise<void>((resolve) => ipv6Server.close(() => resolve()));
  }
}

async function cleanup(): Promise<void> {
  monitor?.stop(); stream?.destroy();
  if (neighbor && neighbor.exitCode === null && neighbor.signalCode === null) {
    const exited = once(neighbor, 'exit');
    neighbor.kill();
    await exited;
  }
  await Promise.all([service?.shutdown(), reference?.shutdown()]);
  for (const socket of sockets) socket.destroy();
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
}

app.whenReady().then(run).then(async () => {
  if (process.env.GUARD_TEST_ROLE !== 'owner') await cleanup();
}).then(() => app.exit(0)).catch(async (error) => {
  console.error(error);
  try { await cleanup(); }
  finally { app.exit(1); }
});
