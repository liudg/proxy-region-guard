import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as http from 'node:http';
import * as net from 'node:net';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import * as yaml from 'js-yaml';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { ClashMonitor } from '../electron/clashMonitor';
import { ConfigStore } from '../electron/configStore';
import { GeoIpService } from '../electron/geoipService';
import { PrivateKernel, PrivateProxyService, verifyCore } from '../electron/privateKernel';
import { ProbeEngine } from '../electron/probeEngine';
import { mihomoRequest, isLocalPortListening } from '../electron/mihomoClient';
import { readYaml } from '../electron/subscriptionCatalog';

async function freePort(): Promise<number> {
  const server = net.createServer().listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

export async function validateLegacyMigration(root: string): Promise<void> {
  const directory = path.join(root, 'legacy-migration');
  const profiles = path.join(directory, 'profiles');
  fs.mkdirSync(profiles, { recursive: true });
  fs.writeFileSync(path.join(directory, 'profiles.yaml'), yaml.dump({ current: 'local', items: [{ uid: 'local', name: '迁移订阅', type: 'local', file: 'local.yaml' }] }));
  const sourceFile = path.join(profiles, 'local.yaml');
  const source = { proxies: [{ name: '迁移节点', type: 'direct' }], dns: { 'proxy-server-nameserver': ['223.5.5.5'] } };
  fs.writeFileSync(sourceFile, yaml.dump(source));
  const monitor = new ClashMonitor(directory);
  monitor.catalog.refresh();
  const snapshot = monitor.catalog.capture('local', '迁移节点');
  const core = path.resolve('resources/mihomo');
  const referenceRoot = path.join(directory, 'reference');
  const reference = new PrivateKernel('claude', referenceRoot, verifyCore(core));
  const service = new PrivateProxyService(path.join(directory, 'private'), core);
  const store = new ConfigStore();
  const originalConfig = store.get();
  let engine: ProbeEngine | undefined;
  const nonce = randomUUID();
  const server = http.createServer((_request, response) => response.end(nonce)).listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`;
  const request = async (port: number) => {
    const agent = new SocksProxyAgent(`socks5h://127.0.0.1:${port}`);
    try {
      return await new Promise<string>((resolve, reject) => {
        const req = http.get(origin, { agent }, (response) => {
          let body = '';
          response.setEncoding('utf8').on('data', (chunk) => body += chunk);
          response.on('end', () => resolve(body));
          response.on('error', reject);
        });
        const timeout = setTimeout(() => req.destroy(new Error('迁移代理请求超时')), 5000);
        req.on('close', () => clearTimeout(timeout));
        req.on('error', reject);
      });
    } finally { agent.destroy(); }
  };
  try {
    const referencePort = await freePort();
    const claudePort = await freePort();
    const agPort = await freePort();
    const customPort = await freePort();
    await reference.select(snapshot, referencePort);
    const saved = JSON.parse(fs.readFileSync(path.join(referenceRoot, 'current.json'), 'utf8'));
    const endpoint = JSON.parse(fs.readFileSync(path.join(referenceRoot, 'runtime.json'), 'utf8')).endpoint;
    const base = readYaml(path.join(referenceRoot, saved.revision, 'config.yaml'));
    base.listeners = [{ name: '用户监听', type: 'mixed', port: customPort, listen: '127.0.0.1', proxy: 'DIRECT' }];
    base['proxy-groups'] = [{ name: 'guard-selected-outbound', type: 'select', proxies: ['迁移节点', 'DIRECT'] }];
    const runtimeFile = path.join(directory, 'clash-verge.yaml');
    fs.writeFileSync(runtimeFile, yaml.dump(base));
    const runtimeBytes = fs.readFileSync(runtimeFile);
    const injected = structuredClone(base);
    injected.proxies = [...snapshot.proxies, { name: '__guard_claude_dedicated_proxy__', type: 'direct' }, { name: '__guard_ag_dedicated_proxy__', type: 'direct' }];
    injected.listeners = [...base.listeners as object[],
      { name: 'proxy-region-guard-claude-in', type: 'mixed', port: claudePort, listen: '127.0.0.1', proxy: '__guard_claude_dedicated_proxy__' },
      { name: 'proxy-region-guard-antigravity-in', type: 'mixed', port: agPort, listen: '127.0.0.1', proxy: '__guard_ag_dedicated_proxy__' }];
    await mihomoRequest(endpoint, '/configs?force=true', 'PUT', { payload: yaml.dump(injected) });
    await mihomoRequest(endpoint, '/configs', 'PATCH', { mode: 'global' });
    await mihomoRequest(endpoint, '/proxies/guard-selected-outbound', 'PUT', { name: 'DIRECT' });
    assert.equal(await request(agPort), nonce);
    assert.equal(await request(customPort), nonce);

    store.update({ claudeExclusiveGuard: false, selectedClashNode: null, dedicatedProxyPort: claudePort,
      antigravityClashNode: '迁移节点', antigravityClashProfileUid: 'local', antigravityClashProfileName: '迁移订阅', antigravityDedicatedPort: agPort });
    engine = new ProbeEngine(store, new GeoIpService(), monitor, service);
    const startup = engine as unknown as { restorePrivateSelections(): Promise<void> };
    await startup.restorePrivateSelections();
    assert.equal(service.channels.antigravity.getState().phase, 'ready');
    assert.equal(store.get().antigravityClashNode, '迁移节点');
    assert.equal(store.get().antigravityDedicatedPort, agPort);
    assert.equal(new ConfigStore().get().antigravityClashProfileUid, 'local');
    assert.equal(await isLocalPortListening(claudePort), false);
    assert.equal(await request(agPort), nonce);
    assert.equal(await request(customPort), nonce);
    assert.equal((await mihomoRequest<{ mode: string }>(endpoint, '/configs')).mode, 'global');
    const proxies = await mihomoRequest<{ proxies: Record<string, { now: string }> }>(endpoint, '/proxies');
    assert.equal(proxies.proxies['guard-selected-outbound'].now, 'DIRECT');
    assert.equal(proxies.proxies.__guard_ag_dedicated_proxy__, undefined);
    assert.deepEqual(fs.readFileSync(runtimeFile), runtimeBytes);
    const privatePid = service.channels.antigravity.getState().pid;
    fs.writeFileSync(sourceFile, yaml.dump({ proxies: [] }));
    await startup.restorePrivateSelections();
    assert.equal(service.channels.antigravity.getState().pid, privatePid);
    assert.equal(store.get().antigravityClashNode, '迁移节点');
    console.log('通过：迁移保留节点、订阅与端口，释放旧监听，保留用户监听、运行模式、代理组选择及配置文件');

    engine.stop();
    await service.shutdown();
    const failedService = new PrivateProxyService(path.join(directory, 'failed-private'), core);
    const failedEngine = new ProbeEngine(store, new GeoIpService(), monitor, failedService);
    const previous = fs.readFileSync(path.join(root, 'guard-config.json'));
    try {
      await (failedEngine as unknown as { restorePrivateSelections(): Promise<void> }).restorePrivateSelections();
      assert.equal(failedService.channels.antigravity.getSnapshot(), null);
      assert.deepEqual(fs.readFileSync(path.join(root, 'guard-config.json')), previous);
      assert.match(failedEngine.getSnapshot().antigravityState.nodeProbeError!, /迁移失败/);
      fs.writeFileSync(sourceFile, yaml.dump(source));
      store.update({ antigravityDedicatedPort: customPort });
      const occupiedConfig = fs.readFileSync(path.join(root, 'guard-config.json'));
      await (failedEngine as unknown as { restorePrivateSelections(): Promise<void> }).restorePrivateSelections();
      assert.deepEqual(fs.readFileSync(path.join(root, 'guard-config.json')), occupiedConfig);
      assert.equal(failedService.channels.antigravity.getSnapshot(), null);
      assert.equal(await request(customPort), nonce);
      store.update({ antigravityDedicatedPort: agPort });
      await (failedEngine as unknown as { restorePrivateSelections(): Promise<void> }).restorePrivateSelections();
      assert.equal(failedService.channels.antigravity.getState().phase, 'ready');
      assert.equal(await request(agPort), nonce);
      console.log('通过：订阅缺失及其他监听占用端口时保留原配置，故障处理后能够重新迁移');
    } finally { failedEngine.stop(); await failedService.shutdown(); }
  } finally {
    engine?.stop();
    monitor.stop();
    await Promise.all([service.shutdown(), reference.shutdown()]);
    store.update(originalConfig);
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}
