import { app } from 'electron';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as net from 'node:net';
import * as yaml from 'js-yaml';
import { setTimeout as delay } from 'node:timers/promises';
import { PrivateProxyService } from '../electron/privateKernel';
import { SubscriptionCatalog, readYaml } from '../electron/subscriptionCatalog';
import { requestTextViaProxy } from '../electron/netClient';
import { ClashMonitor } from '../electron/clashMonitor';
import { ConfigStore } from '../electron/configStore';
import { GeoIpService } from '../electron/geoipService';
import { mihomoRequest } from '../electron/mihomoClient';
import { ProbeEngine } from '../electron/probeEngine';
import { isValidIsoCountryCode } from '../src/shared/countries';

const directory = process.env.GUARD_TEST_DATA!;
fs.mkdirSync(directory, { recursive: true });
app.setPath('userData', directory);
let service: PrivateProxyService;

async function verifyProbeSources(port: number): Promise<void> {
  const aws = 'https://checkip.amazonaws.com';
  const config = new ConfigStore();
  config.update({
    proxyMode: 'manual', manualProxy: { protocol: 'http', host: '127.0.0.1', port },
    customProbeUrl: aws, killProcessesEnabled: false, claudeExclusiveGuard: false,
  });
  const geo = new GeoIpService();
  const engine = new ProbeEngine(config, geo, new ClashMonitor(null), service);
  const ip = (await requestTextViaProxy(aws, `http://127.0.0.1:${port}`, 8000)).trim();
  assert.ok(net.isIP(ip));
  assert.equal(geo.lookup(ip).countryCode, 'UNKNOWN');
  const traced = await engine.checkNow();
  assert.ok(isValidIsoCountryCode(traced.lastProbe?.edgeLoc), traced.lastError || '未获得回显服务的地区');
  console.log('通过：纯 IP 来源缺少离线地区记录时，后续来源返回有效地区');

  await geo.init(process.cwd());
  config.update({ customProbeUrl: '' });
  const kernelDir = path.join(directory, 'kernels', 'antigravity');
  const lease = JSON.parse(fs.readFileSync(path.join(kernelDir, 'runtime.json'), 'utf8'));
  const kernelConfig = readYaml(path.join(kernelDir, lease.revision, 'config.yaml'));
  const blockedHosts = ['ipv4.icanhazip.com', 'checkip.amazonaws.com', 'cp.cloudflare.com', 'www.cloudflare.com'];
  const rules = blockedHosts.map((host) => `DOMAIN,${host},REJECT-DROP`);
  assert.ok(Array.isArray(kernelConfig.rules));
  const payload = yaml.dump({ ...kernelConfig, rules: [...rules, ...kernelConfig.rules] });
  await mihomoRequest(lease.endpoint, '/configs?force=true', 'PUT', { payload });
  const startedAt = Date.now();
  const last = await engine.checkNow();
  assert.ok(isValidIsoCountryCode(last.lastProbe?.countryCode), last.lastError || '最后一个探测来源未返回地区');
  assert.ok(Date.now() - startedAt < 16000, '首轮探测必须在通道时限内完成');
  console.log('通过：前五个探测地址均无法访问时，首轮通过第六个来源取得出口地区');
}

async function run(): Promise<void> {
  const catalog = new SubscriptionCatalog();
  catalog.refresh();
  console.log('本地订阅读取：', JSON.stringify(catalog.groups.map((group) => ({ name: group.name, nodes: group.nodes.length, active: group.isActive }))));
  if (catalog.errors.length) console.log('订阅读取错误：', catalog.errors);
  const nodes = catalog.groups.flatMap((group) => group.nodes);
  const preferred = process.env.GUARD_TEST_NODE_NAME;
  const node = preferred ? nodes.find((item) => item.name === preferred) : nodes.find((item) => /日本|Japan|JP/i.test(item.name));
  assert.ok(node?.profileUid, '需要真实订阅节点，支持使用 GUARD_TEST_NODE_NAME 指定名称');
  const snapshot = catalog.capture(node.profileUid, node.name);
  console.log('测试节点：', node.name, node.type);
  service = new PrivateProxyService(path.join(directory, 'kernels'), path.resolve('resources/mihomo'));
  await Promise.all([
    service.channels.claude.select(snapshot, 28797),
    service.channels.antigravity.select(snapshot, 28798),
  ]);
  for (const channel of Object.values(service.channels)) {
    assert.equal(channel.getState().phase, 'ready', channel.getState().error || '内核未就绪');
    assert.equal(channel.getState().verificationError, null);
  }
  const proxy = 'http://127.0.0.1:28798';
  const exitIp = async () => new URLSearchParams((await requestTextViaProxy('https://cp.cloudflare.com/cdn-cgi/trace', proxy, 10000)).replace(/\r?\n/g, '&')).get('ip');
  const first = await exitIp();
  assert.ok(first);
  console.log('通过：两个独立内核均完成真实 HTTPS 请求');
  const agPid = service.channels.antigravity.getState().pid;
  const oldPid = service.channels.claude.getState().pid!;
  process.kill(oldPid);
  for (let attempt = 0; attempt < 80; attempt++) {
    const state = service.channels.claude.getState();
    if (state.phase === 'ready' && state.pid !== oldPid) break;
    await delay(250);
  }
  assert.equal(service.channels.claude.getState().phase, 'ready');
  assert.notEqual(service.channels.claude.getState().pid, oldPid);
  assert.equal(service.channels.antigravity.getState().pid, agPid);
  assert.equal(await exitIp(), first);
  console.log('通过：Claude 内核异常退出后自动恢复，Antigravity 进程及真实出口保持正常');
  await verifyProbeSources(28798);
}

app.whenReady().then(run).then(() => service.shutdown()).then(() => app.exit(0)).catch(async (error) => {
  console.error(error);
  for (const channel of ['claude', 'antigravity']) {
    const log = path.join(directory, 'kernels', channel, 'kernel.log');
    if (fs.existsSync(log)) console.error(fs.readFileSync(log, 'utf8').slice(-3000));
  }
  if (service) await service.shutdown();
  app.exit(1);
});
