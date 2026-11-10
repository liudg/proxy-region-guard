import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as sleep } from 'node:timers/promises';
import { ClashMonitor } from '../electron/clashMonitor';
import { ConfigStore } from '../electron/configStore';
import { GeoIpService } from '../electron/geoipService';
import { ProbeEngine } from '../electron/probeEngine';
import { AppStateSnapshot } from '../src/shared/types';
import { readWindowsLocaleState } from '../electron/winSystemLocale';

const yaml = require('js-yaml');

async function availablePort(): Promise<number> {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

export async function runMihomoIntegration(directory: string, sourceMonitor: ClashMonitor): Promise<void> {
  const executable = process.env.GUARD_TEST_MIHOMO || 'C:\\Program Files\\Clash Verge\\verge-mihomo.exe';
  if (!fs.existsSync(executable)) {
    console.log('未执行：独立内核验证需要设置 GUARD_TEST_MIHOMO');
    return;
  }
  const source = sourceMonitor as any;
  const scanned = source.scanAllClashVergeProfiles({});
  const node = scanned.availableNodes[0];
  assert.ok(node, '独立内核验证需要可读取的真实订阅节点');
  const definition = source.resolveSlotTargetNodeDefinition({
    desiredNodeName: node.name, desiredProfileUid: node.profileUid,
  });
  assert.ok(definition);
  const proxies = [definition.rawProxy, ...definition.dialerChain];
  const root = path.join(directory, 'mihomo');
  fs.mkdirSync(path.join(root, 'profiles'), { recursive: true });
  const providerPath = path.join(root, 'provider.yaml');
  const profilePath = path.join(root, 'profiles', 'subscription.yaml');
  const yamlPath = path.join(root, 'clash-verge.yaml');
  const writeProvider = (entries: unknown[]) => fs.writeFileSync(providerPath, yaml.dump({ proxies: entries }));
  writeProvider(proxies);
  fs.writeFileSync(profilePath, yaml.dump({
    'proxy-providers': { subscription: { type: 'file', path: providerPath } },
    hosts: definition.hosts, dns: { 'nameserver-policy': definition.nameserverPolicy },
  }));
  fs.writeFileSync(path.join(root, 'profiles.yaml'), yaml.dump({
    current: node.profileUid,
    items: [{ uid: node.profileUid, name: node.profileName, type: 'local', file: 'subscription.yaml' }],
  }));
  const controllerPort = await availablePort();
  const firstPort = await availablePort();
  const secondPort = await availablePort();
  const secret = '00123456';
  fs.writeFileSync(yamlPath, yaml.dump({
    'external-controller': `127.0.0.1:${controllerPort}`,
    mode: 'rule', 'log-level': 'silent', ipv6: false,
    proxies: [], rules: ['MATCH,DIRECT'], tun: { enable: false },
  }) + `secret: ${secret}\n`);

  const monitor = new ClashMonitor();
  const internal = monitor as any;
  const endpoint = { label: '独立测试内核', host: '127.0.0.1', port: controllerPort, secret, yamlFile: yamlPath };
  internal.currentEndpoint = endpoint;
  const processHandle = spawn(executable, ['-d', root, '-f', yamlPath], { windowsHide: true, stdio: 'ignore' });
  await once(processHandle, 'spawn');
  const exited = once(processHandle, 'exit');
  try {
    let ready = false;
    for (let attempt = 0; attempt < 40; attempt++) {
      assert.equal(processHandle.exitCode, null, '独立 Mihomo 内核提前退出');
      try {
        await internal.requestJson(endpoint, '/version', 200);
        ready = true;
        break;
      } catch {
        await sleep(100);
      }
    }
    assert.ok(ready, '独立 Mihomo 控制接口启动超时');

    const metadata = internal.readControllerMetadataCached(yamlPath);
    assert.equal(metadata.port, controllerPort);
    assert.equal(metadata.secret, secret);
    await internal.requestJson({ ...endpoint, secret: metadata.secret }, '/version');
    await assert.rejects(internal.requestJson({ ...endpoint, secret: undefined }, '/version'), /401/);
    console.log('通过：未加引号且含前导零的数字密码可连接真实 Mihomo 控制接口');
    const metadataPath = path.join(root, 'controller-metadata.yaml');
    fs.writeFileSync(metadataPath, yaml.dump({ description: '控制接口配置说明'.repeat(4000) }) +
      `"external-controller": "127.0.0.1:${controllerPort}"\n"secret": "${secret}"\n`);
    const extendedMetadata = internal.readControllerMetadataCached(metadataPath);
    assert.equal(extendedMetadata.port, controllerPort);
    assert.equal(extendedMetadata.secret, secret);
    fs.writeFileSync(metadataPath, `shared: &controller\n  external-controller: 127.0.0.1:${controllerPort}\n` +
      `  secret: ${secret}\n<<: *controller\nport: !!int 7890\n`);
    assert.equal(internal.readControllerMetadataCached(metadataPath).secret, secret);
    console.log('通过：完整 YAML 解析支持带引号的键名及超过 16KB 的控制接口配置');
    const initial = internal.readProfileNodesCached(profilePath, root);
    assert.ok(initial.rawMap.has(node.name));
    const parentStat = fs.statSync(profilePath);
    writeProvider([]);
    assert.equal(internal.readProfileNodesCached(profilePath, root).nodes.length, 0);
    assert.equal(fs.statSync(profilePath).mtimeMs, parentStat.mtimeMs);
    fs.unlinkSync(providerPath);
    assert.equal(internal.readProfileNodesCached(profilePath, root).nodes.length, 0);
    writeProvider(proxies);
    assert.ok(internal.readProfileNodesCached(profilePath, root).rawMap.has(node.name));
    console.log('通过：真实订阅 provider 更新、删除与重新创建使缓存失效');

    const first = monitor.configureAntigravityNode(node.name, firstPort, node.profileUid, true);
    const second = monitor.configureAntigravityNode(node.name, secondPort, node.profileUid, true);
    const results = await Promise.all([first, second]);
    assert.ok(results.every((result) => result.ok), '独立内核绑定失败');
    assert.equal(monitor.getRuntimeInfo().antigravityDedicatedPort, secondPort);
    const active = await internal.requestJson(endpoint, '/proxies');
    assert.ok(active.proxies.__guard_ag_dedicated_proxy__);
    assert.equal(internal.slots.antigravity.boundPort, secondPort);
    console.log('通过：真实 Mihomo 并发绑定按顺序完成，最终端口采用最新配置');

    writeProvider([]);
    await internal.tick();
    assert.equal(monitor.getRuntimeInfo().antigravityPortListening, false);
    writeProvider(proxies);
    const rebound = await monitor.configureAntigravityNode(node.name, secondPort, node.profileUid, false);
    assert.equal(rebound.ok, true);
    console.log('通过：真实 Mihomo 巡检在 provider 节点删除后解除绑定，恢复文件后重新绑定');

    await monitor.configureAntigravityNode(null, secondPort, null, true);
    const store = new ConfigStore();
    const previous = store.get();
    store.update({ selectedClashNode: null, selectedClashProfileUid: null,
      dedicatedProxyPort: firstPort, antigravityClashNode: null, antigravityClashProfileUid: null,
      antigravityDedicatedPort: secondPort, heartbeatIntervalSec: 0 });
    const geo = new GeoIpService();
    await geo.init(process.cwd());
    const engine = new ProbeEngine(store, geo, monitor);
    const runtime = engine as any;
    runtime.winLocale = await readWindowsLocaleState();
    const configPath = path.join(directory, 'guard-config.json');
    const withBlockedSave = async (operation: () => Promise<void>) => {
      fs.renameSync(configPath, `${configPath}.saved`);
      fs.mkdirSync(configPath);
      try {
        await operation();
      } finally {
        fs.rmdirSync(configPath);
        fs.renameSync(`${configPath}.saved`, configPath);
      }
    };
    try {
      await withBlockedSave(async () => {
        await assert.rejects(engine.selectAntigravityClashNode(node.name, node.profileUid));
        await assert.rejects(engine.selectClashNode(node.name, node.profileUid));
        assert.equal(store.get().selectedClashNode, null);
        assert.equal(store.get().antigravityClashNode, null);
        assert.equal(internal.slots.claude.desiredNodeName, null);
        assert.equal(internal.slots.antigravity.desiredNodeName, null);
        const kernel = await internal.requestJson(endpoint, '/proxies');
        assert.equal(kernel.proxies.__guard_claude_dedicated_proxy__, undefined);
        assert.equal(kernel.proxies.__guard_ag_dedicated_proxy__, undefined);
        assert.equal(runtime.applicationChangeInProgress, false);
      });
      console.log('通过：首次绑定保存失败时，Claude 和 Antigravity 均保持未绑定状态');

      await engine.selectClashNode(node.name, node.profileUid);
      await engine.selectAntigravityClashNode(node.name, node.profileUid);
      assert.equal(monitor.getRuntimeInfo().dedicatedPortListening, true);
      assert.equal(monitor.getRuntimeInfo().antigravityPortListening, true);
      await withBlockedSave(async () => {
        await assert.rejects(engine.selectAntigravityClashNode(null));
        await assert.rejects(engine.selectClashNode(null));
        assert.equal(store.get().selectedClashNode, node.name);
        assert.equal(store.get().antigravityClashNode, node.name);
        assert.equal(internal.slots.claude.desiredNodeName, node.name);
        assert.equal(internal.slots.antigravity.desiredNodeName, node.name);
        const kernel = await internal.requestJson(endpoint, '/proxies');
        assert.ok(kernel.proxies.__guard_claude_dedicated_proxy__);
        assert.ok(kernel.proxies.__guard_ag_dedicated_proxy__);
      });
      console.log('通过：取消绑定保存失败时，配置与真实 Mihomo 原有绑定保持一致');

      await internal.tick();
      await Promise.all([engine.probeClaudeNodeNow('回归验证', true), engine.probeAntigravityNodeNow()]);
      let claudeReprobed = false;
      let agReprobed = false;
      engine.on('state-changed', (state: AppStateSnapshot) => {
        claudeReprobed ||= state.claudeState.isProbingNode;
        agReprobed ||= state.antigravityState.isProbingNode;
      });
      for (const apply of [
        () => internal.tick(),
        () => monitor.configureAntigravityNode(node.name, secondPort, node.profileUid, false),
      ]) {
        const claudeSequence = runtime.claudeProbeSeq;
        const agSequence = runtime.antigravityProbeSeq;
        const claudeDefinition = internal.slots.claude.boundDefinition;
        const agDefinition = internal.slots.antigravity.boundDefinition;
        claudeReprobed = false;
        agReprobed = false;
        proxies[0].udp = !proxies[0].udp;
        writeProvider(proxies);
        await apply();
        assert.notEqual(internal.slots.claude.boundDefinition, claudeDefinition);
        assert.notEqual(internal.slots.antigravity.boundDefinition, agDefinition);
        assert.ok(runtime.claudeProbeSeq > claudeSequence);
        assert.ok(runtime.antigravityProbeSeq > agSequence);
        assert.equal(engine.getSnapshot().claudeState.nodeProbe, null);
        assert.equal(engine.getSnapshot().antigravityState.nodeProbe, null);
        assert.equal(engine.getSnapshot().claudeState.nodeProbeError, null);
        assert.equal(engine.getSnapshot().antigravityState.nodeProbeError, null);
        await sleep(350);
        assert.equal(claudeReprobed, true);
        assert.equal(agReprobed, true);
        assert.equal(runtime.heartbeatTimer, null);
        await Promise.all([runtime.claudeProbePromise, runtime.antigravityProbePromise]);
      }
      console.log('通过：关闭心跳时，巡检及手动绑定均使同名 provider 的旧探测失效并自动重新检测');

      const sequence = runtime.antigravityProbeSeq;
      const config = store.get();
      assert.equal(runtime.isCurrentAntigravityProbe(sequence, config), true);
      const pendingRetry = sleep(320).then(() => runtime.isCurrentAntigravityProbe(sequence, config));
      await engine.selectAntigravityClashNode(null, null);
      assert.equal(await pendingRetry, false);
      assert.equal(monitor.getRuntimeInfo().antigravityPortListening, false);
      assert.equal(store.get().antigravityClashNode, null);
      console.log('通过：真实节点配置变更使等待中的旧探测重试失效');
    } finally {
      engine.stop();
      store.update(previous);
    }
  } finally {
    monitor.stop();
    if (processHandle.exitCode === null && processHandle.signalCode === null) processHandle.kill();
    await exited;
  }
}
