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
import { readWindowsSystemProxy } from '../electron/systemProxy';
import { getTargetServiceVerificationError } from '../src/shared/probeValidation';
import { COUNTRY_DEFAULT_WINDOWS_TZ } from '../src/shared/timezones';

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
  const candidates = [
    process.env.GUARD_TEST_MIHOMO,
    'C:\\Program Files\\Clash Verge\\verge-mihomo.exe',
    'C:\\ProgramData\\clash-verge-service\\cores\\verge-mihomo.exe',
  ].filter((item): item is string => Boolean(item));
  const executable = candidates.find((item) => fs.existsSync(item));
  if (!executable) {
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

      const systemProxy = await readWindowsSystemProxy();
      let hostMixedProxy: string | null = null;
      const hostEndpoint = await source.findWorkingEndpoint();
      if (hostEndpoint) {
        try {
          const cfg = await source.requestJson(hostEndpoint, '/configs', 1000);
          const mixedPort = Number(cfg?.['mixed-port'] || cfg?.['port'] || 0);
          if (mixedPort > 0) hostMixedProxy = `http://127.0.0.1:${mixedPort}`;
        } catch {
          // ignore
        }
      }
      const verificationProxy =
        process.env.GUARD_TEST_CLAUDE_PROXY || systemProxy.proxyUrl || hostMixedProxy;
      assert.ok(verificationProxy, 'Claude 安全检查需要可用的代理');
      const upstream = new URL(verificationProxy);
      assert.ok(['http:', 'socks5:', 'socks5h:'].includes(upstream.protocol));
      const upstreamName = '运行期检查专用通道';
      const upstreamProxy = {
        name: upstreamName, type: upstream.protocol === 'http:' ? 'http' : 'socks5',
        server: upstream.hostname, port: Number(upstream.port),
        ...(upstream.username ? { username: decodeURIComponent(upstream.username) } : {}),
        ...(upstream.password ? { password: decodeURIComponent(upstream.password) } : {}),
      };
      writeProvider([...proxies, upstreamProxy]);
      const verifiedState = await engine.selectClashNode(upstreamName, node.profileUid);
      const verified = verifiedState.claudeState.nodeProbe;
      assert.ok(verified, verifiedState.claudeState.nodeProbeError || '未取得真实出口结果');
      assert.equal(getTargetServiceVerificationError(verified), null);
      const actualLocale = await readWindowsLocaleState();
      const matchingLocale = {
        ...actualLocale,
        regionCode: verified.countryCode,
        regionName: verified.countryName,
        timeZoneId: COUNTRY_DEFAULT_WINDOWS_TZ[verified.countryCode] || actualLocale.timeZoneId,
      };
      runtime.winLocale = matchingLocale;
      const initialSafety = runtime.evaluateClaudeSafety();
      assert.equal(initialSafety.safe, true, initialSafety.reason);
      assert.equal(runtime.getClaudeExpectedRegion().countryCode, verified.countryCode);

      // 同时将 Antigravity 绑定至可用通道，验证 Clash Verge 切换订阅组、重载闪断及半途中断恢复
      const verifiedAgState = await engine.selectAntigravityClashNode(upstreamName, node.profileUid);
      const verifiedAg = verifiedAgState.antigravityState.nodeProbe;
      assert.ok(verifiedAg, verifiedAgState.antigravityState.nodeProbeError || 'Antigravity 未取得真实出口结果');
      assert.equal(getTargetServiceVerificationError(verifiedAg, 'antigravity'), null);

      const secondProfileUid = `${node.profileUid}-other`;
      const secondProfilePath = path.join(root, 'profiles', 'other-subscription.yaml');
      fs.writeFileSync(secondProfilePath, yaml.dump({
        proxies: [{ name: 'Other-Node', type: 'socks5', server: '127.0.0.1', port: 65530 }],
      }));
      const writeProfilesYaml = (activeUid: string) => {
        fs.writeFileSync(path.join(root, 'profiles.yaml'), yaml.dump({
          current: activeUid,
          items: [
            { uid: node.profileUid, name: node.profileName, type: 'local', file: 'subscription.yaml' },
            { uid: secondProfileUid, name: '备用测试订阅', type: 'local', file: 'other-subscription.yaml' },
          ],
        }));
      };
      const simulateClashVergeReload = async (extraDoc: Record<string, unknown> = {}) => {
        const coreDoc = {
          'external-controller': `127.0.0.1:${controllerPort}`,
          mode: 'rule',
          'log-level': 'silent',
          ipv6: false,
          proxies: [{ name: 'Other-Node', type: 'socks5', server: '127.0.0.1', port: 65530 }],
          hosts: { 'intranet.local': '10.0.0.1' },
          dns: {
            'enhanced-mode': 'fake-ip',
            'nameserver-policy': {
              '+.quandao.com': ['223.5.5.5'],
              '+.jiandaoyun.com': ['223.5.5.5'],
            },
          },
          rules: ['MATCH,DIRECT'],
          tun: { enable: false },
          ...extraDoc,
        };
        const rawCoreYaml = yaml.dump(coreDoc) + `secret: ${secret}\n`;
        fs.writeFileSync(yamlPath, rawCoreYaml);
        await internal.requestRaw(
          endpoint,
          'PUT',
          '/configs?force=true',
          JSON.stringify({ payload: rawCoreYaml }),
          3500
        );
      };

      // 1) 切换订阅组（携带全局 hosts/nameserver-policy 且清空卫士专属监听）后：自动无感补回监听且不清空/重刷健康探测结果
      const claudeSeqBeforeSwitch = runtime.claudeProbeSeq;
      const agSeqBeforeSwitch = runtime.antigravityProbeSeq;
      const claudeDefBeforeSwitch = internal.slots.claude.boundDefinition;
      const agDefBeforeSwitch = internal.slots.antigravity.boundDefinition;
      claudeReprobed = false;
      agReprobed = false;

      writeProfilesYaml(secondProfileUid);
      await simulateClashVergeReload();
      const wipedKernel = await internal.requestJson(endpoint, '/proxies');
      assert.equal(wipedKernel.proxies.__guard_claude_dedicated_proxy__, undefined);
      assert.equal(wipedKernel.proxies.__guard_ag_dedicated_proxy__, undefined);

      await internal.tick();
      await sleep(350);
      assert.equal(monitor.getRuntimeInfo().dedicatedPortListening, true);
      assert.equal(monitor.getRuntimeInfo().antigravityPortListening, true);
      assert.equal(internal.slots.claude.boundDefinition, claudeDefBeforeSwitch);
      assert.equal(internal.slots.antigravity.boundDefinition, agDefBeforeSwitch);
      assert.equal(runtime.claudeProbeSeq, claudeSeqBeforeSwitch);
      assert.equal(runtime.antigravityProbeSeq, agSeqBeforeSwitch);
      assert.equal(claudeReprobed, false);
      assert.equal(agReprobed, false);
      assert.ok(engine.getSnapshot().claudeState.nodeProbe);
      assert.ok(engine.getSnapshot().antigravityState.nodeProbe);

      // 再切回原订阅组，依然不应误判定义变化或重刷
      writeProfilesYaml(node.profileUid);
      await simulateClashVergeReload();
      await internal.tick();
      await sleep(350);
      assert.equal(internal.slots.claude.boundDefinition, claudeDefBeforeSwitch);
      assert.equal(internal.slots.antigravity.boundDefinition, agDefBeforeSwitch);
      assert.equal(runtime.claudeProbeSeq, claudeSeqBeforeSwitch);
      assert.equal(runtime.antigravityProbeSeq, agSeqBeforeSwitch);
      assert.equal(claudeReprobed, false);
      assert.equal(agReprobed, false);
      console.log('通过：Clash Verge 切换订阅组及全局 DNS 策略不误刷 Claude 与 Antigravity 健康探测状态');

      // 2) profiles.yaml 早于或晚于 clash-verge.yaml 落盘均不污染节点池且不冻结补绑（验证 Bug 1A / 1B 修复）
      writeProfilesYaml(secondProfileUid);
      await internal.tick();
      const secondGroupBeforeReload = monitor
        .getRuntimeInfo()
        .profileGroups.find((g) => g.uid === secondProfileUid);
      assert.deepEqual(
        secondGroupBeforeReload?.nodes.map((n) => n.name),
        ['Other-Node'],
        '切换订阅瞬间未更新的 clash-verge.yaml 旧节点不应污染新订阅节点池'
      );
      assert.equal(monitor.getRuntimeInfo().dedicatedPortListening, true);
      assert.equal(monitor.getRuntimeInfo().antigravityPortListening, true);

      // 模拟 Clash Verge 先重载生成 clash-verge.yaml 清空端口、随后再保存 profiles.yaml（pStat.mtimeMs > rStat.mtimeMs）
      await simulateClashVergeReload();
      const olderRuntimeTime = new Date(Date.now() - 800);
      fs.utimesSync(yamlPath, olderRuntimeTime, olderRuntimeTime);
      writeProfilesYaml(secondProfileUid);
      await internal.tick();
      assert.equal(
        monitor.getRuntimeInfo().dedicatedPortListening,
        true,
        'profiles.yaml 晚于 clash-verge.yaml 落盘时也应立即补绑端口，不得被时间戳冻结'
      );
      assert.equal(monitor.getRuntimeInfo().antigravityPortListening, true);
      writeProfilesYaml(node.profileUid);
      await simulateClashVergeReload();
      await internal.tick();
      console.log('通过：profiles.yaml 早于或晚于 clash-verge.yaml 写入均不污染节点池且立即补绑恢复');

      // 2b) 宽限期内单次补绑瞬态失败不清空健康探测态且第 2 拍继续受宽限保护 + isTicking 期间唤醒不丢失（验证 Bug 2 / Bug 3）
      internal.isTicking = true;
      await internal.tick();
      assert.equal(internal.pendingImmediateTick, true);
      internal.isTicking = false;
      internal.pendingImmediateTick = false;

      internal.rebindGraceUntil = Date.now() + 8000;
      const origReloadDoc = internal.reloadClashDocAndRestoreSelections.bind(internal);
      let concurrentWipeOnce = true;
      internal.reloadClashDocAndRestoreSelections = async (
        doc: Record<string, unknown>,
        selections: Array<{ group: string; now: string }>
      ) => {
        await origReloadDoc(doc, selections);
        if (concurrentWipeOnce) {
          concurrentWipeOnce = false;
          await simulateClashVergeReload();
        }
      };
      try {
        await simulateClashVergeReload();
        await internal.tick();
        assert.equal(concurrentWipeOnce, false);
        assert.equal(monitor.getRuntimeInfo().dedicatedPortListening, true);
        assert.equal(monitor.getRuntimeInfo().antigravityPortListening, true);
        assert.ok(engine.getSnapshot().claudeState.nodeProbe, '宽限期瞬态失败不应清空健康探测态');
        assert.ok(engine.getSnapshot().antigravityState.nodeProbe, '宽限期瞬态失败不应清空健康探测态');
        assert.equal(internal.slots.claude.boundNodeName, upstreamName);
        assert.equal(internal.slots.antigravity.boundNodeName, upstreamName);
        await internal.tick();
        assert.equal(monitor.getRuntimeInfo().dedicatedPortListening, true);
        assert.equal(monitor.getRuntimeInfo().antigravityPortListening, true);
        const restoredKernel = await internal.requestJson(endpoint, '/proxies');
        assert.ok(restoredKernel.proxies.__guard_claude_dedicated_proxy__);
        assert.ok(restoredKernel.proxies.__guard_ag_dedicated_proxy__);
      } finally {
        internal.reloadClashDocAndRestoreSelections = origReloadDoc;
      }
      console.log('通过：宽限期瞬态补绑失败保留绑定与健康探测态，且 isTicking 唤醒补偿正常');

      // 3) 若此前处于失败或校验未完成状态，内核监听补绑完成后自动自愈重测（Claude & Antigravity）
      runtime.claudeNodeProbe = {
        ...verified,
        claudeTraceLoc: undefined,
        claudeTraceError: 'https://claude.ai/cdn-cgi/trace：connect ECONNREFUSED',
      };
      runtime.antigravityNodeProbe = {
        ...verifiedAg,
        googleCountryCode: undefined,
        googleCountryName: undefined,
      };
      await simulateClashVergeReload();
      await internal.tick();
      await sleep(350);
      await Promise.all([runtime.claudeProbePromise, runtime.antigravityProbePromise]);
      assert.equal(getTargetServiceVerificationError(engine.getSnapshot().claudeState.nodeProbe, 'claude'), null);
      assert.equal(getTargetServiceVerificationError(engine.getSnapshot().antigravityState.nodeProbe, 'antigravity'), null);
      console.log('通过：内核专属监听补绑后自动自愈 Claude 与 Antigravity 残留的失败/未完成校验状态');

      // 4) 二阶段连续两次重载冲掉专属端口仍能恢复 + 正常网络失败不空跑翻倍 + 对端运行时禁止跨通道强刷（验证 Bug 4 / 过度设计精简）
      runtime.claudeRunning = true;
      runtime.antigravityRunning = false;
      assert.equal(runtime.canForceReloadDedicatedListeners(), false);
      runtime.claudeRunning = false;
      assert.equal(runtime.canForceReloadDedicatedListeners(), true);

      let normalFailCalls = 0;
      const origVerify = runtime.verifyTargetServiceRegion.bind(runtime);
      runtime.verifyTargetServiceRegion = async (
        _pUrl: string | null,
        pRes: any,
        targetApp: 'claude' | 'antigravity'
      ) => {
        normalFailCalls++;
        if (targetApp === 'claude') {
          pRes.claudeTraceLoc = undefined;
          pRes.claudeTraceError = '模拟目标站网络超时（本地专属端口完好）';
        } else {
          pRes.googleCountryCode = undefined;
        }
      };
      try {
        await engine.probeAntigravityNodeNow();
        assert.equal(normalFailCalls, 1, '本地专属监听完好时二阶段失败不应空转重跑第二遍');
      } finally {
        runtime.verifyTargetServiceRegion = origVerify;
      }

      let claudeWipeCount = 0;
      let agWipeCount = 0;
      runtime.verifyTargetServiceRegion = async (
        pUrl: string | null,
        pRes: unknown,
        targetApp: 'claude' | 'antigravity',
        forceRefresh?: boolean
      ) => {
        if (targetApp === 'claude' && claudeWipeCount < 2) {
          claudeWipeCount++;
          await simulateClashVergeReload();
          if (claudeWipeCount === 2) {
            // 第 2 次重载由 ClashMonitor 巡检补绑并触发 claude-listener-rebound，验证连续两次重载不丢事件
            void internal.tick();
          }
        } else if (targetApp === 'antigravity' && agWipeCount < 2) {
          agWipeCount++;
          await simulateClashVergeReload();
          if (agWipeCount === 2) {
            void internal.tick();
          }
        }
        return origVerify(pUrl, pRes, targetApp, forceRefresh);
      };
      try {
        const midReloadClaude = await engine.probeClaudeNodeNow('手动刷新验证连续重载恢复', true);
        assert.equal(claudeWipeCount, 2);
        assert.equal(getTargetServiceVerificationError(midReloadClaude.claudeState.nodeProbe, 'claude'), null);

        const midReloadAg = await engine.probeAntigravityNodeNow();
        assert.equal(agWipeCount, 2);
        assert.equal(getTargetServiceVerificationError(midReloadAg.antigravityState.nodeProbe, 'antigravity'), null);
      } finally {
        runtime.verifyTargetServiceRegion = origVerify;
      }
      await engine.selectAntigravityClashNode(null, null);
      console.log('通过：连续两次内核重载恢复、正常超时单次退出及对端运行跨通道防强刷验证通过');

      const rejectedEndpoint = { ...endpoint, secret: `${secret}-invalid` };
      internal.currentEndpoint = rejectedEndpoint;
      internal.rebindGraceUntil = 0;
      await internal.tick();
      monitor.stop();
      assert.equal(monitor.getRuntimeInfo().connected, false);
      assert.match(monitor.getRuntimeInfo().bindingVerificationError || '', /401/);
      const stillReachable = await runtime.probeOnceViaChannel(
        `http://127.0.0.1:${firstPort}`, '控制接口故障期间出口检查', 5800
      );
      assert.ok(stillReachable.result, stillReachable.errMsg);
      assert.equal(runtime.evaluateClaudeSafety().alertType, 'verification-unavailable');
      console.log('通过：真实控制接口返回 401 且代理出口仍可达时，ProbeEngine 判定为等待复核');

      internal.currentEndpoint = rejectedEndpoint;
      const unavailable = await engine.probeClaudeNodeNow('控制接口故障检查', true);
      assert.ok(unavailable.claudeState.nodeProbe);
      assert.equal(unavailable.claudeState.nodeProbe.countryCode, verified.countryCode);
      assert.equal(runtime.getClaudeExpectedRegion().countryCode, verified.countryCode);
      assert.equal(runtime.evaluateClaudeSafety().alertType, 'verification-unavailable');
      runtime.claudeNodeProbe = null;
      assert.equal(runtime.getClaudeExpectedRegion().countryCode, verified.countryCode);
      assert.equal(runtime.evaluateClaudeSafety().alertType, 'verification-unavailable');
      const otherCountry = verified.countryCode === 'JP' ? 'US' : 'JP';
      try {
        runtime.winLocale = { ...matchingLocale, regionCode: otherCountry };
        assert.equal(runtime.evaluateClaudeSafety().alertType, 'locale-mismatch');
        runtime.winLocale = { ...matchingLocale, timeZoneId: COUNTRY_DEFAULT_WINDOWS_TZ[otherCountry] };
        assert.equal(runtime.evaluateClaudeSafety().alertType, 'locale-mismatch');
      } finally {
        runtime.winLocale = matchingLocale;
      }
      const binding = store.get();
      try {
        for (const change of [
          { selectedClashNode: `${upstreamName}-changed` },
          { selectedClashProfileUid: `${node.profileUid}-changed` },
          { dedicatedProxyPort: secondPort },
        ]) {
          store.update(change);
          assert.equal(runtime.getClaudeExpectedRegion(), null);
          store.update(binding);
        }
      } finally {
        store.update(binding);
      }
      console.log('通过：真实检测失败保留同一绑定的地区基准，冲突区域及时区输入均立即判定为冲突');

      internal.currentEndpoint = endpoint;
      const restored = await engine.probeClaudeNodeNow('控制接口恢复后的手动检查', true);
      assert.equal(monitor.getRuntimeInfo().bindingVerificationError, null);
      assert.ok(restored.claudeState.nodeProbe);
      assert.equal(getTargetServiceVerificationError(restored.claudeState.nodeProbe), null);
      assert.equal(runtime.evaluateClaudeSafety().safe, true);
      writeProvider(proxies);
      const removedBinding = await monitor.configureDedicatedNode(upstreamName, firstPort, node.profileUid, true);
      assert.equal(removedBinding.listening, false);
      assert.equal(monitor.getRuntimeInfo().bindingVerificationError, null);
      assert.equal(runtime.evaluateClaudeSafety().alertType, 'disconnect');
      await engine.selectClashNode(null);
      assert.equal(runtime.getClaudeExpectedRegion(), null);
      console.log('通过：实际恢复绑定后校验通过，确认节点缺失时判定绑定失效，取消绑定后清除地区基准');
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
