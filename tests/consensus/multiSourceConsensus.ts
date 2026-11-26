import assert from 'node:assert/strict';
import { once } from 'node:events';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import * as yaml from 'js-yaml';
import {
  ClashMonitor,
  isLocalPortListening,
  mihomoRequest,
  readYaml,
  SubscriptionCatalog,
} from '../../electron/clash';
import {
  evaluateClaudeNodeProbeSafety,
  isProbeRegionMismatched,
  ProbeEngine,
  resolveAlertActualMismatchFields,
} from '../../electron/guard';
import { PrivateProxyService } from '../../electron/kernel';
import { requestTextViaProxy } from '../../electron/net';
import {
  BUILTIN_TRACE_ENDPOINTS,
  MIN_CONSENSUS_MATCHES,
  selectProbeEndpointsForTransportHosts,
  TraceEndpoint,
} from '../../electron/probe';
import { ConfigStore, GeoIpService, readWindowsLocaleState } from '../../electron/system';
import { getTargetServiceVerificationError } from '../../src/shared/probeValidation';
import {
  isWindowsLocaleMatchingCountry,
  resolveWindowsTimeZoneForCountry,
} from '../../src/shared/timezones';
import { createConsensusRelayRig } from './consensusRelayFixtures';
import {
  extractEchoIpFromBody,
  freePort,
  readLeaseEndpoint,
  reloadKernelConfig,
  root,
  trackService,
  untrackService,
} from './testHarness';

export async function verifyMultiSourceConsensus(coreDir: string): Promise<void> {
  const tlsCertPath = process.env.GUARD_TEST_TLS_CERT;
  const tlsKeyPath = process.env.GUARD_TEST_TLS_KEY;
  assert.ok(
    tlsCertPath &&
      tlsKeyPath &&
      process.env.NODE_EXTRA_CA_CERTS &&
      fs.existsSync(tlsCertPath) &&
      fs.existsSync(tlsKeyPath),
    '缺少多源共识真实 HTTPS 回归所需的测试 TLS 证书环境变量（请通过 npm test 运行）'
  );
  const tlsCert = fs.readFileSync(tlsCertPath, 'utf8');
  const tlsKey = fs.readFileSync(tlsKeyPath, 'utf8');

  const liveRoot = path.join(root, 'live-consensus');
  const upstreamService = trackService(
    new PrivateProxyService(path.join(liveRoot, 'upstream-kernels'), coreDir)
  );
  const subService = trackService(
    new PrivateProxyService(path.join(liveRoot, 'sub-kernels'), coreDir)
  );
  const geo = new GeoIpService();
  await geo.init(process.cwd());

  const rig = await createConsensusRelayRig(liveRoot, tlsCert, tlsKey, geo);
  const {
    expectedProxyIp,
    expectedProxyDriftedIp,
    expectedForeignIp,
    expectedProxyCountry,
    expectedForeignCountry,
    upstreamPort,
    directUpstreamPort,
    baseUpstreamPort,
    subPort,
    relayPort,
    directDelayPort,
    connectHopPort,
    countedPassPort,
    holdBeforeTlsPort,
    claudeHoldPort,
    primarySnapshot,
    foreignSnapshot,
    observedHopTargets,
    observedHopHosts,
    acceptedPassHosts,
    heldDropClients,
    claudeHoldClients,
  } = rig;

  let subEngine: ProbeEngine | null = null;
  let onSubGeoLookup: ((countryCode: string) => void) | null = null;
  try {
    await upstreamService.channels.claude.select(primarySnapshot, upstreamPort);
    assert.equal(upstreamService.channels.claude.getState().phase, 'ready');

    const upLease = readLeaseEndpoint(path.join(liveRoot, 'upstream-kernels', 'claude'));
    const upBaseCfg = readYaml(upLease.configPath);
    const upProxies = Array.isArray(upBaseCfg.proxies)
      ? (upBaseCfg.proxies as Array<Record<string, unknown>>)
      : [];
    const upHosts = (
      upBaseCfg.hosts && typeof upBaseCfg.hosts === 'object' ? upBaseCfg.hosts : {}
    ) as Record<string, unknown>;
    const outboundGroup = 'guard-selected-outbound';
    const foreignTarget = foreignSnapshot.nodeName;
    const extraForeignProxies: Array<Record<string, unknown>> =
      foreignSnapshot.proxies.map((p) => ({ ...p }));
    const extraForeignHosts: Record<string, unknown> = { ...foreignSnapshot.hosts };
    const makeUpstreamConfig = (rules: string[]) =>
      yaml.dump({
        ...upBaseCfg,
        hosts: { ...upHosts, ...extraForeignHosts },
        listeners: [
          {
            name: 'test-base-upstream',
            type: 'mixed',
            port: baseUpstreamPort,
            listen: '127.0.0.1',
            proxy: outboundGroup,
          },
          {
            name: 'test-direct-upstream',
            type: 'mixed',
            port: directUpstreamPort,
            listen: '127.0.0.1',
            proxy: foreignTarget,
          },
        ],
        proxies: [
          ...upProxies,
          ...extraForeignProxies,
          { name: 'test-delay', type: 'http', server: '127.0.0.1', port: relayPort },
          {
            name: 'test-direct-delay',
            type: 'http',
            server: '127.0.0.1',
            port: directDelayPort,
          },
          {
            name: 'test-counted-pass',
            type: 'http',
            server: '127.0.0.1',
            port: countedPassPort,
          },
          {
            name: 'test-hold-drop',
            type: 'http',
            server: '127.0.0.1',
            port: holdBeforeTlsPort,
          },
          {
            name: 'test-claude-hold',
            type: 'http',
            server: '127.0.0.1',
            port: claudeHoldPort,
          },
        ],
        rules: [...rules, `MATCH,${outboundGroup}`],
      });

    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    const claudeTraceRaw = await requestTextViaProxy(
      'https://claude.ai/cdn-cgi/trace',
      `http://127.0.0.1:${upstreamPort}`,
      12000
    );
    const proxyExitIp = extractEchoIpFromBody(claudeTraceRaw, 'cf-trace');
    const proxyCountry = geo.lookupOfflineStrict(proxyExitIp).countryCode;
    assert.equal(proxyExitIp, expectedProxyIp);
    assert.equal(proxyCountry, expectedProxyCountry);
    console.log(
      `独立回归上游节点就绪，主出口：${proxyExitIp} (${proxyCountry})，异国出口：${expectedForeignIp} (${expectedForeignCountry})`
    );

    const probeForeignCandidates = async () => {
      const checks = await Promise.all(
        BUILTIN_TRACE_ENDPOINTS.map(async (ep) => {
          try {
            const raw = await requestTextViaProxy(
              ep.url,
              `http://127.0.0.1:${directUpstreamPort}`,
              5000
            );
            const echoIp = extractEchoIpFromBody(raw, ep.format);
            if (!echoIp) return null;
            const offlineGeo = geo.lookupOfflineStrict(echoIp);
            if (offlineGeo.countryCode !== proxyCountry) {
              return {
                endpoint: ep,
                host: new URL(ep.url).hostname,
                countryCode: offlineGeo.countryCode,
              };
            }
          } catch {
            // 跳过不可达的回显源
          }
          return null;
        })
      );
      return checks.filter(
        (
          item
        ): item is { endpoint: TraceEndpoint; host: string; countryCode: string } =>
          item !== null
      );
    };

    const directCandidates = await probeForeignCandidates();
    assert.ok(
      directCandidates.length >= 2,
      `需要至少 2 个独立回显源可通过对比通道返回异于代理 (${proxyCountry}) 的离线国家，实际 ${directCandidates.length} 个`
    );
    const [direct1, direct2] = directCandidates;
    const proxySideEndpoints = BUILTIN_TRACE_ENDPOINTS.filter(
      (ep) =>
        ep.registrableDomain !== direct1.endpoint.registrableDomain &&
        ep.registrableDomain !== direct2.endpoint.registrableDomain
    );
    assert.ok(proxySideEndpoints.length >= MIN_CONSENSUS_MATCHES);

    const keptTwoPair = [direct1.endpoint, proxySideEndpoints[0]];
    const excludedThreeDomains = BUILTIN_TRACE_ENDPOINTS.filter(
      (ep) => !keptTwoPair.some((k) => k.registrableDomain === ep.registrableDomain)
    ).map((ep) => ep.registrableDomain);
    const fourKeptSet = new Set([
      direct1.endpoint.registrableDomain,
      direct2.endpoint.registrableDomain,
      proxySideEndpoints[0].registrableDomain,
      proxySideEndpoints[1].registrableDomain,
    ]);
    const fifthExcludedDomain = BUILTIN_TRACE_ENDPOINTS.find(
      (ep) => !fourKeptSet.has(ep.registrableDomain)
    )!.registrableDomain;
    const singleKeptDomain = proxySideEndpoints[0].registrableDomain;
    const allFiveOrdered = [
      singleKeptDomain,
      ...BUILTIN_TRACE_ENDPOINTS.map((ep) => ep.registrableDomain).filter(
        (d) => d !== singleKeptDomain
      ),
    ];
    const hopHostsMap = Object.fromEntries(
      allFiveOrdered.map((d) => [`hop.${d}`, '127.0.0.1'])
    );

    const subVergeDir = path.join(liveRoot, 'sub-verge');
    fs.mkdirSync(path.join(subVergeDir, 'profiles'), { recursive: true });
    fs.writeFileSync(
      path.join(subVergeDir, 'profiles.yaml'),
      yaml.dump({
        current: 'reduced-prof',
        items: [
          {
            uid: 'reduced-prof',
            name: '受限源测试订阅',
            type: 'local',
            file: 'reduced-prof.yaml',
          },
        ],
      }),
      'utf8'
    );
    fs.writeFileSync(
      path.join(subVergeDir, 'profiles', 'reduced-prof.yaml'),
      yaml.dump({
        hosts: hopHostsMap,
        proxies: [
          {
            name: '五源标准节点',
            type: 'http',
            server: '127.0.0.1',
            port: upstreamPort,
          },
          {
            name: '受限前置跳板',
            type: 'http',
            server: `hop.${excludedThreeDomains[2]}`,
            port: connectHopPort,
            headers: { Host: `edge.${excludedThreeDomains[1]}` },
          },
          {
            name: '双源受限节点',
            type: 'http',
            server: `hop.${excludedThreeDomains[0]}`,
            port: upstreamPort,
            'dialer-proxy': '受限前置跳板',
          },
          {
            name: '四源复核节点',
            type: 'http',
            server: `hop.${fifthExcludedDomain}`,
            port: upstreamPort,
          },
          {
            name: '单源跳板-2',
            type: 'http',
            server: `hop.${allFiveOrdered[4]}`,
            port: connectHopPort,
            headers: { Host: `edge.${allFiveOrdered[3]}` },
          },
          {
            name: '单源跳板-1',
            type: 'http',
            server: `hop.${allFiveOrdered[2]}`,
            port: connectHopPort,
            headers: { Host: `edge.${allFiveOrdered[1]}` },
            'dialer-proxy': '单源跳板-2',
          },
          {
            name: '单源受限节点',
            type: 'http',
            server: '127.0.0.1',
            port: upstreamPort,
            'dialer-proxy': '单源跳板-1',
          },
          {
            name: '全重合零源可达节点',
            type: 'http',
            server: `hop.${allFiveOrdered[0]}`,
            port: upstreamPort,
            'dialer-proxy': '单源跳板-1',
          },
        ],
      }),
      'utf8'
    );

    const subCat = new SubscriptionCatalog(subVergeDir);
    subCat.refresh();
    const subStore = new ConfigStore();
    subStore.update({
      selectedClashNode: null,
      selectedClashProfileUid: null,
      selectedClashProfileName: null,
      antigravityClashNode: null,
      antigravityClashProfileUid: null,
      antigravityClashProfileName: null,
      claudeExclusiveGuard: false,
      claudeForceIpv4: false,
      killProcessesEnabled: false,
    });
    const trackedGeo = new Proxy(geo, {
      get(target, prop, receiver) {
        const val = Reflect.get(target, prop, receiver);
        if (
          (prop === 'lookupOfflineStrict' || prop === 'lookup') &&
          typeof val === 'function'
        ) {
          return (...args: unknown[]) => {
            const res = (
              val as (...a: unknown[]) => { countryCode: string; countryName: string }
            ).apply(target, args);
            onSubGeoLookup?.(res.countryCode);
            return res;
          };
        }
        return typeof val === 'function' ? val.bind(target) : val;
      },
    });
    subEngine = new ProbeEngine(
      subStore,
      trackedGeo,
      new ClashMonitor(subVergeDir),
      subService
    );

    const bindSubNode = async (nodeName: string) => {
      subStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const snap = subCat.capture('reduced-prof', nodeName);
      await subService.channels.claude.select(snap, subPort);
      assert.equal(subService.channels.claude.getState().phase, 'ready');
      subStore.update({
        selectedClashNode: nodeName,
        selectedClashProfileUid: 'reduced-prof',
        selectedClashProfileName: '受限源测试订阅',
        dedicatedProxyPort: subPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
    };

    // (0) 验证前 3 个转发探测源全部挂起时，第 4/5 源仍可在 10s 内验证通过
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([
        'DOMAIN,ipv4.icanhazip.com,REJECT-DROP',
        'DOMAIN,checkip.amazonaws.com,REJECT-DROP',
        'DOMAIN,api.ipify.org,REJECT-DROP',
      ])
    );
    await bindSubNode('五源标准节点');
    assert.equal(
      subService.channels.claude.getState().verificationError,
      null,
      `前三个转发探测源挂起时，第 4/5 源应能成功验证转发，实际错误：${
        subService.channels.claude.getState().verificationError
      }`
    );

    // (0b–0e) Antigravity Google 校验、停止取消、端口冲突重测与送中/NotebookLM 校验
    const agLivePort = await freePort();
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([
        'DOMAIN-SUFFIX,youtube.com,test-hold-drop',
        'DOMAIN-SUFFIX,google.com,test-hold-drop',
      ])
    );
    await subService.channels.antigravity.select(
      subCat.capture('reduced-prof', '五源标准节点'),
      agLivePort
    );
    assert.equal(subService.channels.antigravity.getState().phase, 'ready');
    heldDropClients.clear();
    try {
      const agLiveStore = new ConfigStore();
      agLiveStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
        antigravityClashNode: '五源标准节点',
        antigravityClashProfileUid: 'reduced-prof',
        antigravityClashProfileName: '受限源测试订阅',
        antigravityDedicatedPort: agLivePort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const agLiveEngine = new ProbeEngine(
        agLiveStore,
        geo,
        new ClashMonitor(subVergeDir),
        subService
      );
      const agGoogleProbeTask = agLiveEngine.probeAntigravityNodeNow();
      const waitGoogleHold = Date.now() + 8000;
      while (heldDropClients.size === 0 && Date.now() < waitGoogleHold) {
        await delay(30);
      }
      assert.ok(
        heldDropClients.size >= 1,
        'Antigravity 探测应已进入 Google/YouTube 地区校验阶段并建立隧道'
      );
      const googleStopAt = Date.now();
      agLiveEngine.stop();
      await agGoogleProbeTask;
      assert.ok(
        Date.now() - googleStopAt < 2000,
        `Google 地区请求阶段调用 stop() 后应立即返回 (实际 ${
          Date.now() - googleStopAt
        }ms)`
      );
      const waitGoogleClose = Date.now() + 1000;
      while (heldDropClients.size > 0 && Date.now() < waitGoogleClose) {
        await delay(20);
      }
      assert.equal(
        heldDropClients.size,
        0,
        'stop() 后 Google/YouTube 地区校验连接必须全部关闭'
      );

      rig.state.claudeHoldReleasedCount = 0;
      rig.state.claudeHoldClosedBeforeReleaseCount = 0;
      rig.state.holdClaudePrimary = true;
      await reloadKernelConfig(
        upLease.endpoint,
        makeUpstreamConfig([
          'DOMAIN-SUFFIX,youtube.com,test-claude-hold',
          'DOMAIN-SUFFIX,google.com,test-claude-hold',
        ])
      );
      const agConflictStore = new ConfigStore();
      agConflictStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
        antigravityClashNode: '五源标准节点',
        antigravityClashProfileUid: 'reduced-prof',
        antigravityClashProfileName: '受限源测试订阅',
        antigravityDedicatedPort: agLivePort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const agConflictEngine = new ProbeEngine(
        agConflictStore,
        geo,
        new ClashMonitor(subVergeDir),
        subService
      );
      const agSubLease = readLeaseEndpoint(
        path.join(liveRoot, 'sub-kernels', 'antigravity')
      );
      const agConflictHijacker = net.createServer((sock) => sock.destroy());
      try {
        const agConflictProbeTask = agConflictEngine.probeAntigravityNodeNow();
        const waitAgGoogleHold = Date.now() + 8000;
        while (claudeHoldClients.size === 0 && Date.now() < waitAgGoogleHold) {
          await delay(30);
        }
        assert.ok(
          claudeHoldClients.size >= 1,
          'Antigravity 探测应已进入 Google/YouTube 地区响应等待阶段'
        );
        await mihomoRequest(agSubLease.endpoint, '/configs', 'PATCH', {
          'mixed-port': 0,
        });
        const agDropDeadline = Date.now() + 3000;
        while (
          (await isLocalPortListening(agLivePort)) &&
          Date.now() < agDropDeadline
        ) {
          await delay(30);
        }
        agConflictHijacker.listen(agLivePort, '127.0.0.1');
        await once(agConflictHijacker, 'listening');
        assert.equal(
          await subService.channels.antigravity.recoverListenerIfNeeded(),
          'failed'
        );
        assert.equal(subService.channels.antigravity.getState().phase, 'error');

        await agConflictProbeTask;
        const waitAgConflictClose = Date.now() + 1500;
        while (claudeHoldClients.size > 0 && Date.now() < waitAgConflictClose) {
          await delay(20);
        }
        assert.equal(
          claudeHoldClients.size,
          0,
          'port-conflict 后正在等待 Google 地区响应的代理连接必须全部关闭'
        );
        assert.equal(
          rig.state.claudeHoldReleasedCount,
          0,
          '冲突前启动的 Google 探测不得等到延迟释放后写回'
        );
        assert.ok(
          rig.state.claudeHoldClosedBeforeReleaseCount >= 1,
          '冲突前启动的 Google 探测连接应在释放前被取消'
        );
        const conflictSnap = agConflictEngine.getSnapshot();
        assert.equal(
          conflictSnap.antigravityState.nodeProbe,
          null,
          '端口冲突后不得保留或写回旧出口样本'
        );
        assert.match(
          conflictSnap.antigravityState.nodeProbeError || '',
          /监听归属/
        );

        rig.state.holdClaudePrimary = false;
        await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
        await new Promise<void>((resolve) =>
          agConflictHijacker.close(() => resolve())
        );
        assert.equal(
          await subService.channels.antigravity.recoverListenerIfNeeded(),
          'rebound'
        );
        const recoveryProbeDeadline = Date.now() + 8000;
        while (
          (!agConflictEngine.getSnapshot().antigravityState.nodeProbe
            ?.googleCountryCode ||
            agConflictEngine.getSnapshot().antigravityState.nodeProbeError !==
              null) &&
          Date.now() < recoveryProbeDeadline
        ) {
          await delay(50);
        }
        const recoveredAgSnap = agConflictEngine.getSnapshot();
        assert.equal(
          recoveredAgSnap.antigravityState.nodeProbe?.countryCode,
          proxyCountry
        );
        assert.equal(
          recoveredAgSnap.antigravityState.nodeProbe?.googleCountryCode,
          proxyCountry
        );
        assert.equal(recoveredAgSnap.antigravityState.nodeProbeError, null);

        // (0d) 重新绑定端口但上游仍不可达时不得清除 verificationError
        const agRejectHosts = BUILTIN_TRACE_ENDPOINTS.map(
          (ep) => new URL(ep.url).hostname
        );
        await reloadKernelConfig(
          upLease.endpoint,
          makeUpstreamConfig(agRejectHosts.map((h) => `DOMAIN,${h},REJECT`))
        );
        await mihomoRequest(agSubLease.endpoint, '/configs', 'PATCH', {
          'mixed-port': 0,
        });
        const agRebindDropDeadline = Date.now() + 3000;
        while (
          (await isLocalPortListening(agLivePort)) &&
          Date.now() < agRebindDropDeadline
        ) {
          await delay(30);
        }
        assert.equal(
          await isLocalPortListening(agLivePort),
          false,
          '(0d) PATCH mixed-port: 0 后应已关闭 agLivePort'
        );
        assert.equal(
          await subService.channels.antigravity.recoverListenerIfNeeded(),
          'rebound'
        );
        assert.equal(subService.channels.antigravity.getState().phase, 'ready');
        assert.match(
          subService.channels.antigravity.getState().verificationError || '',
          /专属代理请求失败/,
          '重新绑定端口但上游仍不可达时不得清除 verificationError'
        );
        assert.equal(
          agConflictEngine.getSnapshot().antigravityState.canLaunch,
          false,
          '转发校验未通过时必须禁止启动 Antigravity'
        );
        await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
        const agRecoveredForwardDeadline = Date.now() + 8000;
        while (
          subService.channels.antigravity.getState().verificationError !== null &&
          Date.now() < agRecoveredForwardDeadline
        ) {
          await delay(100);
        }
        assert.equal(
          subService.channels.antigravity.getState().verificationError,
          null,
          '上游恢复后后台健康检查应重新验证转发并清除 verificationError'
        );

        // (0e) Antigravity Google 送中与 NotebookLM 域名迁移/地区受限检测
        try {
          rig.state.proxyGoogleHkRedirectFollowHits = 0;
          rig.state.proxyNotebookDomainMigrationHits = 0;
          rig.state.proxyGoogleMode = 'cn-songzhong-hkredirect';
          const songzhongSnap = await agConflictEngine.probeAntigravityNodeNow();
          assert.equal(
            songzhongSnap.antigravityState.nodeProbe?.countryCode,
            proxyCountry
          );
          assert.equal(
            songzhongSnap.antigravityState.nodeProbe?.googleCountryCode,
            'CN'
          );
          assert.equal(
            songzhongSnap.antigravityState.nodeProbe?.googleAiSupported,
            false
          );
          assert.match(
            songzhongSnap.antigravityState.nodeProbe?.regionMismatchDetail || '',
            /CN/
          );
          assert.match(
            songzhongSnap.antigravityState.nodeProbe?.regionMismatchDetail || '',
            /NotebookLM.*不受支持/
          );
          assert.equal(
            rig.state.proxyGoogleHkRedirectFollowHits,
            0,
            '首跳已命中 pref=hkredirect 时应立即停止重定向，避免多跳超时'
          );
          assert.ok(
            getTargetServiceVerificationError(
              songzhongSnap.antigravityState.nodeProbe,
              'antigravity'
            ),
            '送中节点必须触发 Antigravity 目标服务地区校验失败'
          );

          rig.state.proxyGoogleHkRedirectFollowHits = 0;
          rig.state.proxyGoogleMode = 'cn-songzhong-hkredirect-yt-fallback-us';
          const hkRedirectWinsSnap =
            await agConflictEngine.probeAntigravityNodeNow();
          assert.equal(
            hkRedirectWinsSnap.antigravityState.nodeProbe?.countryCode,
            proxyCountry
          );
          assert.equal(
            hkRedirectWinsSnap.antigravityState.nodeProbe?.googleCountryCode,
            'CN',
            '离线库为非 US 国家时，明确的 pref=hkredirect -> CN 不得被缺少 visitorData 的 YouTube 默认 US 覆盖'
          );
          assert.equal(
            hkRedirectWinsSnap.antigravityState.nodeProbe?.googleAiSupported,
            false
          );
          assert.equal(rig.state.proxyGoogleHkRedirectFollowHits, 0);

          rig.state.proxyGoogleMode = 'cn-songzhong-yt-protobuf-only';
          const protobufOnlySnap =
            await agConflictEngine.probeAntigravityNodeNow();
          assert.equal(
            protobufOnlySnap.antigravityState.nodeProbe?.googleCountryCode,
            'CN',
            'Google 首页失败时必须从 sw.js_data visitorData Protobuf 识别出 CN，不得回退采信 inner[1]=US'
          );
          assert.match(
            protobufOnlySnap.antigravityState.nodeProbe?.regionMismatchDetail ||
              '',
            /CN/
          );

          rig.state.proxyNotebookDomainMigrationHits = 0;
          rig.state.proxyGoogleMode = 'same-country-ai-unsupported';
          const aiUnsupportedSnap =
            await agConflictEngine.probeAntigravityNodeNow();
          assert.equal(
            aiUnsupportedSnap.antigravityState.nodeProbe?.countryCode,
            proxyCountry
          );
          assert.equal(
            aiUnsupportedSnap.antigravityState.nodeProbe?.googleCountryCode,
            proxyCountry
          );
          assert.equal(
            aiUnsupportedSnap.antigravityState.nodeProbe?.googleAiSupported,
            false
          );
          assert.ok(
            rig.state.proxyNotebookDomainMigrationHits >= 1,
            '应跟随 notebooklm.google.com -> 301 -> notebook.google.com 正式域名迁移'
          );
          assert.match(
            aiUnsupportedSnap.antigravityState.nodeProbe?.regionMismatchDetail ||
              '',
            /NotebookLM.*不受支持/
          );
          assert.ok(
            getTargetServiceVerificationError(
              aiUnsupportedSnap.antigravityState.nodeProbe,
              'antigravity'
            ),
            '同国但 NotebookLM 不支持时必须拦截/预警'
          );

          rig.state.proxyNotebookDomainMigrationHits = 0;
          rig.state.proxyGoogleMode = 'normal';
          const cleanAgSnap = await agConflictEngine.probeAntigravityNodeNow();
          assert.equal(
            cleanAgSnap.antigravityState.nodeProbe?.countryCode,
            proxyCountry
          );
          assert.equal(
            cleanAgSnap.antigravityState.nodeProbe?.googleCountryCode,
            proxyCountry
          );
          assert.equal(
            cleanAgSnap.antigravityState.nodeProbe?.googleAiSupported,
            true
          );
          assert.ok(
            rig.state.proxyNotebookDomainMigrationHits >= 1,
            '正常线路应跟随 301 到达 notebook.google.com 并确认支持'
          );
          assert.equal(
            cleanAgSnap.antigravityState.nodeProbe?.regionMismatchDetail,
            null
          );
          assert.equal(
            getTargetServiceVerificationError(
              cleanAgSnap.antigravityState.nodeProbe,
              'antigravity'
            ),
            null
          );
        } finally {
          rig.state.proxyGoogleMode = 'normal';
          rig.state.proxyGoogleHkRedirectFollowHits = 0;
          rig.state.proxyNotebookDomainMigrationHits = 0;
        }
      } finally {
        rig.state.holdClaudePrimary = false;
        agConflictEngine.stop();
        if (agConflictHijacker.listening) {
          await new Promise<void>((resolve) =>
            agConflictHijacker.close(() => resolve())
          );
        }
      }
    } finally {
      for (const sock of heldDropClients) sock.destroy();
      heldDropClients.clear();
      subStore.update({
        antigravityClashNode: null,
        antigravityClashProfileUid: null,
        antigravityClashProfileName: null,
      });
      await subService.channels.antigravity.select(null, agLivePort);
      await bindSubNode('五源标准节点');
    }

    // (1a) 错峰对冲绕过首连卡死
    rig.state.relayMode = 'stall-first';
    rig.state.relayHits = 0;
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig(['DOMAIN,claude.ai,test-delay'])
    );
    const hedgeStart = Date.now();
    const hedgedSnap = await subEngine.probeClaudeNodeNow(
      '验证 Claude 慢连接错峰对冲',
      true
    );
    const hedgeElapsed = Date.now() - hedgeStart;
    const hedgedProbe = hedgedSnap.claudeState.nodeProbe;
    assert.ok(
      hedgedProbe &&
        getTargetServiceVerificationError(hedgedProbe, 'claude') === null,
      `错峰对冲应绕过首连卡死并通过校验: err=${
        hedgedSnap.claudeState.nodeProbeError
      } verify=${getTargetServiceVerificationError(hedgedProbe, 'claude')}`
    );
    assert.ok(rig.state.relayHits >= 2, '首连卡死超过 2.8s 应触发错峰对冲连接');
    const claudeOffsetFromStart = hedgedProbe.claudeTraceCheckedAt! - hedgeStart;
    assert.ok(
      claudeOffsetFromStart >= 2700 && claudeOffsetFromStart < 9500,
      `对冲连接应在 2.8s 后触发并在首连 10s 断连前完成 (total=${hedgeElapsed}ms, claudeOffset=${claudeOffsetFromStart}ms, hits=${rig.state.relayHits})`
    );

    // (1a-1) 校验 Claude trace 响应内容后再取消备用请求，并保留可用于判定 IP 漂移的部分结果
    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    try {
      rig.state.proxyClaudeTraceMode = 'bad-first-then-ok';
      rig.state.proxyClaudeTraceHits = 0;
      const badFirstSnap = await subEngine.probeClaudeNodeNow(
        '首路 HTTP 200 无效正文不得取消有效对冲响应',
        true
      );
      const badFirstProbe = badFirstSnap.claudeState.nodeProbe;
      assert.ok(
        badFirstProbe &&
          getTargetServiceVerificationError(badFirstProbe, 'claude') === null,
        `首路返回无效 200 正文时备用对冲请求应继续完成校验: err=${
          badFirstSnap.claudeState.nodeProbeError
        } verify=${getTargetServiceVerificationError(badFirstProbe, 'claude')}`
      );
      assert.ok(
        rig.state.proxyClaudeTraceHits >= 2,
        '首路正文无效时必须继续执行备用对冲请求'
      );
      assert.equal(badFirstProbe.claudeTraceIp, proxyExitIp);

      rig.state.proxyClaudeTraceMode = 'loc-xx-then-fail';
      rig.state.proxyClaudeTraceHits = 0;
      const partialPreservedSnap = await subEngine.probeClaudeNodeNow(
        '两路均无完整结果时保留含 IP 的部分结果',
        true
      );
      const partialPreservedProbe = partialPreservedSnap.claudeState.nodeProbe;
      assert.ok(
        partialPreservedProbe,
        '首路返回 loc=XX 且含有效 IP、次路 502 时应保留部分结果'
      );
      assert.ok(
        rig.state.proxyClaudeTraceHits >= 2,
        '部分结果后仍应尝试对冲请求以争取完整响应'
      );
      assert.equal(partialPreservedProbe.claudeTraceIp, expectedForeignIp);
      assert.equal(
        partialPreservedProbe.claudeTraceCountryCode,
        expectedForeignCountry
      );
      assert.match(
        partialPreservedProbe.claudeTraceError || '',
        /未解析到有效国家\/地区代码/
      );
      const partialDriftCheck = evaluateClaudeNodeProbeSafety(
        partialPreservedProbe,
        {
          claudeRunning: true,
          claudeExternalBaselinePending: false,
          claudeLockExitIp: true,
          sessionInitialIp: proxyExitIp,
        }
      );
      assert.equal(
        partialDriftCheck?.alertType,
        'ip-change',
        '保留的部分 trace IP 必须仍能触发运行期 IP 漂移熔断'
      );

      // (1a-1b) 锁定 IP 会话中首路返回漂移新 IP + loc=XX、对冲路可返回旧 IP + 完整地区时，
      //         必须立即保留首路已确认的 IP 漂移，严禁被后续对冲响应覆盖吞掉。
      const savedWinLocale = { ...subEngine.winLocale };
      try {
        const matchedTz =
          resolveWindowsTimeZoneForCountry(proxyCountry).windowsTimeZoneId ||
          savedWinLocale.timeZoneId;
        subEngine.winLocale = {
          timeZoneId: matchedTz,
          timeZoneDisplayName: matchedTz,
          regionCode: proxyCountry,
          regionName: proxyCountry,
        };
        subStore.update({
          claudeLockExitIp: true,
          claudeExclusiveGuard: false,
          killProcessesEnabled: false,
        });
        subEngine.claude.sessionInitialIp = proxyExitIp;
        rig.state.proxyClaudeTraceMode = 'drift-loc-xx-then-old-ok';
        rig.state.proxyClaudeTraceHits = 0;
        const confirmedDriftSnap = await subEngine.probeClaudeNodeNow(
          '首路部分结果已确认 IP 漂移时不得被对冲旧 IP 覆盖',
          true
        );
        assert.equal(
          confirmedDriftSnap.claudeState.nodeProbe?.claudeTraceIp,
          expectedProxyDriftedIp,
          '首路已确认漂移的新 IP 必须保留，不得被对冲路返回的旧 IP 覆盖'
        );
        assert.equal(
          rig.state.proxyClaudeTraceHits,
          1,
          '首路部分结果已确认违规时应立即结束，无需再采信备用请求'
        );
        const driftSafetyAfterPartial = subEngine.evaluateClaudeSafety(true);
        assert.equal(driftSafetyAfterPartial.alertType, 'ip-change');
        assert.equal(driftSafetyAfterPartial.expectedIp, proxyExitIp);
        assert.equal(driftSafetyAfterPartial.actualIp, expectedProxyDriftedIp);

        // (1a-1c) 运行中 Claude 尚无 IP 基线时，探测在途期间刷新读取真实 Windows 系统区域/时区后，
        //         首路返回与真实系统区域冲突的出口 + loc=XX 必须立即确认违规，严禁被后续对冲路覆盖。
        //         （注：遵循 AGENTS.md 红线“禁误杀宿主机在用的 claude*.exe”，此处保持 skipSafetyEnforcement=true 不触发全机按名强杀）
        const activeSubEngine = subEngine;
        const realHostLocale = await readWindowsLocaleState();
        const foreignViolatesHost = !isWindowsLocaleMatchingCountry(
          realHostLocale.timeZoneId,
          realHostLocale.regionCode,
          rig.expectedForeignCountry
        );
        const preRefreshCountry = foreignViolatesHost
          ? rig.expectedForeignCountry
          : proxyCountry;
        const expectedViolatingIp = foreignViolatesHost ? expectedForeignIp : proxyExitIp;
        const preRefreshTz =
          resolveWindowsTimeZoneForCountry(preRefreshCountry).windowsTimeZoneId ||
          realHostLocale.timeZoneId;
        activeSubEngine.claude.sessionInitialIp = null;
        activeSubEngine.claude.running = true;
        activeSubEngine.winLocale = {
          timeZoneId: preRefreshTz,
          timeZoneDisplayName: preRefreshTz,
          regionCode: preRefreshCountry,
          regionName: preRefreshCountry,
        };
        rig.state.proxyClaudeTraceMode = foreignViolatesHost
          ? 'foreign-loc-xx-then-proxy-ok'
          : 'proxy-loc-xx-then-foreign-ok';
        rig.state.proxyClaudeTraceHits = 0;
        rig.state.onProxyClaudeTraceHit1 = () => {
          activeSubEngine.winLocale = realHostLocale;
        };
        try {
          const localeRefreshViolationSnap = await subEngine.probeClaudeNodeNow(
            '探测期间刷新真实系统区域后首路异国出口立即熔断判定',
            true
          );
          assert.equal(
            localeRefreshViolationSnap.claudeState.nodeProbe?.claudeTraceIp,
            expectedViolatingIp,
            '探测期间刷新真实系统区域后，首路已确认与当前系统区域冲突的出口严禁被对冲路覆盖'
          );
          assert.equal(
            rig.state.proxyClaudeTraceHits,
            1,
            '首路按最新真实系统区域确认违规后应立即结束对冲'
          );
          const localeRefreshSafety = subEngine.evaluateClaudeSafety(true);
          assert.equal(localeRefreshSafety.safe, false);
          assert.equal(localeRefreshSafety.alertType, 'locale-mismatch');
        } finally {
          rig.state.onProxyClaudeTraceHit1 = null;
          subEngine.claude.running = false;
        }
      } finally {
        subEngine.claude.sessionInitialIp = null;
        subEngine.claude.running = false;
        subEngine.winLocale = savedWinLocale;
      }
    } finally {
      rig.state.proxyClaudeTraceMode = 'normal';
      rig.state.proxyClaudeTraceHits = 0;
    }

    // (1a-2) 全部常规探测源均超时/阻断，但 claude.ai 可达
    const allGeneralHosts = BUILTIN_TRACE_ENDPOINTS.map(
      (ep) => new URL(ep.url).hostname
    );
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig(allGeneralHosts.map((h) => `DOMAIN,${h},REJECT-DROP`))
    );
    const allGeneralFailStart = Date.now();
    const allGeneralFailSnap = await subEngine.probeClaudeNodeNow(
      '全部常规源失败时保留 Claude IP 漂移检测',
      true
    );
    const allGeneralFailElapsed = Date.now() - allGeneralFailStart;
    assert.ok(
      allGeneralFailElapsed < 15000,
      `全常规源失败时并发探测必须在 15s 总期限内完成 (实际 ${allGeneralFailElapsed}ms)`
    );
    const claudeOnlyProbe = allGeneralFailSnap.claudeState.nodeProbe;
    assert.ok(claudeOnlyProbe, '全部常规源失败但 Claude 可达时仍须保留 Claude 实测样本');
    assert.equal(
      allGeneralFailSnap.claudeState.canLaunch,
      false,
      '全部常规源失败时必须 Fail-Closed 阻断新启动'
    );
    assert.ok(claudeOnlyProbe.claudeTraceIp, '必须取得实时 Claude 出口 IP');
    assert.equal(claudeOnlyProbe.claudeTraceCountryCode, proxyCountry);
    assert.match(claudeOnlyProbe.claudeTraceError || '', /常规出口探测均不可达/);
    assert.equal(isProbeRegionMismatched(claudeOnlyProbe), false);
    const sameIpCheck = evaluateClaudeNodeProbeSafety(claudeOnlyProbe, {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: claudeOnlyProbe.claudeTraceIp,
    });
    assert.equal(sameIpCheck?.alertType, 'verification-unavailable');
    const driftedIpCheck = evaluateClaudeNodeProbeSafety(claudeOnlyProbe, {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: '198.51.100.77',
    });
    assert.equal(
      driftedIpCheck?.alertType,
      'ip-change',
      '全常规源失败但 Claude 出口 IP 已变更时必须立即触发 ip-change'
    );
    assert.equal(driftedIpCheck?.actualIp, claudeOnlyProbe.claudeTraceIp);
    const driftedAlertFields = resolveAlertActualMismatchFields({
      isClaudeSource: true,
      alertType: 'ip-change',
      expectedCode: proxyCountry,
      explicitActualIp: claudeOnlyProbe.claudeTraceIp,
      refProbe: claudeOnlyProbe,
    });
    assert.equal(
      driftedAlertFields.actualCode,
      proxyCountry,
      'Claude IP 具备有效离线归属时告警应显示准确国家代码而非 UNKNOWN'
    );

    // (1a-3) 常规样本缺失带有 claudeTraceError 但已确认 Claude 出口 IP 漂移时，即使此时端口可恢复重绑也不得进入下一轮丢弃本次漂移
    const subDriftLease = readLeaseEndpoint(
      path.join(liveRoot, 'sub-kernels', 'claude')
    );
    let droppedPortAfterClaudeDrift = false;
    let driftReadyCount = 0;
    const onDriftReady = () => driftReadyCount++;
    subService.channels.claude.on('ready', onDriftReady);
    const prevWinLocale = { ...subEngine.winLocale };
    rig.state.beforePassTunnelReady = async (host) => {
      if (droppedPortAfterClaudeDrift || host !== 'claude.ai') return;
      droppedPortAfterClaudeDrift = true;
      await delay(80);
      await mihomoRequest(subDriftLease.endpoint, '/configs', 'PATCH', {
        'mixed-port': 0,
      });
      const dropDeadline = Date.now() + 2000;
      while (
        (await isLocalPortListening(subPort)) &&
        Date.now() < dropDeadline
      ) {
        await delay(30);
      }
      await reloadKernelConfig(
        upLease.endpoint,
        makeUpstreamConfig([
          'DOMAIN,claude.ai,REJECT',
          ...allGeneralHosts.map((h) => `DOMAIN,${h},REJECT-DROP`),
        ])
      );
    };
    try {
      const matchedTz =
        resolveWindowsTimeZoneForCountry(proxyCountry).windowsTimeZoneId ||
        prevWinLocale.timeZoneId;
      subEngine.winLocale = {
        timeZoneId: matchedTz,
        timeZoneDisplayName: matchedTz,
        regionCode: proxyCountry,
        regionName: proxyCountry,
      };
      subStore.update({
        claudeLockExitIp: true,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      subEngine.claude.sessionInitialIp = '198.51.100.77';
      await reloadKernelConfig(
        upLease.endpoint,
        makeUpstreamConfig([
          'DOMAIN,claude.ai,test-counted-pass',
          ...allGeneralHosts.map((h) => `DOMAIN,${h},REJECT-DROP`),
        ])
      );
      const driftNoRetrySnap = await subEngine.probeClaudeNodeNow(
        '常规源缺失且端口可重绑时不得丢弃已确认 IP 漂移',
        true
      );
      assert.equal(
        droppedPortAfterClaudeDrift,
        true,
        '应在 Claude 隧道建立后先行关闭本地专属监听端口'
      );
      assert.equal(
        await isLocalPortListening(subPort),
        false,
        '已确认 IP 漂移时不得为常规样本缺失触发端口重绑进入下一轮'
      );
      assert.equal(driftReadyCount, 0, '已确认 IP 漂移时不得重绑重试丢弃本轮样本');
      const observedDriftedIp =
        driftNoRetrySnap.claudeState.nodeProbe?.claudeTraceIp;
      assert.ok(
        observedDriftedIp && observedDriftedIp !== '198.51.100.77',
        '不得因常规样本缺失触发端口重绑重测而覆盖本轮已确认的漂移 IP'
      );
      const liveRuntimeSafety = subEngine.evaluateClaudeSafety(true);
      assert.equal(
        liveRuntimeSafety.alertType,
        'ip-change',
        '本轮已确认漂移 IP 必须直接触发 ip-change 判定'
      );
      assert.equal(liveRuntimeSafety.expectedIp, '198.51.100.77');
      assert.equal(liveRuntimeSafety.actualIp, observedDriftedIp);
    } finally {
      rig.state.beforePassTunnelReady = null;
      subService.channels.claude.off('ready', onDriftReady);
      subEngine.claude.sessionInitialIp = null;
      subEngine.winLocale = prevWinLocale;
      await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
      assert.equal(
        await subService.channels.claude.recoverListenerIfNeeded(),
        'rebound'
      );
    }

    // (1a-4) 全重合零常规源链式节点仍检 Claude 实际出口
    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    await bindSubNode('全重合零源可达节点');
    assert.equal(
      selectProbeEndpointsForTransportHosts(
        BUILTIN_TRACE_ENDPOINTS,
        subService.channels.claude.getBoundTransportHosts()
      ).length,
      0,
      '全重合零源可达节点的常规探测池必须为空'
    );
    try {
      const zeroReachableSnap = await subEngine.probeClaudeNodeNow(
        '零常规源链式节点仍检 Claude 实际出口',
        true
      );
      const zeroReachableProbe = zeroReachableSnap.claudeState.nodeProbe;
      assert.equal(
        zeroReachableSnap.claudeState.canLaunch,
        false,
        '零常规源节点对新启动必须维持 Fail-Closed 阻断'
      );
      assert.ok(
        zeroReachableProbe,
        '零常规源节点在 trace 可达时仍须返回 Claude 实际出口样本'
      );
      assert.equal(zeroReachableProbe.countryCode, 'UNKNOWN');
      assert.equal(zeroReachableProbe.claudeTraceIp, proxyExitIp);
      assert.equal(zeroReachableProbe.claudeTraceCountryCode, proxyCountry);
      assert.match(zeroReachableProbe.claudeTraceError || '', /传输层域名重合/);

      const foreignTz =
        resolveWindowsTimeZoneForCountry(expectedForeignCountry)
          .windowsTimeZoneId || prevWinLocale.timeZoneId;
      subEngine.winLocale = {
        timeZoneId: foreignTz,
        timeZoneDisplayName: foreignTz,
        regionCode: expectedForeignCountry,
        regionName: expectedForeignCountry,
      };
      const zeroLocaleMismatch = subEngine.evaluateClaudeSafety(false);
      assert.equal(
        zeroLocaleMismatch.alertType,
        'locale-mismatch',
        `零常规源节点 trace 确认实际出口 (${proxyCountry}) 与系统区域 (${expectedForeignCountry}) 不符时必须触发 locale-mismatch，实际：${zeroLocaleMismatch.alertType} (${zeroLocaleMismatch.reason})`
      );

      const matchedTz =
        resolveWindowsTimeZoneForCountry(proxyCountry).windowsTimeZoneId ||
        prevWinLocale.timeZoneId;
      subEngine.winLocale = {
        timeZoneId: matchedTz,
        timeZoneDisplayName: matchedTz,
        regionCode: proxyCountry,
        regionName: proxyCountry,
      };
      subStore.update({
        claudeLockExitIp: true,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      subEngine.claude.sessionInitialIp = '198.51.100.77';
      const zeroIpDrift = subEngine.evaluateClaudeSafety(false);
      assert.equal(
        zeroIpDrift.alertType,
        'ip-change',
        '零常规源节点 trace 确认出口 IP 漂移时必须触发 ip-change'
      );
      assert.equal(zeroIpDrift.actualIp, proxyExitIp);

      subEngine.claude.sessionInitialIp = proxyExitIp;
      const zeroMatchedSameIp = subEngine.evaluateClaudeSafety(false);
      assert.equal(zeroMatchedSameIp.alertType, 'verification-unavailable');
    } finally {
      subEngine.claude.sessionInitialIp = null;
      subEngine.winLocale = prevWinLocale;
      await bindSubNode('五源标准节点');
    }

    // (1b) 单探测源被旁路至异国，其余 >=2 个独立主域与 Claude 一致 -> 共识通过
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([`DOMAIN,${direct1.host},${foreignTarget}`])
    );
    const singleOutlierSnap = await subEngine.probeClaudeNodeNow(
      '验证单源旁路多主域共识',
      true
    );
    const singleOutlierProbe = singleOutlierSnap.claudeState.nodeProbe;
    assert.ok(singleOutlierProbe, '单源旁路其余一致时应共识通过');
    assert.equal(getTargetServiceVerificationError(singleOutlierProbe, 'claude'), null);
    assert.equal(isProbeRegionMismatched(singleOutlierProbe), false);
    assert.equal(
      singleOutlierProbe.countryCode,
      proxyCountry,
      '被旁路的单点异国源不得被采信为最终基准'
    );
    assert.equal(
      geo.lookupOfflineStrict(singleOutlierProbe.ip).countryCode,
      proxyCountry
    );

    // (1c) 单探测源异常且其余复核源全部拥塞断流 -> Fail-Closed
    const otherHosts = BUILTIN_TRACE_ENDPOINTS.filter(
      (ep) => ep.registrableDomain !== direct1.endpoint.registrableDomain
    ).map((ep) => new URL(ep.url).hostname);
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([
        `DOMAIN,${direct1.host},${foreignTarget}`,
        ...otherHosts.map((h) => `DOMAIN,${h},REJECT-DROP`),
      ])
    );
    const inconclusiveSnap = await subEngine.probeClaudeNodeNow(
      '单源异常其余源断流',
      true
    );
    assert.equal(inconclusiveSnap.claudeState.nodeProbe, null);
    assert.equal(inconclusiveSnap.claudeState.canLaunch, false);
    assert.match(
      inconclusiveSnap.claudeState.nodeProbeError || '',
      /常规出口复核未完成/
    );

    // (1d) 异国常规源先回 + Claude 校验失败 -> claudeTraceError 存在、绝不判为 mismatch
    rig.state.relayMode = 'delay-target-short';
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([
        `DOMAIN,${direct1.host},${foreignTarget}`,
        ...otherHosts.map((h) => `DOMAIN,${h},test-delay`),
        'DOMAIN,claude.ai,REJECT',
      ])
    );
    const traceErrSnap = await subEngine.probeClaudeNodeNow(
      '异国源先回叠加 Claude 失败',
      true
    );
    const traceErrProbe = traceErrSnap.claudeState.nodeProbe;
    assert.ok(traceErrProbe?.claudeTraceError, '应记录 Claude 校验失败');
    assert.equal(traceErrProbe.countryCode, direct1.countryCode);
    assert.equal(
      isProbeRegionMismatched(traceErrProbe),
      false,
      '存在 claudeTraceError 时不得判为 mismatch'
    );
    const traceErrSafety = evaluateClaudeNodeProbeSafety(traceErrProbe, {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: proxyExitIp,
    });
    assert.equal(traceErrSafety?.alertType, 'verification-unavailable');

    // (1d-2) 单异国旁路源先回 + 同国 Claude 出口 IP 漂移提前中止
    try {
      const matchedTz =
        resolveWindowsTimeZoneForCountry(proxyCountry).windowsTimeZoneId ||
        prevWinLocale.timeZoneId;
      subEngine.winLocale = {
        timeZoneId: matchedTz,
        timeZoneDisplayName: matchedTz,
        regionCode: proxyCountry,
        regionName: proxyCountry,
      };
      subStore.update({
        claudeLockExitIp: true,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      subEngine.claude.sessionInitialIp = '198.51.100.88';
      await reloadKernelConfig(
        upLease.endpoint,
        makeUpstreamConfig([
          `DOMAIN,${direct1.host},${foreignTarget}`,
          ...otherHosts.map((h) => `DOMAIN,${h},test-delay`),
        ])
      );
      const earlyDriftSnap = await subEngine.probeClaudeNodeNow(
        '单源旁路叠加同国 IP 漂移提前中止',
        true
      );
      const earlyDriftProbe = earlyDriftSnap.claudeState.nodeProbe;
      assert.ok(earlyDriftProbe, '应返回含 Claude 漂移 IP 的探测结果');
      assert.equal(
        isProbeRegionMismatched(earlyDriftProbe),
        false,
        '未达 2 源共识的单点异国旁路源不得伪造跨国 mismatch'
      );
      assert.notEqual(
        earlyDriftProbe.countryCode,
        direct1.countryCode,
        '提前中止时不得采信单点旁路源国家代码'
      );
      const earlyDriftCheck = evaluateClaudeNodeProbeSafety(earlyDriftProbe, {
        claudeRunning: true,
        claudeExternalBaselinePending: false,
        claudeLockExitIp: true,
        sessionInitialIp: '198.51.100.88',
      });
      assert.equal(
        earlyDriftCheck?.alertType,
        'ip-change',
        '同国 IP 轮换必须触发 ip-change 而非跨国 mismatch'
      );
    } finally {
      subEngine.claude.sessionInitialIp = null;
      subEngine.winLocale = prevWinLocale;
    }

    // (1e) 跨国分流双序验证 + 告警同源配对校验
    const proxySideHosts = proxySideEndpoints.map((ep) => new URL(ep.url).hostname);
    rig.state.relayMode = 'delay-target-short';
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([
        `DOMAIN,${direct1.host},test-direct-delay`,
        `DOMAIN,${direct2.host},test-direct-delay`,
      ])
    );
    const order1Start = Date.now();
    const order1Snap = await subEngine.probeClaudeNodeNow('跨国分流顺序一', true);
    const order1Elapsed = Date.now() - order1Start;
    assert.ok(
      order1Elapsed >= 2100,
      `代理国先回时仍须等待剩余可能凑够 2 异议的慢速源 (实际 ${order1Elapsed}ms)`
    );
    const order1Probe = order1Snap.claudeState.nodeProbe!;
    assert.ok(order1Probe?.regionMismatchDetail);
    assert.equal(isProbeRegionMismatched(order1Probe), true);
    const order1Safety = evaluateClaudeNodeProbeSafety(order1Probe, {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: order1Probe.claudeTraceIp,
    });
    assert.equal(order1Safety?.alertType, 'mismatch');
    const order1Alert = resolveAlertActualMismatchFields({
      isClaudeSource: true,
      alertType: 'mismatch',
      expectedCode: proxyCountry,
      refProbe: order1Probe,
    });
    assert.equal(order1Alert.actualCode, direct1.countryCode);
    assert.ok(
      order1Alert.actualIp && order1Alert.actualIp !== order1Probe.claudeTraceIp
    );
    assert.equal(
      geo.lookupOfflineStrict(order1Alert.actualIp).countryCode,
      order1Alert.actualCode
    );

    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([
        `DOMAIN,${direct1.host},${foreignTarget}`,
        `DOMAIN,${direct2.host},${foreignTarget}`,
        ...proxySideHosts.map((h) => `DOMAIN,${h},test-delay`),
      ])
    );
    const order2Snap = await subEngine.probeClaudeNodeNow('跨国分流顺序二', true);
    const order2Probe = order2Snap.claudeState.nodeProbe!;
    assert.ok(order2Probe?.regionMismatchDetail);
    assert.equal(isProbeRegionMismatched(order2Probe), true);
    const order2Alert = resolveAlertActualMismatchFields({
      isClaudeSource: true,
      alertType: 'mismatch',
      expectedCode: proxyCountry,
      refProbe: order2Probe,
    });
    assert.equal(order2Alert.actualCode, direct1.countryCode);
    assert.ok(
      order2Alert.actualIp && order2Alert.actualIp !== order2Probe.claudeTraceIp
    );
    assert.equal(
      geo.lookupOfflineStrict(order2Alert.actualIp).countryCode,
      order2Alert.actualCode
    );

    // (1f) 时区同步前后的 Claude 状态策略校验
    const localeStore = new ConfigStore();
    localeStore.update({
      selectedClashNode: '五源标准节点',
      selectedClashProfileUid: 'reduced-prof',
      selectedClashProfileName: '受限源测试订阅',
      dedicatedProxyPort: subPort,
      claudeExclusiveGuard: false,
      claudeForceIpv4: false,
      killProcessesEnabled: false,
    });
    const localeEngine = new ProbeEngine(
      localeStore,
      geo,
      new ClashMonitor(subVergeDir),
      subService
    );
    const makeForeignDefaultUpstreamConfig = (rules: string[]) =>
      yaml.dump({
        ...upBaseCfg,
        hosts: { ...upHosts, ...extraForeignHosts },
        listeners: [
          {
            name: 'test-base-upstream',
            type: 'mixed',
            port: baseUpstreamPort,
            listen: '127.0.0.1',
            proxy: outboundGroup,
          },
          {
            name: 'test-direct-upstream',
            type: 'mixed',
            port: directUpstreamPort,
            listen: '127.0.0.1',
            proxy: foreignTarget,
          },
        ],
        proxies: [
          ...upProxies,
          ...extraForeignProxies,
          { name: 'test-delay', type: 'http', server: '127.0.0.1', port: relayPort },
          {
            name: 'test-direct-delay',
            type: 'http',
            server: '127.0.0.1',
            port: directDelayPort,
          },
          {
            name: 'test-counted-pass',
            type: 'http',
            server: '127.0.0.1',
            port: countedPassPort,
          },
          {
            name: 'test-hold-drop',
            type: 'http',
            server: '127.0.0.1',
            port: holdBeforeTlsPort,
          },
          {
            name: 'test-claude-hold',
            type: 'http',
            server: '127.0.0.1',
            port: claudeHoldPort,
          },
        ],
        rules: [...rules, `MATCH,${foreignTarget}`],
      });
    try {
      await reloadKernelConfig(
        upLease.endpoint,
        makeForeignDefaultUpstreamConfig(['DOMAIN,claude.ai,REJECT'])
      );
      const unverifiedSnap = await localeEngine.probeClaudeNodeNow(
        '未校验节点 trace 失败',
        true
      );
      assert.ok(unverifiedSnap.claudeState.nodeProbe?.claudeTraceError);
      const blockedLocaleSync = localeEngine.resolveLocaleSyncTarget('claude');
      assert.equal(
        blockedLocaleSync.ok,
        false,
        '未通过真实校验的节点不得触发系统时区同步'
      );
      assert.match(blockedLocaleSync.message, /校验未通过/);
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('US', 'Eastern Standard Time'),
        true,
        '从未通过真实校验的节点在切换系统时区前必须 Fail-Closed 终止 Claude'
      );

      await reloadKernelConfig(
        upLease.endpoint,
        makeForeignDefaultUpstreamConfig([])
      );
      const verifiedUsSnap = await localeEngine.probeClaudeNodeNow(
        '真实探测确立 US 基线',
        true
      );
      assert.equal(
        verifiedUsSnap.claudeState.proxyCountryCode,
        expectedForeignCountry
      );
      assert.equal(
        getTargetServiceVerificationError(
          verifiedUsSnap.claudeState.nodeProbe,
          'claude'
        ),
        null
      );
      const allowedLocaleSync = localeEngine.resolveLocaleSyncTarget('claude');
      assert.equal(allowedLocaleSync.ok, true);
      if (allowedLocaleSync.ok) {
        assert.equal(allowedLocaleSync.targetCode, expectedForeignCountry);
      }

      await reloadKernelConfig(
        upLease.endpoint,
        makeForeignDefaultUpstreamConfig(['DOMAIN,claude.ai,REJECT'])
      );
      const pendingTraceSnap = await localeEngine.probeClaudeNodeNow(
        'US 基线确立后 trace 暂不可达',
        true
      );
      assert.ok(pendingTraceSnap.claudeState.nodeProbe?.claudeTraceError);
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('US', 'Eastern Standard Time'),
        false,
        '真实确立 US 基线后若仅 trace 暂不可达，切往同属 US 的另一时区必须保留待复核会话'
      );
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('JP', 'Tokyo Standard Time'),
        true,
        '目标时区与真实确立的 US 基线不符时必须终止待复核 Claude 会话'
      );

      await reloadKernelConfig(
        upLease.endpoint,
        makeForeignDefaultUpstreamConfig([
          'DOMAIN,claude.ai,REJECT',
          ...allGeneralHosts.map((h) => `DOMAIN,${h},REJECT`),
        ])
      );
      const allFailPendingSnap = await localeEngine.probeClaudeNodeNow(
        'US 基线确立后全源暂不可达',
        true
      );
      assert.equal(allFailPendingSnap.claudeState.nodeProbe, null);
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('US', 'Central Standard Time'),
        false,
        '全源暂不可达但上次真实确认地区仍匹配目标 US 时区时应保留待复核会话'
      );
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('GB', 'GMT Standard Time'),
        true,
        '全源暂不可达且目标时区与上次真实确认地区不符时必须终止 Claude'
      );

      rig.state.foreignClaudeTraceMode = 'loc-xx-proxy-ip';
      await reloadKernelConfig(
        upLease.endpoint,
        makeForeignDefaultUpstreamConfig([])
      );
      const locXxForeignSnap = await localeEngine.probeClaudeNodeNow(
        'trace 返回 loc=XX 且离线归属为 JP',
        true
      );
      assert.equal(
        locXxForeignSnap.claudeState.nodeProbe?.claudeTraceCountryCode,
        expectedProxyCountry
      );
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('US', 'Eastern Standard Time'),
        true,
        'trace 离线归属已确认不匹配目标 US 时区时必须终止 Claude'
      );
      rig.state.foreignClaudeTraceMode = 'normal';

      await reloadKernelConfig(
        upLease.endpoint,
        makeForeignDefaultUpstreamConfig([
          `DOMAIN,${direct1.host},${outboundGroup}`,
          `DOMAIN,${direct2.host},${outboundGroup}`,
        ])
      );
      const realSplitSnap = await localeEngine.probeClaudeNodeNow(
        '真实探测触发跨国分流',
        true
      );
      assert.equal(isProbeRegionMismatched(realSplitSnap.claudeState.nodeProbe), true);
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('US', 'Eastern Standard Time'),
        true,
        '真实探测确认跨国分流时即使目标时区仍为 US 也必须终止 Claude'
      );
    } finally {
      rig.state.foreignClaudeTraceMode = 'normal';
      localeEngine.stop();
      await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    }

    // (2) 双源受限节点的双序 1:1 冲突校验
    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    observedHopTargets.clear();
    observedHopHosts.clear();
    await bindSubNode('双源受限节点');
    assert.equal(
      selectProbeEndpointsForTransportHosts(
        BUILTIN_TRACE_ENDPOINTS,
        subService.channels.claude.getBoundTransportHosts()
      ).length,
      2
    );
    const twoOk = await subEngine.probeClaudeNodeNow('双源受限节点正常校验', true);
    assert.ok(
      twoOk.claudeState.nodeProbe &&
        getTargetServiceVerificationError(twoOk.claudeState.nodeProbe, 'claude') === null
    );
    assert.equal(observedHopTargets.has(`hop.${excludedThreeDomains[0]}`), true);
    assert.equal(observedHopHosts.has(`edge.${excludedThreeDomains[1]}`), true);

    const keptProxyHost = new URL(proxySideEndpoints[0].url).hostname;
    rig.state.relayMode = 'delay-target-short';
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([`DOMAIN,${direct1.host},test-direct-delay`])
    );
    const tie1Start = Date.now();
    const tie1Snap = await subEngine.probeClaudeNodeNow('双源 1:1 冲突顺序一', true);
    assert.ok(Date.now() - tie1Start >= 2100);
    assert.equal(tie1Snap.claudeState.nodeProbe, null);
    assert.match(tie1Snap.claudeState.nodeProbeError || '', /常规出口复核未完成/);

    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([
        `DOMAIN,${direct1.host},${foreignTarget}`,
        `DOMAIN,${keptProxyHost},test-delay`,
      ])
    );
    const tie2Start = Date.now();
    const tie2Snap = await subEngine.probeClaudeNodeNow('双源 1:1 冲突顺序二', true);
    assert.ok(Date.now() - tie2Start >= 2100);
    assert.equal(tie2Snap.claudeState.nodeProbe, null);
    assert.match(tie2Snap.claudeState.nodeProbeError || '', /常规出口复核未完成/);

    // (3) 单源受限节点：Claude 主连接存活期间本地端口关闭，错峰备用请求 ECONNREFUSED 立即中断主连接并触发私有内核重绑
    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    await bindSubNode('单源受限节点');
    assert.equal(
      selectProbeEndpointsForTransportHosts(
        BUILTIN_TRACE_ENDPOINTS,
        subService.channels.claude.getBoundTransportHosts()
      ).length,
      1
    );
    const subOneLease = readLeaseEndpoint(
      path.join(liveRoot, 'sub-kernels', 'claude')
    );
    rig.state.claudeHoldReleasedCount = 0;
    rig.state.claudeHoldClosedBeforeReleaseCount = 0;
    rig.state.holdClaudePrimary = true;
    let preHedgeLookups = 0;
    let triggeredHedgeRefusal = false;
    let primaryStillOpenAfterClose = false;
    let hedgeReadyCount = 0;
    let hedgeFaultTask: Promise<void> = Promise.resolve();
    const onHedgeReady = () => hedgeReadyCount++;
    subService.channels.claude.on('ready', onHedgeReady);
    const maybeTriggerHedgeRefusal = () => {
      if (
        triggeredHedgeRefusal ||
        claudeHoldClients.size === 0 ||
        preHedgeLookups < 1
      ) {
        return;
      }
      triggeredHedgeRefusal = true;
      rig.state.holdClaudePrimary = false;
      hedgeFaultTask = (async () => {
        await delay(40);
        await mihomoRequest(subOneLease.endpoint, '/configs', 'PATCH', {
          'mixed-port': 0,
        });
        await delay(150);
        primaryStillOpenAfterClose = claudeHoldClients.size > 0;
      })();
      hedgeFaultTask.catch(() => undefined);
    };
    rig.state.onClaudeHoldReady = maybeTriggerHedgeRefusal;
    onSubGeoLookup = (code) => {
      if (triggeredHedgeRefusal) return;
      if (code === proxyCountry) preHedgeLookups++;
      maybeTriggerHedgeRefusal();
    };
    try {
      await reloadKernelConfig(
        upLease.endpoint,
        makeUpstreamConfig(['DOMAIN,claude.ai,test-claude-hold'])
      );
      const hedgeRefusedSnap = await subEngine.probeClaudeNodeNow(
        'Claude 对冲端口拒绝重绑',
        true
      );
      await hedgeFaultTask;
      assert.equal(triggeredHedgeRefusal, true, '应触发 Claude 对冲端口关闭故障');
      assert.equal(
        primaryStillOpenAfterClose,
        true,
        '关闭监听端口后已建立的 Claude 主连接应保持存活'
      );
      assert.equal(
        rig.state.claudeHoldReleasedCount,
        0,
        '错峰备用请求 ECONNREFUSED 后必须立即中断挂起的主连接'
      );
      assert.ok(
        rig.state.claudeHoldClosedBeforeReleaseCount >= 1,
        '被中断的主连接应在释放前关闭'
      );
      assert.equal(hedgeReadyCount, 1, 'Claude 对冲端口拒绝必须触发私有内核重绑');
      assert.equal(
        await isLocalPortListening(subPort),
        true,
        '重绑后专属端口应恢复监听'
      );
      assert.ok(
        hedgeRefusedSnap.claudeState.nodeProbe &&
          getTargetServiceVerificationError(
            hedgeRefusedSnap.claudeState.nodeProbe,
            'claude'
          ) === null,
        `重绑后应校验通过: err=${hedgeRefusedSnap.claudeState.nodeProbeError}`
      );
    } finally {
      rig.state.holdClaudePrimary = false;
      rig.state.onClaudeHoldReady = null;
      onSubGeoLookup = null;
      subService.channels.claude.off('ready', onHedgeReady);
      await hedgeFaultTask.catch(() => undefined);
      await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    }

    // (4) 四源复核节点：已取得 >=2 匹配样本 + 1 异国样本 + Claude 后，关闭本地端口使第 4 源触发 ECONNREFUSED，仍优先重绑
    await bindSubNode('四源复核节点');
    const subFourLease = readLeaseEndpoint(
      path.join(liveRoot, 'sub-kernels', 'claude')
    );
    const passHost0 = new URL(proxySideEndpoints[0].url).hostname.toLowerCase();
    const passHost1 = new URL(proxySideEndpoints[1].url).hostname.toLowerCase();
    acceptedPassHosts.clear();
    let preRefusalProxyLookups = 0;
    let preRefusalForeignLookups = 0;
    let triggeredRefusal = false;
    let fourReadyCount = 0;
    let fourFaultTask: Promise<void> = Promise.resolve();
    const onFourReady = () => fourReadyCount++;
    subService.channels.claude.on('ready', onFourReady);
    const maybeTriggerFourRefusal = () => {
      if (
        triggeredRefusal ||
        heldDropClients.size === 0 ||
        !acceptedPassHosts.has(passHost0) ||
        !acceptedPassHosts.has(passHost1) ||
        !acceptedPassHosts.has('claude.ai') ||
        preRefusalProxyLookups < MIN_CONSENSUS_MATCHES + 1 ||
        preRefusalForeignLookups < 1
      ) {
        return;
      }
      triggeredRefusal = true;
      fourFaultTask = (async () => {
        await delay(40);
        await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
        await mihomoRequest(subFourLease.endpoint, '/configs', 'PATCH', {
          'mixed-port': 0,
        });
        const closeDeadline = Date.now() + 2000;
        while (
          (await isLocalPortListening(subPort)) &&
          Date.now() < closeDeadline
        ) {
          await delay(20);
        }
        for (const sock of heldDropClients) sock.destroy();
      })();
      fourFaultTask.catch(() => undefined);
    };
    rig.state.onPassHostAccepted = maybeTriggerFourRefusal;
    rig.state.onHeldDropReady = maybeTriggerFourRefusal;
    onSubGeoLookup = (code) => {
      if (triggeredRefusal) return;
      if (code === proxyCountry) preRefusalProxyLookups++;
      else preRefusalForeignLookups++;
      maybeTriggerFourRefusal();
    };
    try {
      await reloadKernelConfig(
        upLease.endpoint,
        makeUpstreamConfig([
          `DOMAIN,${direct1.host},${foreignTarget}`,
          `DOMAIN,${passHost0},test-counted-pass`,
          `DOMAIN,${passHost1},test-counted-pass`,
          'DOMAIN,claude.ai,test-counted-pass',
          `DOMAIN,${direct2.host},test-hold-drop`,
        ])
      );
      const refusedRecoveredSnap = await subEngine.probeClaudeNodeNow(
        '两源匹配后本地端口拒绝优先重绑',
        true
      );
      await fourFaultTask;
      assert.equal(
        triggeredRefusal,
        true,
        `应触发四源匹配后端口拒绝: accepted=${[...acceptedPassHosts].join(
          ','
        )}, proxyLookups=${preRefusalProxyLookups}, foreignLookups=${preRefusalForeignLookups}, held=${
          heldDropClients.size
        }`
      );
      assert.ok(
        preRefusalProxyLookups >= MIN_CONSENSUS_MATCHES + 1,
        '触发前应有至少两源匹配+Claude校验'
      );
      assert.ok(preRefusalForeignLookups >= 1, '触发前应有至少一个异国常规样本');
      assert.equal(fourReadyCount, 1, '已匹配两源后遭遇本地端口拒绝必须优先触发重绑');
      assert.equal(
        await isLocalPortListening(subPort),
        true,
        '四源重绑后端口应恢复监听'
      );
      assert.ok(
        refusedRecoveredSnap.claudeState.nodeProbe &&
          getTargetServiceVerificationError(
            refusedRecoveredSnap.claudeState.nodeProbe,
            'claude'
          ) === null,
        `四源重绑后应校验通过: err=${refusedRecoveredSnap.claudeState.nodeProbeError}`
      );
    } finally {
      rig.state.onPassHostAccepted = null;
      rig.state.onHeldDropReady = null;
      onSubGeoLookup = null;
      subService.channels.claude.off('ready', onFourReady);
      await fourFaultTask.catch(() => undefined);
      await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    }

    console.log(
      '通过：基于独立真实测试节点完成错峰对冲、零常规源 Claude 出口检查、单源旁路共识、双源 1:1 双序冲突、多源跨国分流双序与告警同源配对、Antigravity 冲突取消重测及对冲/复核期端口拒绝自动重绑'
    );
  } finally {
    onSubGeoLookup = null;
    subEngine?.stop();
    await Promise.all([subService.shutdown(), upstreamService.shutdown()]);
    untrackService(subService);
    untrackService(upstreamService);
    await rig.cleanup();
  }
}
