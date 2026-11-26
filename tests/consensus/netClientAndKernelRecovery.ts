import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as path from 'node:path';
import type { Duplex } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import * as yaml from 'js-yaml';
import {
  ClashMonitor,
  extractSnapshotTransportHosts,
  isLocalPortListening,
  mihomoRequest,
  SubscriptionCatalog,
} from '../../electron/clash';
import {
  evaluateClaudeNodeProbeSafety,
  ProbeEngine,
  resolveAlertActualMismatchFields,
} from '../../electron/guard';
import { PrivateProxyService, verifyCore } from '../../electron/kernel';
import { isLocalProxyRefusedCause, requestTextViaProxy } from '../../electron/net';
import {
  BUILTIN_TRACE_ENDPOINTS,
  interpretClaudeTracePayload,
  selectProbeEndpointsForTransportHosts,
} from '../../electron/probe';
import { ConfigStore, GeoIpService } from '../../electron/system';
import type { ProbeResult } from '../../src/shared/types';
import {
  freePort,
  listen,
  parseHttpConnectAuthority,
  readLeaseEndpoint,
  root,
  trackService,
  untrackService,
} from './testHarness';

export async function verifyLocalNetClientAndKernelRecovery(
  coreDir: string
): Promise<void> {
  // 1. 本地代理端口 ECONNREFUSED 立即失败（不延迟重试）且精准区分本地代理拒绝与远端目标拒绝
  const closedPort = await freePort();
  const refusedStart = Date.now();
  await assert.rejects(
    requestTextViaProxy('https://example.com', `http://127.0.0.1:${closedPort}`, 5000),
    (err: unknown) => {
      assert.equal(isLocalProxyRefusedCause(err, `http://127.0.0.1:${closedPort}`), true);
      assert.equal(isLocalProxyRefusedCause(err, 'http://127.0.0.1:1'), false);
      return true;
    }
  );
  assert.ok(
    Date.now() - refusedStart < 1500,
    '本地代理端口拒绝连接应立即外抛而非等待重试退避'
  );

  // 2. 前两次瞬断后第三次重试恢复 + AbortSignal 立即取消释放 socket
  const originServer = http.createServer((_req, res) => res.end('ok-body'));
  const originPort = await listen(originServer, '127.0.0.1');
  const relayClients = new Set<net.Socket>();
  let relayHits = 0;
  let relayBehavior: 'drop-first-two' | 'hang' = 'drop-first-two';
  const relayServer = http.createServer((_req, res) => {
    res.writeHead(502);
    res.end();
  });
  relayServer.on('connection', (sock) => {
    relayClients.add(sock);
    sock.once('close', () => relayClients.delete(sock));
  });
  relayServer.on('connect', (_req, client) => {
    const hit = ++relayHits;
    client.on('error', () => client.destroy());
    if (relayBehavior === 'drop-first-two' && hit <= 2) {
      client.write('HTTP/1.1 200 Connection established\r\n\r\n');
      client.destroy();
      return;
    }
    if (relayBehavior === 'hang') {
      client.once('end', () => client.end());
      client.resume();
      return;
    }
    client.write('HTTP/1.1 200 Connection established\r\n\r\n');
    const up = net.connect(originPort, '127.0.0.1', () => {
      client.pipe(up);
      up.pipe(client);
    });
    up.on('error', () => client.destroy());
    client.on('error', () => up.destroy());
  });

  const forwardClients = new Set<net.Socket>();
  let forwardHits = 0;
  const forwardRelay = http.createServer((req, res) => {
    const hit = ++forwardHits;
    if (relayBehavior === 'drop-first-two' && hit <= 2) {
      req.socket.destroy();
      return;
    }
    if (relayBehavior === 'hang') {
      return;
    }
    const target = new URL(req.url!);
    const upReq = http.request(
      { host: target.hostname, port: target.port || 80, path: target.pathname },
      (upRes) => {
        res.writeHead(upRes.statusCode || 200, upRes.headers);
        upRes.pipe(res);
      }
    );
    upReq.on('error', () => res.destroy());
    upReq.end();
  });
  forwardRelay.on('connection', (sock) => {
    forwardClients.add(sock);
    sock.once('close', () => forwardClients.delete(sock));
  });
  const relayPort = await listen(relayServer, '127.0.0.1');
  const forwardPort = await listen(forwardRelay, '127.0.0.1');

  const localTlsCertPath = process.env.GUARD_TEST_TLS_CERT;
  const localTlsKeyPath = process.env.GUARD_TEST_TLS_KEY;
  assert.ok(
    localTlsCertPath &&
      localTlsKeyPath &&
      fs.existsSync(localTlsCertPath) &&
      fs.existsSync(localTlsKeyPath),
    '缺少本地回归真实 TLS 转发服务证书环境变量（请通过 npm test 运行）'
  );
  const localTlsOrigin = https.createServer(
    {
      key: fs.readFileSync(localTlsKeyPath, 'utf8'),
      cert: fs.readFileSync(localTlsCertPath, 'utf8'),
    },
    (req, res) => {
      if ((req.url || '/').startsWith('/cdn-cgi/trace')) {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(
          `fl=29f1\nip=1.0.16.1\nts=${Math.floor(Date.now() / 1000)}\nloc=JP\n`
        );
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('1.0.16.1\n');
    }
  );
  const localTlsOriginPort = await listen(localTlsOrigin, '127.0.0.1');
  const localExitClients = new Set<Duplex>();
  const localExitProxy = http.createServer((req, res) => {
    const target = new URL(req.url || `http://127.0.0.1:${originPort}/`);
    const upReq = http.request(
      {
        host: target.hostname,
        port: target.port || 80,
        path: target.pathname + target.search,
        method: req.method,
      },
      (upRes) => {
        res.writeHead(upRes.statusCode || 200, upRes.headers);
        upRes.pipe(res);
      }
    );
    upReq.on('error', () => res.destroy());
    upReq.end();
  });
  localExitProxy.on('clientError', (_err, sock) => sock.destroy());
  localExitProxy.on('connect', (req, client, head) => {
    localExitClients.add(client);
    const parsed = parseHttpConnectAuthority(req.url);
    const targetPort =
      parsed && parsed.host === '127.0.0.1' && parsed.port === originPort
        ? originPort
        : localTlsOriginPort;
    const up = net.connect(targetPort, '127.0.0.1', () => {
      client.write('HTTP/1.1 200 Connection established\r\n\r\n');
      if (head.length > 0) up.write(head);
      client.pipe(up);
      up.pipe(client);
    });
    up.on('error', () => client.destroy());
    client.on('error', () => up.destroy());
    client.once('end', () => client.end());
    client.once('close', () => {
      up.destroy();
      localExitClients.delete(client);
    });
  });
  const localExitProxyPort = await listen(localExitProxy, '127.0.0.1');

  const localRoot = path.join(root, 'local-kernel-recovery');
  const localSubDir = path.join(localRoot, 'verge');
  fs.mkdirSync(path.join(localSubDir, 'profiles'), { recursive: true });
  const allFiveDomains = BUILTIN_TRACE_ENDPOINTS.map((ep) => ep.registrableDomain);
  const hopHosts = Object.fromEntries(
    allFiveDomains.map((d) => [`hop.${d}`, '127.0.0.1'])
  );
  const dummyPort = await freePort();
  fs.writeFileSync(
    path.join(localSubDir, 'profiles.yaml'),
    yaml.dump({
      current: 'local-prof',
      items: [
        {
          uid: 'local-prof',
          name: '本地测试订阅',
          type: 'local',
          file: 'local-prof.yaml',
        },
      ],
    }),
    'utf8'
  );
  fs.writeFileSync(
    path.join(localSubDir, 'profiles', 'local-prof.yaml'),
    yaml.dump({
      hosts: hopHosts,
      proxies: [
        {
          name: '直连测试节点',
          type: 'http',
          server: '127.0.0.1',
          port: localExitProxyPort,
        },
        {
          name: '零源跳板-2',
          type: 'http',
          server: `hop.${allFiveDomains[4]}`,
          port: dummyPort,
          headers: { Host: `edge.${allFiveDomains[3]}` },
        },
        {
          name: '零源跳板-1',
          type: 'http',
          server: `hop.${allFiveDomains[2]}`,
          port: dummyPort,
          headers: { Host: `edge.${allFiveDomains[1]}` },
          'dialer-proxy': '零源跳板-2',
        },
        {
          name: '全重合零源节点',
          type: 'http',
          server: `hop.${allFiveDomains[0]}`,
          port: dummyPort,
          'dialer-proxy': '零源跳板-1',
        },
      ],
    }),
    'utf8'
  );

  const localService = trackService(
    new PrivateProxyService(path.join(localRoot, 'kernels'), coreDir)
  );
  const localCatalog = new SubscriptionCatalog(localSubDir);
  localCatalog.refresh();
  const localGeo = new GeoIpService();
  await localGeo.init(process.cwd());

  // 验证离线 GeoIP 严格查询命中缓存时不重读磁盘 mmdb
  const cachedFirst = localGeo.lookupOfflineStrict('8.8.8.8');
  assert.equal(cachedFirst.countryCode, 'US');
  assert.equal(localGeo.isReaderLoaded(), true);
  localGeo.releaseCachedReader();
  assert.equal(localGeo.isReaderLoaded(), false);
  const cachedSecond = localGeo.lookupOfflineStrict('8.8.8.8');
  assert.equal(cachedSecond.countryCode, 'US');
  assert.equal(
    localGeo.isReaderLoaded(),
    false,
    '命中缓存时不得重新加载 mmdb 读取器'
  );

  // 验证 Claude trace 返回有效出口 IP 但 loc=XX 时（含离线 mmdb 命中与未命中两种情况），均保留 claudeTraceIp 以检测运行中 IP 漂移
  const locXxKnownGeo = interpretClaudeTracePayload(
    'fl=29f1\nip=8.8.4.4\nloc=XX\nts=1700000000\n',
    (ip) => localGeo.lookupOfflineStrict(ip),
    Date.now(),
    35
  );
  assert.equal(locXxKnownGeo.kind, 'trace-error');
  assert.equal(locXxKnownGeo.claudeTraceIp, '8.8.4.4');
  assert.equal(
    locXxKnownGeo.claudeTraceCountryCode,
    'US',
    'loc=XX 且 mmdb 命中时应保留离线归属国家'
  );
  assert.match(locXxKnownGeo.claudeTraceError, /未解析到有效国家\/地区代码/);

  const locXxUnknownGeo = interpretClaudeTracePayload(
    'fl=29f1\nip=203.0.113.10\nloc=XX\nts=1700000000\n',
    (ip) => localGeo.lookupOfflineStrict(ip),
    Date.now(),
    35
  );
  assert.equal(locXxUnknownGeo.kind, 'trace-error');
  assert.equal(locXxUnknownGeo.claudeTraceIp, '203.0.113.10');
  assert.equal(locXxUnknownGeo.claudeTraceCountryCode, undefined);
  assert.match(locXxUnknownGeo.claudeTraceError, /未解析到有效国家\/地区代码/);

  for (const outcome of [locXxKnownGeo, locXxUnknownGeo]) {
    const locXxProbe: ProbeResult = {
      ip: outcome.claudeTraceIp!,
      countryCode: 'UNKNOWN',
      countryName: '未知',
      viaChannel: '测试通道',
      latencyMs: outcome.latencyMs ?? 35,
      checkedAt: outcome.claudeTraceCheckedAt ?? Date.now(),
      claudeTraceIp: outcome.claudeTraceIp,
      claudeTraceCountryCode: outcome.claudeTraceCountryCode,
      claudeTraceError: outcome.claudeTraceError,
      claudeTraceCheckedAt: outcome.claudeTraceCheckedAt,
      regionMismatchDetail: null,
    };
    const locXxDriftCheck = evaluateClaudeNodeProbeSafety(locXxProbe, {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: '8.8.8.8',
    });
    assert.equal(
      locXxDriftCheck?.alertType,
      'ip-change',
      'loc=XX 返回有效漂移 IP 时必须触发 ip-change'
    );
    assert.equal(locXxDriftCheck?.expectedIp, '8.8.8.8');
    assert.equal(locXxDriftCheck?.actualIp, outcome.claudeTraceIp);
    const locXxSameIpCheck = evaluateClaudeNodeProbeSafety(locXxProbe, {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: outcome.claudeTraceIp,
    });
    assert.equal(locXxSameIpCheck?.alertType, 'verification-unavailable');
  }

  // 验证 loc=XX 但已知 claudeTraceCountryCode 时，告警字段与 claudeTraceIp 同源配对而非误取常规源国家代码
  const locXxCrossGeneralProbe: ProbeResult = {
    ip: '198.51.100.2',
    countryCode: 'JP',
    countryName: '日本',
    viaChannel: '测试通道',
    latencyMs: 35,
    checkedAt: Date.now(),
    claudeTraceIp: '8.8.4.4',
    claudeTraceCountryCode: 'US',
    claudeTraceError: locXxKnownGeo.claudeTraceError,
    claudeTraceCheckedAt: Date.now(),
    regionMismatchDetail: null,
  };
  const locXxAlertPaired = resolveAlertActualMismatchFields({
    isClaudeSource: true,
    alertType: 'ip-change',
    expectedCode: 'JP',
    refProbe: locXxCrossGeneralProbe,
  });
  assert.equal(locXxAlertPaired.actualIp, '8.8.4.4');
  assert.equal(
    locXxAlertPaired.actualCode,
    'US',
    'claudeTraceIp 已知离线国家时不得误取常规源国家代码'
  );
  assert.equal(locXxAlertPaired.actualName, '美国');

  const localStore = new ConfigStore();
  localStore.update({
    selectedClashNode: null,
    selectedClashProfileUid: null,
    selectedClashProfileName: null,
    claudeExclusiveGuard: false,
    killProcessesEnabled: false,
  });
  const localEngine = new ProbeEngine(
    localStore,
    localGeo,
    new ClashMonitor(localSubDir),
    localService
  );
  try {
    const recovered = await requestTextViaProxy(
      `http://127.0.0.1:${originPort}/`,
      `http://127.0.0.1:${forwardPort}`,
      5000,
      undefined,
      0,
      true
    );
    assert.equal(recovered, 'ok-body');
    assert.equal(forwardHits, 3, '前两次瞬断后第三次重试应成功取得响应');

    relayBehavior = 'hang';
    const cancelCtrl = new AbortController();
    const cancelTimer = setTimeout(
      () => cancelCtrl.abort(new Error('主动取消握手')),
      250
    );
    const startCancel = Date.now();
    await assert.rejects(
      requestTextViaProxy(
        'https://example.com',
        `http://127.0.0.1:${relayPort}`,
        8000,
        undefined,
        0,
        false,
        cancelCtrl.signal
      ),
      (err) => err === cancelCtrl.signal.reason
    );
    clearTimeout(cancelTimer);
    assert.ok(Date.now() - startCancel < 1500, 'AbortSignal 必须立即终止代理握手');
    const closeDeadline = Date.now() + 1000;
    while (relayClients.size > 0 && Date.now() < closeDeadline) await delay(20);
    assert.equal(relayClients.size, 0, '取消后必须关闭全部代理连接 socket');

    // 3. 验证全重合零源节点在真实 guard-mihomo.exe + ProbeEngine 中 Fail-Closed 阻断
    const zeroPort = await freePort();
    const zeroSnap = localCatalog.capture('local-prof', '全重合零源节点');
    assert.equal(
      selectProbeEndpointsForTransportHosts(
        BUILTIN_TRACE_ENDPOINTS,
        extractSnapshotTransportHosts(zeroSnap)
      ).length,
      0,
      '全重合节点不得恢复已排除传输层域名'
    );
    await localService.channels.claude.select(zeroSnap, zeroPort);
    assert.equal(localService.channels.claude.getState().phase, 'ready');
    assert.match(
      localService.channels.claude.getState().verificationError || '',
      /传输层域名重合/
    );
    localStore.update({
      selectedClashNode: '全重合零源节点',
      selectedClashProfileUid: 'local-prof',
      selectedClashProfileName: '本地测试订阅',
      dedicatedProxyPort: zeroPort,
      claudeExclusiveGuard: false,
      killProcessesEnabled: false,
    });
    const zeroResult = await localEngine.probeClaudeNodeNow(
      '全重合零源节点 Fail-Closed 校验',
      true
    );
    assert.equal(zeroResult.claudeState.nodeProbe, null);
    assert.equal(zeroResult.claudeState.canLaunch, false);
    assert.match(zeroResult.claudeState.nodeProbeError || '', /传输层域名重合/);
    localStore.update({
      selectedClashNode: null,
      selectedClashProfileUid: null,
      selectedClashProfileName: null,
    });

    // 4. 验证真实 guard-mihomo.exe 端口关闭（mixed-port: 0）后：
    //    (a) 若端口被其他进程抢占，recoverListenerIfNeeded 必须核验 OwningProcess 并 Fail-Closed 返回 failed；
    //    (b) 抢占进程释放后，recoverListenerIfNeeded 精准重绑并恢复转发。
    const directPort = await freePort();
    const directSnap = localCatalog.capture('local-prof', '直连测试节点');
    await localService.channels.claude.select(directSnap, directPort);
    assert.equal(await isLocalPortListening(directPort), true);
    const leaseInfo = readLeaseEndpoint(path.join(localRoot, 'kernels', 'claude'));
    let readyEvents = 0;
    localService.channels.claude.on('ready', () => readyEvents++);
    await mihomoRequest(leaseInfo.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
    const dropDeadline = Date.now() + 3000;
    while ((await isLocalPortListening(directPort)) && Date.now() < dropDeadline) {
      await delay(50);
    }
    assert.equal(
      await isLocalPortListening(directPort),
      false,
      '测试已关闭本地专属监听端口'
    );

    const hijacker = net.createServer((sock) => sock.destroy());
    hijacker.listen(directPort, '127.0.0.1');
    await once(hijacker, 'listening');
    try {
      localStore.update({
        selectedClashNode: '直连测试节点',
        selectedClashProfileUid: 'local-prof',
        selectedClashProfileName: '本地测试订阅',
        dedicatedProxyPort: directPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const hijackedSnap = await localEngine.probeClaudeNodeNow(
        '端口被外部进程占用时运行期判定',
        true
      );
      assert.equal(readyEvents, 0, '端口归属不匹配时不得恢复为 ready');
      assert.equal(
        localService.channels.claude.getState().phase,
        'error',
        '端口被外部进程占用时内核状态不得保持 ready'
      );
      assert.equal(hijackedSnap.privateChannels.claude.phase, 'error');
      assert.match(
        localService.channels.claude.getState().verificationError || '',
        /监听归属/
      );
      assert.match(
        localService.channels.claude.getState().error || '',
        /监听归属/
      );
      const hijackedSafety = localEngine.evaluateClaudeSafety(true);
      assert.equal(hijackedSafety.safe, false);
      assert.equal(
        hijackedSafety.alertType,
        'disconnect',
        `端口归属冲突时运行中会话必须按代理绑定失效 (disconnect) 熔断而非保留会话，实际: ${hijackedSafety.alertType} (${hijackedSafety.reason})`
      );
      assert.match(hijackedSafety.reason, /代理绑定失效/);
      assert.match(hijackedSafety.reason, /监听归属/);
    } finally {
      localStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
      });
      await new Promise<void>((resolve) => hijacker.close(() => resolve()));
    }

    const outcome = await localService.channels.claude.recoverListenerIfNeeded();
    assert.equal(outcome, 'rebound');
    assert.equal(readyEvents, 1);
    assert.equal(localService.channels.claude.getState().phase, 'ready');
    assert.equal(localService.channels.claude.getState().error, null);
    assert.equal(localService.channels.claude.getState().verificationError, null);
    assert.equal(await isLocalPortListening(directPort), true);
    assert.equal(
      await requestTextViaProxy(
        `http://127.0.0.1:${originPort}/`,
        `http://127.0.0.1:${directPort}`,
        5000,
        undefined,
        0,
        true
      ),
      'ok-body'
    );

    // 4b. 验证 Windows 双栈 :: 监听抢占 127.0.0.1 专属端口时同样进入 error 并触发 disconnect
    await mihomoRequest(leaseInfo.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
    const dropDualDeadline = Date.now() + 3000;
    while (
      (await isLocalPortListening(directPort)) &&
      Date.now() < dropDualDeadline
    ) {
      await delay(50);
    }
    assert.equal(await isLocalPortListening(directPort), false);
    const dualStackHijacker = net.createServer((sock) => sock.destroy());
    dualStackHijacker.listen({ port: directPort, host: '::', ipv6Only: false });
    await once(dualStackHijacker, 'listening');
    try {
      assert.equal(
        await isLocalPortListening(directPort),
        true,
        'Windows 双栈 :: 监听应接受 127.0.0.1 连接'
      );
      localStore.update({
        selectedClashNode: '直连测试节点',
        selectedClashProfileUid: 'local-prof',
        selectedClashProfileName: '本地测试订阅',
        dedicatedProxyPort: directPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const readyBeforeDual = readyEvents;
      const dualSnap = await localEngine.probeClaudeNodeNow(
        '双栈 :: 端口抢占运行期判定',
        true
      );
      assert.equal(readyEvents, readyBeforeDual, '双栈 :: 监听抢占时不得恢复为 ready');
      assert.equal(
        localService.channels.claude.getState().phase,
        'error',
        '双栈 :: 抢占时内核必须进入 error'
      );
      assert.equal(dualSnap.privateChannels.claude.phase, 'error');
      const dualSafety = localEngine.evaluateClaudeSafety(true);
      assert.equal(dualSafety.safe, false);
      assert.equal(
        dualSafety.alertType,
        'disconnect',
        '双栈 :: 抢占时必须按代理绑定失效 (disconnect) 处理'
      );
    } finally {
      localStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
      });
      await new Promise<void>((resolve) => dualStackHijacker.close(() => resolve()));
    }
    assert.equal(
      await localService.channels.claude.recoverListenerIfNeeded(),
      'rebound'
    );
    assert.equal(localService.channels.claude.getState().phase, 'ready');

    // 验证从 error 恢复为 ready 后，内核子进程意外退出不会因残留 booting 漏发 lost 事件
    let lostEventsAfterRecover = 0;
    const onLostAfterRecover = () => lostEventsAfterRecover++;
    localService.channels.claude.on('lost', onLostAfterRecover);
    try {
      const pidBeforeKill = localService.channels.claude.getState().pid!;
      assert.ok(pidBeforeKill > 0);
      process.kill(pidBeforeKill);
      const lostDeadline = Date.now() + 3000;
      while (lostEventsAfterRecover === 0 && Date.now() < lostDeadline) {
        await delay(50);
      }
      assert.equal(
        lostEventsAfterRecover,
        1,
        '恢复为 ready 后的内核意外退出必须立即触发 lost 事件'
      );
      const restartDeadline = Date.now() + 15000;
      while (
        (localService.channels.claude.getState().phase !== 'ready' ||
          localService.channels.claude.getState().pid === pidBeforeKill) &&
        Date.now() < restartDeadline
      ) {
        await delay(100);
      }
      assert.equal(localService.channels.claude.getState().phase, 'ready');
    } finally {
      localService.channels.claude.off('lost', onLostAfterRecover);
    }
    const refreshedLeaseInfo = readLeaseEndpoint(
      path.join(localRoot, 'kernels', 'claude')
    );

    // 4c. 验证健康检查等待 getLocalPortOwnerPids() 期间子进程退出，丢弃过期端口归属结果且零未处理 Promise 拒绝
    await mihomoRequest(refreshedLeaseInfo.endpoint, '/configs', 'PATCH', {
      'mixed-port': 0,
    });
    const dropExitRaceDeadline = Date.now() + 3000;
    while (
      (await isLocalPortListening(directPort)) &&
      Date.now() < dropExitRaceDeadline
    ) {
      await delay(50);
    }
    assert.equal(await isLocalPortListening(directPort), false);
    const pidBeforeHealthRace = localService.channels.claude.getState().pid!;
    assert.ok(pidBeforeHealthRace > 0);
    let raceHijackHits = 0;
    let killedDuringOwnerLookup = false;
    let racePortConflictCount = 0;
    let raceLostCount = 0;
    const onRacePortConflict = () => racePortConflictCount++;
    const onRaceLost = () => raceLostCount++;
    localService.channels.claude.on('port-conflict', onRacePortConflict);
    localService.channels.claude.on('lost', onRaceLost);
    const raceHijacker = net.createServer((sock) => {
      raceHijackHits++;
      sock.destroy();
      if (raceHijackHits === 2 && !killedDuringOwnerLookup) {
        killedDuringOwnerLookup = true;
        setTimeout(() => {
          try {
            process.kill(pidBeforeHealthRace);
          } catch {
            // 若已退出则忽略
          }
        }, 30);
      }
    });
    raceHijacker.listen(directPort, '127.0.0.1');
    await once(raceHijacker, 'listening');
    try {
      const raceDeadline = Date.now() + 8000;
      while (
        (!killedDuringOwnerLookup || raceLostCount === 0) &&
        Date.now() < raceDeadline
      ) {
        await delay(50);
      }
      assert.equal(
        killedDuringOwnerLookup,
        true,
        '应在健康检查进入端口归属查询期间触发子进程退出'
      );
      assert.equal(raceLostCount, 1, '子进程退出必须正常触发 lost 事件');
      await delay(1200);
      assert.equal(
        racePortConflictCount,
        0,
        '内核已退出后返回的过期端口归属结果必须被丢弃，不得误报 port-conflict'
      );
    } finally {
      localService.channels.claude.off('port-conflict', onRacePortConflict);
      localService.channels.claude.off('lost', onRaceLost);
      await new Promise<void>((resolve) => raceHijacker.close(() => resolve()));
    }
    const postRaceReadyDeadline = Date.now() + 18000;
    while (
      (localService.channels.claude.getState().phase !== 'ready' ||
        localService.channels.claude.getState().pid === pidBeforeHealthRace) &&
      Date.now() < postRaceReadyDeadline
    ) {
      await delay(100);
    }
    assert.equal(
      localService.channels.claude.getState().phase,
      'ready',
      '竞态结束后内核应自动恢复就绪'
    );
    let postRaceLeaseInfo = readLeaseEndpoint(
      path.join(localRoot, 'kernels', 'claude')
    );

    // 4d. 验证私有内核存活且独占端口归属有效、但 Mihomo 控制接口临时超时时
    const suspendedPid = localService.channels.claude.getState().pid!;
    assert.ok(suspendedPid > 0);
    try {
      execFileSync(
        'powershell.exe',
        [
          '-NoProfile',
          '-NonInteractive',
          '-File',
          path.resolve('tests/suspendKernel.ps1'),
          '-KernelPid',
          String(suspendedPid),
          '-ExpectedExecutable',
          verifyCore(coreDir),
        ],
        { windowsHide: true, stdio: 'pipe' }
      );
      localStore.update({
        selectedClashNode: '直连测试节点',
        selectedClashProfileUid: 'local-prof',
        selectedClashProfileName: '本地测试订阅',
        dedicatedProxyPort: directPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const timeoutSnap = await localEngine.probeClaudeNodeNow(
        '控制接口临时超时保留运行会话',
        true
      );
      assert.equal(
        localService.channels.claude.getState().phase,
        'ready',
        '私有内核存活且无端口冲突时，控制接口超时不得将通道标为 error'
      );
      assert.match(
        localService.channels.claude.getState().verificationError || '',
        /超时/
      );
      assert.equal(
        timeoutSnap.claudeState.canLaunch,
        false,
        '控制接口超时期间必须阻止新启动'
      );
      const timeoutSafety = localEngine.evaluateClaudeSafety(true);
      assert.equal(timeoutSafety.safe, false);
      assert.equal(
        timeoutSafety.alertType,
        'verification-unavailable',
        `控制接口超时且无端口冲突时必须归为 verification-unavailable 保留会话，实际：${timeoutSafety.alertType} (${timeoutSafety.reason})`
      );
    } finally {
      localStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
      });
      await localService.channels.claude.restart();
      assert.equal(localService.channels.claude.getState().phase, 'ready');
      assert.notEqual(localService.channels.claude.getState().pid, suspendedPid);
      postRaceLeaseInfo = readLeaseEndpoint(
        path.join(localRoot, 'kernels', 'claude')
      );
    }

    // 4e. 验证 stopMonitoring() 取消后台端口归属查询且保留私有内核进程，且 shutdown() 立即取消在途查询
    const monitorStopService = trackService(
      new PrivateProxyService(path.join(localRoot, 'monitor-stop-kernels'), coreDir)
    );
    const monitorAgPort = await freePort();
    const monitorClaudePort = await freePort();
    try {
      await Promise.all([
        monitorStopService.channels.antigravity.select(directSnap, monitorAgPort),
        monitorStopService.channels.claude.select(directSnap, monitorClaudePort),
      ]);
      const agMonitorPid = monitorStopService.channels.antigravity.getState().pid!;
      assert.ok(agMonitorPid > 0);
      const agMonitorLease = readLeaseEndpoint(
        path.join(localRoot, 'monitor-stop-kernels', 'antigravity')
      );
      await mihomoRequest(agMonitorLease.endpoint, '/configs', 'PATCH', {
        'mixed-port': 0,
      });
      const dropAgMonDeadline = Date.now() + 3000;
      while (
        (await isLocalPortListening(monitorAgPort)) &&
        Date.now() < dropAgMonDeadline
      ) {
        await delay(40);
      }
      let agMonHits = 0;
      let stoppedMonitoring = false;
      let agMonConflictCount = 0;
      monitorStopService.channels.antigravity.on(
        'port-conflict',
        () => agMonConflictCount++
      );
      const agMonHijacker = net.createServer((sock) => {
        agMonHits++;
        sock.destroy();
        if (agMonHits === 2 && !stoppedMonitoring) {
          stoppedMonitoring = true;
          setTimeout(() => {
            monitorStopService.channels.antigravity.stopMonitoring();
          }, 30);
        }
      });
      agMonHijacker.listen(monitorAgPort, '127.0.0.1');
      await once(agMonHijacker, 'listening');
      try {
        const waitAgMon = Date.now() + 8000;
        while (!stoppedMonitoring && Date.now() < waitAgMon) await delay(40);
        assert.equal(
          stoppedMonitoring,
          true,
          '应在 Antigravity 健康检查进入端口归属查询后触发 stopMonitoring()'
        );
        await delay(600);
        assert.equal(
          agMonConflictCount,
          0,
          'stopMonitoring() 取消在途端口归属查询后不得继续发出 port-conflict'
        );
        assert.doesNotThrow(
          () => process.kill(agMonitorPid, 0),
          'stopMonitoring() 必须保留 Antigravity 私有内核进程继续运行'
        );
      } finally {
        await new Promise<void>((resolve) => agMonHijacker.close(() => resolve()));
      }

      const claudeMonitorLease = readLeaseEndpoint(
        path.join(localRoot, 'monitor-stop-kernels', 'claude')
      );
      await mihomoRequest(claudeMonitorLease.endpoint, '/configs', 'PATCH', {
        'mixed-port': 0,
      });
      const dropClMonDeadline = Date.now() + 3000;
      while (
        (await isLocalPortListening(monitorClaudePort)) &&
        Date.now() < dropClMonDeadline
      ) {
        await delay(40);
      }
      let clMonHits = 0;
      let shutdownPromise: Promise<void> | null = null;
      let shutdownStartedAt = 0;
      const clMonHijacker = net.createServer((sock) => {
        clMonHits++;
        sock.destroy();
        if (clMonHits === 2 && !shutdownPromise) {
          setTimeout(() => {
            shutdownStartedAt = Date.now();
            shutdownPromise = monitorStopService.shutdown();
          }, 30);
        }
      });
      clMonHijacker.listen(monitorClaudePort, '127.0.0.1');
      await once(clMonHijacker, 'listening');
      try {
        const waitClMon = Date.now() + 8000;
        while (!shutdownPromise && Date.now() < waitClMon) await delay(40);
        assert.ok(
          shutdownPromise,
          '应在 Claude 健康检查进入端口归属查询后触发 shutdown()'
        );
        await shutdownPromise;
        const shutdownElapsed = Date.now() - shutdownStartedAt;
        assert.ok(
          shutdownElapsed < 5000,
          `shutdown() 应立即取消在途端口归属查询并快速停机，而非等待 10s PowerShell 超时 (实际 ${shutdownElapsed}ms)`
        );
      } finally {
        await new Promise<void>((resolve) => clMonHijacker.close(() => resolve()));
      }
    } finally {
      await monitorStopService.shutdown();
      untrackService(monitorStopService);
    }

    // 4f. 验证切换节点因新端口被占用提前失败时，仍恢复原内核的后台健康巡检定时器
    const occupiedSwitchPort = await freePort();
    const occupiedSwitchServer = net.createServer((sock) => sock.destroy());
    occupiedSwitchServer.listen(occupiedSwitchPort, '127.0.0.1');
    await once(occupiedSwitchServer, 'listening');
    try {
      const pidBeforeFailedSwitch = localService.channels.claude.getState().pid!;
      await assert.rejects(
        localService.channels.claude.select(directSnap, occupiedSwitchPort),
        /占用/
      );
      assert.equal(localService.channels.claude.getState().phase, 'ready');
      assert.equal(
        localService.channels.claude.getState().pid,
        pidBeforeFailedSwitch
      );
      assert.equal(
        localService.channels.claude.hasScheduledHealthTimer(),
        true,
        '节点切换提前失败保留原内核时，必须继续排期原内核的健康巡检定时器'
      );
    } finally {
      await new Promise<void>((resolve) => occupiedSwitchServer.close(() => resolve()));
    }

    // 4g. 验证托盘退出 stopMonitoring() 在启动期转发校验阶段保留已过监听校验的 Antigravity 内核
    const startupHoldClients = new Set<Duplex>();
    const startupHoldServer = http.createServer();
    startupHoldServer.on('clientError', (_err, sock) => sock.destroy());
    startupHoldServer.on('connect', (_req, client) => {
      startupHoldClients.add(client);
      client.on('error', () => client.destroy());
      client.write('HTTP/1.1 200 Connection established\r\n\r\n');
      client.once('end', () => client.end());
      client.once('close', () => startupHoldClients.delete(client));
      client.resume();
    });
    const startupHoldPort = await listen(startupHoldServer, '127.0.0.1');
    const startupVergeDir = path.join(localRoot, 'startup-hold-verge');
    fs.mkdirSync(path.join(startupVergeDir, 'profiles'), { recursive: true });
    fs.writeFileSync(
      path.join(startupVergeDir, 'profiles.yaml'),
      yaml.dump({
        current: 'startup-prof',
        items: [
          {
            uid: 'startup-prof',
            name: '启动校验订阅',
            type: 'local',
            file: 'startup-prof.yaml',
          },
        ],
      }),
      'utf8'
    );
    fs.writeFileSync(
      path.join(startupVergeDir, 'profiles', 'startup-prof.yaml'),
      yaml.dump({
        proxies: [
          {
            name: '启动转发挂起节点',
            type: 'http',
            server: '127.0.0.1',
            port: startupHoldPort,
          },
        ],
      }),
      'utf8'
    );
    const startupCat = new SubscriptionCatalog(startupVergeDir);
    startupCat.refresh();
    const hangForwardSnap = startupCat.capture('startup-prof', '启动转发挂起节点');
    const trayExitService = trackService(
      new PrivateProxyService(path.join(localRoot, 'tray-exit-kernels'), coreDir)
    );
    const agTrayPort = await freePort();
    const clTrayPort = await freePort();
    try {
      const agStartTask = trayExitService.channels.antigravity.select(
        hangForwardSnap,
        agTrayPort
      );
      const waitAgForward = Date.now() + 10000;
      while (
        (startupHoldClients.size === 0 ||
          !(await isLocalPortListening(agTrayPort))) &&
        Date.now() < waitAgForward
      ) {
        await delay(30);
      }
      assert.ok(
        startupHoldClients.size >= 1,
        'Antigravity 内核应已通过监听校验并进入启动期转发校验'
      );
      trayExitService.channels.antigravity.stopMonitoring();
      await agStartTask;
      const preservedAgPid = trayExitService.channels.antigravity.getState().pid!;
      assert.ok(preservedAgPid > 0, '托盘退出后 Antigravity 内核 PID 应保持记录');
      assert.doesNotThrow(
        () => process.kill(preservedAgPid, 0),
        '托盘退出 stopMonitoring() 取消启动期转发校验时不得终止已启动的 Antigravity 私有内核'
      );
      assert.equal(
        await isLocalPortListening(agTrayPort),
        true,
        '托盘退出后 Antigravity 专属监听应保持活跃'
      );

      const clStartTask = trayExitService.channels.claude.select(
        hangForwardSnap,
        clTrayPort
      );
      const waitClSpawn = Date.now() + 5000;
      while (
        trayExitService.channels.claude.getState().pid === null &&
        Date.now() < waitClSpawn
      ) {
        await delay(25);
      }
      assert.ok(
        trayExitService.channels.claude.getState().pid !== null,
        'Claude 内核应已启动进入启动校验阶段'
      );
      const shutdownDuringStartAt = Date.now();
      await trayExitService.shutdown();
      await clStartTask.catch(() => undefined);
      assert.ok(
        Date.now() - shutdownDuringStartAt < 5000,
        `shutdown() 应立即取消启动阶段归属/转发校验并快速退出 (实际 ${
          Date.now() - shutdownDuringStartAt
        }ms)`
      );
    } finally {
      await trayExitService.shutdown();
      untrackService(trayExitService);
      for (const sock of startupHoldClients) sock.destroy();
      await new Promise<void>((resolve) => startupHoldServer.close(() => resolve()));
    }

    // 5. 验证在 checkPrivateReady 或 recoverListenerIfNeeded 期间调用 stop()，不会继续发起新请求或重载内核配置
    let requestsAfterStop = 0;
    const stopGuardServer = http.createServer();
    stopGuardServer.on('connect', (_req, client) => {
      requestsAfterStop++;
      client.destroy();
    });
    const stopGuardPort = await listen(stopGuardServer, '127.0.0.1');
    try {
      const stopGuardStore = new ConfigStore();
      stopGuardStore.update({
        selectedClashNode: '直连测试节点',
        selectedClashProfileUid: 'local-prof',
        selectedClashProfileName: '本地测试订阅',
        dedicatedProxyPort: stopGuardPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const stopGuardEngine = new ProbeEngine(
        stopGuardStore,
        localGeo,
        new ClashMonitor(localSubDir),
        localService
      );
      const pendingProbe = stopGuardEngine.probeClaudeNodeNow(
        '验证停止后不再发起新网络请求',
        true
      );
      stopGuardEngine.stop();
      await pendingProbe;
      await delay(200);
      assert.equal(
        requestsAfterStop,
        0,
        'stop() 在就绪检查期间触发后不得继续发起新的代理请求'
      );
    } finally {
      await new Promise<void>((resolve) => stopGuardServer.close(() => resolve()));
    }

    // 5b. 验证端口恢复已进入监听归属核验时触发 stop()，不会继续向内核发送配置重载请求
    await mihomoRequest(postRaceLeaseInfo.endpoint, '/configs', 'PATCH', {
      'mixed-port': 0,
    });
    const dropAgainDeadline = Date.now() + 3000;
    while (
      (await isLocalPortListening(directPort)) &&
      Date.now() < dropAgainDeadline
    ) {
      await delay(50);
    }
    assert.equal(await isLocalPortListening(directPort), false);
    let holderConnections = 0;
    const transientHolder = net.createServer((sock) => {
      holderConnections++;
      sock.destroy();
    });
    transientHolder.listen(directPort, '127.0.0.1');
    await once(transientHolder, 'listening');
    try {
      const readyBeforeStop = readyEvents;
      const cancelRecoveryStore = new ConfigStore();
      cancelRecoveryStore.update({
        selectedClashNode: '直连测试节点',
        selectedClashProfileUid: 'local-prof',
        selectedClashProfileName: '本地测试订阅',
        dedicatedProxyPort: directPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const cancelRecoveryEngine = new ProbeEngine(
        cancelRecoveryStore,
        localGeo,
        new ClashMonitor(localSubDir),
        localService
      );
      const inflightRecoveryProbe = cancelRecoveryEngine.probeClaudeNodeNow(
        '验证恢复期间停止不重载内核配置',
        true
      );
      const enterRecoveryDeadline = Date.now() + 3000;
      while (holderConnections < 2 && Date.now() < enterRecoveryDeadline) {
        await delay(10);
      }
      assert.ok(
        holderConnections >= 2,
        '应在进入 recoverListenerIfNeeded 监听核验后再触发取消'
      );
      await new Promise<void>((resolve) => transientHolder.close(() => resolve()));
      cancelRecoveryEngine.stop();
      await inflightRecoveryProbe;
      await delay(250);
      const cfgAfterStop = await mihomoRequest<Record<string, unknown>>(
        postRaceLeaseInfo.endpoint,
        '/configs'
      );
      assert.equal(
        cfgAfterStop['mixed-port'],
        0,
        'stop() 触发后恢复流程不得继续向内核发出配置重载'
      );
      assert.equal(readyEvents, readyBeforeStop, 'stop() 取消恢复后不得触发 ready');
    } finally {
      if (transientHolder.listening) {
        await new Promise<void>((resolve) => transientHolder.close(() => resolve()));
      }
      localStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
      });
    }
    assert.equal(
      await localService.channels.claude.recoverListenerIfNeeded(),
      'rebound'
    );

    // 5c. 验证停止 Antigravity 探测时立即中断已建立的代理隧道连接，不残留 14 秒慢连接
    const agHeldSockets = new Set<Duplex>();
    let agHoldConnects = false;
    const agUpstreamRelay = http.createServer();
    agUpstreamRelay.on('clientError', (_err, sock) => sock.destroy());
    agUpstreamRelay.on('connect', (_req, client) => {
      if (!agHoldConnects) {
        client.destroy();
        return;
      }
      agHeldSockets.add(client);
      client.on('error', () => client.destroy());
      client.write('HTTP/1.1 200 Connection established\r\n\r\n');
      client.once('end', () => client.end());
      client.once('close', () => agHeldSockets.delete(client));
      client.resume();
    });
    const agUpstreamRelayPort = await listen(agUpstreamRelay, '127.0.0.1');
    const agTestPort = await freePort();
    try {
      const agVergeDir = path.join(localRoot, 'ag-verge');
      fs.mkdirSync(path.join(agVergeDir, 'profiles'), { recursive: true });
      fs.writeFileSync(
        path.join(agVergeDir, 'profiles.yaml'),
        yaml.dump({
          current: 'ag-prof',
          items: [
            {
              uid: 'ag-prof',
              name: 'AG测试订阅',
              type: 'local',
              file: 'ag-prof.yaml',
            },
          ],
        }),
        'utf8'
      );
      fs.writeFileSync(
        path.join(agVergeDir, 'profiles', 'ag-prof.yaml'),
        yaml.dump({
          hosts: Object.fromEntries(
            BUILTIN_TRACE_ENDPOINTS.map((ep) => [
              new URL(ep.url).hostname,
              '198.51.100.10',
            ])
          ),
          proxies: [
            {
              name: 'AG挂起测试节点',
              type: 'http',
              server: '127.0.0.1',
              port: agUpstreamRelayPort,
            },
          ],
        }),
        'utf8'
      );
      const agCat = new SubscriptionCatalog(agVergeDir);
      agCat.refresh();
      await localService.channels.antigravity.select(
        agCat.capture('ag-prof', 'AG挂起测试节点'),
        agTestPort
      );
      assert.equal(localService.channels.antigravity.getState().phase, 'ready');

      agHoldConnects = true;
      const agStopStore = new ConfigStore();
      agStopStore.update({
        selectedClashNode: null,
        antigravityClashNode: 'AG挂起测试节点',
        antigravityClashProfileUid: 'ag-prof',
        antigravityClashProfileName: 'AG测试订阅',
        antigravityDedicatedPort: agTestPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const agStopEngine = new ProbeEngine(
        agStopStore,
        localGeo,
        new ClashMonitor(agVergeDir),
        localService
      );
      const agProbeTask = agStopEngine.probeAntigravityNodeNow();
      const waitTunnelDeadline = Date.now() + 3000;
      while (agHeldSockets.size === 0 && Date.now() < waitTunnelDeadline) {
        await delay(25);
      }
      assert.ok(
        agHeldSockets.size >= 1,
        'Antigravity 探测应已通过真实私有内核建立代理隧道'
      );
      const stopStartedAt = Date.now();
      agStopEngine.stop();
      await agProbeTask;
      assert.ok(
        Date.now() - stopStartedAt < 2000,
        `stop() 后 Antigravity 探测必须立即返回而非等待超时 (实际 ${
          Date.now() - stopStartedAt
        }ms)`
      );
      const agCloseDeadline = Date.now() + 1000;
      while (agHeldSockets.size > 0 && Date.now() < agCloseDeadline) {
        await delay(20);
      }
      assert.equal(
        agHeldSockets.size,
        0,
        'stop() 后 Antigravity 探测已建立的代理连接必须全部关闭'
      );
    } finally {
      localStore.update({
        antigravityClashNode: null,
        antigravityClashProfileUid: null,
        antigravityClashProfileName: null,
      });
      for (const sock of agHeldSockets) sock.destroy();
      await new Promise<void>((resolve) => agUpstreamRelay.close(() => resolve()));
    }

    console.log(
      '通过：离线 GeoIP 缓存零重读、本地代理瞬断重试与取消、全重合零源阻断、端口归属 Fail-Closed 恢复与停机零新请求'
    );
  } finally {
    localEngine.stop();
    await localService.shutdown();
    untrackService(localService);
    for (const sock of relayClients) sock.destroy();
    for (const sock of forwardClients) sock.destroy();
    for (const sock of localExitClients) sock.destroy();
    await Promise.all([
      new Promise<void>((resolve) => relayServer.close(() => resolve())),
      new Promise<void>((resolve) => forwardRelay.close(() => resolve())),
      new Promise<void>((resolve) => localExitProxy.close(() => resolve())),
      new Promise<void>((resolve) => localTlsOrigin.close(() => resolve())),
      new Promise<void>((resolve) => originServer.close(() => resolve())),
    ]);
  }
}
