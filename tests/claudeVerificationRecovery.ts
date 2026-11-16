import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as net from 'node:net';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  CLAUDE_DESKTOP_PROCESS_PATTERNS,
  markClaudeLaunchedByGuard,
} from '../electron/claudeController';
import {
  CLAUDE_VERIFICATION_DEADLINE_MS,
  CLAUDE_VERIFICATION_RETRY_MS,
  normalizeVerificationFailureSignature,
} from '../electron/claudeVerificationRecovery';
import { formatNetworkErrorMessage } from '../electron/netClient';
import { isLocalProxyRefusedError, ProbeEngine } from '../electron/probeEngine';
import { ConfigStore } from '../electron/configStore';
import { terminateProtectedProcesses } from '../electron/processGuard';
import { AlertPayload, ProbeResult } from '../src/shared/types';
import { getTargetServiceVerificationError } from '../src/shared/probeValidation';
import { COUNTRY_DEFAULT_WINDOWS_TZ } from '../src/shared/timezones';

export async function runClaudeVerificationRecoveryTests(
  directory: string,
  engine: ProbeEngine,
  store: ConfigStore,
  recoveredProbe: ProbeResult,
  failureProbe: ProbeResult
): Promise<void> {
  const runtime = engine as any;
  const failureReason = getTargetServiceVerificationError(failureProbe);
  assert.ok(failureReason);
  assert.match(failureReason, /claude\.ai\/cdn-cgi\/trace/);
  assert.match(failureReason, /ECONNREFUSED|连接超时/);
  assert.equal(getTargetServiceVerificationError(recoveredProbe), null);
  assert.ok(recoveredProbe.claudeTraceCheckedAt);

  assert.equal(isLocalProxyRefusedError('connect ECONNREFUSED 127.0.0.1:27897', 'http://127.0.0.1:27897'), true);
  assert.equal(isLocalProxyRefusedError('https://ipv4.icanhazip.com：connect ECONNREFUSED 127.0.0.1:27897', 'http://127.0.0.1:27897'), true);
  assert.equal(isLocalProxyRefusedError('connect ECONNREFUSED ::1:27897', 'http://localhost:27897'), true);
  assert.equal(isLocalProxyRefusedError('connect ECONNREFUSED [::1]:27897', 'http://[::1]:27897'), true);
  assert.equal(isLocalProxyRefusedError('connect ECONNREFUSED 127.0.0.1:80', 'http://127.0.0.1'), true);
  assert.equal(isLocalProxyRefusedError('connect ECONNREFUSED', 'http://127.0.0.1:27897'), true);
  assert.equal(isLocalProxyRefusedError('connect ECONNREFUSED 203.0.113.5:443', 'http://127.0.0.1:27897'), false);
  assert.equal(isLocalProxyRefusedError('connect ECONNREFUSED 203.0.113.5:27897', 'http://127.0.0.1:27897'), false);
  assert.equal(isLocalProxyRefusedError('https://example.com:27897/trace：connect ECONNREFUSED 203.0.113.5:443', 'http://127.0.0.1:27897'), false);
  assert.equal(isLocalProxyRefusedError('connect ECONNREFUSED 2606:4700:7890::1:443', 'http://127.0.0.1:7890'), false);
  assert.equal(isLocalProxyRefusedError('connect ECONNREFUSED 203.0.113.5:443', 'http://127.0.0.1'), false);
  assert.equal(isLocalProxyRefusedError('connect ECONNREFUSED 127.0.0.1:9999', 'http://127.0.0.1:27897'), false);

  const emptyMsgAgg = Object.assign(
    new AggregateError(
      [new Error('connect ECONNREFUSED ::1:27897'), new Error('connect ECONNREFUSED 127.0.0.1:27897')],
      ''
    ),
    { code: 'ECONNREFUSED' }
  );
  const formattedAgg = formatNetworkErrorMessage(emptyMsgAgg);
  assert.match(formattedAgg, /ECONNREFUSED 127\.0\.0\.1:27897/);
  assert.equal(isLocalProxyRefusedError(formattedAgg, 'http://localhost:27897'), true);

  let localRefusedCalls = 0;
  const failedLocalExit = await runtime.probeOnceViaChannel(
    'http://127.0.0.1:1',
    '运行期本地端口未监听短路检测',
    4500,
    '探测超时',
    (reason: string, meta: { localProxyRefused: boolean }) => {
      localRefusedCalls++;
      assert.equal(meta.localProxyRefused, true);
      assert.match(reason, /https:\/\//);
    }
  );
  assert.equal(failedLocalExit.result, null);
  assert.equal(failedLocalExit.localProxyRefused, true);
  assert.equal(localRefusedCalls, 1, '本地代理端口 ECONNREFUSED 应立即短路，不重复轮询其余远端 URL');

  const proxyServer = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    if (req.url?.endsWith('/plain-v6')) {
      res.end('2606:4700:4700:0000:0000:0000:0000:ABCD\n');
      return;
    }
    if (req.url?.endsWith('/plain-json-v6')) {
      res.end(JSON.stringify({ ip: '2606:4700:4700:0000:0000:0000:0000:BEEF' }));
      return;
    }
    res.end(`ip=${recoveredProbe.ip}\nloc=${recoveredProbe.countryCode}\n`);
  });
  proxyServer.on('connect', (_req, clientSocket) => {
    clientSocket.destroy();
  });
  await new Promise<void>((resolve) => proxyServer.listen(0, '127.0.0.1', resolve));
  const testPort = (proxyServer.address() as net.AddressInfo).port;

  let firstRequestFailedAt = 0;
  let requestFailures = 0;
  const failedExit = await runtime.probeOnceViaChannel(
    `http://127.0.0.1:${testPort}`,
    '运行期出口检测',
    4500,
    '探测超时',
    (reason: string, meta: { localProxyRefused: boolean }) => {
      firstRequestFailedAt ||= Date.now();
      requestFailures++;
      assert.equal(meta.localProxyRefused, false);
      assert.match(reason, /https:\/\//);
    }
  );
  assert.equal(failedExit.result, null);
  assert.equal(failedExit.localProxyRefused, false);
  assert.ok(requestFailures > 1, '本地代理端口正常监听但远端隧道异常时应依次尝试全部回退探测源');
  assert.ok(firstRequestFailedAt <= Date.now());

  const executableName = `guard-recovery-child-${process.pid}.exe`;
  const executable = path.join(directory, executableName);
  assert.ok(process.env.GUARD_TEST_NODE);
  fs.copyFileSync(process.env.GUARD_TEST_NODE, executable);
  const descendantFile = path.join(directory, 'recovery-descendant.json');
  const child = spawn(executable, [path.resolve('tests/fixtures/process-tree.cjs'), descendantFile], {
    windowsHide: true,
    stdio: 'ignore',
  });
  await once(child, 'spawn');
  const exited = once(child, 'exit');

  const alerts: AlertPayload[] = [];
  const recordAlert = (payload: AlertPayload) => alerts.push(payload);
  engine.on('trigger-alert', recordAlert);

  const previousConfig = store.get();
  const previousLocale = runtime.winLocale;
  const previousClashInfo = runtime.clashMonitor.info;
  CLAUDE_DESKTOP_PROCESS_PATTERNS.push(executableName);
  runtime.claudeVerificationRecovery.retryMs = 80;
  runtime.claudeVerificationRecovery.deadlineMs = 360;

  try {
    for (let attempt = 0; attempt < 50 && !fs.existsSync(descendantFile); attempt++) {
      await sleep(50);
    }
    assert.ok(fs.existsSync(descendantFile));

    store.update({
      selectedClashNode: '运行期测试节点',
      selectedClashProfileUid: 'test-uid',
      dedicatedProxyPort: testPort,
      customProbeUrl: `http://127.0.0.1:${testPort}/trace`,
      alertSoundEnabled: false,
    });
    markClaudeLaunchedByGuard(testPort);
    runtime.claudeRunning = true;
    runtime.claudeAuthorizedSession = true;
    runtime.winLocale = {
      regionCode: recoveredProbe.countryCode,
      regionName: recoveredProbe.countryName,
      timeZoneId: COUNTRY_DEFAULT_WINDOWS_TZ[recoveredProbe.countryCode] || 'UTC',
      timeZoneDisplayName: 'Test TZ',
    };
    runtime.clashMonitor.info = {
      ...runtime.clashMonitor.getRuntimeInfo(),
      connected: true,
      bindingVerificationError: null,
      dedicatedPortListening: true,
      boundNode: '运行期测试节点',
      boundProfileUid: 'test-uid',
      dedicatedPort: testPort,
    };

    runtime.claudeNodeProbe = {
      ...failureProbe,
      countryCode: recoveredProbe.countryCode,
      countryName: recoveredProbe.countryName,
    };
    runtime.claudeNodeProbeError = null;
    const logCount = engine.getSnapshot().logs.length;
    assert.equal(await runtime.enforceClaudeRunningSafety('运行期测试'), false);
    const firstFailure = engine.getSnapshot().claudeState.verificationFailure;
    assert.ok(firstFailure);
    assert.equal(await runtime.enforceClaudeRunningSafety('运行期测试'), false);
    assert.deepEqual(engine.getSnapshot().claudeState.verificationFailure, firstFailure);
    assert.equal(engine.getSnapshot().logs.length, logCount + 1);
    console.log('通过：真实出口请求首次失败立即报告，ProbeEngine 相同校验错误合并记录并保留首次复核期限');

    runtime.claudeNodeProbe = recoveredProbe;
    assert.equal(await runtime.enforceClaudeRunningSafety('Claude 运行期后台复核'), false);
    assert.equal(engine.getSnapshot().claudeState.verificationFailure, null);
    assert.equal(alerts.length, 0);
    assert.equal(child.exitCode, null);
    console.log('通过：真实 Claude 服务恢复后 ProbeEngine 自动取消复核和终止计时');

    const alertTriggered = once(engine, 'trigger-alert') as Promise<[AlertPayload]>;
    runtime.claudeNodeProbe = {
      ...failureProbe,
      countryCode: recoveredProbe.countryCode,
      countryName: recoveredProbe.countryName,
    };
    assert.equal(await runtime.enforceClaudeRunningSafety('运行期测试'), false);
    const activeFailure = engine.getSnapshot().claudeState.verificationFailure;
    assert.ok(activeFailure);

    const [alert] = await alertTriggered;
    await exited;
    assert.ok(Date.now() - activeFailure.startedAt >= 340);
    assert.equal(alerts.length, 1);
    assert.equal(alert.source, 'claude');
    assert.equal(alert.alertType, 'verification-unavailable');
    assert.equal(alert.expectedCode, recoveredProbe.countryCode);
    assert.equal(alert.actualCode, null);
    assert.match(alert.triggerReason, /持续 30 秒无法完成地区校验/);
    assert.match(alert.errorDetail || '', /claude\.ai\/cdn-cgi\/trace/);
    assert.ok(alert.killedProcesses?.some((item) => item.includes(executableName)));
    assert.equal(engine.getSnapshot().claudeState.verificationFailure, null);
    assert.equal(runtime.claudeAuthorizedSession, false);
    assert.equal(runtime.claudeSessionInitialIp, null);
    console.log('通过：ProbeEngine 后台复核到期后自动终止真实进程树并触发提醒');

    // -------------------------------------------------------------------------
    // 进阶验证：会话出口 IP 锁定（0 秒立即强杀、IPv4/IPv6 切换、运行中开关热切换、闪断后漂移恢复、外部启动建基线）
    // -------------------------------------------------------------------------
    const spawnClaudeTreeForCase = async (tag: string) => {
      const caseExeName = `guard-ip-lock-${process.pid}-${tag}.exe`;
      const caseExePath = path.join(directory, caseExeName);
      fs.copyFileSync(process.env.GUARD_TEST_NODE!, caseExePath);
      const caseDescFile = path.join(directory, `desc-${tag}.json`);
      const proc = spawn(caseExePath, [path.resolve('tests/fixtures/process-tree.cjs'), caseDescFile], {
        windowsHide: true,
        stdio: 'ignore',
      });
      await once(proc, 'spawn');
      const procExited = once(proc, 'exit');
      for (let attempt = 0; attempt < 50 && !fs.existsSync(caseDescFile); attempt++) {
        await sleep(50);
      }
      assert.ok(fs.existsSync(caseDescFile), `测试子进程树未就绪 (${tag})`);
      CLAUDE_DESKTOP_PROCESS_PATTERNS.push(caseExeName);
      return {
        exeName: caseExeName,
        proc,
        procExited,
        cleanup: async () => {
          const pIdx = CLAUDE_DESKTOP_PROCESS_PATTERNS.indexOf(caseExeName);
          if (pIdx !== -1) CLAUDE_DESKTOP_PROCESS_PATTERNS.splice(pIdx, 1);
          if (proc.exitCode === null && proc.signalCode === null) {
            await terminateProtectedProcesses([caseExeName]);
            await procExited;
          }
        },
      };
    };

    const initialTraceIp = recoveredProbe.claudeTraceIp || recoveredProbe.ip;
    const driftedTraceIp =
      initialTraceIp === '198.51.100.77' ? '198.51.100.88' : '198.51.100.77';

    // Case 1: 开启 claudeLockExitIp 时，同国出口 IP 漂移（以及双栈 IPv4->IPv6 切换）立即 0 秒强杀进程树并触发 ip-change 告警
    const case1 = await spawnClaudeTreeForCase('drift-kill');
    try {
      alerts.length = 0;
      store.update({ claudeLockExitIp: true, claudeExclusiveGuard: true });
      markClaudeLaunchedByGuard(testPort);
      runtime.claudeRunning = true;
      runtime.claudeAuthorizedSession = true;
      runtime.claudeSessionInitialIp = initialTraceIp;
      runtime.claudeExternalBaselinePending = false;
      runtime.claudeNodeProbe = {
        ...recoveredProbe,
        claudeTraceIp: initialTraceIp,
        regionMismatchDetail: null,
      };
      runtime.claudeNodeProbeError = null;

      assert.equal(engine.getSnapshot().claudeState.lockedSessionIp, initialTraceIp);
      assert.equal(await runtime.enforceClaudeRunningSafety('Claude 运行期心跳巡检'), false);
      assert.equal(case1.proc.exitCode, null);

      // 常规回显 IP (probe.ip) 变化但 claudeTraceIp 未变（同国 AI 分流）-> 绝不误杀
      runtime.claudeNodeProbe = {
        ...recoveredProbe,
        ip: '203.0.113.200',
        claudeTraceIp: initialTraceIp,
        regionMismatchDetail: null,
      };
      assert.equal(await runtime.enforceClaudeRunningSafety('Claude 运行期心跳巡检'), false);
      assert.equal(case1.proc.exitCode, null);

      // 双栈节点 IPv4 -> IPv6 切换判定核验
      runtime.claudeNodeProbe = {
        ...recoveredProbe,
        claudeTraceIp: '2606:4700:4700::1111',
        regionMismatchDetail: null,
      };
      const v6Check = runtime.evaluateClaudeSafety(true);
      assert.equal(v6Check.safe, false);
      assert.equal(v6Check.alertType, 'ip-change');
      assert.equal(v6Check.expectedIp, initialTraceIp);
      assert.equal(v6Check.actualIp, '2606:4700:4700::1111');

      // IPv6 大小写与零压缩等价表示不得误判为漂移
      runtime.claudeSessionInitialIp = '2606:4700:4700::abcd';
      runtime.claudeNodeProbe = {
        ...recoveredProbe,
        claudeTraceIp: '2606:4700:4700:0000:0000:0000:0000:ABCD',
        regionMismatchDetail: null,
      };
      const v6SameCheck = runtime.evaluateClaudeSafety(true);
      assert.equal(v6SameCheck.safe, true, '等价 IPv6 写法不应触发误杀');
      runtime.claudeSessionInitialIp = initialTraceIp;

      // 控制接口异常期 (bindingVerificationError 非空) 若实测已确认出口 IP 漂移，必须立即返回 ip-change 而非退化为 30s 静默宽限
      const savedClashInfo = runtime.clashMonitor.info;
      try {
        runtime.clashMonitor.info = {
          ...savedClashInfo,
          bindingVerificationError: 'Clash 控制接口响应超时',
        };
        runtime.claudeNodeProbe = {
          ...recoveredProbe,
          claudeTraceIp: driftedTraceIp,
          regionMismatchDetail: null,
        };
        const apiDownDriftCheck = runtime.evaluateClaudeSafety(true);
        assert.equal(apiDownDriftCheck.safe, false);
        assert.equal(
          apiDownDriftCheck.alertType,
          'ip-change',
          '控制接口故障期实测确认 IP 漂移仍须立即 0 秒熔断而非进入 30 秒宽限'
        );
        assert.equal(apiDownDriftCheck.expectedIp, initialTraceIp);
        assert.equal(apiDownDriftCheck.actualIp, driftedTraceIp);
      } finally {
        runtime.clashMonitor.info = savedClashInfo;
      }

      // 同国 IPv4 出口漂移 -> 0 秒立即强杀（不进入 30s 宽限期）
      runtime.claudeNodeProbe = {
        ...recoveredProbe,
        claudeTraceIp: driftedTraceIp,
        regionMismatchDetail: null,
      };
      const startedKillAt = Date.now();
      const killed = await runtime.enforceClaudeRunningSafety('Claude 运行期心跳巡检');
      await case1.procExited;
      assert.equal(killed, true);
      assert.ok(Date.now() - startedKillAt < 4000);
      assert.equal(engine.getSnapshot().claudeState.verificationFailure, null);
      assert.equal(engine.getSnapshot().claudeState.lockedSessionIp, null);
      assert.equal(runtime.claudeSessionInitialIp, null);
      assert.equal(alerts.length, 1);
      assert.equal(alerts[0].alertType, 'ip-change');
      assert.equal(alerts[0].source, 'claude');
      assert.equal(alerts[0].expectedIp, initialTraceIp);
      assert.equal(alerts[0].actualIp, driftedTraceIp);
      assert.equal(alerts[0].expectedCode, recoveredProbe.countryCode);
      assert.ok(alerts[0].killedProcesses?.some((item) => item.includes(case1.exeName)));
      console.log('通过：同国会话出口 IP 变更（含 IPv4/IPv6 双栈切换）立即 0 秒强杀进程树并携带前后对比 IP 告警，同国固定 AI 分流不误杀');
    } finally {
      await case1.cleanup();
    }

    // Case 2: 运行中关闭 claudeLockExitIp 允许动态住宅同国换 IP；运行中重新开启若已偏离初始基线则立即强杀
    const case2 = await spawnClaudeTreeForCase('toggle-lock');
    try {
      alerts.length = 0;
      store.update({ claudeLockExitIp: false, claudeExclusiveGuard: true });
      markClaudeLaunchedByGuard(testPort);
      runtime.claudeRunning = true;
      runtime.claudeAuthorizedSession = true;
      runtime.claudeSessionInitialIp = initialTraceIp;
      runtime.claudeExternalBaselinePending = false;
      runtime.claudeNodeProbe = {
        ...recoveredProbe,
        claudeTraceIp: driftedTraceIp,
        regionMismatchDetail: null,
      };
      runtime.claudeNodeProbeError = null;

      assert.equal(engine.getSnapshot().claudeState.lockedSessionIp, null);
      assert.equal(await runtime.enforceClaudeRunningSafety('Claude 运行期心跳巡检'), false);
      assert.equal(case2.proc.exitCode, null);
      assert.equal(alerts.length, 0);

      // 运行中热开启 claudeLockExitIp -> 立即对比会话初始 IP 并强杀已漂移实例
      await engine.updateConfig({ claudeLockExitIp: true });
      await case2.procExited;
      assert.equal(alerts.length, 1);
      assert.equal(alerts[0].alertType, 'ip-change');
      assert.equal(alerts[0].expectedIp, initialTraceIp);
      assert.equal(alerts[0].actualIp, driftedTraceIp);
      assert.ok(alerts[0].killedProcesses?.some((item) => item.includes(case2.exeName)));
      console.log('通过：关闭会话出口 IP 锁定时允许同国轮换 IP，重新开启时立即核验初始基线并强杀已漂移会话');
    } finally {
      await case2.cleanup();
    }

    // Case 3: 瞬态网络故障进入 30s 恢复窗口后，若恢复上线时出口 IP 已变更，不等 30s 立即执行 ip-change 强杀
    const case3 = await spawnClaudeTreeForCase('recover-drifted');
    try {
      alerts.length = 0;
      store.update({ claudeLockExitIp: true, claudeExclusiveGuard: true });
      markClaudeLaunchedByGuard(testPort);
      runtime.claudeRunning = true;
      runtime.claudeAuthorizedSession = true;
      runtime.claudeSessionInitialIp = initialTraceIp;
      runtime.claudeExternalBaselinePending = false;
      runtime.claudeNodeProbe = {
        ...failureProbe,
        countryCode: recoveredProbe.countryCode,
        countryName: recoveredProbe.countryName,
      };
      runtime.claudeNodeProbeError = null;

      assert.equal(await runtime.enforceClaudeRunningSafety('Claude 运行期心跳巡检'), false);
      assert.ok(engine.getSnapshot().claudeState.verificationFailure);
      assert.equal(case3.proc.exitCode, null);

      // 网络恢复但出口 IP 已漂移 -> 立即强杀并清理恢复计时器
      runtime.claudeNodeProbe = {
        ...recoveredProbe,
        claudeTraceIp: driftedTraceIp,
        regionMismatchDetail: null,
      };
      const killedOnRecover = await runtime.enforceClaudeRunningSafety('Claude 运行期后台复核');
      await case3.procExited;
      assert.equal(killedOnRecover, true);
      assert.equal(engine.getSnapshot().claudeState.verificationFailure, null);
      assert.equal(alerts.length, 1);
      assert.equal(alerts[0].alertType, 'ip-change');
      assert.equal(alerts[0].expectedIp, initialTraceIp);
      assert.equal(alerts[0].actualIp, driftedTraceIp);
      console.log('通过：瞬态请求超时恢复后若出口 IP 已发生变更，立即熔断强杀而非误判静默恢复');
    } finally {
      await case3.cleanup();
    }

    // Case 4: 关闭唯一入口拦截 (claudeExclusiveGuard=false) 时外部运行 Claude 不复用启动前旧缓存，锁定新探测 IP 并在漂移时强杀
    const case4 = await spawnClaudeTreeForCase('external-baseline');
    try {
      alerts.length = 0;
      store.update({ claudeLockExitIp: true, claudeExclusiveGuard: false });
      markClaudeLaunchedByGuard(null);
      runtime.claudeRunning = true;
      runtime.claudeAuthorizedSession = false;
      runtime.claudeSessionInitialIp = null;
      runtime.claudeExternalBaselinePending = true;
      // 模拟启动前遗留的旧节点缓存 IP (198.51.100.10)
      runtime.claudeNodeProbe = {
        ...recoveredProbe,
        claudeTraceIp: '198.51.100.10',
        regionMismatchDetail: null,
      };
      runtime.claudeNodeProbeError = null;

      const pendingCheck = runtime.evaluateClaudeSafety(false);
      assert.equal(pendingCheck.safe, false);
      assert.equal(pendingCheck.alertType, 'verification-unavailable');
      assert.equal(runtime.claudeSessionInitialIp, null, '不得将启动前旧缓存误锁为当前外部会话基线');

      // 模拟实时重测返回真实当前出口 initialTraceIp 并完成基线锁定
      runtime.claudeSessionInitialIp = initialTraceIp;
      runtime.claudeExternalBaselinePending = false;
      runtime.claudeNodeProbe = {
        ...recoveredProbe,
        claudeTraceIp: initialTraceIp,
        regionMismatchDetail: null,
      };
      assert.equal(await runtime.enforceClaudeRunningSafety('检测到外部运行 Claude，建立会话出口 IP 基线'), false);
      assert.equal(engine.getSnapshot().claudeState.lockedSessionIp, initialTraceIp);
      assert.equal(case4.proc.exitCode, null);

      // 外部会话后续漂移至 driftedTraceIp -> 立即强杀
      runtime.claudeNodeProbe = {
        ...recoveredProbe,
        claudeTraceIp: driftedTraceIp,
        regionMismatchDetail: null,
      };
      assert.equal(await runtime.enforceClaudeRunningSafety('Claude 运行期心跳巡检'), true);
      await case4.procExited;
      assert.equal(alerts.length, 1);
      assert.equal(alerts[0].alertType, 'ip-change');
      assert.equal(alerts[0].expectedIp, initialTraceIp);
      assert.equal(alerts[0].actualIp, driftedTraceIp);
      console.log('通过：关闭唯一入口拦截时外部 Claude 拒绝复用旧缓存，建立实时基线后漂移同样立即强杀');
    } finally {
      await case4.cleanup();
    }

    // Case 5: 强杀首次受阻 (claudeRunning 仍为 true) 时保留原始 claudeSessionInitialIp，绝不将漂移 IP 误锁为新基线，后续重试完成强杀
    const case5 = await spawnClaudeTreeForCase('kill-retry');
    const origKillSafely = runtime.executeProcessKillSafely.bind(runtime);
    try {
      alerts.length = 0;
      store.update({ claudeLockExitIp: true, claudeExclusiveGuard: false });
      markClaudeLaunchedByGuard(null);
      runtime.claudeRunning = true;
      runtime.claudeAuthorizedSession = false;
      runtime.claudeSessionInitialIp = initialTraceIp;
      runtime.claudeExternalBaselinePending = false;
      runtime.claudeExternalBaselineMinSeq = 0;
      runtime.claudeNodeProbe = {
        ...recoveredProbe,
        claudeTraceIp: driftedTraceIp,
        regionMismatchDetail: null,
      };
      runtime.claudeNodeProbeError = null;

      let failOnce = true;
      runtime.executeProcessKillSafely = async (patterns: string[]) => {
        if (failOnce) {
          failOnce = false;
          runtime.claudeRunning = true;
          return {
            attemptedPids: [case5.proc.pid!],
            killedCount: 0,
            killedSummary: [],
            failedPids: [case5.proc.pid!],
            errorDetail: '模拟首次进程终止受阻',
          };
        }
        return origKillSafely(patterns);
      };

      assert.equal(await runtime.enforceClaudeRunningSafety('Claude 运行期心跳巡检'), true);
      assert.equal(case5.proc.exitCode, null, '首次模拟受阻时子进程仍存活');
      assert.equal(alerts.length, 1);
      assert.equal(alerts[0].alertType, 'ip-change');
      assert.equal(alerts[0].killError, '模拟首次进程终止受阻');
      assert.equal(
        runtime.claudeSessionInitialIp,
        initialTraceIp,
        '终止受阻进程未退出时不得清空原始锁定 IP 基线'
      );

      const retryEval = runtime.evaluateClaudeSafety(false);
      assert.equal(retryEval.safe, false, '后续巡检不得把漂移 IP 采纳为新基线');
      assert.equal(retryEval.alertType, 'ip-change');
      assert.equal(retryEval.expectedIp, initialTraceIp);
      assert.equal(retryEval.actualIp, driftedTraceIp);

      assert.equal(await runtime.enforceClaudeRunningSafety('Claude 运行期实时监控'), true);
      await case5.procExited;
      assert.equal(runtime.claudeSessionInitialIp, null, '进程确认退出后清空锁定 IP 基线');
      assert.equal(alerts.length, 2);
      assert.equal(alerts[1].alertType, 'ip-change');
      assert.ok(alerts[1].killedProcesses?.some((item) => item.includes(case5.exeName)));
      console.log('通过：强杀受阻时保留原始锁定 IP 基线不发生漂移覆盖，后续重试成功终止进程树');
    } finally {
      runtime.executeProcessKillSafely = origKillSafely;
      await case5.cleanup();
    }

    // Case 6: 外部启动 Claude 时若恰有启动前发起的在途探测，必须等待新序号探测完成才锁定会话基线
    const origVerifyTarget = runtime.verifyTargetServiceRegion.bind(runtime);
    try {
      alerts.length = 0;
      store.update({ claudeLockExitIp: true, claudeExclusiveGuard: false });
      markClaudeLaunchedByGuard(null);
      runtime.claudeRunning = false;
      runtime.claudeAuthorizedSession = false;
      runtime.claudeSessionInitialIp = null;
      runtime.claudeExternalBaselinePending = false;
      runtime.claudeExternalBaselineMinSeq = 0;

      let callCount = 0;
      let notifyFirstEntered!: () => void;
      const firstEntered = new Promise<void>((resolve) => {
        notifyFirstEntered = resolve;
      });
      let releaseFirst!: () => void;
      const firstGate = new Promise<void>((resolve) => {
        releaseFirst = resolve;
      });
      let snapshotWhenSecondStarts: { initialIp: string | null; pending: boolean } | null = null;

      runtime.verifyTargetServiceRegion = async (
        _proxyUrl: string | null,
        probeObj: ProbeResult,
        targetApp: 'claude' | 'antigravity'
      ) => {
        if (targetApp !== 'claude') return;
        callCount++;
        if (callCount === 1) {
          notifyFirstEntered();
          await firstGate;
          probeObj.claudeTraceLoc = recoveredProbe.countryCode;
          probeObj.claudeTraceIp = '198.51.100.10';
          probeObj.claudeTraceCheckedAt = Date.now();
          probeObj.regionMismatchDetail = null;
        } else {
          snapshotWhenSecondStarts = {
            initialIp: runtime.claudeSessionInitialIp,
            pending: runtime.claudeExternalBaselinePending,
          };
          probeObj.claudeTraceLoc = recoveredProbe.countryCode;
          probeObj.claudeTraceIp = initialTraceIp;
          probeObj.claudeTraceCheckedAt = Date.now();
          probeObj.regionMismatchDetail = null;
        }
      };

      const inFlightPreLaunch = engine.probeClaudeNodeNow('启动前在途检测', true);
      await firstEntered;

      // 此时旧探测在途，模拟外部 Claude 先于 watcher 被其他路径感知 (claudeExternalBaselinePending 尚未手动置位)
      runtime.claudeRunning = true;
      runtime.claudeNodeProbe = {
        ...recoveredProbe,
        claudeTraceIp: '198.51.100.10',
        regionMismatchDetail: null,
      };
      assert.equal(
        runtime.evaluateClaudeSafety(false).alertType,
        'verification-unavailable',
        '外部会话尚未建立基线时即使 pending 未置位也不得直接信任启动前旧缓存'
      );
      assert.equal(await runtime.enforceClaudeRunningSafety('外部进程先行被感知'), false);
      assert.equal(runtime.claudeExternalBaselinePending, true);

      releaseFirst();
      await inFlightPreLaunch;

      assert.equal(callCount, 2);
      assert.deepEqual(
        snapshotWhenSecondStarts,
        { initialIp: null, pending: true },
        '启动前在途探测完成时不得抢先写入旧 IP 或解除 pending'
      );
      assert.equal(runtime.claudeSessionInitialIp, initialTraceIp);
      assert.equal(runtime.claudeExternalBaselinePending, false);
      assert.equal(runtime.claudeExternalBaselineMinSeq, 0);

      // plain-ip 探测源返回未压缩大写 IPv6（纯文本或 JSON）时同样必须规范化，避免与 claudeTraceIp 比较时误报 AI 分流
      store.update({ customProbeUrl: `http://127.0.0.1:${testPort}/plain-v6` });
      const plainV6Probe = await runtime.probeOnceViaChannel(
        `http://127.0.0.1:${testPort}`,
        'plain-ip IPv6 规范化检测',
        4500
      );
      assert.equal(plainV6Probe.result?.ip, '2606:4700:4700::abcd');
      store.update({ customProbeUrl: `http://127.0.0.1:${testPort}/plain-json-v6` });
      const jsonV6Probe = await runtime.probeOnceViaChannel(
        `http://127.0.0.1:${testPort}`,
        'plain-ip JSON IPv6 规范化检测',
        4500
      );
      assert.equal(jsonV6Probe.result?.ip, '2606:4700:4700::beef');
      store.update({ customProbeUrl: `http://127.0.0.1:${testPort}/trace` });
      console.log('通过：外部会话基线严格等待启动后新发起的探测轮次，忽略启动前在途旧探测结果且 plain-ip IPv6 统一规范化');

      // Case 7: 本地专属端口瞬态 ECONNREFUSED 自动重绑静默自愈（0 误报日志）与多探测源失败去重合并
      const sig1 = normalizeVerificationFailureSignature(
        'Claude 专属节点 [iNetS / JP10] (127.0.0.1:27897)：https://ipv4.icanhazip.com/cdn-cgi/trace：socket hang up'
      );
      const sig2 = normalizeVerificationFailureSignature(
        'Claude 专属节点 [iNetS / JP10] (127.0.0.1:27897)：https://cp.cloudflare.com/cdn-cgi/trace：socket hang up'
      );
      const sigWrapped = normalizeVerificationFailureSignature(
        'Claude 专属节点出口不可达 (Claude 专属节点 [iNetS / JP10] (127.0.0.1:27897)：https://icanhazip.com：socket hang up)'
      );
      const sigCustomPort = normalizeVerificationFailureSignature(
        'Claude 专属节点 [iNetS / JP10] (127.0.0.1:27897)：https://probe.example.com:8443/trace：socket hang up'
      );
      assert.equal(sig1, sig2);
      assert.equal(sig1, sigWrapped);
      assert.equal(sig1, sigCustomPort, '带端口探测 URL 归一化后应与标准探测 URL 合并签名');

      runtime.claudeVerificationRecovery.clear();
      const dedupLogsBefore = engine.getSnapshot().logs.length;
      runtime.recordClaudeVerificationFailure(
        'Claude 专属节点 [iNetS / JP10] (127.0.0.1:27897)：https://probe.example.com:8443/trace：HTTP 状态码 502'
      );
      runtime.recordClaudeVerificationFailure(
        'Claude 专属节点 [iNetS / JP10] (127.0.0.1:27897)：https://ipv4.icanhazip.com/cdn-cgi/trace：socket hang up'
      );
      // 再次交替回 502 与 socket hang up，Set 去重不得重复刷屏
      runtime.recordClaudeVerificationFailure(
        'Claude 专属节点 [iNetS / JP10] (127.0.0.1:27897)：https://cp.cloudflare.com/cdn-cgi/trace：HTTP 状态码 502'
      );
      runtime.recordClaudeVerificationFailure(
        'Claude 专属节点出口不可达 (Claude 专属节点 [iNetS / JP10] (127.0.0.1:27897)：https://icanhazip.com：socket hang up)'
      );
      assert.equal(
        engine.getSnapshot().logs.length,
        dedupLogsBefore + 2,
        '同一复核窗口内 A-B-A 交替错误与多 URL 回退对每种错误签名至多记录 1 条警告日志'
      );
      runtime.claudeVerificationRecovery.clear();

      // 模拟运行期专属端口在 firstPass 瞬间因内核重载闪断 (ECONNREFUSED)，随后自动恢复监听并静默通过，不刷任何警告日志
      const rebindServer = http.createServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`ip=${recoveredProbe.ip}\nloc=${recoveredProbe.countryCode}\n`);
      });
      await new Promise<void>((resolve) => rebindServer.listen(0, '127.0.0.1', resolve));
      const rebindPort = (rebindServer.address() as net.AddressInfo).port;
      const origConfigureDedicated = runtime.clashMonitor.configureDedicatedNode.bind(
        runtime.clashMonitor
      );
      const origProbeOnce = runtime.probeOnceViaChannel.bind(runtime);
      try {
        store.update({
          selectedClashNode: '运行期测试节点',
          selectedClashProfileUid: 'test-uid',
          dedicatedProxyPort: rebindPort,
          customProbeUrl: `http://127.0.0.1:${rebindPort}/trace`,
          claudeLockExitIp: true,
          claudeExclusiveGuard: true,
        });
        markClaudeLaunchedByGuard(rebindPort);
        runtime.claudeRunning = true;
        runtime.claudeAuthorizedSession = true;
        runtime.claudeSessionInitialIp = initialTraceIp;
        runtime.claudeExternalBaselinePending = false;
        runtime.clashMonitor.info = {
          ...runtime.clashMonitor.getRuntimeInfo(),
          connected: true,
          bindingVerificationError: null,
          dedicatedPortListening: true,
          boundNode: '运行期测试节点',
          boundProfileUid: 'test-uid',
          dedicatedPort: rebindPort,
        };
        runtime.verifyTargetServiceRegion = async (
          _pUrl: string | null,
          probeObj: ProbeResult,
          targetApp: 'claude' | 'antigravity'
        ) => {
          if (targetApp !== 'claude') return;
          probeObj.claudeTraceLoc = recoveredProbe.countryCode;
          probeObj.claudeTraceIp = initialTraceIp;
          probeObj.claudeTraceCheckedAt = Date.now();
          probeObj.regionMismatchDetail = null;
        };

        // 场景 A: 端口在巡检前已被 Clash 重载清空（dedicatedPortListening 仍滞后为 true），configureDedicatedNode 自动重绑恢复
        await new Promise<void>((resolve) => rebindServer.close(() => resolve()));
        let configureCalled = 0;
        runtime.clashMonitor.configureDedicatedNode = async () => {
          configureCalled++;
          await new Promise<void>((resolve) => rebindServer.listen(rebindPort, '127.0.0.1', resolve));
          return {
            ok: true,
            listening: true,
            rebound: true,
            profileUid: 'test-uid',
            profileName: '测试订阅',
          };
        };

        const logsBeforePreHeal = engine.getSnapshot().logs.filter((l) =>
          l.message.includes('地区校验暂时不可用')
        ).length;
        const preHealSnap = await engine.probeClaudeNodeNow('Claude 运行期心跳巡检');
        const logsAfterPreHeal = preHealSnap.logs.filter((l) =>
          l.message.includes('地区校验暂时不可用')
        ).length;
        assert.equal(configureCalled, 1);
        assert.equal(logsAfterPreHeal, logsBeforePreHeal, '前置端口探活自动重绑成功不应产生任何地区校验不可用警告');
        assert.equal(preHealSnap.claudeState.verificationFailure, null);
        assert.ok(preHealSnap.claudeState.nodeProbe);

        // 场景 B: 前置探活通过后，firstPass 发起瞬间撞上对端重载导致 ECONNREFUSED，且重绑在 firstPass 返回前已完成（无 reboundBefore 事件）
        let simulateFirstPassRefusedOnce = true;
        runtime.probeOnceViaChannel = async (
          pUrl: string | null,
          via: string,
          tMs: number,
          defErr?: string,
          onFail?: (r: string, meta: { localProxyRefused: boolean }) => void
        ) => {
          if (simulateFirstPassRefusedOnce) {
            simulateFirstPassRefusedOnce = false;
            const err = `https://ipv4.icanhazip.com：connect ECONNREFUSED 127.0.0.1:${rebindPort}`;
            onFail?.(err, { localProxyRefused: true });
            return { result: null, errMsg: err, localProxyRefused: true };
          }
          return origProbeOnce(pUrl, via, tMs, defErr, onFail);
        };

        const logsBeforeMidHeal = engine.getSnapshot().logs.filter((l) =>
          l.message.includes('地区校验暂时不可用')
        ).length;
        const midHealSnap = await engine.probeClaudeNodeNow('Claude 运行期心跳巡检');
        const logsAfterMidHeal = midHealSnap.logs.filter((l) =>
          l.message.includes('地区校验暂时不可用')
        ).length;
        assert.equal(simulateFirstPassRefusedOnce, false);
        assert.equal(logsAfterMidHeal, logsBeforeMidHeal, 'firstPass 瞬态本地 ECONNREFUSED 自动重试恢复不应刷出警告日志');
        assert.equal(midHealSnap.claudeState.verificationFailure, null);
        assert.ok(midHealSnap.claudeState.nodeProbe);

        // 场景 C: 二阶段 verifyTargetServiceRegion 瞬态本地 ECONNREFUSED 自动重试恢复（0 误报）
        let phase2FailOnce = true;
        runtime.verifyTargetServiceRegion = async (
          _pUrl: string | null,
          probeObj: ProbeResult,
          targetApp: 'claude' | 'antigravity'
        ) => {
          if (targetApp !== 'claude') return;
          if (phase2FailOnce) {
            phase2FailOnce = false;
            probeObj.claudeTraceLoc = undefined;
            probeObj.claudeTraceIp = undefined;
            probeObj.claudeTraceError = `https://claude.ai/cdn-cgi/trace：connect ECONNREFUSED 127.0.0.1:${rebindPort}`;
            return;
          }
          probeObj.claudeTraceLoc = recoveredProbe.countryCode;
          probeObj.claudeTraceIp = initialTraceIp;
          probeObj.claudeTraceCheckedAt = Date.now();
          probeObj.claudeTraceError = undefined;
          probeObj.regionMismatchDetail = null;
        };
        const logsBeforePhase2Heal = engine.getSnapshot().logs.filter((l) =>
          l.message.includes('地区校验暂时不可用')
        ).length;
        const phase2HealSnap = await engine.probeClaudeNodeNow('Claude 运行期心跳巡检');
        const logsAfterPhase2Heal = phase2HealSnap.logs.filter((l) =>
          l.message.includes('地区校验暂时不可用')
        ).length;
        assert.equal(phase2FailOnce, false);
        assert.equal(logsAfterPhase2Heal, logsBeforePhase2Heal, '二阶段瞬态本地 ECONNREFUSED 重试恢复不应刷警告日志');
        assert.equal(phase2HealSnap.claudeState.verificationFailure, null);
        assert.equal(getTargetServiceVerificationError(phase2HealSnap.claudeState.nodeProbe), null);

        // 场景 D: 双通道同时绑定且空闲时，wasAliveInKernel=true 的顺带重载事件绝不跨通道拉起新探测（防断网无限活锁）
        let unwantedAgProbes = 0;
        const origProbeAg = engine.probeAntigravityNodeNow.bind(engine);
        (engine as any).probeAntigravityNodeNow = async () => {
          unwantedAgProbes++;
          return engine.getSnapshot();
        };
        try {
          store.update({
            antigravityClashNode: 'AG-Test-Node',
            antigravityClashProfileUid: 'test-uid',
            antigravityDedicatedPort: rebindPort + 1 > 65530 ? rebindPort - 1 : rebindPort + 1,
          });
          runtime.antigravityNodeProbe = null;
          runtime.antigravityNodeProbeError = '模拟断网探测失败';
          runtime.clashMonitor.info = {
            ...runtime.clashMonitor.getRuntimeInfo(),
            antigravityPortListening: true,
          };
          runtime.clashMonitor.emit('antigravity-listener-rebound', { wasAliveInKernel: true });
          await sleep(320);
          assert.equal(unwantedAgProbes, 0, 'wasAliveInKernel=true 的对端重载不得触发跨通道重测活锁');
        } finally {
          (engine as any).probeAntigravityNodeNow = origProbeAg;
          store.update({ antigravityClashNode: null, antigravityClashProfileUid: null });
        }

        // 场景 E: 已实测确认 IP 漂移时即使 claudePendingProbe 非空也必须立即 break 0 秒强杀，且在途 skipSafety=true 遇心跳自动升级为安全强制
        const driftPendingTree = await spawnClaudeTreeForCase('pending-drift-kill');
        try {
          alerts.length = 0;
          runtime.claudeVerificationRecovery.clear();
          markClaudeLaunchedByGuard(rebindPort);
          runtime.claudeRunning = true;
          runtime.claudeAuthorizedSession = true;
          runtime.claudeSessionInitialIp = initialTraceIp;
          runtime.claudeExternalBaselinePending = false;

          let notifyEnteredGate!: () => void;
          const enteredGate = new Promise<void>((r) => {
            notifyEnteredGate = r;
          });
          let releaseGate!: () => void;
          const gate = new Promise<void>((r) => {
            releaseGate = r;
          });
          let traceCallNum = 0;
          runtime.verifyTargetServiceRegion = async (
            _pUrl: string | null,
            probeObj: ProbeResult,
            targetApp: 'claude' | 'antigravity'
          ) => {
            if (targetApp !== 'claude') return;
            traceCallNum++;
            if (traceCallNum === 1) {
              notifyEnteredGate();
              await gate;
              probeObj.claudeTraceLoc = recoveredProbe.countryCode;
              probeObj.claudeTraceIp = driftedTraceIp;
              probeObj.claudeTraceCheckedAt = Date.now();
              probeObj.regionMismatchDetail = null;
            } else {
              // 若错误进入第 2 轮 continue，将覆盖回原 IP 造成漏杀！
              probeObj.claudeTraceLoc = recoveredProbe.countryCode;
              probeObj.claudeTraceIp = initialTraceIp;
              probeObj.claudeTraceCheckedAt = Date.now();
              probeObj.regionMismatchDetail = null;
            }
          };

          // 以 skipSafetyEnforcement=true 启动在途探测，随后收到心跳升级安全强制并排入一个手动重测请求
          const inFlightSkip = engine.probeClaudeNodeNow('启动前遗留在途探测', true);
          await enteredGate;
          void engine.probeClaudeNodeNow('Claude 运行期心跳巡检', false);
          void engine.probeClaudeNodeNow('排队中的手动重测', false);
          assert.equal(runtime.claudeActiveProbeSkipSafety, false, '运行期心跳合并时必须立即解除在途 skipSafety');
          assert.ok(runtime.claudePendingProbe, '应存在排队中的 claudePendingProbe');

          releaseGate();
          await inFlightSkip;
          await driftPendingTree.procExited;
          assert.equal(traceCallNum, 1, '实测确认 IP 漂移后必须立即中断循环强杀，禁止执行 pending 第 2 轮覆盖结果');
          assert.equal(alerts.length, 1);
          assert.equal(alerts[0].alertType, 'ip-change');
          assert.equal(alerts[0].actualIp, driftedTraceIp);
        } finally {
          await driftPendingTree.cleanup();
        }

        // 场景 F (反向安全红线): 持续性本地端口 ECONNREFUSED（含高频 rebound 事件干扰）绝不无限自旋，首轮即启动复核并在到期后强杀进程树
        const persistentRefusedTree = await spawnClaudeTreeForCase('persistent-refused-kill');
        try {
          alerts.length = 0;
          runtime.claudeVerificationRecovery.clear();
          markClaudeLaunchedByGuard(rebindPort);
          runtime.claudeRunning = true;
          runtime.claudeAuthorizedSession = true;
          runtime.claudeSessionInitialIp = initialTraceIp;
          runtime.claudeExternalBaselinePending = false;

          runtime.probeOnceViaChannel = async (
            _pUrl: string | null,
            _via: string,
            _tMs: number,
            _defErr?: string,
            onFail?: (r: string, meta: { localProxyRefused: boolean }) => void
          ) => {
            // 每次探测均模拟外部高频重载事件置位 claudeReboundDuringProbe 且本地端口持续拒绝连接
            runtime.clashMonitor.emit('claude-listener-rebound', { wasAliveInKernel: false });
            const err = `https://ipv4.icanhazip.com：connect ECONNREFUSED 127.0.0.1:${rebindPort}`;
            onFail?.(err, { localProxyRefused: true });
            return { result: null, errMsg: err, localProxyRefused: true };
          };

          const persistentAlertPromise = once(engine, 'trigger-alert') as Promise<[AlertPayload]>;
          const failSnap = await engine.probeClaudeNodeNow('Claude 运行期心跳巡检');
          // 无论是否已超极短测试 deadlineMs (360ms)，首轮 probeClaudeNodeNow 必在有限步内退出（不死循环），且触发复核或到期强杀
          const [persistentAlert] = await persistentAlertPromise;
          await persistentRefusedTree.procExited;
          assert.ok(
            failSnap.claudeState.verificationFailure !== null || alerts.length >= 1,
            '持续本地 ECONNREFUSED 首轮即须进入后台复核或已完成到期强杀'
          );
          assert.equal(persistentAlert.source, 'claude');
          assert.equal(persistentAlert.alertType, 'verification-unavailable');
          assert.match(persistentAlert.errorDetail || '', /ECONNREFUSED/);
          assert.ok(
            persistentAlert.killedProcesses?.some((item) =>
              item.includes(persistentRefusedTree.exeName)
            )
          );
        } finally {
          await persistentRefusedTree.cleanup();
        }

        console.log('通过：本地专属端口瞬态 ECONNREFUSED 自愈、二阶段恢复、防跨通道活锁、IP 漂移防覆盖及持续故障强杀全链路验证通过');
      } finally {
        runtime.clashMonitor.configureDedicatedNode = origConfigureDedicated;
        runtime.probeOnceViaChannel = origProbeOnce;
        await new Promise<void>((resolve) => {
          if (rebindServer.listening) rebindServer.close(() => resolve());
          else resolve();
        });
      }
    } finally {
      runtime.verifyTargetServiceRegion = origVerifyTarget;
      runtime.claudeRunning = false;
      runtime.claudeSessionInitialIp = null;
      runtime.claudeExternalBaselinePending = false;
      runtime.claudeExternalBaselineMinSeq = 0;
    }
  } finally {
    runtime.claudeVerificationRecovery.clear();
    runtime.claudeVerificationRecovery.retryMs = CLAUDE_VERIFICATION_RETRY_MS;
    runtime.claudeVerificationRecovery.deadlineMs = CLAUDE_VERIFICATION_DEADLINE_MS;
    const idx = CLAUDE_DESKTOP_PROCESS_PATTERNS.indexOf(executableName);
    if (idx !== -1) CLAUDE_DESKTOP_PROCESS_PATTERNS.splice(idx, 1);
    markClaudeLaunchedByGuard(null);
    runtime.claudeRunning = false;
    runtime.claudeAuthorizedSession = false;
    runtime.claudeSessionInitialIp = null;
    runtime.claudeExternalBaselinePending = false;
    runtime.claudeExternalBaselineMinSeq = 0;
    runtime.claudeNodeProbe = null;
    runtime.claudeNodeProbeError = null;
    runtime.winLocale = previousLocale;
    runtime.clashMonitor.info = previousClashInfo;
    engine.off('trigger-alert', recordAlert);
    store.update(previousConfig);
    await new Promise<void>((resolve) => proxyServer.close(() => resolve()));
    if (child.exitCode === null && child.signalCode === null) {
      await terminateProtectedProcesses([executableName]);
      await exited;
    }
  }
}
