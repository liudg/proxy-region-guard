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
} from '../electron/claudeVerificationRecovery';
import { ProbeEngine } from '../electron/probeEngine';
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

  let firstRequestFailedAt = 0;
  let requestFailures = 0;
  const failedExit = await runtime.probeOnceViaChannel(
    'http://127.0.0.1:1',
    '运行期出口检测',
    4500,
    '探测超时',
    (reason: string) => {
      firstRequestFailedAt ||= Date.now();
      requestFailures++;
      assert.match(reason, /https:\/\//);
    }
  );
  assert.equal(failedExit.result, null);
  assert.ok(requestFailures > 1);
  assert.ok(firstRequestFailedAt <= Date.now());

  const proxyServer = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`ip=${recoveredProbe.ip}\nloc=${recoveredProbe.countryCode}\n`);
  });
  proxyServer.on('connect', (_req, clientSocket) => {
    clientSocket.destroy();
  });
  await new Promise<void>((resolve) => proxyServer.listen(0, '127.0.0.1', resolve));
  const testPort = (proxyServer.address() as net.AddressInfo).port;

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
