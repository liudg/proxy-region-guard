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
    console.log('通过：ProbeEngine 后台复核到期后自动终止真实进程树并触发提醒');
  } finally {
    runtime.claudeVerificationRecovery.clear();
    runtime.claudeVerificationRecovery.retryMs = CLAUDE_VERIFICATION_RETRY_MS;
    runtime.claudeVerificationRecovery.deadlineMs = CLAUDE_VERIFICATION_DEADLINE_MS;
    const idx = CLAUDE_DESKTOP_PROCESS_PATTERNS.indexOf(executableName);
    if (idx !== -1) CLAUDE_DESKTOP_PROCESS_PATTERNS.splice(idx, 1);
    markClaudeLaunchedByGuard(null);
    runtime.claudeRunning = false;
    runtime.claudeAuthorizedSession = false;
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
