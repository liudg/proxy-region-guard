import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { BrowserWindow, ipcMain } from 'electron';
import { setTimeout as sleep } from 'node:timers/promises';
import { ClaudeVerificationRecovery } from '../electron/claudeVerificationRecovery';
import { ProbeEngine } from '../electron/probeEngine';
import { ConfigStore } from '../electron/configStore';
import { requestTextViaProxy } from '../electron/netClient';
import { assertProcessesStopped, terminateProtectedProcesses } from '../electron/processGuard';
import { AlertPayload, ProbeResult } from '../src/shared/types';
import { getTargetServiceVerificationError } from '../src/shared/probeValidation';

export async function runClaudeVerificationRecoveryTests(
  directory: string,
  engine: ProbeEngine,
  store: ConfigStore,
  proxyUrl: string,
  probe: ProbeResult
): Promise<void> {
  const runtime = engine as any;
  const failureProbe = { ...probe };
  await runtime.verifyTargetServiceRegion('http://127.0.0.1:1', failureProbe, 'claude', true);
  const failureReason = getTargetServiceVerificationError(failureProbe);
  assert.ok(failureReason);
  assert.match(failureReason, /claude\.ai\/cdn-cgi\/trace/);
  assert.match(failureReason, /ECONNREFUSED|连接超时/);
  let firstRequestFailedAt = 0;
  let requestFailures = 0;
  const failedExit = await runtime.probeOnceViaChannel(
    'http://127.0.0.1:1', '运行期出口检测', 4500, '探测超时', (reason: string) => {
      firstRequestFailedAt ||= Date.now();
      requestFailures++;
      assert.match(reason, /https:\/\//);
    }
  );
  assert.equal(failedExit.result, null);
  assert.ok(requestFailures > 1);
  assert.ok(firstRequestFailedAt < Date.now());
  const logCount = engine.getSnapshot().logs.length;
  runtime.recordClaudeVerificationFailure(failureReason);
  const firstFailure = engine.getSnapshot().claudeState.verificationFailure;
  runtime.recordClaudeVerificationFailure(failureReason);
  assert.deepEqual(engine.getSnapshot().claudeState.verificationFailure, firstFailure);
  assert.equal(engine.getSnapshot().logs.length, logCount + 1);
  runtime.claudeVerificationRecovery.clear();
  console.log('通过：真实出口请求首次失败立即报告，运行期相同错误合并记录并保留首次期限');

  const executableName = `guard-recovery-child-${process.pid}.exe`;
  const executable = path.join(directory, executableName);
  assert.ok(process.env.GUARD_TEST_NODE);
  fs.copyFileSync(process.env.GUARD_TEST_NODE, executable);
  const descendantFile = path.join(directory, 'recovery-descendant.json');
  const child = spawn(executable, [path.resolve('tests/fixtures/process-tree.cjs'), descendantFile], {
    windowsHide: true, stdio: 'ignore',
  });
  await once(child, 'spawn');
  const exited = once(child, 'exit');
  const alerts: AlertPayload[] = [];
  const recordAlert = (payload: AlertPayload) => alerts.push(payload);
  engine.on('trigger-alert', recordAlert);
  const previous = store.get();
  store.update({ alertPopupEnabled: false, alertSoundEnabled: false });
  let attempts = 0;
  let activeRequests = 0;
  let maximumActiveRequests = 0;
  let expiredAt = 0;
  const termination = Promise.withResolvers<void>();
  const recovery: ClaudeVerificationRecovery = new ClaudeVerificationRecovery(async (): Promise<void> => {
    attempts++;
    activeRequests++;
    maximumActiveRequests = Math.max(maximumActiveRequests, activeRequests);
    try {
      await assert.rejects(requestTextViaProxy(
        'https://claude.ai/cdn-cgi/trace', 'http://127.0.0.1:1', 4500
      ));
      assert.equal(recovery.recordFailure(failureReason), false);
    } finally {
      activeRequests--;
    }
  }, async (failure) => {
    try {
      expiredAt = Date.now();
      assert.equal(alerts.length, 0);
      const report = await terminateProtectedProcesses([executableName]);
      await assertProcessesStopped([executableName], report);
      assert.equal(report.killedCount, 2);
      runtime.emitAlert({
        source: 'claude', alertType: 'verification-unavailable',
        expectedCode: probe.countryCode, expectedName: probe.countryName,
        triggerReason: `持续 30 秒无法完成地区校验：${failure.reason}`,
        errorDetail: failure.reason,
        killedProcesses: report.killedSummary, killError: report.errorDetail,
      });
      termination.resolve();
    } catch (error) {
      termination.reject(error);
    }
  });

  let recoveryAttempts = 0;
  let unexpectedExpiration = false;
  const recovered = Promise.withResolvers<void>();
  const successfulRecovery = new ClaudeVerificationRecovery(async () => {
    try {
      recoveryAttempts++;
      const result = { ...probe };
      await runtime.verifyTargetServiceRegion(proxyUrl, result, 'claude', true);
      if (!result.claudeTraceLoc) {
        successfulRecovery.recordFailure(getTargetServiceVerificationError(result)!);
        return;
      }
      assert.equal(getTargetServiceVerificationError(result), null);
      assert.ok(result.claudeTraceCheckedAt);
      successfulRecovery.clear();
      recovered.resolve();
    } catch (error) {
      recovered.reject(error);
      successfulRecovery.clear();
    }
  }, async (failure) => {
    unexpectedExpiration = true;
    recovered.reject(new Error(`真实 Claude 服务在 30 秒内未恢复：${failure.reason}`));
  });

  try {
    for (let attempt = 0; attempt < 50 && !fs.existsSync(descendantFile); attempt++) await sleep(50);
    assert.ok(fs.existsSync(descendantFile));
    recovery.recordFailure(failureReason);
    const initial = recovery.snapshot!;
    assert.equal(recovery.recordFailure(failureReason), false);
    assert.equal(recovery.snapshot!.startedAt, initial.startedAt);
    successfulRecovery.recordFailure(failureReason);
    await recovered.promise;
    assert.equal(successfulRecovery.snapshot, null);
    assert.equal(alerts.length, 0);
    assert.equal(child.exitCode, null);
    await termination.promise;
    await exited;
    assert.ok(expiredAt - initial.startedAt >= 30000);
    assert.ok(expiredAt - initial.startedAt < 33000);
    assert.ok(attempts >= 4 && attempts <= 5);
    assert.equal(maximumActiveRequests, 1);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].alertType, 'verification-unavailable');
    assert.equal(alerts[0].actualCode, null);
    assert.match(alerts[0].triggerReason, /持续 30 秒/);
    assert.match(alerts[0].errorDetail || '', /claude\.ai/);
    await sleep(1000);
    assert.equal(unexpectedExpiration, false);
    assert.ok(recoveryAttempts >= 1 && recoveryAttempts <= 5);
    assert.equal(recovery.snapshot, null);
    await verifyTerminationPopup(alerts[0]);
    console.log('通过：真实请求失败期间静默复核，30 秒期限不被重试延长，终止真实进程树后强制提醒');
    console.log('通过：真实 Claude 服务恢复后取消复核和终止计时，恢复过程保持静默');
  } finally {
    recovery.clear();
    successfulRecovery.clear();
    engine.off('trigger-alert', recordAlert);
    store.update(previous);
    if (child.exitCode === null && child.signalCode === null) {
      await terminateProtectedProcesses([executableName]);
      await exited;
    }
  }
}

async function verifyTerminationPopup(payload: AlertPayload): Promise<void> {
  assert.ok(process.env.GUARD_TEST_PRELOAD);
  assert.ok(process.env.GUARD_TEST_RENDERER);
  const window = new BrowserWindow({
    width: 420, height: 420, frame: false, show: false,
    webPreferences: {
      preload: process.env.GUARD_TEST_PRELOAD,
      contextIsolation: true, nodeIntegration: false, sandbox: true,
      backgroundThrottling: false,
    },
  });
  ipcMain.handle('guard:get-alert-data', () => payload);
  try {
    await window.loadFile(process.env.GUARD_TEST_RENDERER, { hash: 'alert' });
    await window.webContents.executeJavaScript(`new Promise((resolve, reject) => {
      const deadline = setTimeout(() => reject(new Error('终止弹窗未完成渲染')), 5000);
      const inspect = () => {
        if (!document.querySelector('.alert-title-text')) return;
        clearTimeout(deadline);
        observer.disconnect();
        resolve(true);
      };
      const observer = new MutationObserver(inspect);
      observer.observe(document.body, { childList: true, subtree: true });
      inspect();
    })`);
    const content = await window.webContents.executeJavaScript(`({
      text: document.body.innerText,
      comparison: !!document.querySelector('.alert-compare-grid'),
      reason: document.querySelector('.meta-v.alert-detail')?.textContent,
      bodyFits: document.body.scrollHeight <= window.innerHeight,
      reasonStyle: getComputedStyle(document.querySelector('.meta-v.alert-detail')).whiteSpace
    })`);
    assert.match(content.text, /Claude 地区校验持续失败/);
    assert.ok(content.reason.includes(payload.triggerReason));
    assert.equal(content.comparison, false);
    assert.equal(content.bodyFits, true);
    assert.equal(content.reasonStyle, 'normal');
    window.showInactive();
    await window.webContents.executeJavaScript(`document.fonts.ready.then(() =>
      new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))`);
    const screenshot = await window.capturePage();
    assert.ok(screenshot.toBitmap().some((value, index) => index % 4 !== 3 && value > 200),
      '终止弹窗截图未包含已绘制的文字');
    const artifactDirectory = path.resolve('release/verification-tests');
    fs.mkdirSync(artifactDirectory, { recursive: true });
    fs.writeFileSync(path.join(artifactDirectory, 'timeout-alert.png'), screenshot.toPNG());
    console.log('通过：真实终止结果在 Electron 弹窗完整显示，校验失败提示使用独立布局');
  } finally {
    ipcMain.removeHandler('guard:get-alert-data');
    window.destroy();
  }
}
