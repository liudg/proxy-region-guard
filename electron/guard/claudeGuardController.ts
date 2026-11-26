import {
  AppConfig,
  AppStateSnapshot,
  ClaudeLaunchResult,
  ClaudeRuntimeState,
  ProbeResult,
} from '../../src/shared/types';
import { normalizeIpAddress } from '../../src/shared/probeValidation';
import {
  assertProcessesStopped,
  CLAUDE_DESKTOP_PROCESS_PATTERNS,
  countRunningClaudeProcesses,
  detectClaudeInstallation,
  markClaudeLaunchedByGuard,
  ProcessKillReport,
  terminateClaudeProcessesSync,
} from '../system';
import { CLAUDE_MAX_RUNTIME_POLL_SEC } from '../probe';
import { ClaudeSafetyCheck } from './alertBuilder';
import { ClaudeNodeProbeRunner } from './claudeNodeProbeRunner';
import {
  ClaudeSessionSupervisorHost,
  executeAuthorizedClaudeLaunch,
  runClaudeExclusiveWatchTick,
} from './claudeProcessSupervisor';
import {
  buildClaudeRuntimeStateSnapshot,
  ClaudePolicySnapshotInput,
  evaluateClaudeFullSafety,
  evaluateClaudeLocalSafety,
  evaluateShouldStopClaudeBeforeLocaleChange,
  getVerifiedClaudeCountryCode,
  resolveExpectedClaudeRegion,
} from './claudeSafetyPolicy';
import {
  CLAUDE_VERIFICATION_RETRY_MS,
  ClaudeVerificationRecovery,
} from './claudeVerificationRecovery';
import { GuardRuntimeContext } from './guardTypes';
import { PrivateChannelCoordinator } from './privateChannelCoordinator';

export class ClaudeGuardController implements ClaudeSessionSupervisorHost {
  public detectedExe: string | null = null;
  public installType: ClaudeRuntimeState['installType'] = 'not-found';
  public running = false;
  public processCount = 0;
  public runningPids: number[] = [];
  public authorizedSession = false;
  public sessionInitialIp: string | null = null;

  public fastCheckTicks = 0;
  public externalBaselinePending = false;
  public externalBaselineMinSeq = 0;
  public seenRunningSinceAuth = false;
  public launchGraceUntil = 0;

  private switchingCount = 0;
  private safetyKillPromise: Promise<boolean> | null = null;
  private readonly verificationRecovery: ClaudeVerificationRecovery;
  private readonly prober: ClaudeNodeProbeRunner;

  private claudeHeartbeatTimer: NodeJS.Timeout | null = null;
  private watchTimer: NodeJS.Timeout | null = null;
  private debounceTimer: NodeJS.Timeout | null = null;

  constructor(
    public readonly ctx: GuardRuntimeContext,
    public readonly channels: PrivateChannelCoordinator
  ) {
    this.prober = new ClaudeNodeProbeRunner({
      ctx,
      channels,
      isRunning: () => this.running,
      isAuthorizedSession: () => this.authorizedSession,
      getSessionInitialIp: () => this.sessionInitialIp,
      recordSessionBaselineIp: (ip, countryName, countryCode) => {
        this.sessionInitialIp = ip;
        this.externalBaselinePending = false;
        this.externalBaselineMinSeq = 0;
        this.ctx.logs.add(
          'info',
          `已记录运行中 Claude 会话初始出口 IP 基线：${this.sessionInitialIp} (${countryName} ${countryCode})`
        );
      },
      isExternalBaselinePending: () => this.externalBaselinePending,
      getExternalBaselineMinSeq: () => this.externalBaselineMinSeq,
      getSwitchingCount: () => this.switchingCount,
      hasSafetyKillInFlight: () => this.safetyKillPromise !== null,
      isEffectiveForceIpv4: (cfg) => this.isEffectiveForceIpv4(cfg),
      getPolicySnapshotInput: (cfg) => this.getPolicySnapshotInput(cfg),
      evaluateSafety: (requireDedicatedNode) => this.evaluateSafety(requireDedicatedNode),
      clearVerificationFailureIfRecovered: () => this.clearVerificationFailureIfRecovered(),
      recordVerificationFailure: (reason) => this.recordVerificationFailure(reason),
      enforceRunningSafety: (triggerContext) => this.enforceRunningSafety(triggerContext),
      clearHeartbeatTimer: () => this.clearHeartbeatTimer(),
      syncHeartbeatSchedule: () => this.syncHeartbeatSchedule(),
    });

    this.verificationRecovery = new ClaudeVerificationRecovery(
      async (signal) => {
        if (this.ctx.isStopped() || signal.aborted || !this.running) {
          this.verificationRecovery.clear();
          return;
        }
        if (!this.prober.probePromise && !this.safetyKillPromise) {
          const onAbort = () => {
            this.abortActiveProbe('Claude 后台复核已取消');
          };
          signal.addEventListener('abort', onAbort, { once: true });
          try {
            await this.probeNodeNow('Claude 运行期后台复核');
          } finally {
            signal.removeEventListener('abort', onAbort);
          }
        }
      },
      CLAUDE_VERIFICATION_RETRY_MS,
      (error) => {
        if (this.ctx.isStopped() || !this.running) {
          this.verificationRecovery.clear();
          return;
        }
        const detail = error instanceof Error ? error.message : String(error);
        this.recordVerificationFailure(`Claude 后台复核异常：${detail}`);
      }
    );

    this.ctx.killQueue.setAfterKillHook(async () => {
      const claudeNow = await countRunningClaudeProcesses(true);
      this.running = claudeNow.running;
      this.processCount = claudeNow.count;
      this.runningPids = claudeNow.pids;
      this.fastCheckTicks = 0;
    });
  }

  private getPolicySnapshotInput(
    cfg: AppConfig = this.ctx.configStore.get()
  ): ClaudePolicySnapshotInput {
    return {
      cfg,
      kernel: this.ctx.privateProxies.channels.claude.getState(),
      winLocale: this.ctx.getWinLocale(),
      detectedExe: this.detectedExe,
      installType: this.installType,
      running: this.running,
      processCount: this.processCount,
      authorizedSession: this.authorizedSession,
      sessionInitialIp: this.sessionInitialIp,
      externalBaselinePending: this.externalBaselinePending,
      isProbing: this.prober.isProbing,
      nodeProbe: this.prober.nodeProbe,
      nodeProbeError: this.prober.nodeProbeError,
      lastVerificationSuccessAt: this.prober.lastVerificationSuccessAt,
      lastVerifiedRegion: this.prober.lastVerifiedRegion,
      verificationFailure: this.verificationRecovery.snapshot,
      effectiveForceIpv4: this.isEffectiveForceIpv4(cfg),
    };
  }

  public getNodeProbe(): ProbeResult | null {
    return this.prober.nodeProbe;
  }

  public isProbingNode(): boolean {
    return this.prober.isProbing;
  }

  public applyDetectedState(
    install: { exePath: string | null; installType: ClaudeRuntimeState['installType'] },
    proc: { running: boolean; count: number; pids: number[] }
  ): void {
    this.detectedExe = install.exePath;
    this.installType = install.installType;
    this.running = proc.running;
    this.processCount = proc.count;
    this.runningPids = proc.pids;
  }

  public beginStartupExternalBaselineIfNeeded(cfg: AppConfig): void {
    if (this.running && !cfg.claudeExclusiveGuard) {
      this.externalBaselinePending = true;
      this.externalBaselineMinSeq = this.prober.probeSeq + 1;
    }
  }

  public async refreshInstallDetection(): Promise<void> {
    const cfg = this.ctx.configStore.get();
    const info = await detectClaudeInstallation(cfg.claudeExePath, true);
    this.detectedExe = info.exePath;
    this.installType = info.installType;
    this.ctx.emitState();
  }

  public async refreshLiveProcessState(): Promise<void> {
    const liveProc = await countRunningClaudeProcesses(true);
    this.running = liveProc.running;
    this.processCount = liveProc.count;
    this.runningPids = liveProc.pids;
  }

  public async isActiveForUpdateInterlock(): Promise<boolean> {
    if (this.running || this.authorizedSession) {
      return true;
    }
    const live = await countRunningClaudeProcesses(true);
    if (live.running) {
      this.running = true;
      this.processCount = live.count;
      this.runningPids = live.pids;
      return true;
    }
    return false;
  }

  public isEffectiveForceIpv4(cfg: AppConfig = this.ctx.configStore.get()): boolean {
    if (!cfg.claudeForceIpv4) return false;
    const kernel = this.ctx.privateProxies.channels.claude;
    if (this.running && kernel.getSnapshot() && !kernel.getIpv4Only()) {
      return false;
    }
    return true;
  }

  public abortActiveProbe(reason = 'Claude 探测已取消'): void {
    this.prober.abortActiveProbe(reason);
  }

  public clearHeartbeatTimer(): void {
    if (this.claudeHeartbeatTimer) {
      clearTimeout(this.claudeHeartbeatTimer);
      this.claudeHeartbeatTimer = null;
    }
  }

  public syncHeartbeatSchedule(): void {
    this.clearHeartbeatTimer();
    if (this.ctx.isStopped() || !this.ctx.isStarted()) return;
    const cfg = this.ctx.configStore.get();
    if (
      !this.running ||
      !cfg.selectedClashNode ||
      this.verificationRecovery.snapshot !== null
    ) {
      return;
    }

    const sec = cfg.heartbeatIntervalSec;
    const claudePollSec =
      sec > 0 ? Math.min(sec, CLAUDE_MAX_RUNTIME_POLL_SEC) : CLAUDE_MAX_RUNTIME_POLL_SEC;
    const pollIntervalMs = claudePollSec * 1000;
    const elapsedMs =
      this.prober.lastClaudeProbeCompletedAt > 0
        ? Math.max(0, Date.now() - this.prober.lastClaudeProbeCompletedAt)
        : 0;
    const delayMs =
      this.prober.lastClaudeProbeCompletedAt > 0
        ? Math.max(1000, pollIntervalMs - elapsedMs)
        : pollIntervalMs;

    this.claudeHeartbeatTimer = setTimeout(() => {
      this.claudeHeartbeatTimer = null;
      if (this.ctx.isStopped()) return;
      const latestCfg = this.ctx.configStore.get();
      if (
        !this.running ||
        !latestCfg.selectedClashNode ||
        this.verificationRecovery.snapshot !== null
      ) {
        return;
      }
      if (!this.prober.probePromise && !this.safetyKillPromise) {
        void this.probeNodeNow('Claude 运行期心跳巡检');
      } else {
        this.syncHeartbeatSchedule();
      }
    }, delayMs);
  }

  public prepareManualNodeReset(reason: string): void {
    this.prober.probeSeq++;
    this.abortActiveProbe(reason);
    this.prober.lastClaudeProbeCompletedAt = 0;
    this.prober.nodeProbe = null;
  }

  public resetProbeForModeSwitch(reason: string): void {
    this.prober.probeSeq++;
    this.abortActiveProbe(reason);
    this.prober.lastClaudeProbeCompletedAt = 0;
    this.prober.nodeProbe = null;
    this.prober.nodeProbeError = null;
  }

  public resetVerificationStateWithoutKilling(reason: string): void {
    this.verificationRecovery.clear();
    this.abortActiveProbe(reason);
    this.unsetAuthLock();
    this.prober.lastVerificationSuccessAt = null;
    this.prober.lastVerifiedRegion = null;
    this.prober.lastClaudeProbeCompletedAt = 0;
  }

  public setNodeProbeError(err: string | null): void {
    this.prober.nodeProbeError = err;
  }

  public incrementSwitchingCount(): void {
    this.switchingCount++;
  }

  public decrementSwitchingCount(): void {
    this.switchingCount--;
  }

  public clearVerificationRecovery(): void {
    this.verificationRecovery.clear();
  }

  public unsetAuthLock(): void {
    this.verificationRecovery.clear();
    this.authorizedSession = false;
    this.sessionInitialIp = null;
    this.externalBaselinePending = false;
    this.externalBaselineMinSeq = 0;
    this.seenRunningSinceAuth = false;
    this.launchGraceUntil = 0;
    markClaudeLaunchedByGuard(null);
    this.fastCheckTicks = 0;
    this.syncHeartbeatSchedule();
  }

  public handleListenerRebound(): void {
    if (this.ctx.isStopped()) return;
    if (this.prober.isProbing) {
      this.prober.reboundDuringProbe = true;
    }
    this.ctx.emitState();

    const cfg = this.ctx.configStore.get();
    const channelState = this.ctx.privateProxies.getState();
    if (
      cfg.selectedClashNode &&
      channelState.claude.phase === 'ready' &&
      this.switchingCount === 0 &&
      !this.prober.isProbing &&
      this.prober.needsRecoveryProbe()
    ) {
      if (this.debounceTimer) clearTimeout(this.debounceTimer);
      this.debounceTimer = setTimeout(() => {
        this.debounceTimer = null;
        if (this.ctx.isStopped()) return;
        void this.probeNodeNow('Claude 专属代理端口恢复重测');
      }, 250);
    }
  }

  public handleChannelLost(reason: string): void {
    this.prober.probeSeq++;
    this.abortActiveProbe(reason);
    this.prober.lastClaudeProbeCompletedAt = 0;
    this.prober.nodeProbe = null;
    this.prober.nodeProbeError = reason;
    void this.enforceRunningSafety(reason);
  }

  public handlePortConflict(reason: string): void {
    this.prober.probeSeq++;
    this.abortActiveProbe(reason);
    this.prober.pendingProbe = null;
    this.prober.lastClaudeProbeCompletedAt = 0;
    this.prober.nodeProbe = null;
    this.prober.nodeProbeError = reason;
    this.ctx.logs.add('danger', `claude：${reason}`);
    this.ctx.emitState();
    if (!this.prober.activeProbeSkipSafety && this.running) {
      void this.enforceRunningSafety(reason);
    }
  }

  public async migrateDeferredIpv4IfIdle(): Promise<void> {
    if (this.ctx.isStopped() || this.running || this.ctx.hasActiveApplicationChanges()) return;
    const cfg = this.ctx.configStore.get();
    const kernel = this.ctx.privateProxies.channels.claude;
    if (
      !cfg.selectedClashNode ||
      !kernel.getSnapshot() ||
      kernel.getIpv4Only() === cfg.claudeForceIpv4
    ) {
      return;
    }
    try {
      await this.ctx.runApplicationChange(async () => {
        if (this.ctx.isStopped() || this.running) return;
        const latestCfg = this.ctx.configStore.get();
        if (
          !latestCfg.selectedClashNode ||
          !kernel.getSnapshot() ||
          kernel.getIpv4Only() === latestCfg.claudeForceIpv4
        ) {
          return;
        }
        this.resetProbeForModeSwitch('执行延后的 Claude 私有内核 IPv4 模式迁移');
        this.switchingCount++;
        let bindRes: { ok: boolean; error?: string };
        try {
          bindRes = await this.channels.bindPrivateSelection(
            'claude',
            latestCfg.selectedClashNode,
            latestCfg.dedicatedProxyPort,
            latestCfg.selectedClashProfileUid,
            { ipv4OnlyOverride: latestCfg.claudeForceIpv4 }
          );
        } finally {
          this.switchingCount--;
        }
        if (!bindRes.ok) {
          const message = `延后迁移 Claude 私有内核 IPv4 模式失败：${
            bindRes.error || '未知错误'
          }`;
          this.prober.nodeProbeError = message;
          this.ctx.logs.add('danger', message);
          this.ctx.emitState();
          return;
        }
        this.ctx.logs.add(
          'success',
          latestCfg.claudeForceIpv4
            ? `外部 Claude 会话已退出，已自动将私有内核切换至强制仅走 IPv4 出站 (127.0.0.1:${latestCfg.dedicatedProxyPort})`
            : `外部 Claude 会话已退出，已自动将私有内核切换至双栈出站 (127.0.0.1:${latestCfg.dedicatedProxyPort})`
        );
        this.ctx.emitState();
        void this.probeNodeNow('应用延后的 Claude IPv4 出站模式迁移');
      }, 'claude');
    } catch {
      // 并发变更进行中时自动交由下次巡检或下次启动完成迁移
    }
  }

  public async stopBeforeRoutingChange(forceTerminate = false): Promise<ProcessKillReport> {
    this.verificationRecovery.clear();
    this.abortActiveProbe('调整 Claude 专属代理配置');
    const shouldTerminateClaude =
      forceTerminate ||
      this.ctx.isStarted() ||
      this.running ||
      this.authorizedSession ||
      this.ctx.configStore.get().claudeExclusiveGuard;
    const report: ProcessKillReport = shouldTerminateClaude
      ? await this.ctx.killQueue.executeSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS)
      : {
          killedSummary: [],
          killedCount: 0,
          failedSummary: [],
          failedPids: [],
          accessDenied: false,
        };
    if (shouldTerminateClaude) {
      await assertProcessesStopped(CLAUDE_DESKTOP_PROCESS_PATTERNS, report);
    }
    this.unsetAuthLock();
    this.prober.lastVerificationSuccessAt = null;
    this.prober.lastVerifiedRegion = null;
    this.prober.lastClaudeProbeCompletedAt = 0;
    if (report.killedCount > 0) {
      this.ctx.logs.add(
        'info',
        `调整 Claude 专属代理前已终止关联进程：${report.killedSummary.join(', ')}`
      );
    }
    return report;
  }

  public async selectClashNode(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    return this.ctx.runApplicationChange(async () => {
      await this.stopBeforeRoutingChange();
      return this.selectClashNodeInternal(nodeName, profileUid);
    }, 'claude');
  }

  public async selectClashNodeInternal(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    const cleanNode = nodeName && nodeName.trim() ? nodeName.trim() : null;
    const prevCfg = this.ctx.configStore.get();
    const effectiveProfileUid =
      profileUid !== undefined
        ? profileUid && profileUid.trim()
          ? profileUid.trim()
          : null
        : prevCfg.selectedClashProfileUid;

    this.resetProbeForModeSwitch('切换 Claude 专属节点');

    if (cleanNode) {
      this.switchingCount++;
      this.ctx.logs.add(
        'info',
        `正在将 Claude 专属代理通道切换至 Clash 节点：[${cleanNode}] (127.0.0.1:${prevCfg.dedicatedProxyPort})...`
      );
      let bindRes: { ok: boolean; error?: string };
      try {
        bindRes = await this.channels.bindPrivateSelection(
          'claude',
          cleanNode,
          prevCfg.dedicatedProxyPort,
          effectiveProfileUid
        );
      } finally {
        this.switchingCount--;
      }

      const cfg = this.ctx.configStore.get();
      const fullLabel = cfg.selectedClashProfileName
        ? `${cfg.selectedClashProfileName} / ${cleanNode}`
        : cleanNode;

      if (!bindRes.ok) {
        const errText = bindRes.error || `绑定 Claude 节点 [${fullLabel}] 失败`;
        this.prober.nodeProbeError = errText;
        this.ctx.logs.add('warn', errText);
        this.ctx.emitState();
        if (this.running) {
          await this.enforceRunningSafety(`绑定 Claude 节点 [${fullLabel}] 失败`);
        }
        return this.ctx.getSnapshot();
      }

      this.ctx.logs.add(
        'success',
        `已锁定 Claude 专属节点 [${fullLabel}] → 本地专属端口 127.0.0.1:${cfg.dedicatedProxyPort}`
      );

      return this.probeNodeNow(`切换 Claude 专属节点: ${fullLabel}`);
    }

    this.prober.pendingProbe = null;
    this.switchingCount++;
    try {
      await this.channels.bindPrivateSelection(
        'claude',
        null,
        prevCfg.dedicatedProxyPort,
        null
      );
    } finally {
      this.switchingCount--;
    }
    this.prober.nodeProbe = null;
    this.prober.nodeProbeError = null;
    if (prevCfg.selectedClashNode) {
      this.ctx.logs.add('info', '已取消 Claude 专属 Clash 节点绑定');
    }
    this.ctx.emitState();
    if (this.running) {
      await this.enforceRunningSafety('取消 Claude 专属节点绑定');
    }
    return this.ctx.getSnapshot();
  }

  public probeNodeNow(
    reason = '检测 Claude 专属节点',
    skipSafetyEnforcement = false
  ): Promise<AppStateSnapshot> {
    return this.prober.probeNodeNow(reason, skipSafetyEnforcement);
  }

  public async launchFromGuard(): Promise<ClaudeLaunchResult> {
    return this.ctx.runApplicationChange(
      () => executeAuthorizedClaudeLaunch(this),
      'claude'
    );
  }

  public async terminateManually(): Promise<ClaudeLaunchResult> {
    this.verificationRecovery.clear();

    const report = await this.ctx.killQueue.executeSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
    if (!this.running) {
      this.unsetAuthLock();
    }

    const msg =
      report.killedCount > 0
        ? `已安全终止 Claude 进程树：${report.killedSummary.join(', ')}`
        : '当前无运行中的 Claude 进程，已重置启动授权锁';
    this.ctx.logs.add('info', msg);
    this.ctx.emitState();

    return {
      ok: !this.running,
      message: report.errorDetail || msg,
      state: this.ctx.getSnapshot(),
    };
  }

  public startExclusiveWatcher(): void {
    const scheduleNext = (delayMs: number) => {
      if (this.ctx.isStopped()) return;
      if (this.watchTimer) {
        clearTimeout(this.watchTimer);
      }
      this.watchTimer = setTimeout(() => {
        this.watchTimer = null;
        void runClaudeExclusiveWatchTick(this).then((nextDelay) => {
          scheduleNext(nextDelay);
        });
      }, delayMs);
    };

    scheduleNext(1200);
  }

  public ensureExternalBaselineProbe(cfg: AppConfig = this.ctx.configStore.get()): void {
    if (
      this.running &&
      !this.authorizedSession &&
      !cfg.claudeExclusiveGuard &&
      this.sessionInitialIp === null &&
      cfg.selectedClashNode &&
      !this.externalBaselinePending
    ) {
      this.externalBaselinePending = true;
      this.externalBaselineMinSeq = this.prober.probeSeq + 1;
      this.ctx.emitState();
      void this.probeNodeNow('检测到外部运行 Claude，建立会话出口 IP 基线');
    }
  }

  public async enforceRunningSafety(triggerContext: string): Promise<boolean> {
    if (!this.ctx.isStarted() || !this.running || this.ctx.isStopped()) {
      this.verificationRecovery.clear();
      return false;
    }
    if (this.safetyKillPromise) return this.safetyKillPromise;
    const cfg = this.ctx.configStore.get();
    this.ensureExternalBaselineProbe(cfg);
    const requireDedicatedNode = this.authorizedSession || cfg.claudeExclusiveGuard;
    if (this.prober.isProbing || this.switchingCount > 0) {
      const localCheck = evaluateClaudeLocalSafety(
        requireDedicatedNode,
        this.getPolicySnapshotInput(cfg)
      );
      if (localCheck) return this.terminateUnsafe(localCheck, triggerContext);
      const kernel = this.ctx.privateProxies.channels.claude.getState();
      if (cfg.selectedClashNode && kernel.verificationError) {
        this.recordVerificationFailure(kernel.verificationError);
      }
      return false;
    }
    const check = this.evaluateSafety(requireDedicatedNode);
    if (check.safe) {
      let stateChanged = false;
      if (this.running && this.authorizedSession && this.sessionInitialIp === null) {
        const traceIp = normalizeIpAddress(this.prober.nodeProbe?.claudeTraceIp);
        if (traceIp) {
          this.sessionInitialIp = traceIp;
          stateChanged = true;
        }
      }
      if (this.clearVerificationFailureIfRecovered()) {
        stateChanged = true;
      }
      if (stateChanged) {
        this.ctx.emitState();
      }
      return false;
    }
    if (check.alertType === 'verification-unavailable') {
      this.recordVerificationFailure(check.reason);
      return false;
    }
    return this.terminateUnsafe(check, triggerContext);
  }

  private clearVerificationFailureIfRecovered(): boolean {
    if (!this.verificationRecovery.clear()) return false;
    this.syncHeartbeatSchedule();
    this.ctx.logs.add('success', 'Claude 地区校验已恢复，后台复核结束');
    return true;
  }

  private recordVerificationFailure(reason: string): void {
    this.clearHeartbeatTimer();
    const { shouldLog, stateChanged } = this.verificationRecovery.recordFailure(reason);
    if (shouldLog) {
      this.ctx.logs.add('warn', `Claude 地区校验暂时不可用，正在后台复核：${reason}`);
    }
    if (shouldLog || stateChanged) {
      this.ctx.emitState();
    }
  }

  private terminateUnsafe(check: ClaudeSafetyCheck, triggerContext: string): Promise<boolean> {
    if (this.safetyKillPromise) return this.safetyKillPromise;
    const operation = async () => {
      this.verificationRecovery.clear();

      const report = await this.ctx.killQueue.executeSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
      if (!this.running) {
        this.unsetAuthLock();
      }
      if (report.killedCount > 0) {
        this.ctx.logs.add(
          'danger',
          `Claude 保护终止 (${check.reason})：${report.killedSummary.join(', ')}`
        );
      } else if (report.errorDetail) {
        this.ctx.logs.add('warn', report.errorDetail);
      }
      this.ctx.emitState();

      if (report.killedCount > 0 || report.errorDetail) {
        const winLocale = this.ctx.getWinLocale();
        const expectedRegion = resolveExpectedClaudeRegion(
          this.ctx.configStore.get(),
          this.prober.nodeProbe,
          this.prober.lastVerifiedRegion
        );
        const expectedCode = expectedRegion?.countryCode || winLocale.regionCode;
        const expectedName = expectedRegion?.countryName || winLocale.regionName;
        this.ctx.emitGuardAlert({
          source: 'claude',
          alertType: check.alertType,
          expectedCode,
          expectedName,
          expectedIp: check.expectedIp,
          actualIp: check.actualIp,
          triggerReason: `${triggerContext}：${check.reason}`,
          errorDetail: check.reason,
          killedProcesses: report.killedCount > 0 ? report.killedSummary : undefined,
          killError: report.errorDetail,
        });
      }

      return true;
    };
    this.safetyKillPromise = operation().finally(() => {
      this.safetyKillPromise = null;
    });
    return this.safetyKillPromise;
  }

  public evaluateSafety(requireDedicatedNode = true): ClaudeSafetyCheck {
    return evaluateClaudeFullSafety(requireDedicatedNode, this.getPolicySnapshotInput());
  }

  public getVerifiedProbeCountryCode(): string | null {
    return getVerifiedClaudeCountryCode(this.prober.nodeProbe);
  }

  public shouldStopBeforeLocaleChange(targetCode: string, targetTimeZone: string): boolean {
    return evaluateShouldStopClaudeBeforeLocaleChange(
      targetCode,
      targetTimeZone,
      this.getPolicySnapshotInput()
    );
  }

  public buildRuntimeState(): ClaudeRuntimeState {
    return buildClaudeRuntimeStateSnapshot(this.getPolicySnapshotInput());
  }

  public stop(wasStarted: boolean): void {
    this.abortActiveProbe('应用已停止');
    this.verificationRecovery.clear();

    const shouldKillClaudeOnExit =
      wasStarted &&
      (this.running ||
        this.authorizedSession ||
        this.ctx.configStore.get().claudeExclusiveGuard);

    this.authorizedSession = false;
    this.sessionInitialIp = null;
    this.externalBaselinePending = false;
    this.externalBaselineMinSeq = 0;
    this.seenRunningSinceAuth = false;
    this.launchGraceUntil = 0;
    markClaudeLaunchedByGuard(null);

    if (shouldKillClaudeOnExit) {
      terminateClaudeProcessesSync();
    }

    this.clearHeartbeatTimer();
    if (this.watchTimer) {
      clearTimeout(this.watchTimer);
      this.watchTimer = null;
    }
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
  }
}
