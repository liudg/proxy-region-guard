import { setTimeout as sleep } from 'node:timers/promises';
import {
  AntigravityLaunchResult,
  AntigravityRuntimeState,
  AppConfig,
  AppStateSnapshot,
  ProbeResult,
} from '../../src/shared/types';
import { isValidIsoCountryCode } from '../../src/shared/countries';
import {
  ANTIGRAVITY_PROCESS_PATTERNS,
  assertProcessesStopped,
  detectAntigravityInstallation,
  inspectRunningAntigravityProcesses,
  markAntigravityLaunchedByGuard,
  spawnAntigravityWithDedicatedProxy,
} from '../system';
import {
  probeOnceViaChannel,
  simplifyNetworkError,
  verifyAntigravityGoogleRegion,
} from '../probe';
import { GuardRuntimeContext, MAX_IN_FLIGHT_REBOUND_CONTINUES } from './guardTypes';
import { PrivateChannelCoordinator } from './privateChannelCoordinator';

export class AntigravityGuardController {
  public detectedExe: string | null = null;
  public installType: AntigravityRuntimeState['installType'] = 'not-found';
  public running = false;
  public uiCount = 0;
  public lsCount = 0;
  public totalCount = 0;
  public proxiedSession = false;

  private isProbing = false;
  private probePromise: Promise<AppStateSnapshot> | null = null;
  private probeSeq = 0;
  private pendingReprobe = false;
  private switchingCount = 0;
  private nodeProbe: ProbeResult | null = null;
  private nodeProbeError: string | null = null;
  private probeAbortController: AbortController | null = null;
  private debounceTimer: NodeJS.Timeout | null = null;
  private reboundDuringProbe = false;

  constructor(
    private readonly ctx: GuardRuntimeContext,
    private readonly channels: PrivateChannelCoordinator
  ) {}

  public applyDetectedState(
    install: { exePath: string | null; installType: AntigravityRuntimeState['installType'] },
    proc: {
      running: boolean;
      uiProcessCount: number;
      languageServerCount: number;
      totalProcessCount: number;
      proxiedSession: boolean;
    }
  ): void {
    this.detectedExe = install.exePath;
    this.installType = install.installType;
    this.running = proc.running;
    this.uiCount = proc.uiProcessCount;
    this.lsCount = proc.languageServerCount;
    this.totalCount = proc.totalProcessCount;
    this.proxiedSession = proc.proxiedSession;
  }

  public async pollRunningProcesses(dedicatedPort: number): Promise<boolean> {
    const agProc = await inspectRunningAntigravityProcesses(dedicatedPort);
    const changed =
      agProc.running !== this.running ||
      agProc.uiProcessCount !== this.uiCount ||
      agProc.languageServerCount !== this.lsCount ||
      agProc.proxiedSession !== this.proxiedSession;
    if (changed) {
      this.running = agProc.running;
      this.uiCount = agProc.uiProcessCount;
      this.lsCount = agProc.languageServerCount;
      this.totalCount = agProc.totalProcessCount;
      this.proxiedSession = agProc.proxiedSession;
    }
    return changed;
  }

  public async refreshInstallDetection(): Promise<void> {
    const cfg = this.ctx.configStore.get();
    const info = await detectAntigravityInstallation(cfg.antigravityExePath);
    this.detectedExe = info.exePath;
    this.installType = info.installType;
    this.ctx.emitState();
  }

  public abortActiveProbe(reason = 'Antigravity 探测已取消'): void {
    const controller = this.probeAbortController;
    if (controller && !controller.signal.aborted) {
      controller.abort(Object.assign(new Error(reason), { name: 'AbortError' }));
    }
  }

  public prepareManualNodeReset(reason: string): void {
    this.probeSeq++;
    this.abortActiveProbe(reason);
    this.nodeProbe = null;
  }

  public setNodeProbeError(err: string | null): void {
    this.nodeProbeError = err;
  }

  private needsRecoveryProbe(): boolean {
    if (!this.nodeProbe || Boolean(this.nodeProbeError)) {
      return true;
    }
    return !isValidIsoCountryCode(this.nodeProbe.googleCountryCode);
  }

  public handleListenerRebound(): void {
    if (this.ctx.isStopped()) return;
    if (this.isProbing) {
      this.reboundDuringProbe = true;
    }
    this.ctx.emitState();

    const cfg = this.ctx.configStore.get();
    const channelState = this.ctx.privateProxies.getState();
    if (
      cfg.antigravityClashNode &&
      channelState.antigravity.phase === 'ready' &&
      this.switchingCount === 0 &&
      !this.isProbing &&
      this.needsRecoveryProbe()
    ) {
      if (this.debounceTimer) clearTimeout(this.debounceTimer);
      this.debounceTimer = setTimeout(() => {
        this.debounceTimer = null;
        if (this.ctx.isStopped()) return;
        void this.probeNodeNow();
      }, 250);
    }
  }

  public handleChannelLost(reason: string): void {
    this.probeSeq++;
    this.abortActiveProbe(reason);
    this.nodeProbe = null;
    this.nodeProbeError = reason;
  }

  public handlePortConflict(reason: string): void {
    this.probeSeq++;
    this.abortActiveProbe(reason);
    this.pendingReprobe = false;
    this.nodeProbe = null;
    this.nodeProbeError = reason;
    this.ctx.logs.add('warn', `antigravity：${reason}`);
    this.ctx.emitState();
  }

  private isCurrentProbe(sequence: number, config: AppConfig): boolean {
    const current = this.ctx.configStore.get();
    return (
      this.switchingCount === 0 &&
      this.probeSeq === sequence &&
      current.antigravityClashNode === config.antigravityClashNode &&
      current.antigravityClashProfileUid === config.antigravityClashProfileUid &&
      current.antigravityDedicatedPort === config.antigravityDedicatedPort
    );
  }

  /** 从订阅保存 Antigravity 节点副本并启动对应私有内核。 */
  public async selectClashNode(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    return this.ctx.runApplicationChange(
      () => this.selectClashNodeInternal(nodeName, profileUid),
      'antigravity'
    );
  }

  public async selectClashNodeInternal(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    this.probeSeq++;
    this.abortActiveProbe('切换 Antigravity 专属节点');
    this.nodeProbe = null;
    this.nodeProbeError = null;
    this.switchingCount++;
    try {
      await this.bindSelection(nodeName, profileUid);
    } finally {
      this.switchingCount--;
    }
    if (
      this.ctx.configStore.get().antigravityClashNode &&
      this.ctx.privateProxies.channels.antigravity.getState().phase === 'ready'
    ) {
      return this.probeNodeNow();
    }
    return this.ctx.getSnapshot();
  }

  private async bindSelection(
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
        : prevCfg.antigravityClashProfileUid;

    if (cleanNode) {
      this.ctx.logs.add(
        'info',
        `正在将 Antigravity 专属代理通道切换至节点：[${cleanNode}] (127.0.0.1:${prevCfg.antigravityDedicatedPort})...`
      );
      const bindRes = await this.channels.bindPrivateSelection(
        'antigravity',
        cleanNode,
        prevCfg.antigravityDedicatedPort,
        effectiveProfileUid
      );
      const cfg = this.ctx.configStore.get();

      const fullLabel = cfg.antigravityClashProfileName
        ? `${cfg.antigravityClashProfileName} / ${cleanNode}`
        : cleanNode;

      if (!bindRes.ok) {
        const errText = bindRes.error || `绑定 Antigravity 节点 [${fullLabel}] 失败`;
        this.nodeProbeError = errText;
        this.ctx.logs.add('warn', errText);
        this.ctx.emitState();
        return this.ctx.getSnapshot();
      }

      this.ctx.logs.add(
        'success',
        `Antigravity 私有内核已启动 [${fullLabel}] → 127.0.0.1:${cfg.antigravityDedicatedPort}`
      );
      return this.ctx.getSnapshot();
    }

    this.pendingReprobe = false;
    await this.channels.bindPrivateSelection(
      'antigravity',
      null,
      prevCfg.antigravityDedicatedPort,
      null
    );
    this.nodeProbe = null;
    this.nodeProbeError = null;
    if (prevCfg.antigravityClashNode) {
      this.ctx.logs.add('info', '已取消 Antigravity 专属 Clash 节点绑定');
    }
    this.ctx.emitState();
    return this.ctx.getSnapshot();
  }

  /** 探测 Antigravity 专属端口的出口地区，用于界面展示。 */
  public async probeNodeNow(): Promise<AppStateSnapshot> {
    if (this.ctx.isStopped() || this.switchingCount > 0) return this.ctx.getSnapshot();
    const cfg = this.ctx.configStore.get();
    if (!cfg.antigravityClashNode) {
      this.probeSeq++;
      this.abortActiveProbe('未选择 Antigravity 节点');
      this.pendingReprobe = false;
      this.reboundDuringProbe = false;
      this.nodeProbe = null;
      this.nodeProbeError = null;
      this.ctx.emitState();
      return this.ctx.getSnapshot();
    }

    if (this.probePromise) {
      this.pendingReprobe = true;
      return this.probePromise;
    }

    let p: Promise<AppStateSnapshot> | null = null;
    const runProbe = async (): Promise<AppStateSnapshot> => {
      try {
        this.isProbing = true;
        this.ctx.emitState();

        let agReboundContinueCount = 0;
        let agRetriedBinding = false;
        while (!this.ctx.isStopped()) {
          if (this.switchingCount > 0) break;
          this.pendingReprobe = false;
          const seqAtStart = ++this.probeSeq;
          const curCfg = this.ctx.configStore.get();
          const targetNode = curCfg.antigravityClashNode;
          if (!targetNode) {
            this.nodeProbe = null;
            this.nodeProbeError = null;
            break;
          }

          const tryContinueSupersededAgProbe = (): boolean => {
            if (!this.ctx.isStopped() && !this.isCurrentProbe(seqAtStart, curCfg)) {
              if (this.ctx.configStore.get().antigravityClashNode) {
                if (
                  this.ctx.privateProxies.channels.antigravity.getState().phase !== 'ready'
                ) {
                  return false;
                }
                agRetriedBinding = false;
                agReboundContinueCount = 0;
                return true;
              }
              this.nodeProbe = null;
              this.nodeProbeError = null;
            }
            return false;
          };

          const agController = new AbortController();
          this.probeAbortController = agController;
          let probeSuccess: ProbeResult | null = null;
          let lastErrMsg = '探测超时';
          const proxyUrl = `http://127.0.0.1:${curCfg.antigravityDedicatedPort}`;
          const channelDesc = `Antigravity 专属端口 (127.0.0.1:${curCfg.antigravityDedicatedPort})`;

          try {
            const bindRes = await this.channels.checkPrivateReady(
              'antigravity',
              agController.signal
            );
            if (this.ctx.isStopped() || agController.signal.aborted) {
              if (tryContinueSupersededAgProbe()) continue;
              break;
            }
            if (!bindRes.ok) {
              if (!agRetriedBinding && this.isCurrentProbe(seqAtStart, curCfg)) {
                const recovered =
                  await this.ctx.privateProxies.channels.antigravity.recoverListenerIfNeeded(
                    agController.signal
                  );
                if (this.ctx.isStopped() || agController.signal.aborted) {
                  if (tryContinueSupersededAgProbe()) continue;
                  break;
                }
                if (recovered !== 'failed' && this.isCurrentProbe(seqAtStart, curCfg)) {
                  agRetriedBinding = true;
                  continue;
                }
              }
              if (!this.isCurrentProbe(seqAtStart, curCfg)) {
                if (tryContinueSupersededAgProbe()) continue;
                break;
              }
              this.nodeProbe = null;
              this.nodeProbeError =
                this.ctx.privateProxies.channels.antigravity.getState().error ||
                bindRes.error ||
                `专属端口 127.0.0.1:${curCfg.antigravityDedicatedPort} 未就绪`;
              if (this.pendingReprobe && this.ctx.configStore.get().antigravityClashNode) {
                agRetriedBinding = false;
                agReboundContinueCount = 0;
                continue;
              }
              break;
            }

            if (!this.isCurrentProbe(seqAtStart, curCfg)) {
              if (tryContinueSupersededAgProbe()) continue;
              break;
            }

            this.reboundDuringProbe = false;
            const firstPass = await probeOnceViaChannel({
              proxyUrl,
              viaChannel: channelDesc,
              timeoutMs: 7500,
              defaultErrMsg: '探测超时',
              customProbeUrl: curCfg.customProbeUrl,
              includeCustom: false,
              transportHosts:
                this.ctx.privateProxies.channels.antigravity.getBoundTransportHosts(),
              signal: agController.signal,
              geoIp: this.ctx.geoIp,
            });
            if (this.ctx.isStopped() || agController.signal.aborted) {
              if (tryContinueSupersededAgProbe()) continue;
              break;
            }
            if (
              firstPass.localProxyRefused &&
              !agRetriedBinding &&
              this.isCurrentProbe(seqAtStart, curCfg)
            ) {
              const recovered =
                await this.ctx.privateProxies.channels.antigravity.recoverListenerIfNeeded(
                  agController.signal
                );
              if (this.ctx.isStopped() || agController.signal.aborted) {
                if (tryContinueSupersededAgProbe()) continue;
                break;
              }
              if (recovered !== 'failed' && this.isCurrentProbe(seqAtStart, curCfg)) {
                agRetriedBinding = true;
                continue;
              }
            }
            probeSuccess = firstPass.result;
            lastErrMsg = firstPass.errMsg;

            if (probeSuccess && this.isCurrentProbe(seqAtStart, curCfg)) {
              this.ctx.privateProxies.channels.antigravity.clearForwardingError();
              await verifyAntigravityGoogleRegion(
                proxyUrl,
                probeSuccess,
                agController.signal
              );
              if (this.ctx.isStopped() || agController.signal.aborted) {
                if (tryContinueSupersededAgProbe()) continue;
                break;
              }
            }
          } finally {
            if (this.probeAbortController === agController) {
              this.probeAbortController = null;
            }
            agController.abort();
          }

          if (!this.isCurrentProbe(seqAtStart, curCfg)) {
            if (tryContinueSupersededAgProbe()) continue;
            break;
          }

          if (
            this.reboundDuringProbe &&
            agReboundContinueCount < MAX_IN_FLIGHT_REBOUND_CONTINUES &&
            (!probeSuccess || !isValidIsoCountryCode(probeSuccess.googleCountryCode))
          ) {
            agReboundContinueCount++;
            continue;
          }

          if (probeSuccess) {
            this.nodeProbe = probeSuccess;
            this.nodeProbeError = null;
            if (probeSuccess.regionMismatchDetail) {
              this.ctx.logs.add(
                'warn',
                `Antigravity 节点地区预警 [${targetNode}]：${probeSuccess.regionMismatchDetail}`
              );
            }
          } else {
            this.nodeProbe = null;
            this.nodeProbeError = simplifyNetworkError(lastErrMsg, channelDesc);
          }

          if (this.pendingReprobe && this.ctx.configStore.get().antigravityClashNode) {
            agRetriedBinding = false;
            agReboundContinueCount = 0;
            continue;
          }
          break;
        }
      } finally {
        this.isProbing = false;
        if (this.probePromise === p) {
          this.probePromise = null;
        }
        this.ctx.emitState();
      }

      return this.ctx.getSnapshot();
    };

    p = runProbe();
    this.probePromise = p;
    return p;
  }

  /**
   * 通过指定专属代理节点启动（或重启）Antigravity：
   * 1. 确认 Antigravity 私有内核及专属端口已经就绪
   * 2. 若已有运行中的 Antigravity.exe / language_server.exe，先关闭旧实例以释放单实例锁
   * 3. 注入 --proxy-server 与 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / GRPC_PROXY / NO_PROXY 拉起 Antigravity.exe
   */
  public async launchFromGuard(): Promise<AntigravityLaunchResult> {
    return this.ctx.runApplicationChange(() => this.launchInternal(), 'antigravity');
  }

  private async launchInternal(): Promise<AntigravityLaunchResult> {
    const cfg = this.ctx.configStore.get();

    const install = await detectAntigravityInstallation(cfg.antigravityExePath);
    this.detectedExe = install.exePath;
    this.installType = install.installType;

    if (!install.exePath) {
      const msg = '未检测到 Antigravity.exe 安装路径，请先点击下方「浏览」手动指定';
      this.ctx.logs.add('warn', msg);
      this.ctx.emitState();
      return { ok: false, message: msg, state: this.ctx.getSnapshot() };
    }

    if (!cfg.antigravityClashNode) {
      const msg = '请先在下拉框中选择要为 Antigravity 绑定的 Clash 代理节点';
      this.ctx.logs.add('warn', msg);
      this.ctx.emitState();
      return { ok: false, message: msg, state: this.ctx.getSnapshot() };
    }

    const bindRes = await this.channels.ensurePrivateChannelReadyForLaunch('antigravity');
    if (!bindRes.ok) {
      const msg = `无法建立节点 [${cfg.antigravityClashNode}] 的专属代理端口 (127.0.0.1:${
        cfg.antigravityDedicatedPort
      })：${bindRes.error || '端口未监听'}`;
      this.ctx.logs.add('warn', msg);
      this.ctx.emitState();
      return { ok: false, message: msg, state: this.ctx.getSnapshot() };
    }
    const agKernelState = this.ctx.privateProxies.channels.antigravity.getState();
    if (agKernelState.verificationError) {
      const msg = `无法通过节点 [${cfg.antigravityClashNode}] 启动 Antigravity：${agKernelState.verificationError}`;
      this.ctx.logs.add('warn', msg);
      this.ctx.emitState();
      return { ok: false, message: msg, state: this.ctx.getSnapshot() };
    }

    markAntigravityLaunchedByGuard(null);
    const killReport = await this.ctx.killQueue.executeSafely(ANTIGRAVITY_PROCESS_PATTERNS);
    await assertProcessesStopped(ANTIGRAVITY_PROCESS_PATTERNS, killReport);

    markAntigravityLaunchedByGuard(cfg.antigravityDedicatedPort);
    const spawnRes = await spawnAntigravityWithDedicatedProxy(
      install.exePath,
      cfg.antigravityDedicatedPort
    );

    if (!spawnRes.ok) {
      markAntigravityLaunchedByGuard(null);
      const errMsg = `拉起 Antigravity 失败：${spawnRes.error || '未知错误'}`;
      this.ctx.logs.add('danger', errMsg);
      this.ctx.emitState();
      return { ok: false, message: errMsg, state: this.ctx.getSnapshot() };
    }

    let afterProc = await inspectRunningAntigravityProcesses(
      cfg.antigravityDedicatedPort,
      true
    );
    const launchDeadline = Date.now() + 6000;
    while (Date.now() < launchDeadline) {
      if (afterProc.uiProcessCount > 0 && afterProc.proxiedSession) break;
      await sleep(250);
      afterProc = await inspectRunningAntigravityProcesses(
        cfg.antigravityDedicatedPort,
        true
      );
    }

    this.running = afterProc.running;
    this.uiCount = afterProc.uiProcessCount;
    this.lsCount = afterProc.languageServerCount;
    this.totalCount = afterProc.totalProcessCount;
    this.proxiedSession = afterProc.proxiedSession;

    if (afterProc.uiProcessCount === 0 || !afterProc.proxiedSession) {
      markAntigravityLaunchedByGuard(null);
      const message =
        afterProc.uiProcessCount === 0
          ? '启动 Antigravity 失败：未检测到主进程运行'
          : '启动 Antigravity 失败：未确认主进程绑定指定代理端口';
      this.ctx.logs.add('danger', message);
      this.ctx.emitState();
      return { ok: false, message, state: this.ctx.getSnapshot() };
    }

    if (!this.nodeProbe && !this.isProbing) {
      void this.probeNodeNow();
    }

    const okMsg = `已通过专属节点 [${cfg.antigravityClashNode}] (127.0.0.1:${cfg.antigravityDedicatedPort}) 启动 Antigravity，并设置代理启动参数与环境变量`;
    this.ctx.logs.add('success', okMsg);
    this.ctx.emitState();

    return {
      ok: true,
      message: okMsg,
      state: this.ctx.getSnapshot(),
    };
  }

  /** 手动关闭 Antigravity 及其 language_server.exe 进程树 */
  public async terminateManually(): Promise<AntigravityLaunchResult> {
    markAntigravityLaunchedByGuard(null);
    const report = await this.ctx.killQueue.executeSafely(ANTIGRAVITY_PROCESS_PATTERNS);
    const cfg = this.ctx.configStore.get();
    const afterProc = await inspectRunningAntigravityProcesses(
      cfg.antigravityDedicatedPort,
      true
    );

    this.running = afterProc.running;
    this.uiCount = afterProc.uiProcessCount;
    this.lsCount = afterProc.languageServerCount;
    this.totalCount = afterProc.totalProcessCount;
    this.proxiedSession = afterProc.proxiedSession;

    const msg =
      report.killedCount > 0
        ? `已关闭 Antigravity 关联进程：${report.killedSummary.join(', ')}`
        : '当前无运行中的 Antigravity 进程';
    this.ctx.logs.add('info', msg);
    this.ctx.emitState();

    return {
      ok: !this.running,
      message: report.errorDetail || msg,
      state: this.ctx.getSnapshot(),
    };
  }

  public buildRuntimeState(): AntigravityRuntimeState {
    const cfg = this.ctx.configStore.get();
    const kernel = this.ctx.privateProxies.channels.antigravity.getState();

    let launchHint: string | null = null;
    if (!this.detectedExe) {
      launchHint = '未检测到 Antigravity.exe 安装路径，请在下方手动浏览指定';
    } else if (!cfg.antigravityClashNode) {
      launchHint = '请先在上方下拉框中选择要绑定的 Clash 代理节点';
    } else if (kernel.phase !== 'ready') {
      launchHint = kernel.error || 'Antigravity 私有内核尚未就绪';
    } else if (kernel.verificationError) {
      launchHint = kernel.verificationError;
    }

    return {
      detectedExePath: this.detectedExe,
      installType: this.installType,
      running: this.running,
      uiProcessCount: this.uiCount,
      languageServerCount: this.lsCount,
      totalProcessCount: this.totalCount,
      proxiedSession: this.proxiedSession,
      canLaunch: launchHint === null,
      launchHint,
      isProbingNode: this.isProbing,
      nodeProbe: this.nodeProbe ? { ...this.nodeProbe } : null,
      nodeProbeError: this.nodeProbeError,
    };
  }

  public stop(): void {
    this.abortActiveProbe('应用已停止');
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
  }
}
