import { EventEmitter } from 'node:events';
import {
  AlertPayload,
  AntigravityLaunchResult,
  AppConfig,
  AppStateSnapshot,
  ClaudeLaunchResult,
  GuardEventLog,
  LocaleSyncResult,
  PrivateChannelId,
  UpdateStateSnapshot,
  WindowsLocaleState,
} from '../../src/shared/types';
import {
  DEFAULT_CHINA_REGION_CODE,
  DEFAULT_CHINA_TIMEZONE_ID,
} from '../../src/shared/timezones';
import { ClashMonitor } from '../clash';
import { PrivateProxyService } from '../kernel';
import {
  ConfigStore,
  countRunningClaudeProcesses,
  detectAntigravityInstallation,
  detectClaudeInstallation,
  GeoIpService,
  getNetworkInterfaceFingerprint,
  inspectRunningAntigravityProcesses,
  readWindowsLocaleState,
  readWindowsSystemProxy,
  SystemProxyState,
} from '../system';
import { UpdaterHostAdapter } from '../updater';
import {
  buildGuardAlertPayload,
  buildSystemAlertPayload,
  ClaudeSafetyCheck,
  createFallbackUpdateStateSnapshot,
  GuardAlertInput,
} from './alertBuilder';
import { AntigravityGuardController } from './antigravityGuardController';
import { ClaudeGuardController } from './claudeGuardController';
import { EventLogStore } from './eventLogStore';
import { GuardRuntimeContext } from './guardTypes';
import { LocaleSyncController } from './localeSyncController';
import { PrivateChannelCoordinator } from './privateChannelCoordinator';
import { ProcessKillQueue } from './processKillQueue';
import { RealtimeMonitorController } from './realtimeMonitorController';

export class GuardCoordinator extends EventEmitter implements UpdaterHostAdapter {
  public readonly logs = new EventLogStore();
  public readonly killQueue = new ProcessKillQueue();
  public readonly channels: PrivateChannelCoordinator;
  public readonly claude: ClaudeGuardController;
  public readonly antigravity: AntigravityGuardController;
  public readonly monitor: RealtimeMonitorController;
  public readonly localeSync: LocaleSyncController;

  public winLocale: WindowsLocaleState = {
    timeZoneId: DEFAULT_CHINA_TIMEZONE_ID,
    timeZoneDisplayName: '(UTC+08:00) 北京，重庆，香港特别行政区，乌鲁木齐',
    regionCode: DEFAULT_CHINA_REGION_CODE,
    regionName: '中国',
  };

  private started = false;
  private stopped = false;
  private syncingLocale = false;
  private applicationChanges = new Set<PrivateChannelId | 'global'>();
  private cachedSysProxy: { state: SystemProxyState; readAt: number } | null = null;
  private updateStateProvider: (() => UpdateStateSnapshot) | null = null;

  constructor(
    private readonly configStore: ConfigStore,
    private readonly geoIp: GeoIpService,
    private readonly clashMonitor: ClashMonitor,
    private readonly privateProxies: PrivateProxyService
  ) {
    super();

    const ctx: GuardRuntimeContext = {
      configStore: this.configStore,
      geoIp: this.geoIp,
      clashMonitor: this.clashMonitor,
      privateProxies: this.privateProxies,
      logs: this.logs,
      killQueue: this.killQueue,
      isStarted: () => this.started,
      isStopped: () => this.stopped,
      getWinLocale: () => this.winLocale,
      setWinLocale: (locale) => {
        this.winLocale = locale;
      },
      isSyncingLocale: () => this.syncingLocale,
      setSyncingLocale: (syncing) => {
        this.syncingLocale = syncing;
      },
      hasActiveApplicationChanges: () => this.applicationChanges.size > 0,
      runApplicationChange: (op, channel) => this.runApplicationChange(op, channel),
      getSystemProxyFresh: (force) => this.getSystemProxyFresh(force),
      emitState: () => this.emitState(),
      emitGuardAlert: (input) => this.emitGuardAlert(input),
      emitSystemAlert: (alertType, message) => this.emitSystemAlert(alertType, message),
      emitRecoveredAlert: (payload) => this.emit('alert-recovered', payload),
      getSnapshot: () => this.getSnapshot(),
    };

    this.channels = new PrivateChannelCoordinator(ctx);
    this.claude = new ClaudeGuardController(ctx, this.channels);
    this.antigravity = new AntigravityGuardController(ctx, this.channels);
    this.monitor = new RealtimeMonitorController(ctx, this.claude, this.antigravity);
    this.localeSync = new LocaleSyncController(ctx, this.claude, this.monitor);

    this.bindSubsystemEvents();
  }

  private bindSubsystemEvents(): void {
    this.clashMonitor.on('clash-change', (reason: string) => {
      this.monitor.handleClashChangeDebounced(reason);
    });

    this.privateProxies.on('state', () => {
      if (!this.stopped) this.emitState();
    });
    this.privateProxies.on('ready', (channel: PrivateChannelId) => {
      if (this.stopped) return;
      if (channel === 'claude') {
        this.claude.handleListenerRebound();
      } else {
        this.antigravity.handleListenerRebound();
      }
    });
    this.privateProxies.on('lost', (channel: PrivateChannelId, reason: string) => {
      if (this.stopped) return;
      if (channel === 'claude') {
        this.claude.handleChannelLost(reason);
      } else {
        this.antigravity.handleChannelLost(reason);
      }
      this.logs.add('danger', `${channel}：${reason}`);
    });
    this.privateProxies.on('port-conflict', (channel: PrivateChannelId, reason: string) => {
      if (this.stopped) return;
      if (channel === 'claude') {
        this.claude.handlePortConflict(reason);
      } else {
        this.antigravity.handlePortConflict(reason);
      }
    });
    this.privateProxies.on('fault', (channel: PrivateChannelId, reason: string) => {
      if (this.stopped) return;
      this.emitSystemAlert('kernel-error', `${channel} 私有内核故障：${reason}`);
    });

    this.clashMonitor.on('catalog-updated', () => {
      for (const kernel of Object.values(this.privateProxies.channels)) {
        kernel.refreshSource(this.clashMonitor.catalog);
      }
    });
    this.clashMonitor.on('tun-enabled', () => {
      this.emitSystemAlert(
        'tun-enabled',
        '检测到 Clash Verge 已开启 TUN。当前专属代理尚未兼容 TUN 模式，Clash Verge 切换订阅、重启或退出可能影响 Claude 和 Antigravity 的连接。请关闭 TUN。'
      );
    });
    this.clashMonitor.on('clash-status-updated', () => {
      this.monitor.handleClashStatusUpdated();
    });
  }

  private emitSystemAlert(alertType: 'tun-enabled' | 'kernel-error', message: string): void {
    this.emit(
      'trigger-alert',
      buildSystemAlertPayload(
        alertType,
        message,
        this.configStore.get().alertSoundEnabled
      )
    );
  }

  private emitGuardAlert(input: GuardAlertInput): void {
    const payload: AlertPayload | null = buildGuardAlertPayload({
      input,
      cfg: this.configStore.get(),
      clash: this.clashMonitor.getRuntimeInfo(),
      claudeNodeProbe: this.claude.getNodeProbe(),
      monitorLastProbe: this.monitor.getLastProbe(),
      geoIp: this.geoIp,
      winLocale: this.winLocale,
    });
    if (payload) {
      this.emit('trigger-alert', payload);
    }
  }

  private emitState(): void {
    this.emit('state-changed', this.getSnapshot());
  }

  private async getSystemProxyFresh(force = false): Promise<SystemProxyState> {
    const now = Date.now();
    if (!force && this.cachedSysProxy && now - this.cachedSysProxy.readAt < 2500) {
      return this.cachedSysProxy.state;
    }
    const state = await readWindowsSystemProxy();
    this.cachedSysProxy = { state, readAt: Date.now() };
    return state;
  }

  private async runApplicationChange<T>(
    operation: () => Promise<T>,
    channel: PrivateChannelId | 'global' = 'global'
  ): Promise<T> {
    if (
      this.applicationChanges.has('global') ||
      this.applicationChanges.has(channel) ||
      (channel === 'global' && this.applicationChanges.size > 0)
    ) {
      throw new Error('应用启动或代理配置操作正在进行，请等待完成');
    }
    this.applicationChanges.add(channel);
    try {
      return await operation();
    } finally {
      this.applicationChanges.delete(channel);
    }
  }

  public async restorePrivateSelections(): Promise<void> {
    await this.privateProxies.restore();
    for (const channel of ['claude', 'antigravity'] as const) {
      const kernel = this.privateProxies.channels[channel];
      const cfg = this.configStore.get();
      if (kernel.getSnapshot()) {
        if (
          channel === 'claude' &&
          kernel.getIpv4Only() !== cfg.claudeForceIpv4 &&
          kernel.getState().port
        ) {
          if (this.claude.running) {
            this.logs.add(
              'warn',
              '检测到已有运行中的 Claude 会话，已暂留现有私有内核出站模式以避免中断外部会话；待 Claude 退出或下次从专栏启动前将自动应用「强制通道仅走 IPv4 出站」设置'
            );
          } else {
            this.claude.abortActiveProbe('升级 Claude 私有内核 IPv4 模式');
            try {
              await kernel.select(kernel.getSnapshot(), kernel.getState().port!, {
                ipv4Only: cfg.claudeForceIpv4,
              });
              kernel.refreshSource(this.clashMonitor.catalog);
            } catch (error) {
              const detail = error instanceof Error ? error.message : String(error);
              const message = `claude 私有内核切换 IPv4 模式失败：${detail}`;
              this.claude.setNodeProbeError(message);
              this.logs.add('danger', message);
              this.emitSystemAlert('kernel-error', message);
            }
          }
        }
        this.channels.persistPrivateSelection(channel);
        continue;
      }
      if (kernel.getState().phase !== 'idle') continue;
      const node = channel === 'claude' ? cfg.selectedClashNode : cfg.antigravityClashNode;
      if (!node) continue;
      const uid =
        channel === 'claude' ? cfg.selectedClashProfileUid : cfg.antigravityClashProfileUid;
      const port =
        channel === 'claude' ? cfg.dedicatedProxyPort : cfg.antigravityDedicatedPort;
      if (channel === 'claude') await this.claude.stopBeforeRoutingChange();
      const result = await this.channels.bindPrivateSelection(channel, node, port, uid);
      if (!result.ok) {
        const message = `${channel} 节点迁移失败：${result.error}`;
        if (channel === 'claude') this.claude.setNodeProbeError(message);
        else this.antigravity.setNodeProbeError(message);
        this.logs.add('danger', message);
        this.emitSystemAlert('kernel-error', message);
      }
    }
  }

  public ensurePrivateChannelReadyForLaunch(
    channel: PrivateChannelId
  ): Promise<{ ok: boolean; error?: string }> {
    return this.channels.ensurePrivateChannelReadyForLaunch(channel);
  }

  public async applyNodeUpdate(channel: PrivateChannelId): Promise<AppStateSnapshot> {
    return this.runApplicationChange(async () => {
      const state = this.privateProxies.channels[channel].getState();
      if (!state.nodeName || !state.profileUid || !state.port) {
        throw new Error('尚未保存专属节点');
      }
      if (channel === 'claude') {
        await this.claude.stopBeforeRoutingChange();
        this.claude.prepareManualNodeReset('手动应用节点更新');
      } else {
        this.antigravity.prepareManualNodeReset('手动应用节点更新');
      }
      const result = await this.channels.bindPrivateSelection(
        channel,
        state.nodeName,
        state.port,
        state.profileUid,
        { applyUpdate: true }
      );
      if (!result.ok) throw new Error(result.error);
      return channel === 'claude'
        ? this.claude.probeNodeNow('手动应用节点更新')
        : this.antigravity.probeNodeNow();
    }, channel);
  }

  public async restartPrivateKernel(channel: PrivateChannelId): Promise<AppStateSnapshot> {
    return this.runApplicationChange(async () => {
      if (channel === 'claude') {
        await this.claude.stopBeforeRoutingChange();
        this.claude.prepareManualNodeReset('手动重启私有内核');
      } else {
        this.antigravity.prepareManualNodeReset('手动重启私有内核');
      }
      await this.privateProxies.channels[channel].restart();
      return channel === 'claude'
        ? this.claude.probeNodeNow('手动重启私有内核')
        : this.antigravity.probeNodeNow();
    }, channel);
  }

  public async start(): Promise<void> {
    this.stopped = false;
    this.started = true;
    let cfg = this.configStore.get();
    const [sys, initialLocale, claudeInstall, claudeProc, agInstall, agProc] =
      await Promise.all([
        this.getSystemProxyFresh(true),
        readWindowsLocaleState(),
        detectClaudeInstallation(cfg.claudeExePath),
        countRunningClaudeProcesses(),
        detectAntigravityInstallation(cfg.antigravityExePath),
        inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort),
      ]);

    this.winLocale = initialLocale;
    this.claude.applyDetectedState(claudeInstall, claudeProc);
    this.antigravity.applyDetectedState(agInstall, agProc);
    this.monitor.applyInitialNetworkSnapshots(sys, getNetworkInterfaceFingerprint());

    this.clashMonitor.start();
    await this.restorePrivateSelections();
    cfg = this.configStore.get();
    this.monitor.startLocalEnvironmentWatcher();
    this.claude.startExclusiveWatcher();
    this.monitor.restartHeartbeatTimer();

    if (cfg.selectedClashNode) {
      this.claude.beginStartupExternalBaselineIfNeeded(cfg);
      void this.claude.probeNodeNow('应用启动检测 Claude 专属节点');
    }
    await this.monitor.checkNow('应用启动首次检测');
  }

  public stop(): void {
    if (this.stopped) return;
    const wasStarted = this.started;
    this.stopped = true;
    this.started = false;

    this.claude.stop(wasStarted);
    this.antigravity.stop();
    this.clashMonitor.stop();
    this.monitor.stop();
  }

  public async prepareForUpdate(): Promise<void> {
    this.stop();
    await this.privateProxies.shutdown();
  }

  public async resumeAfterUpdateFailure(): Promise<void> {
    await this.start();
  }

  public restartHeartbeatTimer(): void {
    this.monitor.restartHeartbeatTimer();
  }

  public async updateConfig(
    partial: Partial<AppConfig>,
    options?: { confirmTerminateClaude?: boolean }
  ): Promise<AppConfig> {
    return this.runApplicationChange(async () => {
      const previous = this.configStore.get();
      const requested = this.configStore.preview(partial);
      const claudeNodeOrPortChanged =
        previous.selectedClashNode !== requested.selectedClashNode ||
        previous.selectedClashProfileUid !== requested.selectedClashProfileUid ||
        previous.dedicatedProxyPort !== requested.dedicatedProxyPort;
      const claudeIpv4Changed = previous.claudeForceIpv4 !== requested.claudeForceIpv4;
      const claudeChanged = claudeNodeOrPortChanged || claudeIpv4Changed;
      const needsClaudeChannelRebuild =
        (claudeNodeOrPortChanged &&
          (Boolean(previous.selectedClashNode) || Boolean(requested.selectedClashNode))) ||
        (claudeIpv4Changed && Boolean(requested.selectedClashNode));
      const antigravityChanged =
        previous.antigravityClashNode !== requested.antigravityClashNode ||
        previous.antigravityClashProfileUid !== requested.antigravityClashProfileUid ||
        previous.antigravityDedicatedPort !== requested.antigravityDedicatedPort;

      if (needsClaudeChannelRebuild) {
        if (claudeIpv4Changed && !claudeNodeOrPortChanged && !options?.confirmTerminateClaude) {
          if (this.started) {
            await this.claude.refreshLiveProcessState();
          }
          if (this.claude.running || this.claude.authorizedSession) {
            this.emitState();
            throw new Error(
              'CLAUDE_RUNNING_CONFIRM_REQUIRED:检测到正在运行的 Claude 会话，切换 IPv4 出站模式将终止并重建代理通道，请先确认'
            );
          }
          this.claude.resetVerificationStateWithoutKilling('调整 Claude 专属代理配置');
        } else {
          await this.claude.stopBeforeRoutingChange();
        }
      }

      const rebuiltClaudeForIpv4 = Boolean(claudeIpv4Changed && requested.selectedClashNode);
      if (rebuiltClaudeForIpv4) {
        this.claude.resetProbeForModeSwitch('切换 Claude 通道 IPv4 出站模式');
        this.claude.incrementSwitchingCount();
        let bindRes: { ok: boolean; error?: string };
        try {
          bindRes = await this.channels.bindPrivateSelection(
            'claude',
            requested.selectedClashNode,
            requested.dedicatedProxyPort,
            requested.selectedClashProfileUid,
            { ipv4OnlyOverride: requested.claudeForceIpv4, persistSelection: false }
          );
        } finally {
          this.claude.decrementSwitchingCount();
        }
        if (!bindRes.ok) {
          const errText = bindRes.error || '切换 Claude 通道 IPv4 出站模式失败';
          this.claude.setNodeProbeError(errText);
          this.logs.add('danger', errText);
          this.emitState();
          throw new Error(errText);
        }
      }

      let next: AppConfig;
      try {
        const finalPartial: Partial<AppConfig> = rebuiltClaudeForIpv4
          ? {
              ...partial,
              ...(this.privateProxies.channels.claude.getState().profileName
                ? {
                    selectedClashProfileName:
                      this.privateProxies.channels.claude.getState().profileName,
                  }
                : {}),
            }
          : partial;
        next = this.configStore.update(finalPartial);
      } catch (saveError) {
        if (rebuiltClaudeForIpv4) {
          this.claude.incrementSwitchingCount();
          try {
            if (previous.selectedClashNode) {
              await this.channels.bindPrivateSelection(
                'claude',
                previous.selectedClashNode,
                previous.dedicatedProxyPort,
                previous.selectedClashProfileUid,
                { ipv4OnlyOverride: previous.claudeForceIpv4, persistSelection: false }
              );
            } else {
              await this.privateProxies.channels.claude
                .select(null, previous.dedicatedProxyPort)
                .catch(() => undefined);
            }
          } finally {
            this.claude.decrementSwitchingCount();
          }
          const detail = saveError instanceof Error ? saveError.message : String(saveError);
          const errText = `保存配置文件失败，已撤销 Claude IPv4 模式切换：${detail}`;
          this.claude.setNodeProbeError(errText);
          this.logs.add('danger', errText);
          this.emitState();
        }
        throw saveError;
      }

      if (previous.heartbeatIntervalSec !== next.heartbeatIntervalSec && this.started) {
        this.monitor.restartHeartbeatTimer();
      }

      if (claudeChanged) {
        if (claudeIpv4Changed && !next.selectedClashNode) {
          if (claudeNodeOrPortChanged) {
            await this.claude.selectClashNodeInternal(null, null);
          }
          this.logs.add(
            'info',
            next.claudeForceIpv4
              ? '已开启 Claude 通道强制仅走 IPv4 出站'
              : '已关闭 Claude 通道强制仅走 IPv4 出站（允许双栈/IPv6 节点）'
          );
          this.emitState();
        } else if (claudeIpv4Changed && next.selectedClashNode) {
          this.logs.add(
            'success',
            next.claudeForceIpv4
              ? `已开启 Claude 通道强制仅走 IPv4 出站 (127.0.0.1:${next.dedicatedProxyPort})`
              : `已关闭 Claude 通道强制仅走 IPv4 出站，允许双栈/IPv6 出站 (127.0.0.1:${next.dedicatedProxyPort})`
          );
          this.emitState();
          await this.claude.probeNodeNow(
            next.claudeForceIpv4 ? '开启 Claude 仅 IPv4 出站' : '关闭 Claude 仅 IPv4 出站'
          );
        } else {
          await this.claude.selectClashNodeInternal(
            next.selectedClashNode,
            next.selectedClashProfileUid
          );
        }
      } else if (previous.claudeLockExitIp !== next.claudeLockExitIp) {
        this.logs.add(
          'info',
          next.claudeLockExitIp
            ? '已开启 Claude 会话出口 IP 锁定（运行期出口 IP 变更将立即强杀保护）'
            : '已关闭 Claude 会话出口 IP 锁定（仍保留地区与系统时区一致性保护）'
        );
        this.emitState();
        if (next.claudeLockExitIp && this.claude.running) {
          const killed = await this.claude.enforceRunningSafety('开启 Claude 会话出口 IP 锁定');
          if (
            !killed &&
            this.claude.running &&
            next.selectedClashNode &&
            !this.claude.isProbingNode()
          ) {
            void this.claude.probeNodeNow('开启 Claude 会话出口 IP 锁定实时复核');
          }
        }
      }

      if (antigravityChanged) {
        await this.antigravity.selectClashNodeInternal(
          next.antigravityClashNode,
          next.antigravityClashProfileUid
        );
      }

      return this.configStore.get();
    });
  }

  public getSnapshot(): AppStateSnapshot {
    return {
      status: this.monitor.getStatus(),
      isChecking: this.monitor.getIsChecking(),
      isSyncingLocale: this.syncingLocale,
      config: this.configStore.get(),
      winLocale: { ...this.winLocale },
      lastProbe: this.monitor.getLastProbe() ? { ...this.monitor.getLastProbe()! } : null,
      lastError: this.monitor.getLastError(),
      clashInfo: this.clashMonitor.getRuntimeInfo(),
      privateChannels: this.privateProxies.getState(),
      claudeState: this.claude.buildRuntimeState(),
      antigravityState: this.antigravity.buildRuntimeState(),
      updateState: this.updateStateProvider
        ? this.updateStateProvider()
        : createFallbackUpdateStateSnapshot(),
      geoDbSource: this.geoIp.getSourceDescription(),
      logs: this.logs.getSnapshot(),
    };
  }

  public clearLogs(): AppStateSnapshot {
    this.logs.clear();
    this.emitState();
    return this.getSnapshot();
  }

  // --- Delegated domain operations ---

  public refreshClaudeInstallDetection(): Promise<void> {
    return this.claude.refreshInstallDetection();
  }

  public refreshAntigravityInstallDetection(): Promise<void> {
    return this.antigravity.refreshInstallDetection();
  }

  public selectAntigravityClashNode(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    return this.antigravity.selectClashNode(nodeName, profileUid);
  }

  public probeAntigravityNodeNow(): Promise<AppStateSnapshot> {
    return this.antigravity.probeNodeNow();
  }

  public launchAntigravityFromGuard(): Promise<AntigravityLaunchResult> {
    return this.antigravity.launchFromGuard();
  }

  public terminateAntigravityManually(): Promise<AntigravityLaunchResult> {
    return this.antigravity.terminateManually();
  }

  public selectClashNode(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    return this.claude.selectClashNode(nodeName, profileUid);
  }

  public probeClaudeNodeNow(
    reason?: string,
    skipSafetyEnforcement?: boolean
  ): Promise<AppStateSnapshot> {
    return this.claude.probeNodeNow(reason, skipSafetyEnforcement);
  }

  public launchClaudeFromGuard(): Promise<ClaudeLaunchResult> {
    return this.claude.launchFromGuard();
  }

  public terminateClaudeManually(): Promise<ClaudeLaunchResult> {
    return this.claude.terminateManually();
  }

  public evaluateClaudeSafety(requireDedicatedNode = true): ClaudeSafetyCheck {
    return this.claude.evaluateSafety(requireDedicatedNode);
  }

  public checkNow(reason?: string): Promise<AppStateSnapshot> {
    return this.monitor.checkNow(reason);
  }

  public evaluateStatusOnly(reason?: string): AppStateSnapshot {
    return this.monitor.evaluateStatusOnly(reason);
  }

  public shouldStopClaudeBeforeLocaleChange(
    targetCode: string,
    targetTimeZone: string
  ): boolean {
    return this.claude.shouldStopBeforeLocaleChange(targetCode, targetTimeZone);
  }

  public resolveLocaleSyncTarget(targetSource: 'monitor' | 'claude' = 'monitor') {
    return this.localeSync.resolveLocaleSyncTarget(targetSource);
  }

  public syncSystemLocaleToDefault(
    targetSource: 'monitor' | 'claude' = 'monitor'
  ): Promise<LocaleSyncResult> {
    return this.localeSync.syncSystemLocaleToDefault(targetSource);
  }

  public restoreDefaultChinaLocale(): Promise<LocaleSyncResult> {
    return this.localeSync.restoreDefaultChinaLocale();
  }

  // --- UpdaterHostAdapter implementation ---

  public setUpdateStateProvider(provider: () => UpdateStateSnapshot): void {
    this.updateStateProvider = provider;
  }

  public recordExternalLog(
    level: GuardEventLog['level'],
    message: string,
    broadcast = true
  ): void {
    this.logs.add(level, message);
    if (broadcast) {
      this.emitState();
    }
  }

  public notifyExternalStateChanged(): void {
    this.emitState();
  }

  public isClaudeActiveForUpdateInterlock(): Promise<boolean> {
    return this.claude.isActiveForUpdateInterlock();
  }

  public resolveUpdateDownloadProxies(
    targetUrl?: string
  ): Promise<Array<{ proxyUrl: string | null; label: string }>> {
    return this.monitor.resolveUpdateDownloadProxies(targetUrl);
  }
}

export { GuardCoordinator as ProbeEngine };
