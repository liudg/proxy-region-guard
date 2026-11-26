import { setTimeout as sleep } from 'node:timers/promises';
import {
  AppStateSnapshot,
  GuardStatus,
  ProbeResult,
} from '../../src/shared/types';
import { getCountryNameZh, isValidIsoCountryCode } from '../../src/shared/countries';
import { isWindowsLocaleMatchingCountry } from '../../src/shared/timezones';
import { formatHostForUrl } from '../net';
import {
  getNetworkInterfaceFingerprint,
  readWindowsLocaleState,
  SystemProxyState,
} from '../system';
import { probeOnceViaChannel, simplifyNetworkError } from '../probe';
import { buildRecoveredAlertPayload } from './alertBuilder';
import { AntigravityGuardController } from './antigravityGuardController';
import { ClaudeGuardController } from './claudeGuardController';
import { GuardRuntimeContext } from './guardTypes';

export class RealtimeMonitorController {
  private status: GuardStatus = 'checking';
  private isChecking = false;
  private pendingReason: string | null = null;
  private lastProbe: ProbeResult | null = null;
  private lastError: string | null = null;

  private heartbeatTimer: NodeJS.Timeout | null = null;
  private localEnvTimer: NodeJS.Timeout | null = null;
  private clashDebounceTimer: NodeJS.Timeout | null = null;
  private netDebounceTimer: NodeJS.Timeout | null = null;

  private envTickCounter = 0;
  private lastSysProxySnapshot = '';
  private lastNetFingerprint = '';
  private lastAlertSignature: string | null = null;
  private lastGuardFailSignature: string | null = null;

  constructor(
    private readonly ctx: GuardRuntimeContext,
    private readonly claude: ClaudeGuardController,
    private readonly antigravity: AntigravityGuardController
  ) {}

  public getStatus(): GuardStatus {
    return this.status;
  }

  public getIsChecking(): boolean {
    return this.isChecking;
  }

  public getLastProbe(): ProbeResult | null {
    return this.lastProbe;
  }

  public getLastError(): string | null {
    return this.lastError;
  }

  public resetGuardFailSignature(): void {
    this.lastGuardFailSignature = null;
  }

  public setLastAlertSignature(sig: string | null): void {
    this.lastAlertSignature = sig;
  }

  public applyInitialNetworkSnapshots(sys: SystemProxyState, netFingerprint: string): void {
    this.lastSysProxySnapshot = `${sys.enabled}|${sys.proxyUrl || ''}`;
    this.lastNetFingerprint = netFingerprint;
  }

  public handleClashChangeDebounced(reason: string): void {
    if (this.clashDebounceTimer) {
      clearTimeout(this.clashDebounceTimer);
    }
    this.clashDebounceTimer = setTimeout(() => {
      this.clashDebounceTimer = null;
      this.ctx.logs.add('info', `实时捕获事件：${reason}`);
      void this.checkNow(reason);
    }, 250);
  }

  public handleClashStatusUpdated(): void {
    const info = this.ctx.clashMonitor.getRuntimeInfo();
    this.ctx.emitState();

    if (
      info.connected &&
      (!this.lastProbe || this.status === 'error') &&
      !this.isChecking
    ) {
      if (this.clashDebounceTimer) {
        clearTimeout(this.clashDebounceTimer);
      }
      this.clashDebounceTimer = setTimeout(() => {
        this.clashDebounceTimer = null;
        void this.checkNow('Clash 控制接口已连接');
      }, 300);
    }
  }

  public restartHeartbeatTimer(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    this.claude.clearHeartbeatTimer();
    if (this.ctx.isStopped()) return;

    const sec = this.ctx.configStore.get().heartbeatIntervalSec;
    if (sec > 0) {
      this.heartbeatTimer = setInterval(() => {
        if (this.ctx.isStopped()) return;
        // 实时监控通道巡检：后台定时静默复核出口 IP 是否漂移
        void this.checkNow('轻量心跳巡检');
      }, sec * 1000);
    }

    this.claude.syncHeartbeatSchedule();
  }

  public startLocalEnvironmentWatcher(): void {
    const scheduleNext = (delayMs: number) => {
      if (this.ctx.isStopped()) return;
      if (this.localEnvTimer) {
        clearTimeout(this.localEnvTimer);
      }
      this.localEnvTimer = setTimeout(() => {
        this.localEnvTimer = null;
        void runEnvTick();
      }, delayMs);
    };

    const runEnvTick = async () => {
      if (this.ctx.isStopped()) return;
      this.envTickCounter = (this.envTickCounter + 1) % 2;
      const cfg = this.ctx.configStore.get();

      try {
        // 0. 刷新 Antigravity 进程运行状态（仅状态展示，不做任何拦截或强杀）
        const agChanged = await this.antigravity.pollRunningProcesses(
          cfg.antigravityDedicatedPort
        );
        if (agChanged) {
          this.ctx.emitState();
        }

        // 1. 每 ~7 秒同步一次外部手动修改的 Windows 时区与区域
        if (this.envTickCounter === 0 && !this.ctx.isSyncingLocale()) {
          const latestLocale = await readWindowsLocaleState();
          const currentLocale = this.ctx.getWinLocale();
          const localeChanged =
            latestLocale.timeZoneId !== currentLocale.timeZoneId ||
            latestLocale.regionCode !== currentLocale.regionCode;
          if (localeChanged) {
            this.ctx.setWinLocale(latestLocale);
            this.ctx.logs.add(
              'info',
              `检测到系统区域/时区变更：${latestLocale.regionName} (${latestLocale.regionCode}) · ${latestLocale.timeZoneDisplayName}`
            );
            if (this.claude.running) {
              await this.claude.enforceRunningSafety('系统时区或区域变更');
            }
            this.evaluateStatusOnly('系统时区或区域变更');
          }
        }

        // 2. 后台持续进程守护（通用受保护进程列表 + 实时监控默认地区校验）
        const targetCountry = this.getEffectiveTargetCountryCode();
        if (
          targetCountry &&
          cfg.killProcessesEnabled &&
          cfg.protectedProcessPatterns.length > 0
        ) {
          await this.enforceProcessGuardInBackground();
        } else {
          this.lastGuardFailSignature = null;
        }

        // 3. 持续监测系统代理与网卡路由变动，驱动实时监控自动刷新
        const sys = await this.ctx.getSystemProxyFresh(true);
        const sysSnap = `${sys.enabled}|${sys.proxyUrl || ''}`;
        if (this.lastSysProxySnapshot && sysSnap !== this.lastSysProxySnapshot) {
          this.lastSysProxySnapshot = sysSnap;
          const desc = sys.enabled ? `开启 (${sys.proxyUrl})` : '已关闭';
          this.ctx.logs.add('info', `系统代理设置变更：${desc}`);
          void this.checkNow(`系统代理变更: ${desc}`);
          scheduleNext(3500);
          return;
        }
        this.lastSysProxySnapshot = sysSnap;

        const netFp = getNetworkInterfaceFingerprint();
        if (this.lastNetFingerprint && netFp !== this.lastNetFingerprint) {
          this.lastNetFingerprint = netFp;
          if (this.netDebounceTimer) {
            clearTimeout(this.netDebounceTimer);
          }
          this.netDebounceTimer = setTimeout(() => {
            this.netDebounceTimer = null;
            this.ctx.logs.add('info', '检测到本机网络接口 / TUN 虚拟网卡变动');
            void this.checkNow('本机网卡 / TUN 路由变动');
          }, 450);
        }
      } catch {
        // ignore transient polling errors
      }

      scheduleNext(3500);
    };

    scheduleNext(3500);
  }

  /**
   * 获取【实时监控】用于对比时区/区域的基准国家代码：
   * 优先使用已锁定的 defaultCountryCode；否则以当前实时监控探测到的 Clash 选中通道国家代码为准
   */
  public getEffectiveTargetCountryCode(): string | null {
    const cfg = this.ctx.configStore.get();
    if (cfg.defaultCountryCode && isValidIsoCountryCode(cfg.defaultCountryCode)) {
      return cfg.defaultCountryCode.toUpperCase();
    }
    if (this.lastProbe && isValidIsoCountryCode(this.lastProbe.countryCode)) {
      return this.lastProbe.countryCode.toUpperCase();
    }
    return null;
  }

  public async resolveUpdateDownloadProxies(
    targetUrl?: string
  ): Promise<Array<{ proxyUrl: string | null; label: string }>> {
    if (targetUrl) {
      try {
        const parsed = new URL(targetUrl);
        const h = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
        if (h === '127.0.0.1' || h === 'localhost' || h === '::1') {
          return [{ proxyUrl: null, label: '本机回环直连' }];
        }
      } catch {
        // ignore invalid url and fall through
      }
    }

    const cfg = this.ctx.configStore.get();
    if (cfg.proxyMode === 'direct') {
      return [{ proxyUrl: null, label: '本机直连 / TUN' }];
    }

    const out: Array<{ proxyUrl: string | null; label: string }> = [];
    const seen = new Set<string>();
    const pushUnique = (proxyUrl: string | null, label: string) => {
      const key = proxyUrl || '__DIRECT__';
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ proxyUrl, label });
    };

    if (cfg.proxyMode === 'manual') {
      const scheme = cfg.manualProxy.protocol === 'socks5' ? 'socks5h' : 'http';
      const host = formatHostForUrl(cfg.manualProxy.host);
      pushUnique(
        `${scheme}://${host}:${cfg.manualProxy.port}`,
        `手动代理 (${host}:${cfg.manualProxy.port})`
      );
      return out;
    }

    const clash = this.ctx.clashMonitor.getRuntimeInfo();
    const isClashGlobalDirect = clash.mode?.trim().toLowerCase() === 'direct';
    if (clash.connected && clash.mixedPort && !isClashGlobalDirect) {
      pushUnique(
        `http://127.0.0.1:${clash.mixedPort}`,
        `Clash 混合端口 (127.0.0.1:${clash.mixedPort})`
      );
    }
    for (const [channel, kernel] of Object.entries(this.ctx.privateProxies.getState())) {
      if (kernel.phase === 'ready' && kernel.port) {
        pushUnique(`http://127.0.0.1:${kernel.port}`, `${channel} 私有代理端口`);
      }
    }

    const sys = await this.ctx.getSystemProxyFresh(false);
    const clashDirectMixedUrl =
      clash.connected && isClashGlobalDirect && clash.mixedPort
        ? `http://127.0.0.1:${clash.mixedPort}`
        : null;
    if (sys.enabled && sys.proxyUrl && sys.proxyUrl !== clashDirectMixedUrl) {
      pushUnique(sys.proxyUrl, 'Windows 系统代理');
    }

    pushUnique(null, '本机直连 / TUN');
    return out;
  }

  /**
   * 实时监控代理检测通道解析（纯粹检测 Clash 当前选中的代理通道，绝不关联启动器专属节点）：
   * 1. auto 模式下优先检测 Clash 当前选中的代理通道 (127.0.0.1:mixedPort)，未连接 Clash 时回退系统代理或默认路由
   * 2. manual / direct 模式下按用户在【设置】中指定的规则检测
   */
  public async resolveProxyChannel(): Promise<{
    proxyUrl: string | null;
    description: string;
    errorHint?: string;
  }> {
    const cfg = this.ctx.configStore.get();

    if (cfg.proxyMode === 'direct') {
      return {
        proxyUrl: null,
        description: '网卡直连 / TUN 模式',
      };
    }

    if (cfg.proxyMode === 'manual') {
      const scheme = cfg.manualProxy.protocol === 'socks5' ? 'socks5h' : 'http';
      const formattedHost = formatHostForUrl(cfg.manualProxy.host);
      const proxyUrl = `${scheme}://${formattedHost}:${cfg.manualProxy.port}`;
      return {
        proxyUrl,
        description: `手动端口 (${cfg.manualProxy.protocol.toUpperCase()} ${formattedHost}:${cfg.manualProxy.port})`,
      };
    }

    // auto 模式：优先检测 Clash 当前选中的代理通道
    const clash = this.ctx.clashMonitor.getRuntimeInfo();
    if (clash.connected) {
      if (clash.mode === 'direct') {
        return {
          proxyUrl: null,
          description: 'Clash 选中通道 [直连模式 DIRECT]',
        };
      }
      if (clash.mixedPort) {
        const activeLabel = clash.activeNode
          ? clash.activeProfileName
            ? `${clash.activeProfileName} / ${clash.activeNode}`
            : clash.activeNode
          : clash.mode.toUpperCase();
        return {
          proxyUrl: `http://127.0.0.1:${clash.mixedPort}`,
          description: `Clash 选中通道 [${activeLabel}] (127.0.0.1:${clash.mixedPort})`,
        };
      }
    }

    const sys = await this.ctx.getSystemProxyFresh(false);
    if (sys.enabled && sys.proxyUrl) {
      const cleanAddr = sys.proxyUrl.replace(/^[a-z0-9+.-]+:\/\//i, '');
      const clashNodeSuffix =
        clash.connected && clash.activeNode ? ` [${clash.activeNode}]` : '';
      return {
        proxyUrl: sys.proxyUrl,
        description: `系统代理${clashNodeSuffix} (${cleanAddr})`,
      };
    }

    if (clash.connected && clash.activeNode) {
      return {
        proxyUrl: null,
        description: `Clash TUN 路由 [${clash.activeNode}]`,
      };
    }

    return {
      proxyUrl: null,
      description: '本机默认路由 (TUN / 直连)',
    };
  }

  public evaluateStatusOnly(reason?: string): AppStateSnapshot {
    void this.applyMonitorStatus(reason || '状态更新');
    return this.ctx.getSnapshot();
  }

  private async applyMonitorStatus(
    reason: string,
    logResult = false,
    probeChanged = false
  ): Promise<void> {
    const cfg = this.ctx.configStore.get();
    const winLocale = this.ctx.getWinLocale();
    const previousStatus = this.status;
    let transition: 'disconnect' | 'mismatch' | 'locale-mismatch' | null = null;
    if (!cfg.monitorAlertEnabled) this.lastAlertSignature = null;
    if (this.lastError) {
      this.status = 'error';
      transition = 'disconnect';
    } else if (this.lastProbe) {
      const probeCode = this.lastProbe.countryCode.toUpperCase();
      const enforceLocaleMatch =
        Boolean(cfg.defaultCountryCode) ||
        cfg.monitorAlertEnabled ||
        (cfg.killProcessesEnabled &&
          cfg.killOnLocaleMismatch &&
          cfg.protectedProcessPatterns.length > 0);
      if (!isValidIsoCountryCode(probeCode)) {
        this.status = 'unset';
      } else if (cfg.defaultCountryCode && probeCode !== cfg.defaultCountryCode.toUpperCase()) {
        this.status = 'mismatch';
        transition = 'mismatch';
      } else if (
        enforceLocaleMatch &&
        !isWindowsLocaleMatchingCountry(
          winLocale.timeZoneId,
          winLocale.regionCode,
          probeCode
        )
      ) {
        this.status = 'mismatch';
        transition = 'locale-mismatch';
      } else {
        this.status = 'ok';
      }
    }

    if (!this.getEffectiveTargetCountryCode() || this.status === 'unset') {
      this.lastAlertSignature = null;
      this.lastGuardFailSignature = null;
    }
    if (
      logResult &&
      (probeChanged || previousStatus !== this.status || reason !== '轻量心跳巡检')
    ) {
      const detail =
        this.lastError ||
        (this.lastProbe
          ? `${this.lastProbe.countryName} (${this.lastProbe.countryCode}) · IP: ${this.lastProbe.ip}`
          : '尚未获得出口信息');
      const localeMatched = this.lastProbe
        ? isWindowsLocaleMatchingCountry(
            winLocale.timeZoneId,
            winLocale.regionCode,
            this.lastProbe.countryCode.toUpperCase()
          )
        : false;
      const label =
        transition === 'disconnect'
          ? '代理连接失败'
          : transition === 'mismatch'
          ? `出口偏离保护地区 [${cfg.defaultCountryName}]`
          : transition === 'locale-mismatch'
          ? '出口与系统时区/区域不一致'
          : this.status === 'ok'
          ? localeMatched
            ? '出口与系统时区/区域一致'
            : '代理出口正常（未锁定默认保护地区）'
          : '出口地区待确认';
      this.ctx.logs.add(
        this.status === 'ok' ? 'success' : transition ? 'warn' : 'info',
        `${label}：${detail}`
      );
    }
    try {
      if (transition === 'disconnect') {
        await this.handleDisconnectTransition(reason, this.lastError!);
      } else if (transition === 'mismatch') {
        await this.handleMismatchTransition(reason);
      } else if (transition === 'locale-mismatch') {
        await this.handleLocaleMismatchTransition(reason);
      } else if (this.status === 'ok') {
        if (this.lastAlertSignature !== null) {
          this.lastAlertSignature = null;
          if (cfg.monitorAlertEnabled && this.lastProbe) {
            this.ctx.emitRecoveredAlert(buildRecoveredAlertPayload(cfg, this.lastProbe));
          }
        }
        await this.enforceProcessGuardInBackground();
      }
    } finally {
      this.ctx.emitState();
    }
  }

  public async checkNow(reason = '手动立即检测'): Promise<AppStateSnapshot> {
    if (this.isChecking) {
      if (reason !== '轻量心跳巡检') {
        this.pendingReason = reason;
      }
      return this.ctx.getSnapshot();
    }

    this.isChecking = true;
    this.ctx.emitState();

    try {
      let channel = await this.resolveProxyChannel();
      const customProbeUrl = this.ctx.configStore.get().customProbeUrl;

      let probeSuccess: ProbeResult | null = null;
      let lastErrMsg = channel.errorHint || '所有回显探测源均不可达';

      if (!channel.errorHint) {
        const firstTry = await probeOnceViaChannel({
          proxyUrl: channel.proxyUrl,
          viaChannel: channel.description,
          timeoutMs: 6000,
          defaultErrMsg: '所有回显探测源均不可达',
          customProbeUrl,
          geoIp: this.ctx.geoIp,
        });
        probeSuccess = firstTry.result;
        if (!probeSuccess) {
          lastErrMsg = firstTry.errMsg;
        }
      }

      // 若恰好遇到 Clash 切换节点/订阅瞬间端口闪断，短暂等待后重新解析 Clash 选中通道重试一次
      if (!probeSuccess) {
        await sleep(300);
        channel = await this.resolveProxyChannel();
        if (!channel.errorHint) {
          const retryRes = await probeOnceViaChannel({
            proxyUrl: channel.proxyUrl,
            viaChannel: channel.description,
            timeoutMs: 6000,
            defaultErrMsg: '所有回显探测源均不可达',
            customProbeUrl: this.ctx.configStore.get().customProbeUrl,
            geoIp: this.ctx.geoIp,
          });
          probeSuccess = retryRes.result;
          if (!probeSuccess) {
            lastErrMsg = retryRes.errMsg;
          }
        }
      }

      const probeChanged =
        this.lastProbe?.ip !== probeSuccess?.ip ||
        this.lastProbe?.countryCode !== probeSuccess?.countryCode;
      if (probeSuccess) {
        this.lastProbe = probeSuccess;
        this.lastError = null;
      } else {
        this.lastError = channel.errorHint
          ? channel.errorHint
          : simplifyNetworkError(lastErrMsg, channel.description);
      }
      await this.applyMonitorStatus(reason, true, probeChanged);
    } finally {
      this.isChecking = false;
      this.ctx.emitState();

      if (this.pendingReason) {
        const nextReason = this.pendingReason;
        this.pendingReason = null;
        setTimeout(() => {
          void this.checkNow(nextReason);
        }, 150);
      }
    }

    return this.ctx.getSnapshot();
  }

  public async enforceProcessGuardInBackground(): Promise<void> {
    const cfg = this.ctx.configStore.get();
    const winLocale = this.ctx.getWinLocale();
    const targetCountry = this.getEffectiveTargetCountryCode();
    if (
      !targetCountry ||
      !cfg.killProcessesEnabled ||
      cfg.protectedProcessPatterns.length === 0 ||
      this.status === 'checking'
    ) {
      this.lastGuardFailSignature = null;
      return;
    }

    const targetCountryName = getCountryNameZh(targetCountry);
    let unsafeType: 'mismatch' | 'disconnect' | 'locale-mismatch' | null = null;
    let unsafeReason = '';

    if (
      cfg.defaultCountryCode &&
      this.lastProbe &&
      this.lastProbe.countryCode.toUpperCase() !== cfg.defaultCountryCode.toUpperCase()
    ) {
      unsafeType = 'mismatch';
      unsafeReason = `实时监控出口地区 [${this.lastProbe.countryName}] 与默认地区 [${cfg.defaultCountryName}] 不符`;
    } else if (this.status === 'error' && cfg.killOnDisconnect) {
      unsafeType = 'disconnect';
      unsafeReason = '实时监控代理连接异常断开期间禁止运行受保护进程';
    } else if (
      cfg.killOnLocaleMismatch &&
      !isWindowsLocaleMatchingCountry(
        winLocale.timeZoneId,
        winLocale.regionCode,
        targetCountry
      )
    ) {
      unsafeType = 'locale-mismatch';
      unsafeReason = `系统时区/区域 (${winLocale.regionName}) 与保护地区 (${targetCountryName}) 不一致`;
    }

    if (!unsafeType) {
      this.lastGuardFailSignature = null;
      return;
    }

    const result = await this.terminateMonitorProcesses(
      cfg.protectedProcessPatterns,
      unsafeType,
      unsafeReason
    );
    if (!result.hasKillEvent) return;

    if (unsafeType === 'locale-mismatch') {
      this.lastAlertSignature = `locale-mismatch:${targetCountry}:${winLocale.regionCode}:${winLocale.timeZoneId}`;
    }

    this.ctx.emitGuardAlert({
      source: 'monitor',
      alertType: unsafeType,
      expectedCode: targetCountry,
      expectedName: targetCountryName,
      triggerReason: unsafeReason,
      errorDetail: unsafeType === 'disconnect' ? this.lastError || undefined : undefined,
      killedProcesses: result.killedProcesses,
      killError: result.killError,
    });
  }

  private async terminateMonitorProcesses(
    patterns: string[],
    type: 'mismatch' | 'disconnect' | 'locale-mismatch',
    reason: string
  ): Promise<{ killedProcesses?: string[]; killError?: string; hasKillEvent: boolean }> {
    if (patterns.length === 0) {
      this.lastGuardFailSignature = null;
      return { hasKillEvent: false };
    }
    const report = await this.ctx.killQueue.executeSafely(patterns);
    const failSig =
      report.failedPids.length > 0 ? `${type}:${report.failedPids.join(',')}` : null;
    const newFailure = Boolean(failSig && failSig !== this.lastGuardFailSignature);
    this.lastGuardFailSignature = failSig;
    const hasKillEvent = report.killedCount > 0 || newFailure;
    if (report.killedCount > 0) {
      this.ctx.logs.add(
        'danger',
        `已终止受保护进程：${report.killedSummary.join(', ')} · ${reason}`
      );
    }
    if (newFailure && report.errorDetail) this.ctx.logs.add('warn', report.errorDetail);
    if (hasKillEvent) this.ctx.emitState();
    return {
      killedProcesses: report.killedCount > 0 ? report.killedSummary : undefined,
      killError: report.errorDetail,
      hasKillEvent,
    };
  }

  private async handleLocaleMismatchTransition(reason: string): Promise<void> {
    if (!this.lastProbe) return;
    const cfg = this.ctx.configStore.get();
    const winLocale = this.ctx.getWinLocale();
    const probeCode = this.lastProbe.countryCode.toUpperCase();
    const sig = `locale-mismatch:${probeCode}:${winLocale.regionCode}:${winLocale.timeZoneId}`;
    const prevSig = this.lastAlertSignature;

    await this.enforceProcessGuardInBackground();

    // 实时监控异常弹窗由开关 monitorAlertEnabled 控制
    if (!cfg.monitorAlertEnabled) {
      return;
    }

    // 若后台进程守护已发送告警并更新了签名，则不重复弹窗；否则在首次检测到时区/区域不匹配时弹出告警
    if (this.lastAlertSignature === sig && prevSig === sig) {
      return;
    }
    if (this.lastAlertSignature !== sig) {
      this.lastAlertSignature = sig;
      this.ctx.emitGuardAlert({
        source: 'monitor',
        alertType: 'locale-mismatch',
        expectedCode: probeCode,
        expectedName: this.lastProbe.countryName || getCountryNameZh(probeCode),
        triggerReason: `${reason}：系统时区/区域 (${winLocale.regionName}) 与 Clash 选中通道出口 (${this.lastProbe.countryName}) 不一致`,
      });
    }
  }

  private async handleMismatchTransition(reason: string): Promise<void> {
    const cfg = this.ctx.configStore.get();
    if (!cfg.defaultCountryCode || !this.lastProbe) return;

    const patternsToKill = cfg.killProcessesEnabled ? cfg.protectedProcessPatterns : [];
    const { killedProcesses, killError, hasKillEvent } =
      await this.terminateMonitorProcesses(patternsToKill, 'mismatch', reason);

    if (!cfg.monitorAlertEnabled) {
      return;
    }

    const sig = `mismatch:${cfg.defaultCountryCode}->${this.lastProbe.countryCode}`;
    const isSameSig = this.lastAlertSignature === sig;
    this.lastAlertSignature = sig;

    if (isSameSig && !hasKillEvent) {
      return;
    }

    this.ctx.emitGuardAlert({
      source: 'monitor',
      alertType: 'mismatch',
      expectedCode: cfg.defaultCountryCode,
      expectedName: cfg.defaultCountryName,
      triggerReason: reason,
      killedProcesses,
      killError,
    });
  }

  private async handleDisconnectTransition(reason: string, errDetail: string): Promise<void> {
    const cfg = this.ctx.configStore.get();
    const targetCountry = this.getEffectiveTargetCountryCode();
    if (!targetCountry) return;

    const patternsToKill =
      cfg.killProcessesEnabled && cfg.killOnDisconnect ? cfg.protectedProcessPatterns : [];
    const { killedProcesses, killError, hasKillEvent } =
      await this.terminateMonitorProcesses(patternsToKill, 'disconnect', reason);
    if (!cfg.monitorAlertEnabled || (!cfg.alertOnDisconnect && !hasKillEvent)) {
      return;
    }

    const sig = `disconnect:${targetCountry}`;
    const isSameSig = this.lastAlertSignature === sig;
    this.lastAlertSignature = sig;

    if (isSameSig && !hasKillEvent) {
      return;
    }

    this.ctx.emitGuardAlert({
      source: 'monitor',
      alertType: 'disconnect',
      expectedCode: targetCountry,
      expectedName: getCountryNameZh(targetCountry),
      triggerReason: reason,
      errorDetail: errDetail,
      killedProcesses,
      killError,
    });
  }

  public stop(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    if (this.localEnvTimer) {
      clearTimeout(this.localEnvTimer);
      this.localEnvTimer = null;
    }
    if (this.clashDebounceTimer) {
      clearTimeout(this.clashDebounceTimer);
      this.clashDebounceTimer = null;
    }
    if (this.netDebounceTimer) {
      clearTimeout(this.netDebounceTimer);
      this.netDebounceTimer = null;
    }
  }
}
