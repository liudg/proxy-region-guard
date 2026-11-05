import { EventEmitter } from 'node:events';
import * as net from 'node:net';
import {
  AlertPayload,
  AppStateSnapshot,
  GuardEventLog,
  GuardStatus,
  LocaleSyncResult,
  ProbeResult,
  WindowsLocaleState,
} from '../src/shared/types';
import {
  DEFAULT_CHINA_REGION_CODE,
  DEFAULT_CHINA_TIMEZONE_ID,
  hasOfflineTimeZoneMapping,
  isMultiTimeZoneCountry,
  isWindowsLocaleMatchingCountry,
  resolveWindowsTimeZoneForCountry,
} from '../src/shared/timezones';
import { ConfigStore } from './configStore';
import { GeoIpService } from './geoipService';
import { ClashMonitor } from './clashMonitor';
import {
  getNetworkInterfaceFingerprint,
  readWindowsSystemProxy,
  SystemProxyState,
} from './systemProxy';
import { ProcessKillReport, terminateProtectedProcesses } from './processGuard';
import {
  applyWindowsTimeZoneAndRegion,
  queryExactExitIanaTimeZone,
  readWindowsLocaleState,
} from './winSystemLocale';
import { formatHostForUrl, requestTextViaProxy } from './netClient';

interface TraceEndpoint {
  name: string;
  url: string;
  format: 'cf-trace' | 'plain-ip';
}

const BUILTIN_TRACE_ENDPOINTS: TraceEndpoint[] = [
  {
    name: 'Cloudflare Connectivity Trace',
    url: 'https://cp.cloudflare.com/cdn-cgi/trace',
    format: 'cf-trace',
  },
  {
    name: 'Cloudflare Global Trace',
    url: 'https://www.cloudflare.com/cdn-cgi/trace',
    format: 'cf-trace',
  },
  {
    name: 'AWS CheckIP',
    url: 'https://checkip.amazonaws.com',
    format: 'plain-ip',
  },
  {
    name: 'Cloudflare ICanHazIP',
    url: 'https://icanhazip.com',
    format: 'plain-ip',
  },
];

export class ProbeEngine extends EventEmitter {
  private configStore: ConfigStore;
  private geoIp: GeoIpService;
  private clashMonitor: ClashMonitor;

  private status: GuardStatus = 'checking';
  private isChecking = false;
  private isSyncingLocale = false;
  private isKillingProcesses = false;
  private pendingReason: string | null = null;
  private lastProbe: ProbeResult | null = null;
  private lastError: string | null = null;
  private winLocale: WindowsLocaleState = {
    timeZoneId: DEFAULT_CHINA_TIMEZONE_ID,
    timeZoneDisplayName: '(UTC+08:00) 北京，重庆，香港特别行政区，乌鲁木齐',
    regionCode: DEFAULT_CHINA_REGION_CODE,
    regionName: '中国',
  };
  private logs: GuardEventLog[] = [];

  private heartbeatTimer: NodeJS.Timeout | null = null;
  private localEnvTimer: NodeJS.Timeout | null = null;
  private clashDebounceTimer: NodeJS.Timeout | null = null;
  private netDebounceTimer: NodeJS.Timeout | null = null;

  private cachedSysProxy: { state: SystemProxyState; readAt: number } | null = null;
  private envTickCounter = 0;
  private lastSysProxySnapshot = '';
  private lastNetFingerprint = '';
  private lastAlertSignature: string | null = null;
  private lastGuardFailSignature: string | null = null;

  constructor(configStore: ConfigStore, geoIp: GeoIpService, clashMonitor: ClashMonitor) {
    super();
    this.configStore = configStore;
    this.geoIp = geoIp;
    this.clashMonitor = clashMonitor;

    this.clashMonitor.on('clash-change', (reason: string) => {
      if (this.clashDebounceTimer) {
        clearTimeout(this.clashDebounceTimer);
      }
      // 合并短时间内的连续节点切换，并留出 250ms 内部路由生效时间后校验出口
      this.clashDebounceTimer = setTimeout(() => {
        this.clashDebounceTimer = null;
        this.addLog('info', `实时捕获事件：${reason}`);
        void this.checkNow(reason);
      }, 250);
    });

    this.clashMonitor.on('clash-status-updated', () => {
      const info = this.clashMonitor.getRuntimeInfo();
      this.addLog(
        'info',
        `已连接 Clash 控制接口 (${info.source})，当前节点: ${info.activeNode || '未知'}`
      );
      this.emitState();

      // Clash 首次就绪或重启恢复后自动重测一次出口（避免仅事件模式下状态滞留）
      if (this.clashDebounceTimer) {
        clearTimeout(this.clashDebounceTimer);
      }
      this.clashDebounceTimer = setTimeout(() => {
        this.clashDebounceTimer = null;
        void this.checkNow('Clash 控制接口已连接');
      }, 300);
    });
  }

  public async start(): Promise<void> {
    const [sys, initialLocale] = await Promise.all([
      this.getSystemProxyFresh(true),
      readWindowsLocaleState(),
    ]);
    this.winLocale = initialLocale;
    this.lastSysProxySnapshot = `${sys.enabled}|${sys.proxyUrl || ''}`;
    this.lastNetFingerprint = getNetworkInterfaceFingerprint();

    this.clashMonitor.start();
    this.startLocalEnvironmentWatcher();
    this.restartHeartbeatTimer();

    await this.checkNow('应用启动首次检测');
  }

  public stop(): void {
    this.clashMonitor.stop();
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    if (this.localEnvTimer) {
      clearInterval(this.localEnvTimer);
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

  public restartHeartbeatTimer(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    const sec = this.configStore.get().heartbeatIntervalSec;
    if (sec > 0) {
      this.heartbeatTimer = setInterval(() => {
        void this.checkNow('轻量心跳巡检');
      }, sec * 1000);
    }
  }

  private async getSystemProxyFresh(force = false): Promise<SystemProxyState> {
    const now = Date.now();
    if (!force && this.cachedSysProxy && now - this.cachedSysProxy.readAt < 1500) {
      return this.cachedSysProxy.state;
    }
    const state = await readWindowsSystemProxy();
    this.cachedSysProxy = { state, readAt: Date.now() };
    return state;
  }

  private startLocalEnvironmentWatcher(): void {
    this.localEnvTimer = setInterval(async () => {
      this.envTickCounter = (this.envTickCounter + 1) % 3;
      const cfg = this.configStore.get();

      try {
        // 1. 每 6 秒（3 个周期）同步一次外部手动修改的 Windows 时区与区域，降低子进程开销
        if (this.envTickCounter === 0 && !this.isSyncingLocale) {
          const latestLocale = await readWindowsLocaleState();
          const localeChanged =
            latestLocale.timeZoneId !== this.winLocale.timeZoneId ||
            latestLocale.regionCode !== this.winLocale.regionCode;
          if (localeChanged) {
            this.winLocale = latestLocale;
            this.checkLocaleAlertRecovery(cfg.defaultCountryCode);
            this.emitState();
          }
        }

        // 2. 仅当已锁定默认地区且开启了进程守护规则时，执行异常态持续拦截
        if (
          cfg.defaultCountryCode &&
          cfg.killProcessesEnabled &&
          cfg.protectedProcessPatterns.length > 0
        ) {
          await this.enforceProcessGuardInBackground();
        } else {
          this.lastGuardFailSignature = null;
        }

        // 3. 系统代理与网卡路由监测
        const sys = await this.getSystemProxyFresh(true);
        const sysSnap = `${sys.enabled}|${sys.proxyUrl || ''}`;
        if (this.lastSysProxySnapshot && sysSnap !== this.lastSysProxySnapshot) {
          this.lastSysProxySnapshot = sysSnap;
          const desc = sys.enabled ? `开启 (${sys.proxyUrl})` : '已关闭';
          this.addLog('info', `系统代理设置变更：${desc}`);
          void this.checkNow(`系统代理变更: ${desc}`);
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
            this.addLog('info', '检测到本机网络接口 / TUN 虚拟网卡变动');
            void this.checkNow('本机网卡 / TUN 路由变动');
          }, 450);
        }
      } catch {
        // ignore transient polling errors
      }
    }, 2000);
  }

  public getSnapshot(): AppStateSnapshot {
    return {
      status: this.status,
      isChecking: this.isChecking,
      isSyncingLocale: this.isSyncingLocale,
      config: this.configStore.get(),
      winLocale: structuredClone(this.winLocale),
      lastProbe: this.lastProbe ? structuredClone(this.lastProbe) : null,
      lastError: this.lastError,
      clashInfo: this.clashMonitor.getRuntimeInfo(),
      geoDbSource: this.geoIp.getSourceDescription(),
      logs: [...this.logs],
    };
  }

  public clearLogs(): AppStateSnapshot {
    this.logs = [];
    this.emitState();
    return this.getSnapshot();
  }

  public evaluateStatusOnly(reason?: string): AppStateSnapshot {
    const cfg = this.configStore.get();

    // 若最新一次探测为失败（this.lastError 非空），绝不能被上次历史缓存的 lastProbe 误洗白为 ok
    if (this.lastError) {
      this.status = 'error';
      if (!cfg.defaultCountryCode) {
        this.lastAlertSignature = null;
        this.lastGuardFailSignature = null;
      } else {
        void this.handleDisconnectTransition(reason || '默认地区配置更新', this.lastError);
      }
      this.emitState();
      return this.getSnapshot();
    }

    if (this.lastProbe) {
      if (!cfg.defaultCountryCode) {
        this.status = 'unset';
        this.lastAlertSignature = null;
        this.lastGuardFailSignature = null;
      } else if (this.lastProbe.countryCode === cfg.defaultCountryCode) {
        this.status = 'ok';
        if (
          this.lastAlertSignature !== null &&
          !this.lastAlertSignature.startsWith('locale-mismatch:')
        ) {
          this.lastAlertSignature = null;
          this.emitRecoveredAlert();
        }
        this.checkLocaleAlertRecovery(cfg.defaultCountryCode);
      } else {
        this.status = 'mismatch';
        void this.handleMismatchTransition(reason || '默认地区配置更新');
        this.emitState();
        return this.getSnapshot();
      }
    }

    if (cfg.defaultCountryCode) {
      void this.enforceProcessGuardInBackground();
    } else {
      this.lastGuardFailSignature = null;
    }

    this.emitState();
    return this.getSnapshot();
  }

  public async checkNow(reason = '手动立即检测'): Promise<AppStateSnapshot> {
    if (this.isChecking) {
      if (reason !== '轻量心跳巡检') {
        this.pendingReason = reason;
      }
      return this.getSnapshot();
    }

    this.isChecking = true;
    this.emitState();

    try {
      const channel = await this.resolveProxyChannel();
      const endpoints = this.buildEndpointsList();

      let probeSuccess: ProbeResult | null = null;
      let lastErrMsg = '所有回显探测源均不可达';

      for (const ep of endpoints) {
        try {
          const startedAt = Date.now();
          const rawBody = await requestTextViaProxy(ep.url, channel.proxyUrl, 6000);
          const latencyMs = Date.now() - startedAt;

          const parsed = parseTraceResponse(rawBody, ep.format);
          if (!parsed.ip) {
            throw new Error('响应中未解析到有效公网 IP');
          }

          const geo = this.geoIp.lookup(parsed.ip, parsed.loc);
          probeSuccess = {
            ip: parsed.ip,
            countryCode: geo.countryCode,
            countryName: geo.countryName,
            edgeLoc: parsed.loc,
            viaChannel: channel.description,
            latencyMs,
            checkedAt: Date.now(),
          };
          break;
        } catch (err) {
          lastErrMsg = err instanceof Error ? err.message : String(err);
        }
      }

      const cfg = this.configStore.get();

      if (probeSuccess) {
        const prevIp = this.lastProbe?.ip;
        const prevCountry = this.lastProbe?.countryCode;

        this.lastProbe = probeSuccess;
        this.lastError = null;

        if (!cfg.defaultCountryCode) {
          this.status = 'unset';
          this.lastAlertSignature = null;
          this.lastGuardFailSignature = null;
          if (prevIp !== probeSuccess.ip || prevCountry !== probeSuccess.countryCode) {
            this.addLog(
              'info',
              `当前出口: ${probeSuccess.countryName} (${probeSuccess.countryCode}) · ${probeSuccess.ip}`
            );
          }
        } else if (probeSuccess.countryCode === cfg.defaultCountryCode) {
          const wasAbnormal = this.status === 'mismatch' || this.status === 'error';
          this.status = 'ok';
          if (
            wasAbnormal ||
            prevIp !== probeSuccess.ip ||
            prevCountry !== probeSuccess.countryCode
          ) {
            this.addLog(
              'success',
              `地区正常 [${probeSuccess.countryName}] · IP: ${probeSuccess.ip} (${probeSuccess.latencyMs}ms)`
            );
          }
          if (
            this.lastAlertSignature !== null &&
            !this.lastAlertSignature.startsWith('locale-mismatch:')
          ) {
            this.lastAlertSignature = null;
            this.emitRecoveredAlert();
          }
          this.checkLocaleAlertRecovery(cfg.defaultCountryCode);
          await this.enforceProcessGuardInBackground();
        } else {
          this.status = 'mismatch';
          if (
            prevIp !== probeSuccess.ip ||
            prevCountry !== probeSuccess.countryCode ||
            reason !== '轻量心跳巡检'
          ) {
            this.addLog(
              'danger',
              `地区不匹配！期望 [${cfg.defaultCountryName}]，实际为 [${probeSuccess.countryName} (${probeSuccess.countryCode})] · IP: ${probeSuccess.ip}`
            );
          }
          await this.handleMismatchTransition(reason);
        }
      } else {
        this.lastError = simplifyNetworkError(lastErrMsg, channel.description);
        this.status = 'error';
        this.addLog('warn', `代理检测失败：${this.lastError}`);
        await this.handleDisconnectTransition(reason, this.lastError);
      }
    } finally {
      this.isChecking = false;
      this.emitState();

      if (this.pendingReason) {
        const nextReason = this.pendingReason;
        this.pendingReason = null;
        setTimeout(() => {
          void this.checkNow(nextReason);
        }, 150);
      }
    }

    return this.getSnapshot();
  }

  /**
   * 根据默认保护地区一键设置 Windows 时区与区域
   * 单一时区国家 0ms 纯离线完成；仅多时区大国（美/加/澳/俄等）或未知冷门国联网探测城市级时区
   */
  public async syncSystemLocaleToDefault(): Promise<LocaleSyncResult> {
    const cfg = this.configStore.get();
    if (!cfg.defaultCountryCode) {
      return {
        ok: false,
        message: '请先设置“默认保护地区”后再执行一键同步',
        killedProcesses: [],
        state: this.getSnapshot(),
      };
    }

    const targetCode = cfg.defaultCountryCode.toUpperCase();
    this.isSyncingLocale = true;
    this.emitState();

    try {
      let exactIanaTz: string | null = null;
      const needsCityTzLookup =
        isMultiTimeZoneCountry(targetCode) || !hasOfflineTimeZoneMapping(targetCode);

      if (needsCityTzLookup && this.lastProbe && this.lastProbe.countryCode === targetCode) {
        const ch = await this.resolveProxyChannel();
        exactIanaTz = await queryExactExitIanaTimeZone(ch.proxyUrl, targetCode);
      }

      const resolved = resolveWindowsTimeZoneForCountry(targetCode, exactIanaTz);
      const applyRes = await applyWindowsTimeZoneAndRegion(resolved.windowsTimeZoneId, targetCode);
      this.winLocale = applyRes.updated;

      if (!applyRes.ok) {
        const errMsg = applyRes.error || '修改系统时区或区域失败';
        this.addLog('warn', `一键同步时区/区域失败：${errMsg}`);
        return {
          ok: false,
          message: errMsg,
          killedProcesses: [],
          state: this.getSnapshot(),
        };
      }

      this.lastGuardFailSignature = null;
      this.checkLocaleAlertRecovery(targetCode);

      const detailNote =
        resolved.fromExactIp && exactIanaTz ? `（精确匹配城市时区 ${exactIanaTz}）` : '';
      const okMsg = `已同步 Windows 区域为 [${applyRes.updated.regionName}]，时区为 [${applyRes.updated.timeZoneDisplayName}]${detailNote}`;
      this.addLog('success', okMsg);

      return {
        ok: true,
        message: okMsg,
        killedProcesses: [],
        state: this.getSnapshot(),
      };
    } finally {
      this.isSyncingLocale = false;
      this.emitState();
    }
  }

  /**
   * 还原回默认中国时区与区域（UTC+08:00 北京时间 + 区域“中国”）
   * 若与当前出口 IP 或默认地区不一致，严格执行“先强杀受保护进程并确认全部退出后，才允许切换回中国时区”
   */
  public async restoreDefaultChinaLocale(): Promise<LocaleSyncResult> {
    const cfg = this.configStore.get();
    this.isSyncingLocale = true;
    this.emitState();

    const killedProcesses: string[] = [];

    try {
      const ipCountry =
        this.lastProbe?.countryCode && this.lastProbe.countryCode !== 'UNKNOWN'
          ? this.lastProbe.countryCode.toUpperCase()
          : null;
      const defCountry = cfg.defaultCountryCode ? cfg.defaultCountryCode.toUpperCase() : null;

      const mismatchWithCurrentEnv =
        (ipCountry !== null && ipCountry !== DEFAULT_CHINA_REGION_CODE) ||
        (defCountry !== null && defCountry !== DEFAULT_CHINA_REGION_CODE);

      // 第一步：在切回中国时区之前，先强杀受保护进程树；若有任何目标进程存活，立即中止还原！
      if (
        mismatchWithCurrentEnv &&
        cfg.killProcessesEnabled &&
        cfg.protectedProcessPatterns.length > 0
      ) {
        const killReport = await this.executeProcessKillSafely(cfg.protectedProcessPatterns);
        if (killReport.killedCount > 0) {
          killedProcesses.push(...killReport.killedSummary);
          this.addLog(
            'danger',
            `还原中国时区前检测到地区不一致，已先行强杀进程：${killReport.killedSummary.join(', ')}`
          );
        }

        if (killReport.failedPids.length > 0) {
          const abortMsg = `${
            killReport.errorDetail || '部分受保护进程无法终止'
          }，已中止还原中国时区以防暴露！`;
          this.addLog('danger', abortMsg);

          if (cfg.alertPopupEnabled) {
            const expectedCode = defCountry || ipCountry || DEFAULT_CHINA_REGION_CODE;
            const expectedName =
              cfg.defaultCountryName || this.lastProbe?.countryName || expectedCode;
            this.emit('trigger-alert', {
              alertType: 'locale-mismatch',
              expectedCode,
              expectedName,
              actualCode: this.lastProbe?.countryCode || null,
              actualName: this.lastProbe?.countryName || null,
              actualIp: this.lastProbe?.ip || null,
              triggerReason: '还原中国时区被安全拦截（受保护进程未能终止）',
              killedProcesses: killedProcesses.length > 0 ? killedProcesses : undefined,
              killError: killReport.errorDetail,
              sysRegionCode: this.winLocale.regionCode,
              sysRegionName: this.winLocale.regionName,
              sysTimeZoneDisplay: this.winLocale.timeZoneDisplayName,
              soundEnabled: cfg.alertSoundEnabled,
              timestamp: Date.now(),
            } satisfies AlertPayload);
          }

          return {
            ok: false,
            message: abortMsg,
            killedProcesses,
            state: this.getSnapshot(),
          };
        }

        if (killReport.killedCount > 0) {
          await sleep(80);
        }
      }

      // 第二步：确认无残留受保护进程后，还原 Windows 时区与区域至默认中国状态
      const applyRes = await applyWindowsTimeZoneAndRegion(
        DEFAULT_CHINA_TIMEZONE_ID,
        DEFAULT_CHINA_REGION_CODE
      );
      this.winLocale = applyRes.updated;

      if (!applyRes.ok) {
        const errMsg = applyRes.error || '还原默认时区失败';
        this.addLog('warn', `还原默认时区/区域失败：${errMsg}`);
        return {
          ok: false,
          message: errMsg,
          killedProcesses,
          state: this.getSnapshot(),
        };
      }

      const killedSuffix =
        killedProcesses.length > 0 ? `（已先行终止：${killedProcesses.join(', ')}）` : '';
      const okMsg = `已还原为默认时区 [${applyRes.updated.timeZoneDisplayName}] · 区域 [${applyRes.updated.regionName}]${killedSuffix}`;
      this.addLog('info', okMsg);

      if (killedProcesses.length > 0 && cfg.alertPopupEnabled) {
        const expectedCode = defCountry || ipCountry || DEFAULT_CHINA_REGION_CODE;
        const expectedName =
          cfg.defaultCountryName || this.lastProbe?.countryName || expectedCode;
        this.lastAlertSignature = `locale-mismatch:${expectedCode}`;
        this.emit('trigger-alert', {
          alertType: 'locale-mismatch',
          expectedCode,
          expectedName,
          actualCode: this.lastProbe?.countryCode || null,
          actualName: this.lastProbe?.countryName || null,
          actualIp: this.lastProbe?.ip || null,
          triggerReason: '手动还原中国时区（与保护地区不一致，已先行强杀进程）',
          killedProcesses,
          sysRegionCode: this.winLocale.regionCode,
          sysRegionName: this.winLocale.regionName,
          sysTimeZoneDisplay: this.winLocale.timeZoneDisplayName,
          soundEnabled: cfg.alertSoundEnabled,
          timestamp: Date.now(),
        } satisfies AlertPayload);
      }

      return {
        ok: true,
        message: okMsg,
        killedProcesses,
        state: this.getSnapshot(),
      };
    } finally {
      this.isSyncingLocale = false;
      this.emitState();
    }
  }

  private checkLocaleAlertRecovery(defaultCountryCode: string | null): void {
    if (
      defaultCountryCode &&
      this.status === 'ok' &&
      this.lastAlertSignature?.startsWith('locale-mismatch:') &&
      isWindowsLocaleMatchingCountry(
        this.winLocale.timeZoneId,
        this.winLocale.regionCode,
        defaultCountryCode
      )
    ) {
      this.lastAlertSignature = null;
      this.emitRecoveredAlert();
    }
  }

  private async executeProcessKillSafely(patterns: string[]): Promise<ProcessKillReport> {
    if (this.isKillingProcesses) {
      return {
        killedSummary: [],
        killedCount: 0,
        failedSummary: [],
        failedPids: [],
        accessDenied: false,
      };
    }
    this.isKillingProcesses = true;
    try {
      return await terminateProtectedProcesses(patterns);
    } finally {
      this.isKillingProcesses = false;
    }
  }

  /**
   * 后台持续巡检：仅当已设置默认保护地区，且处于 IP 地区不符、断连、或系统时区/区域不符期间，拦截受保护进程重开
   */
  private async enforceProcessGuardInBackground(): Promise<void> {
    const cfg = this.configStore.get();
    if (
      !cfg.defaultCountryCode ||
      !cfg.killProcessesEnabled ||
      cfg.protectedProcessPatterns.length === 0 ||
      this.status === 'checking'
    ) {
      this.lastGuardFailSignature = null;
      return;
    }

    let unsafeType: 'mismatch' | 'disconnect' | 'locale-mismatch' | null = null;
    let unsafeReason = '';

    if (this.status === 'mismatch') {
      unsafeType = 'mismatch';
      unsafeReason = `出口地区 [${this.lastProbe?.countryName}] 与默认地区 [${cfg.defaultCountryName}] 不符`;
    } else if (this.status === 'error' && cfg.killOnDisconnect) {
      unsafeType = 'disconnect';
      unsafeReason = '代理连接异常断开期间禁止运行受保护进程';
    } else if (
      cfg.killOnLocaleMismatch &&
      !isWindowsLocaleMatchingCountry(
        this.winLocale.timeZoneId,
        this.winLocale.regionCode,
        cfg.defaultCountryCode
      )
    ) {
      unsafeType = 'locale-mismatch';
      unsafeReason = `系统时区/区域 (${this.winLocale.regionName}) 与默认保护地区 (${cfg.defaultCountryName}) 不一致`;
    }

    if (!unsafeType) {
      this.lastGuardFailSignature = null;
      return;
    }

    const report = await this.executeProcessKillSafely(cfg.protectedProcessPatterns);
    if (report.killedCount === 0 && report.failedPids.length === 0) {
      this.lastGuardFailSignature = null;
      return;
    }

    // 若没有任何新进程被杀，仅存在同一批因权限不足无法终止的存活 PID，抑制每 2 秒重复刷屏弹窗
    const failSig =
      report.failedPids.length > 0 ? `${unsafeType}:${report.failedPids.join(',')}` : null;
    if (report.killedCount === 0 && failSig && failSig === this.lastGuardFailSignature) {
      return;
    }
    this.lastGuardFailSignature = failSig;

    if (report.killedCount > 0) {
      this.addLog(
        'danger',
        `已自动强杀进程：${report.killedSummary.join(', ')} · 原因：${unsafeReason}`
      );
    }
    if (report.errorDetail) {
      this.addLog('warn', report.errorDetail);
    }
    this.emitState();

    if (unsafeType === 'locale-mismatch') {
      this.lastAlertSignature = `locale-mismatch:${cfg.defaultCountryCode}`;
    }

    if (cfg.alertPopupEnabled) {
      const clash = this.clashMonitor.getRuntimeInfo();
      const payload: AlertPayload = {
        alertType: unsafeType,
        expectedCode: cfg.defaultCountryCode,
        expectedName: cfg.defaultCountryName,
        actualCode: unsafeType === 'disconnect' ? null : this.lastProbe?.countryCode || null,
        actualName: unsafeType === 'disconnect' ? '连接断开' : this.lastProbe?.countryName || null,
        actualIp: unsafeType === 'disconnect' ? null : this.lastProbe?.ip || null,
        edgeLoc: this.lastProbe?.edgeLoc,
        viaChannel: this.lastProbe?.viaChannel,
        activeNode: clash.connected ? clash.activeNode : null,
        triggerReason: unsafeReason,
        errorDetail: unsafeType === 'disconnect' ? this.lastError || undefined : undefined,
        killedProcesses: report.killedCount > 0 ? report.killedSummary : undefined,
        killError: report.errorDetail,
        sysRegionCode: this.winLocale.regionCode,
        sysRegionName: this.winLocale.regionName,
        sysTimeZoneDisplay: this.winLocale.timeZoneDisplayName,
        soundEnabled: cfg.alertSoundEnabled,
        timestamp: Date.now(),
      };
      this.emit('trigger-alert', payload);
    }
  }

  private async handleMismatchTransition(reason: string): Promise<void> {
    const cfg = this.configStore.get();
    if (!cfg.defaultCountryCode || !this.lastProbe) return;

    let killedProcesses: string[] | undefined;
    let killError: string | undefined;
    let addedLogs = false;

    if (cfg.killProcessesEnabled && cfg.protectedProcessPatterns.length > 0) {
      const report = await this.executeProcessKillSafely(cfg.protectedProcessPatterns);
      if (report.killedCount > 0) {
        killedProcesses = report.killedSummary;
        this.addLog(
          'danger',
          `地区变更保护已触发，强杀进程：${report.killedSummary.join(', ')}`
        );
        addedLogs = true;
      }
      if (report.errorDetail) {
        killError = report.errorDetail;
        this.lastGuardFailSignature = `mismatch:${report.failedPids.join(',')}`;
        this.addLog('warn', report.errorDetail);
        addedLogs = true;
      }
    }

    if (addedLogs) {
      this.emitState();
    }

    const sig = `mismatch:${cfg.defaultCountryCode}->${this.lastProbe.countryCode}`;
    const isSameSig = this.lastAlertSignature === sig;
    this.lastAlertSignature = sig;

    if (isSameSig && (!killedProcesses || killedProcesses.length === 0) && !killError) {
      return;
    }

    if (!cfg.alertPopupEnabled) return;

    const clash = this.clashMonitor.getRuntimeInfo();
    const payload: AlertPayload = {
      alertType: 'mismatch',
      expectedCode: cfg.defaultCountryCode,
      expectedName: cfg.defaultCountryName,
      actualCode: this.lastProbe.countryCode,
      actualName: this.lastProbe.countryName,
      actualIp: this.lastProbe.ip,
      edgeLoc: this.lastProbe.edgeLoc,
      viaChannel: this.lastProbe.viaChannel,
      activeNode: clash.connected ? clash.activeNode : null,
      triggerReason: reason,
      killedProcesses,
      killError,
      soundEnabled: cfg.alertSoundEnabled,
      timestamp: Date.now(),
    };

    this.emit('trigger-alert', payload);
  }

  private async handleDisconnectTransition(reason: string, errDetail: string): Promise<void> {
    const cfg = this.configStore.get();
    if (!cfg.defaultCountryCode) return;

    let killedProcesses: string[] | undefined;
    let killError: string | undefined;
    let addedLogs = false;

    if (
      cfg.killProcessesEnabled &&
      cfg.killOnDisconnect &&
      cfg.protectedProcessPatterns.length > 0
    ) {
      const report = await this.executeProcessKillSafely(cfg.protectedProcessPatterns);
      if (report.killedCount > 0) {
        killedProcesses = report.killedSummary;
        this.addLog(
          'danger',
          `代理断连保护已触发，强杀进程：${report.killedSummary.join(', ')}`
        );
        addedLogs = true;
      }
      if (report.errorDetail) {
        killError = report.errorDetail;
        this.lastGuardFailSignature = `disconnect:${report.failedPids.join(',')}`;
        this.addLog('warn', report.errorDetail);
        addedLogs = true;
      }
    }

    if (addedLogs) {
      this.emitState();
    }

    if (!cfg.alertOnDisconnect) return;

    const sig = `disconnect:${cfg.defaultCountryCode}`;
    const isSameSig = this.lastAlertSignature === sig;
    this.lastAlertSignature = sig;

    if (isSameSig && (!killedProcesses || killedProcesses.length === 0) && !killError) {
      return;
    }

    if (!cfg.alertPopupEnabled) return;

    const clash = this.clashMonitor.getRuntimeInfo();
    const payload: AlertPayload = {
      alertType: 'disconnect',
      expectedCode: cfg.defaultCountryCode,
      expectedName: cfg.defaultCountryName,
      actualCode: null,
      actualName: '连接断开',
      actualIp: null,
      activeNode: clash.connected ? clash.activeNode : null,
      triggerReason: reason,
      errorDetail: errDetail,
      killedProcesses,
      killError,
      soundEnabled: cfg.alertSoundEnabled,
      timestamp: Date.now(),
    };

    this.emit('trigger-alert', payload);
  }

  private emitRecoveredAlert(): void {
    const cfg = this.configStore.get();
    if (!this.lastProbe) return;
    const payload: AlertPayload = {
      alertType: 'recovered',
      expectedCode: cfg.defaultCountryCode,
      expectedName: cfg.defaultCountryName,
      actualCode: this.lastProbe.countryCode,
      actualName: this.lastProbe.countryName,
      actualIp: this.lastProbe.ip,
      viaChannel: this.lastProbe.viaChannel,
      triggerReason: '已恢复至默认地区',
      soundEnabled: false,
      timestamp: Date.now(),
    };
    this.emit('alert-recovered', payload);
  }

  private buildEndpointsList(): TraceEndpoint[] {
    const custom = this.configStore.get().customProbeUrl.trim();
    const list: TraceEndpoint[] = [];
    if (custom) {
      list.push({
        name: '自定义探测源',
        url: custom,
        format: custom.includes('cdn-cgi/trace') ? 'cf-trace' : 'plain-ip',
      });
    }
    list.push(...BUILTIN_TRACE_ENDPOINTS);
    return list;
  }

  private async resolveProxyChannel(): Promise<{ proxyUrl: string | null; description: string }> {
    const cfg = this.configStore.get();

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

    // auto 模式：严格遵循操作系统实际全局出口（系统代理优先，系统代理关闭时走默认网卡路由检测 TUN / 直连，绝不借道闲置本地端口造成漏报）
    const sys = await this.getSystemProxyFresh(false);
    if (sys.enabled && sys.proxyUrl) {
      const cleanAddr = sys.proxyUrl.replace(/^[a-z0-9+.-]+:\/\//i, '');
      return {
        proxyUrl: sys.proxyUrl,
        description: `系统代理 (${cleanAddr})`,
      };
    }

    return {
      proxyUrl: null,
      description: '本机默认路由 (TUN / 直连)',
    };
  }

  private addLog(level: GuardEventLog['level'], message: string): void {
    const entry: GuardEventLog = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: Date.now(),
      level,
      message,
    };
    this.logs.unshift(entry);
    if (this.logs.length > 60) {
      this.logs.length = 60;
    }
  }

  private emitState(): void {
    this.emit('state-changed', this.getSnapshot());
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseTraceResponse(
  raw: string,
  format: 'cf-trace' | 'plain-ip'
): { ip: string | null; loc?: string } {
  const text = raw.trim();
  if (format === 'cf-trace' || /^ip=/m.test(text)) {
    let ip: string | null = null;
    let loc: string | undefined;
    for (const line of text.split(/\r?\n/)) {
      const idx = line.indexOf('=');
      if (idx <= 0) continue;
      const k = line.slice(0, idx).trim();
      const v = line.slice(idx + 1).trim();
      if (k === 'ip' && net.isIP(v)) {
        ip = v;
      } else if (k === 'loc' && v) {
        loc = v.toUpperCase();
      }
    }
    return { ip, loc };
  }

  if (net.isIP(text)) {
    return { ip: text };
  }
  try {
    const obj = JSON.parse(text) as Record<string, unknown>;
    const candidate = String(obj['ip'] || obj['query'] || '').trim();
    if (net.isIP(candidate)) {
      return { ip: candidate };
    }
  } catch {
    const firstLine = text.split(/\r?\n/)[0]?.trim() || '';
    if (net.isIP(firstLine)) {
      return { ip: firstLine };
    }
  }
  return { ip: null };
}

function simplifyNetworkError(errMsg: string, channelDesc: string): string {
  if (errMsg.includes('ECONNREFUSED')) {
    return `代理端口拒绝连接 (${channelDesc})，请检查 VPN/Clash 是否已启动`;
  }
  if (errMsg.includes('超时') || errMsg.includes('ETIMEDOUT') || errMsg.includes('Timeout')) {
    return `经由 [${channelDesc}] 访问超时，当前代理节点可能已失效`;
  }
  if (errMsg.includes('ENOTFOUND')) {
    return `DNS 解析失败 (${channelDesc})，网络连接异常`;
  }
  return `${errMsg} (${channelDesc})`;
}
