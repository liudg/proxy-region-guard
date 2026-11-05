import { EventEmitter } from 'node:events';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
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
  isWindowsLocaleMatchingCountry,
  resolveWindowsTimeZoneForCountry,
} from '../src/shared/timezones';
import { ConfigStore } from './configStore';
import { GeoIpService } from './geoipService';
import { ClashMonitor } from './clashMonitor';
import { getNetworkInterfaceFingerprint, readWindowsSystemProxy } from './systemProxy';
import { ProcessKillReport, terminateProtectedProcesses } from './processGuard';
import {
  applyWindowsTimeZoneAndRegion,
  queryExactExitIanaTimeZone,
  readWindowsLocaleState,
} from './winSystemLocale';

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
  private lastTriggerReason = '初始化启动检测';
  private systemProxyUrl: string | null = null;
  private winLocale: WindowsLocaleState = {
    timeZoneId: DEFAULT_CHINA_TIMEZONE_ID,
    timeZoneDisplayName: '(UTC+08:00) 北京，重庆，香港特别行政区，乌鲁木齐',
    regionCode: DEFAULT_CHINA_REGION_CODE,
    regionName: '中国',
    geoId: '45',
  };
  private logs: GuardEventLog[] = [];

  private heartbeatTimer: NodeJS.Timeout | null = null;
  private localEnvTimer: NodeJS.Timeout | null = null;
  private lastSysProxySnapshot = '';
  private lastNetFingerprint = '';
  private lastAlertSignature: string | null = null;

  constructor(configStore: ConfigStore, geoIp: GeoIpService, clashMonitor: ClashMonitor) {
    super();
    this.configStore = configStore;
    this.geoIp = geoIp;
    this.clashMonitor = clashMonitor;

    this.clashMonitor.on('clash-change', (reason: string) => {
      this.addLog('info', `实时捕获事件：${reason}`);
      // 给 Clash 节点切换留出 250ms 内部路由生效时间后立即校验出口
      setTimeout(() => {
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
    });
  }

  public async start(): Promise<void> {
    const [sys, initialLocale] = await Promise.all([
      readWindowsSystemProxy(),
      readWindowsLocaleState(),
    ]);
    this.systemProxyUrl = sys.proxyUrl;
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

  private startLocalEnvironmentWatcher(): void {
    // 纯本机轻量环境监测（注册表系统代理、网卡/TUN 变动、系统时区区域同步状态 & 异常期持续进程拦截，0 外部网络流量）
    this.localEnvTimer = setInterval(async () => {
      try {
        // 1. 同步刷新系统时区与区域显示
        const latestLocale = await readWindowsLocaleState();
        const localeChanged =
          latestLocale.timeZoneId !== this.winLocale.timeZoneId ||
          latestLocale.regionCode !== this.winLocale.regionCode;
        if (localeChanged) {
          this.winLocale = latestLocale;
          this.emitState();
        }

        // 2. 持续执行异常态 / 时区不一致态的受保护进程防重开拦截
        await this.enforceProcessGuardInBackground();

        // 3. 系统代理与网卡路由监测
        const sys = await readWindowsSystemProxy();
        this.systemProxyUrl = sys.proxyUrl;
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
          this.addLog('info', '检测到本机网络接口 / TUN 虚拟网卡变动');
          setTimeout(() => {
            void this.checkNow('本机网卡 / TUN 路由变动');
          }, 400);
        }
      } catch {
        // ignore
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
      lastTriggerReason: this.lastTriggerReason,
      clashInfo: this.clashMonitor.getRuntimeInfo(),
      systemProxyUrl: this.systemProxyUrl,
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
    if (reason) {
      this.lastTriggerReason = reason;
    }

    if (this.lastError && !this.lastProbe) {
      this.status = 'error';
    } else if (this.lastProbe) {
      if (!cfg.defaultCountryCode) {
        this.status = 'unset';
        this.lastAlertSignature = null;
      } else if (this.lastProbe.countryCode === cfg.defaultCountryCode) {
        this.status = 'ok';
        if (this.lastAlertSignature !== null) {
          this.lastAlertSignature = null;
          this.emitRecoveredAlert();
        }
      } else {
        this.status = 'mismatch';
        void this.handleMismatchTransition(reason || '默认地区配置更新');
        this.emitState();
        return this.getSnapshot();
      }
    }

    void this.enforceProcessGuardInBackground();
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
    this.lastTriggerReason = reason;
    this.emitState();

    try {
      const channel = await this.resolveProxyChannel();
      const endpoints = this.buildEndpointsList();

      let probeSuccess: ProbeResult | null = null;
      let lastErrMsg = '所有回显探测源均不可达';

      for (const ep of endpoints) {
        try {
          const startedAt = Date.now();
          const rawBody = await fetchViaProxy(ep.url, channel.proxyUrl, 6000);
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
            probeSource: ep.name,
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
          if (prevIp !== probeSuccess.ip || prevCountry !== probeSuccess.countryCode) {
            this.addLog(
              'info',
              `当前出口: ${probeSuccess.countryName} (${probeSuccess.countryCode}) · ${probeSuccess.ip}`
            );
          }
          await this.enforceProcessGuardInBackground();
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
          if (this.lastAlertSignature !== null) {
            this.lastAlertSignature = null;
            this.emitRecoveredAlert();
          }
          // 即使 IP 地区一致，若系统时区/区域尚未同步且开启了时区不一致拦截，也立即检查一次
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
   * 根据默认保护地区（及当前匹配的出口 IP 精确城市时区），一键设置 Windows 时区与区域
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
    const targetName = cfg.defaultCountryName || targetCode;

    this.isSyncingLocale = true;
    this.emitState();

    try {
      let exactIanaTz: string | null = null;
      // 当当前出口 IP 处于目标保护地区时，经由代理获取该出口 IP 精确的城市级时区（如区分美西/美东）
      if (this.lastProbe && this.lastProbe.countryCode === targetCode) {
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

      const detailNote =
        resolved.fromExactIp && exactIanaTz ? `（精确匹配出口时区 ${exactIanaTz}）` : '';
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
   * 若当前出口 IP 或默认保护地区与中国不一致，严格执行“先强杀受保护进程，确认退出后再切换回中国时区”
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

      // 第一步：在切回中国时区之前，先强杀受保护进程树，确保目标软件存活期间绝不暴露于中国时区下
      if (
        mismatchWithCurrentEnv &&
        cfg.killProcessesEnabled &&
        cfg.protectedProcessPatterns.length > 0
      ) {
        const killReport = await this.executeProcessKillSafely(cfg.protectedProcessPatterns);
        if (killReport.totalMatchedPids > 0) {
          killedProcesses.push(...killReport.matchedSummary);
          this.addLog(
            'danger',
            `还原中国时区前检测到与当前出口/默认地区不一致，已先行强杀进程：${killReport.matchedSummary.join(', ')}`
          );
          if (killReport.accessDenied && killReport.errorDetail) {
            this.addLog('warn', killReport.errorDetail);
          }
          // 留出极短内核句柄回收缓冲后再广播系统时区变更
          await sleep(80);
        }
      }

      // 第二步：还原 Windows 时区与区域至默认中国状态
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
        this.emit('trigger-alert', {
          alertType: 'locale-mismatch',
          expectedCode,
          expectedName,
          actualCode: this.lastProbe?.countryCode || null,
          actualName: this.lastProbe?.countryName || null,
          actualIp: this.lastProbe?.ip || null,
          triggerReason: '手动还原中国时区（与出口 IP 不一致，已先行强杀进程）',
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

  private async executeProcessKillSafely(patterns: string[]): Promise<ProcessKillReport> {
    if (this.isKillingProcesses) {
      return {
        matchedSummary: [],
        matchedRawNames: [],
        totalMatchedPids: 0,
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
   * 后台持续巡检：处于 IP 地区不匹配、断连、或系统时区/区域不匹配期间，若受保护应用被启动则立即强杀
   */
  private async enforceProcessGuardInBackground(): Promise<void> {
    const cfg = this.configStore.get();
    if (!cfg.killProcessesEnabled || cfg.protectedProcessPatterns.length === 0) {
      return;
    }
    if (this.status === 'checking') {
      return;
    }

    let unsafeType: 'mismatch' | 'disconnect' | 'locale-mismatch' | null = null;
    let unsafeReason = '';
    let compareTargetCode: string | null = cfg.defaultCountryCode;
    let compareTargetName: string | null = cfg.defaultCountryName;

    if (this.status === 'mismatch' && cfg.defaultCountryCode) {
      unsafeType = 'mismatch';
      unsafeReason = `出口地区 [${this.lastProbe?.countryName}] 与默认地区 [${cfg.defaultCountryName}] 不符`;
    } else if (this.status === 'error' && cfg.killOnDisconnect && cfg.defaultCountryCode) {
      unsafeType = 'disconnect';
      unsafeReason = '代理连接异常断开期间禁止运行受保护进程';
    } else if (cfg.killOnLocaleMismatch) {
      // 检查系统时区/区域是否与“默认保护地区”或“当前出口 IP 地区”不一致
      if (
        cfg.defaultCountryCode &&
        !isWindowsLocaleMatchingCountry(
          this.winLocale.timeZoneId,
          this.winLocale.regionCode,
          cfg.defaultCountryCode
        )
      ) {
        unsafeType = 'locale-mismatch';
        compareTargetCode = cfg.defaultCountryCode;
        compareTargetName = cfg.defaultCountryName;
        unsafeReason = `系统时区/区域 (${this.winLocale.regionName}) 与默认地区 (${cfg.defaultCountryName}) 不一致`;
      } else if (
        this.lastProbe &&
        this.lastProbe.countryCode !== 'UNKNOWN' &&
        !isWindowsLocaleMatchingCountry(
          this.winLocale.timeZoneId,
          this.winLocale.regionCode,
          this.lastProbe.countryCode
        )
      ) {
        unsafeType = 'locale-mismatch';
        compareTargetCode = this.lastProbe.countryCode;
        compareTargetName = this.lastProbe.countryName;
        unsafeReason = `系统时区/区域 (${this.winLocale.regionName}) 与当前出口 IP (${this.lastProbe.countryName}) 不一致`;
      }
    }

    if (!unsafeType) {
      return;
    }

    const report = await this.executeProcessKillSafely(cfg.protectedProcessPatterns);
    if (report.totalMatchedPids === 0) {
      return;
    }

    this.addLog(
      'danger',
      `已自动强杀进程：${report.matchedSummary.join(', ')} · 原因：${unsafeReason}`
    );
    if (report.accessDenied && report.errorDetail) {
      this.addLog('warn', report.errorDetail);
    }
    this.emitState();

    if (cfg.alertPopupEnabled) {
      const clash = this.clashMonitor.getRuntimeInfo();
      const payload: AlertPayload = {
        alertType: unsafeType,
        expectedCode: compareTargetCode,
        expectedName: compareTargetName,
        actualCode: unsafeType === 'disconnect' ? null : this.lastProbe?.countryCode || null,
        actualName: unsafeType === 'disconnect' ? '连接断开' : this.lastProbe?.countryName || null,
        actualIp: unsafeType === 'disconnect' ? null : this.lastProbe?.ip || null,
        edgeLoc: this.lastProbe?.edgeLoc,
        viaChannel: this.lastProbe?.viaChannel,
        activeNode: clash.connected ? clash.activeNode : null,
        triggerReason: unsafeReason,
        errorDetail: unsafeType === 'disconnect' ? this.lastError || undefined : undefined,
        killedProcesses: report.matchedSummary,
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

    if (cfg.killProcessesEnabled && cfg.protectedProcessPatterns.length > 0) {
      const report = await this.executeProcessKillSafely(cfg.protectedProcessPatterns);
      if (report.totalMatchedPids > 0) {
        killedProcesses = report.matchedSummary;
        this.addLog(
          'danger',
          `地区变更保护已触发，强杀进程：${report.matchedSummary.join(', ')}`
        );
      }
      if (report.accessDenied && report.errorDetail) {
        killError = report.errorDetail;
        this.addLog('warn', report.errorDetail);
      }
    }

    const sig = `mismatch:${cfg.defaultCountryCode}->${this.lastProbe.countryCode}`;
    const isSameSig = this.lastAlertSignature === sig;
    this.lastAlertSignature = sig;

    // 如果同一异常状态没有新杀掉进程，则不重复弹窗；若有新强杀进程则必须弹窗告知
    if (isSameSig && (!killedProcesses || killedProcesses.length === 0)) {
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

    if (
      cfg.killProcessesEnabled &&
      cfg.killOnDisconnect &&
      cfg.protectedProcessPatterns.length > 0
    ) {
      const report = await this.executeProcessKillSafely(cfg.protectedProcessPatterns);
      if (report.totalMatchedPids > 0) {
        killedProcesses = report.matchedSummary;
        this.addLog(
          'danger',
          `代理断连保护已触发，强杀进程：${report.matchedSummary.join(', ')}`
        );
      }
      if (report.accessDenied && report.errorDetail) {
        killError = report.errorDetail;
        this.addLog('warn', report.errorDetail);
      }
    }

    if (!cfg.alertOnDisconnect) return;

    const sig = `disconnect:${cfg.defaultCountryCode}`;
    const isSameSig = this.lastAlertSignature === sig;
    this.lastAlertSignature = sig;

    if (isSameSig && (!killedProcesses || killedProcesses.length === 0)) {
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
      viaChannel: undefined,
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
      const proxyUrl = `${scheme}://${cfg.manualProxy.host}:${cfg.manualProxy.port}`;
      return {
        proxyUrl,
        description: `手动端口 (${cfg.manualProxy.protocol.toUpperCase()} ${cfg.manualProxy.host}:${cfg.manualProxy.port})`,
      };
    }

    // auto 模式：1) 优先读取系统代理 -> 2) 其次读取本机运行中的 Clash mixed-port -> 3) 回退到 TUN / 网卡直连
    const sys = await readWindowsSystemProxy();
    this.systemProxyUrl = sys.proxyUrl;
    if (sys.enabled && sys.proxyUrl) {
      const cleanAddr = sys.proxyUrl.replace(/^[a-z0-9+.-]+:\/\//i, '');
      return {
        proxyUrl: sys.proxyUrl,
        description: `系统代理 (${cleanAddr})`,
      };
    }

    const clash = this.clashMonitor.getRuntimeInfo();
    if (clash.connected && clash.mixedPort) {
      const alive = await canConnectLocalPort('127.0.0.1', clash.mixedPort, 400);
      if (alive) {
        return {
          proxyUrl: `http://127.0.0.1:${clash.mixedPort}`,
          description: `Clash 端口 (127.0.0.1:${clash.mixedPort})`,
        };
      }
    }

    for (const candidatePort of [7897, 7890, 10809]) {
      const alive = await canConnectLocalPort('127.0.0.1', candidatePort, 250);
      if (alive) {
        return {
          proxyUrl: `http://127.0.0.1:${candidatePort}`,
          description: `自动发现本地端口 (127.0.0.1:${candidatePort})`,
        };
      }
    }

    return {
      proxyUrl: null,
      description: '自动 (TUN 虚拟网卡 / 本机直连)',
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
  if (format === 'cf-trace' || text.includes('ip=')) {
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

function fetchViaProxy(
  targetUrl: string,
  proxyUrl: string | null,
  timeoutMs: number
): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(targetUrl);
    const isHttps = parsedUrl.protocol === 'https:';

    let agent: http.Agent | undefined;
    if (proxyUrl) {
      if (proxyUrl.startsWith('socks')) {
        agent = new SocksProxyAgent(proxyUrl, { keepAlive: false, timeout: timeoutMs });
      } else {
        agent = new HttpsProxyAgent(proxyUrl, { keepAlive: false, timeout: timeoutMs });
      }
    } else {
      agent = isHttps
        ? new https.Agent({ keepAlive: false, timeout: timeoutMs })
        : new http.Agent({ keepAlive: false, timeout: timeoutMs });
    }

    const transport = isHttps ? https : http;
    const req = transport.request(
      parsedUrl,
      {
        method: 'GET',
        agent,
        timeout: timeoutMs,
        headers: {
          'User-Agent': 'curl/8.7.1',
          Accept: 'text/plain, */*',
          'Cache-Control': 'no-cache',
          Connection: 'close',
        },
      },
      (res) => {
        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          reject(new Error(`HTTP 状态码 ${res.statusCode}`));
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => {
          resolve(Buffer.concat(chunks).toString('utf-8'));
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error('连接超时'));
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.end();
  });
}

function canConnectLocalPort(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => finish(true));
    socket.on('timeout', () => finish(false));
    socket.on('error', () => finish(false));
  });
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
