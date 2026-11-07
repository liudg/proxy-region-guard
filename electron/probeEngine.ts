import { EventEmitter } from 'node:events';
import * as net from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  AlertPayload,
  AntigravityLaunchResult,
  AntigravityRuntimeState,
  AppStateSnapshot,
  ClashRuntimeInfo,
  ClaudeLaunchResult,
  ClaudeRuntimeState,
  GuardEventLog,
  GuardStatus,
  LocaleSyncResult,
  ProbeResult,
  WindowsLocaleState,
} from '../src/shared/types';
import { getCountryNameZh, isValidIsoCountryCode } from '../src/shared/countries';
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
  ANTIGRAVITY_PROCESS_PATTERNS,
  detectAntigravityInstallation,
  inspectRunningAntigravityProcesses,
  markAntigravityLaunchedByGuard,
  spawnAntigravityWithDedicatedProxy,
} from './antigravityController';
import {
  areAnyPidsAlive,
  CLAUDE_DESKTOP_PROCESS_PATTERNS,
  countRunningClaudeProcesses,
  detectClaudeInstallation,
  spawnClaudeWithDedicatedProxy,
  terminateClaudeProcessesSync,
} from './claudeController';
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
  private stopped = false;
  private isChecking = false;
  private isSyncingLocale = false;
  private activeKillCount = 0;
  private killQueue: Promise<unknown> = Promise.resolve();
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

  // Claude 专栏运行时状态与唯一启动入口授权锁
  private claudeDetectedExe: string | null = null;
  private claudeInstallType: ClaudeRuntimeState['installType'] = 'not-found';
  private claudeRunning = false;
  private claudeProcessCount = 0;
  private claudeRunningPids: number[] = [];
  private claudeFastCheckTicks = 0;
  private claudeAuthorizedSession = false;
  private claudeSeenRunningSinceAuth = false;
  private claudeLaunchGraceUntil = 0;

  // Antigravity 启动器专栏状态（纯代理指定，无监控预警、无时区限制、无断连强杀）
  private antigravityDetectedExe: string | null = null;
  private antigravityInstallType: AntigravityRuntimeState['installType'] = 'not-found';
  private antigravityRunning = false;
  private antigravityUiCount = 0;
  private antigravityLsCount = 0;
  private antigravityTotalCount = 0;
  private antigravityProxiedSession = false;
  private antigravityIsProbing = false;
  private antigravityNodeProbe: ProbeResult | null = null;
  private antigravityNodeProbeError: string | null = null;

  private heartbeatTimer: NodeJS.Timeout | null = null;
  private localEnvTimer: NodeJS.Timeout | null = null;
  private claudeWatchTimer: NodeJS.Timeout | null = null;
  private clashDebounceTimer: NodeJS.Timeout | null = null;
  private antigravityDebounceTimer: NodeJS.Timeout | null = null;
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
      this.clashDebounceTimer = setTimeout(() => {
        this.clashDebounceTimer = null;
        this.addLog('info', `实时捕获事件：${reason}`);
        void this.checkNow(reason);
      }, 250);
    });

    this.clashMonitor.on('antigravity-clash-ready', () => {
      this.emitState();
      const cfg = this.configStore.get();
      const info = this.clashMonitor.getRuntimeInfo();
      if (cfg.antigravityClashNode && info.antigravityPortListening && !this.antigravityIsProbing) {
        if (this.antigravityDebounceTimer) {
          clearTimeout(this.antigravityDebounceTimer);
        }
        this.antigravityDebounceTimer = setTimeout(() => {
          this.antigravityDebounceTimer = null;
          void this.probeAntigravityNodeNow();
        }, 250);
      }
    });

    this.clashMonitor.on('clash-status-updated', () => {
      const info = this.clashMonitor.getRuntimeInfo();
      this.emitState();

      if (info.connected && (!this.lastProbe || this.status === 'error') && !this.isChecking) {
        if (this.clashDebounceTimer) {
          clearTimeout(this.clashDebounceTimer);
        }
        this.clashDebounceTimer = setTimeout(() => {
          this.clashDebounceTimer = null;
          void this.checkNow('Clash 控制接口已连接');
        }, 300);
      }
    });
  }

  public async start(): Promise<void> {
    this.stopped = false;
    const cfg = this.configStore.get();
    const [sys, initialLocale, claudeInstall, claudeProc, agInstall, agProc] = await Promise.all([
      this.getSystemProxyFresh(true),
      readWindowsLocaleState(),
      detectClaudeInstallation(cfg.claudeExePath),
      countRunningClaudeProcesses(),
      detectAntigravityInstallation(cfg.antigravityExePath),
      inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort),
    ]);

    this.winLocale = initialLocale;
    this.claudeDetectedExe = claudeInstall.exePath;
    this.claudeInstallType = claudeInstall.installType;
    this.claudeRunning = claudeProc.running;
    this.claudeProcessCount = claudeProc.count;
    this.claudeRunningPids = claudeProc.pids;

    this.antigravityDetectedExe = agInstall.exePath;
    this.antigravityInstallType = agInstall.installType;
    this.antigravityRunning = agProc.running;
    this.antigravityUiCount = agProc.uiProcessCount;
    this.antigravityLsCount = agProc.languageServerCount;
    this.antigravityTotalCount = agProc.totalProcessCount;
    this.antigravityProxiedSession = agProc.proxiedSession;

    this.lastSysProxySnapshot = `${sys.enabled}|${sys.proxyUrl || ''}`;
    this.lastNetFingerprint = getNetworkInterfaceFingerprint();

    this.clashMonitor.start(
      cfg.selectedClashNode,
      cfg.dedicatedProxyPort,
      cfg.antigravityClashNode,
      cfg.antigravityDedicatedPort,
      cfg.selectedClashProfileUid,
      cfg.selectedClashProfileName,
      cfg.selectedClashNodeRaw || null,
      cfg.selectedClashNodeDialerRaw || null,
      cfg.antigravityClashProfileUid,
      cfg.antigravityClashProfileName,
      cfg.antigravityClashNodeRaw || null,
      cfg.antigravityClashNodeDialerRaw || null
    );
    this.startLocalEnvironmentWatcher();
    this.startClaudeExclusiveWatcher();
    this.restartHeartbeatTimer();

    await this.checkNow('应用启动首次检测');
  }

  public stop(): void {
    if (this.stopped) return;
    this.stopped = true;

    const shouldKillClaudeOnExit =
      this.claudeRunning ||
      this.claudeAuthorizedSession ||
      this.configStore.get().claudeExclusiveGuard;

    this.claudeAuthorizedSession = false;
    this.claudeSeenRunningSinceAuth = false;
    this.claudeLaunchGraceUntil = 0;

    // 卫士完全退出时，同步强杀全部 Claude 关联进程树，杜绝脱离监管后裸奔
    // （注意：Antigravity 专栏不设强杀监管，卫士退出时保持 Antigravity 正常运行）
    if (shouldKillClaudeOnExit) {
      terminateClaudeProcessesSync();
    }

    this.clashMonitor.stop();
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    if (this.localEnvTimer) {
      clearTimeout(this.localEnvTimer);
      this.localEnvTimer = null;
    }
    if (this.claudeWatchTimer) {
      clearTimeout(this.claudeWatchTimer);
      this.claudeWatchTimer = null;
    }
    if (this.clashDebounceTimer) {
      clearTimeout(this.clashDebounceTimer);
      this.clashDebounceTimer = null;
    }
    if (this.antigravityDebounceTimer) {
      clearTimeout(this.antigravityDebounceTimer);
      this.antigravityDebounceTimer = null;
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
        const cfg = this.configStore.get();
        const hasCustomGuard =
          cfg.killProcessesEnabled && cfg.protectedProcessPatterns.length > 0;
        // 仅当 Claude 正在运行或已启用额外守护进程时，才执行后台静默心跳巡检；
        // 平时未运行受控进程时，仅由应用启动、切换节点、代理/时区事件及手动点击按需触发
        if (this.claudeRunning || hasCustomGuard) {
          void this.checkNow('轻量心跳巡检');
        }
      }, sec * 1000);
    }
  }

  public async refreshClaudeInstallDetection(): Promise<void> {
    const cfg = this.configStore.get();
    const info = await detectClaudeInstallation(cfg.claudeExePath, true);
    this.claudeDetectedExe = info.exePath;
    this.claudeInstallType = info.installType;
    this.emitState();
  }

  public async refreshAntigravityInstallDetection(): Promise<void> {
    const cfg = this.configStore.get();
    const info = await detectAntigravityInstallation(cfg.antigravityExePath);
    this.antigravityDetectedExe = info.exePath;
    this.antigravityInstallType = info.installType;
    this.emitState();
  }

  /**
   * 切换 Antigravity 专属 Clash 节点（支持跨订阅组选择任意具体节点）：
   * 仅在 Mihomo 中动态注入该节点的完整配置、专属本地端口及 PROCESS-NAME 规则，并轻量获取一次节点出口信息用于展示，
   * 不触发任何时区校验、默认地区变更、弹窗预警或进程强杀。
   */
  public async selectAntigravityClashNode(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    const cleanNode = nodeName && nodeName.trim() ? nodeName.trim() : null;
    const prevCfg = this.configStore.get();
    const effectiveProfileUid =
      profileUid !== undefined
        ? profileUid && profileUid.trim()
          ? profileUid.trim()
          : null
        : prevCfg.antigravityClashProfileUid;

    if (
      prevCfg.antigravityClashNode !== cleanNode ||
      prevCfg.antigravityClashProfileUid !== effectiveProfileUid
    ) {
      this.antigravityNodeProbe = null;
      this.antigravityNodeProbeError = null;
    }

    if (cleanNode) {
      this.addLog(
        'info',
        `正在将 Antigravity 专属代理通道切换至节点：[${cleanNode}] (127.0.0.1:${prevCfg.antigravityDedicatedPort})...`
      );
      const bindRes = await this.clashMonitor.configureAntigravityNode(
        cleanNode,
        prevCfg.antigravityDedicatedPort,
        effectiveProfileUid,
        true
      );

      const cfg = this.configStore.update({
        antigravityClashNode: cleanNode,
        antigravityClashProfileUid: bindRes.profileUid ?? effectiveProfileUid,
        antigravityClashProfileName: bindRes.profileName ?? prevCfg.antigravityClashProfileName,
        antigravityClashNodeRaw: bindRes.nodeRaw ?? prevCfg.antigravityClashNodeRaw,
        antigravityClashNodeDialerRaw:
          bindRes.dialerRaw ?? prevCfg.antigravityClashNodeDialerRaw,
      });

      const fullLabel = cfg.antigravityClashProfileName
        ? `${cfg.antigravityClashProfileName} / ${cleanNode}`
        : cleanNode;

      if (!bindRes.ok) {
        const errText = bindRes.error || `绑定 Antigravity 节点 [${fullLabel}] 失败`;
        this.antigravityNodeProbeError = errText;
        this.addLog('warn', errText);
        this.emitState();
        return this.getSnapshot();
      }

      this.addLog(
        'success',
        `Antigravity 专属节点已锁定 [${fullLabel}] → 127.0.0.1:${cfg.antigravityDedicatedPort} (含 Antigravity.exe / language_server.exe 进程规则)`
      );
      return this.probeAntigravityNodeNow();
    } else {
      const cfg = this.configStore.update({
        antigravityClashNode: null,
        antigravityClashProfileUid: null,
        antigravityClashProfileName: null,
        antigravityClashNodeRaw: null,
        antigravityClashNodeDialerRaw: null,
      });
      await this.clashMonitor.configureAntigravityNode(
        null,
        cfg.antigravityDedicatedPort,
        null,
        true
      );
      this.antigravityNodeProbe = null;
      this.antigravityNodeProbeError = null;
      this.addLog('info', '已取消 Antigravity 专属 Clash 节点绑定');
      this.emitState();
      return this.getSnapshot();
    }
  }

  /**
   * 轻量探测 Antigravity 专属端口的出口 IP 与国家（纯界面展示，绝不触发任何警告或状态拦截）
   */
  public async probeAntigravityNodeNow(): Promise<AppStateSnapshot> {
    const cfg = this.configStore.get();
    if (!cfg.antigravityClashNode) {
      this.antigravityNodeProbe = null;
      this.antigravityNodeProbeError = null;
      this.emitState();
      return this.getSnapshot();
    }

    if (this.antigravityIsProbing) {
      return this.getSnapshot();
    }

    this.antigravityIsProbing = true;
    this.emitState();

    try {
      let clash = this.clashMonitor.getRuntimeInfo();
      if (!clash.connected || !clash.antigravityPortListening) {
        const bindRes = await this.clashMonitor.configureAntigravityNode(
          cfg.antigravityClashNode,
          cfg.antigravityDedicatedPort,
          cfg.antigravityClashProfileUid,
          false
        );
        clash = this.clashMonitor.getRuntimeInfo();
        if (!bindRes.ok || !bindRes.listening) {
          this.antigravityNodeProbe = null;
          this.antigravityNodeProbeError =
            bindRes.error ||
            `专属端口 127.0.0.1:${cfg.antigravityDedicatedPort} 未就绪`;
          return this.getSnapshot();
        }
      }

      const proxyUrl = `http://127.0.0.1:${cfg.antigravityDedicatedPort}`;
      const channelDesc = `Antigravity 专属端口 (127.0.0.1:${cfg.antigravityDedicatedPort})`;
      const endpoints = this.buildEndpointsList();

      let probeSuccess: ProbeResult | null = null;
      let lastErrMsg = '探测超时';

      for (const ep of endpoints) {
        try {
          const startedAt = Date.now();
          const rawBody = await requestTextViaProxy(ep.url, proxyUrl, 5500);
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
            viaChannel: channelDesc,
            latencyMs,
            checkedAt: Date.now(),
          };
          break;
        } catch (err) {
          lastErrMsg = err instanceof Error ? err.message : String(err);
        }
      }

      if (probeSuccess) {
        this.antigravityNodeProbe = probeSuccess;
        this.antigravityNodeProbeError = null;
      } else {
        this.antigravityNodeProbe = null;
        this.antigravityNodeProbeError = simplifyNetworkError(lastErrMsg, channelDesc);
      }
    } finally {
      this.antigravityIsProbing = false;
      this.emitState();
    }

    return this.getSnapshot();
  }

  /**
   * 通过指定专属代理节点启动（或重启）Antigravity：
   * 1. 确保 Clash 专属端口 (如 127.0.0.1:27898) 与 PROCESS-NAME 规则已绑定
   * 2. 若已有运行中的 Antigravity.exe / language_server.exe，先关闭旧实例以释放单实例锁
   * 3. 注入 --proxy-server 与 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / GRPC_PROXY / NO_PROXY 拉起 Antigravity.exe
   */
  public async launchAntigravityFromGuard(): Promise<AntigravityLaunchResult> {
    let cfg = this.configStore.get();

    const install = await detectAntigravityInstallation(cfg.antigravityExePath);
    this.antigravityDetectedExe = install.exePath;
    this.antigravityInstallType = install.installType;

    if (!install.exePath) {
      const msg = '未检测到 Antigravity.exe 安装路径，请先点击下方「浏览」手动指定';
      this.addLog('warn', msg);
      this.emitState();
      return { ok: false, message: msg, state: this.getSnapshot() };
    }

    if (!cfg.antigravityClashNode) {
      const msg = '请先在下拉框中选择要为 Antigravity 绑定的 Clash 代理节点';
      this.addLog('warn', msg);
      this.emitState();
      return { ok: false, message: msg, state: this.getSnapshot() };
    }

    const bindRes = await this.clashMonitor.configureAntigravityNode(
      cfg.antigravityClashNode,
      cfg.antigravityDedicatedPort,
      cfg.antigravityClashProfileUid,
      false
    );
    if (bindRes.nodeRaw && !cfg.antigravityClashNodeRaw) {
      cfg = this.configStore.update({
        antigravityClashProfileUid: bindRes.profileUid ?? cfg.antigravityClashProfileUid,
        antigravityClashProfileName: bindRes.profileName ?? cfg.antigravityClashProfileName,
        antigravityClashNodeRaw: bindRes.nodeRaw,
        antigravityClashNodeDialerRaw: bindRes.dialerRaw ?? null,
      });
    }
    if (!bindRes.ok || !bindRes.listening) {
      const msg = `无法建立节点 [${cfg.antigravityClashNode}] 的专属代理端口 (127.0.0.1:${
        cfg.antigravityDedicatedPort
      })：${bindRes.error || '端口未监听'}`;
      this.addLog('warn', msg);
      this.emitState();
      return { ok: false, message: msg, state: this.getSnapshot() };
    }

    // 若当前已有 Antigravity.exe 或 language_server.exe 运行，需先终止旧进程，否则 Electron 单实例锁会使新进程直接退出
    const beforeProc = await inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort);
    if (beforeProc.running) {
      markAntigravityLaunchedByGuard(null);
      await this.executeProcessKillSafely(ANTIGRAVITY_PROCESS_PATTERNS);
      for (let i = 0; i < 8; i++) {
        const checkAlive = await inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort);
        if (!checkAlive.running) break;
        await sleep(160);
      }
    }

    markAntigravityLaunchedByGuard(cfg.antigravityDedicatedPort);
    const spawnRes = await spawnAntigravityWithDedicatedProxy(
      install.exePath,
      cfg.antigravityDedicatedPort
    );

    if (!spawnRes.ok) {
      markAntigravityLaunchedByGuard(null);
      const errMsg = `拉起 Antigravity 失败：${spawnRes.error || '未知错误'}`;
      this.addLog('danger', errMsg);
      this.emitState();
      return { ok: false, message: errMsg, state: this.getSnapshot() };
    }

    let afterProc = await inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort);
    for (let i = 0; i < 6; i++) {
      if (afterProc.running) break;
      await sleep(250);
      afterProc = await inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort);
    }

    this.antigravityRunning = afterProc.running;
    this.antigravityUiCount = afterProc.uiProcessCount;
    this.antigravityLsCount = afterProc.languageServerCount;
    this.antigravityTotalCount = afterProc.totalProcessCount;
    this.antigravityProxiedSession = afterProc.running;

    if (!this.antigravityNodeProbe && !this.antigravityIsProbing) {
      void this.probeAntigravityNodeNow();
    }

    const okMsg = `已通过专属节点 [${cfg.antigravityClashNode}] (127.0.0.1:${cfg.antigravityDedicatedPort}) 启动 Antigravity，主进程与 language_server.exe 已全链路绑定代理`;
    this.addLog('success', okMsg);
    this.emitState();

    return {
      ok: true,
      message: okMsg,
      state: this.getSnapshot(),
    };
  }

  /**
   * 手动关闭 Antigravity 及其 language_server.exe 进程树
   */
  public async terminateAntigravityManually(): Promise<AntigravityLaunchResult> {
    markAntigravityLaunchedByGuard(null);
    const report = await this.executeProcessKillSafely(ANTIGRAVITY_PROCESS_PATTERNS);
    const cfg = this.configStore.get();
    const afterProc = await inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort);

    this.antigravityRunning = afterProc.running;
    this.antigravityUiCount = afterProc.uiProcessCount;
    this.antigravityLsCount = afterProc.languageServerCount;
    this.antigravityTotalCount = afterProc.totalProcessCount;
    this.antigravityProxiedSession = afterProc.proxiedSession;

    const msg =
      report.killedCount > 0
        ? `已关闭 Antigravity 关联进程：${report.killedSummary.join(', ')}`
        : '当前无运行中的 Antigravity 进程';
    this.addLog('info', msg);
    this.emitState();

    return {
      ok: !this.antigravityRunning,
      message: report.errorDetail || msg,
      state: this.getSnapshot(),
    };
  }

  /**
   * 切换下拉框中指定的 Clash 节点（Claude 专栏 · 支持跨订阅组选择任意具体节点）：
   * 1. 在 Mihomo 中将该节点的完整配置及独立专属端口动态注入（及进程规则锁死）
   * 2. 立即通过该专属通道探测真实出口 IP 与国家，并与系统时区/区域对比
   */
  public async selectClashNode(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    const cleanNode = nodeName && nodeName.trim() ? nodeName.trim() : null;
    const prevCfg = this.configStore.get();
    const effectiveProfileUid =
      profileUid !== undefined
        ? profileUid && profileUid.trim()
          ? profileUid.trim()
          : null
        : prevCfg.selectedClashProfileUid;

    if (
      prevCfg.selectedClashNode !== cleanNode ||
      prevCfg.selectedClashProfileUid !== effectiveProfileUid
    ) {
      this.lastProbe = null;
      this.lastError = null;
    }

    if (cleanNode) {
      this.addLog('info', `正在将专属代理通道切换至 Clash 节点：[${cleanNode}]...`);
      const bindRes = await this.clashMonitor.configureDedicatedNode(
        cleanNode,
        prevCfg.dedicatedProxyPort,
        effectiveProfileUid,
        true
      );

      const cfg = this.configStore.update({
        selectedClashNode: cleanNode,
        selectedClashProfileUid: bindRes.profileUid ?? effectiveProfileUid,
        selectedClashProfileName: bindRes.profileName ?? prevCfg.selectedClashProfileName,
        selectedClashNodeRaw: bindRes.nodeRaw ?? prevCfg.selectedClashNodeRaw,
        selectedClashNodeDialerRaw: bindRes.dialerRaw ?? prevCfg.selectedClashNodeDialerRaw,
      });

      const fullLabel = cfg.selectedClashProfileName
        ? `${cfg.selectedClashProfileName} / ${cleanNode}`
        : cleanNode;

      if (!bindRes.ok) {
        this.addLog('warn', bindRes.error || `绑定节点 [${fullLabel}] 失败`);
      } else {
        this.addLog(
          'success',
          `已锁定 Clash 跨订阅专属节点 [${fullLabel}] → 本地专属端口 127.0.0.1:${cfg.dedicatedProxyPort}`
        );
      }

      const snap = await this.checkNow(`切换指定 Clash 节点: ${fullLabel}`);

      // 仅当用户尚未设置默认保护地区时，首次选定节点后自动初始化默认保护地区；
      // 若已锁定默认保护地区，绝不随节点切换自动篡改，从而保留对所选节点真实出口的防呆校验能力
      if (this.lastProbe && isValidIsoCountryCode(this.lastProbe.countryCode)) {
        const newCode = this.lastProbe.countryCode.toUpperCase();
        const curCfg = this.configStore.get();
        if (!curCfg.defaultCountryCode) {
          this.configStore.update({
            defaultCountryCode: newCode,
            defaultCountryName: this.lastProbe.countryName,
          });
          return this.evaluateStatusOnly(
            `已将首次选定节点的出口地区 [${this.lastProbe.countryName}] 设为默认保护地区`
          );
        }
      }
      return snap;
    } else {
      const cfg = this.configStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
        selectedClashNodeRaw: null,
        selectedClashNodeDialerRaw: null,
      });
      await this.clashMonitor.configureDedicatedNode(null, cfg.dedicatedProxyPort, null, true);
      this.addLog('info', '已取消指定 Clash 节点，恢复自动识别系统全局出口');
      return this.checkNow('取消指定 Clash 节点');
    }
  }

  /**
   * Claude 唯一安全启动入口：
   * 启动前实时强校验：[指定 Clash 节点真实出口地区] == [Windows 系统区域] == [Windows 系统时区]
   */
  public async launchClaudeFromGuard(): Promise<ClaudeLaunchResult> {
    let cfg = this.configStore.get();

    // 1. 确认 Claude Desktop 安装路径
    const install = await detectClaudeInstallation(cfg.claudeExePath);
    this.claudeDetectedExe = install.exePath;
    this.claudeInstallType = install.installType;

    // 2. 若已选择节点，确保专属端口绑定就绪
    if (cfg.selectedClashNode) {
      const bindRes = await this.clashMonitor.configureDedicatedNode(
        cfg.selectedClashNode,
        cfg.dedicatedProxyPort,
        cfg.selectedClashProfileUid,
        false
      );
      if (bindRes.nodeRaw && !cfg.selectedClashNodeRaw) {
        cfg = this.configStore.update({
          selectedClashProfileUid: bindRes.profileUid ?? cfg.selectedClashProfileUid,
          selectedClashProfileName: bindRes.profileName ?? cfg.selectedClashProfileName,
          selectedClashNodeRaw: bindRes.nodeRaw,
          selectedClashNodeDialerRaw: bindRes.dialerRaw ?? null,
        });
      }
      if (!bindRes.ok || !bindRes.listening) {
        const msg = `启动被拦截：无法建立节点 [${cfg.selectedClashNode}] 的专属代理端口 (${
          bindRes.error || '端口未监听'
        })`;
        this.addLog('danger', msg);
        this.emitState();
        return { ok: false, message: msg, state: this.getSnapshot() };
      }
    }

    // 3. 实时刷新读取本机最新 Windows 时区/区域，并对指定节点发起一次真实出口探测
    this.winLocale = await readWindowsLocaleState();
    await this.checkNow('Claude 启动前三重安全校验');

    // 4. 统一复用 buildClaudeRuntimeState 校验结果，消除重复校验代码
    const prelaunchState = this.buildClaudeRuntimeState();
    if (!prelaunchState.canLaunch || !install.exePath || !prelaunchState.proxyCountryCode) {
      const msg = `启动被拦截：${prelaunchState.launchBlockReason || '安全校验未通过'}`;
      this.addLog('danger', msg);
      this.emitState();
      return { ok: false, message: msg, state: this.getSnapshot() };
    }

    const proxyCountry = prelaunchState.proxyCountryCode;
    const proxyCountryName = prelaunchState.proxyCountryName || getCountryNameZh(proxyCountry);

    // 若尚未锁定默认保护地区，自动同步锁定为当前通过校验的节点国家
    if (!cfg.defaultCountryCode) {
      this.configStore.update({
        defaultCountryCode: proxyCountry,
        defaultCountryName: proxyCountryName,
      });
    }

    // 5. 若当前已有运行中的 Claude 进程（含旧代理参数实例或后台 cowork-svc.exe 服务），必须先彻底清理并等待退出，
    // 否则 Electron 单实例锁会使新拉起的进程直接退出并沿用旧实例的环境参数
    await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
    for (let i = 0; i < 6; i++) {
      const checkAlive = await countRunningClaudeProcesses();
      if (!checkAlive.running) break;
      await sleep(150);
    }

    // 6. 授予唯一入口会话锁并注入专属代理参数拉起 Claude
    this.claudeAuthorizedSession = true;
    this.claudeSeenRunningSinceAuth = false;
    this.claudeLaunchGraceUntil = Date.now() + 12000;

    const dedicatedProxyUrl = `http://127.0.0.1:${cfg.dedicatedProxyPort}`;
    const spawnRes = await spawnClaudeWithDedicatedProxy(
      install.exePath,
      install.fallbackDirectPath,
      dedicatedProxyUrl
    );

    if (!spawnRes.ok) {
      this.unsetClaudeAuthLock();
      const errMsg = `拉起 Claude 进程失败：${spawnRes.error || '未知错误'}`;
      this.addLog('danger', errMsg);
      this.emitState();
      return { ok: false, message: errMsg, state: this.getSnapshot() };
    }

    let afterProc = { running: false, count: 0, pids: [] as number[] };
    for (let i = 0; i < 5; i++) {
      await sleep(250);
      afterProc = await countRunningClaudeProcesses();
      if (afterProc.running) break;
    }

    this.claudeRunning = afterProc.running;
    this.claudeProcessCount = afterProc.count;
    this.claudeRunningPids = afterProc.pids;
    this.claudeFastCheckTicks = 0;
    if (afterProc.running) {
      this.claudeSeenRunningSinceAuth = true;
    }

    const fullNodeLabel = cfg.selectedClashProfileName
      ? `${cfg.selectedClashProfileName} / ${cfg.selectedClashNode}`
      : cfg.selectedClashNode;
    const okMsg = `三重校验通过！已通过专属节点 [${fullNodeLabel}] (127.0.0.1:${cfg.dedicatedProxyPort} · ${proxyCountryName}) 安全启动 Claude`;
    this.addLog('success', okMsg);
    this.evaluateStatusOnly();
    return {
      ok: true,
      message: okMsg,
      state: this.getSnapshot(),
    };
  }

  /**
   * 手动一键终止 Claude 所有关联进程并回收授权锁
   */
  public async terminateClaudeManually(): Promise<ClaudeLaunchResult> {
    this.unsetClaudeAuthLock();

    const report = await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);

    const msg =
      report.killedCount > 0
        ? `已安全终止 Claude 进程树：${report.killedSummary.join(', ')}`
        : '当前无运行中的 Claude 进程，已重置启动授权锁';
    this.addLog('info', msg);
    this.emitState();

    return {
      ok: !this.claudeRunning,
      message: report.errorDetail || msg,
      state: this.getSnapshot(),
    };
  }

  private unsetClaudeAuthLock(): void {
    this.claudeAuthorizedSession = false;
    this.claudeSeenRunningSinceAuth = false;
    this.claudeLaunchGraceUntil = 0;
    this.claudeFastCheckTicks = 0;
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

  /**
   * 轻量非重叠巡检：
   * 1. 严防任何未通过本卫士【Claude 专栏】启动的外部 Claude 进程（唯一启动入口硬性保障）
   * 2. 当 Claude 退出后自动回收 `claudeAuthorizedSession`，确保下次仍须从专栏启动
   * 3. 当 Claude 运行期间出现「指定代理 vs 系统时区/区域」不一致或断连时，毫秒级强杀
   *    （若因 Clash 切换订阅组导致专属端口瞬时重载，自动触发跨订阅节点重绑自愈，绝不误杀 Claude）
   */
  private startClaudeExclusiveWatcher(): void {
    const scheduleNext = (delayMs: number) => {
      if (this.stopped) return;
      if (this.claudeWatchTimer) {
        clearTimeout(this.claudeWatchTimer);
      }
      this.claudeWatchTimer = setTimeout(() => {
        this.claudeWatchTimer = null;
        void runWatchTick();
      }, delayMs);
    };

    const runWatchTick = async () => {
      if (this.stopped) return;
      let nextDelay = 2000;

      if (this.activeKillCount === 0) {
        try {
          let proc: { running: boolean; count: number; pids: number[] };

          if (
            this.claudeAuthorizedSession &&
            this.claudeSeenRunningSinceAuth &&
            this.claudeRunningPids.length > 0 &&
            this.claudeFastCheckTicks < 4
          ) {
            this.claudeFastCheckTicks++;
            const fast = areAnyPidsAlive(this.claudeRunningPids);
            if (fast.aliveCount > 0) {
              proc = {
                running: true,
                count: this.claudeProcessCount,
                pids: fast.alivePids,
              };
            } else {
              this.claudeFastCheckTicks = 0;
              proc = await countRunningClaudeProcesses();
            }
          } else {
            this.claudeFastCheckTicks = 0;
            proc = await countRunningClaudeProcesses();
          }
          const prevRunning = this.claudeRunning;
          const prevCount = this.claudeProcessCount;
          this.claudeRunning = proc.running;
          this.claudeProcessCount = proc.count;
          this.claudeRunningPids = proc.pids;

          if (proc.running) {
            if (this.claudeAuthorizedSession) {
              this.claudeSeenRunningSinceAuth = true;
            }
          } else if (
            this.claudeAuthorizedSession &&
            (this.claudeSeenRunningSinceAuth || Date.now() > this.claudeLaunchGraceUntil)
          ) {
            // 用户已关闭 Claude，立即回收唯一入口会话授权锁，并连带清理残留的 cowork-svc.exe 等后台进程
            this.unsetClaudeAuthLock();
            await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
            this.addLog(
              'info',
              '检测到 Claude 已退出，已自动清理关联后台进程并回收启动授权锁（下次需从专栏启动）'
            );
            this.emitState();
            scheduleNext(2000);
            return;
          }

          const cfg = this.configStore.get();

          // 拦截 1：开启唯一启动入口拦截时，未通过卫士专栏授权启动的外部 Claude -> 立即无条件强杀！
          if (proc.running && !this.claudeAuthorizedSession && cfg.claudeExclusiveGuard) {
            const report = await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
            const reason = '拦截到从外部直接启动 Claude！本卫士【Claude 专栏】是唯一允许的启动入口';
            if (report.killedCount > 0) {
              this.addLog(
                'danger',
                `${reason}，已立即强杀：${report.killedSummary.join(', ')}`
              );
            } else if (report.errorDetail) {
              this.addLog('warn', `${reason}，但终止受阻：${report.errorDetail}`);
            }
            this.emitState();

            if (cfg.alertPopupEnabled && (report.killedCount > 0 || report.errorDetail)) {
              this.emitAlert({
                alertType: 'unauthorized-launch',
                expectedCode: this.lastProbe?.countryCode || cfg.defaultCountryCode,
                expectedName: this.lastProbe?.countryName || cfg.defaultCountryName,
                triggerReason: reason,
                killedProcesses: report.killedCount > 0 ? report.killedSummary : undefined,
                killError: report.errorDetail,
              });
            }
            scheduleNext(1500);
            return;
          }

          // 拦截 2：无论是否开启唯一启动入口，只要 Claude 在运行，一旦出现「代理地区 ↔ 系统时区/区域」不一致或断连，立即剥夺授权并强杀！
          if (proc.running && this.status !== 'checking') {
            let check = this.evaluateClaudeSafety(
              this.claudeAuthorizedSession || cfg.claudeExclusiveGuard
            );

            // 若因 Clash 切换订阅组导致专属端口短暂重绑，立即尝试自动重绑并复核，成功则无缝保持 Claude 运行
            if (!check.safe && check.alertType === 'disconnect' && cfg.selectedClashNode) {
              const healRes = await this.clashMonitor.configureDedicatedNode(
                cfg.selectedClashNode,
                cfg.dedicatedProxyPort,
                cfg.selectedClashProfileUid,
                true
              );
              if (healRes.listening) {
                await this.checkNow('Clash 订阅切换后专属通道自愈复核');
                check = this.evaluateClaudeSafety(
                  this.claudeAuthorizedSession || cfg.claudeExclusiveGuard
                );
              }
            }

            if (!check.safe) {
              this.unsetClaudeAuthLock();

              const report = await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
              if (report.killedCount > 0) {
                this.addLog(
                  'danger',
                  `Claude 安全校验失效 (${check.reason})，已立即强杀：${report.killedSummary.join(', ')}`
                );
              } else if (report.errorDetail) {
                this.addLog('warn', report.errorDetail);
              }
              this.emitState();

              if (cfg.alertPopupEnabled && (report.killedCount > 0 || report.errorDetail)) {
                const expectedCode = this.lastProbe?.countryCode || cfg.defaultCountryCode;
                const expectedName = this.lastProbe?.countryName || cfg.defaultCountryName;
                this.emitAlert({
                  alertType: check.alertType,
                  expectedCode,
                  expectedName,
                  triggerReason: check.reason,
                  errorDetail:
                    check.alertType === 'disconnect' ? this.lastError || undefined : undefined,
                  killedProcesses: report.killedCount > 0 ? report.killedSummary : undefined,
                  killError: report.errorDetail,
                });
              }
              scheduleNext(1500);
              return;
            }
          }

          if (prevRunning !== this.claudeRunning || prevCount !== this.claudeProcessCount) {
            this.emitState();
          }

          if (this.claudeRunning || Date.now() < this.claudeLaunchGraceUntil) {
            nextDelay = 1200;
          } else if (cfg.claudeExclusiveGuard && this.claudeInstallType !== 'not-found') {
            nextDelay = 2000;
          } else {
            nextDelay = 5000;
          }
        } catch {
          // ignore transient watcher error
        }
      }

      scheduleNext(nextDelay);
    };

    scheduleNext(1200);
  }

  private evaluateClaudeSafety(requireDedicatedNode = true): {
    safe: boolean;
    reason: string;
    alertType: 'mismatch' | 'disconnect' | 'locale-mismatch';
  } {
    const cfg = this.configStore.get();
    const clash = this.clashMonitor.getRuntimeInfo();

    if (requireDedicatedNode && !cfg.selectedClashNode) {
      return {
        safe: false,
        reason: '未指定 Clash 专属节点，禁止运行 Claude',
        alertType: 'disconnect',
      };
    }

    if (cfg.selectedClashNode && (!clash.connected || !clash.dedicatedPortListening)) {
      return {
        safe: false,
        reason: `指定 Clash 节点 [${cfg.selectedClashNode}] 专属端口断开连接`,
        alertType: 'disconnect',
      };
    }

    if (this.status === 'error' || this.lastError || !this.lastProbe) {
      return {
        safe: false,
        reason: `代理出口不可达 (${this.lastError || '连接异常'})`,
        alertType: 'disconnect',
      };
    }

    const proxyCountry = this.lastProbe.countryCode.toUpperCase();
    const proxyCountryName = this.lastProbe.countryName;

    if (!isValidIsoCountryCode(proxyCountry)) {
      return {
        safe: false,
        reason: '无法识别有效出口国家/地区',
        alertType: 'mismatch',
      };
    }

    if (cfg.defaultCountryCode && cfg.defaultCountryCode.toUpperCase() !== proxyCountry) {
      return {
        safe: false,
        reason: `实际出口 [${proxyCountryName} (${proxyCountry})] 与锁定保护地区 [${cfg.defaultCountryName} (${cfg.defaultCountryCode})] 不一致`,
        alertType: 'mismatch',
      };
    }

    const localeMatched = isWindowsLocaleMatchingCountry(
      this.winLocale.timeZoneId,
      this.winLocale.regionCode,
      proxyCountry
    );
    if (!localeMatched) {
      return {
        safe: false,
        reason: `代理地区 [${proxyCountryName} (${proxyCountry})] 与系统时区/区域 [${this.winLocale.regionName} · ${this.winLocale.timeZoneDisplayName}] 不一致`,
        alertType: 'locale-mismatch',
      };
    }

    return {
      safe: true,
      reason: '',
      alertType: 'mismatch',
    };
  }

  private buildClaudeRuntimeState(clashInfo?: ClashRuntimeInfo): ClaudeRuntimeState {
    const cfg = this.configStore.get();
    const clash = clashInfo || this.clashMonitor.getRuntimeInfo();
    const proxyCountryCode =
      this.lastProbe && isValidIsoCountryCode(this.lastProbe.countryCode)
        ? this.lastProbe.countryCode.toUpperCase()
        : null;
    const proxyCountryName = proxyCountryCode ? this.lastProbe?.countryName || null : null;

    const winRegionMatched = proxyCountryCode
      ? this.winLocale.regionCode.toUpperCase() === proxyCountryCode
      : false;
    const winTimeZoneMatched = proxyCountryCode
      ? isWindowsLocaleMatchingCountry(
          this.winLocale.timeZoneId,
          proxyCountryCode,
          proxyCountryCode
        )
      : false;

    const defaultRegionMatched =
      !cfg.defaultCountryCode ||
      (proxyCountryCode !== null && cfg.defaultCountryCode.toUpperCase() === proxyCountryCode);

    const threeWayMatched = Boolean(
      proxyCountryCode && winRegionMatched && winTimeZoneMatched && defaultRegionMatched
    );

    let launchBlockReason: string | null = null;
    if (!this.claudeDetectedExe) {
      launchBlockReason = '未检测到 Claude Desktop 安装路径，请手动指定 Claude.exe';
    } else if (!cfg.selectedClashNode) {
      launchBlockReason = '请先在下方选择要绑定的 Clash Verge Rev 代理节点';
    } else if (!clash.connected) {
      launchBlockReason = '未连接到 Clash Verge Rev 控制接口，请确认 Clash Verge 已启动';
    } else if (!clash.dedicatedPortListening) {
      launchBlockReason = `节点 [${cfg.selectedClashNode}] 专属端口 (127.0.0.1:${cfg.dedicatedProxyPort}) 尚未就绪`;
    } else if (this.isChecking && !this.lastProbe && !this.lastError) {
      launchBlockReason = '正在验证指定节点的真实出口 IP 与归属地...';
    } else if (this.lastError || !proxyCountryCode) {
      launchBlockReason = `指定节点出口探测异常：${this.lastError || '未获取到有效出口国家'}`;
    } else if (!defaultRegionMatched) {
      launchBlockReason = `节点出口 [${proxyCountryName} (${proxyCountryCode})] 与锁定的默认保护地区 [${cfg.defaultCountryName} (${cfg.defaultCountryCode})] 不符`;
    } else if (!winRegionMatched) {
      launchBlockReason = `系统区域 [${this.winLocale.regionName} (${this.winLocale.regionCode})] 与节点出口 [${proxyCountryName} (${proxyCountryCode})] 不一致，请点击下方一键同步`;
    } else if (!winTimeZoneMatched) {
      launchBlockReason = `系统时区 [${this.winLocale.timeZoneDisplayName}] 与节点出口 [${proxyCountryName} (${proxyCountryCode})] 不一致，请点击下方一键同步`;
    }

    return {
      detectedExePath: this.claudeDetectedExe,
      installType: this.claudeInstallType,
      running: this.claudeRunning,
      processCount: this.claudeProcessCount,
      authorizedSession: this.claudeAuthorizedSession,
      canLaunch: launchBlockReason === null,
      launchBlockReason,
      threeWayMatched,
      proxyCountryCode,
      proxyCountryName,
      winRegionMatched,
      winTimeZoneMatched,
    };
  }

  private buildAntigravityRuntimeState(clashInfo?: ClashRuntimeInfo): AntigravityRuntimeState {
    const cfg = this.configStore.get();
    const clash = clashInfo || this.clashMonitor.getRuntimeInfo();

    let launchHint: string | null = null;
    if (!this.antigravityDetectedExe) {
      launchHint = '未检测到 Antigravity.exe 安装路径，请在下方手动浏览指定';
    } else if (!cfg.antigravityClashNode) {
      launchHint = '请先在下方下拉框中选择要绑定的 Clash 代理节点';
    } else if (!clash.connected) {
      launchHint = '未连接到 Clash Verge / Mihomo 控制接口，请确认 Clash 已启动';
    } else if (!clash.antigravityPortListening) {
      launchHint = `正在准备节点 [${cfg.antigravityClashNode}] 的专属代理端口 (127.0.0.1:${cfg.antigravityDedicatedPort})...`;
    }

    return {
      detectedExePath: this.antigravityDetectedExe,
      installType: this.antigravityInstallType,
      running: this.antigravityRunning,
      uiProcessCount: this.antigravityUiCount,
      languageServerCount: this.antigravityLsCount,
      totalProcessCount: this.antigravityTotalCount,
      proxiedSession: this.antigravityProxiedSession,
      canLaunch: launchHint === null,
      launchHint,
      isProbingNode: this.antigravityIsProbing,
      nodeProbe: this.antigravityNodeProbe ? { ...this.antigravityNodeProbe } : null,
      nodeProbeError: this.antigravityNodeProbeError,
    };
  }

  private startLocalEnvironmentWatcher(): void {
    const scheduleNext = (delayMs: number) => {
      if (this.stopped) return;
      if (this.localEnvTimer) {
        clearTimeout(this.localEnvTimer);
      }
      this.localEnvTimer = setTimeout(() => {
        this.localEnvTimer = null;
        void runEnvTick();
      }, delayMs);
    };

    const runEnvTick = async () => {
      if (this.stopped) return;
      this.envTickCounter = (this.envTickCounter + 1) % 2;
      const cfg = this.configStore.get();

      try {
        // 0. 刷新 Antigravity 进程运行状态（仅状态展示，不做任何拦截或强杀）
        const agProc = await inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort);
        const agStateChanged =
          agProc.running !== this.antigravityRunning ||
          agProc.uiProcessCount !== this.antigravityUiCount ||
          agProc.languageServerCount !== this.antigravityLsCount ||
          agProc.proxiedSession !== this.antigravityProxiedSession;
        if (agStateChanged) {
          this.antigravityRunning = agProc.running;
          this.antigravityUiCount = agProc.uiProcessCount;
          this.antigravityLsCount = agProc.languageServerCount;
          this.antigravityTotalCount = agProc.totalProcessCount;
          this.antigravityProxiedSession = agProc.proxiedSession;
          this.emitState();
        }

        // 1. 每 ~7 秒同步一次外部手动修改的 Windows 时区与区域
        if (this.envTickCounter === 0 && !this.isSyncingLocale) {
          const latestLocale = await readWindowsLocaleState();
          const localeChanged =
            latestLocale.timeZoneId !== this.winLocale.timeZoneId ||
            latestLocale.regionCode !== this.winLocale.regionCode;
          if (localeChanged) {
            this.winLocale = latestLocale;
            this.addLog(
              'info',
              `检测到系统区域/时区变更：${latestLocale.regionName} (${latestLocale.regionCode}) · ${latestLocale.timeZoneDisplayName}`
            );
            this.evaluateStatusOnly('系统时区或区域变更');
          }
        }

        // 2. 后台持续进程守护（通用受保护进程列表 + 指定代理/默认地区校验）
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

        // 3. 当未指定固定 Clash 节点时，监测系统代理与网卡路由变动
        if (!cfg.selectedClashNode) {
          const sys = await this.getSystemProxyFresh(true);
          const sysSnap = `${sys.enabled}|${sys.proxyUrl || ''}`;
          if (this.lastSysProxySnapshot && sysSnap !== this.lastSysProxySnapshot) {
            this.lastSysProxySnapshot = sysSnap;
            const desc = sys.enabled ? `开启 (${sys.proxyUrl})` : '已关闭';
            this.addLog('info', `系统代理设置变更：${desc}`);
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
              this.addLog('info', '检测到本机网络接口 / TUN 虚拟网卡变动');
              void this.checkNow('本机网卡 / TUN 路由变动');
            }, 450);
          }
        }
      } catch {
        // ignore transient polling errors
      }

      scheduleNext(3500);
    };

    scheduleNext(3500);
  }

  /**
   * 获取当前用于对比时区/区域的基准国家代码：
   * 优先使用已锁定的 defaultCountryCode；若已指定 Clash 节点且探测出了有效国家代码，则以指定节点的国家代码为准
   */
  private getEffectiveTargetCountryCode(): string | null {
    const cfg = this.configStore.get();
    if (cfg.defaultCountryCode && isValidIsoCountryCode(cfg.defaultCountryCode)) {
      return cfg.defaultCountryCode.toUpperCase();
    }
    if (
      cfg.selectedClashNode &&
      this.lastProbe &&
      isValidIsoCountryCode(this.lastProbe.countryCode)
    ) {
      return this.lastProbe.countryCode.toUpperCase();
    }
    return null;
  }

  public getSnapshot(): AppStateSnapshot {
    const clashInfo = this.clashMonitor.getRuntimeInfo();
    return {
      status: this.status,
      isChecking: this.isChecking,
      isSyncingLocale: this.isSyncingLocale,
      config: this.configStore.get(),
      winLocale: { ...this.winLocale },
      lastProbe: this.lastProbe ? { ...this.lastProbe } : null,
      lastError: this.lastError,
      clashInfo,
      claudeState: this.buildClaudeRuntimeState(clashInfo),
      antigravityState: this.buildAntigravityRuntimeState(clashInfo),
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
    const effectiveTarget = this.getEffectiveTargetCountryCode();

    if (this.lastError) {
      this.status = 'error';
      if (!effectiveTarget) {
        this.lastAlertSignature = null;
        this.lastGuardFailSignature = null;
      } else {
        void this.handleDisconnectTransition(reason || '状态更新', this.lastError);
      }
      this.emitState();
      return this.getSnapshot();
    }

    if (this.lastProbe) {
      const probeCode = this.lastProbe.countryCode.toUpperCase();
      const localeMatchedWithProbe = isWindowsLocaleMatchingCountry(
        this.winLocale.timeZoneId,
        this.winLocale.regionCode,
        probeCode
      );

      if (!cfg.defaultCountryCode && !cfg.selectedClashNode) {
        this.status = 'unset';
        this.lastAlertSignature = null;
        this.lastGuardFailSignature = null;
      } else if (cfg.defaultCountryCode && probeCode !== cfg.defaultCountryCode.toUpperCase()) {
        this.status = 'mismatch';
        void this.handleMismatchTransition(reason || '默认地区配置更新');
        this.emitState();
        return this.getSnapshot();
      } else if (!localeMatchedWithProbe) {
        this.status = 'mismatch';
        void this.handleLocaleMismatchTransition(reason || '系统时区或区域变更');
        this.emitState();
        return this.getSnapshot();
      } else {
        this.status = 'ok';
        if (this.lastAlertSignature !== null) {
          this.lastAlertSignature = null;
          this.emitRecoveredAlert();
        }
      }
    }

    if (effectiveTarget) {
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
      let channel = await this.resolveProxyChannel();
      const endpoints = this.buildEndpointsList();

      const tryProbeOnce = async (
        proxyUrl: string | null,
        viaDesc: string
      ): Promise<{ result: ProbeResult | null; errMsg: string }> => {
        let errOut = '所有回显探测源均不可达';
        for (const ep of endpoints) {
          try {
            const startedAt = Date.now();
            const rawBody = await requestTextViaProxy(ep.url, proxyUrl, 6000);
            const latencyMs = Date.now() - startedAt;

            const parsed = parseTraceResponse(rawBody, ep.format);
            if (!parsed.ip) {
              throw new Error('响应中未解析到有效公网 IP');
            }

            const geo = this.geoIp.lookup(parsed.ip, parsed.loc);
            return {
              result: {
                ip: parsed.ip,
                countryCode: geo.countryCode,
                countryName: geo.countryName,
                edgeLoc: parsed.loc,
                viaChannel: viaDesc,
                latencyMs,
                checkedAt: Date.now(),
              },
              errMsg: '',
            };
          } catch (err) {
            errOut = err instanceof Error ? err.message : String(err);
          }
        }
        return { result: null, errMsg: errOut };
      };

      let probeSuccess: ProbeResult | null = null;
      let lastErrMsg = channel.errorHint || '所有回显探测源均不可达';

      if (!channel.errorHint) {
        const firstTry = await tryProbeOnce(channel.proxyUrl, channel.description);
        probeSuccess = firstTry.result;
        if (!probeSuccess) {
          lastErrMsg = firstTry.errMsg;
        }
      }

      const cfg = this.configStore.get();

      // 若指定了 Clash 专属节点，且探测恰好撞上 Clash Verge 切换订阅组导致瞬时闪断，
      // 自动执行一次跨订阅节点强制重绑并重试探测，确保持续守护不误判为断连
      if (!probeSuccess && cfg.selectedClashNode) {
        await sleep(320);
        const rebindRes = await this.clashMonitor.configureDedicatedNode(
          cfg.selectedClashNode,
          cfg.dedicatedProxyPort,
          cfg.selectedClashProfileUid,
          true
        );
        if (rebindRes.ok && rebindRes.listening) {
          channel = await this.resolveProxyChannel();
          if (!channel.errorHint) {
            const retryRes = await tryProbeOnce(channel.proxyUrl, channel.description);
            probeSuccess = retryRes.result;
            if (!probeSuccess) {
              lastErrMsg = retryRes.errMsg;
            }
          }
        }
      }

      if (probeSuccess) {
        const prevIp = this.lastProbe?.ip;
        const prevCountry = this.lastProbe?.countryCode;

        this.lastProbe = probeSuccess;
        this.lastError = null;

        const probeCode = probeSuccess.countryCode.toUpperCase();
        const localeMatchedWithProbe = isWindowsLocaleMatchingCountry(
          this.winLocale.timeZoneId,
          this.winLocale.regionCode,
          probeCode
        );

        if (!cfg.defaultCountryCode && !cfg.selectedClashNode) {
          this.status = 'unset';
          this.lastAlertSignature = null;
          this.lastGuardFailSignature = null;
          if (prevIp !== probeSuccess.ip || prevCountry !== probeSuccess.countryCode) {
            this.addLog(
              'info',
              `当前出口: ${probeSuccess.countryName} (${probeSuccess.countryCode}) · ${probeSuccess.ip}`
            );
          }
        } else if (cfg.defaultCountryCode && probeCode !== cfg.defaultCountryCode.toUpperCase()) {
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
        } else if (!localeMatchedWithProbe) {
          this.status = 'mismatch';
          if (
            prevIp !== probeSuccess.ip ||
            prevCountry !== probeSuccess.countryCode ||
            reason !== '轻量心跳巡检'
          ) {
            this.addLog(
              'warn',
              `代理出口 [${probeSuccess.countryName} (${probeCode})] 与系统时区/区域 [${this.winLocale.regionName} (${this.winLocale.regionCode})] 不一致 · IP: ${probeSuccess.ip}`
            );
          }
          await this.handleLocaleMismatchTransition(reason);
        } else {
          const wasAbnormal = this.status === 'mismatch' || this.status === 'error';
          this.status = 'ok';
          if (
            wasAbnormal ||
            prevIp !== probeSuccess.ip ||
            prevCountry !== probeSuccess.countryCode
          ) {
            this.addLog(
              'success',
              `代理与时区校验一致 [${probeSuccess.countryName}] · IP: ${probeSuccess.ip} (${probeSuccess.latencyMs}ms)`
            );
          }
          if (this.lastAlertSignature !== null) {
            this.lastAlertSignature = null;
            this.emitRecoveredAlert();
          }
          await this.enforceProcessGuardInBackground();
        }
      } else {
        this.lastError = channel.errorHint
          ? channel.errorHint
          : simplifyNetworkError(lastErrMsg, channel.description);
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
   * 根据当前指定代理节点的出口地区（或默认保护地区）一键同步 Windows 时区与区域
   */
  public async syncSystemLocaleToDefault(): Promise<LocaleSyncResult> {
    const cfg = this.configStore.get();
    const probeCode =
      this.lastProbe && isValidIsoCountryCode(this.lastProbe.countryCode)
        ? this.lastProbe.countryCode.toUpperCase()
        : null;
    const defCode =
      cfg.defaultCountryCode && isValidIsoCountryCode(cfg.defaultCountryCode)
        ? cfg.defaultCountryCode.toUpperCase()
        : null;

    // 若已设置默认保护地区，始终以默认保护地区为准，避免被节点切换或异常出口覆盖；
    // 仅当尚未设置默认保护地区时，才使用当前探测地区并自动初始化默认保护地区
    const targetCode = defCode || probeCode;

    if (!targetCode) {
      return {
        ok: false,
        message: '请先选择 Clash 代理节点并等待检测出有效出口地区，或先设置默认保护地区',
        killedProcesses: [],
        state: this.getSnapshot(),
      };
    }

    if (!defCode && probeCode) {
      this.configStore.update({
        defaultCountryCode: probeCode,
        defaultCountryName: getCountryNameZh(probeCode),
      });
    }

    this.isSyncingLocale = true;
    this.emitState();

    try {
      let exactIanaTz: string | null = null;
      const needsCityTzLookup =
        isMultiTimeZoneCountry(targetCode) || !hasOfflineTimeZoneMapping(targetCode);

      if (needsCityTzLookup && this.lastProbe && this.lastProbe.countryCode === targetCode) {
        const ch = await this.resolveProxyChannel();
        if (!ch.errorHint) {
          exactIanaTz = await queryExactExitIanaTimeZone(ch.proxyUrl, targetCode);
        }
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
      this.evaluateStatusOnly('完成一键同步系统时区与区域');

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
   * 若与当前指定节点出口 IP 或默认地区不一致，严格执行“先强杀 Claude 及受保护进程并确认全部退出后，才允许切换回中国时区”
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

      // 合并 Claude 进程规则与用户自定义守护进程规则，确保还原中国时区前 Claude 100% 被先行强杀
      const combinedPatterns = Array.from(
        new Set([
          ...CLAUDE_DESKTOP_PROCESS_PATTERNS,
          ...(cfg.killProcessesEnabled ? cfg.protectedProcessPatterns : []),
        ])
      );

      if (mismatchWithCurrentEnv && combinedPatterns.length > 0) {
        this.unsetClaudeAuthLock();

        const killReport = await this.executeProcessKillSafely(combinedPatterns);

        if (killReport.killedCount > 0) {
          killedProcesses.push(...killReport.killedSummary);
          this.addLog(
            'danger',
            `还原中国时区前检测到代理地区非中国，已先行强杀进程：${killReport.killedSummary.join(', ')}`
          );
        }

        if (killReport.failedPids.length > 0) {
          const abortMsg = `${
            killReport.errorDetail || '部分受保护进程无法终止'
          }，已中止还原中国时区以防暴露！`;
          this.addLog('danger', abortMsg);

          const expectedCode = ipCountry || defCountry || DEFAULT_CHINA_REGION_CODE;
          const expectedName =
            this.lastProbe?.countryName || cfg.defaultCountryName || expectedCode;
          this.emitAlert({
            alertType: 'locale-mismatch',
            expectedCode,
            expectedName,
            triggerReason: '还原中国时区被安全拦截（受保护进程未能终止）',
            killedProcesses: killedProcesses.length > 0 ? killedProcesses : undefined,
            killError: killReport.errorDetail,
          });

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

      this.evaluateStatusOnly('还原默认中国时区');

      const killedSuffix =
        killedProcesses.length > 0 ? `（已先行终止：${killedProcesses.join(', ')}）` : '';
      const okMsg = `已还原为默认时区 [${applyRes.updated.timeZoneDisplayName}] · 区域 [${applyRes.updated.regionName}]${killedSuffix}`;
      this.addLog('info', okMsg);

      if (killedProcesses.length > 0) {
        const expectedCode = ipCountry || defCountry || DEFAULT_CHINA_REGION_CODE;
        const expectedName =
          this.lastProbe?.countryName || cfg.defaultCountryName || expectedCode;
        this.lastAlertSignature = `locale-mismatch:${expectedCode}`;
        this.emitAlert({
          alertType: 'locale-mismatch',
          expectedCode,
          expectedName,
          triggerReason: '手动还原中国时区（与代理地区不一致，已先行强杀进程）',
          killedProcesses,
        });
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

  /**
   * 串行化进程强杀队列：确保并发触发的强杀调用等待真实强杀结果，并在每次强杀后同步刷新 Claude 进程计数
   */
  private async executeProcessKillSafely(patterns: string[]): Promise<ProcessKillReport> {
    const run = async (): Promise<ProcessKillReport> => {
      this.activeKillCount++;
      try {
        const report = await terminateProtectedProcesses(patterns);
        const claudeNow = await countRunningClaudeProcesses();
        this.claudeRunning = claudeNow.running;
        this.claudeProcessCount = claudeNow.count;
        this.claudeRunningPids = claudeNow.pids;
        this.claudeFastCheckTicks = 0;
        return report;
      } finally {
        this.activeKillCount--;
      }
    };

    const task = this.killQueue.then(run, run);
    this.killQueue = task.then(
      () => undefined,
      () => undefined
    );
    return task;
  }

  private async enforceProcessGuardInBackground(): Promise<void> {
    const cfg = this.configStore.get();
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
      unsafeReason = `出口地区 [${this.lastProbe.countryName}] 与默认地区 [${cfg.defaultCountryName}] 不符`;
    } else if (this.status === 'error' && cfg.killOnDisconnect) {
      unsafeType = 'disconnect';
      unsafeReason = '代理连接异常断开期间禁止运行受保护进程';
    } else if (
      cfg.killOnLocaleMismatch &&
      !isWindowsLocaleMatchingCountry(
        this.winLocale.timeZoneId,
        this.winLocale.regionCode,
        targetCountry
      )
    ) {
      unsafeType = 'locale-mismatch';
      unsafeReason = `系统时区/区域 (${this.winLocale.regionName}) 与指定代理地区 (${targetCountryName}) 不一致`;
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
      this.lastAlertSignature = `locale-mismatch:${targetCountry}:${this.winLocale.regionCode}:${this.winLocale.timeZoneId}`;
    }

    this.emitAlert({
      alertType: unsafeType,
      expectedCode: targetCountry,
      expectedName: targetCountryName,
      triggerReason: unsafeReason,
      errorDetail: unsafeType === 'disconnect' ? this.lastError || undefined : undefined,
      killedProcesses: report.killedCount > 0 ? report.killedSummary : undefined,
      killError: report.errorDetail,
    });
  }

  private async handleLocaleMismatchTransition(reason: string): Promise<void> {
    if (!this.lastProbe) return;
    const probeCode = this.lastProbe.countryCode.toUpperCase();
    const sig = `locale-mismatch:${probeCode}:${this.winLocale.regionCode}:${this.winLocale.timeZoneId}`;
    const prevSig = this.lastAlertSignature;

    await this.enforceProcessGuardInBackground();

    // 若后台进程守护已发送告警并更新了签名，则不重复弹窗；否则在首次检测到时区/区域不匹配时弹出告警
    if (this.lastAlertSignature === sig && prevSig === sig) {
      return;
    }
    if (this.lastAlertSignature !== sig) {
      this.lastAlertSignature = sig;
      this.emitAlert({
        alertType: 'locale-mismatch',
        expectedCode: probeCode,
        expectedName: this.lastProbe.countryName || getCountryNameZh(probeCode),
        triggerReason: `${reason}：系统时区/区域 (${this.winLocale.regionName}) 与代理出口 (${this.lastProbe.countryName}) 不一致`,
      });
    }
  }

  private async handleMismatchTransition(reason: string): Promise<void> {
    const cfg = this.configStore.get();
    if (!cfg.defaultCountryCode || !this.lastProbe) return;

    let killedProcesses: string[] | undefined;
    let killError: string | undefined;
    let addedLogs = false;

    const patternsToKill = Array.from(
      new Set([
        ...CLAUDE_DESKTOP_PROCESS_PATTERNS,
        ...(cfg.killProcessesEnabled ? cfg.protectedProcessPatterns : []),
      ])
    );

    if (patternsToKill.length > 0) {
      this.unsetClaudeAuthLock();

      const report = await this.executeProcessKillSafely(patternsToKill);

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

    this.emitAlert({
      alertType: 'mismatch',
      expectedCode: cfg.defaultCountryCode,
      expectedName: cfg.defaultCountryName,
      triggerReason: reason,
      killedProcesses,
      killError,
    });
  }

  private async handleDisconnectTransition(reason: string, errDetail: string): Promise<void> {
    const cfg = this.configStore.get();
    const targetCountry = this.getEffectiveTargetCountryCode();
    if (!targetCountry && !this.claudeRunning) return;

    let killedProcesses: string[] | undefined;
    let killError: string | undefined;
    let addedLogs = false;

    const patternsToKill = Array.from(
      new Set([
        ...CLAUDE_DESKTOP_PROCESS_PATTERNS,
        ...(cfg.killProcessesEnabled && cfg.killOnDisconnect ? cfg.protectedProcessPatterns : []),
      ])
    );

    if (patternsToKill.length > 0) {
      this.unsetClaudeAuthLock();

      const report = await this.executeProcessKillSafely(patternsToKill);

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

    if (!cfg.alertOnDisconnect || !targetCountry) return;

    const sig = `disconnect:${targetCountry}`;
    const isSameSig = this.lastAlertSignature === sig;
    this.lastAlertSignature = sig;

    if (isSameSig && (!killedProcesses || killedProcesses.length === 0) && !killError) {
      return;
    }

    this.emitAlert({
      alertType: 'disconnect',
      expectedCode: targetCountry,
      expectedName: getCountryNameZh(targetCountry),
      triggerReason: reason,
      errorDetail: errDetail,
      killedProcesses,
      killError,
    });
  }

  private emitAlert(opts: {
    alertType: AlertPayload['alertType'];
    expectedCode: string | null;
    expectedName: string | null;
    triggerReason: string;
    errorDetail?: string;
    killedProcesses?: string[];
    killError?: string;
  }): void {
    const cfg = this.configStore.get();
    if (!cfg.alertPopupEnabled) return;

    const clash = this.clashMonitor.getRuntimeInfo();
    const isDisconnect = opts.alertType === 'disconnect';
    const selectedFullLabel = cfg.selectedClashNode
      ? cfg.selectedClashProfileName
        ? `${cfg.selectedClashProfileName} / ${cfg.selectedClashNode}`
        : cfg.selectedClashNode
      : null;

    const payload: AlertPayload = {
      alertType: opts.alertType,
      expectedCode: opts.expectedCode,
      expectedName: opts.expectedName,
      actualCode: isDisconnect ? null : this.lastProbe?.countryCode || null,
      actualName: isDisconnect ? '连接断开' : this.lastProbe?.countryName || null,
      actualIp: isDisconnect ? null : this.lastProbe?.ip || null,
      edgeLoc: this.lastProbe?.edgeLoc,
      viaChannel: this.lastProbe?.viaChannel,
      activeNode: selectedFullLabel || (clash.connected ? clash.activeNode : null),
      triggerReason: opts.triggerReason,
      errorDetail: opts.errorDetail,
      killedProcesses: opts.killedProcesses,
      killError: opts.killError,
      sysRegionCode: this.winLocale.regionCode,
      sysRegionName: this.winLocale.regionName,
      sysTimeZoneDisplay: this.winLocale.timeZoneDisplayName,
      soundEnabled: cfg.alertSoundEnabled,
      timestamp: Date.now(),
    };

    this.emit('trigger-alert', payload);
  }

  private emitRecoveredAlert(): void {
    const cfg = this.configStore.get();
    if (!this.lastProbe) return;
    const targetCode = cfg.defaultCountryCode || this.lastProbe.countryCode;
    const payload: AlertPayload = {
      alertType: 'recovered',
      expectedCode: targetCode,
      expectedName: getCountryNameZh(targetCode),
      actualCode: this.lastProbe.countryCode,
      actualName: this.lastProbe.countryName,
      actualIp: this.lastProbe.ip,
      viaChannel: this.lastProbe.viaChannel,
      triggerReason: '指定代理地区与系统时区/区域已恢复一致',
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

  /**
   * 代理检测通道解析：
   * 若用户已在下拉框指定了 Clash 节点，则 100% 强制通过该节点的独立专属本地端口 (127.0.0.1:dedicatedProxyPort) 探测；
   * 仅当未指定节点时，才按 proxyMode (auto/manual/direct) 走系统全局或手动端口。
   */
  private async resolveProxyChannel(): Promise<{
    proxyUrl: string | null;
    description: string;
    errorHint?: string;
  }> {
    let cfg = this.configStore.get();

    if (cfg.selectedClashNode) {
      let clash = this.clashMonitor.getRuntimeInfo();
      if (!clash.connected || !clash.dedicatedPortListening) {
        const bindRes = await this.clashMonitor.configureDedicatedNode(
          cfg.selectedClashNode,
          cfg.dedicatedProxyPort,
          cfg.selectedClashProfileUid,
          false
        );
        if (bindRes.nodeRaw && !cfg.selectedClashNodeRaw) {
          cfg = this.configStore.update({
            selectedClashProfileUid: bindRes.profileUid ?? cfg.selectedClashProfileUid,
            selectedClashProfileName: bindRes.profileName ?? cfg.selectedClashProfileName,
            selectedClashNodeRaw: bindRes.nodeRaw,
            selectedClashNodeDialerRaw: bindRes.dialerRaw ?? null,
          });
        }
        clash = this.clashMonitor.getRuntimeInfo();
        const label = cfg.selectedClashProfileName
          ? `${cfg.selectedClashProfileName} / ${cfg.selectedClashNode}`
          : cfg.selectedClashNode;
        if (!bindRes.ok || !bindRes.listening) {
          return {
            proxyUrl: `http://127.0.0.1:${cfg.dedicatedProxyPort}`,
            description: `指定节点 [${label}] (127.0.0.1:${cfg.dedicatedProxyPort})`,
            errorHint:
              bindRes.error ||
              `无法绑定指定节点 [${label}] 的专属代理端口 (127.0.0.1:${cfg.dedicatedProxyPort})`,
          };
        }
      }

      const label =
        cfg.selectedClashProfileName || clash.boundProfileName
          ? `${cfg.selectedClashProfileName || clash.boundProfileName} / ${cfg.selectedClashNode}`
          : cfg.selectedClashNode;

      return {
        proxyUrl: `http://127.0.0.1:${cfg.dedicatedProxyPort}`,
        description: `指定节点 [${label}] (127.0.0.1:${cfg.dedicatedProxyPort})`,
      };
    }

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
    return `经由 [${channelDesc}] 访问超时，当前指定的代理节点可能已失效`;
  }
  if (errMsg.includes('ENOTFOUND')) {
    return `DNS 解析失败 (${channelDesc})，网络连接异常`;
  }
  return `${errMsg} (${channelDesc})`;
}
