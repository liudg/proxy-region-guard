import { EventEmitter } from 'node:events';
import * as net from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  AlertPayload,
  AntigravityLaunchResult,
  AntigravityRuntimeState,
  AppConfig,
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
import {
  getCountryNameZh,
  isValidIsoCountryCode,
  normalizeIsoCountryCode,
} from '../src/shared/countries';
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
import { ClashMonitor, isLocalPortListening } from './clashMonitor';
import {
  getNetworkInterfaceFingerprint,
  readWindowsSystemProxy,
  SystemProxyState,
} from './systemProxy';
import { assertProcessesStopped, ProcessKillReport, terminateProtectedProcesses } from './processGuard';
import { getTargetServiceVerificationError } from '../src/shared/probeValidation';
import { ClaudeVerificationRecovery } from './claudeVerificationRecovery';
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
  getLaunchedClaudePort,
  markClaudeLaunchedByGuard,
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

interface ClaudeSafetyCheck {
  safe: boolean;
  reason: string;
  alertType: 'mismatch' | 'disconnect' | 'locale-mismatch' | 'verification-unavailable';
}

const BUILTIN_TRACE_ENDPOINTS: TraceEndpoint[] = [
  {
    name: 'Cloudflare IPv4 Trace',
    url: 'https://ipv4.icanhazip.com/cdn-cgi/trace',
    format: 'cf-trace',
  },
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
    name: 'AWS CheckIP (IPv4)',
    url: 'https://checkip.amazonaws.com',
    format: 'plain-ip',
  },
  {
    name: 'Cloudflare ICanHazIP (IPv4)',
    url: 'https://ipv4.icanhazip.com',
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
  private applicationChangeInProgress = false;
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

  // Claude 专栏运行时状态、独立节点探测与唯一启动入口授权锁
  private claudeDetectedExe: string | null = null;
  private claudeInstallType: ClaudeRuntimeState['installType'] = 'not-found';
  private claudeRunning = false;
  private claudeProcessCount = 0;
  private claudeRunningPids: number[] = [];
  private claudeFastCheckTicks = 0;
  private claudeAuthorizedSession = false;
  private claudeSeenRunningSinceAuth = false;
  private claudeLaunchGraceUntil = 0;
  private claudeIsProbing = false;
  private claudeProbePromise: Promise<AppStateSnapshot> | null = null;
  private claudeProbeSeq = 0;
  private claudePendingProbe: { reason: string; skipSafetyEnforcement: boolean } | null = null;
  private claudeSwitchingCount = 0;
  private claudeSafetyKillPromise: Promise<boolean> | null = null;
  private claudeNodeProbe: ProbeResult | null = null;
  private claudeNodeProbeError: string | null = null;
  private claudeLastVerificationSuccessAt: number | null = null;
  private claudeLastVerifiedRegion: {
    node: string;
    profileUid: string | null;
    port: number;
    countryCode: string;
    countryName: string;
  } | null = null;
  private readonly claudeVerificationRecovery: ClaudeVerificationRecovery;

  // Antigravity 启动器专栏状态（纯代理指定，无监控预警、无时区限制、无断连强杀）
  private antigravityDetectedExe: string | null = null;
  private antigravityInstallType: AntigravityRuntimeState['installType'] = 'not-found';
  private antigravityRunning = false;
  private antigravityUiCount = 0;
  private antigravityLsCount = 0;
  private antigravityTotalCount = 0;
  private antigravityProxiedSession = false;
  private antigravityIsProbing = false;
  private antigravityProbePromise: Promise<AppStateSnapshot> | null = null;
  private antigravityProbeSeq = 0;
  private antigravityPendingReprobe = false;
  private antigravitySwitchingCount = 0;
  private antigravityNodeProbe: ProbeResult | null = null;
  private antigravityNodeProbeError: string | null = null;

  private heartbeatTimer: NodeJS.Timeout | null = null;
  private localEnvTimer: NodeJS.Timeout | null = null;
  private claudeWatchTimer: NodeJS.Timeout | null = null;
  private clashDebounceTimer: NodeJS.Timeout | null = null;
  private claudeDebounceTimer: NodeJS.Timeout | null = null;
  private antigravityDebounceTimer: NodeJS.Timeout | null = null;
  private netDebounceTimer: NodeJS.Timeout | null = null;

  private cachedSysProxy: { state: SystemProxyState; readAt: number } | null = null;
  private envTickCounter = 0;
  private lastSysProxySnapshot = '';
  private lastNetFingerprint = '';
  private lastAlertSignature: string | null = null;
  private lastGuardFailSignature: string | null = null;
  private targetVerifyCache = new Map<
    string,
    {
      checkedAt: number;
      googleCountryCode?: string;
      googleCountryName?: string;
      claudeTraceLoc?: string;
      claudeTraceIp?: string;
      regionMismatchDetail?: string | null;
    }
  >();

  constructor(configStore: ConfigStore, geoIp: GeoIpService, clashMonitor: ClashMonitor) {
    super();
    this.configStore = configStore;
    this.geoIp = geoIp;
    this.clashMonitor = clashMonitor;
    this.claudeVerificationRecovery = new ClaudeVerificationRecovery(
      async () => {
        if (this.stopped || !this.claudeRunning) {
          this.claudeVerificationRecovery.clear();
          return;
        }
        if (!this.claudeProbePromise && !this.claudeSafetyKillPromise) {
          await this.probeClaudeNodeNow('Claude 运行期后台复核');
        }
      },
      async (failure) => {
        if (this.stopped || !this.claudeRunning) return;
        await this.terminateUnsafeClaude({
          safe: false,
          alertType: 'verification-unavailable',
          reason: `持续 30 秒无法完成地区校验：${failure.reason}`,
        }, 'Claude 运行期后台复核');
      }
    );

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

    this.clashMonitor.on('claude-clash-ready', (definitionChanged = false) => {
      if (definitionChanged) {
        this.claudeProbeSeq++;
        this.claudeNodeProbe = null;
        this.claudeNodeProbeError = null;
      }
      this.emitState();
      const cfg = this.configStore.get();
      const info = this.clashMonitor.getRuntimeInfo();
      if (cfg.selectedClashNode && info.dedicatedPortListening && this.claudeSwitchingCount === 0 &&
          (!this.claudeIsProbing || definitionChanged)) {
        if (this.claudeDebounceTimer) {
          clearTimeout(this.claudeDebounceTimer);
        }
        this.claudeDebounceTimer = setTimeout(() => {
          this.claudeDebounceTimer = null;
          void this.probeClaudeNodeNow('Claude 专属代理端口已就绪');
        }, 250);
      }
    });

    this.clashMonitor.on('antigravity-clash-ready', (definitionChanged = false) => {
      if (definitionChanged) {
        this.antigravityProbeSeq++;
        this.antigravityNodeProbe = null;
        this.antigravityNodeProbeError = null;
      }
      this.emitState();
      const cfg = this.configStore.get();
      const info = this.clashMonitor.getRuntimeInfo();
      if (cfg.antigravityClashNode && info.antigravityPortListening && this.antigravitySwitchingCount === 0 &&
          (!this.antigravityIsProbing || definitionChanged)) {
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

      const cfg = this.configStore.get();
      if (
        info.connected &&
        cfg.selectedClashNode &&
        info.dedicatedPortListening &&
        !this.claudeNodeProbe &&
        !this.claudeNodeProbeError &&
        !this.claudeIsProbing
      ) {
        if (this.claudeDebounceTimer) {
          clearTimeout(this.claudeDebounceTimer);
        }
        this.claudeDebounceTimer = setTimeout(() => {
          this.claudeDebounceTimer = null;
          void this.probeClaudeNodeNow('Clash 控制接口已连接');
        }, 300);
      }

      if (
        info.connected &&
        cfg.antigravityClashNode &&
        info.antigravityPortListening &&
        !this.antigravityNodeProbe &&
        !this.antigravityNodeProbeError &&
        !this.antigravityIsProbing
      ) {
        if (this.antigravityDebounceTimer) {
          clearTimeout(this.antigravityDebounceTimer);
        }
        this.antigravityDebounceTimer = setTimeout(() => {
          this.antigravityDebounceTimer = null;
          void this.probeAntigravityNodeNow();
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
      cfg.antigravityClashProfileUid,
      cfg.antigravityClashProfileName
    );
    this.startLocalEnvironmentWatcher();
    this.startClaudeExclusiveWatcher();
    this.restartHeartbeatTimer();

    if (cfg.selectedClashNode) {
      void this.probeClaudeNodeNow('应用启动检测 Claude 专属节点');
    }
    await this.checkNow('应用启动首次检测');
  }

  public stop(): void {
    if (this.stopped) return;
    this.stopped = true;
    this.claudeVerificationRecovery.clear();

    const shouldKillClaudeOnExit =
      this.claudeRunning ||
      this.claudeAuthorizedSession ||
      this.configStore.get().claudeExclusiveGuard;

    this.claudeAuthorizedSession = false;
    this.claudeSeenRunningSinceAuth = false;
    this.claudeLaunchGraceUntil = 0;
    markClaudeLaunchedByGuard(null);

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
    if (this.claudeDebounceTimer) {
      clearTimeout(this.claudeDebounceTimer);
      this.claudeDebounceTimer = null;
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
        // 1. Claude 选定节点独立巡检：当 Claude 运行中且已配置专属节点时，后台独立巡检 Claude 专属端口 (27897)
        if (this.claudeRunning && cfg.selectedClashNode) {
          void this.probeClaudeNodeNow('Claude 运行期心跳巡检');
        }
        // 2. 实时监控通道巡检：后台定时静默复核出口 IP 是否漂移
        void this.checkNow('轻量心跳巡检');
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
    return this.runApplicationChange(() => this.selectAntigravityClashNodeInternal(nodeName, profileUid));
  }

  private async selectAntigravityClashNodeInternal(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    this.antigravityProbeSeq++;
    this.antigravityNodeProbe = null;
    this.antigravityNodeProbeError = null;
    this.antigravitySwitchingCount++;
    try {
      await this.bindAntigravitySelection(nodeName, profileUid);
    } finally {
      this.antigravitySwitchingCount--;
    }
    if (this.configStore.get().antigravityClashNode &&
        this.clashMonitor.getRuntimeInfo().antigravityPortListening) {
      return this.probeAntigravityNodeNow();
    }
    return this.getSnapshot();
  }

  private async bindAntigravitySelection(
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

    if (cleanNode) {
      this.addLog(
        'info',
        `正在将 Antigravity 专属代理通道切换至节点：[${cleanNode}] (127.0.0.1:${prevCfg.antigravityDedicatedPort})...`
      );
      let cfg = prevCfg;
      const bindRes = await this.clashMonitor.configureAntigravityNode(
        cleanNode,
        prevCfg.antigravityDedicatedPort,
        effectiveProfileUid,
        true,
        (resolvedUid, resolvedName) => {
          cfg = this.configStore.update({
            antigravityClashNode: cleanNode,
            antigravityClashProfileUid: resolvedUid,
            antigravityClashProfileName: resolvedName,
          });
        }
      );

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
      return this.getSnapshot();
    } else {
      this.antigravityPendingReprobe = false;
      await this.clashMonitor.configureAntigravityNode(
        null,
        prevCfg.antigravityDedicatedPort,
        null,
        true,
        () => this.configStore.update({
          antigravityClashNode: null,
          antigravityClashProfileUid: null,
          antigravityClashProfileName: null,
        })
      );
      this.antigravityNodeProbe = null;
      this.antigravityNodeProbeError = null;
      if (prevCfg.antigravityClashNode) {
        this.addLog('info', '已取消 Antigravity 专属 Clash 节点绑定');
      }
      this.emitState();
      return this.getSnapshot();
    }
  }

  private isCurrentAntigravityProbe(sequence: number, config: AppConfig): boolean {
    const current = this.configStore.get();
    return this.antigravitySwitchingCount === 0 && this.antigravityProbeSeq === sequence &&
      current.antigravityClashNode === config.antigravityClashNode &&
      current.antigravityClashProfileUid === config.antigravityClashProfileUid &&
      current.antigravityDedicatedPort === config.antigravityDedicatedPort;
  }

  /** 探测 Antigravity 专属端口的出口地区，用于界面展示。 */
  public async probeAntigravityNodeNow(): Promise<AppStateSnapshot> {
    if (this.antigravitySwitchingCount > 0) return this.getSnapshot();
    const cfg = this.configStore.get();
    if (!cfg.antigravityClashNode) {
      this.antigravityProbeSeq++;
      this.antigravityPendingReprobe = false;
      this.antigravityNodeProbe = null;
      this.antigravityNodeProbeError = null;
      this.emitState();
      return this.getSnapshot();
    }

    if (this.antigravityProbePromise) {
      this.antigravityPendingReprobe = true;
      return this.antigravityProbePromise;
    }

    const runProbe = async (): Promise<AppStateSnapshot> => {
      this.antigravityIsProbing = true;
      this.emitState();

      try {
        while (!this.stopped) {
          if (this.antigravitySwitchingCount > 0) break;
          this.antigravityPendingReprobe = false;
          const seqAtStart = ++this.antigravityProbeSeq;
          const curCfg = this.configStore.get();
          const targetNode = curCfg.antigravityClashNode;
          const targetProfileUid = curCfg.antigravityClashProfileUid;
          if (!targetNode) {
            this.antigravityNodeProbe = null;
            this.antigravityNodeProbeError = null;
            break;
          }

          let clash = this.clashMonitor.getRuntimeInfo();
          if (!clash.connected || !clash.antigravityPortListening) {
            const bindRes = await this.clashMonitor.configureAntigravityNode(
              targetNode,
              curCfg.antigravityDedicatedPort,
              targetProfileUid,
              false
            );
            clash = this.clashMonitor.getRuntimeInfo();
            if (!bindRes.ok || !bindRes.listening) {
              const latestCfg = this.configStore.get();
              if (
                this.antigravityProbeSeq !== seqAtStart ||
                latestCfg.antigravityClashNode !== targetNode ||
                latestCfg.antigravityClashProfileUid !== targetProfileUid
              ) {
                if (latestCfg.antigravityClashNode) continue;
                this.antigravityNodeProbe = null;
                this.antigravityNodeProbeError = null;
                break;
              }
              this.antigravityNodeProbe = null;
              this.antigravityNodeProbeError =
                bindRes.error ||
                `专属端口 127.0.0.1:${curCfg.antigravityDedicatedPort} 未就绪`;
              if (this.antigravityPendingReprobe && this.configStore.get().antigravityClashNode) {
                continue;
              }
              break;
            }
          }

          const proxyUrl = `http://127.0.0.1:${curCfg.antigravityDedicatedPort}`;
          const channelDesc = `Antigravity 专属端口 (127.0.0.1:${curCfg.antigravityDedicatedPort})`;

          const firstPass = await this.probeOnceViaChannel(proxyUrl, channelDesc, 5500);
          let probeSuccess = firstPass.result;
          let lastErrMsg = firstPass.errMsg;

          if (
            !probeSuccess &&
            this.isCurrentAntigravityProbe(seqAtStart, curCfg)
          ) {
            await sleep(320);
            if (!this.isCurrentAntigravityProbe(seqAtStart, curCfg)) continue;
            const rebindRes = await this.clashMonitor.configureAntigravityNode(
              targetNode,
              curCfg.antigravityDedicatedPort,
              targetProfileUid,
              true
            );
            if (rebindRes.ok && rebindRes.listening) {
              const secondPass = await this.probeOnceViaChannel(proxyUrl, channelDesc, 5500);
              probeSuccess = secondPass.result;
              if (!probeSuccess) {
                lastErrMsg = secondPass.errMsg;
              }
            }
          }

          if (
            probeSuccess &&
            this.isCurrentAntigravityProbe(seqAtStart, curCfg)
          ) {
            await this.verifyTargetServiceRegion(proxyUrl, probeSuccess, 'antigravity', true);
          }

          const afterCfg = this.configStore.get();
          if (!this.isCurrentAntigravityProbe(seqAtStart, curCfg)) {
            if (afterCfg.antigravityClashNode) {
              continue;
            }
            this.antigravityNodeProbe = null;
            this.antigravityNodeProbeError = null;
            break;
          }

          if (probeSuccess) {
            this.antigravityNodeProbe = probeSuccess;
            this.antigravityNodeProbeError = null;
            if (probeSuccess.regionMismatchDetail) {
              this.addLog(
                'warn',
                `Antigravity 节点地区预警 [${targetNode}]：${probeSuccess.regionMismatchDetail}`
              );
            }
          } else {
            this.antigravityNodeProbe = null;
            this.antigravityNodeProbeError = simplifyNetworkError(lastErrMsg, channelDesc);
          }

          if (this.antigravityPendingReprobe && this.configStore.get().antigravityClashNode) {
            continue;
          }
          break;
        }
      } finally {
        this.antigravityIsProbing = false;
        if (this.antigravityProbePromise === p) {
          this.antigravityProbePromise = null;
        }
        this.emitState();
      }

      return this.getSnapshot();
    };

    const p = runProbe().finally(() => {
      if (this.antigravityProbePromise === p) {
        this.antigravityProbePromise = null;
      }
    });
    this.antigravityProbePromise = p;
    return p;
  }

  /**
   * 通过指定专属代理节点启动（或重启）Antigravity：
   * 1. 确保 Clash 专属端口 (如 127.0.0.1:27898) 与 PROCESS-NAME 规则已绑定
   * 2. 若已有运行中的 Antigravity.exe / language_server.exe，先关闭旧实例以释放单实例锁
   * 3. 注入 --proxy-server 与 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / GRPC_PROXY / NO_PROXY 拉起 Antigravity.exe
   */
  public async launchAntigravityFromGuard(): Promise<AntigravityLaunchResult> {
    return this.runApplicationChange(() => this.launchAntigravityInternal());
  }

  private async launchAntigravityInternal(): Promise<AntigravityLaunchResult> {
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

    markAntigravityLaunchedByGuard(null);
    const killReport = await this.executeProcessKillSafely(ANTIGRAVITY_PROCESS_PATTERNS);
    await assertProcessesStopped(ANTIGRAVITY_PROCESS_PATTERNS, killReport);

    const bindRes = await this.clashMonitor.configureAntigravityNode(
      cfg.antigravityClashNode,
      cfg.antigravityDedicatedPort,
      cfg.antigravityClashProfileUid,
      false
    );
    if (bindRes.profileUid || bindRes.profileName) {
      cfg = this.configStore.update({
        antigravityClashProfileUid: bindRes.profileUid ?? cfg.antigravityClashProfileUid,
        antigravityClashProfileName: bindRes.profileName ?? cfg.antigravityClashProfileName,
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

    await assertProcessesStopped(ANTIGRAVITY_PROCESS_PATTERNS, killReport);
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

    let afterProc = await inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort, true);
    const launchDeadline = Date.now() + 6000;
    while (Date.now() < launchDeadline) {
      if (afterProc.uiProcessCount > 0 && afterProc.proxiedSession) break;
      await sleep(250);
      afterProc = await inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort, true);
    }

    this.antigravityRunning = afterProc.running;
    this.antigravityUiCount = afterProc.uiProcessCount;
    this.antigravityLsCount = afterProc.languageServerCount;
    this.antigravityTotalCount = afterProc.totalProcessCount;
    this.antigravityProxiedSession = afterProc.proxiedSession;

    if (afterProc.uiProcessCount === 0 || !afterProc.proxiedSession) {
      markAntigravityLaunchedByGuard(null);
      const message = afterProc.uiProcessCount === 0
        ? '启动 Antigravity 失败：未检测到主进程运行'
        : '启动 Antigravity 失败：未确认主进程绑定指定代理端口';
      this.addLog('danger', message);
      this.emitState();
      return { ok: false, message, state: this.getSnapshot() };
    }

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
    const afterProc = await inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort, true);

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
   * 2. 独立通过该专属端口 (127.0.0.1:dedicatedProxyPort) 探测节点真实出口 IP 与国家（不干扰实时监控通道）
   */
  public async selectClashNode(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    return this.runApplicationChange(async () => {
      await this.stopClaudeBeforeRoutingChange();
      return this.selectClashNodeInternal(nodeName, profileUid);
    });
  }

  private async selectClashNodeInternal(
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

    this.claudeProbeSeq++;
    this.claudeNodeProbe = null;
    this.claudeNodeProbeError = null;

    if (cleanNode) {
      this.claudeSwitchingCount++;
      this.addLog(
        'info',
        `正在将 Claude 专属代理通道切换至 Clash 节点：[${cleanNode}] (127.0.0.1:${prevCfg.dedicatedProxyPort})...`
      );
      let bindRes: Awaited<ReturnType<ClashMonitor['configureDedicatedNode']>>;
      let cfg = prevCfg;
      try {
        bindRes = await this.clashMonitor.configureDedicatedNode(
          cleanNode,
          prevCfg.dedicatedProxyPort,
          effectiveProfileUid,
          true,
          (resolvedUid, resolvedName) => {
            cfg = this.configStore.update({
              selectedClashNode: cleanNode,
              selectedClashProfileUid: resolvedUid,
              selectedClashProfileName: resolvedName,
            });
          }
        );
      } finally {
        this.claudeSwitchingCount--;
      }

      const fullLabel = cfg.selectedClashProfileName
        ? `${cfg.selectedClashProfileName} / ${cleanNode}`
        : cleanNode;

      if (!bindRes.ok) {
        const errText = bindRes.error || `绑定 Claude 节点 [${fullLabel}] 失败`;
        this.claudeNodeProbeError = errText;
        this.addLog('warn', errText);
        this.emitState();
        if (this.claudeRunning) {
          await this.enforceClaudeRunningSafety(`绑定 Claude 节点 [${fullLabel}] 失败`);
        }
        return this.getSnapshot();
      }

      this.addLog(
        'success',
        `已锁定 Claude 专属节点 [${fullLabel}] → 本地专属端口 127.0.0.1:${cfg.dedicatedProxyPort}`
      );

      return this.probeClaudeNodeNow(`切换 Claude 专属节点: ${fullLabel}`);
    } else {
      this.claudePendingProbe = null;
      this.claudeSwitchingCount++;
      try {
        await this.clashMonitor.configureDedicatedNode(null, prevCfg.dedicatedProxyPort, null, true,
          () => this.configStore.update({
            selectedClashNode: null,
            selectedClashProfileUid: null,
            selectedClashProfileName: null,
          }));
      } finally {
        this.claudeSwitchingCount--;
      }
      this.claudeNodeProbe = null;
      this.claudeNodeProbeError = null;
      if (prevCfg.selectedClashNode) {
        this.addLog('info', '已取消 Claude 专属 Clash 节点绑定');
      }
      this.emitState();
      if (this.claudeRunning) {
        await this.enforceClaudeRunningSafety('取消 Claude 专属节点绑定');
      }
      return this.getSnapshot();
    }
  }

  /**
   * 独立探测 Claude 专栏选定节点的真实出口 IP 与国家（固定走 127.0.0.1:dedicatedProxyPort，与实时监控完全解耦）
   */
  public async probeClaudeNodeNow(
    reason = '检测 Claude 专属节点',
    skipSafetyEnforcement = false
  ): Promise<AppStateSnapshot> {
    if (this.claudeSwitchingCount > 0) return this.getSnapshot();
    const cfg = this.configStore.get();
    if (!cfg.selectedClashNode) {
      this.claudeProbeSeq++;
      this.claudePendingProbe = null;
      this.claudeNodeProbe = null;
      this.claudeNodeProbeError = null;
      this.emitState();
      return this.getSnapshot();
    }

    if (this.claudeProbePromise) {
      if (!reason.includes('心跳')) {
        this.claudePendingProbe = {
          reason,
          skipSafetyEnforcement:
            (this.claudePendingProbe?.skipSafetyEnforcement ?? true) && skipSafetyEnforcement,
        };
      } else if (!skipSafetyEnforcement && this.claudePendingProbe) {
        this.claudePendingProbe.skipSafetyEnforcement = false;
      }
      return this.claudeProbePromise;
    }

    let activeReason = reason;
    let activeSkipSafety = skipSafetyEnforcement;

    const runProbe = async (): Promise<AppStateSnapshot> => {
      this.claudeIsProbing = true;
      this.emitState();

      try {
        while (!this.stopped) {
          if (this.claudeSwitchingCount > 0) break;
          const seqAtStart = ++this.claudeProbeSeq;
          let curCfg = this.configStore.get();
          const targetNode = curCfg.selectedClashNode;
          const targetProfileUid = curCfg.selectedClashProfileUid;
          if (!targetNode) {
            this.claudeNodeProbe = null;
            this.claudeNodeProbeError = null;
            break;
          }

          let clash = this.clashMonitor.getRuntimeInfo();
          if (!clash.connected || clash.bindingVerificationError || !clash.dedicatedPortListening) {
            const bindRes = await this.clashMonitor.configureDedicatedNode(
              targetNode,
              curCfg.dedicatedProxyPort,
              targetProfileUid,
              false
            );
            if (
              (bindRes.profileUid || bindRes.profileName) &&
              this.claudeProbeSeq === seqAtStart &&
              this.configStore.get().selectedClashNode === targetNode
            ) {
              curCfg = this.configStore.update({
                selectedClashProfileUid: bindRes.profileUid ?? curCfg.selectedClashProfileUid,
                selectedClashProfileName: bindRes.profileName ?? curCfg.selectedClashProfileName,
              });
            }
            clash = this.clashMonitor.getRuntimeInfo();
            const canProbeExistingPort =
              Boolean(clash.bindingVerificationError) &&
              this.getClaudeExpectedRegion() !== null &&
              (await isLocalPortListening(curCfg.dedicatedProxyPort));
            if ((!bindRes.ok || !bindRes.listening) && !canProbeExistingPort) {
              const latestCfg = this.configStore.get();
              if (
                this.claudeProbeSeq !== seqAtStart ||
                latestCfg.selectedClashNode !== targetNode ||
                latestCfg.selectedClashProfileUid !== (curCfg.selectedClashProfileUid ?? targetProfileUid)
              ) {
                if (this.claudePendingProbe) {
                  const next = this.claudePendingProbe;
                  this.claudePendingProbe = null;
                  activeReason = next.reason;
                  activeSkipSafety = activeSkipSafety && next.skipSafetyEnforcement;
                  continue;
                }
                if (latestCfg.selectedClashNode) continue;
                this.claudeNodeProbe = null;
                this.claudeNodeProbeError = null;
                break;
              }
              this.claudeNodeProbe = null;
              this.claudeNodeProbeError =
                bindRes.error ||
                `Claude 专属端口 127.0.0.1:${curCfg.dedicatedProxyPort} 未就绪`;
              if (this.claudePendingProbe && this.configStore.get().selectedClashNode) {
                const next = this.claudePendingProbe;
                this.claudePendingProbe = null;
                activeReason = next.reason;
                activeSkipSafety = activeSkipSafety && next.skipSafetyEnforcement;
                continue;
              }
              break;
            }
          }

          const effectiveProfileUid = curCfg.selectedClashProfileUid;
          const label =
            curCfg.selectedClashProfileName || clash.boundProfileName
              ? `${curCfg.selectedClashProfileName || clash.boundProfileName} / ${targetNode}`
              : targetNode;
          const proxyUrl = `http://127.0.0.1:${curCfg.dedicatedProxyPort}`;
          const channelDesc = `Claude 专属节点 [${label}] (127.0.0.1:${curCfg.dedicatedProxyPort})`;

          const firstPass = await this.probeOnceViaChannel(
            proxyUrl,
            channelDesc,
            5800,
            '探测超时',
            (error) => {
              if (
                this.claudeProbeSeq === seqAtStart &&
                !activeSkipSafety &&
                this.claudeRunning &&
                !this.claudeSafetyKillPromise &&
                !this.stopped
              ) {
                this.recordClaudeVerificationFailure(`${channelDesc}：${error}`);
              }
            }
          );
          let probeSuccess = firstPass.result;
          let lastErrMsg = firstPass.errMsg;

          if (
            !probeSuccess &&
            !this.claudeRunning &&
            !clash.bindingVerificationError &&
            this.claudeProbeSeq === seqAtStart &&
            this.configStore.get().selectedClashNode === targetNode
          ) {
            await sleep(320);
            if (this.claudeProbeSeq !== seqAtStart || this.claudeSwitchingCount > 0) {
              continue;
            }
            const rebindRes = await this.clashMonitor.configureDedicatedNode(
              targetNode,
              curCfg.dedicatedProxyPort,
              effectiveProfileUid,
              true
            );
            if (rebindRes.ok && rebindRes.listening) {
              const secondPass = await this.probeOnceViaChannel(proxyUrl, channelDesc, 5800);
              probeSuccess = secondPass.result;
              if (!probeSuccess) {
                lastErrMsg = secondPass.errMsg;
              }
            }
          }

          const isHeartbeat = activeReason.includes('心跳');
          const isSilentPoll = isHeartbeat || activeReason.includes('后台复核');
          if (
            probeSuccess &&
            this.claudeProbeSeq === seqAtStart &&
            this.configStore.get().selectedClashNode === targetNode
          ) {
            const forceRefresh =
              activeReason.includes('手动') ||
              activeReason.includes('切换') ||
              activeReason.includes('启动') ||
              this.claudeVerificationRecovery.snapshot !== null ||
              !this.claudeNodeProbe;
            await this.verifyTargetServiceRegion(proxyUrl, probeSuccess, 'claude', forceRefresh);
          }

          const afterCfg = this.configStore.get();
          if (
            this.claudeProbeSeq !== seqAtStart ||
            afterCfg.selectedClashNode !== targetNode ||
            afterCfg.selectedClashProfileUid !== effectiveProfileUid
          ) {
            if (this.claudePendingProbe) {
              const next = this.claudePendingProbe;
              this.claudePendingProbe = null;
              activeReason = next.reason;
              activeSkipSafety = activeSkipSafety && next.skipSafetyEnforcement;
              continue;
            }
            if (afterCfg.selectedClashNode) {
              continue;
            }
            this.claudeNodeProbe = null;
            this.claudeNodeProbeError = null;
            break;
          }

          if (probeSuccess) {
            const prevIp = this.claudeNodeProbe?.ip;
            const prevCountry = this.claudeNodeProbe?.countryCode;
            const previousVerificationError = getTargetServiceVerificationError(this.claudeNodeProbe);
            const verificationError = getTargetServiceVerificationError(probeSuccess);
            this.claudeNodeProbe = probeSuccess;
            this.claudeNodeProbeError = null;
            if (!verificationError && !clash.bindingVerificationError) {
              this.claudeLastVerificationSuccessAt = probeSuccess.claudeTraceCheckedAt || probeSuccess.checkedAt;
              this.claudeLastVerifiedRegion = {
                node: targetNode,
                profileUid: effectiveProfileUid,
                port: curCfg.dedicatedProxyPort,
                countryCode: probeSuccess.countryCode,
                countryName: probeSuccess.countryName,
              };
            }

            if (verificationError) {
              if (!this.claudeRunning && (previousVerificationError !== verificationError || !isSilentPoll)) {
                this.addLog(
                  'danger',
                  `Claude 目标服务地区校验未通过 [${label}]：${verificationError}`
                );
              }
            } else if (
              prevIp !== probeSuccess.ip ||
              prevCountry !== probeSuccess.countryCode ||
              !isSilentPoll
            ) {
              const verifiedTag =
                probeSuccess.claudeTraceLoc
                  ? ' · 目标服务地区校验通过'
                  : '';
              this.addLog(
                'info',
                `Claude 节点检测 [${label}]：${probeSuccess.countryName} (${probeSuccess.countryCode})${verifiedTag} · IP: ${probeSuccess.ip} (${probeSuccess.latencyMs}ms)`
              );
            }
          } else {
            this.claudeNodeProbe = null;
            this.claudeNodeProbeError = `${channelDesc}：${lastErrMsg}`;
            if (!this.claudeRunning) {
              this.addLog('warn', `Claude 节点检测失败：${this.claudeNodeProbeError}`);
            }
          }

          if (this.claudePendingProbe && this.configStore.get().selectedClashNode) {
            const next = this.claudePendingProbe;
            this.claudePendingProbe = null;
            activeReason = next.reason;
            activeSkipSafety = activeSkipSafety && next.skipSafetyEnforcement;
            continue;
          }
          break;
        }
      } finally {
        this.claudeIsProbing = false;
        if (this.claudeProbePromise === p) {
          this.claudeProbePromise = null;
        }
        this.emitState();
      }

      // 若 Claude 正在运行，探测完成后立即核验其选定节点与系统时区/区域的一致性
      if (!activeSkipSafety && this.claudeRunning) {
        await this.enforceClaudeRunningSafety(activeReason);
      }

      return this.getSnapshot();
    };

    const p = runProbe().finally(() => {
      if (this.claudeProbePromise === p) {
        this.claudeProbePromise = null;
      }
    });
    this.claudeProbePromise = p;
    return p;
  }

  /**
   * Claude 唯一安全启动入口：
   * 启动前实时强校验：[Claude 选定节点真实出口地区] == [Windows 系统区域] == [Windows 系统时区]
   */
  public async launchClaudeFromGuard(): Promise<ClaudeLaunchResult> {
    return this.runApplicationChange(() => this.launchClaudeInternal());
  }

  private async launchClaudeInternal(): Promise<ClaudeLaunchResult> {
    let cfg = this.configStore.get();

    // 1. 确认 Claude Desktop 安装路径
    const install = await detectClaudeInstallation(cfg.claudeExePath);
    this.claudeDetectedExe = install.exePath;
    this.claudeInstallType = install.installType;

    if (!install.exePath) {
      return { ok: false, message: '未检测到 Claude Desktop 安装路径', state: this.getSnapshot() };
    }
    const killReport = await this.stopClaudeBeforeRoutingChange();

    // 2. 若已选择节点，确保专属端口绑定就绪
    if (cfg.selectedClashNode) {
      const bindRes = await this.clashMonitor.configureDedicatedNode(
        cfg.selectedClashNode,
        cfg.dedicatedProxyPort,
        cfg.selectedClashProfileUid,
        false
      );
      if (bindRes.profileUid || bindRes.profileName) {
        cfg = this.configStore.update({
          selectedClashProfileUid: bindRes.profileUid ?? cfg.selectedClashProfileUid,
          selectedClashProfileName: bindRes.profileName ?? cfg.selectedClashProfileName,
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

    // 3. 实时刷新读取本机最新 Windows 时区/区域，并对 Claude 选定节点发起一次独立真实出口探测
    this.winLocale = await readWindowsLocaleState();
    await this.probeClaudeNodeNow('Claude 启动前三重安全校验', true);

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

    // 授权前再次检查全部关联进程，包含可能被外部服务重新启动的后台进程。
    await assertProcessesStopped(CLAUDE_DESKTOP_PROCESS_PATTERNS, killReport);

    // 6. 授予唯一入口会话锁并注入专属代理参数拉起 Claude
    this.claudeAuthorizedSession = true;
    this.claudeSeenRunningSinceAuth = false;
    this.claudeLaunchGraceUntil = Date.now() + 12000;
    markClaudeLaunchedByGuard(cfg.dedicatedProxyPort);

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
    while (Date.now() < this.claudeLaunchGraceUntil) {
      await sleep(250);
      afterProc = await countRunningClaudeProcesses(true);
      if (afterProc.running) break;
    }

    this.claudeRunning = afterProc.running;
    this.claudeProcessCount = afterProc.count;
    this.claudeRunningPids = afterProc.pids;
    this.claudeFastCheckTicks = 0;
    if (!afterProc.running) {
      this.unsetClaudeAuthLock();
      const message = '启动 Claude 失败：未检测到主进程运行';
      this.addLog('danger', message);
      this.emitState();
      return { ok: false, message, state: this.getSnapshot() };
    }
    this.claudeSeenRunningSinceAuth = true;

    const fullNodeLabel = cfg.selectedClashProfileName
      ? `${cfg.selectedClashProfileName} / ${cfg.selectedClashNode}`
      : cfg.selectedClashNode;
    const okMsg = `三重校验通过！已通过专属节点 [${fullNodeLabel}] (127.0.0.1:${cfg.dedicatedProxyPort} · ${proxyCountryName}) 安全启动 Claude`;
    this.addLog('success', okMsg);
    this.emitState();
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
    this.claudeVerificationRecovery.clear();
    this.claudeAuthorizedSession = false;
    this.claudeSeenRunningSinceAuth = false;
    this.claudeLaunchGraceUntil = 0;
    markClaudeLaunchedByGuard(null);
    this.claudeFastCheckTicks = 0;
  }

  private async runApplicationChange<T>(operation: () => Promise<T>): Promise<T> {
    if (this.applicationChangeInProgress) {
      throw new Error('应用启动或代理配置操作正在进行，请等待完成');
    }
    this.applicationChangeInProgress = true;
    try {
      return await operation();
    } finally {
      this.applicationChangeInProgress = false;
    }
  }

  private async stopClaudeBeforeRoutingChange(): Promise<ProcessKillReport> {
    this.unsetClaudeAuthLock();
    this.claudeLastVerificationSuccessAt = null;
    this.claudeLastVerifiedRegion = null;
    const report = await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
    await assertProcessesStopped(CLAUDE_DESKTOP_PROCESS_PATTERNS, report);
    if (report.killedCount > 0) {
      this.addLog('info', `调整 Claude 专属代理前已终止关联进程：${report.killedSummary.join(', ')}`);
    }
    return report;
  }

  public async updateConfig(partial: Partial<AppConfig>): Promise<AppConfig> {
    return this.runApplicationChange(async () => {
      const previous = this.configStore.get();
      const requested = this.configStore.preview(partial);
      const claudeChanged =
        previous.selectedClashNode !== requested.selectedClashNode ||
        previous.selectedClashProfileUid !== requested.selectedClashProfileUid ||
        previous.dedicatedProxyPort !== requested.dedicatedProxyPort;
      const antigravityChanged =
        previous.antigravityClashNode !== requested.antigravityClashNode ||
        previous.antigravityClashProfileUid !== requested.antigravityClashProfileUid ||
        previous.antigravityDedicatedPort !== requested.antigravityDedicatedPort;
      if (claudeChanged) await this.stopClaudeBeforeRoutingChange();
      const next = this.configStore.update(partial);
      if (claudeChanged) {
        await this.selectClashNodeInternal(next.selectedClashNode, next.selectedClashProfileUid);
      }
      if (antigravityChanged) {
        await this.selectAntigravityClashNodeInternal(next.antigravityClashNode, next.antigravityClashProfileUid);
      }
      return this.configStore.get();
    });
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
   * 3. 地区、系统环境或代理绑定冲突立即终止；请求失败进入有期限的后台复核。
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
          if (!proc.running) this.claudeVerificationRecovery.clear();

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

            if (report.killedCount > 0 || report.errorDetail) {
              this.emitAlert({
                source: 'claude',
                alertType: 'unauthorized-launch',
                expectedCode: this.claudeNodeProbe?.countryCode || cfg.defaultCountryCode,
                expectedName: this.claudeNodeProbe?.countryName || cfg.defaultCountryName,
                triggerReason: reason,
                killedProcesses: report.killedCount > 0 ? report.killedSummary : undefined,
                killError: report.errorDetail,
              });
            }
            scheduleNext(1500);
            return;
          }

          // 运行期安全检查独立于唯一启动入口设置。
          if (proc.running) {
            const killedOrBlocked = await this.enforceClaudeRunningSafety('Claude 运行期实时监控');
            if (killedOrBlocked) {
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

  /**
   * 明确冲突立即终止；校验请求失败静默复核，持续 30 秒未恢复时终止并提醒。
   */
  private async enforceClaudeRunningSafety(triggerContext: string): Promise<boolean> {
    if (!this.claudeRunning || this.stopped) {
      this.claudeVerificationRecovery.clear();
      return false;
    }
    if (this.claudeSafetyKillPromise) return this.claudeSafetyKillPromise;
    const cfg = this.configStore.get();
    const requireDedicatedNode =
      this.claudeAuthorizedSession || cfg.claudeExclusiveGuard;
    if (this.claudeIsProbing || this.claudeSwitchingCount > 0) {
      const localCheck = this.evaluateClaudeLocalSafety(requireDedicatedNode);
      if (localCheck) return this.terminateUnsafeClaude(localCheck, triggerContext);
      const clash = this.clashMonitor.getRuntimeInfo();
      if (cfg.selectedClashNode && (!clash.connected || clash.bindingVerificationError)) {
        this.recordClaudeVerificationFailure(
          clash.bindingVerificationError || 'Clash 控制接口暂时不可用，无法确认专属节点绑定状态'
        );
      }
      return false;
    }
    const check = this.evaluateClaudeSafety(requireDedicatedNode);
    if (check.safe) {
      if (this.claudeVerificationRecovery.clear()) {
        this.addLog('success', 'Claude 地区校验已恢复，后台复核结束');
        this.emitState();
      }
      return false;
    }
    if (check.alertType === 'verification-unavailable') {
      this.recordClaudeVerificationFailure(check.reason);
      return false;
    }
    return this.terminateUnsafeClaude(check, triggerContext);
  }

  private recordClaudeVerificationFailure(reason: string): void {
    if (this.claudeVerificationRecovery.recordFailure(reason)) {
      this.addLog('warn', `Claude 地区校验暂时不可用，正在后台复核：${reason}`);
      this.emitState();
    }
  }

  private terminateUnsafeClaude(check: ClaudeSafetyCheck, triggerContext: string): Promise<boolean> {
    if (this.claudeSafetyKillPromise) return this.claudeSafetyKillPromise;
    const operation = async () => {
      this.unsetClaudeAuthLock();

      const report = await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
      if (report.killedCount > 0) {
        this.addLog(
          'danger',
          `Claude 保护终止 (${check.reason})：${report.killedSummary.join(', ')}`
        );
      } else if (report.errorDetail) {
        this.addLog('warn', report.errorDetail);
      }
      this.emitState();

      if (report.killedCount > 0 || report.errorDetail) {
        const expectedRegion = this.getClaudeExpectedRegion();
        const expectedCode = expectedRegion?.countryCode || this.winLocale.regionCode;
        const expectedName = expectedRegion?.countryName || this.winLocale.regionName;
        this.emitAlert({
          source: 'claude',
          alertType: check.alertType,
          expectedCode,
          expectedName,
          triggerReason: `${triggerContext}：${check.reason}`,
          errorDetail: check.reason,
          killedProcesses: report.killedCount > 0 ? report.killedSummary : undefined,
          killError: report.errorDetail,
        });
      }

      return true;
    };
    this.claudeSafetyKillPromise = operation().finally(() => {
      this.claudeSafetyKillPromise = null;
    });
    return this.claudeSafetyKillPromise;
  }

  private getClaudeExpectedRegion(): { countryCode: string; countryName: string } | null {
    if (this.claudeNodeProbe && isValidIsoCountryCode(this.claudeNodeProbe.countryCode)) {
      return this.claudeNodeProbe;
    }
    const cfg = this.configStore.get();
    const previous = this.claudeLastVerifiedRegion;
    return previous && previous.node === cfg.selectedClashNode &&
      previous.profileUid === cfg.selectedClashProfileUid && previous.port === cfg.dedicatedProxyPort
      ? previous : null;
  }

  private evaluateClaudeLocalSafety(requireDedicatedNode: boolean): ClaudeSafetyCheck | null {
    const cfg = this.configStore.get();
    const launchedPort = getLaunchedClaudePort();
    if (
      this.claudeAuthorizedSession &&
      launchedPort !== null &&
      launchedPort !== cfg.dedicatedProxyPort
    ) {
      return {
        safe: false,
        reason: `Claude 运行实例绑定的旧端口 (127.0.0.1:${launchedPort}) 与当前专属端口 (127.0.0.1:${cfg.dedicatedProxyPort}) 不一致，需重新从专栏启动`,
        alertType: 'disconnect',
      };
    }

    if (requireDedicatedNode && !cfg.selectedClashNode) {
      return {
        safe: false,
        reason: '未指定 Claude 专属节点，禁止运行 Claude',
        alertType: 'disconnect',
      };
    }

    const clash = this.clashMonitor.getRuntimeInfo();
    if (cfg.selectedClashNode && clash.connected && !clash.bindingVerificationError && (
      !clash.dedicatedPortListening ||
      clash.boundNode !== cfg.selectedClashNode || clash.dedicatedPort !== cfg.dedicatedProxyPort ||
      (cfg.selectedClashProfileUid && clash.boundProfileUid !== cfg.selectedClashProfileUid)
    )) {
      return {
        safe: false,
        reason: `Claude 专属节点 [${cfg.selectedClashNode}] 代理绑定失效 (127.0.0.1:${cfg.dedicatedProxyPort})`,
        alertType: 'disconnect',
      };
    }

    const probe = this.getClaudeExpectedRegion();
    if (probe && isValidIsoCountryCode(probe.countryCode) &&
        !isWindowsLocaleMatchingCountry(this.winLocale.timeZoneId, this.winLocale.regionCode, probe.countryCode)) {
      return {
        safe: false,
        reason: `Claude 节点地区 [${probe.countryName} (${probe.countryCode})] 与系统时区/区域 [${this.winLocale.regionName} · ${this.winLocale.timeZoneDisplayName}] 不一致`,
        alertType: 'locale-mismatch',
      };
    }
    return null;
  }

  private evaluateClaudeSafety(requireDedicatedNode = true): ClaudeSafetyCheck {
    const localCheck = this.evaluateClaudeLocalSafety(requireDedicatedNode);
    if (localCheck) return localCheck;

    if (this.claudeNodeProbe) {
      const proxyCountry = this.claudeNodeProbe.countryCode.toUpperCase();
      if (!isValidIsoCountryCode(proxyCountry)) {
        return {
          safe: false,
          reason: '无法识别 Claude 选定节点的有效出口国家/地区',
          alertType: 'verification-unavailable',
        };
      }

      const verificationError = getTargetServiceVerificationError(this.claudeNodeProbe);
      if (verificationError) {
        return {
          safe: false,
          reason: `目标服务地区校验未通过：${verificationError}`,
          alertType: isValidIsoCountryCode(this.claudeNodeProbe.claudeTraceLoc)
            ? 'mismatch' : 'verification-unavailable',
        };
      }
    }

    const cfg = this.configStore.get();
    const clash = this.clashMonitor.getRuntimeInfo();
    if (cfg.selectedClashNode && (!clash.connected || clash.bindingVerificationError)) {
      return {
        safe: false,
        reason: clash.bindingVerificationError || 'Clash 控制接口暂时不可用，无法确认专属节点绑定状态',
        alertType: 'verification-unavailable',
      };
    }

    if (this.claudeNodeProbeError || !this.claudeNodeProbe) {
      return {
        safe: false,
        reason: `Claude 专属节点出口不可达 (${this.claudeNodeProbeError || '连接异常'})`,
        alertType: 'verification-unavailable',
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
      this.claudeNodeProbe && isValidIsoCountryCode(this.claudeNodeProbe.countryCode)
        ? this.claudeNodeProbe.countryCode.toUpperCase()
        : null;
    const proxyCountryName = proxyCountryCode ? this.claudeNodeProbe?.countryName || null : null;

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

    const verificationError = getTargetServiceVerificationError(this.claudeNodeProbe);
    const threeWayMatched = Boolean(
      proxyCountryCode &&
        !verificationError &&
        winRegionMatched &&
        winTimeZoneMatched
    );

    let launchBlockReason: string | null = null;
    if (!this.claudeDetectedExe) {
      launchBlockReason = '未检测到 Claude Desktop 安装路径，请手动指定 Claude.exe';
    } else if (!cfg.selectedClashNode) {
      launchBlockReason = '请先在上方选择要为 Claude 绑定的 Clash 代理节点';
    } else if (!clash.connected) {
      launchBlockReason = '未连接到 Clash Verge Rev 控制接口，请确认 Clash Verge 已启动';
    } else if (clash.bindingVerificationError) {
      launchBlockReason = clash.bindingVerificationError;
    } else if (!clash.dedicatedPortListening) {
      launchBlockReason = `节点 [${cfg.selectedClashNode}] 专属端口 (127.0.0.1:${cfg.dedicatedProxyPort}) 尚未就绪`;
    } else if (this.claudeIsProbing && !this.claudeNodeProbe && !this.claudeNodeProbeError) {
      launchBlockReason = '正在独立验证 Claude 所选节点的真实出口 IP 与归属地...';
    } else if (this.claudeNodeProbeError || !proxyCountryCode) {
      launchBlockReason = `Claude 节点出口探测异常：${
        this.claudeNodeProbeError || '未获取到有效出口国家'
      }`;
    } else if (verificationError) {
      launchBlockReason = `目标服务地区校验未通过：${verificationError}`;
    } else if (!winRegionMatched) {
      launchBlockReason = `系统区域 [${this.winLocale.regionName} (${this.winLocale.regionCode})] 与 Claude 节点出口 [${proxyCountryName} (${proxyCountryCode})] 不一致，请点击下方一键同步`;
    } else if (!winTimeZoneMatched) {
      launchBlockReason = `系统时区 [${this.winLocale.timeZoneDisplayName}] 与 Claude 节点出口 [${proxyCountryName} (${proxyCountryCode})] 不一致，请点击下方一键同步`;
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
      isProbingNode: this.claudeIsProbing,
      nodeProbe: this.claudeNodeProbe ? { ...this.claudeNodeProbe } : null,
      nodeProbeError: this.claudeNodeProbeError,
      verificationFailure: this.claudeVerificationRecovery.snapshot,
      lastVerificationSuccessAt: this.claudeLastVerificationSuccessAt,
    };
  }

  private buildAntigravityRuntimeState(clashInfo?: ClashRuntimeInfo): AntigravityRuntimeState {
    const cfg = this.configStore.get();
    const clash = clashInfo || this.clashMonitor.getRuntimeInfo();

    let launchHint: string | null = null;
    if (!this.antigravityDetectedExe) {
      launchHint = '未检测到 Antigravity.exe 安装路径，请在下方手动浏览指定';
    } else if (!cfg.antigravityClashNode) {
      launchHint = '请先在上方下拉框中选择要绑定的 Clash 代理节点';
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
            if (this.claudeRunning) {
              await this.enforceClaudeRunningSafety('系统时区或区域变更');
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
  private getEffectiveTargetCountryCode(): string | null {
    const cfg = this.configStore.get();
    if (cfg.defaultCountryCode && isValidIsoCountryCode(cfg.defaultCountryCode)) {
      return cfg.defaultCountryCode.toUpperCase();
    }
    if (this.lastProbe && isValidIsoCountryCode(this.lastProbe.countryCode)) {
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
    void this.applyMonitorStatus(reason || '状态更新');
    return this.getSnapshot();
  }

  private async applyMonitorStatus(reason: string, logResult = false, probeChanged = false): Promise<void> {
    const cfg = this.configStore.get();
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
        !isWindowsLocaleMatchingCountry(this.winLocale.timeZoneId, this.winLocale.regionCode, probeCode)
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
    if (logResult && (probeChanged || previousStatus !== this.status || reason !== '轻量心跳巡检')) {
      const detail = this.lastError || (this.lastProbe
        ? `${this.lastProbe.countryName} (${this.lastProbe.countryCode}) · IP: ${this.lastProbe.ip}`
        : '尚未获得出口信息');
      const localeMatched = this.lastProbe
        ? isWindowsLocaleMatchingCountry(
            this.winLocale.timeZoneId,
            this.winLocale.regionCode,
            this.lastProbe.countryCode.toUpperCase()
          )
        : false;
      const label = transition === 'disconnect' ? '代理连接失败'
        : transition === 'mismatch' ? `出口偏离保护地区 [${cfg.defaultCountryName}]`
        : transition === 'locale-mismatch' ? '出口与系统时区/区域不一致'
        : this.status === 'ok'
        ? localeMatched
          ? '出口与系统时区/区域一致'
          : '代理出口正常（未锁定默认保护地区）'
        : '出口地区待确认';
      this.addLog(this.status === 'ok' ? 'success' : transition ? 'warn' : 'info', `${label}：${detail}`);
    }
    try {
      if (transition === 'disconnect') await this.handleDisconnectTransition(reason, this.lastError!);
      else if (transition === 'mismatch') await this.handleMismatchTransition(reason);
      else if (transition === 'locale-mismatch') await this.handleLocaleMismatchTransition(reason);
      else if (this.status === 'ok') {
        if (this.lastAlertSignature !== null) {
          this.lastAlertSignature = null;
          if (cfg.monitorAlertEnabled) this.emitRecoveredAlert();
        }
        await this.enforceProcessGuardInBackground();
      }
    } finally {
      this.emitState();
    }
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

      let probeSuccess: ProbeResult | null = null;
      let lastErrMsg = channel.errorHint || '所有回显探测源均不可达';

      if (!channel.errorHint) {
        const firstTry = await this.probeOnceViaChannel(
          channel.proxyUrl,
          channel.description,
          6000,
          '所有回显探测源均不可达'
        );
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
          const retryRes = await this.probeOnceViaChannel(
            channel.proxyUrl,
            channel.description,
            6000,
            '所有回显探测源均不可达'
          );
          probeSuccess = retryRes.result;
          if (!probeSuccess) {
            lastErrMsg = retryRes.errMsg;
          }
        }
      }

      const probeChanged = this.lastProbe?.ip !== probeSuccess?.ip ||
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
   * 根据目标通道（Claude 专栏选定节点 或 实时监控通道/默认保护地区）一键同步 Windows 时区与区域
   */
  public async syncSystemLocaleToDefault(
    targetSource: 'monitor' | 'claude' = 'monitor'
  ): Promise<LocaleSyncResult> {
    return this.runApplicationChange(() =>
      this.runLocaleChange(() => this.syncSystemLocaleInternal(targetSource))
    );
  }

  private async runLocaleChange(
    operation: () => Promise<Omit<LocaleSyncResult, 'state'>>
  ): Promise<LocaleSyncResult> {
    this.isSyncingLocale = true;
    this.emitState();
    let result: Omit<LocaleSyncResult, 'state'>;
    try {
      result = await operation();
    } finally {
      this.isSyncingLocale = false;
      this.emitState();
    }
    return { ...result, state: this.getSnapshot() };
  }

  private async stopProcessesBeforeLocaleChange(
    targetCode: string,
    targetTimeZone: string
  ): Promise<ProcessKillReport> {
    const cfg = this.configStore.get();
    const stopClaude = !isWindowsLocaleMatchingCountry(
      targetTimeZone, targetCode, this.claudeNodeProbe?.countryCode
    );
    const stopProtected = cfg.killProcessesEnabled && cfg.killOnLocaleMismatch &&
      !isWindowsLocaleMatchingCountry(targetTimeZone, targetCode, this.getEffectiveTargetCountryCode());
    const patterns = [...new Set([
      ...(stopClaude ? CLAUDE_DESKTOP_PROCESS_PATTERNS : []),
      ...(stopProtected ? cfg.protectedProcessPatterns : []),
    ])];
    if (stopClaude) this.unsetClaudeAuthLock();
    const report = await this.executeProcessKillSafely(patterns);
    await assertProcessesStopped(patterns, report);
    if (report.killedCount > 0) {
      this.addLog('info', `修改系统时区与区域前已终止关联进程：${report.killedSummary.join(', ')}`);
    }
    return report;
  }

  private async syncSystemLocaleInternal(
    targetSource: 'monitor' | 'claude'
  ): Promise<Omit<LocaleSyncResult, 'state'>> {
    const cfg = this.configStore.get();
    const claudeCode =
      this.claudeNodeProbe && isValidIsoCountryCode(this.claudeNodeProbe.countryCode)
        ? this.claudeNodeProbe.countryCode.toUpperCase()
        : null;
    const monitorProbeCode =
      this.lastProbe && isValidIsoCountryCode(this.lastProbe.countryCode)
        ? this.lastProbe.countryCode.toUpperCase()
        : null;
    const defCode =
      cfg.defaultCountryCode && isValidIsoCountryCode(cfg.defaultCountryCode)
        ? cfg.defaultCountryCode.toUpperCase()
        : null;

    const targetCode =
      targetSource === 'claude'
        ? claudeCode
        : defCode || monitorProbeCode || claudeCode;

    if (!targetCode) {
      return {
        ok: false,
        message:
          targetSource === 'claude'
            ? '请先在 Claude 专栏选择 Clash 节点并等待检测出有效出口地区'
            : '请先等待检测出有效出口地区，或先设置默认保护地区',
        killedProcesses: [],
      };
    }

    if (!hasOfflineTimeZoneMapping(targetCode)) {
      return {
        ok: false,
        message: `尚未收录国家 ${targetCode} 的 Windows 时区映射，无法安全同步`,
        killedProcesses: [],
      };
    }

    const killedProcesses: string[] = [];

    {
      let exactIanaTz: string | null = null;
      const needsCityTzLookup =
        isMultiTimeZoneCountry(targetCode) || !hasOfflineTimeZoneMapping(targetCode);

      if (needsCityTzLookup) {
        if (
          targetSource === 'claude' &&
          this.claudeNodeProbe &&
          this.claudeNodeProbe.countryCode.toUpperCase() === targetCode
        ) {
          const claudeProxyUrl = `http://127.0.0.1:${cfg.dedicatedProxyPort}`;
          exactIanaTz = await queryExactExitIanaTimeZone(
            claudeProxyUrl,
            targetCode,
            this.claudeNodeProbe.ip
          );
        } else if (
          this.lastProbe &&
          this.lastProbe.countryCode.toUpperCase() === targetCode
        ) {
          const ch = await this.resolveProxyChannel();
          if (!ch.errorHint) {
            exactIanaTz = await queryExactExitIanaTimeZone(
              ch.proxyUrl,
              targetCode,
              this.lastProbe.ip
            );
          }
        } else if (
          this.claudeNodeProbe &&
          this.claudeNodeProbe.countryCode.toUpperCase() === targetCode
        ) {
          const claudeProxyUrl = `http://127.0.0.1:${cfg.dedicatedProxyPort}`;
          exactIanaTz = await queryExactExitIanaTimeZone(
            claudeProxyUrl,
            targetCode,
            this.claudeNodeProbe.ip
          );
        }
      }

      const resolved = resolveWindowsTimeZoneForCountry(targetCode, exactIanaTz);
      const currentLocale = await readWindowsLocaleState();
      if (currentLocale.regionCode !== targetCode || currentLocale.timeZoneId !== resolved.windowsTimeZoneId) {
        const report = await this.stopProcessesBeforeLocaleChange(targetCode, resolved.windowsTimeZoneId);
        killedProcesses.push(...report.killedSummary);
      }
      const applyRes = await applyWindowsTimeZoneAndRegion(resolved.windowsTimeZoneId, targetCode);
      this.winLocale = applyRes.updated;

      if (!applyRes.ok) {
        const errMsg = applyRes.error || '修改系统时区或区域失败';
        this.addLog('warn', `一键同步时区/区域失败：${errMsg}`);
        return {
          ok: false,
          message: errMsg,
          killedProcesses,
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
        killedProcesses,
      };
    }
  }

  /**
   * 还原回默认中国时区与区域（UTC+08:00 北京时间 + 区域“中国”）
   * 若与当前 Claude 节点出口或实时监控地区不一致，严格执行“先强杀 Claude 及受保护进程并确认全部退出后，才允许切换回中国时区”
   */
  public async restoreDefaultChinaLocale(): Promise<LocaleSyncResult> {
    return this.runApplicationChange(() =>
      this.runLocaleChange(() => this.restoreDefaultChinaLocaleInternal())
    );
  }

  private async restoreDefaultChinaLocaleInternal(): Promise<Omit<LocaleSyncResult, 'state'>> {
    const cfg = this.configStore.get();

    const killedProcesses: string[] = [];

    {
      const claudeCountry =
        this.claudeNodeProbe?.countryCode && this.claudeNodeProbe.countryCode !== 'UNKNOWN'
          ? this.claudeNodeProbe.countryCode.toUpperCase()
          : null;
      const ipCountry =
        this.lastProbe?.countryCode && this.lastProbe.countryCode !== 'UNKNOWN'
          ? this.lastProbe.countryCode.toUpperCase()
          : null;
      const defCountry = cfg.defaultCountryCode ? cfg.defaultCountryCode.toUpperCase() : null;

      const wasClaudeRunning = this.claudeRunning;
      const claudeNeedsKill =
        wasClaudeRunning ||
        (claudeCountry !== null && claudeCountry !== DEFAULT_CHINA_REGION_CODE);
      const guardNeedsKill =
        cfg.killProcessesEnabled &&
        cfg.protectedProcessPatterns.length > 0 &&
        ((ipCountry !== null && ipCountry !== DEFAULT_CHINA_REGION_CODE) ||
          (defCountry !== null && defCountry !== DEFAULT_CHINA_REGION_CODE));

      const emitRestoreLocaleAlert = (triggerReason: string, killError?: string) => {
        const involvesClaude =
          wasClaudeRunning ||
          !guardNeedsKill ||
          killedProcesses.some((s) => /claude|cowork/i.test(s));
        const alertSource: 'claude' | 'monitor' =
          claudeNeedsKill && involvesClaude ? 'claude' : 'monitor';
        const expectedCode =
          alertSource === 'claude'
            ? claudeCountry || ipCountry || defCountry || DEFAULT_CHINA_REGION_CODE
            : ipCountry || defCountry || claudeCountry || DEFAULT_CHINA_REGION_CODE;
        const expectedName =
          (alertSource === 'claude' && claudeCountry
            ? this.claudeNodeProbe?.countryName
            : ipCountry
            ? this.lastProbe?.countryName
            : defCountry
            ? cfg.defaultCountryName
            : null) || getCountryNameZh(expectedCode);

        this.emitAlert({
          source: alertSource,
          alertType: 'locale-mismatch',
          expectedCode,
          expectedName,
          triggerReason,
          killedProcesses: killedProcesses.length > 0 ? killedProcesses : undefined,
          killError,
        });
      };

      const combinedPatterns = Array.from(
        new Set([
          ...(claudeNeedsKill ? CLAUDE_DESKTOP_PROCESS_PATTERNS : []),
          ...(guardNeedsKill ? cfg.protectedProcessPatterns : []),
        ])
      );

      if (combinedPatterns.length > 0) {
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

          emitRestoreLocaleAlert(
            '还原中国时区被安全拦截（受保护进程未能终止）',
            killReport.errorDetail
          );

          return {
            ok: false,
            message: abortMsg,
            killedProcesses,
          };
        }

        await assertProcessesStopped(combinedPatterns, killReport);
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
        };
      }

      // 若本次还原已先行强杀进程，预先对齐实时监控的 4 段式告警签名，防止 evaluateStatusOnly 异步触发普通时区不一致弹窗覆盖强杀结果
      if (
        killedProcesses.length > 0 &&
        cfg.monitorAlertEnabled &&
        this.lastProbe &&
        isValidIsoCountryCode(this.lastProbe.countryCode)
      ) {
        const probeCode = this.lastProbe.countryCode.toUpperCase();
        this.lastAlertSignature = `locale-mismatch:${probeCode}:${this.winLocale.regionCode}:${this.winLocale.timeZoneId}`;
      }

      this.evaluateStatusOnly('还原默认中国时区');

      const killedSuffix =
        killedProcesses.length > 0 ? `（已先行终止：${killedProcesses.join(', ')}）` : '';
      const okMsg = `已还原为默认时区 [${applyRes.updated.timeZoneDisplayName}] · 区域 [${applyRes.updated.regionName}]${killedSuffix}`;
      this.addLog('info', okMsg);

      if (killedProcesses.length > 0) {
        emitRestoreLocaleAlert('手动还原中国时区（与代理地区不一致，已先行强杀进程）');
      }

      return {
        ok: true,
        message: okMsg,
        killedProcesses,
      };
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
        const claudeNow = await countRunningClaudeProcesses(true);
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
      unsafeReason = `实时监控出口地区 [${this.lastProbe.countryName}] 与默认地区 [${cfg.defaultCountryName}] 不符`;
    } else if (this.status === 'error' && cfg.killOnDisconnect) {
      unsafeType = 'disconnect';
      unsafeReason = '实时监控代理连接异常断开期间禁止运行受保护进程';
    } else if (
      cfg.killOnLocaleMismatch &&
      !isWindowsLocaleMatchingCountry(
        this.winLocale.timeZoneId,
        this.winLocale.regionCode,
        targetCountry
      )
    ) {
      unsafeType = 'locale-mismatch';
      unsafeReason = `系统时区/区域 (${this.winLocale.regionName}) 与保护地区 (${targetCountryName}) 不一致`;
    }

    if (!unsafeType) {
      this.lastGuardFailSignature = null;
      return;
    }

    const result = await this.terminateMonitorProcesses(cfg.protectedProcessPatterns, unsafeType, unsafeReason);
    if (!result.hasKillEvent) return;

    if (unsafeType === 'locale-mismatch') {
      this.lastAlertSignature = `locale-mismatch:${targetCountry}:${this.winLocale.regionCode}:${this.winLocale.timeZoneId}`;
    }

    this.emitAlert({
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
    const report = await this.executeProcessKillSafely(patterns);
    const failSig = report.failedPids.length > 0 ? `${type}:${report.failedPids.join(',')}` : null;
    const newFailure = Boolean(failSig && failSig !== this.lastGuardFailSignature);
    this.lastGuardFailSignature = failSig;
    const hasKillEvent = report.killedCount > 0 || newFailure;
    if (report.killedCount > 0) {
      this.addLog('danger', `已终止受保护进程：${report.killedSummary.join(', ')} · ${reason}`);
    }
    if (newFailure && report.errorDetail) this.addLog('warn', report.errorDetail);
    if (hasKillEvent) this.emitState();
    return {
      killedProcesses: report.killedCount > 0 ? report.killedSummary : undefined,
      killError: report.errorDetail,
      hasKillEvent,
    };
  }

  private async handleLocaleMismatchTransition(reason: string): Promise<void> {
    if (!this.lastProbe) return;
    const cfg = this.configStore.get();
    const probeCode = this.lastProbe.countryCode.toUpperCase();
    const sig = `locale-mismatch:${probeCode}:${this.winLocale.regionCode}:${this.winLocale.timeZoneId}`;
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
      this.emitAlert({
        source: 'monitor',
        alertType: 'locale-mismatch',
        expectedCode: probeCode,
        expectedName: this.lastProbe.countryName || getCountryNameZh(probeCode),
        triggerReason: `${reason}：系统时区/区域 (${this.winLocale.regionName}) 与 Clash 选中通道出口 (${this.lastProbe.countryName}) 不一致`,
      });
    }
  }

  private async handleMismatchTransition(reason: string): Promise<void> {
    const cfg = this.configStore.get();
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

    this.emitAlert({
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
    const cfg = this.configStore.get();
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

    this.emitAlert({
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

  private emitAlert(opts: {
    alertType: AlertPayload['alertType'];
    expectedCode: string | null;
    expectedName: string | null;
    triggerReason: string;
    errorDetail?: string;
    killedProcesses?: string[];
    killError?: string;
    source?: 'claude' | 'monitor';
  }): void {
    const cfg = this.configStore.get();
    const isClaudeSource = opts.source === 'claude';
    if (!isClaudeSource && !cfg.monitorAlertEnabled) {
      return;
    }

    const clash = this.clashMonitor.getRuntimeInfo();
    const isDisconnect = opts.alertType === 'disconnect';
    const isVerificationUnavailable = opts.alertType === 'verification-unavailable';
    const refProbe = isClaudeSource ? this.claudeNodeProbe : this.lastProbe;

    const selectedFullLabel = cfg.selectedClashNode
      ? cfg.selectedClashProfileName
        ? `${cfg.selectedClashProfileName} / ${cfg.selectedClashNode}`
        : cfg.selectedClashNode
      : null;

    const activeNodeLabel = isClaudeSource
      ? selectedFullLabel
      : clash.connected
      ? clash.activeProfileName && clash.activeNode
        ? `${clash.activeProfileName} / ${clash.activeNode}`
        : clash.activeNode || clash.mode
      : null;

    const actualMismatchCode = refProbe?.regionMismatchDetail
      ? refProbe.googleCountryCode && refProbe.googleCountryCode !== refProbe.countryCode
        ? refProbe.googleCountryCode
        : refProbe.claudeTraceLoc && refProbe.claudeTraceLoc !== refProbe.countryCode
        ? refProbe.claudeTraceLoc
        : refProbe.countryCode
      : refProbe?.countryCode || null;
    const actualMismatchName = actualMismatchCode
      ? getCountryNameZh(actualMismatchCode)
      : refProbe?.countryName || null;

    const payload: AlertPayload = {
      source: opts.source,
      alertType: opts.alertType,
      expectedCode: opts.expectedCode,
      expectedName: opts.expectedName,
      actualCode: isDisconnect || isVerificationUnavailable ? null : actualMismatchCode,
      actualName: isVerificationUnavailable ? '校验未完成' : isDisconnect ? '连接断开' : actualMismatchName,
      actualIp: isDisconnect || isVerificationUnavailable ? null : refProbe?.ip || null,
      edgeLoc: refProbe?.edgeLoc,
      viaChannel: refProbe?.viaChannel,
      activeNode: activeNodeLabel,
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
      triggerReason: 'Clash 选中通道地区与系统时区/区域已恢复一致',
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

  private async probeOnceViaChannel(
    proxyUrl: string | null,
    viaChannel: string,
    timeoutMs: number,
    defaultErrMsg = '探测超时',
    onFailure?: (reason: string) => void
  ): Promise<{ result: ProbeResult | null; errMsg: string }> {
    const endpoints = this.buildEndpointsList();
    let errOut = defaultErrMsg;
    for (const ep of endpoints) {
      try {
        const startedAt = Date.now();
        const rawBody = await requestTextViaProxy(ep.url, proxyUrl, timeoutMs);
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
            viaChannel,
            latencyMs,
            checkedAt: Date.now(),
          },
          errMsg: '',
        };
      } catch (err) {
        errOut = `${ep.url}：${err instanceof Error ? err.message : String(err)}`;
        onFailure?.(errOut);
      }
    }
    return { result: null, errMsg: errOut };
  }

  /**
   * 校验目标服务地区；心跳允许复用 45 秒内的完整结果，切换及启动时重新校验。
   */
  private async verifyTargetServiceRegion(
    proxyUrl: string | null,
    probe: ProbeResult,
    targetApp: 'claude' | 'antigravity',
    forceRefresh = false
  ): Promise<void> {
    const baseCode = probe.countryCode.toUpperCase();
    if (!isValidIsoCountryCode(baseCode)) return;

    const cacheKey = `${targetApp}|${proxyUrl}|${probe.ip}|${baseCode}`;
    const cached = this.targetVerifyCache.get(cacheKey);
    if (!forceRefresh && cached && Date.now() - cached.checkedAt < 45000) {
      probe.googleCountryCode = cached.googleCountryCode;
      probe.googleCountryName = cached.googleCountryName;
      probe.claudeTraceLoc = cached.claudeTraceLoc;
      probe.claudeTraceIp = cached.claudeTraceIp;
      probe.claudeTraceError = undefined;
      probe.claudeTraceCheckedAt = targetApp === 'claude' ? cached.checkedAt : undefined;
      probe.regionMismatchDetail = cached.regionMismatchDetail;
      return;
    }

    this.targetVerifyCache.delete(cacheKey);
    probe.googleCountryCode = undefined;
    probe.googleCountryName = undefined;
    probe.claudeTraceLoc = undefined;
    probe.claudeTraceIp = undefined;
    probe.claudeTraceError = undefined;
    probe.claudeTraceCheckedAt = undefined;
    probe.regionMismatchDetail = null;

    const [googleSettled, claudeSettled] = await Promise.allSettled([
      targetApp === 'antigravity' ? probeGoogleRegionViaProxy(proxyUrl) : Promise.resolve(null),
      targetApp === 'claude' ? probeClaudeTraceViaProxy(proxyUrl) : Promise.resolve(null),
    ]);

    const googleRes =
      googleSettled.status === 'fulfilled' ? googleSettled.value : null;
    const claudeRes =
      claudeSettled.status === 'fulfilled' ? claudeSettled.value : null;
    if (targetApp === 'claude' && claudeSettled.status === 'rejected') {
      const error = claudeSettled.reason;
      probe.claudeTraceError = `https://claude.ai/cdn-cgi/trace：${error instanceof Error ? error.message : String(error)}`;
    }

    let googleCode: string | undefined;
    if (googleRes) {
      if (googleRes.altCountryCode && googleRes.altCountryCode !== baseCode) {
        googleCode = googleRes.altCountryCode;
      } else {
        googleCode = googleRes.countryCode;
      }
    }

    if (googleCode && isValidIsoCountryCode(googleCode)) {
      probe.googleCountryCode = googleCode;
      probe.googleCountryName = getCountryNameZh(googleCode);
    }

    if (claudeRes && isValidIsoCountryCode(claudeRes.loc)) {
      probe.claudeTraceLoc = claudeRes.loc;
      probe.claudeTraceCheckedAt = Date.now();
      if (claudeRes.ip) {
        probe.claudeTraceIp = claudeRes.ip;
      }
    }

    const googleMismatch = Boolean(
      probe.googleCountryCode && probe.googleCountryCode !== baseCode
    );
    const claudeMismatch = Boolean(
      targetApp === 'claude' &&
        probe.claudeTraceLoc &&
        probe.claudeTraceLoc !== baseCode
    );

    let mismatchDetail: string | null = null;
    if (googleMismatch && probe.googleCountryCode) {
      mismatchDetail = `离线库为 ${probe.countryName} (${baseCode})，但 Google 实际识别为 ${probe.googleCountryName} (${probe.googleCountryCode})（疑似假${probe.countryName}/送中节点）`;
    } else if (claudeMismatch && probe.claudeTraceLoc) {
      const splitIpNote =
        probe.claudeTraceIp && probe.claudeTraceIp !== probe.ip
          ? `，且分流出口 IP 变为 ${probe.claudeTraceIp}`
          : '';
      mismatchDetail = `离线库为 ${probe.countryName} (${baseCode})，但访问 Claude 实际识别为 ${getCountryNameZh(probe.claudeTraceLoc)} (${probe.claudeTraceLoc})${splitIpNote}`;
    }

    probe.regionMismatchDetail = mismatchDetail;

    if (
      isValidIsoCountryCode(targetApp === 'claude' ? probe.claudeTraceLoc : probe.googleCountryCode)
    ) {
      if (this.targetVerifyCache.size >= 64) {
        const oldestKey = this.targetVerifyCache.keys().next().value;
        if (oldestKey !== undefined) {
          this.targetVerifyCache.delete(oldestKey);
        }
      }
      this.targetVerifyCache.set(cacheKey, {
        checkedAt: Date.now(),
        googleCountryCode: probe.googleCountryCode,
        googleCountryName: probe.googleCountryName,
        claudeTraceLoc: probe.claudeTraceLoc,
        claudeTraceIp: probe.claudeTraceIp,
        regionMismatchDetail: mismatchDetail,
      });
    }
  }

  /**
   * 实时监控代理检测通道解析（纯粹检测 Clash 当前选中的代理通道，绝不关联启动器专属节点）：
   * 1. auto 模式下优先检测 Clash 当前选中的代理通道 (127.0.0.1:mixedPort)，未连接 Clash 时回退系统代理或默认路由
   * 2. manual / direct 模式下按用户在【设置】中指定的规则检测
   */
  private async resolveProxyChannel(): Promise<{
    proxyUrl: string | null;
    description: string;
    errorHint?: string;
  }> {
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

    // auto 模式：优先检测 Clash 当前选中的代理通道
    const clash = this.clashMonitor.getRuntimeInfo();
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

    const sys = await this.getSystemProxyFresh(false);
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

async function probeGoogleRegionViaProxy(
  proxyUrl: string | null
): Promise<{ countryCode: string; ip?: string; altCountryCode?: string } | null> {
  const parseSwJsData = (raw: string): { countryCode: string; ip?: string } | null => {
    const m = raw.match(
      /\["yt\.sw\.adr"\s*,\s*null\s*,\s*\[\[\[\s*"[^"]*"\s*,\s*"([A-Za-z]{2,3})"\s*,\s*null\s*,\s*"([^"]*)"/
    );
    if (m) {
      const code = normalizeIsoCountryCode(m[1]);
      if (code) {
        const ipStr = m[2].trim();
        return { countryCode: code, ip: net.isIP(ipStr) ? ipStr : undefined };
      }
    }
    try {
      const cleaned = raw.replace(/^\)\]\}'\s*/, '');
      const parsed = JSON.parse(cleaned) as unknown[];
      const firstEntry = (parsed?.[0] as unknown[])?.[2] as unknown[];
      const inner = (firstEntry?.[0] as unknown[])?.[0] as unknown[];
      if (Array.isArray(inner)) {
        const code = normalizeIsoCountryCode(String(inner[1] || ''));
        const ipCandidate = String(inner[3] || '').trim();
        if (code) {
          return {
            countryCode: code,
            ip: net.isIP(ipCandidate) ? ipCandidate : undefined,
          };
        }
      }
    } catch {
      // ignore JSON parse failure
    }
    return null;
  };

  const parseGoogleSearchHtml = (raw: string): { countryCode: string } | null => {
    const patterns = [
      /"MgUcDb"\s*:\s*"([A-Za-z]{2,3})"/,
      /,\d+,\d+,200,"([A-Za-z]{2,3})",null/,
    ];
    for (const pat of patterns) {
      const m = raw.match(pat);
      if (m) {
        const code = normalizeIsoCountryCode(m[1]);
        if (code) {
          return { countryCode: code };
        }
      }
    }
    return null;
  };

  const [ytSettled, gSearchSettled] = await Promise.allSettled([
    requestTextViaProxy('https://www.youtube.com/sw.js_data', proxyUrl, 4500),
    requestTextViaProxy('https://www.google.com/?hl=en', proxyUrl, 4500, 'text/html, */*'),
  ]);

  const ytRes =
    ytSettled.status === 'fulfilled' ? parseSwJsData(ytSettled.value) : null;
  const gSearchRes =
    gSearchSettled.status === 'fulfilled' ? parseGoogleSearchHtml(gSearchSettled.value) : null;

  if (ytRes && gSearchRes && ytRes.countryCode !== gSearchRes.countryCode) {
    return {
      countryCode: gSearchRes.countryCode,
      ip: ytRes.ip,
      altCountryCode: ytRes.countryCode,
    };
  }

  if (gSearchRes) {
    return { countryCode: gSearchRes.countryCode, ip: ytRes?.ip };
  }
  return ytRes;
}

async function probeClaudeTraceViaProxy(
  proxyUrl: string | null
): Promise<{ loc: string; ip: string | null }> {
  const raw = await requestTextViaProxy('https://claude.ai/cdn-cgi/trace', proxyUrl, 4500);
  const parsed = parseTraceResponse(raw, 'cf-trace');
  const loc = normalizeIsoCountryCode(parsed.loc);
  if (!loc) throw new Error('响应中未解析到有效国家/地区代码');
  return { loc, ip: parsed.ip };
}
