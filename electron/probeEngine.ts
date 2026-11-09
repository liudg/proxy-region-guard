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
  private isEnforcingClaudeSafety = false;
  private claudeNodeProbe: ProbeResult | null = null;
  private claudeNodeProbeError: string | null = null;

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

    this.clashMonitor.on('claude-clash-ready', () => {
      this.emitState();
      const cfg = this.configStore.get();
      const info = this.clashMonitor.getRuntimeInfo();
      if (cfg.selectedClashNode && info.dedicatedPortListening && !this.claudeIsProbing) {
        if (this.claudeDebounceTimer) {
          clearTimeout(this.claudeDebounceTimer);
        }
        this.claudeDebounceTimer = setTimeout(() => {
          this.claudeDebounceTimer = null;
          void this.probeClaudeNodeNow('Claude 专属代理端口已就绪');
        }, 250);
      }
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
      this.antigravityProbeSeq++;
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
      this.antigravityProbeSeq++;
      this.antigravityPendingReprobe = false;
      const cfg = this.configStore.update({
        antigravityClashNode: null,
        antigravityClashProfileUid: null,
        antigravityClashProfileName: null,
      });
      await this.clashMonitor.configureAntigravityNode(
        null,
        cfg.antigravityDedicatedPort,
        null,
        true
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

  /**
   * 轻量探测 Antigravity 专属端口的出口 IP 与国家（纯界面展示，绝不触发任何警告或状态拦截）
   */
  public async probeAntigravityNodeNow(): Promise<AppStateSnapshot> {
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
            this.antigravityProbeSeq === seqAtStart &&
            this.configStore.get().antigravityClashNode === targetNode
          ) {
            await sleep(320);
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
            this.antigravityProbeSeq === seqAtStart &&
            this.configStore.get().antigravityClashNode === targetNode
          ) {
            await this.verifyTargetServiceRegion(proxyUrl, probeSuccess, 'antigravity', true);
          }

          const afterCfg = this.configStore.get();
          if (
            this.antigravityProbeSeq !== seqAtStart ||
            afterCfg.antigravityClashNode !== targetNode ||
            afterCfg.antigravityClashProfileUid !== targetProfileUid
          ) {
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

    // 若当前已有 Antigravity.exe 或 language_server.exe 运行，需先终止旧进程，否则 Electron 单实例锁会使新进程直接退出
    const beforeProc = await inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort, true);
    if (beforeProc.running) {
      markAntigravityLaunchedByGuard(null);
      await this.executeProcessKillSafely(ANTIGRAVITY_PROCESS_PATTERNS);
      for (let i = 0; i < 8; i++) {
        const checkAlive = await inspectRunningAntigravityProcesses(
          cfg.antigravityDedicatedPort,
          true
        );
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

    let afterProc = await inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort, true);
    for (let i = 0; i < 6; i++) {
      if (afterProc.running) break;
      await sleep(250);
      afterProc = await inspectRunningAntigravityProcesses(cfg.antigravityDedicatedPort, true);
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
      this.claudeProbeSeq++;
      this.claudeNodeProbe = null;
      this.claudeNodeProbeError = null;
    }

    if (cleanNode) {
      this.claudeSwitchingCount++;
      this.addLog(
        'info',
        `正在将 Claude 专属代理通道切换至 Clash 节点：[${cleanNode}] (127.0.0.1:${prevCfg.dedicatedProxyPort})...`
      );
      let bindRes: Awaited<ReturnType<ClashMonitor['configureDedicatedNode']>>;
      try {
        bindRes = await this.clashMonitor.configureDedicatedNode(
          cleanNode,
          prevCfg.dedicatedProxyPort,
          effectiveProfileUid,
          true
        );
      } catch (err) {
        this.claudeSwitchingCount = Math.max(0, this.claudeSwitchingCount - 1);
        throw err;
      }

      const cfg = this.configStore.update({
        selectedClashNode: cleanNode,
        selectedClashProfileUid: bindRes.profileUid ?? effectiveProfileUid,
        selectedClashProfileName: bindRes.profileName ?? prevCfg.selectedClashProfileName,
      });

      const fullLabel = cfg.selectedClashProfileName
        ? `${cfg.selectedClashProfileName} / ${cleanNode}`
        : cleanNode;

      if (!bindRes.ok) {
        this.claudeSwitchingCount = Math.max(0, this.claudeSwitchingCount - 1);
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

      const probeTask = this.probeClaudeNodeNow(`切换 Claude 专属节点: ${fullLabel}`);
      this.claudeSwitchingCount = Math.max(0, this.claudeSwitchingCount - 1);
      return probeTask;
    } else {
      this.claudeProbeSeq++;
      this.claudePendingProbe = null;
      this.claudeSwitchingCount++;
      const cfg = this.configStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
      });
      try {
        await this.clashMonitor.configureDedicatedNode(null, cfg.dedicatedProxyPort, null, true);
      } finally {
        this.claudeSwitchingCount = Math.max(0, this.claudeSwitchingCount - 1);
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
          skipSafetyEnforcement,
        };
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
          if (!clash.connected || !clash.dedicatedPortListening) {
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
            if (!bindRes.ok || !bindRes.listening) {
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
                  activeSkipSafety = next.skipSafetyEnforcement;
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
                activeSkipSafety = next.skipSafetyEnforcement;
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

          const firstPass = await this.probeOnceViaChannel(proxyUrl, channelDesc, 5800);
          let probeSuccess = firstPass.result;
          let lastErrMsg = firstPass.errMsg;

          if (
            !probeSuccess &&
            this.claudeProbeSeq === seqAtStart &&
            this.configStore.get().selectedClashNode === targetNode
          ) {
            await sleep(320);
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
          if (
            probeSuccess &&
            this.claudeProbeSeq === seqAtStart &&
            this.configStore.get().selectedClashNode === targetNode
          ) {
            if (isHeartbeat) {
              // 定时心跳巡检保持原状，绝不向 Google / Claude 发起高频请求；仅沿用同 IP 已有的目标服务校验结果
              this.applyCachedTargetServiceVerification(proxyUrl, probeSuccess, 'claude');
            } else {
              const forceRefresh =
                activeReason.includes('手动') ||
                activeReason.includes('切换') ||
                activeReason.includes('启动') ||
                !this.claudeNodeProbe;
              await this.verifyTargetServiceRegion(proxyUrl, probeSuccess, 'claude', forceRefresh);
            }
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
              activeSkipSafety = next.skipSafetyEnforcement;
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
            const prevMismatch = this.claudeNodeProbe?.regionMismatchDetail;
            this.claudeNodeProbe = probeSuccess;
            this.claudeNodeProbeError = null;

            if (probeSuccess.regionMismatchDetail) {
              if (prevMismatch !== probeSuccess.regionMismatchDetail || !isHeartbeat) {
                this.addLog(
                  'danger',
                  `Claude 节点真伪校验未通过 [${label}]：${probeSuccess.regionMismatchDetail}`
                );
              }
            } else if (
              prevIp !== probeSuccess.ip ||
              prevCountry !== probeSuccess.countryCode ||
              !isHeartbeat
            ) {
              const verifiedTag =
                probeSuccess.googleCountryCode || probeSuccess.claudeTraceLoc
                  ? ' · 目标服务地区校验通过'
                  : '';
              this.addLog(
                'info',
                `Claude 节点检测 [${label}]：${probeSuccess.countryName} (${probeSuccess.countryCode})${verifiedTag} · IP: ${probeSuccess.ip} (${probeSuccess.latencyMs}ms)`
              );
            }
          } else {
            this.claudeNodeProbe = null;
            this.claudeNodeProbeError = simplifyNetworkError(lastErrMsg, channelDesc);
            this.addLog('warn', `Claude 节点检测失败：${this.claudeNodeProbeError}`);
          }

          if (this.claudePendingProbe && this.configStore.get().selectedClashNode) {
            const next = this.claudePendingProbe;
            this.claudePendingProbe = null;
            activeReason = next.reason;
            activeSkipSafety = next.skipSafetyEnforcement;
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

    // 5. 若当前已有运行中的 Claude 进程（含旧代理参数实例或后台 cowork-svc.exe 服务），必须先彻底清理并等待退出，
    // 否则 Electron 单实例锁会使新拉起的进程直接退出并沿用旧实例的环境参数
    await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
    for (let i = 0; i < 6; i++) {
      const checkAlive = await countRunningClaudeProcesses(true);
      if (!checkAlive.running) break;
      await sleep(150);
    }

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
    for (let i = 0; i < 5; i++) {
      await sleep(250);
      afterProc = await countRunningClaudeProcesses(true);
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
    this.claudeAuthorizedSession = false;
    this.claudeSeenRunningSinceAuth = false;
    this.claudeLaunchGraceUntil = 0;
    markClaudeLaunchedByGuard(null);
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

          // 拦截 2：无论是否开启唯一启动入口，只要 Claude 在运行，一旦出现「Claude 选定节点地区 ↔ 系统时区/区域」不一致或断连，立即剥夺授权并强杀！
          if (proc.running && !this.claudeIsProbing && this.claudeSwitchingCount === 0) {
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
   * 校验正在运行的 Claude 是否满足其独立选定节点的三重安全条件，不满足时尝试自愈复核，仍不满足则立即强杀并弹窗
   */
  private async enforceClaudeRunningSafety(triggerContext: string): Promise<boolean> {
    if (
      !this.claudeRunning ||
      this.claudeIsProbing ||
      this.claudeSwitchingCount > 0 ||
      this.isEnforcingClaudeSafety
    ) {
      return false;
    }
    this.isEnforcingClaudeSafety = true;
    try {
      const cfg = this.configStore.get();

      let check = this.evaluateClaudeSafety(
        this.claudeAuthorizedSession || cfg.claudeExclusiveGuard
      );

      // 若因 Clash 切换订阅组导致专属端口短暂重绑，立即尝试自动重绑并独立复核 Claude 节点，成功则无缝保持 Claude 运行
      const launchedPort = getLaunchedClaudePort();
      const portMatchesSession =
        !this.claudeAuthorizedSession ||
        launchedPort === null ||
        launchedPort === cfg.dedicatedProxyPort;

      if (
        !check.safe &&
        check.alertType === 'disconnect' &&
        cfg.selectedClashNode &&
        portMatchesSession
      ) {
        const healRes = await this.clashMonitor.configureDedicatedNode(
          cfg.selectedClashNode,
          cfg.dedicatedProxyPort,
          cfg.selectedClashProfileUid,
          true
        );
        if (healRes.listening) {
          await this.probeClaudeNodeNow('Clash 订阅切换后 Claude 专属通道自愈复核', true);
          check = this.evaluateClaudeSafety(
            this.claudeAuthorizedSession || cfg.claudeExclusiveGuard
          );
        }
      }

      if (check.safe) {
        return false;
      }

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

      if (report.killedCount > 0 || report.errorDetail) {
        const expectedCode = this.claudeNodeProbe?.countryCode || this.winLocale.regionCode;
        const expectedName = this.claudeNodeProbe?.countryName || this.winLocale.regionName;
        this.emitAlert({
          source: 'claude',
          alertType: check.alertType,
          expectedCode,
          expectedName,
          triggerReason: `${triggerContext}：${check.reason}`,
          errorDetail:
            check.alertType === 'disconnect'
              ? this.claudeNodeProbeError || undefined
              : undefined,
          killedProcesses: report.killedCount > 0 ? report.killedSummary : undefined,
          killError: report.errorDetail,
        });
      }

      return true;
    } finally {
      this.isEnforcingClaudeSafety = false;
    }
  }

  private evaluateClaudeSafety(requireDedicatedNode = true): {
    safe: boolean;
    reason: string;
    alertType: 'mismatch' | 'disconnect' | 'locale-mismatch';
  } {
    const cfg = this.configStore.get();
    const clash = this.clashMonitor.getRuntimeInfo();

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

    if (cfg.selectedClashNode && (!clash.connected || !clash.dedicatedPortListening)) {
      return {
        safe: false,
        reason: `Claude 专属节点 [${cfg.selectedClashNode}] 端口断开连接`,
        alertType: 'disconnect',
      };
    }

    if (this.claudeNodeProbeError || !this.claudeNodeProbe) {
      return {
        safe: false,
        reason: `Claude 专属节点出口不可达 (${this.claudeNodeProbeError || '连接异常'})`,
        alertType: 'disconnect',
      };
    }

    const proxyCountry = this.claudeNodeProbe.countryCode.toUpperCase();
    const proxyCountryName = this.claudeNodeProbe.countryName;

    if (!isValidIsoCountryCode(proxyCountry)) {
      return {
        safe: false,
        reason: '无法识别 Claude 选定节点的有效出口国家/地区',
        alertType: 'mismatch',
      };
    }

    if (this.claudeNodeProbe.regionMismatchDetail) {
      return {
        safe: false,
        reason: `节点真伪校验未通过：${this.claudeNodeProbe.regionMismatchDetail}`,
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
        reason: `Claude 节点地区 [${proxyCountryName} (${proxyCountry})] 与系统时区/区域 [${this.winLocale.regionName} · ${this.winLocale.timeZoneDisplayName}] 不一致`,
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

    const threeWayMatched = Boolean(
      proxyCountryCode &&
        !this.claudeNodeProbe?.regionMismatchDetail &&
        winRegionMatched &&
        winTimeZoneMatched
    );

    let launchBlockReason: string | null = null;
    if (!this.claudeDetectedExe) {
      launchBlockReason = '未检测到 Claude Desktop 安装路径，请手动指定 Claude.exe';
    } else if (!cfg.selectedClashNode) {
      launchBlockReason = '请先在下方选择要为 Claude 绑定的 Clash 代理节点';
    } else if (!clash.connected) {
      launchBlockReason = '未连接到 Clash Verge Rev 控制接口，请确认 Clash Verge 已启动';
    } else if (!clash.dedicatedPortListening) {
      launchBlockReason = `节点 [${cfg.selectedClashNode}] 专属端口 (127.0.0.1:${cfg.dedicatedProxyPort}) 尚未就绪`;
    } else if (this.claudeIsProbing && !this.claudeNodeProbe && !this.claudeNodeProbeError) {
      launchBlockReason = '正在独立验证 Claude 所选节点的真实出口 IP 与归属地...';
    } else if (this.claudeNodeProbeError || !proxyCountryCode) {
      launchBlockReason = `Claude 节点出口探测异常：${
        this.claudeNodeProbeError || '未获取到有效出口国家'
      }`;
    } else if (this.claudeNodeProbe?.regionMismatchDetail) {
      launchBlockReason = `节点真伪校验未通过：${this.claudeNodeProbe.regionMismatchDetail}，请更换节点`;
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
    const cfg = this.configStore.get();
    const effectiveTarget = this.getEffectiveTargetCountryCode();

    if (!cfg.monitorAlertEnabled) {
      this.lastAlertSignature = null;
    }

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

      if (!isValidIsoCountryCode(probeCode)) {
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
          if (cfg.monitorAlertEnabled) {
            this.emitRecoveredAlert();
          }
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

      const cfg = this.configStore.get();

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

        if (!isValidIsoCountryCode(probeCode)) {
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
              `实时监控地区不匹配！期望 [${cfg.defaultCountryName}]，实际为 [${probeSuccess.countryName} (${probeSuccess.countryCode})] · IP: ${probeSuccess.ip}`
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
              `实时监控出口 [${probeSuccess.countryName} (${probeCode})] 与系统时区/区域 [${this.winLocale.regionName} (${this.winLocale.regionCode})] 不一致 · IP: ${probeSuccess.ip}`
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
              `实时监控出口与时区一致 [${probeSuccess.countryName}] · IP: ${probeSuccess.ip} (${probeSuccess.latencyMs}ms)`
            );
          }
          if (this.lastAlertSignature !== null) {
            this.lastAlertSignature = null;
            if (cfg.monitorAlertEnabled) {
              this.emitRecoveredAlert();
            }
          }
          await this.enforceProcessGuardInBackground();
        }
      } else {
        this.lastError = channel.errorHint
          ? channel.errorHint
          : simplifyNetworkError(lastErrMsg, channel.description);
        this.status = 'error';
        this.addLog('warn', `实时监控代理检测失败：${this.lastError}`);
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
   * 根据目标通道（Claude 专栏选定节点 或 实时监控通道/默认保护地区）一键同步 Windows 时区与区域
   */
  public async syncSystemLocaleToDefault(
    targetSource: 'monitor' | 'claude' = 'monitor'
  ): Promise<LocaleSyncResult> {
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
        state: this.getSnapshot(),
      };
    }

    this.isSyncingLocale = true;
    this.emitState();

    const killedProcesses: string[] = [];

    try {
      // 若 Claude 正在运行，且即将切换的目标时区国家与 Claude 选定节点国家不一致（或 Claude 节点尚未检测出地区），必须先终止 Claude 以防暴露
      if (this.claudeRunning && claudeCode !== targetCode) {
        this.unsetClaudeAuthLock();
        const killReport = await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
        const claudeRegionLabel = claudeCode ? getCountryNameZh(claudeCode) : '未知/未就绪';
        if (killReport.killedCount > 0) {
          killedProcesses.push(...killReport.killedSummary);
          this.addLog(
            'danger',
            `同步系统时区至 [${getCountryNameZh(targetCode)}] 前检测到与运行中的 Claude 节点地区 [${claudeRegionLabel}] 不符，已先行终止：${killReport.killedSummary.join(', ')}`
          );
        }
        if (killReport.failedPids.length > 0) {
          const abortMsg = `${
            killReport.errorDetail || '运行中的 Claude 进程无法终止'
          }，已中止同步系统时区以防暴露！`;
          this.addLog('danger', abortMsg);
          this.emitAlert({
            source: 'claude',
            alertType: 'locale-mismatch',
            expectedCode: claudeCode || targetCode,
            expectedName: claudeCode ? getCountryNameZh(claudeCode) : getCountryNameZh(targetCode),
            triggerReason: '同步系统时区被安全拦截（运行中的 Claude 进程未能终止）',
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
      }

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
      const applyRes = await applyWindowsTimeZoneAndRegion(resolved.windowsTimeZoneId, targetCode);
      this.winLocale = applyRes.updated;

      if (!applyRes.ok) {
        const errMsg = applyRes.error || '修改系统时区或区域失败';
        this.addLog('warn', `一键同步时区/区域失败：${errMsg}`);
        return {
          ok: false,
          message: errMsg,
          killedProcesses,
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
        killedProcesses,
        state: this.getSnapshot(),
      };
    } finally {
      this.isSyncingLocale = false;
      this.emitState();
    }
  }

  /**
   * 还原回默认中国时区与区域（UTC+08:00 北京时间 + 区域“中国”）
   * 若与当前 Claude 节点出口或实时监控地区不一致，严格执行“先强杀 Claude 及受保护进程并确认全部退出后，才允许切换回中国时区”
   */
  public async restoreDefaultChinaLocale(): Promise<LocaleSyncResult> {
    const cfg = this.configStore.get();
    this.isSyncingLocale = true;
    this.emitState();

    const killedProcesses: string[] = [];

    try {
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
        `已自动强杀受保护进程：${report.killedSummary.join(', ')} · 原因：${unsafeReason}`
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
      source: 'monitor',
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

    let killedProcesses: string[] | undefined;
    let killError: string | undefined;
    let addedLogs = false;

    // 注意：实时监控仅管理【进程守护】Tab 中的自定义受保护进程；Claude 由其专属节点独立监控保护，绝不因 Clash 全局通道切换而误杀 Claude
    const patternsToKill = cfg.killProcessesEnabled ? cfg.protectedProcessPatterns : [];

    if (patternsToKill.length > 0) {
      const report = await this.executeProcessKillSafely(patternsToKill);

      if (report.killedCount > 0) {
        killedProcesses = report.killedSummary;
        this.addLog(
          'danger',
          `地区变更保护已触发，强杀受保护进程：${report.killedSummary.join(', ')}`
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

    if (!cfg.monitorAlertEnabled) {
      return;
    }

    const hasKillEvent = Boolean((killedProcesses && killedProcesses.length > 0) || killError);
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

    let killedProcesses: string[] | undefined;
    let killError: string | undefined;
    let addedLogs = false;

    const patternsToKill =
      cfg.killProcessesEnabled && cfg.killOnDisconnect ? cfg.protectedProcessPatterns : [];

    if (patternsToKill.length > 0) {
      const report = await this.executeProcessKillSafely(patternsToKill);

      if (report.killedCount > 0) {
        killedProcesses = report.killedSummary;
        this.addLog(
          'danger',
          `代理断连保护已触发，强杀受保护进程：${report.killedSummary.join(', ')}`
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

    const hasKillEvent = Boolean((killedProcesses && killedProcesses.length > 0) || killError);
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
    if (isClaudeSource) {
      if (!cfg.alertPopupEnabled) return;
    } else {
      if (!cfg.monitorAlertEnabled) return;
    }

    const clash = this.clashMonitor.getRuntimeInfo();
    const isDisconnect = opts.alertType === 'disconnect';
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
      actualCode: isDisconnect ? null : actualMismatchCode,
      actualName: isDisconnect ? '连接断开' : actualMismatchName,
      actualIp: isDisconnect ? null : refProbe?.ip || null,
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
    defaultErrMsg = '探测超时'
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
        errOut = err instanceof Error ? err.message : String(err);
      }
    }
    return { result: null, errMsg: errOut };
  }

  /**
   * 定时心跳巡检时复用同 IP 已有的目标服务地区校验结果，不向 Google / Claude 发起任何高频请求
   */
  private applyCachedTargetServiceVerification(
    proxyUrl: string,
    probe: ProbeResult,
    targetApp: 'claude' | 'antigravity' = 'claude'
  ): void {
    const baseCode = probe.countryCode.toUpperCase();
    const cacheKey = `${targetApp}|${proxyUrl}|${probe.ip}|${baseCode}`;
    const cached = this.targetVerifyCache.get(cacheKey);
    if (cached) {
      probe.googleCountryCode = cached.googleCountryCode;
      probe.googleCountryName = cached.googleCountryName;
      probe.claudeTraceLoc = cached.claudeTraceLoc;
      probe.claudeTraceIp = cached.claudeTraceIp;
      probe.regionMismatchDetail = cached.regionMismatchDetail;
      return;
    }
    if (
      targetApp === 'claude' &&
      this.claudeNodeProbe &&
      this.claudeNodeProbe.ip === probe.ip &&
      this.claudeNodeProbe.countryCode.toUpperCase() === baseCode
    ) {
      probe.googleCountryCode = this.claudeNodeProbe.googleCountryCode;
      probe.googleCountryName = this.claudeNodeProbe.googleCountryName;
      probe.claudeTraceLoc = this.claudeNodeProbe.claudeTraceLoc;
      probe.claudeTraceIp = this.claudeNodeProbe.claudeTraceIp;
      probe.regionMismatchDetail = this.claudeNodeProbe.regionMismatchDetail;
    }
  }

  /**
   * 对 Google / Claude 目标服务做一次真实地区校验（仅在切换代理、手动重测或启动前触发，精准识别「送中/假地区」或「机场服务端分流不一致」节点）
   */
  private async verifyTargetServiceRegion(
    proxyUrl: string,
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
      probe.regionMismatchDetail = cached.regionMismatchDetail;
      return;
    }

    const [googleSettled, claudeSettled] = await Promise.allSettled([
      probeGoogleRegionViaProxy(proxyUrl),
      targetApp === 'claude' ? probeClaudeTraceViaProxy(proxyUrl) : Promise.resolve(null),
    ]);

    const googleRes =
      googleSettled.status === 'fulfilled' ? googleSettled.value : null;
    const claudeRes =
      claudeSettled.status === 'fulfilled' ? claudeSettled.value : null;

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
    if (googleMismatch && claudeMismatch && probe.googleCountryCode && probe.claudeTraceLoc) {
      mismatchDetail = `离线库为 ${probe.countryName} (${baseCode})，但 Google 实际识别为 ${probe.googleCountryName} (${probe.googleCountryCode})、Claude 识别为 ${getCountryNameZh(probe.claudeTraceLoc)} (${probe.claudeTraceLoc})（疑似假${probe.countryName}/送中节点）`;
    } else if (googleMismatch && probe.googleCountryCode) {
      mismatchDetail = `离线库为 ${probe.countryName} (${baseCode})，但 Google 实际识别为 ${probe.googleCountryName} (${probe.googleCountryCode})（疑似假${probe.countryName}/送中节点）`;
    } else if (claudeMismatch && probe.claudeTraceLoc) {
      const splitIpNote =
        probe.claudeTraceIp && probe.claudeTraceIp !== probe.ip
          ? `，且分流出口 IP 变为 ${probe.claudeTraceIp}`
          : '';
      mismatchDetail = `离线库为 ${probe.countryName} (${baseCode})，但访问 Claude 实际识别为 ${getCountryNameZh(probe.claudeTraceLoc)} (${probe.claudeTraceLoc})${splitIpNote}`;
    }

    probe.regionMismatchDetail = mismatchDetail;

    if (probe.googleCountryCode || probe.claudeTraceLoc) {
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
  proxyUrl: string
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
  proxyUrl: string
): Promise<{ loc: string; ip: string | null } | null> {
  try {
    const raw = await requestTextViaProxy('https://claude.ai/cdn-cgi/trace', proxyUrl, 4500);
    const parsed = parseTraceResponse(raw, 'cf-trace');
    const loc = normalizeIsoCountryCode(parsed.loc);
    if (!loc && !parsed.ip) return null;
    return {
      loc: loc || 'UNKNOWN',
      ip: parsed.ip,
    };
  } catch {
    return null;
  }
}
