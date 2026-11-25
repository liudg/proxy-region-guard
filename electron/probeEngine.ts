import { app } from 'electron';
import { BinaryReader, WireType } from '@bufbuild/protobuf/wire';
import { EventEmitter } from 'node:events';
import * as net from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  AlertPayload,
  AntigravityLaunchResult,
  AntigravityRuntimeState,
  AppConfig,
  AppStateSnapshot,
  PrivateChannelId,
  ClaudeLaunchResult,
  ClaudeRuntimeState,
  GuardEventLog,
  GuardStatus,
  LocaleSyncResult,
  ProbeResult,
  UpdateStateSnapshot,
  WindowsLocaleState,
} from '../src/shared/types';
import { DEFAULT_GITHUB_RELEASES_PAGE_URL } from '../src/shared/updateManifest';
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
import { PrivateProxyService } from './privateKernel';
import {
  BUILTIN_TRACE_ENDPOINTS,
  doesHostShareDomain,
  selectProbeEndpointsForTransportHosts,
  TraceEndpoint,
} from './subscriptionCatalog';
import {
  getNetworkInterfaceFingerprint,
  readWindowsSystemProxy,
  SystemProxyState,
} from './systemProxy';
import { assertProcessesStopped, ProcessKillReport, terminateProtectedProcesses } from './processGuard';
import {
  getTargetServiceVerificationError,
  isValidIpAddress,
  normalizeIpAddress,
} from '../src/shared/probeValidation';
import {
  CLAUDE_VERIFICATION_RETRY_MS,
  ClaudeVerificationRecovery,
} from './claudeVerificationRecovery';
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
import {
  formatHostForUrl,
  formatNetworkErrorMessage,
  isLocalProxyRefusedCause,
  ProxyHttpResponse,
  requestHttpViaProxy,
  requestTextViaProxy,
} from './netClient';

export type { TraceEndpoint };

export const CLAUDE_MAX_RUNTIME_POLL_SEC = 10;
const MAX_IN_FLIGHT_REBOUND_CONTINUES = 2;
const EXIT_PROBE_TIMEOUT_MS = 15000;
const GENERAL_SOURCE_TIMEOUT_MS = 8000;
export const MIN_CONSENSUS_MATCHES = 2;
const CLAUDE_TRACE_TIMEOUT_MS = 14500;
const CLAUDE_TRACE_HEDGE_DELAY_MS = 2800;

export interface ClaudeSafetyCheck {
  safe: boolean;
  reason: string;
  alertType:
    | 'mismatch'
    | 'ip-change'
    | 'disconnect'
    | 'locale-mismatch'
    | 'verification-unavailable';
  expectedIp?: string | null;
  actualIp?: string | null;
}

export type ClaudeSampleOutcome =
  | { kind: 'refused' }
  | {
      kind: 'trace-error';
      claudeTraceError: string;
      claudeTraceLoc?: string;
      claudeTraceIp?: string;
      claudeTraceCountryCode?: string;
      claudeTraceCheckedAt?: number;
      latencyMs?: number;
    }
  | {
      kind: 'ok';
      loc: string;
      ip: string;
      countryCode: string;
      countryName: string;
      checkedAt: number;
      latencyMs: number;
    };

export function interpretClaudeTracePayload(
  raw: string,
  lookupOfflineStrict: (ip: string) => { countryCode: string; countryName: string },
  checkedAt: number,
  latencyMs: number
): Exclude<ClaudeSampleOutcome, { kind: 'refused' }> {
  const parsed = parseTraceResponse(raw, 'cf-trace');
  const loc = normalizeIsoCountryCode(parsed.loc);
  const normalizedClaudeIp = normalizeIpAddress(parsed.ip);
  if (!normalizedClaudeIp) {
    return {
      kind: 'trace-error',
      claudeTraceLoc: loc ?? undefined,
      claudeTraceCheckedAt: checkedAt,
      latencyMs,
      claudeTraceError: 'https://claude.ai/cdn-cgi/trace：响应中未解析到有效出口 IP',
    };
  }

  let traceGeo: { countryCode: string; countryName: string } | null = null;
  let traceGeoError: string | null = null;
  try {
    traceGeo = lookupOfflineStrict(normalizedClaudeIp);
  } catch (err) {
    traceGeoError = err instanceof Error ? err.message : String(err);
  }

  if (!loc) {
    return {
      kind: 'trace-error',
      claudeTraceIp: normalizedClaudeIp,
      claudeTraceCountryCode: traceGeo ? traceGeo.countryCode.toUpperCase() : undefined,
      claudeTraceCheckedAt: checkedAt,
      latencyMs,
      claudeTraceError: 'https://claude.ai/cdn-cgi/trace：响应中未解析到有效国家/地区代码',
    };
  }

  if (!traceGeo) {
    return {
      kind: 'trace-error',
      claudeTraceLoc: loc,
      claudeTraceIp: normalizedClaudeIp,
      claudeTraceCheckedAt: checkedAt,
      latencyMs,
      claudeTraceError: traceGeoError || '离线 GeoIP 校验失败',
    };
  }

  return {
    kind: 'ok',
    loc,
    ip: normalizedClaudeIp,
    countryCode: traceGeo.countryCode.toUpperCase(),
    countryName: traceGeo.countryName,
    checkedAt,
    latencyMs,
  };
}

export {
  BUILTIN_TRACE_ENDPOINTS,
  doesHostShareDomain,
  selectProbeEndpointsForTransportHosts,
};

export function isProbeRegionMismatched(probe: ProbeResult | null): boolean {
  if (!probe || probe.claudeTraceError) return false;
  if (probe.regionMismatchDetail) return true;
  if (
    !isValidIsoCountryCode(probe.countryCode) ||
    !isValidIsoCountryCode(probe.claudeTraceCountryCode)
  ) {
    return false;
  }
  const country = probe.countryCode.toUpperCase();
  if (probe.claudeTraceCountryCode.toUpperCase() !== country) return true;
  return Boolean(
    isValidIsoCountryCode(probe.claudeTraceLoc) &&
      probe.claudeTraceLoc.toUpperCase() !== country
  );
}

export function evaluateClaudeNodeProbeSafety(
  probe: ProbeResult,
  options: {
    claudeRunning: boolean;
    claudeExternalBaselinePending: boolean;
    claudeLockExitIp: boolean;
    claudeForceIpv4?: boolean;
    sessionInitialIp: string | null | undefined;
  }
): ClaudeSafetyCheck | null {
  const proxyCountry = probe.countryCode.toUpperCase();
  const verificationError = getTargetServiceVerificationError(probe, 'claude');
  if (verificationError && isProbeRegionMismatched(probe)) {
    return {
      safe: false,
      reason: `目标服务地区校验未通过：${verificationError}`,
      alertType: 'mismatch',
    };
  }

  const probeTraceIp = normalizeIpAddress(probe.claudeTraceIp);
  const lockedSessionIp = normalizeIpAddress(options.sessionInitialIp);
  if (
    options.claudeRunning &&
    !options.claudeExternalBaselinePending &&
    options.claudeLockExitIp &&
    lockedSessionIp &&
    probeTraceIp &&
    probeTraceIp !== lockedSessionIp
  ) {
    const stackSwitchNote =
      net.isIPv4(lockedSessionIp) && net.isIPv6(probeTraceIp)
        ? '，远端节点切至 IPv6 出口'
        : '';
    return {
      safe: false,
      reason: `Claude 会话出口 IP 发生变更（锁定基线 ${lockedSessionIp} → 当前 ${probeTraceIp}${stackSwitchNote}）`,
      alertType: 'ip-change',
      expectedIp: lockedSessionIp,
      actualIp: probeTraceIp,
    };
  }

  if (options.claudeForceIpv4 && probeTraceIp && net.isIPv6(probeTraceIp)) {
    return {
      safe: false,
      reason: `已开启强制仅走 IPv4 出站，但远端节点访问 Claude 返回了 IPv6 出口 (${probeTraceIp})`,
      alertType: 'ip-change',
      expectedIp: lockedSessionIp ?? null,
      actualIp: probeTraceIp,
    };
  }

  if (!isValidIsoCountryCode(proxyCountry)) {
    return {
      safe: false,
      reason: probe.claudeTraceError
        ? `目标服务地区校验未通过：${probe.claudeTraceError}`
        : '无法识别 Claude 选定节点的有效出口国家/地区',
      alertType: 'verification-unavailable',
    };
  }

  if (verificationError) {
    return {
      safe: false,
      reason: `目标服务地区校验未通过：${verificationError}`,
      alertType: 'verification-unavailable',
    };
  }

  return null;
}

export function resolveAlertActualMismatchFields(options: {
  isClaudeSource: boolean;
  alertType: AlertPayload['alertType'];
  expectedCode: string | null;
  explicitActualIp?: string | null;
  refProbe: ProbeResult | null;
  claudeSplitGeoCode?: string | null;
}): {
  actualCode: string | null;
  actualName: string | null;
  actualIp: string | null;
} {
  const { isClaudeSource, alertType, expectedCode, explicitActualIp, refProbe } = options;
  const isDisconnect = alertType === 'disconnect';
  const isVerificationUnavailable = alertType === 'verification-unavailable';
  const splitGeoCode =
    options.claudeSplitGeoCode ??
    (isClaudeSource && isValidIsoCountryCode(refProbe?.claudeTraceCountryCode)
      ? refProbe!.claudeTraceCountryCode!.toUpperCase()
      : null);

  const mismatchExitCandidates: Array<{ code: string | null | undefined; ip: string | null }> =
    isClaudeSource
      ? [
          { code: refProbe?.claudeTraceLoc, ip: refProbe?.claudeTraceIp || null },
          { code: splitGeoCode, ip: refProbe?.claudeTraceIp || null },
          { code: refProbe?.countryCode, ip: refProbe?.ip || null },
        ]
      : [
          { code: refProbe?.googleCountryCode, ip: refProbe?.ip || null },
          { code: refProbe?.countryCode, ip: refProbe?.ip || null },
        ];
  const differingExit = expectedCode
    ? mismatchExitCandidates.find(
        (item) =>
          isValidIsoCountryCode(item.code) &&
          item.code.toUpperCase() !== expectedCode.toUpperCase()
      )
    : undefined;

  const fallbackMismatchExit = !isClaudeSource &&
    refProbe?.googleCountryCode &&
    refProbe.googleCountryCode !== refProbe.countryCode
    ? { code: refProbe.googleCountryCode, ip: refProbe.ip || null }
    : refProbe?.claudeTraceLoc && refProbe.claudeTraceLoc !== refProbe.countryCode
    ? { code: refProbe.claudeTraceLoc, ip: refProbe.claudeTraceIp || null }
    : splitGeoCode && splitGeoCode !== refProbe?.countryCode
    ? { code: splitGeoCode, ip: refProbe?.claudeTraceIp || null }
    : { code: refProbe?.countryCode || null, ip: refProbe?.ip || null };

  const selectedMismatchExit = differingExit
    ? { code: differingExit.code!.toUpperCase(), ip: differingExit.ip }
    : {
        code: fallbackMismatchExit.code ? fallbackMismatchExit.code.toUpperCase() : null,
        ip: fallbackMismatchExit.ip,
      };

  const isUnknownGeoIpChange =
    isClaudeSource &&
    alertType === 'ip-change' &&
    Boolean(refProbe?.claudeTraceError) &&
    !isValidIsoCountryCode(refProbe?.claudeTraceCountryCode);

  const fallbackValidCountry =
    isClaudeSource && refProbe?.claudeTraceIp && splitGeoCode
      ? splitGeoCode
      : isValidIsoCountryCode(refProbe?.countryCode)
      ? refProbe!.countryCode.toUpperCase()
      : splitGeoCode;

  const actualMismatchCode = isUnknownGeoIpChange
    ? null
    : refProbe?.regionMismatchDetail
    ? selectedMismatchExit.code
    : fallbackValidCountry || null;
  const actualMismatchName = isUnknownGeoIpChange
    ? '归属地未知'
    : actualMismatchCode
    ? getCountryNameZh(actualMismatchCode)
    : refProbe?.countryName || null;

  const resolvedActualIp =
    explicitActualIp !== undefined
      ? explicitActualIp
      : isDisconnect || isVerificationUnavailable
      ? null
      : isClaudeSource && refProbe?.regionMismatchDetail
      ? selectedMismatchExit.ip
      : isClaudeSource
      ? refProbe?.claudeTraceIp || refProbe?.ip || null
      : refProbe?.ip || null;

  return {
    actualCode: isDisconnect || isVerificationUnavailable ? null : actualMismatchCode,
    actualName: isVerificationUnavailable
      ? '校验未完成'
      : isDisconnect
      ? '连接断开'
      : actualMismatchName,
    actualIp: resolvedActualIp,
  };
}

export class ProbeEngine extends EventEmitter {
  private configStore: ConfigStore;
  private geoIp: GeoIpService;
  private clashMonitor: ClashMonitor;

  private status: GuardStatus = 'checking';
  private started = false;
  private stopped = false;
  private isChecking = false;
  private isSyncingLocale = false;
  private activeKillCount = 0;
  private killQueue: Promise<unknown> = Promise.resolve();
  private applicationChanges = new Set<PrivateChannelId | 'global'>();
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
  private claudeSessionInitialIp: string | null = null;
  private claudeExternalBaselinePending = false;
  private claudeExternalBaselineMinSeq = 0;
  private claudeSeenRunningSinceAuth = false;
  private claudeLaunchGraceUntil = 0;
  private claudeIsProbing = false;
  private claudeActiveProbeSkipSafety = false;
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
  private claudeHeartbeatTimer: NodeJS.Timeout | null = null;
  private lastClaudeProbeCompletedAt = 0;
  private claudeProbeAbortController: AbortController | null = null;
  private antigravityProbeAbortController: AbortController | null = null;
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
  private claudeReboundDuringProbe = false;
  private antigravityReboundDuringProbe = false;
  private updateStateProvider: (() => UpdateStateSnapshot) | null = null;

  constructor(configStore: ConfigStore, geoIp: GeoIpService, clashMonitor: ClashMonitor, private readonly privateProxies: PrivateProxyService) {
    super();
    this.configStore = configStore;
    this.geoIp = geoIp;
    this.clashMonitor = clashMonitor;
    this.claudeVerificationRecovery = new ClaudeVerificationRecovery(
      async (signal) => {
        if (this.stopped || signal.aborted || !this.claudeRunning) {
          this.claudeVerificationRecovery.clear();
          return;
        }
        if (!this.claudeProbePromise && !this.claudeSafetyKillPromise) {
          const onAbort = () => {
            this.abortActiveClaudeProbe('Claude 后台复核已取消');
          };
          signal.addEventListener('abort', onAbort, { once: true });
          try {
            await this.probeClaudeNodeNow('Claude 运行期后台复核');
          } finally {
            signal.removeEventListener('abort', onAbort);
          }
        }
      },
      CLAUDE_VERIFICATION_RETRY_MS,
      (error) => {
        if (this.stopped || !this.claudeRunning) {
          this.claudeVerificationRecovery.clear();
          return;
        }
        const detail = error instanceof Error ? error.message : String(error);
        this.recordClaudeVerificationFailure(`Claude 后台复核异常：${detail}`);
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

    this.privateProxies.on('state', () => {
      if (!this.stopped) this.emitState();
    });
    this.privateProxies.on('ready', (channel: PrivateChannelId) => {
      if (!this.stopped) this.handleChannelListenerRebound(channel);
    });
    this.privateProxies.on('lost', (channel: PrivateChannelId, reason: string) => {
      if (this.stopped) return;
      if (channel === 'claude') {
        this.claudeProbeSeq++;
        this.abortActiveClaudeProbe(reason);
        this.lastClaudeProbeCompletedAt = 0;
        this.claudeNodeProbe = null;
        this.claudeNodeProbeError = reason;
        void this.enforceClaudeRunningSafety(reason);
      } else {
        this.antigravityProbeSeq++;
        this.abortActiveAntigravityProbe(reason);
        this.antigravityNodeProbe = null;
        this.antigravityNodeProbeError = reason;
      }
      this.addLog('danger', `${channel}：${reason}`);
    });
    this.privateProxies.on('port-conflict', (channel: PrivateChannelId, reason: string) => {
      if (this.stopped) return;
      if (channel === 'claude') {
        this.claudeProbeSeq++;
        this.abortActiveClaudeProbe(reason);
        this.claudePendingProbe = null;
        this.lastClaudeProbeCompletedAt = 0;
        this.claudeNodeProbe = null;
        this.claudeNodeProbeError = reason;
        this.addLog('danger', `claude：${reason}`);
        this.emitState();
        if (!this.claudeActiveProbeSkipSafety && this.claudeRunning) {
          void this.enforceClaudeRunningSafety(reason);
        }
      } else {
        this.antigravityProbeSeq++;
        this.abortActiveAntigravityProbe(reason);
        this.antigravityPendingReprobe = false;
        this.antigravityNodeProbe = null;
        this.antigravityNodeProbeError = reason;
        this.addLog('warn', `antigravity：${reason}`);
        this.emitState();
      }
    });
    this.privateProxies.on('fault', (channel: PrivateChannelId, reason: string) => {
      if (this.stopped) return;
      this.emit('trigger-alert', this.systemAlert('kernel-error', `${channel} 私有内核故障：${reason}`));
    });
    this.clashMonitor.on('catalog-updated', () => {
      for (const kernel of Object.values(this.privateProxies.channels)) kernel.refreshSource(this.clashMonitor.catalog);
    });
    this.clashMonitor.on('tun-enabled', () => {
      this.emit('trigger-alert', this.systemAlert('tun-enabled', '检测到 Clash Verge 已开启 TUN。当前专属代理尚未兼容 TUN 模式，Clash Verge 切换订阅、重启或退出可能影响 Claude 和 Antigravity 的连接。请关闭 TUN。'));
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

  private systemAlert(alertType: 'tun-enabled' | 'kernel-error', message: string): AlertPayload {
    return { source: 'system', alertType, expectedCode: null, expectedName: null, actualCode: null,
      actualName: null, actualIp: null, triggerReason: message, errorDetail: message,
      soundEnabled: this.configStore.get().alertSoundEnabled, timestamp: Date.now() };
  }

  private persistPrivateSelection(channel: PrivateChannelId): void {
    const state = this.privateProxies.channels[channel].getState();
    const cfg = this.configStore.get();
    this.configStore.update(channel === 'claude'
      ? { selectedClashNode: state.nodeName, selectedClashProfileUid: state.profileUid,
        selectedClashProfileName: state.profileName, dedicatedProxyPort: state.port || cfg.dedicatedProxyPort }
      : { antigravityClashNode: state.nodeName, antigravityClashProfileUid: state.profileUid,
        antigravityClashProfileName: state.profileName, antigravityDedicatedPort: state.port || cfg.antigravityDedicatedPort });
  }

  private async checkPrivateReady(
    channel: PrivateChannelId,
    signal?: AbortSignal
  ): Promise<{ ok: boolean; error?: string }> {
    try { await this.privateProxies.channels[channel].checkReady(signal); return { ok: true }; }
    catch (error) { return { ok: false, error: error instanceof Error ? error.message : String(error) }; }
  }

  private isEffectiveClaudeForceIpv4(cfg: AppConfig = this.configStore.get()): boolean {
    if (!cfg.claudeForceIpv4) return false;
    const kernel = this.privateProxies.channels.claude;
    // 升级启动时若为保护宿主机已有外部 Claude 会话而延后内核迁移，保留该运行中会话直到其退出或下次安全启动
    if (this.claudeRunning && kernel.getSnapshot() && !kernel.getIpv4Only()) {
      return false;
    }
    return true;
  }

  private async bindPrivateSelection(
    channel: PrivateChannelId,
    node: string | null,
    port: number,
    uid: string | null,
    applyUpdate = false,
    ipv4OnlyOverride?: boolean,
    skipLegacyRelease = false,
    persistSelection = true
  ): Promise<{ ok: boolean; error?: string }> {
    const kernel = this.privateProxies.channels[channel];
    let selectionCompleted = false;
    try {
      const current = kernel.getSnapshot();
      const targetIpv4Only =
        channel === 'claude'
          ? ipv4OnlyOverride ?? this.configStore.get().claudeForceIpv4
          : false;
      if (node && !uid) throw new Error('请选择节点所属的订阅');
      let snapshot = current;
      if (!node) snapshot = null;
      else if (applyUpdate || current?.nodeName !== node || current.profileUid !== uid) {
        await this.clashMonitor.refresh();
        snapshot = this.clashMonitor.catalog.capture(uid!, node);
      }
      if (
        snapshot?.fingerprint === current?.fingerprint &&
        kernel.getState().port === port &&
        kernel.getState().phase === 'ready' &&
        kernel.getIpv4Only() === targetIpv4Only
      ) {
        return { ok: true };
      }
      if (node && !kernel.getState().pid && !skipLegacyRelease) {
        await this.clashMonitor.releaseLegacyListeners(port);
      }
      await kernel.select(snapshot, port, { ipv4Only: targetIpv4Only });
      selectionCompleted = true;
      kernel.refreshSource(this.clashMonitor.catalog);
      return { ok: true };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    } finally {
      if (persistSelection && (kernel.getSnapshot() || selectionCompleted)) {
        this.persistPrivateSelection(channel);
      }
    }
  }

  private async migrateDeferredClaudeIpv4IfIdle(): Promise<void> {
    if (this.stopped || this.claudeRunning || this.applicationChanges.size > 0) return;
    const cfg = this.configStore.get();
    const kernel = this.privateProxies.channels.claude;
    if (!cfg.selectedClashNode || !kernel.getSnapshot() || kernel.getIpv4Only() === cfg.claudeForceIpv4) {
      return;
    }
    try {
      await this.runApplicationChange(async () => {
        if (this.stopped || this.claudeRunning) return;
        const latestCfg = this.configStore.get();
        if (
          !latestCfg.selectedClashNode ||
          !kernel.getSnapshot() ||
          kernel.getIpv4Only() === latestCfg.claudeForceIpv4
        ) {
          return;
        }
        this.claudeProbeSeq++;
        this.abortActiveClaudeProbe('执行延后的 Claude 私有内核 IPv4 模式迁移');
        this.lastClaudeProbeCompletedAt = 0;
        this.claudeNodeProbe = null;
        this.claudeNodeProbeError = null;
        this.claudeSwitchingCount++;
        let bindRes: { ok: boolean; error?: string };
        try {
          bindRes = await this.bindPrivateSelection(
            'claude',
            latestCfg.selectedClashNode,
            latestCfg.dedicatedProxyPort,
            latestCfg.selectedClashProfileUid,
            false,
            latestCfg.claudeForceIpv4,
            true
          );
        } finally {
          this.claudeSwitchingCount--;
        }
        if (!bindRes.ok) {
          const message = `延后迁移 Claude 私有内核 IPv4 模式失败：${bindRes.error || '未知错误'}`;
          this.claudeNodeProbeError = message;
          this.addLog('danger', message);
          this.emitState();
          return;
        }
        this.addLog(
          'success',
          latestCfg.claudeForceIpv4
            ? `外部 Claude 会话已退出，已自动将私有内核切换至强制仅走 IPv4 出站 (127.0.0.1:${latestCfg.dedicatedProxyPort})`
            : `外部 Claude 会话已退出，已自动将私有内核切换至双栈出站 (127.0.0.1:${latestCfg.dedicatedProxyPort})`
        );
        this.emitState();
        void this.probeClaudeNodeNow('应用延后的 Claude IPv4 出站模式迁移');
      }, 'claude');
    } catch {
      // 并发变更进行中时自动交由下次巡检或下次启动完成迁移
    }
  }

  private async restorePrivateSelections(): Promise<void> {
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
          if (this.claudeRunning) {
            // 升级启动时宿主机已有运行中的 Claude 会话：不中断外部会话，同时保留用户的 claudeForceIpv4 设置，
            // 待外部会话退出或下次从面板安全启动前自动完成私有内核迁移。
            this.addLog(
              'warn',
              '检测到已有运行中的 Claude 会话，已暂留现有私有内核出站模式以避免中断外部会话；待 Claude 退出或下次从专栏启动前将自动应用「强制通道仅走 IPv4 出站」设置'
            );
          } else {
            this.abortActiveClaudeProbe('升级 Claude 私有内核 IPv4 模式');
            try {
              await kernel.select(kernel.getSnapshot(), kernel.getState().port!, {
                ipv4Only: cfg.claudeForceIpv4,
              });
              kernel.refreshSource(this.clashMonitor.catalog);
            } catch (error) {
              const detail = error instanceof Error ? error.message : String(error);
              const message = `claude 私有内核切换 IPv4 模式失败：${detail}`;
              this.claudeNodeProbeError = message;
              this.addLog('danger', message);
              this.emit('trigger-alert', this.systemAlert('kernel-error', message));
            }
          }
        }
        this.persistPrivateSelection(channel);
        continue;
      }
      if (kernel.getState().phase !== 'idle') continue;
      const node = channel === 'claude' ? cfg.selectedClashNode : cfg.antigravityClashNode;
      if (!node) continue;
      const uid = channel === 'claude' ? cfg.selectedClashProfileUid : cfg.antigravityClashProfileUid;
      const port = channel === 'claude' ? cfg.dedicatedProxyPort : cfg.antigravityDedicatedPort;
      if (channel === 'claude') await this.stopClaudeBeforeRoutingChange();
      const result = await this.bindPrivateSelection(channel, node, port, uid);
      if (!result.ok) {
        const message = `${channel} 节点迁移失败：${result.error}`;
        if (channel === 'claude') this.claudeNodeProbeError = message;
        else this.antigravityNodeProbeError = message;
        this.addLog('danger', message);
        this.emit('trigger-alert', this.systemAlert('kernel-error', message));
      }
    }
  }

  public async applyNodeUpdate(channel: PrivateChannelId): Promise<AppStateSnapshot> {
    return this.runApplicationChange(async () => {
      const state = this.privateProxies.channels[channel].getState();
      if (!state.nodeName || !state.profileUid || !state.port) throw new Error('尚未保存专属节点');
      if (channel === 'claude') await this.stopClaudeBeforeRoutingChange();
      if (channel === 'claude') {
        this.claudeProbeSeq++;
        this.abortActiveClaudeProbe('手动应用节点更新');
        this.lastClaudeProbeCompletedAt = 0;
        this.claudeNodeProbe = null;
      }
      else {
        this.antigravityProbeSeq++;
        this.abortActiveAntigravityProbe('手动应用节点更新');
        this.antigravityNodeProbe = null;
      }
      const result = await this.bindPrivateSelection(channel, state.nodeName, state.port, state.profileUid, true);
      if (!result.ok) throw new Error(result.error);
      return channel === 'claude' ? this.probeClaudeNodeNow('手动应用节点更新') : this.probeAntigravityNodeNow();
    }, channel);
  }

  public async restartPrivateKernel(channel: PrivateChannelId): Promise<AppStateSnapshot> {
    return this.runApplicationChange(async () => {
      if (channel === 'claude') {
        await this.stopClaudeBeforeRoutingChange();
        this.claudeProbeSeq++;
        this.abortActiveClaudeProbe('手动重启私有内核');
        this.lastClaudeProbeCompletedAt = 0;
        this.claudeNodeProbe = null;
      }
      else {
        this.antigravityProbeSeq++;
        this.abortActiveAntigravityProbe('手动重启私有内核');
        this.antigravityNodeProbe = null;
      }
      const state = this.privateProxies.channels[channel].getState();
      if (state.port && !state.pid) await this.clashMonitor.releaseLegacyListeners(state.port);
      await this.privateProxies.channels[channel].restart();
      return channel === 'claude' ? this.probeClaudeNodeNow('手动重启私有内核') : this.probeAntigravityNodeNow();
    }, channel);
  }

  public async start(): Promise<void> {
    this.stopped = false;
    this.started = true;
    let cfg = this.configStore.get();
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

    this.clashMonitor.start();
    await this.restorePrivateSelections();
    cfg = this.configStore.get();
    this.startLocalEnvironmentWatcher();
    this.startClaudeExclusiveWatcher();
    this.restartHeartbeatTimer();

    if (cfg.selectedClashNode) {
      if (this.claudeRunning && !cfg.claudeExclusiveGuard) {
        this.claudeExternalBaselinePending = true;
        this.claudeExternalBaselineMinSeq = this.claudeProbeSeq + 1;
      }
      void this.probeClaudeNodeNow('应用启动检测 Claude 专属节点');
    }
    await this.checkNow('应用启动首次检测');
  }

  public stop(): void {
    if (this.stopped) return;
    const wasStarted = this.started;
    this.stopped = true;
    this.started = false;
    this.abortActiveClaudeProbe('应用已停止');
    this.abortActiveAntigravityProbe('应用已停止');
    this.claudeVerificationRecovery.clear();

    const shouldKillClaudeOnExit =
      wasStarted &&
      (this.claudeRunning ||
        this.claudeAuthorizedSession ||
        this.configStore.get().claudeExclusiveGuard);

    this.claudeAuthorizedSession = false;
    this.claudeSessionInitialIp = null;
    this.claudeExternalBaselinePending = false;
    this.claudeExternalBaselineMinSeq = 0;
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
    this.clearClaudeHeartbeatTimer();
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

  private abortActiveClaudeProbe(reason = 'Claude 探测已取消'): void {
    const controller = this.claudeProbeAbortController;
    if (controller && !controller.signal.aborted) {
      controller.abort(Object.assign(new Error(reason), { name: 'AbortError' }));
    }
  }

  private abortActiveAntigravityProbe(reason = 'Antigravity 探测已取消'): void {
    const controller = this.antigravityProbeAbortController;
    if (controller && !controller.signal.aborted) {
      controller.abort(Object.assign(new Error(reason), { name: 'AbortError' }));
    }
  }

  private clearClaudeHeartbeatTimer(): void {
    if (this.claudeHeartbeatTimer) {
      clearTimeout(this.claudeHeartbeatTimer);
      this.claudeHeartbeatTimer = null;
    }
  }

  private syncClaudeHeartbeatSchedule(): void {
    this.clearClaudeHeartbeatTimer();
    if (this.stopped || !this.started) return;
    const cfg = this.configStore.get();
    if (
      !this.claudeRunning ||
      !cfg.selectedClashNode ||
      this.claudeVerificationRecovery.snapshot !== null
    ) {
      return;
    }

    // Claude 专属运行期巡检：不受全局心跳关闭 (0s) 或长周期拖累，最高 10s 间隔动态调度实时校验
    const sec = cfg.heartbeatIntervalSec;
    const claudePollSec =
      sec > 0 ? Math.min(sec, CLAUDE_MAX_RUNTIME_POLL_SEC) : CLAUDE_MAX_RUNTIME_POLL_SEC;
    const pollIntervalMs = claudePollSec * 1000;
    const elapsedMs =
      this.lastClaudeProbeCompletedAt > 0
        ? Math.max(0, Date.now() - this.lastClaudeProbeCompletedAt)
        : 0;
    const delayMs =
      this.lastClaudeProbeCompletedAt > 0
        ? Math.max(1000, pollIntervalMs - elapsedMs)
        : pollIntervalMs;

    this.claudeHeartbeatTimer = setTimeout(() => {
      this.claudeHeartbeatTimer = null;
      if (this.stopped) return;
      const latestCfg = this.configStore.get();
      if (
        !this.claudeRunning ||
        !latestCfg.selectedClashNode ||
        this.claudeVerificationRecovery.snapshot !== null
      ) {
        return;
      }
      if (!this.claudeProbePromise && !this.claudeSafetyKillPromise) {
        void this.probeClaudeNodeNow('Claude 运行期心跳巡检');
      } else {
        this.syncClaudeHeartbeatSchedule();
      }
    }, delayMs);
  }

  public async prepareForUpdate(): Promise<void> {
    this.stop();
    await this.privateProxies.shutdown();
  }

  public async resumeAfterUpdateFailure(): Promise<void> {
    await this.start();
  }

  public restartHeartbeatTimer(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    this.clearClaudeHeartbeatTimer();
    if (this.stopped) return;

    const sec = this.configStore.get().heartbeatIntervalSec;
    if (sec > 0) {
      this.heartbeatTimer = setInterval(() => {
        if (this.stopped) return;
        // 实时监控通道巡检：后台定时静默复核出口 IP 是否漂移
        void this.checkNow('轻量心跳巡检');
      }, sec * 1000);
    }

    this.syncClaudeHeartbeatSchedule();
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

  /** 从订阅保存 Antigravity 节点副本并启动对应私有内核。 */
  public async selectAntigravityClashNode(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    return this.runApplicationChange(() => this.selectAntigravityClashNodeInternal(nodeName, profileUid), 'antigravity');
  }

  private async selectAntigravityClashNodeInternal(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    this.antigravityProbeSeq++;
    this.abortActiveAntigravityProbe('切换 Antigravity 专属节点');
    this.antigravityNodeProbe = null;
    this.antigravityNodeProbeError = null;
    this.antigravitySwitchingCount++;
    try {
      await this.bindAntigravitySelection(nodeName, profileUid);
    } finally {
      this.antigravitySwitchingCount--;
    }
    if (this.configStore.get().antigravityClashNode &&
        this.privateProxies.channels.antigravity.getState().phase === 'ready') {
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
      const bindRes = await this.bindPrivateSelection('antigravity',
        cleanNode,
        prevCfg.antigravityDedicatedPort,
        effectiveProfileUid
      );
      const cfg = this.configStore.get();

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
        `Antigravity 私有内核已启动 [${fullLabel}] → 127.0.0.1:${cfg.antigravityDedicatedPort}`
      );
      return this.getSnapshot();
    } else {
      this.antigravityPendingReprobe = false;
      await this.bindPrivateSelection('antigravity', null, prevCfg.antigravityDedicatedPort, null);
      this.antigravityNodeProbe = null;
      this.antigravityNodeProbeError = null;
      if (prevCfg.antigravityClashNode) {
        this.addLog('info', '已取消 Antigravity 专属 Clash 节点绑定');
      }
      this.emitState();
      return this.getSnapshot();
    }
  }

  private needsChannelRecoveryProbe(channel: 'claude' | 'antigravity'): boolean {
    const probe = channel === 'claude' ? this.claudeNodeProbe : this.antigravityNodeProbe;
    const probeErr =
      channel === 'claude' ? this.claudeNodeProbeError : this.antigravityNodeProbeError;
    if (!probe || Boolean(probeErr)) {
      return true;
    }
    if (channel === 'claude') {
      return Boolean(getTargetServiceVerificationError(probe, 'claude'));
    }
    return !isValidIsoCountryCode(probe.googleCountryCode);
  }

  private handleChannelListenerRebound(
    channel: 'claude' | 'antigravity'
  ): void {
    if (this.stopped) return;
    if (channel === 'claude') {
      if (this.claudeIsProbing) this.claudeReboundDuringProbe = true;
    } else if (this.antigravityIsProbing) {
      this.antigravityReboundDuringProbe = true;
    }
    this.emitState();

    const cfg = this.configStore.get();
    const channels = this.privateProxies.getState();
    if (channel === 'claude') {
      if (
        cfg.selectedClashNode &&
        channels.claude.phase === 'ready' &&
        this.claudeSwitchingCount === 0 &&
        !this.claudeIsProbing &&
        this.needsChannelRecoveryProbe('claude')
      ) {
        if (this.claudeDebounceTimer) clearTimeout(this.claudeDebounceTimer);
        this.claudeDebounceTimer = setTimeout(() => {
          this.claudeDebounceTimer = null;
          if (this.stopped) return;
          void this.probeClaudeNodeNow('Claude 专属代理端口恢复重测');
        }, 250);
      }
    } else if (
      cfg.antigravityClashNode &&
      channels.antigravity.phase === 'ready' &&
      this.antigravitySwitchingCount === 0 &&
      !this.antigravityIsProbing &&
      this.needsChannelRecoveryProbe('antigravity')
    ) {
      if (this.antigravityDebounceTimer) clearTimeout(this.antigravityDebounceTimer);
      this.antigravityDebounceTimer = setTimeout(() => {
        this.antigravityDebounceTimer = null;
        if (this.stopped) return;
        void this.probeAntigravityNodeNow();
      }, 250);
    }
  }

  private isCurrentClaudeProbe(sequence: number, config: AppConfig): boolean {
    const current = this.configStore.get();
    return (
      this.claudeSwitchingCount === 0 &&
      this.claudeProbeSeq === sequence &&
      current.selectedClashNode === config.selectedClashNode &&
      current.selectedClashProfileUid === config.selectedClashProfileUid &&
      current.dedicatedProxyPort === config.dedicatedProxyPort &&
      current.claudeForceIpv4 === config.claudeForceIpv4
    );
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
    if (this.stopped || this.antigravitySwitchingCount > 0) return this.getSnapshot();
    const cfg = this.configStore.get();
    if (!cfg.antigravityClashNode) {
      this.antigravityProbeSeq++;
      this.abortActiveAntigravityProbe('未选择 Antigravity 节点');
      this.antigravityPendingReprobe = false;
      this.antigravityReboundDuringProbe = false;
      this.antigravityNodeProbe = null;
      this.antigravityNodeProbeError = null;
      this.emitState();
      return this.getSnapshot();
    }

    if (this.antigravityProbePromise) {
      this.antigravityPendingReprobe = true;
      return this.antigravityProbePromise;
    }

    let p: Promise<AppStateSnapshot> | null = null;
    const runProbe = async (): Promise<AppStateSnapshot> => {
      try {
        this.antigravityIsProbing = true;
        this.emitState();

        let agReboundContinueCount = 0;
        let agRetriedBinding = false;
        while (!this.stopped) {
          if (this.antigravitySwitchingCount > 0) break;
          this.antigravityPendingReprobe = false;
          const seqAtStart = ++this.antigravityProbeSeq;
          const curCfg = this.configStore.get();
          const targetNode = curCfg.antigravityClashNode;
          if (!targetNode) {
            this.antigravityNodeProbe = null;
            this.antigravityNodeProbeError = null;
            break;
          }

          const tryContinueSupersededAgProbe = (): boolean => {
            if (!this.stopped && !this.isCurrentAntigravityProbe(seqAtStart, curCfg)) {
              if (this.configStore.get().antigravityClashNode) {
                if (this.privateProxies.channels.antigravity.getState().phase !== 'ready') {
                  return false;
                }
                agRetriedBinding = false;
                agReboundContinueCount = 0;
                return true;
              }
              this.antigravityNodeProbe = null;
              this.antigravityNodeProbeError = null;
            }
            return false;
          };

          const agController = new AbortController();
          this.antigravityProbeAbortController = agController;
          let probeSuccess: ProbeResult | null = null;
          let lastErrMsg = '探测超时';
          const proxyUrl = `http://127.0.0.1:${curCfg.antigravityDedicatedPort}`;
          const channelDesc = `Antigravity 专属端口 (127.0.0.1:${curCfg.antigravityDedicatedPort})`;

          try {
            const bindRes = await this.checkPrivateReady('antigravity', agController.signal);
            if (this.stopped || agController.signal.aborted) {
              if (tryContinueSupersededAgProbe()) continue;
              break;
            }
            if (!bindRes.ok) {
              if (!agRetriedBinding && this.isCurrentAntigravityProbe(seqAtStart, curCfg)) {
                const recovered = await this.privateProxies.channels.antigravity.recoverListenerIfNeeded(
                  agController.signal
                );
                if (this.stopped || agController.signal.aborted) {
                  if (tryContinueSupersededAgProbe()) continue;
                  break;
                }
                if (recovered !== 'failed' && this.isCurrentAntigravityProbe(seqAtStart, curCfg)) {
                  agRetriedBinding = true;
                  continue;
                }
              }
              if (!this.isCurrentAntigravityProbe(seqAtStart, curCfg)) {
                if (tryContinueSupersededAgProbe()) continue;
                break;
              }
              this.antigravityNodeProbe = null;
              this.antigravityNodeProbeError =
                this.privateProxies.channels.antigravity.getState().error ||
                bindRes.error ||
                `专属端口 127.0.0.1:${curCfg.antigravityDedicatedPort} 未就绪`;
              if (this.antigravityPendingReprobe && this.configStore.get().antigravityClashNode) {
                agRetriedBinding = false;
                agReboundContinueCount = 0;
                continue;
              }
              break;
            }

            if (!this.isCurrentAntigravityProbe(seqAtStart, curCfg)) {
              if (tryContinueSupersededAgProbe()) continue;
              break;
            }

            this.antigravityReboundDuringProbe = false;
            const firstPass = await this.probeOnceViaChannel(proxyUrl, channelDesc, 7500, '探测超时', {
              includeCustom: false,
              transportHosts: this.privateProxies.channels.antigravity.getBoundTransportHosts(),
              signal: agController.signal,
            });
            if (this.stopped || agController.signal.aborted) {
              if (tryContinueSupersededAgProbe()) continue;
              break;
            }
            if (
              firstPass.localProxyRefused &&
              !agRetriedBinding &&
              this.isCurrentAntigravityProbe(seqAtStart, curCfg)
            ) {
              const recovered = await this.privateProxies.channels.antigravity.recoverListenerIfNeeded(
                agController.signal
              );
              if (this.stopped || agController.signal.aborted) {
                if (tryContinueSupersededAgProbe()) continue;
                break;
              }
              if (recovered !== 'failed' && this.isCurrentAntigravityProbe(seqAtStart, curCfg)) {
                agRetriedBinding = true;
                continue;
              }
            }
            probeSuccess = firstPass.result;
            lastErrMsg = firstPass.errMsg;

            if (probeSuccess && this.isCurrentAntigravityProbe(seqAtStart, curCfg)) {
              this.privateProxies.channels.antigravity.clearForwardingError();
              await this.verifyAntigravityGoogleRegion(proxyUrl, probeSuccess, agController.signal);
              if (this.stopped || agController.signal.aborted) {
                if (tryContinueSupersededAgProbe()) continue;
                break;
              }
            }
          } finally {
            if (this.antigravityProbeAbortController === agController) {
              this.antigravityProbeAbortController = null;
            }
            agController.abort();
          }

          if (!this.isCurrentAntigravityProbe(seqAtStart, curCfg)) {
            if (tryContinueSupersededAgProbe()) continue;
            break;
          }

          if (
            this.antigravityReboundDuringProbe &&
            agReboundContinueCount < MAX_IN_FLIGHT_REBOUND_CONTINUES &&
            (!probeSuccess || !isValidIsoCountryCode(probeSuccess.googleCountryCode))
          ) {
            agReboundContinueCount++;
            continue;
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
            agRetriedBinding = false;
            agReboundContinueCount = 0;
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

    p = runProbe();
    this.antigravityProbePromise = p;
    return p;
  }

  private async ensurePrivateChannelReadyForLaunch(
    channel: PrivateChannelId
  ): Promise<{ ok: boolean; error?: string }> {
    if (channel === 'claude') {
      const cfg = this.configStore.get();
      const kernel = this.privateProxies.channels.claude;
      if (
        cfg.selectedClashNode &&
        kernel.getSnapshot() &&
        kernel.getIpv4Only() !== cfg.claudeForceIpv4
      ) {
        const migrated = await this.bindPrivateSelection(
          'claude',
          cfg.selectedClashNode,
          cfg.dedicatedProxyPort,
          cfg.selectedClashProfileUid,
          false,
          cfg.claudeForceIpv4,
          true
        );
        if (!migrated.ok) {
          return migrated;
        }
      }
    }
    let bindRes = await this.checkPrivateReady(channel);
    if (!bindRes.ok || this.privateProxies.channels[channel].getState().verificationError) {
      const recovered = await this.privateProxies.channels[channel].recoverListenerIfNeeded();
      if (recovered !== 'failed') {
        bindRes = await this.checkPrivateReady(channel);
      }
    }
    return bindRes;
  }

  /**
   * 通过指定专属代理节点启动（或重启）Antigravity：
   * 1. 确认 Antigravity 私有内核及专属端口已经就绪
   * 2. 若已有运行中的 Antigravity.exe / language_server.exe，先关闭旧实例以释放单实例锁
   * 3. 注入 --proxy-server 与 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / GRPC_PROXY / NO_PROXY 拉起 Antigravity.exe
   */
  public async launchAntigravityFromGuard(): Promise<AntigravityLaunchResult> {
    return this.runApplicationChange(() => this.launchAntigravityInternal(), 'antigravity');
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

    const bindRes = await this.ensurePrivateChannelReadyForLaunch('antigravity');
    if (!bindRes.ok) {
      const msg = `无法建立节点 [${cfg.antigravityClashNode}] 的专属代理端口 (127.0.0.1:${
        cfg.antigravityDedicatedPort
      })：${bindRes.error || '端口未监听'}`;
      this.addLog('warn', msg);
      this.emitState();
      return { ok: false, message: msg, state: this.getSnapshot() };
    }
    const agKernelState = this.privateProxies.channels.antigravity.getState();
    if (agKernelState.verificationError) {
      const msg = `无法通过节点 [${cfg.antigravityClashNode}] 启动 Antigravity：${agKernelState.verificationError}`;
      this.addLog('warn', msg);
      this.emitState();
      return { ok: false, message: msg, state: this.getSnapshot() };
    }

    markAntigravityLaunchedByGuard(null);
    const killReport = await this.executeProcessKillSafely(ANTIGRAVITY_PROCESS_PATTERNS);
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

    const okMsg = `已通过专属节点 [${cfg.antigravityClashNode}] (127.0.0.1:${cfg.antigravityDedicatedPort}) 启动 Antigravity，并设置代理启动参数与环境变量`;
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

  /** 保存 Claude 节点副本，启动私有内核并检查真实出口。 */
  public async selectClashNode(
    nodeName: string | null,
    profileUid?: string | null
  ): Promise<AppStateSnapshot> {
    return this.runApplicationChange(async () => {
      await this.stopClaudeBeforeRoutingChange();
      return this.selectClashNodeInternal(nodeName, profileUid);
    }, 'claude');
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
    this.abortActiveClaudeProbe('切换 Claude 专属节点');
    this.lastClaudeProbeCompletedAt = 0;
    this.claudeNodeProbe = null;
    this.claudeNodeProbeError = null;

    if (cleanNode) {
      this.claudeSwitchingCount++;
      this.addLog(
        'info',
        `正在将 Claude 专属代理通道切换至 Clash 节点：[${cleanNode}] (127.0.0.1:${prevCfg.dedicatedProxyPort})...`
      );
      let bindRes: { ok: boolean; error?: string };
      try {
        bindRes = await this.bindPrivateSelection('claude',
          cleanNode,
          prevCfg.dedicatedProxyPort,
          effectiveProfileUid
        );
      } finally {
        this.claudeSwitchingCount--;
      }

      const cfg = this.configStore.get();
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
        await this.bindPrivateSelection('claude', null, prevCfg.dedicatedProxyPort, null);
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

  private hasConfirmedClaudeProbeViolation(probe: ProbeResult | null, curCfg: AppConfig): boolean {
    if (!probe) return false;
    if (isProbeRegionMismatched(probe)) return true;
    const hasSessionBaseline =
      this.claudeRunning || this.claudeAuthorizedSession || this.claudeSessionInitialIp !== null;
    const probeCheck = evaluateClaudeNodeProbeSafety(probe, {
      claudeRunning: hasSessionBaseline,
      claudeExternalBaselinePending: this.claudeExternalBaselinePending,
      claudeLockExitIp: curCfg.claudeLockExitIp,
      claudeForceIpv4: this.isEffectiveClaudeForceIpv4(curCfg),
      sessionInitialIp: this.claudeSessionInitialIp,
    });
    if (probeCheck && probeCheck.alertType !== 'verification-unavailable') {
      return true;
    }
    if (
      hasSessionBaseline &&
      isValidIsoCountryCode(probe.claudeTraceCountryCode) &&
      !isWindowsLocaleMatchingCountry(
        this.winLocale.timeZoneId,
        this.winLocale.regionCode,
        probe.claudeTraceCountryCode.toUpperCase()
      )
    ) {
      return true;
    }
    return false;
  }

  private async tryRecoverClaudeBindingAfterFailure(
    curCfg: AppConfig,
    seqAtStart: number,
    localProxyRefused: boolean,
    signal: AbortSignal
  ): Promise<boolean> {
    if (this.stopped || signal.aborted || !this.isCurrentClaudeProbe(seqAtStart, curCfg)) {
      return false;
    }
    const kernel = this.privateProxies.channels.claude;
    const kernelState = kernel.getState();
    const canAttemptPortRecovery =
      kernelState.phase === 'ready' || (kernelState.phase === 'error' && kernelState.pid !== null);
    if (
      !canAttemptPortRecovery ||
      kernelState.nodeName !== curCfg.selectedClashNode ||
      kernelState.port !== curCfg.dedicatedProxyPort ||
      kernelState.profileUid !== curCfg.selectedClashProfileUid
    ) {
      return false;
    }

    if (!localProxyRefused) {
      const ready = await this.checkPrivateReady('claude', signal);
      if (ready.ok) return false;
      if (this.stopped || signal.aborted || !this.isCurrentClaudeProbe(seqAtStart, curCfg)) {
        return false;
      }
    }
    const outcome = await kernel.recoverListenerIfNeeded(signal);
    if (outcome === 'failed') {
      return false;
    }
    return (
      !this.stopped &&
      !signal.aborted &&
      this.isCurrentClaudeProbe(seqAtStart, curCfg)
    );
  }

  /**
   * 独立探测 Claude 专栏选定节点的真实出口 IP 与国家（固定走 127.0.0.1:dedicatedProxyPort，与实时监控完全解耦）
   */
  public async probeClaudeNodeNow(
    reason = '检测 Claude 专属节点',
    skipSafetyEnforcement = false
  ): Promise<AppStateSnapshot> {
    if (this.stopped || this.claudeSwitchingCount > 0) return this.getSnapshot();
    const cfg = this.configStore.get();
    if (!cfg.selectedClashNode) {
      this.claudeProbeSeq++;
      this.abortActiveClaudeProbe('未选择 Claude 节点');
      this.lastClaudeProbeCompletedAt = 0;
      this.claudePendingProbe = null;
      this.claudeReboundDuringProbe = false;
      this.claudeNodeProbe = null;
      this.claudeNodeProbeError = null;
      this.clearClaudeHeartbeatTimer();
      this.emitState();
      return this.getSnapshot();
    }

    if (this.claudeProbePromise) {
      if (!skipSafetyEnforcement) {
        this.claudeActiveProbeSkipSafety = false;
      }
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
    this.claudeActiveProbeSkipSafety = skipSafetyEnforcement;

    let p: Promise<AppStateSnapshot> | null = null;
    const runProbe = async (): Promise<AppStateSnapshot> => {
      try {
        this.claudeIsProbing = true;
        this.emitState();

        let claudeReboundContinueCount = 0;
        let retriedBinding = false;
        while (!this.stopped) {
          if (this.claudeSwitchingCount > 0) break;
          const seqAtStart = ++this.claudeProbeSeq;
          const curCfg = this.configStore.get();
          const targetNode = curCfg.selectedClashNode;
          if (!targetNode) {
            this.claudeNodeProbe = null;
            this.claudeNodeProbeError = null;
            break;
          }

          const tryContinueNextClaudeProbe = (includeSupersededNode: boolean): boolean => {
            if (this.stopped) return false;
            const latestSelectedNode = this.configStore.get().selectedClashNode;
            if (this.claudePendingProbe && latestSelectedNode) {
              const next = this.claudePendingProbe;
              this.claudePendingProbe = null;
              activeReason = next.reason;
              this.claudeActiveProbeSkipSafety =
                this.claudeActiveProbeSkipSafety && next.skipSafetyEnforcement;
              retriedBinding = false;
              claudeReboundContinueCount = 0;
              return true;
            }
            if (this.claudePendingProbe && !latestSelectedNode) {
              this.claudePendingProbe = null;
            }
            if (includeSupersededNode) {
              if (latestSelectedNode) {
                if (this.privateProxies.channels.claude.getState().phase !== 'ready') {
                  return false;
                }
                retriedBinding = false;
                claudeReboundContinueCount = 0;
                return true;
              }
              this.claudeNodeProbe = null;
              this.claudeNodeProbeError = null;
            }
            return false;
          };

          const settleIterationSafetyBeforeLoopControl = (): 'must-break' | 'ok' => {
            if (
              this.claudeActiveProbeSkipSafety ||
              !this.claudeRunning ||
              this.claudeSafetyKillPromise ||
              this.stopped ||
              !this.isCurrentClaudeProbe(seqAtStart, curCfg)
            ) {
              return 'ok';
            }
            const requireDedicated =
              this.claudeAuthorizedSession || this.configStore.get().claudeExclusiveGuard;
            const check = this.evaluateClaudeSafety(requireDedicated);
            if (check.safe) {
              this.clearClaudeVerificationFailureIfRecovered();
              return 'ok';
            }
            if (check.alertType === 'verification-unavailable') {
              this.recordClaudeVerificationFailure(check.reason);
              return 'ok';
            }
            // 实测已确认触发立即熔断（ip-change / mismatch / locale-mismatch / disconnect）：
            // 立即终止循环并执行 0 秒强杀，禁止被排队中的 claudePendingProbe 延迟或覆盖
            this.claudePendingProbe = null;
            return 'must-break';
          };

          const controller = new AbortController();
          this.claudeProbeAbortController = controller;
          let probeSuccess: ProbeResult | null = null;
          let lastErrMsg = '探测超时';
          let localProxyRefused = false;
          let effectiveProfileUid: string | null = null;
          let label = targetNode;
          let channelDesc = '';
          let bindFailed = false;
          let bindError: string | undefined;

          try {
            const bindRes = await this.checkPrivateReady('claude', controller.signal);
            if (this.stopped || controller.signal.aborted) {
              if (tryContinueNextClaudeProbe(!this.isCurrentClaudeProbe(seqAtStart, curCfg))) {
                continue;
              }
              break;
            }
            if (!bindRes.ok) {
              if (
                !retriedBinding &&
                (await this.tryRecoverClaudeBindingAfterFailure(
                  curCfg,
                  seqAtStart,
                  true,
                  controller.signal
                ))
              ) {
                retriedBinding = true;
                continue;
              }
              if (this.stopped || controller.signal.aborted) {
                if (tryContinueNextClaudeProbe(!this.isCurrentClaudeProbe(seqAtStart, curCfg))) {
                  continue;
                }
                break;
              }
              bindFailed = true;
              bindError = this.privateProxies.channels.claude.getState().error || bindRes.error;
            } else {
              if (!this.isCurrentClaudeProbe(seqAtStart, curCfg)) {
                if (tryContinueNextClaudeProbe(true)) continue;
                break;
              }

              this.claudeReboundDuringProbe = false;
              effectiveProfileUid = curCfg.selectedClashProfileUid;
              label = curCfg.selectedClashProfileName
                ? `${curCfg.selectedClashProfileName} / ${targetNode}`
                : targetNode;
              const proxyUrl = `http://127.0.0.1:${curCfg.dedicatedProxyPort}`;
              channelDesc = `Claude 专属节点 [${label}] (127.0.0.1:${curCfg.dedicatedProxyPort}${
                this.privateProxies.channels.claude.getIpv4Only() ? ' · 仅IPv4' : ''
              })`;

              const activeEndpoints = selectProbeEndpointsForTransportHosts(
                BUILTIN_TRACE_ENDPOINTS,
                this.privateProxies.channels.claude.getBoundTransportHosts()
              );
              const consensus = await this.probeAndVerifyClaudeExitConsensus(
                proxyUrl,
                channelDesc,
                activeEndpoints,
                curCfg,
                controller.signal
              );
              if (this.stopped || controller.signal.aborted) {
                if (tryContinueNextClaudeProbe(!this.isCurrentClaudeProbe(seqAtStart, curCfg))) {
                  continue;
                }
                break;
              }
              probeSuccess = consensus.result;
              lastErrMsg = consensus.errMsg;
              localProxyRefused = consensus.localProxyRefused;

              const hasConfirmedViolationEarly = this.hasConfirmedClaudeProbeViolation(
                probeSuccess,
                curCfg
              );
              if (
                !hasConfirmedViolationEarly &&
                !retriedBinding &&
                (!probeSuccess || probeSuccess.claudeTraceError || localProxyRefused) &&
                (await this.tryRecoverClaudeBindingAfterFailure(
                  curCfg,
                  seqAtStart,
                  localProxyRefused,
                  controller.signal
                ))
              ) {
                retriedBinding = true;
                continue;
              }
              if (this.stopped || controller.signal.aborted) {
                if (tryContinueNextClaudeProbe(!this.isCurrentClaudeProbe(seqAtStart, curCfg))) {
                  continue;
                }
                break;
              }
            }
          } finally {
            if (this.claudeProbeAbortController === controller) {
              this.claudeProbeAbortController = null;
            }
            controller.abort();
          }

          if (this.stopped) break;

          if (bindFailed) {
            if (!this.isCurrentClaudeProbe(seqAtStart, curCfg)) {
              if (tryContinueNextClaudeProbe(true)) continue;
              break;
            }
            this.lastClaudeProbeCompletedAt = Date.now();
            this.claudeNodeProbe = null;
            this.claudeNodeProbeError =
              bindError ||
              `Claude 专属端口 127.0.0.1:${curCfg.dedicatedProxyPort} 未就绪`;
            if (settleIterationSafetyBeforeLoopControl() === 'must-break') {
              break;
            }
            if (tryContinueNextClaudeProbe(false)) continue;
            break;
          }

          const hasConfirmedViolation = this.hasConfirmedClaudeProbeViolation(probeSuccess, curCfg);
          const isHeartbeat = activeReason.includes('心跳');
          const isSilentPoll = isHeartbeat || activeReason.includes('后台复核');

          if (!this.isCurrentClaudeProbe(seqAtStart, curCfg)) {
            if (tryContinueNextClaudeProbe(true)) continue;
            break;
          }

          if (
            !hasConfirmedViolation &&
            this.claudeReboundDuringProbe &&
            claudeReboundContinueCount < MAX_IN_FLIGHT_REBOUND_CONTINUES &&
            (!probeSuccess ||
              !isValidIsoCountryCode(probeSuccess.claudeTraceLoc) ||
              !isValidIpAddress(probeSuccess.claudeTraceIp) ||
              Boolean(probeSuccess.claudeTraceError))
          ) {
            claudeReboundContinueCount++;
            if (
              claudeReboundContinueCount >= 2 &&
              !this.claudeActiveProbeSkipSafety &&
              this.claudeRunning &&
              !this.claudeSafetyKillPromise &&
              !this.stopped &&
              this.isCurrentClaudeProbe(seqAtStart, curCfg)
            ) {
              const reboundErrDetail = probeSuccess
                ? getTargetServiceVerificationError(probeSuccess, 'claude') || '目标服务校验未完成'
                : lastErrMsg;
              this.recordClaudeVerificationFailure(`${channelDesc}：${reboundErrDetail}`);
            }
            activeReason = 'Claude 专属代理端口恢复重测';
            continue;
          }

          this.lastClaudeProbeCompletedAt = Date.now();
          if (probeSuccess) {
            const prevIp =
              normalizeIpAddress(this.claudeNodeProbe?.claudeTraceIp) || this.claudeNodeProbe?.ip;
            const prevCountry = this.claudeNodeProbe?.countryCode;
            const previousVerificationError = getTargetServiceVerificationError(
              this.claudeNodeProbe,
              'claude'
            );
            const verificationError = getTargetServiceVerificationError(probeSuccess, 'claude');
            const normalizedTraceIp = normalizeIpAddress(probeSuccess.claudeTraceIp);
            if (normalizedTraceIp) {
              probeSuccess.claudeTraceIp = normalizedTraceIp;
            }
            this.claudeNodeProbe = probeSuccess;
            this.claudeNodeProbeError = null;
            if (!verificationError) {
              this.privateProxies.channels.claude.clearForwardingError();
            }
            const unexpectedIpv6Violation = Boolean(
              this.isEffectiveClaudeForceIpv4(curCfg) &&
                normalizedTraceIp &&
                net.isIPv6(normalizedTraceIp)
            );
            if (
              !verificationError &&
              !unexpectedIpv6Violation &&
              !this.privateProxies.channels.claude.getState().verificationError
            ) {
              this.claudeLastVerificationSuccessAt =
                probeSuccess.claudeTraceCheckedAt || probeSuccess.checkedAt;
              this.claudeLastVerifiedRegion = {
                node: targetNode,
                profileUid: effectiveProfileUid,
                port: curCfg.dedicatedProxyPort,
                countryCode: probeSuccess.countryCode,
                countryName: probeSuccess.countryName,
              };
              const canRecordSessionBaseline = this.claudeAuthorizedSession
                ? true
                : !curCfg.claudeExclusiveGuard &&
                  this.claudeExternalBaselinePending &&
                  seqAtStart >= this.claudeExternalBaselineMinSeq;
              if (
                this.claudeRunning &&
                this.claudeSessionInitialIp === null &&
                canRecordSessionBaseline &&
                normalizedTraceIp &&
                isWindowsLocaleMatchingCountry(
                  this.winLocale.timeZoneId,
                  this.winLocale.regionCode,
                  probeSuccess.countryCode
                )
              ) {
                this.claudeSessionInitialIp = normalizedTraceIp;
                this.claudeExternalBaselinePending = false;
                this.claudeExternalBaselineMinSeq = 0;
                this.addLog(
                  'info',
                  `已记录运行中 Claude 会话初始出口 IP 基线：${this.claudeSessionInitialIp} (${probeSuccess.countryName} ${probeSuccess.countryCode})`
                );
              }
            }

            const normalizedLockedIp = normalizeIpAddress(this.claudeSessionInitialIp);
            const effectiveTraceIp = normalizedTraceIp || probeSuccess.ip;
            const willTriggerIpDriftKill = Boolean(
              !this.claudeActiveProbeSkipSafety &&
                this.claudeRunning &&
                (unexpectedIpv6Violation ||
                  (!this.claudeExternalBaselinePending &&
                    curCfg.claudeLockExitIp &&
                    normalizedLockedIp &&
                    normalizedTraceIp &&
                    normalizedTraceIp !== normalizedLockedIp))
            );

            if (verificationError) {
              if (!this.claudeRunning && (previousVerificationError !== verificationError || !isSilentPoll)) {
                this.addLog(
                  'danger',
                  `Claude 目标服务地区校验未通过 [${label}]：${verificationError}`
                );
              }
            } else if (
              !willTriggerIpDriftKill &&
              (prevIp !== effectiveTraceIp ||
                prevCountry !== probeSuccess.countryCode ||
                !isSilentPoll)
            ) {
              const verifiedTag =
                probeSuccess.claudeTraceLoc
                  ? ' · 目标服务地区校验通过'
                  : '';
              const splitExitTag =
                probeSuccess.claudeTraceIp && probeSuccess.claudeTraceIp !== probeSuccess.ip
                  ? ` (常规回显: ${probeSuccess.ip})`
                  : '';
              this.addLog(
                'info',
                `Claude 节点检测 [${label}]：${probeSuccess.countryName} (${probeSuccess.countryCode})${verifiedTag} · Claude 出口 IP: ${effectiveTraceIp}${splitExitTag} (${probeSuccess.latencyMs}ms)`
              );
            }
          } else {
            this.claudeNodeProbe = null;
            this.claudeNodeProbeError = `${channelDesc}：${lastErrMsg}`;
            if (!this.claudeRunning) {
              this.addLog('warn', `Claude 节点检测失败：${this.claudeNodeProbeError}`);
            }
          }

          if (settleIterationSafetyBeforeLoopControl() === 'must-break') {
            break;
          }

          if (tryContinueNextClaudeProbe(false)) continue;
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
      if (!this.claudeActiveProbeSkipSafety && this.claudeRunning) {
        await this.enforceClaudeRunningSafety(activeReason);
      }
      this.syncClaudeHeartbeatSchedule();

      return this.getSnapshot();
    };

    p = runProbe();
    this.claudeProbePromise = p;
    return p;
  }

  /**
   * Claude 唯一安全启动入口：
   * 启动前实时强校验：[Claude 选定节点真实出口地区] == [Windows 系统区域] == [Windows 系统时区]
   */
  public async launchClaudeFromGuard(): Promise<ClaudeLaunchResult> {
    return this.runApplicationChange(() => this.launchClaudeInternal(), 'claude');
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
    const killReport = await this.stopClaudeBeforeRoutingChange(true);

    // 2. 若已选择节点，确保专属端口绑定就绪
    if (cfg.selectedClashNode) {
      const bindRes = await this.ensurePrivateChannelReadyForLaunch('claude');
      if (!bindRes.ok) {
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
    const initialClaudeIp = normalizeIpAddress(this.claudeNodeProbe?.claudeTraceIp);
    if (
      !prelaunchState.canLaunch ||
      !install.exePath ||
      !prelaunchState.proxyCountryCode ||
      !initialClaudeIp
    ) {
      const msg = `启动被拦截：${prelaunchState.launchBlockReason || '未获取到有效 Claude 出口 IP'}`;
      this.addLog('danger', msg);
      this.emitState();
      return { ok: false, message: msg, state: this.getSnapshot() };
    }

    const proxyCountry = prelaunchState.proxyCountryCode;
    const proxyCountryName = prelaunchState.proxyCountryName || getCountryNameZh(proxyCountry);

    // 授权前再次检查全部关联进程，包含可能被外部服务重新启动的后台进程。
    await assertProcessesStopped(CLAUDE_DESKTOP_PROCESS_PATTERNS, killReport);

    // 6. 授予唯一入口会话锁、锁定初始会话出口 IP 并注入专属代理参数拉起 Claude
    this.claudeAuthorizedSession = true;
    this.claudeSessionInitialIp = initialClaudeIp;
    this.claudeExternalBaselinePending = false;
    this.claudeExternalBaselineMinSeq = 0;
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
    this.syncClaudeHeartbeatSchedule();

    const fullNodeLabel = cfg.selectedClashProfileName
      ? `${cfg.selectedClashProfileName} / ${cfg.selectedClashNode}`
      : cfg.selectedClashNode;
    const ipLockTag = cfg.claudeLockExitIp
      ? `锁定出口 IP ${initialClaudeIp}`
      : `初始出口 IP ${initialClaudeIp}`;
    const ipv4Tag = cfg.claudeForceIpv4 ? ' · 仅IPv4' : '';
    const okMsg = `三重校验通过！已通过专属节点 [${fullNodeLabel}] (127.0.0.1:${cfg.dedicatedProxyPort}${ipv4Tag} · ${proxyCountryName} · ${ipLockTag}) 安全启动 Claude`;
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
    this.claudeVerificationRecovery.clear();

    const report = await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
    if (!this.claudeRunning) {
      this.unsetClaudeAuthLock();
    }

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
    this.claudeSessionInitialIp = null;
    this.claudeExternalBaselinePending = false;
    this.claudeExternalBaselineMinSeq = 0;
    this.claudeSeenRunningSinceAuth = false;
    this.claudeLaunchGraceUntil = 0;
    markClaudeLaunchedByGuard(null);
    this.claudeFastCheckTicks = 0;
    this.syncClaudeHeartbeatSchedule();
  }

  private async runApplicationChange<T>(operation: () => Promise<T>, channel: PrivateChannelId | 'global' = 'global'): Promise<T> {
    if (this.applicationChanges.has('global') || this.applicationChanges.has(channel) || (channel === 'global' && this.applicationChanges.size > 0)) {
      throw new Error('应用启动或代理配置操作正在进行，请等待完成');
    }
    this.applicationChanges.add(channel);
    try {
      return await operation();
    } finally {
      this.applicationChanges.delete(channel);
    }
  }

  private async stopClaudeBeforeRoutingChange(forceTerminate = false): Promise<ProcessKillReport> {
    this.claudeVerificationRecovery.clear();
    this.abortActiveClaudeProbe('调整 Claude 专属代理配置');
    const shouldTerminateClaude =
      forceTerminate ||
      this.started ||
      this.claudeRunning ||
      this.claudeAuthorizedSession ||
      this.configStore.get().claudeExclusiveGuard;
    const report: ProcessKillReport = shouldTerminateClaude
      ? await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS)
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
    this.unsetClaudeAuthLock();
    this.claudeLastVerificationSuccessAt = null;
    this.claudeLastVerifiedRegion = null;
    this.lastClaudeProbeCompletedAt = 0;
    if (report.killedCount > 0) {
      this.addLog('info', `调整 Claude 专属代理前已终止关联进程：${report.killedSummary.join(', ')}`);
    }
    return report;
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

      // 仅在确实需要重建 Claude 通道时检查并停止关联进程；纯 IPv4 开关切换且未显式确认时，
      // 在主进程实时核验是否有运行中的 Claude 会话，绝不未经确认终止进程。
      if (needsClaudeChannelRebuild) {
        if (claudeIpv4Changed && !claudeNodeOrPortChanged && !options?.confirmTerminateClaude) {
          if (this.started) {
            const liveProc = await countRunningClaudeProcesses(true);
            this.claudeRunning = liveProc.running;
            this.claudeProcessCount = liveProc.count;
            this.claudeRunningPids = liveProc.pids;
          }
          if (this.claudeRunning || this.claudeAuthorizedSession) {
            this.emitState();
            throw new Error(
              'CLAUDE_RUNNING_CONFIRM_REQUIRED:检测到正在运行的 Claude 会话，切换 IPv4 出站模式将终止并重建代理通道，请先确认'
            );
          }
          // 实时核验当前无运行中的 Claude：仅重置校验状态，不向宿主机发出无确认的进程终止指令
          this.claudeVerificationRecovery.clear();
          this.abortActiveClaudeProbe('调整 Claude 专属代理配置');
          this.unsetClaudeAuthLock();
          this.claudeLastVerificationSuccessAt = null;
          this.claudeLastVerifiedRegion = null;
          this.lastClaudeProbeCompletedAt = 0;
        } else {
          await this.stopClaudeBeforeRoutingChange();
        }
      }

      // 切换 Claude 强制 IPv4 开关且已绑定节点时，必须先完成私有内核重建（不触碰外部 Clash 控制接口），
      // 成功后再持久化配置文件；若配置文件落盘失败则立即回滚私有内核至原模式，确保配置与监听原子一致。
      const rebuiltClaudeForIpv4 = Boolean(claudeIpv4Changed && requested.selectedClashNode);
      if (rebuiltClaudeForIpv4) {
        this.claudeProbeSeq++;
        this.abortActiveClaudeProbe('切换 Claude 通道 IPv4 出站模式');
        this.lastClaudeProbeCompletedAt = 0;
        this.claudeNodeProbe = null;
        this.claudeNodeProbeError = null;
        this.claudeSwitchingCount++;
        let bindRes: { ok: boolean; error?: string };
        try {
          bindRes = await this.bindPrivateSelection(
            'claude',
            requested.selectedClashNode,
            requested.dedicatedProxyPort,
            requested.selectedClashProfileUid,
            false,
            requested.claudeForceIpv4,
            !claudeNodeOrPortChanged,
            false
          );
        } finally {
          this.claudeSwitchingCount--;
        }
        if (!bindRes.ok) {
          // 私有内核重建失败时保持先前已生效的 claudeForceIpv4，绝不提交未生效配置
          const errText = bindRes.error || '切换 Claude 通道 IPv4 出站模式失败';
          this.claudeNodeProbeError = errText;
          this.addLog('danger', errText);
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
          this.claudeSwitchingCount++;
          try {
            if (previous.selectedClashNode) {
              await this.bindPrivateSelection(
                'claude',
                previous.selectedClashNode,
                previous.dedicatedProxyPort,
                previous.selectedClashProfileUid,
                false,
                previous.claudeForceIpv4,
                true,
                false
              );
            } else {
              await this.privateProxies.channels.claude
                .select(null, previous.dedicatedProxyPort)
                .catch(() => undefined);
            }
          } finally {
            this.claudeSwitchingCount--;
          }
          const detail = saveError instanceof Error ? saveError.message : String(saveError);
          const errText = `保存配置文件失败，已撤销 Claude IPv4 模式切换：${detail}`;
          this.claudeNodeProbeError = errText;
          this.addLog('danger', errText);
          this.emitState();
        }
        throw saveError;
      }
      if (previous.heartbeatIntervalSec !== next.heartbeatIntervalSec && this.started) {
        this.restartHeartbeatTimer();
      }
      if (claudeChanged) {
        if (claudeIpv4Changed && !next.selectedClashNode) {
          if (claudeNodeOrPortChanged) {
            await this.selectClashNodeInternal(null, null);
          }
          this.addLog(
            'info',
            next.claudeForceIpv4
              ? '已开启 Claude 通道强制仅走 IPv4 出站'
              : '已关闭 Claude 通道强制仅走 IPv4 出站（允许双栈/IPv6 节点）'
          );
          this.emitState();
        } else if (claudeIpv4Changed && next.selectedClashNode) {
          this.addLog(
            'success',
            next.claudeForceIpv4
              ? `已开启 Claude 通道强制仅走 IPv4 出站 (127.0.0.1:${next.dedicatedProxyPort})`
              : `已关闭 Claude 通道强制仅走 IPv4 出站，允许双栈/IPv6 出站 (127.0.0.1:${next.dedicatedProxyPort})`
          );
          this.emitState();
          await this.probeClaudeNodeNow(
            next.claudeForceIpv4 ? '开启 Claude 仅 IPv4 出站' : '关闭 Claude 仅 IPv4 出站'
          );
        } else {
          await this.selectClashNodeInternal(next.selectedClashNode, next.selectedClashProfileUid);
        }
      } else if (previous.claudeLockExitIp !== next.claudeLockExitIp) {
        this.addLog(
          'info',
          next.claudeLockExitIp
            ? '已开启 Claude 会话出口 IP 锁定（运行期出口 IP 变更将立即强杀保护）'
            : '已关闭 Claude 会话出口 IP 锁定（仍保留地区与系统时区一致性保护）'
        );
        this.emitState();
        if (next.claudeLockExitIp && this.claudeRunning) {
          const killed = await this.enforceClaudeRunningSafety('开启 Claude 会话出口 IP 锁定');
          if (!killed && this.claudeRunning && next.selectedClashNode && !this.claudeIsProbing) {
            void this.probeClaudeNodeNow('开启 Claude 会话出口 IP 锁定实时复核');
          }
        }
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
   * 3. 地区、系统环境或代理绑定冲突立即终止；请求失败时持续进行后台复核。
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
          } else if (
            !this.claudeAuthorizedSession &&
            Date.now() > this.claudeLaunchGraceUntil &&
            (this.claudeSessionInitialIp !== null || this.claudeExternalBaselinePending)
          ) {
            this.claudeSessionInitialIp = null;
            this.claudeExternalBaselinePending = false;
            this.claudeExternalBaselineMinSeq = 0;
            this.emitState();
          }

          const cfg = this.configStore.get();

          // 拦截 1：开启唯一启动入口拦截时，未通过卫士专栏授权启动的外部 Claude -> 立即无条件强杀！
          if (proc.running && !this.claudeAuthorizedSession && cfg.claudeExclusiveGuard) {
            const report = await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
            if (!this.claudeRunning) {
              this.unsetClaudeAuthLock();
            }
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

          // 若关闭了唯一入口拦截且检测到外部拉起的 Claude 尚未建立会话出口 IP 基线，立即发起实时重测（不复用启动前旧缓存）
          this.ensureExternalClaudeBaselineProbe(cfg);

          // 运行期安全检查独立于唯一启动入口设置。
          if (proc.running) {
            const killedOrBlocked = await this.enforceClaudeRunningSafety('Claude 运行期实时监控');
            if (killedOrBlocked) {
              scheduleNext(1500);
              return;
            }
          } else if (
            cfg.selectedClashNode &&
            this.privateProxies.channels.claude.getSnapshot() &&
            this.privateProxies.channels.claude.getIpv4Only() !== cfg.claudeForceIpv4 &&
            this.applicationChanges.size === 0
          ) {
            void this.migrateDeferredClaudeIpv4IfIdle();
          }

          if (prevRunning !== this.claudeRunning || prevCount !== this.claudeProcessCount) {
            if (prevRunning !== this.claudeRunning) {
              this.syncClaudeHeartbeatSchedule();
            }
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

  private ensureExternalClaudeBaselineProbe(cfg: AppConfig = this.configStore.get()): void {
    if (
      this.claudeRunning &&
      !this.claudeAuthorizedSession &&
      !cfg.claudeExclusiveGuard &&
      this.claudeSessionInitialIp === null &&
      cfg.selectedClashNode &&
      !this.claudeExternalBaselinePending
    ) {
      this.claudeExternalBaselinePending = true;
      this.claudeExternalBaselineMinSeq = this.claudeProbeSeq + 1;
      this.emitState();
      void this.probeClaudeNodeNow('检测到外部运行 Claude，建立会话出口 IP 基线');
    }
  }

  /**
   * 明确冲突立即终止；校验请求失败时持续进行后台复核，成功后清除异常状态。
   */
  private async enforceClaudeRunningSafety(triggerContext: string): Promise<boolean> {
    if (!this.started || !this.claudeRunning || this.stopped) {
      this.claudeVerificationRecovery.clear();
      return false;
    }
    if (this.claudeSafetyKillPromise) return this.claudeSafetyKillPromise;
    const cfg = this.configStore.get();
    this.ensureExternalClaudeBaselineProbe(cfg);
    const requireDedicatedNode =
      this.claudeAuthorizedSession || cfg.claudeExclusiveGuard;
    if (this.claudeIsProbing || this.claudeSwitchingCount > 0) {
      const localCheck = this.evaluateClaudeLocalSafety(requireDedicatedNode);
      if (localCheck) return this.terminateUnsafeClaude(localCheck, triggerContext);
      const kernel = this.privateProxies.channels.claude.getState();
      if (cfg.selectedClashNode && kernel.verificationError) {
        this.recordClaudeVerificationFailure(
          kernel.verificationError
        );
      }
      return false;
    }
    const check = this.evaluateClaudeSafety(requireDedicatedNode);
    if (check.safe) {
      let stateChanged = false;
      if (
        this.claudeRunning &&
        this.claudeAuthorizedSession &&
        this.claudeSessionInitialIp === null
      ) {
        const traceIp = normalizeIpAddress(this.claudeNodeProbe?.claudeTraceIp);
        if (traceIp) {
          this.claudeSessionInitialIp = traceIp;
          stateChanged = true;
        }
      }
      if (this.clearClaudeVerificationFailureIfRecovered()) {
        stateChanged = true;
      }
      if (stateChanged) {
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

  private clearClaudeVerificationFailureIfRecovered(): boolean {
    if (!this.claudeVerificationRecovery.clear()) return false;
    this.syncClaudeHeartbeatSchedule();
    this.addLog('success', 'Claude 地区校验已恢复，后台复核结束');
    return true;
  }

  private recordClaudeVerificationFailure(reason: string): void {
    this.clearClaudeHeartbeatTimer();
    const { shouldLog, stateChanged } = this.claudeVerificationRecovery.recordFailure(reason);
    if (shouldLog) {
      this.addLog('warn', `Claude 地区校验暂时不可用，正在后台复核：${reason}`);
    }
    if (shouldLog || stateChanged) {
      this.emitState();
    }
  }

  private terminateUnsafeClaude(check: ClaudeSafetyCheck, triggerContext: string): Promise<boolean> {
    if (this.claudeSafetyKillPromise) return this.claudeSafetyKillPromise;
    const operation = async () => {
      this.claudeVerificationRecovery.clear();

      const report = await this.executeProcessKillSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
      if (!this.claudeRunning) {
        this.unsetClaudeAuthLock();
      }
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
    this.claudeSafetyKillPromise = operation().finally(() => {
      this.claudeSafetyKillPromise = null;
    });
    return this.claudeSafetyKillPromise;
  }

  private getClaudeExpectedRegion(): { countryCode: string; countryName: string } | null {
    if (
      this.claudeNodeProbe &&
      isValidIsoCountryCode(this.claudeNodeProbe.countryCode) &&
      !getTargetServiceVerificationError(this.claudeNodeProbe, 'claude')
    ) {
      return this.claudeNodeProbe;
    }
    const cfg = this.configStore.get();
    const previous = this.claudeLastVerifiedRegion;
    if (
      previous &&
      previous.node === cfg.selectedClashNode &&
      previous.profileUid === cfg.selectedClashProfileUid &&
      previous.port === cfg.dedicatedProxyPort
    ) {
      return previous;
    }
    return this.claudeNodeProbe &&
      !this.claudeNodeProbe.claudeTraceError &&
      isValidIsoCountryCode(this.claudeNodeProbe.countryCode)
      ? this.claudeNodeProbe
      : null;
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

    const kernel = this.privateProxies.channels.claude.getState();
    if (cfg.selectedClashNode && (
      kernel.phase !== 'ready' ||
      kernel.nodeName !== cfg.selectedClashNode || kernel.port !== cfg.dedicatedProxyPort ||
      kernel.profileUid !== cfg.selectedClashProfileUid
    )) {
      const detailSuffix = kernel.error ? `：${kernel.error}` : '';
      return {
        safe: false,
        reason: `Claude 专属节点 [${cfg.selectedClashNode}] 代理绑定失效 (127.0.0.1:${cfg.dedicatedProxyPort})${detailSuffix}`,
        alertType: 'disconnect',
      };
    }

    const confirmedClaudeCountry =
      this.claudeNodeProbe &&
      !isProbeRegionMismatched(this.claudeNodeProbe) &&
      isValidIsoCountryCode(this.claudeNodeProbe.claudeTraceCountryCode)
        ? this.claudeNodeProbe.claudeTraceCountryCode.toUpperCase()
        : null;
    if (
      confirmedClaudeCountry &&
      !isWindowsLocaleMatchingCountry(
        this.winLocale.timeZoneId,
        this.winLocale.regionCode,
        confirmedClaudeCountry
      )
    ) {
      return {
        safe: false,
        reason: `Claude 实际出口地区 [${getCountryNameZh(confirmedClaudeCountry)} (${confirmedClaudeCountry})] 与系统时区/区域 [${this.winLocale.regionName} · ${this.winLocale.timeZoneDisplayName}] 不一致`,
        alertType: 'locale-mismatch',
      };
    }

    const probe = this.getClaudeExpectedRegion();
    if (
      !(isProbeRegionMismatched(this.claudeNodeProbe) && !this.claudeIsProbing) &&
      probe &&
      isValidIsoCountryCode(probe.countryCode) &&
      !isWindowsLocaleMatchingCountry(this.winLocale.timeZoneId, this.winLocale.regionCode, probe.countryCode)
    ) {
      return {
        safe: false,
        reason: `Claude 节点地区 [${probe.countryName} (${probe.countryCode})] 与系统时区/区域 [${this.winLocale.regionName} · ${this.winLocale.timeZoneDisplayName}] 不一致`,
        alertType: 'locale-mismatch',
      };
    }
    return null;
  }

  public evaluateClaudeSafety(requireDedicatedNode = true): ClaudeSafetyCheck {
    const localCheck = this.evaluateClaudeLocalSafety(requireDedicatedNode);
    if (localCheck) return localCheck;

    const cfg = this.configStore.get();
    const kernel = this.privateProxies.channels.claude.getState();

    if (this.claudeNodeProbe) {
      const probeCheck = evaluateClaudeNodeProbeSafety(this.claudeNodeProbe, {
        claudeRunning:
          this.claudeRunning || this.claudeAuthorizedSession || this.claudeSessionInitialIp !== null,
        claudeExternalBaselinePending: this.claudeExternalBaselinePending,
        claudeLockExitIp: cfg.claudeLockExitIp,
        claudeForceIpv4: this.isEffectiveClaudeForceIpv4(cfg),
        sessionInitialIp: this.claudeSessionInitialIp,
      });
      if (probeCheck) return probeCheck;
    }

    if (cfg.selectedClashNode && kernel.verificationError) {
      return {
        safe: false,
        reason: kernel.verificationError,
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

    const actualTraceIp = normalizeIpAddress(this.claudeNodeProbe.claudeTraceIp);
    if (!actualTraceIp) {
      return {
        safe: false,
        reason: '尚未获取到有效的 Claude 出口 IP',
        alertType: 'verification-unavailable',
      };
    }

    if (
      this.claudeRunning &&
      (this.claudeExternalBaselinePending ||
        (!this.claudeAuthorizedSession &&
          !cfg.claudeExclusiveGuard &&
          this.claudeSessionInitialIp === null))
    ) {
      return {
        safe: false,
        reason: '正在实时核验并锁定 Claude 会话初始出口 IP...',
        alertType: 'verification-unavailable',
      };
    }

    return {
      safe: true,
      reason: '',
      alertType: 'mismatch',
    };
  }

  private buildClaudeRuntimeState(): ClaudeRuntimeState {
    const cfg = this.configStore.get();
    const kernel = this.privateProxies.channels.claude.getState();
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
    const normalizedClaudeTraceIp = normalizeIpAddress(this.claudeNodeProbe?.claudeTraceIp);
    const unexpectedIpv6Exit = Boolean(
      cfg.claudeForceIpv4 && normalizedClaudeTraceIp && net.isIPv6(normalizedClaudeTraceIp)
    );
    const threeWayMatched = Boolean(
      proxyCountryCode &&
        !verificationError &&
        !unexpectedIpv6Exit &&
        winRegionMatched &&
        winTimeZoneMatched
    );

    let launchBlockReason: string | null = null;
    if (!this.claudeDetectedExe) {
      launchBlockReason = '未检测到客户端路径，请手动指定 Claude.exe';
    } else if (!cfg.selectedClashNode) {
      launchBlockReason = '请先选择代理节点';
    } else if (kernel.phase !== 'ready') {
      launchBlockReason = kernel.error || '私有代理内核未就绪';
    } else if (kernel.verificationError) {
      launchBlockReason = kernel.verificationError;
    } else if (this.claudeIsProbing && !this.claudeNodeProbe && !this.claudeNodeProbeError) {
      launchBlockReason = '正在校验节点出口与地区...';
    } else if (this.claudeNodeProbeError || !proxyCountryCode) {
      launchBlockReason = `出口探测异常：${
        this.claudeNodeProbeError || this.claudeNodeProbe?.claudeTraceError || '未获取到有效国家'
      }`;
    } else if (verificationError) {
      launchBlockReason = `地区校验未通过：${verificationError}`;
    } else if (unexpectedIpv6Exit) {
      launchBlockReason = `已开启强制仅走 IPv4 出站，但远端节点访问 Claude 仍返回 IPv6 (${normalizedClaudeTraceIp})，请更换节点或关闭该开关`;
    } else if (!winRegionMatched) {
      launchBlockReason = `系统区域（${this.winLocale.regionName}）与节点地区（${proxyCountryName}）不一致`;
    } else if (!winTimeZoneMatched) {
      launchBlockReason = `系统时区与节点地区（${proxyCountryName}）不一致`;
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
      lockedSessionIp:
        this.claudeRunning && cfg.claudeLockExitIp
          ? normalizeIpAddress(this.claudeSessionInitialIp)
          : null,
    };
  }

  private buildAntigravityRuntimeState(): AntigravityRuntimeState {
    const cfg = this.configStore.get();
    const kernel = this.privateProxies.channels.antigravity.getState();

    let launchHint: string | null = null;
    if (!this.antigravityDetectedExe) {
      launchHint = '未检测到 Antigravity.exe 安装路径，请在下方手动浏览指定';
    } else if (!cfg.antigravityClashNode) {
      launchHint = '请先在上方下拉框中选择要绑定的 Clash 代理节点';
    } else if (kernel.phase !== 'ready') {
      launchHint = kernel.error || 'Antigravity 私有内核尚未就绪';
    } else if (kernel.verificationError) {
      launchHint = kernel.verificationError;
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

  public setUpdateStateProvider(provider: () => UpdateStateSnapshot): void {
    this.updateStateProvider = provider;
  }

  public recordExternalLog(
    level: GuardEventLog['level'],
    message: string,
    broadcast = true
  ): void {
    this.addLog(level, message);
    if (broadcast) {
      this.emitState();
    }
  }

  public notifyExternalStateChanged(): void {
    this.emitState();
  }

  public async isClaudeActiveForUpdateInterlock(): Promise<boolean> {
    if (this.claudeRunning || this.claudeAuthorizedSession) {
      return true;
    }
    const live = await countRunningClaudeProcesses(true);
    if (live.running) {
      this.claudeRunning = true;
      this.claudeProcessCount = live.count;
      this.claudeRunningPids = live.pids;
      return true;
    }
    return false;
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

    const cfg = this.configStore.get();
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

    const clash = this.clashMonitor.getRuntimeInfo();
    const isClashGlobalDirect = clash.mode?.trim().toLowerCase() === 'direct';
    if (clash.connected && clash.mixedPort && !isClashGlobalDirect) {
      pushUnique(
        `http://127.0.0.1:${clash.mixedPort}`,
        `Clash 混合端口 (127.0.0.1:${clash.mixedPort})`
      );
    }
    for (const [channel, kernel] of Object.entries(this.privateProxies.getState())) {
      if (kernel.phase === 'ready' && kernel.port) pushUnique(`http://127.0.0.1:${kernel.port}`, `${channel} 私有代理端口`);
    }

    const sys = await this.getSystemProxyFresh(false);
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
      privateChannels: this.privateProxies.getState(),
      claudeState: this.buildClaudeRuntimeState(),
      antigravityState: this.buildAntigravityRuntimeState(),
      updateState: this.updateStateProvider
        ? this.updateStateProvider()
        : createFallbackUpdateStateSnapshot(),
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

  private getVerifiedClaudeProbeCountryCode(): string | null {
    if (
      !this.claudeNodeProbe ||
      !isValidIsoCountryCode(this.claudeNodeProbe.countryCode) ||
      getTargetServiceVerificationError(this.claudeNodeProbe, 'claude')
    ) {
      return null;
    }
    return this.claudeNodeProbe.countryCode.toUpperCase();
  }

  public shouldStopClaudeBeforeLocaleChange(
    targetCode: string,
    targetTimeZone: string
  ): boolean {
    if (isProbeRegionMismatched(this.claudeNodeProbe)) {
      return true;
    }
    const cfg = this.configStore.get();
    if (this.claudeNodeProbe) {
      const probeCheck = evaluateClaudeNodeProbeSafety(this.claudeNodeProbe, {
        claudeRunning:
          this.claudeRunning || this.claudeAuthorizedSession || this.claudeSessionInitialIp !== null,
        claudeExternalBaselinePending: this.claudeExternalBaselinePending,
        claudeLockExitIp: cfg.claudeLockExitIp,
        claudeForceIpv4: this.isEffectiveClaudeForceIpv4(cfg),
        sessionInitialIp: this.claudeSessionInitialIp,
      });
      if (probeCheck && probeCheck.alertType !== 'verification-unavailable') {
        return true;
      }
    }
    const verifiedClaudeCode = this.getVerifiedClaudeProbeCountryCode();
    const lastVerifiedClaudeCode =
      this.claudeLastVerifiedRegion &&
      this.claudeLastVerifiedRegion.node === cfg.selectedClashNode &&
      this.claudeLastVerifiedRegion.profileUid === cfg.selectedClashProfileUid &&
      this.claudeLastVerifiedRegion.port === cfg.dedicatedProxyPort &&
      isValidIsoCountryCode(this.claudeLastVerifiedRegion.countryCode)
        ? this.claudeLastVerifiedRegion.countryCode.toUpperCase()
        : null;
    const confirmedClaudeCode = verifiedClaudeCode || lastVerifiedClaudeCode;
    if (!confirmedClaudeCode) {
      return true;
    }
    const traceClaudeCode = isValidIsoCountryCode(this.claudeNodeProbe?.claudeTraceCountryCode)
      ? this.claudeNodeProbe!.claudeTraceCountryCode!.toUpperCase()
      : null;
    const claudeCodesToMatch = [confirmedClaudeCode, traceClaudeCode].filter(
      (code): code is string => Boolean(code)
    );
    return claudeCodesToMatch.some(
      (code) => !isWindowsLocaleMatchingCountry(targetTimeZone, targetCode, code)
    );
  }

  private async stopProcessesBeforeLocaleChange(
    targetCode: string,
    targetTimeZone: string
  ): Promise<ProcessKillReport> {
    const cfg = this.configStore.get();
    const stopClaude = this.shouldStopClaudeBeforeLocaleChange(targetCode, targetTimeZone);
    const stopProtected = cfg.killProcessesEnabled && cfg.killOnLocaleMismatch &&
      !isWindowsLocaleMatchingCountry(targetTimeZone, targetCode, this.getEffectiveTargetCountryCode());
    const patterns = [...new Set([
      ...(stopClaude ? CLAUDE_DESKTOP_PROCESS_PATTERNS : []),
      ...(stopProtected ? cfg.protectedProcessPatterns : []),
    ])];
    if (stopClaude) this.claudeVerificationRecovery.clear();
    const report = await this.executeProcessKillSafely(patterns);
    await assertProcessesStopped(patterns, report);
    if (stopClaude) this.unsetClaudeAuthLock();
    if (report.killedCount > 0) {
      this.addLog('info', `修改系统时区与区域前已终止关联进程：${report.killedSummary.join(', ')}`);
    }
    return report;
  }

  public resolveLocaleSyncTarget(
    targetSource: 'monitor' | 'claude' = 'monitor'
  ): { ok: true; targetCode: string; claudeCode: string | null } | { ok: false; message: string } {
    const cfg = this.configStore.get();
    const claudeCode = this.getVerifiedClaudeProbeCountryCode();
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
      const claudeVerifyError =
        targetSource === 'claude' && this.claudeNodeProbe
          ? getTargetServiceVerificationError(this.claudeNodeProbe, 'claude')
          : null;
      return {
        ok: false,
        message:
          targetSource === 'claude'
            ? claudeVerifyError
              ? `Claude 节点地区校验未通过，无法同步系统时区与区域：${claudeVerifyError}`
              : '请先在 Claude 专栏选择 Clash 节点并等待检测出有效出口地区'
            : '请先等待检测出有效出口地区，或先设置默认保护地区',
      };
    }

    if (!hasOfflineTimeZoneMapping(targetCode)) {
      return {
        ok: false,
        message: `尚未收录国家 ${targetCode} 的 Windows 时区映射，无法安全同步`,
      };
    }

    return { ok: true, targetCode, claudeCode };
  }

  private async syncSystemLocaleInternal(
    targetSource: 'monitor' | 'claude'
  ): Promise<Omit<LocaleSyncResult, 'state'>> {
    const cfg = this.configStore.get();
    const resolvedTarget = this.resolveLocaleSyncTarget(targetSource);
    if (!resolvedTarget.ok) {
      return {
        ok: false,
        message: resolvedTarget.message,
        killedProcesses: [],
      };
    }
    const { targetCode, claudeCode } = resolvedTarget;

    const killedProcesses: string[] = [];

    {
      let exactIanaTz: string | null = null;
      const needsCityTzLookup =
        isMultiTimeZoneCountry(targetCode) || !hasOfflineTimeZoneMapping(targetCode);

      if (needsCityTzLookup) {
        if (
          targetSource === 'claude' &&
          this.claudeNodeProbe &&
          claudeCode === targetCode
        ) {
          const claudeProxyUrl = `http://127.0.0.1:${cfg.dedicatedProxyPort}`;
          const claudeLookupIp =
            this.claudeNodeProbe.claudeTraceIp &&
            !this.claudeNodeProbe.claudeTraceIp.includes(':')
              ? this.claudeNodeProbe.claudeTraceIp
              : this.claudeNodeProbe.ip;
          exactIanaTz = await queryExactExitIanaTimeZone(
            claudeProxyUrl,
            targetCode,
            claudeLookupIp
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
          claudeCode === targetCode
        ) {
          const claudeProxyUrl = `http://127.0.0.1:${cfg.dedicatedProxyPort}`;
          const claudeLookupIp =
            this.claudeNodeProbe.claudeTraceIp &&
            !this.claudeNodeProbe.claudeTraceIp.includes(':')
              ? this.claudeNodeProbe.claudeTraceIp
              : this.claudeNodeProbe.ip;
          exactIanaTz = await queryExactExitIanaTimeZone(
            claudeProxyUrl,
            targetCode,
            claudeLookupIp
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
        this.claudeVerificationRecovery.clear();

        const killReport = await this.executeProcessKillSafely(combinedPatterns);
        if (!this.claudeRunning) {
          this.unsetClaudeAuthLock();
        }

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
        if (claudeNeedsKill) {
          this.unsetClaudeAuthLock();
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
    expectedIp?: string | null;
    actualIp?: string | null;
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

    const claudeSplitGeoCode =
      isClaudeSource && refProbe
        ? isValidIsoCountryCode(refProbe.claudeTraceCountryCode)
          ? refProbe.claudeTraceCountryCode.toUpperCase()
          : refProbe.regionMismatchDetail && refProbe.claudeTraceIp
          ? (() => {
              const g = this.geoIp.lookup(refProbe.claudeTraceIp);
              return isValidIsoCountryCode(g.countryCode) ? g.countryCode.toUpperCase() : null;
            })()
          : null
        : null;

    const { actualCode, actualName, actualIp } = resolveAlertActualMismatchFields({
      isClaudeSource,
      alertType: opts.alertType,
      expectedCode: opts.expectedCode,
      explicitActualIp: opts.actualIp,
      refProbe,
      claudeSplitGeoCode,
    });

    const payload: AlertPayload = {
      source: opts.source,
      alertType: opts.alertType,
      expectedCode: opts.expectedCode,
      expectedName: opts.expectedName,
      expectedIp: opts.expectedIp ?? null,
      actualCode,
      actualName,
      actualIp,
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
      source: 'monitor',
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

  private buildEndpointsList(
    includeCustom = true,
    transportHosts: readonly string[] = []
  ): TraceEndpoint[] {
    const list: TraceEndpoint[] = [];
    if (includeCustom) {
      const custom = this.configStore.get().customProbeUrl.trim();
      if (custom) {
        let domain = '';
        try {
          domain = new URL(custom).hostname.toLowerCase();
        } catch {
          domain = '';
        }
        list.push({
          name: '自定义探测源',
          url: custom,
          format: custom.includes('cdn-cgi/trace') ? 'cf-trace' : 'plain-ip',
          registrableDomain: domain,
        });
      }
    }
    list.push(...selectProbeEndpointsForTransportHosts(BUILTIN_TRACE_ENDPOINTS, transportHosts));
    return list;
  }

  private async probeOnceViaChannel(
    proxyUrl: string | null,
    viaChannel: string,
    timeoutMs: number,
    defaultErrMsg = '探测超时',
    options?: {
      includeCustom?: boolean;
      transportHosts?: readonly string[];
      signal?: AbortSignal;
    }
  ): Promise<{ result: ProbeResult | null; errMsg: string; localProxyRefused: boolean }> {
    const includeCustom = options?.includeCustom ?? true;
    const transportHosts = options?.transportHosts ?? [];
    const endpoints = this.buildEndpointsList(includeCustom, transportHosts);
    if (endpoints.length === 0) {
      return {
        result: null,
        errMsg: '常规探测源均与当前节点传输层域名重合，无法执行独立出口校验',
        localProxyRefused: false,
      };
    }
    const hasCustomFirst = includeCustom && Boolean(this.configStore.get().customProbeUrl.trim());
    const channelDeadlineAt = Date.now() + Math.max(timeoutMs, EXIT_PROBE_TIMEOUT_MS);
    const backupTimeoutMs = Math.min(timeoutMs, 3600);
    const controller = new AbortController();
    const outerSignal = options?.signal
      ? AbortSignal.any([options.signal, controller.signal])
      : controller.signal;
    let unknownRegion: ProbeResult | null = null;
    let errOut = defaultErrMsg;

    const probe = async (
      ep: TraceEndpoint,
      budgetMs: number,
      signal: AbortSignal
    ): Promise<ProbeResult> => {
      const startedAt = Date.now();
      const body = await requestTextViaProxy(ep.url, proxyUrl, budgetMs, undefined, undefined, false, signal);
      const parsed = parseTraceResponse(body, ep.format);
      if (!parsed.ip) throw new Error('响应中未解析到有效公网 IP');

      const checkedAt = Date.now();
      const result: ProbeResult = {
        ip: parsed.ip,
        ...this.geoIp.lookup(parsed.ip, parsed.loc),
        edgeLoc: parsed.loc,
        viaChannel,
        latencyMs: checkedAt - startedAt,
        checkedAt,
      };
      if (!isValidIsoCountryCode(result.countryCode)) {
        unknownRegion ??= result;
        throw new Error('尚未获取有效出口国家');
      }
      return result;
    };

    try {
      for (let index = 0; index < endpoints.length;) {
        if (outerSignal.aborted) break;
        const remainingMs = channelDeadlineAt - Date.now();
        const limitMs = index === 0 ? (hasCustomFirst ? Math.min(timeoutMs, 5500) : timeoutMs) : backupTimeoutMs;
        // 剩余时间只够完成一轮时，同时请求余下的来源。
        const batch = remainingMs <= limitMs + backupTimeoutMs
          ? endpoints.slice(index)
          : [endpoints[index]];
        const batchCtrl = new AbortController();
        const batchSignal = AbortSignal.any([outerSignal, batchCtrl.signal]);
        let batchLocalRefusedErr: string | null = null;
        try {
          const result = await Promise.any(
            batch.map((ep) =>
              probe(ep, Math.min(limitMs, remainingMs), batchSignal).catch((cause) => {
                if (isLocalProxyRefusedCause(cause, proxyUrl)) {
                  batchLocalRefusedErr ??= `${ep.url}：${formatNetworkErrorMessage(cause)}`;
                  batchCtrl.abort(cause);
                }
                throw cause;
              })
            )
          );
          if (batchLocalRefusedErr) {
            return { result: null, errMsg: batchLocalRefusedErr, localProxyRefused: true };
          }
          return { result, errMsg: '', localProxyRefused: false };
        } catch (error) {
          if (outerSignal.aborted) {
            return { result: null, errMsg: '探测已取消', localProxyRefused: false };
          }
          if (batchLocalRefusedErr) {
            return { result: null, errMsg: batchLocalRefusedErr, localProxyRefused: true };
          }
          if (!(error instanceof AggregateError)) throw error;
          for (const [offset, cause] of error.errors.entries()) {
            const reason = formatNetworkErrorMessage(cause);
            errOut = `${batch[offset].url}：${reason}`;
            if (isLocalProxyRefusedCause(cause, proxyUrl)) {
              return { result: null, errMsg: errOut, localProxyRefused: true };
            }
          }
        } finally {
          batchCtrl.abort();
        }
        index += batch.length;
      }
      return { result: unknownRegion, errMsg: unknownRegion ? '' : errOut, localProxyRefused: false };
    } finally {
      controller.abort();
    }
  }

  private async sampleClaudeGeneralEndpoint(
    endpoint: TraceEndpoint,
    proxyUrl: string,
    viaChannel: string,
    timeoutMs: number,
    signal: AbortSignal
  ): Promise<ProbeResult> {
    const start = Date.now();
    const raw = await requestTextViaProxy(
      endpoint.url,
      proxyUrl,
      timeoutMs,
      undefined,
      undefined,
      false,
      signal
    );
    const { ip, loc } = parseTraceResponse(raw, endpoint.format);
    if (!ip) throw new Error('响应中未解析到有效公网 IP');
    const geo = this.geoIp.lookupOfflineStrict(ip);
    const checkedAt = Date.now();
    return {
      ip,
      ...geo,
      edgeLoc: loc,
      viaChannel,
      latencyMs: checkedAt - start,
      checkedAt,
    };
  }

  private attachClaudeOutcomeToSample(
    baseSample: ProbeResult,
    claudeOutcome: Exclude<ClaudeSampleOutcome, { kind: 'refused' }>
  ): ProbeResult {
    const probe: ProbeResult = {
      ...baseSample,
      claudeTraceLoc: undefined,
      claudeTraceIp: undefined,
      claudeTraceCountryCode: undefined,
      claudeTraceError: undefined,
      claudeTraceCheckedAt: undefined,
      regionMismatchDetail: null,
    };

    if (claudeOutcome.kind === 'trace-error') {
      probe.claudeTraceLoc = claudeOutcome.claudeTraceLoc;
      probe.claudeTraceIp = claudeOutcome.claudeTraceIp;
      probe.claudeTraceCountryCode = claudeOutcome.claudeTraceCountryCode;
      probe.claudeTraceCheckedAt = claudeOutcome.claudeTraceCheckedAt;
      probe.claudeTraceError = claudeOutcome.claudeTraceError;
      return probe;
    }

    probe.claudeTraceLoc = claudeOutcome.loc;
    probe.claudeTraceIp = claudeOutcome.ip;
    probe.claudeTraceCountryCode = claudeOutcome.countryCode;
    probe.claudeTraceCheckedAt = claudeOutcome.checkedAt;

    const baseCode = probe.countryCode.toUpperCase();
    if (!isValidIsoCountryCode(baseCode)) {
      return probe;
    }

    if (claudeOutcome.loc !== baseCode) {
      const splitIpNote =
        claudeOutcome.ip && claudeOutcome.ip !== probe.ip
          ? `，且分流出口 IP 变为 ${claudeOutcome.ip}`
          : '';
      probe.regionMismatchDetail = `离线库为 ${probe.countryName} (${baseCode})，但访问 Claude 实际识别为 ${getCountryNameZh(
        claudeOutcome.loc
      )} (${claudeOutcome.loc})${splitIpNote}`;
    } else if (claudeOutcome.countryCode !== baseCode) {
      probe.regionMismatchDetail = `节点常规出口为 ${probe.countryName} (${baseCode})，但访问 Claude 的实际分流出口 IP (${claudeOutcome.ip}) 离线库归属为 ${claudeOutcome.countryName} (${claudeOutcome.countryCode})（跨国分流拦截）`;
    }

    return probe;
  }

  private async requestClaudeTraceOutcome(
    proxyUrl: string,
    signal: AbortSignal,
    timeoutMs = CLAUDE_TRACE_TIMEOUT_MS,
    doesConfirmViolation?: (outcome: Exclude<ClaudeSampleOutcome, { kind: 'refused' }>) => boolean
  ): Promise<{
    outcome: Exclude<ClaudeSampleOutcome, { kind: 'refused' }>;
    localRefusedError?: unknown;
  }> {
    const url = 'https://claude.ai/cdn-cgi/trace';
    const effectiveTimeoutMs = Math.max(1, Math.min(CLAUDE_TRACE_TIMEOUT_MS, timeoutMs));
    const startedAt = Date.now();
    const deadline = startedAt + effectiveTimeoutMs;
    const hedgeController = new AbortController();
    const requestSignal = AbortSignal.any([signal, hedgeController.signal]);
    const hedgeDelayController = new AbortController();
    const hedgeDelaySignal = AbortSignal.any([requestSignal, hedgeDelayController.signal]);
    let localRefusedError: unknown = null;
    let bestPartialOutcome: Extract<ClaudeSampleOutcome, { kind: 'trace-error' }> | null = null;
    let confirmedViolationOutcome: Exclude<ClaudeSampleOutcome, { kind: 'refused' }> | null = null;

    const recordPartialOutcome = (
      outcome: Extract<ClaudeSampleOutcome, { kind: 'trace-error' }>
    ): void => {
      if (!bestPartialOutcome) {
        bestPartialOutcome = outcome;
        return;
      }
      const score = (item: Extract<ClaudeSampleOutcome, { kind: 'trace-error' }>): number =>
        (item.claudeTraceIp ? 2 : 0) +
        (item.claudeTraceCountryCode ? 2 : 0) +
        (item.claudeTraceLoc ? 1 : 0);
      if (score(outcome) >= score(bestPartialOutcome)) {
        bestPartialOutcome = outcome;
      }
    };

    const interpretOrRejectBranch = (
      raw: string
    ): Exclude<ClaudeSampleOutcome, { kind: 'refused' }> => {
      const checkedAt = Date.now();
      const latencyMs = checkedAt - startedAt;
      const outcome = interpretClaudeTracePayload(
        raw,
        (ip) => this.geoIp.lookupOfflineStrict(ip),
        checkedAt,
        latencyMs
      );
      if (outcome.kind === 'ok') {
        if (doesConfirmViolation?.(outcome)) {
          confirmedViolationOutcome ??= outcome;
        }
        return outcome;
      }
      recordPartialOutcome(outcome);
      if (doesConfirmViolation?.(outcome)) {
        // 已确认运行期违规（如锁定 IP 漂移或离线归属国家不符）：立即返回并中止对冲，严禁被后续备用请求覆盖
        confirmedViolationOutcome ??= outcome;
        return outcome;
      }
      throw new Error(outcome.claudeTraceError);
    };

    const handleBranchError = (err: unknown): never => {
      if (isLocalProxyRefusedCause(err, proxyUrl)) {
        localRefusedError ??= err;
        hedgeController.abort(err);
      }
      throw err;
    };

    const primary = requestTextViaProxy(
      url,
      proxyUrl,
      effectiveTimeoutMs,
      undefined,
      undefined,
      false,
      requestSignal
    )
      .then((raw) => interpretOrRejectBranch(raw))
      .catch((err) => {
        hedgeDelayController.abort();
        return handleBranchError(err);
      });

    const hedged = (async () => {
      await sleep(CLAUDE_TRACE_HEDGE_DELAY_MS, undefined, { signal: hedgeDelaySignal }).catch(
        () => undefined
      );
      requestSignal.throwIfAborted();
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error('连接超时');
      const raw = await requestTextViaProxy(
        url,
        proxyUrl,
        remaining,
        undefined,
        undefined,
        false,
        requestSignal
      );
      return interpretOrRejectBranch(raw);
    })().catch(handleBranchError);

    try {
      const winningOutcome = await Promise.any([primary, hedged]);
      return {
        outcome: confirmedViolationOutcome ?? winningOutcome,
        ...(localRefusedError ? { localRefusedError } : {}),
      };
    } catch (error) {
      signal.throwIfAborted();
      const fallbackOutcome = confirmedViolationOutcome ?? bestPartialOutcome;
      if (fallbackOutcome) {
        return {
          outcome: fallbackOutcome,
          ...(localRefusedError ? { localRefusedError } : {}),
        };
      }
      if (localRefusedError) throw localRefusedError;
      if (error instanceof AggregateError) {
        const nonAbort = error.errors.filter(
          (item) => !(item instanceof Error && item.name === 'AbortError')
        );
        throw nonAbort[nonAbort.length - 1] ?? error.errors[0] ?? error;
      }
      throw error;
    } finally {
      hedgeDelayController.abort();
      hedgeController.abort();
    }
  }

  private async probeAndVerifyClaudeExitConsensus(
    proxyUrl: string,
    viaChannel: string,
    endpoints: readonly TraceEndpoint[],
    cfg: AppConfig,
    signal: AbortSignal
  ): Promise<{
    result: ProbeResult | null;
    errMsg: string;
    localProxyRefused: boolean;
  }> {
    const roundStartedAt = Date.now();
    const deadline = roundStartedAt + EXIT_PROBE_TIMEOUT_MS;
    const roundCtrl = new AbortController();
    const requestSignal = AbortSignal.any([signal, roundCtrl.signal]);

    const generalSamples: Array<{
      index: number;
      sample: ProbeResult;
    }> = [];
    const generalErrors: string[] = [];
    let settledGeneralCount = 0;
    let refused = false;
    let claudeOutcome = null as ClaudeSampleOutcome | null;

    const hasSessionBaseline =
      this.claudeRunning || this.claudeAuthorizedSession || this.claudeSessionInitialIp !== null;

    const isLockedIpDrifted = (ip: string | null | undefined): boolean => {
      if (!hasSessionBaseline || this.claudeExternalBaselinePending || !cfg.claudeLockExitIp) {
        return false;
      }
      const lockedIp = normalizeIpAddress(this.claudeSessionInitialIp);
      const currentIp = normalizeIpAddress(ip);
      return Boolean(lockedIp && currentIp && currentIp !== lockedIp);
    };

    const isClaudeCountryViolatingRunningSession = (
      countryCode: string | null | undefined
    ): boolean => {
      if (!hasSessionBaseline || !isValidIsoCountryCode(countryCode)) {
        return false;
      }
      return !isWindowsLocaleMatchingCountry(
        this.winLocale.timeZoneId,
        this.winLocale.regionCode,
        countryCode.toUpperCase()
      );
    };

    const isForcedIpv4Violated = (ip: string | null | undefined): boolean => {
      if (!this.isEffectiveClaudeForceIpv4(cfg)) return false;
      const currentIp = normalizeIpAddress(ip);
      return Boolean(currentIp && net.isIPv6(currentIp));
    };

    const isClaudeSelfViolatingRunningSession = (
      outcome: Extract<ClaudeSampleOutcome, { kind: 'ok' }>
    ): boolean => {
      if (!hasSessionBaseline) {
        return false;
      }
      if (isLockedIpDrifted(outcome.ip) || isForcedIpv4Violated(outcome.ip)) {
        return true;
      }
      return isClaudeCountryViolatingRunningSession(outcome.countryCode);
    };

    const doesClaudeOutcomeConfirmViolation = (
      outcome: ClaudeSampleOutcome | null
    ): boolean => {
      if (!outcome || outcome.kind === 'refused') return false;
      if (outcome.kind === 'trace-error') {
        return (
          isLockedIpDrifted(outcome.claudeTraceIp) ||
          (hasSessionBaseline && isForcedIpv4Violated(outcome.claudeTraceIp)) ||
          isClaudeCountryViolatingRunningSession(outcome.claudeTraceCountryCode)
        );
      }
      return outcome.loc !== outcome.countryCode || isClaudeSelfViolatingRunningSession(outcome);
    };

    const evaluateEarlyStop = (): void => {
      if (roundCtrl.signal.aborted) return;
      if (refused) {
        roundCtrl.abort();
        return;
      }
      if (!claudeOutcome) return;
      if (claudeOutcome.kind === 'refused') {
        roundCtrl.abort();
        return;
      }
      if (claudeOutcome.kind === 'trace-error') {
        if (doesClaudeOutcomeConfirmViolation(claudeOutcome) || generalSamples.length >= 1) {
          roundCtrl.abort();
        }
        return;
      }
      if (
        claudeOutcome.loc !== claudeOutcome.countryCode ||
        isClaudeSelfViolatingRunningSession(claudeOutcome)
      ) {
        roundCtrl.abort();
        return;
      }

      const target = claudeOutcome.countryCode;
      let matchCount = 0;
      let dissentCount = 0;
      for (const item of generalSamples) {
        if (item.sample.countryCode.toUpperCase() === target) {
          matchCount++;
        } else {
          dissentCount++;
        }
      }
      const pendingCount = endpoints.length - settledGeneralCount;
      if (dissentCount >= MIN_CONSENSUS_MATCHES) {
        roundCtrl.abort();
        return;
      }
      if (dissentCount + pendingCount <= 1 && matchCount >= MIN_CONSENSUS_MATCHES) {
        roundCtrl.abort();
      }
    };

    const runClaudeCheck = async (): Promise<void> => {
      try {
        try {
          const remaining = deadline - Date.now();
          if (remaining <= 0) throw new Error('探测超时');
          const traceResult = await this.requestClaudeTraceOutcome(
            proxyUrl,
            requestSignal,
            Math.min(CLAUDE_TRACE_TIMEOUT_MS, remaining),
            (outcome) => doesClaudeOutcomeConfirmViolation(outcome)
          );
          if (traceResult.localRefusedError) {
            refused = true;
            generalErrors.push(
              `本地代理端口连接被拒绝 (${formatNetworkErrorMessage(traceResult.localRefusedError)})`
            );
          }
          claudeOutcome = traceResult.outcome;
        } catch (err) {
          const detail = formatNetworkErrorMessage(err);
          if (isLocalProxyRefusedCause(err, proxyUrl)) {
            refused = true;
            generalErrors.push(`本地代理端口连接被拒绝 (${detail})`);
            claudeOutcome = { kind: 'refused' };
            return;
          }
          if (signal.aborted || roundCtrl.signal.aborted) return;
          claudeOutcome = {
            kind: 'trace-error',
            claudeTraceError: `https://claude.ai/cdn-cgi/trace：${detail}`,
          };
          return;
        }
      } finally {
        evaluateEarlyStop();
      }
    };

    // 与常规探测源并发启动 Claude trace，保证单轮总时长严格受 EXIT_PROBE_TIMEOUT_MS 约束，
    // 并在全部常规源均失败时仍能检测 Claude 出口 IP 漂移或地区违规。
    const claudePromise = runClaudeCheck();

    const generalTasks = endpoints.map(async (endpoint, index) => {
      const remaining = deadline - Date.now();
      try {
        if (remaining <= 0) throw new Error('探测超时');
        const budget = Math.min(GENERAL_SOURCE_TIMEOUT_MS, remaining);
        const sample = await this.sampleClaudeGeneralEndpoint(
          endpoint,
          proxyUrl,
          viaChannel,
          budget,
          requestSignal
        );
        generalSamples.push({
          index,
          sample,
        });
      } catch (error) {
        const detail = formatNetworkErrorMessage(error);
        if (isLocalProxyRefusedCause(error, proxyUrl)) {
          refused = true;
          generalErrors.push(`本地代理端口连接被拒绝 (${detail})`);
          return;
        }
        if (signal.aborted || roundCtrl.signal.aborted) return;
        generalErrors.push(`${endpoint.name}：${detail}`);
      } finally {
        settledGeneralCount++;
        evaluateEarlyStop();
      }
    });

    try {
      await Promise.allSettled([claudePromise, ...generalTasks]);
    } finally {
      roundCtrl.abort();
    }

    if (signal.aborted) {
      return { result: null, errMsg: '探测已取消', localProxyRefused: false };
    }

    if (refused && !doesClaudeOutcomeConfirmViolation(claudeOutcome)) {
      return {
        result: null,
        errMsg: generalErrors.join('；') || '本地代理端口连接被拒绝',
        localProxyRefused: true,
      };
    }

    if (generalSamples.length === 0) {
      const noGeneralEndpointsMsg =
        '常规探测源均与当前节点传输层域名重合，无法执行独立出口校验';
      const generalErrText =
        endpoints.length === 0 ? noGeneralEndpointsMsg : generalErrors.join('；') || '探测超时';
      if (claudeOutcome?.kind === 'ok') {
        const baseSample: ProbeResult = {
          ip: claudeOutcome.ip,
          countryCode:
            claudeOutcome.loc !== claudeOutcome.countryCode
              ? claudeOutcome.countryCode
              : 'UNKNOWN',
          countryName:
            claudeOutcome.loc !== claudeOutcome.countryCode
              ? claudeOutcome.countryName
              : '未知',
          viaChannel,
          latencyMs: claudeOutcome.latencyMs,
          checkedAt: claudeOutcome.checkedAt,
        };
        const attached = this.attachClaudeOutcomeToSample(baseSample, claudeOutcome);
        if (claudeOutcome.loc === claudeOutcome.countryCode) {
          attached.claudeTraceError =
            endpoints.length === 0
              ? noGeneralEndpointsMsg
              : `常规出口探测均不可达（${generalErrText}）`;
        }
        return {
          result: attached,
          errMsg: '',
          localProxyRefused: false,
        };
      }
      if (claudeOutcome?.kind === 'trace-error' && claudeOutcome.claudeTraceIp) {
        const baseSample: ProbeResult = {
          ip: claudeOutcome.claudeTraceIp,
          countryCode: 'UNKNOWN',
          countryName: '未知',
          viaChannel,
          latencyMs: claudeOutcome.latencyMs ?? Math.max(0, Date.now() - roundStartedAt),
          checkedAt: claudeOutcome.claudeTraceCheckedAt ?? Date.now(),
        };
        const attached = this.attachClaudeOutcomeToSample(baseSample, claudeOutcome);
        if (endpoints.length === 0) {
          attached.claudeTraceError = `${claudeOutcome.claudeTraceError}；${noGeneralEndpointsMsg}`;
        }
        return {
          result: attached,
          errMsg: '',
          localProxyRefused: false,
        };
      }
      const combinedErrors =
        claudeOutcome?.kind === 'trace-error'
          ? [
              claudeOutcome.claudeTraceError,
              ...(endpoints.length === 0 ? [noGeneralEndpointsMsg] : generalErrors),
            ]
          : endpoints.length === 0
          ? [noGeneralEndpointsMsg]
          : generalErrors;
      return {
        result: null,
        errMsg: combinedErrors.join('；') || '探测超时',
        localProxyRefused: false,
      };
    }

    const byIndex = [...generalSamples].sort((a, b) => a.index - b.index);

    if (!claudeOutcome || claudeOutcome.kind === 'refused') {
      return {
        result: null,
        errMsg: generalErrors.join('；') || '目标服务校验未完成',
        localProxyRefused: false,
      };
    }

    if (claudeOutcome.kind === 'trace-error') {
      const traceErrLoc = claudeOutcome.claudeTraceLoc;
      const preferred =
        (traceErrLoc
          ? byIndex.find((item) => item.sample.countryCode.toUpperCase() === traceErrLoc)
          : undefined) || byIndex[0];
      return {
        result: this.attachClaudeOutcomeToSample(preferred.sample, claudeOutcome),
        errMsg: '',
        localProxyRefused: false,
      };
    }

    const okClaude: Extract<ClaudeSampleOutcome, { kind: 'ok' }> = claudeOutcome;
    const targetCountry = okClaude.countryCode;
    const matched = byIndex.filter(
      (item) => item.sample.countryCode.toUpperCase() === targetCountry
    );
    const dissenting = byIndex.filter(
      (item) => item.sample.countryCode.toUpperCase() !== targetCountry
    );

    if (okClaude.loc !== okClaude.countryCode) {
      const baseSample: ProbeResult = matched[0]?.sample ?? {
        ip: okClaude.ip,
        countryCode: okClaude.countryCode,
        countryName: okClaude.countryName,
        viaChannel,
        latencyMs: okClaude.latencyMs,
        checkedAt: okClaude.checkedAt,
      };
      return {
        result: this.attachClaudeOutcomeToSample(baseSample, okClaude),
        errMsg: '',
        localProxyRefused: false,
      };
    }

    if (dissenting.length >= MIN_CONSENSUS_MATCHES) {
      return {
        result: this.attachClaudeOutcomeToSample(dissenting[0].sample, okClaude),
        errMsg: '',
        localProxyRefused: false,
      };
    }

    if (
      (dissenting.length === 0 &&
        settledGeneralCount === endpoints.length &&
        matched.length >= 1) ||
      (dissenting.length <= 1 && matched.length >= MIN_CONSENSUS_MATCHES)
    ) {
      return {
        result: this.attachClaudeOutcomeToSample(matched[0].sample, okClaude),
        errMsg: '',
        localProxyRefused: false,
      };
    }

    if (isClaudeSelfViolatingRunningSession(okClaude)) {
      const baseSample: ProbeResult = {
        ip: okClaude.ip,
        countryCode: 'UNKNOWN',
        countryName: '未知',
        viaChannel,
        latencyMs: okClaude.latencyMs,
        checkedAt: okClaude.checkedAt,
      };
      const attached = this.attachClaudeOutcomeToSample(baseSample, okClaude);
      attached.claudeTraceError = '常规出口复核未完成（已优先拦截 Claude 会话异常）';
      return {
        result: attached,
        errMsg: '',
        localProxyRefused: false,
      };
    }

    const outlierCode = dissenting[0]?.sample.countryCode.toUpperCase() || 'UNKNOWN';
    const prefix = `常规出口复核未完成：单源 ${outlierCode} 与 Claude (${targetCountry}) 待核实`;
    const details =
      endpoints.length === 1
        ? ['无其余独立常规探测源可供复核']
        : generalErrors.length > 0
        ? generalErrors
        : [`仅 ${matched.length} 个独立常规源支持 ${targetCountry}，不足 ${MIN_CONSENSUS_MATCHES} 个共识阈值`];

    return {
      result: null,
      errMsg: [prefix, ...details].join('；'),
      localProxyRefused: false,
    };
  }

  /**
   * 校验 Antigravity 的 Google 识别地区与 NotebookLM 地区可用性。
   */
  private async verifyAntigravityGoogleRegion(
    proxyUrl: string | null,
    probe: ProbeResult,
    signal?: AbortSignal
  ): Promise<void> {
    if (signal?.aborted) return;
    const baseCode = probe.countryCode.toUpperCase();
    if (!isValidIsoCountryCode(baseCode)) return;

    probe.googleCountryCode = undefined;
    probe.googleCountryName = undefined;
    probe.googleAiSupported = undefined;
    probe.regionMismatchDetail = null;

    const googleRes = await probeGoogleRegionViaProxy(proxyUrl, signal);
    if (signal?.aborted) return;

    let googleCode: string | undefined;
    if (googleRes) {
      if (googleRes.countryCode && googleRes.countryCode !== baseCode) {
        googleCode = googleRes.countryCode;
      } else if (googleRes.altCountryCode && googleRes.altCountryCode !== baseCode) {
        googleCode = googleRes.altCountryCode;
      } else {
        googleCode = googleRes.countryCode ?? googleRes.altCountryCode;
      }
      probe.googleAiSupported = googleRes.aiSupported;
    }

    if (googleCode && isValidIsoCountryCode(googleCode)) {
      probe.googleCountryCode = googleCode;
      probe.googleCountryName = getCountryNameZh(googleCode);
    }

    const googleMismatch = Boolean(
      probe.googleCountryCode && probe.googleCountryCode !== baseCode
    );
    const aiUnsupported = probe.googleAiSupported === false;

    if (googleMismatch && probe.googleCountryCode) {
      probe.regionMismatchDetail = aiUnsupported
        ? `离线库为 ${probe.countryName} (${baseCode})，但 Google 实际识别为 ${probe.googleCountryName} (${probe.googleCountryCode})，且 NotebookLM 判定该地区不受支持（疑似假${probe.countryName}/送中节点）`
        : `离线库为 ${probe.countryName} (${baseCode})，但 Google 实际识别为 ${probe.googleCountryName} (${probe.googleCountryCode})（疑似假${probe.countryName}/送中节点）`;
    } else if (aiUnsupported) {
      probe.regionMismatchDetail = probe.googleCountryCode
        ? `Google 识别地区为 ${probe.googleCountryName} (${probe.googleCountryCode})，但 NotebookLM 判定当前节点地区不受支持`
        : `离线库为 ${probe.countryName} (${baseCode})，但 NotebookLM 判定当前节点地区不受支持（疑似送中或受限地区节点）`;
    } else {
      probe.regionMismatchDetail = null;
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

function createFallbackUpdateStateSnapshot(): UpdateStateSnapshot {
  return {
    currentVersion: app.getVersion() || '1.0.0',
    electronVersion: process.versions.electron || '0.0.0',
    isPackaged: app.isPackaged,
    status: 'idle',
    hasUpdate: false,
    latestVersion: null,
    publishedAt: null,
    releaseNotes: null,
    deliveryMode: null,
    includeMmdbUpdate: false,
    downloadTotalBytes: null,
    downloadedBytes: 0,
    progressPercent: null,
    signatureVerified: false,
    lastCheckedAt: null,
    lastSuccessfulCheckAt: null,
    viaChannel: null,
    error: null,
    releasePageUrl: DEFAULT_GITHUB_RELEASES_PAGE_URL,
  };
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
        ip = normalizeIpAddress(v) || v;
      } else if (k === 'loc' && v) {
        loc = v.toUpperCase();
      }
    }
    return { ip, loc };
  }

  if (net.isIP(text)) {
    return { ip: normalizeIpAddress(text) || text };
  }
  try {
    const obj = JSON.parse(text) as Record<string, unknown>;
    const candidate = String(obj['ip'] || obj['query'] || '').trim();
    if (net.isIP(candidate)) {
      return { ip: normalizeIpAddress(candidate) || candidate };
    }
  } catch {
    const firstLine = text.split(/\r?\n/)[0]?.trim() || '';
    if (net.isIP(firstLine)) {
      return { ip: normalizeIpAddress(firstLine) || firstLine };
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

const GOOGLE_REGION_PROBE_TIMEOUT_MS = 8500;
const GOOGLE_AI_CHECK_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36';

function isAsciiAlphaByte(byte: number): boolean {
  return (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a);
}

/**
 * 使用 @bufbuild/protobuf/wire 解析 YouTube sw.js_data 内嵌的 visitorData Protobuf（field 6 -> field 1），
 * 提取 Google 内部 GeoIP 真实国家码（解决 CN 送中节点在 inner[1] 被静默回退为 US 的盲区）。
 */
export function extractYoutubeVisitorCountryCode(rawToken: string): string | null {
  const trimmed = rawToken.trim();
  if (!trimmed || trimmed.length < 16 || trimmed.length > 2048) return null;

  let decodedText = trimmed;
  if (decodedText.includes('%')) {
    try {
      decodedText = decodeURIComponent(decodedText);
    } catch {
      return null;
    }
  }
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(decodedText)) return null;

  const normalized = decodedText.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const buf = Buffer.from(padded, 'base64');
  if (buf.length < 12) return null;

  let visitorId: Uint8Array | null = null;
  let timestamp: bigint | null = null;
  let geoContainer: Uint8Array | null = null;

  try {
    const reader = new BinaryReader(buf);
    while (reader.pos < reader.len) {
      const [fieldNo, wireType] = reader.tag();
      if (fieldNo <= 0) return null;
      if (fieldNo === 1 && wireType === WireType.LengthDelimited && visitorId === null) {
        visitorId = reader.bytes();
      } else if (fieldNo === 5 && wireType === WireType.Varint && timestamp === null) {
        timestamp = BigInt(reader.uint64());
      } else if (fieldNo === 6 && wireType === WireType.LengthDelimited && geoContainer === null) {
        geoContainer = reader.bytes();
      } else {
        reader.skip(wireType, fieldNo);
      }
    }
  } catch {
    return null;
  }

  if (
    !visitorId ||
    visitorId.length < 6 ||
    visitorId.length > 32 ||
    timestamp === null ||
    timestamp < 1_000_000_000n ||
    !geoContainer ||
    geoContainer.length < 4
  ) {
    return null;
  }

  let countryBytes: Uint8Array | null = null;
  try {
    const geoReader = new BinaryReader(geoContainer);
    while (geoReader.pos < geoReader.len) {
      const [fieldNo, wireType] = geoReader.tag();
      if (fieldNo <= 0) return null;
      if (fieldNo === 1 && wireType === WireType.LengthDelimited && countryBytes === null) {
        countryBytes = geoReader.bytes();
      } else {
        geoReader.skip(wireType, fieldNo);
      }
    }
  } catch {
    return null;
  }

  // 严格校验原始字节为纯 ASCII 字母，禁止使用 Buffer.toString('ascii') 剥离最高位导致非法字节误判
  if (
    !countryBytes ||
    countryBytes.length !== 2 ||
    !isAsciiAlphaByte(countryBytes[0]) ||
    !isAsciiAlphaByte(countryBytes[1])
  ) {
    return null;
  }

  return normalizeIsoCountryCode(String.fromCharCode(countryBytes[0], countryBytes[1]));
}

export interface YoutubeSwJsDataResult {
  countryCode: string;
  ip?: string;
  glCountryCode?: string;
  visitorCountryCode?: string;
}

export function parseYoutubeSwJsData(raw: string): YoutubeSwJsDataResult | null {
  let glCountryCode: string | undefined;
  let visitorCountryCode: string | undefined;
  let ip: string | undefined;

  try {
    const cleaned = raw.replace(/^\)\]\}'\s*/, '');
    const parsed = JSON.parse(cleaned) as unknown;
    let entry: unknown[] | null = null;
    if (Array.isArray(parsed)) {
      if (parsed[0] === 'yt.sw.adr') {
        entry = parsed;
      } else {
        const found = parsed.find((item) => Array.isArray(item) && item[0] === 'yt.sw.adr');
        if (Array.isArray(found)) entry = found;
      }
    }
    const inner = ((entry?.[2] as unknown[])?.[0] as unknown[])?.[0];
    if (Array.isArray(inner)) {
      glCountryCode = normalizeIsoCountryCode(String(inner[1] || '')) || undefined;
      const ipCandidate = String(inner[3] || '').trim();
      if (net.isIP(ipCandidate)) {
        ip = normalizeIpAddress(ipCandidate) || ipCandidate;
      }
      const candidateTokens: string[] = [];
      if (typeof inner[13] === 'string') {
        candidateTokens.push(inner[13]);
      }
      for (let i = 4; i < inner.length; i++) {
        if (i !== 13 && typeof inner[i] === 'string' && inner[i].length >= 16) {
          candidateTokens.push(inner[i]);
        }
      }
      for (const token of candidateTokens) {
        const extracted = extractYoutubeVisitorCountryCode(token);
        if (extracted) {
          visitorCountryCode = extracted;
          break;
        }
      }
    }
  } catch {
    // ignore JSON parse failure, fall back to regex below
  }

  if (!glCountryCode && !visitorCountryCode) {
    const m = raw.match(
      /\["yt\.sw\.adr"\s*,\s*null\s*,\s*\[\[\[\s*"[^"]*"\s*,\s*"([A-Za-z]{2,3})"\s*,\s*null\s*,\s*"([^"]*)"/
    );
    if (m) {
      glCountryCode = normalizeIsoCountryCode(m[1]) || undefined;
      const ipStr = m[2].trim();
      if (net.isIP(ipStr)) {
        ip = normalizeIpAddress(ipStr) || ipStr;
      }
    }
  }

  const countryCode = visitorCountryCode || glCountryCode;
  if (!countryCode) return null;
  return {
    countryCode,
    ip,
    glCountryCode,
    visitorCountryCode,
  };
}

export function extractGoogleRedirectCountry(
  rawLocation: string,
  baseUrl = 'https://www.google.com/'
): string | null {
  try {
    const parsed = new URL(rawLocation, baseUrl);
    const host = parsed.hostname.toLowerCase();
    if (parsed.searchParams.get('pref')?.toLowerCase() === 'hkredirect') {
      return 'CN';
    }
    if (host === 'google.cn' || host.endsWith('.google.cn')) {
      return 'CN';
    }
    if (host === 'consent.google.com') {
      const gl = normalizeIsoCountryCode(parsed.searchParams.get('gl'));
      if (gl) return gl;
    }
  } catch {
    // ignore malformed redirect URL
  }
  return null;
}

export function parseGoogleSearchHtml(raw: string): { countryCode: string } | null {
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
}

function isNotebookLmDomainMigrationRedirect(
  rawLocation: string,
  fromUrl = 'https://notebooklm.google.com/'
): boolean {
  try {
    const parsed = new URL(rawLocation, fromUrl);
    if (parsed.protocol !== 'https:') return false;
    if (parsed.searchParams.get('location')?.toLowerCase() === 'unsupported') {
      return false;
    }
    const host = parsed.hostname.toLowerCase();
    return host === 'notebook.google.com' || host === 'notebooklm.google.com';
  } catch {
    return false;
  }
}

export function classifyNotebookLmResponse(
  res: Pick<ProxyHttpResponse, 'statusCode' | 'location'> & { finalUrl?: string }
): boolean | undefined {
  if (res.location && res.statusCode >= 300 && res.statusCode < 400) {
    try {
      const parsed = new URL(res.location, res.finalUrl || 'https://notebooklm.google.com/');
      if (parsed.searchParams.get('location')?.toLowerCase() === 'unsupported') {
        return false;
      }
      const host = parsed.hostname.toLowerCase();
      if (
        host === 'accounts.google.com' ||
        host === 'notebooklm.google' ||
        host === 'notebook.google'
      ) {
        return true;
      }
    } catch {
      return undefined;
    }
    return undefined;
  }
  if (res.statusCode >= 200 && res.statusCode < 300) {
    return true;
  }
  return undefined;
}

export interface GoogleRegionProbeResult {
  countryCode?: string;
  countryCodeAuthoritative?: boolean;
  ip?: string;
  altCountryCode?: string;
  aiSupported?: boolean;
}

export async function probeGoogleRegionViaProxy(
  proxyUrl: string | null,
  signal?: AbortSignal
): Promise<GoogleRegionProbeResult | null> {
  const [ytSettled, gSearchSettled, notebookLmSettled] = await Promise.allSettled([
    requestTextViaProxy(
      'https://www.youtube.com/sw.js_data',
      proxyUrl,
      GOOGLE_REGION_PROBE_TIMEOUT_MS,
      undefined,
      2,
      false,
      signal
    ),
    requestHttpViaProxy(
      'https://www.google.com/?hl=en',
      proxyUrl,
      GOOGLE_REGION_PROBE_TIMEOUT_MS,
      {
        acceptHeader: 'text/html, */*',
        redirectsLeft: 2,
        allowLocalhost: false,
        signal,
        allowRedirectStatus: true,
        onRedirect: ({ location, fromUrl }) =>
          extractGoogleRedirectCountry(location, fromUrl.toString()) ? 'stop' : 'follow',
      }
    ),
    requestHttpViaProxy(
      'https://notebooklm.google.com/',
      proxyUrl,
      GOOGLE_REGION_PROBE_TIMEOUT_MS,
      {
        acceptHeader: 'text/html, */*',
        redirectsLeft: 2,
        allowLocalhost: false,
        signal,
        userAgent: GOOGLE_AI_CHECK_USER_AGENT,
        headers: { 'Accept-Language': 'en-US,en;q=0.9' },
        allowRedirectStatus: true,
        onRedirect: ({ location, fromUrl }) =>
          isNotebookLmDomainMigrationRedirect(location, fromUrl.toString()) ? 'follow' : 'stop',
        discardBody: true,
      }
    ),
  ]);

  const ytRes =
    ytSettled.status === 'fulfilled' ? parseYoutubeSwJsData(ytSettled.value) : null;

  let gSearchRes: { countryCode: string; authoritative: boolean } | null = null;
  if (gSearchSettled.status === 'fulfilled') {
    const resp = gSearchSettled.value;
    const redirectCode = resp.location
      ? extractGoogleRedirectCountry(resp.location, resp.finalUrl)
      : null;
    if (redirectCode) {
      gSearchRes = { countryCode: redirectCode, authoritative: true };
    } else if (resp.statusCode >= 200 && resp.statusCode < 300 && resp.body) {
      const htmlRes = parseGoogleSearchHtml(resp.body);
      if (htmlRes) {
        gSearchRes = { countryCode: htmlRes.countryCode, authoritative: false };
      }
    }
  }

  const aiSupported =
    notebookLmSettled.status === 'fulfilled'
      ? classifyNotebookLmResponse(notebookLmSettled.value)
      : undefined;

  if (ytRes && gSearchRes && ytRes.countryCode !== gSearchRes.countryCode) {
    // 若 Google 搜索通过明确重定向（如 pref=hkredirect -> CN）得出结论，
    // 不允许缺少 visitorData 的 YouTube 默认 GL（常将 CN 回退为 US）作为备选值覆盖该结论。
    const altCountryCode =
      gSearchRes.authoritative && !ytRes.visitorCountryCode
        ? undefined
        : ytRes.countryCode;
    return {
      countryCode: gSearchRes.countryCode,
      countryCodeAuthoritative: gSearchRes.authoritative,
      ip: ytRes.ip,
      altCountryCode,
      aiSupported,
    };
  }

  if (gSearchRes) {
    return {
      countryCode: gSearchRes.countryCode,
      countryCodeAuthoritative: gSearchRes.authoritative,
      ip: ytRes?.ip,
      aiSupported,
    };
  }

  if (ytRes) {
    return {
      countryCode: ytRes.countryCode,
      countryCodeAuthoritative: Boolean(ytRes.visitorCountryCode),
      ip: ytRes.ip,
      aiSupported,
    };
  }

  if (aiSupported !== undefined) {
    return { aiSupported };
  }

  return null;
}
