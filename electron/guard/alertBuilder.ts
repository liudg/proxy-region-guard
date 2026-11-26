import { app } from 'electron';
import * as net from 'node:net';
import {
  AlertPayload,
  AppConfig,
  ClashRuntimeInfo,
  ProbeResult,
  UpdateStateSnapshot,
  WindowsLocaleState,
} from '../../src/shared/types';
import { DEFAULT_GITHUB_RELEASES_PAGE_URL } from '../../src/shared/updateManifest';
import { getCountryNameZh, isValidIsoCountryCode } from '../../src/shared/countries';
import {
  getTargetServiceVerificationError,
  normalizeIpAddress,
} from '../../src/shared/probeValidation';
import { GeoIpService } from '../system/geoipService';

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

  const fallbackMismatchExit =
    !isClaudeSource &&
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

export interface GuardAlertInput {
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
}

export function buildGuardAlertPayload(options: {
  input: GuardAlertInput;
  cfg: AppConfig;
  clash: ClashRuntimeInfo;
  claudeNodeProbe: ProbeResult | null;
  monitorLastProbe: ProbeResult | null;
  geoIp: GeoIpService;
  winLocale: WindowsLocaleState;
}): AlertPayload | null {
  const { input, cfg, clash, claudeNodeProbe, monitorLastProbe, geoIp, winLocale } = options;
  const isClaudeSource = input.source === 'claude';
  if (!isClaudeSource && !cfg.monitorAlertEnabled) {
    return null;
  }

  const refProbe = isClaudeSource ? claudeNodeProbe : monitorLastProbe;

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
            const g = geoIp.lookup(refProbe.claudeTraceIp);
            return isValidIsoCountryCode(g.countryCode) ? g.countryCode.toUpperCase() : null;
          })()
        : null
      : null;

  const { actualCode, actualName, actualIp } = resolveAlertActualMismatchFields({
    isClaudeSource,
    alertType: input.alertType,
    expectedCode: input.expectedCode,
    explicitActualIp: input.actualIp,
    refProbe,
    claudeSplitGeoCode,
  });

  return {
    source: input.source,
    alertType: input.alertType,
    expectedCode: input.expectedCode,
    expectedName: input.expectedName,
    expectedIp: input.expectedIp ?? null,
    actualCode,
    actualName,
    actualIp,
    edgeLoc: refProbe?.edgeLoc,
    viaChannel: refProbe?.viaChannel,
    activeNode: activeNodeLabel,
    triggerReason: input.triggerReason,
    errorDetail: input.errorDetail,
    killedProcesses: input.killedProcesses,
    killError: input.killError,
    sysRegionCode: winLocale.regionCode,
    sysRegionName: winLocale.regionName,
    sysTimeZoneDisplay: winLocale.timeZoneDisplayName,
    soundEnabled: cfg.alertSoundEnabled,
    timestamp: Date.now(),
  };
}

export function buildRecoveredAlertPayload(
  cfg: AppConfig,
  lastProbe: ProbeResult
): AlertPayload {
  const targetCode = cfg.defaultCountryCode || lastProbe.countryCode;
  return {
    source: 'monitor',
    alertType: 'recovered',
    expectedCode: targetCode,
    expectedName: getCountryNameZh(targetCode),
    actualCode: lastProbe.countryCode,
    actualName: lastProbe.countryName,
    actualIp: lastProbe.ip,
    viaChannel: lastProbe.viaChannel,
    triggerReason: 'Clash 选中通道地区与系统时区/区域已恢复一致',
    soundEnabled: false,
    timestamp: Date.now(),
  };
}

export function buildSystemAlertPayload(
  alertType: 'tun-enabled' | 'kernel-error',
  message: string,
  soundEnabled: boolean
): AlertPayload {
  return {
    source: 'system',
    alertType,
    expectedCode: null,
    expectedName: null,
    actualCode: null,
    actualName: null,
    actualIp: null,
    triggerReason: message,
    errorDetail: message,
    soundEnabled,
    timestamp: Date.now(),
  };
}

export function createFallbackUpdateStateSnapshot(): UpdateStateSnapshot {
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
