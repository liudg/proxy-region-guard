import * as net from 'node:net';
import {
  AppConfig,
  ClaudeVerificationFailure,
  ClaudeRuntimeState,
  PrivateChannelState,
  ProbeResult,
  WindowsLocaleState,
} from '../../src/shared/types';
import { getCountryNameZh, isValidIsoCountryCode } from '../../src/shared/countries';
import {
  getTargetServiceVerificationError,
  normalizeIpAddress,
} from '../../src/shared/probeValidation';
import { isWindowsLocaleMatchingCountry } from '../../src/shared/timezones';
import { getLaunchedClaudePort } from '../system';
import {
  ClaudeSafetyCheck,
  evaluateClaudeNodeProbeSafety,
  isProbeRegionMismatched,
} from './alertBuilder';

export interface VerifiedRegionSnapshot {
  node: string;
  profileUid: string | null;
  port: number;
  countryCode: string;
  countryName: string;
}

export interface ClaudePolicySnapshotInput {
  cfg: AppConfig;
  kernel: PrivateChannelState;
  winLocale: WindowsLocaleState;
  detectedExe: string | null;
  installType: ClaudeRuntimeState['installType'];
  running: boolean;
  processCount: number;
  authorizedSession: boolean;
  sessionInitialIp: string | null;
  externalBaselinePending: boolean;
  isProbing: boolean;
  nodeProbe: ProbeResult | null;
  nodeProbeError: string | null;
  lastVerificationSuccessAt: number | null;
  lastVerifiedRegion: VerifiedRegionSnapshot | null;
  verificationFailure: ClaudeVerificationFailure | null;
  effectiveForceIpv4: boolean;
}

export function hasConfirmedClaudeProbeViolation(
  probe: ProbeResult | null,
  input: Pick<
    ClaudePolicySnapshotInput,
    | 'cfg'
    | 'winLocale'
    | 'running'
    | 'authorizedSession'
    | 'sessionInitialIp'
    | 'externalBaselinePending'
    | 'effectiveForceIpv4'
  >
): boolean {
  if (!probe) return false;
  if (isProbeRegionMismatched(probe)) return true;
  const hasSessionBaseline =
    input.running || input.authorizedSession || input.sessionInitialIp !== null;
  const probeCheck = evaluateClaudeNodeProbeSafety(probe, {
    claudeRunning: hasSessionBaseline,
    claudeExternalBaselinePending: input.externalBaselinePending,
    claudeLockExitIp: input.cfg.claudeLockExitIp,
    claudeForceIpv4: input.effectiveForceIpv4,
    sessionInitialIp: input.sessionInitialIp,
  });
  if (probeCheck && probeCheck.alertType !== 'verification-unavailable') {
    return true;
  }
  if (
    hasSessionBaseline &&
    isValidIsoCountryCode(probe.claudeTraceCountryCode) &&
    !isWindowsLocaleMatchingCountry(
      input.winLocale.timeZoneId,
      input.winLocale.regionCode,
      probe.claudeTraceCountryCode.toUpperCase()
    )
  ) {
    return true;
  }
  return false;
}

export function resolveExpectedClaudeRegion(
  cfg: AppConfig,
  nodeProbe: ProbeResult | null,
  lastVerifiedRegion: VerifiedRegionSnapshot | null
): { countryCode: string; countryName: string } | null {
  if (
    nodeProbe &&
    isValidIsoCountryCode(nodeProbe.countryCode) &&
    !getTargetServiceVerificationError(nodeProbe, 'claude')
  ) {
    return nodeProbe;
  }
  if (
    lastVerifiedRegion &&
    lastVerifiedRegion.node === cfg.selectedClashNode &&
    lastVerifiedRegion.profileUid === cfg.selectedClashProfileUid &&
    lastVerifiedRegion.port === cfg.dedicatedProxyPort
  ) {
    return lastVerifiedRegion;
  }
  return nodeProbe &&
    !nodeProbe.claudeTraceError &&
    isValidIsoCountryCode(nodeProbe.countryCode)
    ? nodeProbe
    : null;
}

export function evaluateClaudeLocalSafety(
  requireDedicatedNode: boolean,
  input: ClaudePolicySnapshotInput
): ClaudeSafetyCheck | null {
  const { cfg, kernel, winLocale, authorizedSession, isProbing, nodeProbe, lastVerifiedRegion } =
    input;
  const launchedPort = getLaunchedClaudePort();
  if (
    authorizedSession &&
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

  if (
    cfg.selectedClashNode &&
    (kernel.phase !== 'ready' ||
      kernel.nodeName !== cfg.selectedClashNode ||
      kernel.port !== cfg.dedicatedProxyPort ||
      kernel.profileUid !== cfg.selectedClashProfileUid)
  ) {
    const detailSuffix = kernel.error ? `：${kernel.error}` : '';
    return {
      safe: false,
      reason: `Claude 专属节点 [${cfg.selectedClashNode}] 代理绑定失效 (127.0.0.1:${cfg.dedicatedProxyPort})${detailSuffix}`,
      alertType: 'disconnect',
    };
  }

  const confirmedClaudeCountry =
    nodeProbe &&
    !isProbeRegionMismatched(nodeProbe) &&
    isValidIsoCountryCode(nodeProbe.claudeTraceCountryCode)
      ? nodeProbe.claudeTraceCountryCode.toUpperCase()
      : null;
  if (
    confirmedClaudeCountry &&
    !isWindowsLocaleMatchingCountry(
      winLocale.timeZoneId,
      winLocale.regionCode,
      confirmedClaudeCountry
    )
  ) {
    return {
      safe: false,
      reason: `Claude 实际出口地区 [${getCountryNameZh(confirmedClaudeCountry)} (${confirmedClaudeCountry})] 与系统时区/区域 [${winLocale.regionName} · ${winLocale.timeZoneDisplayName}] 不一致`,
      alertType: 'locale-mismatch',
    };
  }

  const probe = resolveExpectedClaudeRegion(cfg, nodeProbe, lastVerifiedRegion);
  if (
    !(isProbeRegionMismatched(nodeProbe) && !isProbing) &&
    probe &&
    isValidIsoCountryCode(probe.countryCode) &&
    !isWindowsLocaleMatchingCountry(
      winLocale.timeZoneId,
      winLocale.regionCode,
      probe.countryCode
    )
  ) {
    return {
      safe: false,
      reason: `Claude 节点地区 [${probe.countryName} (${probe.countryCode})] 与系统时区/区域 [${winLocale.regionName} · ${winLocale.timeZoneDisplayName}] 不一致`,
      alertType: 'locale-mismatch',
    };
  }
  return null;
}

export function evaluateClaudeFullSafety(
  requireDedicatedNode: boolean,
  input: ClaudePolicySnapshotInput
): ClaudeSafetyCheck {
  const localCheck = evaluateClaudeLocalSafety(requireDedicatedNode, input);
  if (localCheck) return localCheck;

  const {
    cfg,
    kernel,
    running,
    authorizedSession,
    sessionInitialIp,
    externalBaselinePending,
    nodeProbe,
    nodeProbeError,
    effectiveForceIpv4,
  } = input;

  if (nodeProbe) {
    const probeCheck = evaluateClaudeNodeProbeSafety(nodeProbe, {
      claudeRunning: running || authorizedSession || sessionInitialIp !== null,
      claudeExternalBaselinePending: externalBaselinePending,
      claudeLockExitIp: cfg.claudeLockExitIp,
      claudeForceIpv4: effectiveForceIpv4,
      sessionInitialIp,
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

  if (nodeProbeError || !nodeProbe) {
    return {
      safe: false,
      reason: `Claude 专属节点出口不可达 (${nodeProbeError || '连接异常'})`,
      alertType: 'verification-unavailable',
    };
  }

  const actualTraceIp = normalizeIpAddress(nodeProbe.claudeTraceIp);
  if (!actualTraceIp) {
    return {
      safe: false,
      reason: '尚未获取到有效的 Claude 出口 IP',
      alertType: 'verification-unavailable',
    };
  }

  if (
    running &&
    (externalBaselinePending ||
      (!authorizedSession && !cfg.claudeExclusiveGuard && sessionInitialIp === null))
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

export function getVerifiedClaudeCountryCode(nodeProbe: ProbeResult | null): string | null {
  if (
    !nodeProbe ||
    !isValidIsoCountryCode(nodeProbe.countryCode) ||
    getTargetServiceVerificationError(nodeProbe, 'claude')
  ) {
    return null;
  }
  return nodeProbe.countryCode.toUpperCase();
}

export function evaluateShouldStopClaudeBeforeLocaleChange(
  targetCode: string,
  targetTimeZone: string,
  input: ClaudePolicySnapshotInput
): boolean {
  const {
    cfg,
    running,
    authorizedSession,
    sessionInitialIp,
    externalBaselinePending,
    nodeProbe,
    lastVerifiedRegion,
    effectiveForceIpv4,
  } = input;
  if (isProbeRegionMismatched(nodeProbe)) {
    return true;
  }
  if (nodeProbe) {
    const probeCheck = evaluateClaudeNodeProbeSafety(nodeProbe, {
      claudeRunning: running || authorizedSession || sessionInitialIp !== null,
      claudeExternalBaselinePending: externalBaselinePending,
      claudeLockExitIp: cfg.claudeLockExitIp,
      claudeForceIpv4: effectiveForceIpv4,
      sessionInitialIp,
    });
    if (probeCheck && probeCheck.alertType !== 'verification-unavailable') {
      return true;
    }
  }
  const verifiedClaudeCode = getVerifiedClaudeCountryCode(nodeProbe);
  const lastVerifiedClaudeCode =
    lastVerifiedRegion &&
    lastVerifiedRegion.node === cfg.selectedClashNode &&
    lastVerifiedRegion.profileUid === cfg.selectedClashProfileUid &&
    lastVerifiedRegion.port === cfg.dedicatedProxyPort &&
    isValidIsoCountryCode(lastVerifiedRegion.countryCode)
      ? lastVerifiedRegion.countryCode.toUpperCase()
      : null;
  const confirmedClaudeCode = verifiedClaudeCode || lastVerifiedClaudeCode;
  if (!confirmedClaudeCode) {
    return true;
  }
  const traceClaudeCode = isValidIsoCountryCode(nodeProbe?.claudeTraceCountryCode)
    ? nodeProbe!.claudeTraceCountryCode!.toUpperCase()
    : null;
  const claudeCodesToMatch = [confirmedClaudeCode, traceClaudeCode].filter(
    (code): code is string => Boolean(code)
  );
  return claudeCodesToMatch.some(
    (code) => !isWindowsLocaleMatchingCountry(targetTimeZone, targetCode, code)
  );
}

export function buildClaudeRuntimeStateSnapshot(
  input: ClaudePolicySnapshotInput
): ClaudeRuntimeState {
  const {
    cfg,
    kernel,
    winLocale,
    detectedExe,
    installType,
    running,
    processCount,
    authorizedSession,
    sessionInitialIp,
    isProbing,
    nodeProbe,
    nodeProbeError,
    lastVerificationSuccessAt,
    verificationFailure,
  } = input;

  const proxyCountryCode =
    nodeProbe && isValidIsoCountryCode(nodeProbe.countryCode)
      ? nodeProbe.countryCode.toUpperCase()
      : null;
  const proxyCountryName = proxyCountryCode ? nodeProbe?.countryName || null : null;

  const winRegionMatched = proxyCountryCode
    ? winLocale.regionCode.toUpperCase() === proxyCountryCode
    : false;
  const winTimeZoneMatched = proxyCountryCode
    ? isWindowsLocaleMatchingCountry(winLocale.timeZoneId, proxyCountryCode, proxyCountryCode)
    : false;

  const verificationError = getTargetServiceVerificationError(nodeProbe);
  const normalizedClaudeTraceIp = normalizeIpAddress(nodeProbe?.claudeTraceIp);
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
  if (!detectedExe) {
    launchBlockReason = '未检测到客户端路径，请手动指定 Claude.exe';
  } else if (!cfg.selectedClashNode) {
    launchBlockReason = '请先选择代理节点';
  } else if (kernel.phase !== 'ready') {
    launchBlockReason = kernel.error || '私有代理内核未就绪';
  } else if (kernel.verificationError) {
    launchBlockReason = kernel.verificationError;
  } else if (isProbing && !nodeProbe && !nodeProbeError) {
    launchBlockReason = '正在校验节点出口与地区...';
  } else if (nodeProbeError || !proxyCountryCode) {
    launchBlockReason = `出口探测异常：${
      nodeProbeError || nodeProbe?.claudeTraceError || '未获取到有效国家'
    }`;
  } else if (verificationError) {
    launchBlockReason = `地区校验未通过：${verificationError}`;
  } else if (unexpectedIpv6Exit) {
    launchBlockReason = `已开启强制仅走 IPv4 出站，但远端节点访问 Claude 仍返回 IPv6 (${normalizedClaudeTraceIp})，请更换节点或关闭该开关`;
  } else if (!winRegionMatched) {
    launchBlockReason = `系统区域（${winLocale.regionName}）与节点地区（${proxyCountryName}）不一致`;
  } else if (!winTimeZoneMatched) {
    launchBlockReason = `系统时区与节点地区（${proxyCountryName}）不一致`;
  }

  return {
    detectedExePath: detectedExe,
    installType,
    running,
    processCount,
    authorizedSession,
    canLaunch: launchBlockReason === null,
    launchBlockReason,
    threeWayMatched,
    proxyCountryCode,
    proxyCountryName,
    winRegionMatched,
    winTimeZoneMatched,
    isProbingNode: isProbing,
    nodeProbe: nodeProbe ? { ...nodeProbe } : null,
    nodeProbeError,
    verificationFailure,
    lastVerificationSuccessAt,
    lockedSessionIp:
      running && cfg.claudeLockExitIp ? normalizeIpAddress(sessionInitialIp) : null,
  };
}
