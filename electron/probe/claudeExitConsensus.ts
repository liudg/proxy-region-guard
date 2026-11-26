import * as net from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import { ProbeResult, WindowsLocaleState } from '../../src/shared/types';
import {
  getCountryNameZh,
  isValidIsoCountryCode,
  normalizeIsoCountryCode,
} from '../../src/shared/countries';
import { normalizeIpAddress } from '../../src/shared/probeValidation';
import { isWindowsLocaleMatchingCountry } from '../../src/shared/timezones';
import { TraceEndpoint } from '../clash/transportHosts';
import { GeoIpService } from '../system/geoipService';
import {
  formatNetworkErrorMessage,
  isLocalProxyRefusedCause,
  requestTextViaProxy,
} from '../net';
import { EXIT_PROBE_TIMEOUT_MS } from './generalExitProber';
import { parseTraceResponse } from './traceParser';

export const CLAUDE_MAX_RUNTIME_POLL_SEC = 10;
export const MIN_CONSENSUS_MATCHES = 2;
const GENERAL_SOURCE_TIMEOUT_MS = 8000;
const CLAUDE_TRACE_TIMEOUT_MS = 14500;
const CLAUDE_TRACE_HEDGE_DELAY_MS = 2800;

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

export interface ClaudeConsensusSessionContext {
  hasSessionBaseline: boolean;
  claudeExternalBaselinePending: boolean;
  claudeLockExitIp: boolean;
  effectiveForceIpv4: boolean;
  sessionInitialIp: string | null;
  winLocale: WindowsLocaleState;
}

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

export function attachClaudeOutcomeToSample(
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

async function sampleClaudeGeneralEndpoint(
  endpoint: TraceEndpoint,
  proxyUrl: string,
  viaChannel: string,
  timeoutMs: number,
  geoIp: GeoIpService,
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
  const geo = geoIp.lookupOfflineStrict(ip);
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

export async function requestClaudeTraceOutcome(
  proxyUrl: string,
  geoIp: GeoIpService,
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
      (ip) => geoIp.lookupOfflineStrict(ip),
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

export async function probeAndVerifyClaudeExitConsensus(options: {
  proxyUrl: string;
  viaChannel: string;
  endpoints: readonly TraceEndpoint[];
  geoIp: GeoIpService;
  getSession: () => ClaudeConsensusSessionContext;
  signal: AbortSignal;
}): Promise<{
  result: ProbeResult | null;
  errMsg: string;
  localProxyRefused: boolean;
}> {
  const { proxyUrl, viaChannel, endpoints, geoIp, getSession, signal } = options;
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

  const isLockedIpDrifted = (ip: string | null | undefined): boolean => {
    const session = getSession();
    if (
      !session.hasSessionBaseline ||
      session.claudeExternalBaselinePending ||
      !session.claudeLockExitIp
    ) {
      return false;
    }
    const lockedIp = normalizeIpAddress(session.sessionInitialIp);
    const currentIp = normalizeIpAddress(ip);
    return Boolean(lockedIp && currentIp && currentIp !== lockedIp);
  };

  const isClaudeCountryViolatingRunningSession = (
    countryCode: string | null | undefined
  ): boolean => {
    const session = getSession();
    if (!session.hasSessionBaseline || !isValidIsoCountryCode(countryCode)) {
      return false;
    }
    return !isWindowsLocaleMatchingCountry(
      session.winLocale.timeZoneId,
      session.winLocale.regionCode,
      countryCode.toUpperCase()
    );
  };

  const isForcedIpv4Violated = (ip: string | null | undefined): boolean => {
    const session = getSession();
    if (!session.effectiveForceIpv4) return false;
    const currentIp = normalizeIpAddress(ip);
    return Boolean(currentIp && net.isIPv6(currentIp));
  };

  const isClaudeSelfViolatingRunningSession = (
    outcome: Extract<ClaudeSampleOutcome, { kind: 'ok' }>
  ): boolean => {
    const session = getSession();
    if (!session.hasSessionBaseline) {
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
      const session = getSession();
      return (
        isLockedIpDrifted(outcome.claudeTraceIp) ||
        (session.hasSessionBaseline && isForcedIpv4Violated(outcome.claudeTraceIp)) ||
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
        const traceResult = await requestClaudeTraceOutcome(
          proxyUrl,
          geoIp,
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
      const sample = await sampleClaudeGeneralEndpoint(
        endpoint,
        proxyUrl,
        viaChannel,
        budget,
        geoIp,
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
      const attached = attachClaudeOutcomeToSample(baseSample, claudeOutcome);
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
      const attached = attachClaudeOutcomeToSample(baseSample, claudeOutcome);
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
      result: attachClaudeOutcomeToSample(preferred.sample, claudeOutcome),
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
      result: attachClaudeOutcomeToSample(baseSample, okClaude),
      errMsg: '',
      localProxyRefused: false,
    };
  }

  if (dissenting.length >= MIN_CONSENSUS_MATCHES) {
    return {
      result: attachClaudeOutcomeToSample(dissenting[0].sample, okClaude),
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
      result: attachClaudeOutcomeToSample(matched[0].sample, okClaude),
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
    const attached = attachClaudeOutcomeToSample(baseSample, okClaude);
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
