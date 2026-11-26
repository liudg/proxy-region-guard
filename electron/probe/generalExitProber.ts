import { ProbeResult } from '../../src/shared/types';
import { isValidIsoCountryCode } from '../../src/shared/countries';
import { TraceEndpoint } from '../clash/transportHosts';
import { GeoIpService } from '../system/geoipService';
import {
  formatNetworkErrorMessage,
  isLocalProxyRefusedCause,
  requestTextViaProxy,
} from '../net';
import { buildProbeEndpointsList, parseTraceResponse } from './traceParser';

export const EXIT_PROBE_TIMEOUT_MS = 15000;

export interface GeneralChannelProbeOptions {
  proxyUrl: string | null;
  viaChannel: string;
  timeoutMs: number;
  defaultErrMsg?: string;
  customProbeUrl?: string;
  includeCustom?: boolean;
  transportHosts?: readonly string[];
  signal?: AbortSignal;
  geoIp: GeoIpService;
}

export async function probeOnceViaChannel(
  options: GeneralChannelProbeOptions
): Promise<{ result: ProbeResult | null; errMsg: string; localProxyRefused: boolean }> {
  const {
    proxyUrl,
    viaChannel,
    timeoutMs,
    defaultErrMsg = '探测超时',
    customProbeUrl = '',
    includeCustom = true,
    transportHosts = [],
    geoIp,
  } = options;

  const endpoints = buildProbeEndpointsList(customProbeUrl, includeCustom, transportHosts);
  if (endpoints.length === 0) {
    return {
      result: null,
      errMsg: '常规探测源均与当前节点传输层域名重合，无法执行独立出口校验',
      localProxyRefused: false,
    };
  }
  const hasCustomFirst = includeCustom && Boolean(customProbeUrl.trim());
  const channelDeadlineAt = Date.now() + Math.max(timeoutMs, EXIT_PROBE_TIMEOUT_MS);
  const backupTimeoutMs = Math.min(timeoutMs, 3600);
  const controller = new AbortController();
  const outerSignal = options.signal
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
    const body = await requestTextViaProxy(
      ep.url,
      proxyUrl,
      budgetMs,
      undefined,
      undefined,
      false,
      signal
    );
    const parsed = parseTraceResponse(body, ep.format);
    if (!parsed.ip) throw new Error('响应中未解析到有效公网 IP');

    const checkedAt = Date.now();
    const result: ProbeResult = {
      ip: parsed.ip,
      ...geoIp.lookup(parsed.ip, parsed.loc),
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
    for (let index = 0; index < endpoints.length; ) {
      if (outerSignal.aborted) break;
      const remainingMs = channelDeadlineAt - Date.now();
      const limitMs =
        index === 0 ? (hasCustomFirst ? Math.min(timeoutMs, 5500) : timeoutMs) : backupTimeoutMs;
      // 剩余时间只够完成一轮时，同时请求余下的来源。
      const batch =
        remainingMs <= limitMs + backupTimeoutMs
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
    return {
      result: unknownRegion,
      errMsg: unknownRegion ? '' : errOut,
      localProxyRefused: false,
    };
  } finally {
    controller.abort();
  }
}
