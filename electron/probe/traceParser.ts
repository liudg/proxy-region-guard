import * as net from 'node:net';
import { normalizeIpAddress } from '../../src/shared/probeValidation';
import {
  BUILTIN_TRACE_ENDPOINTS,
  selectProbeEndpointsForTransportHosts,
  TraceEndpoint,
} from '../clash/transportHosts';

export function parseTraceResponse(
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

export function simplifyNetworkError(errMsg: string, channelDesc: string): string {
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

export function buildProbeEndpointsList(
  customProbeUrl: string,
  includeCustom = true,
  transportHosts: readonly string[] = []
): TraceEndpoint[] {
  const list: TraceEndpoint[] = [];
  if (includeCustom) {
    const custom = customProbeUrl.trim();
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
