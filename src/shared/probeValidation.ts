import { isValidIsoCountryCode } from './countries';
import { ProbeResult } from './types';

const IPV4_REGEX =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

export function normalizeIpAddress(ip: string | null | undefined): string | null {
  if (!ip) return null;
  const trimmed = ip.trim();
  if (!trimmed) return null;
  if (IPV4_REGEX.test(trimmed)) return trimmed;
  if (!trimmed.includes(':') || !/^[0-9a-fA-F:.]+$/.test(trimmed)) return null;
  try {
    const parsed = new URL(`http://[${trimmed}]/`);
    if (
      parsed.hostname.startsWith('[') &&
      parsed.hostname.endsWith(']') &&
      parsed.port === '' &&
      parsed.pathname === '/' &&
      parsed.search === '' &&
      parsed.hash === ''
    ) {
      return parsed.hostname.slice(1, -1);
    }
    return null;
  } catch {
    return null;
  }
}

export function isValidIpAddress(ip: string | null | undefined): boolean {
  return normalizeIpAddress(ip) !== null;
}

export function getTargetServiceVerificationError(
  probe: ProbeResult | null,
  targetApp: 'claude' | 'antigravity' = 'claude'
): string | null {
  if (!probe) {
    return '尚未获取有效出口国家';
  }
  if (targetApp === 'claude' && probe.claudeTraceError) {
    return probe.claudeTraceError;
  }
  if (!isValidIsoCountryCode(probe.countryCode)) {
    return '尚未获取有效出口国家';
  }
  const serviceCountry = targetApp === 'claude' ? probe.claudeTraceLoc : probe.googleCountryCode;
  const serviceName = targetApp === 'claude' ? 'Claude' : 'Google';
  if (!isValidIsoCountryCode(serviceCountry)) {
    return `${serviceName} 地区校验未完成，请重新检测`;
  }
  if (targetApp === 'claude' && !isValidIpAddress(probe.claudeTraceIp)) {
    return 'Claude 出口 IP 校验未完成，请重新检测';
  }
  if (probe.regionMismatchDetail) return probe.regionMismatchDetail;
  if (targetApp === 'antigravity' && probe.googleAiSupported === false) {
    return 'NotebookLM 判定当前节点地区不受支持';
  }
  const country = probe.countryCode.toUpperCase();
  if (targetApp === 'claude') {
    if (!isValidIsoCountryCode(probe.claudeTraceCountryCode)) {
      return 'Claude 出口 IP 的离线国家校验未完成';
    }
    if (probe.claudeTraceCountryCode.toUpperCase() !== country) {
      return 'Claude 出口 IP 的离线归属与节点出口国家不一致';
    }
  }
  if (serviceCountry?.toUpperCase() !== country) {
    return '目标服务识别地区与出口国家不一致';
  }
  return null;
}
