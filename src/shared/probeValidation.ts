import { isValidIsoCountryCode } from './countries';
import { ProbeResult } from './types';

const IPV4_REGEX =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

export function isValidIpAddress(ip: string | null | undefined): boolean {
  if (!ip) return false;
  const trimmed = ip.trim();
  if (!trimmed) return false;
  if (IPV4_REGEX.test(trimmed)) return true;
  if (!trimmed.includes(':')) return false;
  try {
    const parsed = new URL(`http://[${trimmed}]/`);
    return parsed.hostname === `[${trimmed.toLowerCase()}]` || parsed.hostname.startsWith('[');
  } catch {
    return false;
  }
}

export function getTargetServiceVerificationError(
  probe: ProbeResult | null,
  targetApp: 'claude' | 'antigravity' = 'claude'
): string | null {
  if (!probe || !isValidIsoCountryCode(probe.countryCode)) {
    return '尚未获取有效出口国家';
  }
  const serviceCountry = targetApp === 'claude' ? probe.claudeTraceLoc : probe.googleCountryCode;
  const serviceName = targetApp === 'claude' ? 'Claude' : 'Google';
  if (!isValidIsoCountryCode(serviceCountry)) {
    if (targetApp === 'claude' && probe.claudeTraceError) return probe.claudeTraceError;
    return `${serviceName} 地区校验未完成，请重新检测`;
  }
  if (targetApp === 'claude' && !isValidIpAddress(probe.claudeTraceIp)) {
    if (probe.claudeTraceError) return probe.claudeTraceError;
    return 'Claude 出口 IP 校验未完成，请重新检测';
  }
  if (probe.regionMismatchDetail) return probe.regionMismatchDetail;
  const country = probe.countryCode.toUpperCase();
  if (serviceCountry?.toUpperCase() !== country) {
    return '目标服务识别地区与出口国家不一致';
  }
  return null;
}
