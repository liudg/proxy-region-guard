import { isValidIsoCountryCode } from './countries';
import { ProbeResult } from './types';

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
  if (probe.regionMismatchDetail) return probe.regionMismatchDetail;
  const country = probe.countryCode.toUpperCase();
  if (serviceCountry?.toUpperCase() !== country) {
    return '目标服务识别地区与出口国家不一致';
  }
  return null;
}
