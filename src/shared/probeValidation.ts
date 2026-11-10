import { isValidIsoCountryCode } from './countries';
import { ProbeResult } from './types';

export function getTargetServiceVerificationError(
  probe: ProbeResult | null,
  targetApp: 'claude' | 'antigravity' = 'claude'
): string | null {
  if (!probe || !isValidIsoCountryCode(probe.countryCode)) {
    return '尚未获取有效出口国家';
  }
  const missing: string[] = [];
  if (!isValidIsoCountryCode(probe.googleCountryCode)) missing.push('Google');
  if (targetApp === 'claude' && !isValidIsoCountryCode(probe.claudeTraceLoc)) {
    missing.push('Claude');
  }
  if (missing.length > 0) return `${missing.join('、')} 地区校验未完成，请重新检测`;
  if (probe.regionMismatchDetail) return probe.regionMismatchDetail;
  const country = probe.countryCode.toUpperCase();
  if (
    probe.googleCountryCode?.toUpperCase() !== country ||
    (targetApp === 'claude' && probe.claudeTraceLoc?.toUpperCase() !== country)
  ) {
    return '目标服务识别地区与出口国家不一致';
  }
  return null;
}
