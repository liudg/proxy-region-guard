import { getCountryNameZh, isValidIsoCountryCode } from './countries';

export const DEFAULT_CHINA_TIMEZONE_ID = 'China Standard Time';
export const DEFAULT_CHINA_REGION_CODE = 'CN';

/**
 * 权威 CLDR IANA 时区 -> Windows TimeZone ID 映射表
 * 覆盖全球主流代理落地城市与多时区大国（美/加/澳/俄/巴/墨/印尼等）
 */
export const IANA_TO_WINDOWS_TZ: Record<string, string> = {
  // 北美 - 美国 / 加拿大 / 墨西哥
  'America/Los_Angeles': 'Pacific Standard Time',
  'US/Pacific': 'Pacific Standard Time',
  'America/Vancouver': 'Pacific Standard Time',
  'America/Tijuana': 'Pacific Standard Time (Mexico)',
  'America/Denver': 'Mountain Standard Time',
  'America/Boise': 'Mountain Standard Time',
  'US/Mountain': 'Mountain Standard Time',
  'America/Phoenix': 'US Mountain Standard Time',
  'US/Arizona': 'US Mountain Standard Time',
  'America/Edmonton': 'Mountain Standard Time',
  'America/Calgary': 'Mountain Standard Time',
  'America/Chihuahua': 'Mountain Standard Time (Mexico)',
  'America/Mazatlan': 'Mountain Standard Time (Mexico)',
  'America/Chicago': 'Central Standard Time',
  'US/Central': 'Central Standard Time',
  'America/Winnipeg': 'Central Standard Time',
  'America/Regina': 'Canada Central Standard Time',
  'America/Mexico_City': 'Central Standard Time (Mexico)',
  'America/Monterrey': 'Central Standard Time (Mexico)',
  'America/Cancun': 'Eastern Standard Time (Mexico)',
  'America/New_York': 'Eastern Standard Time',
  'America/Detroit': 'Eastern Standard Time',
  'America/Kentucky/Louisville': 'Eastern Standard Time',
  'US/Eastern': 'Eastern Standard Time',
  'America/Indiana/Indianapolis': 'US Eastern Standard Time',
  'America/Toronto': 'Eastern Standard Time',
  'America/Montreal': 'Eastern Standard Time',
  'America/Halifax': 'Atlantic Standard Time',
  'America/St_Johns': 'Newfoundland Standard Time',
  'America/Anchorage': 'Alaskan Standard Time',
  'America/Juneau': 'Alaskan Standard Time',
  'Pacific/Honolulu': 'Hawaiian Standard Time',
  'US/Hawaii': 'Hawaiian Standard Time',
  'America/Adak': 'Aleutian Standard Time',
  'America/Whitehorse': 'Yukon Standard Time',
  'America/Puerto_Rico': 'SA Western Standard Time',

  // 拉美
  'America/Sao_Paulo': 'E. South America Standard Time',
  'America/Fortaleza': 'SA Eastern Standard Time',
  'America/Recife': 'SA Eastern Standard Time',
  'America/Bahia': 'Bahia Standard Time',
  'America/Manaus': 'SA Western Standard Time',
  'America/Cuiaba': 'Central Brazilian Standard Time',
  'America/Buenos_Aires': 'Argentina Standard Time',
  'America/Argentina/Buenos_Aires': 'Argentina Standard Time',
  'America/Santiago': 'Pacific SA Standard Time',
  'America/Bogota': 'SA Pacific Standard Time',
  'America/Lima': 'SA Pacific Standard Time',
  'America/Panama': 'SA Pacific Standard Time',
  'America/Caracas': 'Venezuela Standard Time',
  'America/Montevideo': 'Montevideo Standard Time',
  'America/Asuncion': 'Paraguay Standard Time',
  'America/Guatemala': 'Central America Standard Time',
  'America/Costa_Rica': 'Central America Standard Time',

  // 亚洲 - 东亚 / 东南亚 / 南亚 / 中亚 / 中东
  'Asia/Shanghai': 'China Standard Time',
  'Asia/Chongqing': 'China Standard Time',
  'Asia/Harbin': 'China Standard Time',
  'Asia/Urumqi': 'China Standard Time',
  'Asia/Hong_Kong': 'China Standard Time',
  'Asia/Macau': 'China Standard Time',
  'Asia/Taipei': 'Taipei Standard Time',
  'Asia/Tokyo': 'Tokyo Standard Time',
  'Asia/Seoul': 'Korea Standard Time',
  'Asia/Pyongyang': 'North Korea Standard Time',
  'Asia/Singapore': 'Singapore Standard Time',
  'Asia/Kuala_Lumpur': 'Singapore Standard Time',
  'Asia/Kuching': 'Singapore Standard Time',
  'Asia/Manila': 'Singapore Standard Time',
  'Asia/Brunei': 'Singapore Standard Time',
  'Asia/Makassar': 'Singapore Standard Time',
  'Asia/Bangkok': 'SE Asia Standard Time',
  'Asia/Ho_Chi_Minh': 'SE Asia Standard Time',
  'Asia/Saigon': 'SE Asia Standard Time',
  'Asia/Jakarta': 'SE Asia Standard Time',
  'Asia/Phnom_Penh': 'SE Asia Standard Time',
  'Asia/Vientiane': 'SE Asia Standard Time',
  'Asia/Jayapura': 'Tokyo Standard Time',
  'Asia/Yangon': 'Myanmar Standard Time',
  'Asia/Rangoon': 'Myanmar Standard Time',
  'Asia/Kolkata': 'India Standard Time',
  'Asia/Calcutta': 'India Standard Time',
  'Asia/Colombo': 'Sri Lanka Standard Time',
  'Asia/Kathmandu': 'Nepal Standard Time',
  'Asia/Dhaka': 'Bangladesh Standard Time',
  'Asia/Karachi': 'Pakistan Standard Time',
  'Asia/Kabul': 'Afghanistan Standard Time',
  'Asia/Tashkent': 'West Asia Standard Time',
  'Asia/Almaty': 'Central Asia Standard Time',
  'Asia/Qyzylorda': 'Qyzylorda Standard Time',
  'Asia/Bishkek': 'Central Asia Standard Time',
  'Asia/Ulaanbaatar': 'Ulaanbaatar Standard Time',
  'Asia/Dubai': 'Arabian Standard Time',
  'Asia/Muscat': 'Arabian Standard Time',
  'Asia/Riyadh': 'Arab Standard Time',
  'Asia/Qatar': 'Arab Standard Time',
  'Asia/Kuwait': 'Arab Standard Time',
  'Asia/Bahrain': 'Arab Standard Time',
  'Asia/Baghdad': 'Arabic Standard Time',
  'Asia/Tehran': 'Iran Standard Time',
  'Asia/Jerusalem': 'Israel Standard Time',
  'Asia/Tel_Aviv': 'Israel Standard Time',
  'Asia/Amman': 'Jordan Standard Time',
  'Asia/Beirut': 'Middle East Standard Time',
  'Asia/Damascus': 'Syria Standard Time',
  'Asia/Baku': 'Azerbaijan Standard Time',
  'Asia/Tbilisi': 'Georgian Standard Time',
  'Asia/Yerevan': 'Caucasus Standard Time',

  // 欧洲 & 俄罗斯
  'Europe/London': 'GMT Standard Time',
  'Europe/Dublin': 'GMT Standard Time',
  'Europe/Lisbon': 'GMT Standard Time',
  'Atlantic/Reykjavik': 'Greenwich Standard Time',
  'Europe/Berlin': 'W. Europe Standard Time',
  'Europe/Amsterdam': 'W. Europe Standard Time',
  'Europe/Vienna': 'W. Europe Standard Time',
  'Europe/Rome': 'W. Europe Standard Time',
  'Europe/Zurich': 'W. Europe Standard Time',
  'Europe/Stockholm': 'W. Europe Standard Time',
  'Europe/Oslo': 'W. Europe Standard Time',
  'Europe/Luxembourg': 'W. Europe Standard Time',
  'Europe/Paris': 'Romance Standard Time',
  'Europe/Madrid': 'Romance Standard Time',
  'Europe/Brussels': 'Romance Standard Time',
  'Europe/Copenhagen': 'Romance Standard Time',
  'Europe/Warsaw': 'Central European Standard Time',
  'Europe/Prague': 'Central Europe Standard Time',
  'Europe/Budapest': 'Central Europe Standard Time',
  'Europe/Belgrade': 'Central Europe Standard Time',
  'Europe/Bratislava': 'Central Europe Standard Time',
  'Europe/Ljubljana': 'Central Europe Standard Time',
  'Europe/Zagreb': 'Central Europe Standard Time',
  'Europe/Helsinki': 'FLE Standard Time',
  'Europe/Kyiv': 'FLE Standard Time',
  'Europe/Kiev': 'FLE Standard Time',
  'Europe/Sofia': 'FLE Standard Time',
  'Europe/Tallinn': 'FLE Standard Time',
  'Europe/Riga': 'FLE Standard Time',
  'Europe/Vilnius': 'FLE Standard Time',
  'Europe/Bucharest': 'GTB Standard Time',
  'Europe/Athens': 'GTB Standard Time',
  'Europe/Istanbul': 'Turkey Standard Time',
  'Asia/Istanbul': 'Turkey Standard Time',
  'Europe/Minsk': 'Belarus Standard Time',
  'Europe/Kaliningrad': 'Kaliningrad Standard Time',
  'Europe/Moscow': 'Russian Standard Time',
  'Europe/Simferopol': 'Russian Standard Time',
  'Europe/Volgograd': 'Volgograd Standard Time',
  'Europe/Samara': 'Russia Time Zone 3',
  'Asia/Yekaterinburg': 'Ekaterinburg Standard Time',
  'Asia/Omsk': 'Omsk Standard Time',
  'Asia/Novosibirsk': 'N. Central Asia Standard Time',
  'Asia/Krasnoyarsk': 'North Asia Standard Time',
  'Asia/Irkutsk': 'North Asia East Standard Time',
  'Asia/Yakutsk': 'Yakutsk Standard Time',
  'Asia/Vladivostok': 'Vladivostok Standard Time',
  'Asia/Sakhalin': 'Sakhalin Standard Time',
  'Asia/Kamchatka': 'Kamchatka Standard Time',

  // 大洋洲
  'Australia/Sydney': 'AUS Eastern Standard Time',
  'Australia/Melbourne': 'AUS Eastern Standard Time',
  'Australia/Canberra': 'AUS Eastern Standard Time',
  'Australia/Brisbane': 'E. Australia Standard Time',
  'Australia/Adelaide': 'Cen. Australia Standard Time',
  'Australia/Darwin': 'AUS Central Standard Time',
  'Australia/Perth': 'W. Australia Standard Time',
  'Australia/Hobart': 'Tasmania Standard Time',
  'Pacific/Auckland': 'New Zealand Standard Time',
  'Pacific/Fiji': 'Fiji Standard Time',
  'Pacific/Guam': 'West Pacific Standard Time',

  // 非洲
  'Africa/Johannesburg': 'South Africa Standard Time',
  'Africa/Cairo': 'Egypt Standard Time',
  'Africa/Casablanca': 'Morocco Standard Time',
  'Africa/Lagos': 'W. Central Africa Standard Time',
  'Africa/Nairobi': 'E. Africa Standard Time',
  'Etc/UTC': 'UTC',
  UTC: 'UTC',
};

/**
 * 国家/地区 ISO 代码 -> 默认代表性 Windows TimeZone ID 兜底表
 */
export const COUNTRY_DEFAULT_WINDOWS_TZ: Record<string, string> = {
  CN: 'China Standard Time',
  HK: 'China Standard Time',
  MO: 'China Standard Time',
  TW: 'Taipei Standard Time',
  US: 'Pacific Standard Time',
  JP: 'Tokyo Standard Time',
  SG: 'Singapore Standard Time',
  KR: 'Korea Standard Time',
  KP: 'North Korea Standard Time',
  GB: 'GMT Standard Time',
  IE: 'GMT Standard Time',
  PT: 'GMT Standard Time',
  IS: 'Greenwich Standard Time',
  DE: 'W. Europe Standard Time',
  NL: 'W. Europe Standard Time',
  CH: 'W. Europe Standard Time',
  SE: 'W. Europe Standard Time',
  NO: 'W. Europe Standard Time',
  AT: 'W. Europe Standard Time',
  IT: 'W. Europe Standard Time',
  LU: 'W. Europe Standard Time',
  FR: 'Romance Standard Time',
  ES: 'Romance Standard Time',
  BE: 'Romance Standard Time',
  DK: 'Romance Standard Time',
  PL: 'Central European Standard Time',
  CZ: 'Central Europe Standard Time',
  HU: 'Central Europe Standard Time',
  SK: 'Central Europe Standard Time',
  SI: 'Central Europe Standard Time',
  RS: 'Central Europe Standard Time',
  HR: 'Central Europe Standard Time',
  FI: 'FLE Standard Time',
  UA: 'FLE Standard Time',
  EE: 'FLE Standard Time',
  LV: 'FLE Standard Time',
  LT: 'FLE Standard Time',
  BG: 'FLE Standard Time',
  RO: 'GTB Standard Time',
  GR: 'GTB Standard Time',
  TR: 'Turkey Standard Time',
  RU: 'Russian Standard Time',
  BY: 'Belarus Standard Time',
  CA: 'Eastern Standard Time',
  MX: 'Central Standard Time (Mexico)',
  PA: 'SA Pacific Standard Time',
  CR: 'Central America Standard Time',
  GT: 'Central America Standard Time',
  VE: 'Venezuela Standard Time',
  UY: 'Montevideo Standard Time',
  PY: 'Paraguay Standard Time',
  PR: 'SA Western Standard Time',
  AU: 'AUS Eastern Standard Time',
  NZ: 'New Zealand Standard Time',
  FJ: 'Fiji Standard Time',
  GU: 'West Pacific Standard Time',
  MY: 'Singapore Standard Time',
  PH: 'Singapore Standard Time',
  BN: 'Singapore Standard Time',
  TH: 'SE Asia Standard Time',
  VN: 'SE Asia Standard Time',
  ID: 'SE Asia Standard Time',
  KH: 'SE Asia Standard Time',
  LA: 'SE Asia Standard Time',
  MM: 'Myanmar Standard Time',
  IN: 'India Standard Time',
  PK: 'Pakistan Standard Time',
  BD: 'Bangladesh Standard Time',
  LK: 'Sri Lanka Standard Time',
  NP: 'Nepal Standard Time',
  AF: 'Afghanistan Standard Time',
  KZ: 'Central Asia Standard Time',
  KG: 'Central Asia Standard Time',
  UZ: 'West Asia Standard Time',
  MN: 'Ulaanbaatar Standard Time',
  AE: 'Arabian Standard Time',
  OM: 'Arabian Standard Time',
  SA: 'Arab Standard Time',
  QA: 'Arab Standard Time',
  KW: 'Arab Standard Time',
  BH: 'Arab Standard Time',
  IQ: 'Arabic Standard Time',
  IR: 'Iran Standard Time',
  IL: 'Israel Standard Time',
  JO: 'Jordan Standard Time',
  LB: 'Middle East Standard Time',
  SY: 'Syria Standard Time',
  AZ: 'Azerbaijan Standard Time',
  GE: 'Georgian Standard Time',
  AM: 'Caucasus Standard Time',
  EG: 'Egypt Standard Time',
  ZA: 'South Africa Standard Time',
  NG: 'W. Central Africa Standard Time',
  KE: 'E. Africa Standard Time',
  MA: 'Morocco Standard Time',
  BR: 'E. South America Standard Time',
  AR: 'Argentina Standard Time',
  CL: 'Pacific SA Standard Time',
  CO: 'SA Pacific Standard Time',
  PE: 'SA Pacific Standard Time',
};

/**
 * 多时区大国合法的真实 Windows TimeZone ID 集合
 * 用于精准判断当前 Windows 时区是否属于目标国家，以及决定是否需要联网识别城市级时区
 */
const MULTI_TZ_COUNTRY_VALID_ZONES: Record<string, string[]> = {
  US: [
    'Pacific Standard Time',
    'Mountain Standard Time',
    'US Mountain Standard Time',
    'Central Standard Time',
    'Eastern Standard Time',
    'US Eastern Standard Time',
    'Alaskan Standard Time',
    'Hawaiian Standard Time',
    'Aleutian Standard Time',
  ],
  CA: [
    'Pacific Standard Time',
    'Mountain Standard Time',
    'Yukon Standard Time',
    'Central Standard Time',
    'Canada Central Standard Time',
    'Eastern Standard Time',
    'Atlantic Standard Time',
    'Newfoundland Standard Time',
  ],
  AU: [
    'AUS Eastern Standard Time',
    'E. Australia Standard Time',
    'Cen. Australia Standard Time',
    'AUS Central Standard Time',
    'W. Australia Standard Time',
    'Tasmania Standard Time',
    'Aus Central W. Standard Time',
    'Lord Howe Standard Time',
  ],
  RU: [
    'Kaliningrad Standard Time',
    'Russian Standard Time',
    'Volgograd Standard Time',
    'Russia Time Zone 3',
    'Saratov Standard Time',
    'Astrakhan Standard Time',
    'Ekaterinburg Standard Time',
    'Omsk Standard Time',
    'N. Central Asia Standard Time',
    'Altai Standard Time',
    'Tomsk Standard Time',
    'North Asia Standard Time',
    'North Asia East Standard Time',
    'Transbaikal Standard Time',
    'Yakutsk Standard Time',
    'Vladivostok Standard Time',
    'Magadan Standard Time',
    'Sakhalin Standard Time',
    'Russia Time Zone 10',
    'Russia Time Zone 11',
    'Kamchatka Standard Time',
  ],
  BR: [
    'E. South America Standard Time',
    'SA Eastern Standard Time',
    'Bahia Standard Time',
    'SA Western Standard Time',
    'Central Brazilian Standard Time',
    'Tocantins Standard Time',
  ],
  MX: [
    'Central Standard Time (Mexico)',
    'Mountain Standard Time (Mexico)',
    'Pacific Standard Time (Mexico)',
    'Eastern Standard Time (Mexico)',
  ],
  ID: ['SE Asia Standard Time', 'Singapore Standard Time', 'Tokyo Standard Time'],
  KZ: ['Central Asia Standard Time', 'West Asia Standard Time', 'Qyzylorda Standard Time'],
  MN: ['Ulaanbaatar Standard Time', 'W. Mongolia Standard Time'],
};

export function isMultiTimeZoneCountry(countryCode: string | null | undefined): boolean {
  if (!countryCode) return false;
  return Boolean(MULTI_TZ_COUNTRY_VALID_ZONES[countryCode.trim().toUpperCase()]);
}

export function hasOfflineTimeZoneMapping(countryCode: string | null | undefined): boolean {
  if (!countryCode) return false;
  return Boolean(COUNTRY_DEFAULT_WINDOWS_TZ[countryCode.trim().toUpperCase()]);
}

export function mapIanaToWindowsTimeZone(ianaZone: string | null | undefined): string | null {
  if (!ianaZone) return null;
  const trimmed = ianaZone.trim();
  if (!trimmed) return null;

  if (IANA_TO_WINDOWS_TZ[trimmed]) {
    return IANA_TO_WINDOWS_TZ[trimmed];
  }

  const lower = trimmed.toLowerCase();
  for (const [k, v] of Object.entries(IANA_TO_WINDOWS_TZ)) {
    if (k.toLowerCase() === lower) {
      return v;
    }
  }

  return null;
}

export function resolveWindowsTimeZoneForCountry(
  countryCode: string,
  ianaZone?: string | null
): { windowsTimeZoneId: string; fromExactIp: boolean } {
  const upper = countryCode.trim().toUpperCase();
  const mappedFromIana = mapIanaToWindowsTimeZone(ianaZone);

  if (mappedFromIana) {
    const validMulti = MULTI_TZ_COUNTRY_VALID_ZONES[upper];
    if (validMulti) {
      if (validMulti.some((z) => z.toLowerCase() === mappedFromIana.toLowerCase())) {
        return { windowsTimeZoneId: mappedFromIana, fromExactIp: true };
      }
      // 不在目标多时区国合法集合内时丢弃，安全回退到该国默认时区
    } else if (COUNTRY_DEFAULT_WINDOWS_TZ[upper]) {
      if (COUNTRY_DEFAULT_WINDOWS_TZ[upper].toLowerCase() === mappedFromIana.toLowerCase()) {
        return { windowsTimeZoneId: mappedFromIana, fromExactIp: true };
      }
      // 单一时区国家严格使用权威标准时区，确保与 isWindowsLocaleMatchingCountry 100% 一致
    } else if (
      upper === DEFAULT_CHINA_REGION_CODE
        ? mappedFromIana === DEFAULT_CHINA_TIMEZONE_ID
        : mappedFromIana !== DEFAULT_CHINA_TIMEZONE_ID
    ) {
      return { windowsTimeZoneId: mappedFromIana, fromExactIp: true };
    }
  }

  const fallback = COUNTRY_DEFAULT_WINDOWS_TZ[upper] || 'UTC';
  return { windowsTimeZoneId: fallback, fromExactIp: false };
}

export function isWindowsLocaleMatchingCountry(
  winTimeZoneId: string | null | undefined,
  winRegionCode: string | null | undefined,
  targetCountryCode: string | null | undefined
): boolean {
  if (!isValidIsoCountryCode(targetCountryCode)) {
    return true;
  }
  const target = targetCountryCode.trim().toUpperCase();
  const curRegion = (winRegionCode || '').trim().toUpperCase();
  const curTz = (winTimeZoneId || '').trim();

  if (!curRegion || curRegion !== target) {
    return false;
  }

  if (!curTz) {
    return false;
  }

  const validMulti = MULTI_TZ_COUNTRY_VALID_ZONES[target];
  if (validMulti) {
    return validMulti.some((z) => z.toLowerCase() === curTz.toLowerCase());
  }

  const expectedTz = COUNTRY_DEFAULT_WINDOWS_TZ[target];
  if (expectedTz) {
    return curTz.toLowerCase() === expectedTz.toLowerCase();
  }

  // 未在静态表中的冷门小国：只要系统区域匹配，且非中国大陆时区（避免未改时区漏网）即视为匹配
  return target === DEFAULT_CHINA_REGION_CODE
    ? curTz.toLowerCase() === DEFAULT_CHINA_TIMEZONE_ID.toLowerCase()
    : curTz.toLowerCase() !== DEFAULT_CHINA_TIMEZONE_ID.toLowerCase();
}

export function getWindowsRegionDisplayNameZh(code: string | null | undefined): string {
  if (!code) return '未知';
  const upper = code.trim().toUpperCase();
  if (upper === 'CN') return '中国';
  if (upper === 'HK') return '香港特别行政区';
  if (upper === 'MO') return '澳门特别行政区';
  if (upper === 'TW') return '台湾';
  return getCountryNameZh(upper);
}
