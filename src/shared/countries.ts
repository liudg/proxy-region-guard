export interface CountryMeta {
  code: string;
  name: string;
  accent: string; // 用于 Windows 端渲染精致国旗徽章的主色调
}

export const COMMON_COUNTRIES: CountryMeta[] = [
  { code: 'US', name: '美国', accent: '#3B82F6' },
  { code: 'JP', name: '日本', accent: '#F43F5E' },
  { code: 'SG', name: '新加坡', accent: '#EC4899' },
  { code: 'HK', name: '中国香港', accent: '#E11D48' },
  { code: 'TW', name: '中国台湾', accent: '#6366F1' },
  { code: 'KR', name: '韩国', accent: '#0EA5E9' },
  { code: 'GB', name: '英国', accent: '#2563EB' },
  { code: 'DE', name: '德国', accent: '#F59E0B' },
  { code: 'NL', name: '荷兰', accent: '#F97316' },
  { code: 'FR', name: '法国', accent: '#3B82F6' },
  { code: 'CA', name: '加拿大', accent: '#EF4444' },
  { code: 'AU', name: '澳大利亚', accent: '#14B8A6' },
  { code: 'MY', name: '马来西亚', accent: '#8B5CF6' },
  { code: 'TH', name: '泰国', accent: '#06B6D4' },
  { code: 'VN', name: '越南', accent: '#EF4444' },
  { code: 'PH', name: '菲律宾', accent: '#3B82F6' },
  { code: 'ID', name: '印度尼西亚', accent: '#F43F5E' },
  { code: 'IN', name: '印度', accent: '#F97316' },
  { code: 'TR', name: '土耳其', accent: '#E11D48' },
  { code: 'RU', name: '俄罗斯', accent: '#2563EB' },
  { code: 'BR', name: '巴西', accent: '#10B981' },
  { code: 'AR', name: '阿根廷', accent: '#38BDF8' },
  { code: 'CH', name: '瑞士', accent: '#EF4444' },
  { code: 'SE', name: '瑞典', accent: '#EAB308' },
  { code: 'IE', name: '爱尔兰', accent: '#10B981' },
  { code: 'AE', name: '阿联酋', accent: '#14B8A6' },
  { code: 'CN', name: '中国大陆', accent: '#EF4444' },
];

const COUNTRY_NAME_MAP: Record<string, string> = Object.fromEntries(
  COMMON_COUNTRIES.map((c) => [c.code, c.name])
);

const EXTRA_NAMES: Record<string, string> = {
  MO: '中国澳门',
  IT: '意大利',
  ES: '西班牙',
  PL: '波兰',
  AT: '奥地利',
  BE: '比利时',
  DK: '丹麦',
  FI: '芬兰',
  NO: '挪威',
  PT: '葡萄牙',
  CZ: '捷克',
  HU: '匈牙利',
  RO: '罗马尼亚',
  UA: '乌克兰',
  IL: '以色列',
  SA: '沙特阿拉伯',
  ZA: '南非',
  MX: '墨西哥',
  CL: '智利',
  CO: '哥伦比亚',
  PE: '秘鲁',
  NZ: '新西兰',
  PK: '巴基斯坦',
  BD: '孟加拉国',
  KH: '柬埔寨',
  MM: '缅甸',
  LA: '老挝',
  KP: '朝鲜',
  MN: '蒙古',
  KZ: '哈萨克斯坦',
};

let displayNames: Intl.DisplayNames | null = null;
try {
  displayNames = new Intl.DisplayNames(['zh-CN'], { type: 'region' });
} catch {
  displayNames = null;
}

export function getCountryNameZh(code: string | null | undefined): string {
  if (!code) return '未知地区';
  const upper = code.trim().toUpperCase();
  if (!upper || upper === 'UNKNOWN') return '未知地区';
  if (COUNTRY_NAME_MAP[upper]) return COUNTRY_NAME_MAP[upper];
  if (EXTRA_NAMES[upper]) return EXTRA_NAMES[upper];
  if (displayNames) {
    try {
      const intlName = displayNames.of(upper);
      if (intlName && intlName !== upper) return intlName;
    } catch {
      // ignore invalid ISO codes
    }
  }
  return upper;
}

export function getCountryAccent(code: string | null | undefined): string {
  if (!code) return '#64748B';
  const upper = code.trim().toUpperCase();
  const found = COMMON_COUNTRIES.find((c) => c.code === upper);
  return found ? found.accent : '#6366F1';
}
