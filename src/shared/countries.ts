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

const NON_COUNTRY_CODES = new Set([
  'UNKNOWN',
  'XX',
  'T1',
  'EU',
  'AP',
  'A1',
  'A2',
  'O1',
  'ZZ',
]);

const ISO_ALPHA3_TO_ALPHA2: Record<string, string> = {
  USA: 'US',
  JPN: 'JP',
  SGP: 'SG',
  HKG: 'HK',
  TWN: 'TW',
  KOR: 'KR',
  GBR: 'GB',
  DEU: 'DE',
  NLD: 'NL',
  FRA: 'FR',
  CAN: 'CA',
  AUS: 'AU',
  MYS: 'MY',
  THA: 'TH',
  VNM: 'VN',
  PHL: 'PH',
  IDN: 'ID',
  IND: 'IN',
  TUR: 'TR',
  RUS: 'RU',
  BRA: 'BR',
  ARG: 'AR',
  CHE: 'CH',
  SWE: 'SE',
  IRL: 'IE',
  ARE: 'AE',
  CHN: 'CN',
  MAC: 'MO',
  ITA: 'IT',
  ESP: 'ES',
  POL: 'PL',
  AUT: 'AT',
  BEL: 'BE',
  DNK: 'DK',
  FIN: 'FI',
  NOR: 'NO',
  PRT: 'PT',
  CZE: 'CZ',
  HUN: 'HU',
  ROU: 'RO',
  UKR: 'UA',
  ISR: 'IL',
  SAU: 'SA',
  ZAF: 'ZA',
  MEX: 'MX',
  CHL: 'CL',
  COL: 'CO',
  PER: 'PE',
  NZL: 'NZ',
  PAK: 'PK',
  BGD: 'BD',
  KHM: 'KH',
  MMR: 'MM',
  LAO: 'LA',
  PRK: 'KP',
  MNG: 'MN',
  KAZ: 'KZ',
};

export function normalizeIsoCountryCode(code: string | null | undefined): string | null {
  if (!code) return null;
  const upper = code.trim().toUpperCase();
  if (upper === 'UK') return 'GB';
  if (/^[A-Z]{3}$/.test(upper) && ISO_ALPHA3_TO_ALPHA2[upper]) {
    return ISO_ALPHA3_TO_ALPHA2[upper];
  }
  return isValidIsoCountryCode(upper) ? upper : null;
}

export function isValidIsoCountryCode(code: string | null | undefined): code is string {
  if (!code) return false;
  const upper = code.trim().toUpperCase();
  return /^[A-Z]{2}$/.test(upper) && !NON_COUNTRY_CODES.has(upper);
}

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

export interface CountryAliasEntry {
  code: string;
  shortNameZh: string;
  zhKeywords: string[];
  enKeywords: string[];
}

export const COUNTRY_SEARCH_ALIASES: CountryAliasEntry[] = [
  {
    code: 'HK',
    shortNameZh: '香港',
    zhKeywords: ['香港', '中国香港', '深港', '沪港', '广港', '港线', '将军澳', '九龙', '新界'],
    enKeywords: ['hk', 'hkg', 'hongkong', 'hong kong'],
  },
  {
    code: 'TW',
    shortNameZh: '台湾',
    zhKeywords: ['台湾', '中国台湾', '台北', '台中', '高雄', '彰化', '新北', '桃园', '新竹', '台线'],
    enKeywords: ['tw', 'twn', 'taiwan', 'taipei', 'tpe', 'khh'],
  },
  {
    code: 'JP',
    shortNameZh: '日本',
    zhKeywords: ['日本', '东京', '大阪', '名古屋', '埼玉', '福冈', '千叶', '横滨', '日线'],
    enKeywords: ['jp', 'jpn', 'japan', 'tokyo', 'osaka', 'nagoya', 'nrt', 'hnd', 'kix', 'tyo'],
  },
  {
    code: 'SG',
    shortNameZh: '新加坡',
    zhKeywords: ['新加坡', '狮城', '星洲', '新线'],
    enKeywords: ['sg', 'sgp', 'singapore', 'sin'],
  },
  {
    code: 'US',
    shortNameZh: '美国',
    zhKeywords: [
      '美国',
      '美西',
      '美东',
      '美中',
      '美南',
      '硅谷',
      '圣何塞',
      '洛杉矶',
      '西雅图',
      '纽约',
      '芝加哥',
      '达拉斯',
      '凤凰城',
      '波特兰',
      '丹佛',
      '亚特兰大',
      '弗吉尼亚',
      '阿什本',
      '迈阿密',
      '旧金山',
      '休斯顿',
      '盐湖城',
      '拉斯维加斯',
    ],
    enKeywords: [
      'us',
      'usa',
      'america',
      'united states',
      'silicon valley',
      'los angeles',
      'san jose',
      'seattle',
      'new york',
      'chicago',
      'dallas',
      'phoenix',
      'portland',
      'denver',
      'atlanta',
      'ashburn',
      'miami',
      'lax',
      'sjc',
      'sea',
      'ord',
      'jfk',
      'ewr',
      'dfw',
      'iad',
      'phx',
      'pdx',
    ],
  },
  {
    code: 'KR',
    shortNameZh: '韩国',
    zhKeywords: ['韩国', '首尔', '春川', '釜山', '仁川', '韩线'],
    enKeywords: ['kr', 'kor', 'korea', 'seoul', 'busan', 'chuncheon', 'icn', 'sel'],
  },
  {
    code: 'GB',
    shortNameZh: '英国',
    zhKeywords: ['英国', '伦敦', '曼彻斯特', '考文垂', '伯明翰', '苏格兰', '英格兰'],
    enKeywords: ['gb', 'uk', 'gbr', 'united kingdom', 'britain', 'england', 'london', 'manchester', 'lon', 'lhr'],
  },
  {
    code: 'DE',
    shortNameZh: '德国',
    zhKeywords: ['德国', '法兰克福', '慕尼黑', '柏林', '纽伦堡', '杜塞尔多夫'],
    enKeywords: ['de', 'deu', 'germany', 'frankfurt', 'munich', 'berlin', 'fra', 'muc', 'ber'],
  },
  {
    code: 'NL',
    shortNameZh: '荷兰',
    zhKeywords: ['荷兰', '阿姆斯特丹', '鹿特丹'],
    enKeywords: ['nl', 'nld', 'netherlands', 'holland', 'amsterdam', 'ams'],
  },
  {
    code: 'FR',
    shortNameZh: '法国',
    zhKeywords: ['法国', '巴黎', '马赛', '里昂'],
    enKeywords: ['fr', 'france', 'paris', 'marseille', 'cdg', 'par'],
  },
  {
    code: 'CA',
    shortNameZh: '加拿大',
    zhKeywords: ['加拿大', '多伦多', '温哥华', '蒙特利尔', '渥太华'],
    enKeywords: ['ca', 'can', 'canada', 'toronto', 'vancouver', 'montreal', 'yyz', 'yvr', 'yul'],
  },
  {
    code: 'AU',
    shortNameZh: '澳大利亚',
    zhKeywords: ['澳大利亚', '澳洲', '悉尼', '墨尔本', '珀斯', '布里斯班'],
    enKeywords: ['au', 'aus', 'australia', 'sydney', 'melbourne', 'perth', 'syd', 'mel', 'per'],
  },
  {
    code: 'MY',
    shortNameZh: '马来西亚',
    zhKeywords: ['马来西亚', '大马', '吉隆坡', '柔佛', '槟城'],
    enKeywords: ['my', 'mys', 'malaysia', 'kuala lumpur', 'kul'],
  },
  {
    code: 'TH',
    shortNameZh: '泰国',
    zhKeywords: ['泰国', '曼谷', '清迈'],
    enKeywords: ['th', 'tha', 'thailand', 'bangkok', 'bkk'],
  },
  {
    code: 'VN',
    shortNameZh: '越南',
    zhKeywords: ['越南', '河内', '胡志明', '岘港'],
    enKeywords: ['vn', 'vnm', 'vietnam', 'hanoi', 'ho chi minh', 'han', 'sgn'],
  },
  {
    code: 'PH',
    shortNameZh: '菲律宾',
    zhKeywords: ['菲律宾', '马尼拉'],
    enKeywords: ['ph', 'phl', 'philippines', 'manila', 'mnl'],
  },
  {
    code: 'ID',
    shortNameZh: '印尼',
    zhKeywords: ['印尼', '印度尼西亚', '雅加达', '巴厘岛'],
    enKeywords: ['id', 'idn', 'indonesia', 'jakarta', 'cgk'],
  },
  {
    code: 'IN',
    shortNameZh: '印度',
    zhKeywords: ['印度', '孟买', '新德里', '金奈', '班加罗尔'],
    enKeywords: ['in', 'ind', 'india', 'mumbai', 'delhi', 'chennai', 'bom', 'del'],
  },
  {
    code: 'TR',
    shortNameZh: '土耳其',
    zhKeywords: ['土耳其', '伊斯坦布尔', '安卡拉'],
    enKeywords: ['tr', 'tur', 'turkey', 'turkiye', 'istanbul', 'ist'],
  },
  {
    code: 'RU',
    shortNameZh: '俄罗斯',
    zhKeywords: ['俄罗斯', '莫斯科', '圣彼得堡', '伯力', '新西伯利亚', '海参崴'],
    enKeywords: ['ru', 'rus', 'russia', 'moscow', 'svo', 'dme'],
  },
  {
    code: 'BR',
    shortNameZh: '巴西',
    zhKeywords: ['巴西', '圣保罗', '里约'],
    enKeywords: ['br', 'bra', 'brazil', 'sao paulo', 'gru'],
  },
  {
    code: 'AR',
    shortNameZh: '阿根廷',
    zhKeywords: ['阿根廷', '布宜诺斯艾利斯'],
    enKeywords: ['ar', 'arg', 'argentina', 'buenos aires', 'eze'],
  },
  {
    code: 'CH',
    shortNameZh: '瑞士',
    zhKeywords: ['瑞士', '苏黎世', '日内瓦'],
    enKeywords: ['ch', 'che', 'switzerland', 'zurich', 'geneva', 'zrh'],
  },
  {
    code: 'SE',
    shortNameZh: '瑞典',
    zhKeywords: ['瑞典', '斯德哥尔摩'],
    enKeywords: ['se', 'swe', 'sweden', 'stockholm', 'arn'],
  },
  {
    code: 'IE',
    shortNameZh: '爱尔兰',
    zhKeywords: ['爱尔兰', '都柏林'],
    enKeywords: ['ie', 'irl', 'ireland', 'dublin', 'dub'],
  },
  {
    code: 'AE',
    shortNameZh: '阿联酋',
    zhKeywords: ['阿联酋', '迪拜', '阿布扎比'],
    enKeywords: ['ae', 'are', 'uae', 'dubai', 'abu dhabi', 'dxb'],
  },
  {
    code: 'MO',
    shortNameZh: '澳门',
    zhKeywords: ['澳门', '中国澳门'],
    enKeywords: ['mo', 'mac', 'macau', 'macao'],
  },
  {
    code: 'IT',
    shortNameZh: '意大利',
    zhKeywords: ['意大利', '米兰', '罗马'],
    enKeywords: ['it', 'ita', 'italy', 'milan', 'rome', 'mxp', 'fco'],
  },
  {
    code: 'ES',
    shortNameZh: '西班牙',
    zhKeywords: ['西班牙', '马德里', '巴塞罗那'],
    enKeywords: ['es', 'esp', 'spain', 'madrid', 'barcelona', 'mad', 'bcn'],
  },
  {
    code: 'PL',
    shortNameZh: '波兰',
    zhKeywords: ['波兰', '华沙'],
    enKeywords: ['pl', 'pol', 'poland', 'warsaw', 'waw'],
  },
  {
    code: 'AT',
    shortNameZh: '奥地利',
    zhKeywords: ['奥地利', '维也纳'],
    enKeywords: ['at', 'aut', 'austria', 'vienna', 'vie'],
  },
  {
    code: 'FI',
    shortNameZh: '芬兰',
    zhKeywords: ['芬兰', '赫尔辛基'],
    enKeywords: ['fi', 'fin', 'finland', 'helsinki', 'hel'],
  },
  {
    code: 'NO',
    shortNameZh: '挪威',
    zhKeywords: ['挪威', '奥斯陆'],
    enKeywords: ['no', 'nor', 'norway', 'oslo', 'osl'],
  },
  {
    code: 'ZA',
    shortNameZh: '南非',
    zhKeywords: ['南非', '约翰内斯堡', '开普敦'],
    enKeywords: ['za', 'zaf', 'south africa', 'johannesburg', 'jnb'],
  },
  {
    code: 'NZ',
    shortNameZh: '新西兰',
    zhKeywords: ['新西兰', '奥克兰'],
    enKeywords: ['nz', 'nzl', 'new zealand', 'auckland', 'akl'],
  },
  {
    code: 'CN',
    shortNameZh: '中国大陆',
    zhKeywords: ['中国大陆', '深圳', '上海', '北京', '广州', '杭州'],
    enKeywords: ['cn', 'chn', 'china'],
  },
];

const COUNTRY_ALIAS_BY_CODE: Record<string, CountryAliasEntry> = Object.fromEntries(
  COUNTRY_SEARCH_ALIASES.map((entry) => [entry.code, entry])
);

const AMBIGUOUS_EN_SHORT_CODES = new Set(['in', 'it', 'at', 'no', 'id', 'my', 'ie', 'se']);

const COUNTRY_EN_MATCHERS: Array<{
  code: string;
  generalRegex: RegExp;
  strictShortCodeRegex: RegExp | null;
}> = COUNTRY_SEARCH_ALIASES.map((entry) => {
  const generalKws = entry.enKeywords.filter((kw) => !AMBIGUOUS_EN_SHORT_CODES.has(kw));
  const strictShortKws = entry.enKeywords.filter((kw) => AMBIGUOUS_EN_SHORT_CODES.has(kw));

  const escapedGeneral = generalKws.map((kw) =>
    kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  );
  const escapedStrict = strictShortKws.map((kw) =>
    kw.toUpperCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  );

  return {
    code: entry.code,
    generalRegex: new RegExp(`(?<![a-zA-Z])(${escapedGeneral.join('|')})(?![a-zA-Z])`, 'i'),
    // 对易与英文介词/缩写冲突的双字母代码（如 IN/IT/AT/NO/ID/MY），要求大写且不紧跟点号（避免匹配 No.1）
    strictShortCodeRegex:
      escapedStrict.length > 0
        ? new RegExp(`(?<![a-zA-Z])(${escapedStrict.join('|')})(?![a-zA-Z.])`)
        : null,
  };
});

export function getShortCountryNameZh(code: string | null | undefined): string {
  if (!code) return '未知';
  const upper = code.trim().toUpperCase();
  if (COUNTRY_ALIAS_BY_CODE[upper]) {
    return COUNTRY_ALIAS_BY_CODE[upper].shortNameZh;
  }
  return getCountryNameZh(upper);
}

/**
 * 从代理节点名称智能推断其归属的 ISO 国家/地区代码（支持 Emoji 国旗、中英文地区/城市名、ISO/机场三字码）
 */
export function inferNodeCountryCode(nodeName: string): string | null {
  if (!nodeName) return null;

  // 1. 优先识别 Unicode 区域指示符国旗 Emoji (例如 🇺🇸 / 🇺🇲 / 🇯🇵 / 🇭🇰)
  const flagMatch = nodeName.match(/\uD83C[\uDDE6-\uDDFF]\uD83C[\uDDE6-\uDDFF]/g);
  if (flagMatch) {
    for (const pair of flagMatch) {
      const chars = Array.from(pair);
      if (chars.length === 2) {
        const c1 = (chars[0].codePointAt(0) || 0) - 0x1f1e6 + 65;
        const c2 = (chars[1].codePointAt(0) || 0) - 0x1f1e6 + 65;
        if (c1 >= 65 && c1 <= 90 && c2 >= 65 && c2 <= 90) {
          const rawCode = String.fromCharCode(c1, c2);
          const normalized =
            rawCode === 'UM' ? 'US' : rawCode === 'UK' ? 'GB' : normalizeIsoCountryCode(rawCode);
          if (normalized) return normalized;
        }
      }
    }
  }

  // 2. 匹配中文国家/地区/城市关键词
  for (const entry of COUNTRY_SEARCH_ALIASES) {
    for (const kw of entry.zhKeywords) {
      if (nodeName.includes(kw)) {
        return entry.code;
      }
    }
  }

  // 3. 匹配非模糊英文国家缩写、全称及常见机场代码 (兼容 US01 / US-SJC / [JP] 等命名)
  for (const item of COUNTRY_EN_MATCHERS) {
    if (item.generalRegex.test(nodeName)) {
      return item.code;
    }
  }

  // 4. 匹配严格大写的双字母代码
  for (const item of COUNTRY_EN_MATCHERS) {
    if (item.strictShortCodeRegex && item.strictShortCodeRegex.test(nodeName)) {
      return item.code;
    }
  }

  return null;
}

/**
 * 构建单个节点的增强检索文本（融合节点名、协议、订阅名以及归属地区的中英文/ISO/城市同义词）
 */
export function buildNodeSearchText(
  nodeName: string,
  nodeType: string,
  groupName: string,
  inferredCountryCode: string | null
): string {
  const parts: string[] = [
    nodeName.toLowerCase(),
    nodeType.toLowerCase(),
    groupName.toLowerCase(),
  ];

  if (inferredCountryCode) {
    const codeUpper = inferredCountryCode.toUpperCase();
    parts.push(codeUpper.toLowerCase());
    const zhFull = getCountryNameZh(codeUpper);
    if (zhFull) parts.push(zhFull.toLowerCase());

    const alias = COUNTRY_ALIAS_BY_CODE[codeUpper];
    if (alias) {
      parts.push(alias.shortNameZh.toLowerCase());
      for (const kw of alias.zhKeywords) {
        parts.push(kw.toLowerCase());
      }
      for (const kw of alias.enKeywords) {
        parts.push(kw.toLowerCase());
      }
    }
  }

  return parts.join(' ');
}

export function matchesNodeSearchToken(
  searchText: string,
  countryCode: string | null,
  token: string
): boolean {
  const queryCountry = normalizeIsoCountryCode(token);
  if (queryCountry && (COUNTRY_NAME_MAP[queryCountry] || EXTRA_NAMES[queryCountry])) {
    return countryCode === queryCountry;
  }
  return searchText.includes(token);
}
