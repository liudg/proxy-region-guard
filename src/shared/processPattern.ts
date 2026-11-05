export type PatternMode = 'wildcard' | 'regex';

export interface PatternInspection {
  valid: boolean;
  normalized: string;
  mode: PatternMode;
  regex?: RegExp;
  error?: string;
}

const SLASH_REGEX_RE = /^\/(.+)\/([a-zA-Z]*)$/;
// 仅当包含典型正则结构（首尾锚点 ^/$、分支 |、转义 \、字符组 [...]）时才按无斜杠正则处理，
// 避免误伤 notepad++.exe、vc_redist(x64).exe、claude.* 等合法进程名或通配符
const EXPLICIT_REGEX_RE = /^\^|\$$|[|\\]|\[[^\]]+\]/;

/**
 * 绝不允许被规则命中或强杀的 Windows 系统核心进程与工具链进程
 */
export const CRITICAL_SYSTEM_PROCESSES = [
  'system',
  'smss.exe',
  'csrss.exe',
  'wininit.exe',
  'services.exe',
  'lsass.exe',
  'svchost.exe',
  'winlogon.exe',
  'explorer.exe',
  'dwm.exe',
  'conhost.exe',
  'sihost.exe',
  'taskhostw.exe',
  'spoolsv.exe',
  'fontdrvhost.exe',
  'tasklist.exe',
  'taskkill.exe',
  'reg.exe',
  'tzutil.exe',
  'powershell.exe',
  'cmd.exe',
] as const;

export function inspectProcessPattern(input: string): PatternInspection {
  const normalized = input.trim();
  if (!normalized) {
    return {
      valid: false,
      normalized,
      mode: 'wildcard',
      error: '请输入进程名或匹配规则',
    };
  }

  let mode: PatternMode = 'wildcard';
  let compiled: RegExp;

  const slashMatch = normalized.match(SLASH_REGEX_RE);
  if (slashMatch) {
    mode = 'regex';
    const body = slashMatch[1];
    const rawFlags = slashMatch[2] || '';
    // 移除 g / y 有状态修饰符，确保多次 .test() 稳定，并强制大小写不敏感
    const safeFlags = Array.from(new Set((rawFlags.replace(/[gy]/g, '') + 'i').split(''))).join('');
    try {
      compiled = new RegExp(body, safeFlags);
    } catch (err) {
      return {
        valid: false,
        normalized,
        mode: 'regex',
        error: `正则表达式语法错误: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  } else if (EXPLICIT_REGEX_RE.test(normalized)) {
    mode = 'regex';
    try {
      compiled = new RegExp(normalized, 'i');
    } catch (err) {
      return {
        valid: false,
        normalized,
        mode: 'regex',
        error: `正则表达式语法错误: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  } else {
    mode = 'wildcard';
    if (!/[a-zA-Z0-9\u4e00-\u9fa5]/.test(normalized)) {
      return {
        valid: false,
        normalized,
        mode: 'wildcard',
        error: '规则缺少有效进程名字符或范围过大，请限定具体应用名称，如 claude*.exe',
      };
    }
    const escaped = normalized
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.');

    const lower = normalized.toLowerCase();
    const hasExtOrTrailingWildcard =
      /\.[a-z0-9]{1,8}$/i.test(lower) || normalized.endsWith('*') || normalized.endsWith('?');

    const fullSource = hasExtOrTrailingWildcard
      ? `^(?:${escaped})$`
      : `^(?:${escaped})(?:\\.exe)?$`;

    try {
      compiled = new RegExp(fullSource, 'i');
    } catch (err) {
      return {
        valid: false,
        normalized,
        mode: 'wildcard',
        error: `规则解析失败: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  const hitCritical = CRITICAL_SYSTEM_PROCESSES.find((proc) => compiled.test(proc));
  if (hitCritical) {
    return {
      valid: false,
      normalized,
      mode,
      error: `规则匹配范围过大（会误伤系统关键进程 ${hitCritical}），请限定具体应用名称，如 claude*.exe`,
    };
  }

  return {
    valid: true,
    normalized,
    mode,
    regex: compiled,
  };
}

export function compileValidPatterns(patterns: string[]): Array<{ raw: string; regex: RegExp }> {
  const result: Array<{ raw: string; regex: RegExp }> = [];
  for (const p of patterns) {
    const info = inspectProcessPattern(p);
    if (info.valid && info.regex) {
      result.push({ raw: info.normalized, regex: info.regex });
    }
  }
  return result;
}
