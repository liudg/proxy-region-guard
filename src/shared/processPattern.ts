export type PatternMode = 'wildcard' | 'regex';

export interface PatternInspection {
  valid: boolean;
  normalized: string;
  mode: PatternMode;
  regex?: RegExp;
  error?: string;
}

const REGEX_SYNTAX_RE = /[\^$()[\]{}|\\+]|\.\*|\.\+/;
const SLASH_REGEX_RE = /^\/(.+)\/([a-zA-Z]*)$/;

// 用于拦截范围过大的危险规则（如 *.exe / .* / .+）
const CANARY_SYSTEM_PROCESSES = ['svchost.exe', 'explorer.exe', 'dwm.exe', 'notepad.exe'];

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
  } else if (REGEX_SYNTAX_RE.test(normalized)) {
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
    const escaped = normalized
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.');

    const lower = normalized.toLowerCase();
    const hasExtOrTrailingWildcard =
      lower.endsWith('.exe') || normalized.endsWith('*') || normalized.endsWith('?');

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

  const hitsAllCanaries = CANARY_SYSTEM_PROCESSES.every((proc) => compiled.test(proc));
  if (hitsAllCanaries) {
    return {
      valid: false,
      normalized,
      mode,
      error: '规则匹配范围过大（会命中系统基础进程），请限定具体应用前缀，如 claude*.exe',
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
