import * as net from 'node:net';

export const MAX_RESPONSE_BYTES = 256 * 1024;
export const MAX_HEADER_BYTES = 64 * 1024;
export const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

export function normalizeProxyUrlScheme(proxyUrl: string): string {
  const trimmed = proxyUrl.trim();
  if (/^socks5?:\/\//i.test(trimmed)) {
    return trimmed.replace(/^socks5?:\/\//i, 'socks5h://');
  }
  return trimmed;
}

export function formatHostForUrl(host: string): string {
  const trimmed = host.trim();
  if (trimmed.includes(':') && !trimmed.startsWith('[')) {
    return `[${trimmed}]`;
  }
  return trimmed;
}

function isPrivateOrReservedIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return true;
  const nums = parts.map((p) => (/^(0|[1-9]\d*)$/.test(p) ? Number(p) : NaN));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = nums;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

export function isLoopbackOrPrivateHost(rawHostname: string): boolean {
  const h = rawHostname.trim().replace(/^\[|\]$/g, '').toLowerCase();
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;

  const ipVer = net.isIP(h);
  if (ipVer === 4) {
    return isPrivateOrReservedIpv4(h);
  }
  if (ipVer === 6) {
    if (h === '::' || h === '::1' || h === '0:0:0:0:0:0:0:1' || h === '0:0:0:0:0:0:0:0') {
      return true;
    }
    if (/^fe[89ab][0-9a-f]:/i.test(h)) return true; // fe80::/10 link-local
    if (/^f[cd][0-9a-f]{2}:/i.test(h)) return true; // fc00::/7 unique local
    if (h.startsWith('::ffff:')) {
      const tail = h.slice('::ffff:'.length);
      if (net.isIP(tail) === 4) {
        return isPrivateOrReservedIpv4(tail);
      }
      // URL parser normalizes ::ffff:127.0.0.1 to ::ffff:7f00:1
      const hexMatch = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(tail);
      if (hexMatch) {
        const hi = parseInt(hexMatch[1], 16);
        const lo = parseInt(hexMatch[2], 16);
        const v4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        return isPrivateOrReservedIpv4(v4);
      }
      return true;
    }
    return false;
  }

  // 拦截纯十进制/十六进制/八进制变形 IP 字面量（如 2130706433、0x7f000001、0177.0.0.1）
  if (/^(0x[0-9a-f]+|\d+)$/i.test(h)) return true;
  if (/^[0-9x.]+$/i.test(h)) return true;

  return false;
}

export function resolveSafeRedirectUrl(
  fromUrl: URL,
  rawLocation: string,
  allowLocalhost = false
): string {
  let nextUrl: URL;
  try {
    nextUrl = new URL(rawLocation, fromUrl);
  } catch {
    throw new Error('重定向地址无效');
  }

  if (nextUrl.protocol !== 'http:' && nextUrl.protocol !== 'https:') {
    throw new Error(`重定向目标协议不受支持: ${nextUrl.protocol}`);
  }
  if (nextUrl.username || nextUrl.password) {
    throw new Error('安全策略拦截：禁止重定向至含凭据的 URL');
  }
  if (fromUrl.protocol === 'https:' && nextUrl.protocol !== 'https:') {
    throw new Error('安全策略拦截：禁止从 HTTPS 重定向降级至明文 HTTP');
  }

  if (isLoopbackOrPrivateHost(nextUrl.hostname)) {
    const isAllowedLocalTestHost =
      allowLocalhost &&
      (nextUrl.hostname === '127.0.0.1' || nextUrl.hostname === 'localhost');
    if (!isAllowedLocalTestHost) {
      throw new Error(`安全策略拦截：禁止重定向至本机或内网地址 (${nextUrl.hostname})`);
    }
  }

  return nextUrl.toString();
}

export function formatNetworkErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    const trimmed = err.message.trim();
    if (trimmed) return trimmed;
    const aggErrors = (err as Error & { errors?: unknown[] }).errors;
    if (Array.isArray(aggErrors) && aggErrors.length > 0) {
      const subMessages = aggErrors
        .map((item) =>
          item instanceof Error ? item.message.trim() : String(item || '').trim()
        )
        .filter(Boolean);
      if (subMessages.length > 0) {
        return subMessages.join('; ');
      }
    }
    const code = (err as NodeJS.ErrnoException).code;
    if (code) return `connect ${code}`;
    return err.name || '网络连接异常';
  }
  return String(err || '网络连接异常').trim() || '网络连接异常';
}

function matchesLocalProxyRefusedMessage(errMsg: string, effectivePort: number): boolean {
  if (!/ECONNREFUSED/i.test(errMsg)) return false;
  // 剥离头部的探测目标 URL 前缀（兼容带端口 URL，如 https://example.com:27897/trace：...）
  const body = errMsg.replace(/^https?:\/\/[^\s：]+?(?:：|:\s+)/i, '').trim();
  if (!/ECONNREFUSED/i.test(body)) {
    return false;
  }

  // 显式匹配本机回环地址 + 专属代理端口（兼容 127.0.0.1、localhost、[::1]、::1）
  const loopbackEndpointRe = new RegExp(
    `(?:^|[\\s(\\[])(?:127\\.0\\.0\\.1|localhost|\\[::1\\]|::1):${effectivePort}(?!\\d)`,
    'i'
  );
  if (loopbackEndpointRe.test(body)) {
    return true;
  }

  // 若错误信息包含任何其他显式地址:端口（如远端 IP:端口、非当前代理端口或 IPv6 地址），绝不误判为本机代理拒绝
  if (/(?:[0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):\d+\b/.test(body)) {
    return false;
  }
  if (/[0-9a-fA-F]*:[0-9a-fA-F]*:[0-9a-fA-F:]+/.test(body)) {
    return false;
  }

  return true;
}

export function isLocalProxyRefusedCause(error: unknown, proxyUrl: string | null): boolean {
  if (!proxyUrl || !error) return false;
  let parsed: URL;
  try {
    parsed = new URL(normalizeProxyUrlScheme(proxyUrl));
  } catch {
    return false;
  }
  const proxyHost = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (proxyHost !== '127.0.0.1' && proxyHost !== 'localhost' && proxyHost !== '::1') {
    return false;
  }
  const proto = parsed.protocol.toLowerCase();
  const effectivePort = Number(
    parsed.port || (proto === 'https:' ? '443' : proto.startsWith('socks') ? '1080' : '80')
  );
  if (!Number.isInteger(effectivePort) || effectivePort <= 0) {
    return false;
  }

  const checkSingleCause = (cause: unknown): boolean | null => {
    if (!cause || typeof cause !== 'object') return null;
    const nested = (cause as { errors?: unknown[] }).errors;
    if (Array.isArray(nested) && nested.length > 0) {
      let sawStructured = false;
      for (const item of nested) {
        const res = checkSingleCause(item);
        if (res === true) return true;
        if (res === false) sawStructured = true;
      }
      if (sawStructured) return false;
    }
    const err = cause as NodeJS.ErrnoException & { address?: string; port?: number };
    if (err.code !== 'ECONNREFUSED') {
      return null;
    }
    if (typeof err.address === 'string' && err.port !== undefined) {
      const addr = err.address.replace(/^\[|\]$/g, '').toLowerCase();
      const hostMatched =
        addr === proxyHost ||
        (proxyHost === 'localhost' && (addr === '127.0.0.1' || addr === '::1'));
      return hostMatched && Number(err.port) === effectivePort;
    }
    return null;
  };

  const structured = checkSingleCause(error);
  if (structured !== null) {
    return structured;
  }
  return matchesLocalProxyRefusedMessage(formatNetworkErrorMessage(error), effectivePort);
}
