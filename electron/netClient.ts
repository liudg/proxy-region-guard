import * as crypto from 'node:crypto';
import type * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as path from 'node:path';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { getRawFs } from './updateCrypto';

const rawFs = getRawFs();

const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_HEADER_BYTES = 64 * 1024;
const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

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

export async function requestTextViaProxy(
  targetUrl: string,
  proxyUrl: string | null,
  timeoutMs: number,
  acceptHeader = 'text/plain, */*',
  redirectsLeft = 2,
  allowLocalhost = false
): Promise<string> {
  const deadlineAt = Date.now() + timeoutMs;
  try {
    return await requestTextViaProxyOnce(
      targetUrl,
      proxyUrl,
      deadlineAt,
      acceptHeader,
      redirectsLeft,
      allowLocalhost
    );
  } catch (err) {
    const msg = formatNetworkErrorMessage(err);
    const remainingMs = deadlineAt - Date.now();
    const isTransientProxySocketDisconnect =
      Boolean(proxyUrl) &&
      remainingMs >= 1600 &&
      /before secure TLS connection was established|socket hang up|ECONNRESET|ECONNREFUSED|EPIPE/i.test(
        msg
      );
    if (!isTransientProxySocketDisconnect) {
      throw err;
    }
    await new Promise((r) => setTimeout(r, 240));
    const retryDeadlineAt = Math.max(deadlineAt, Date.now() + 1500);
    return requestTextViaProxyOnce(
      targetUrl,
      proxyUrl,
      retryDeadlineAt,
      acceptHeader,
      redirectsLeft,
      allowLocalhost
    );
  }
}

async function requestTextViaProxyOnce(
  targetUrl: string,
  proxyUrl: string | null,
  deadlineAt: number,
  acceptHeader = 'text/plain, */*',
  redirectsLeft = 2,
  allowLocalhost = false
): Promise<string> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    throw new Error(`探测 URL 格式无效: ${targetUrl}`);
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new Error(`不支持的 URL 协议: ${parsedUrl.protocol}`);
  }

  const budgetMs = deadlineAt - Date.now();
  if (budgetMs <= 0) {
    throw new Error('连接超时');
  }

  const normalizedProxy = proxyUrl ? normalizeProxyUrlScheme(proxyUrl) : null;

  return new Promise<string>((resolve, reject) => {
    let settled = false;
    let req: http.ClientRequest | null = null;

    const finish = (err: Error | null, body?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardDeadline);
      if (err) {
        const normalizedErr = err.message.trim()
          ? err
          : Object.assign(new Error(formatNetworkErrorMessage(err)), {
              code: (err as NodeJS.ErrnoException).code,
            });
        reject(normalizedErr);
      } else {
        resolve(body ?? '');
      }
    };

    // 硬总时长截止定时器：防止半死连接慢速滴水导致探测引擎永久挂起
    const hardDeadline = setTimeout(() => {
      if (req) {
        req.destroy(new Error('连接超时'));
      }
      finish(new Error('连接超时'));
    }, budgetMs);

    const isHttps = parsedUrl.protocol === 'https:';
    const baseHeaders: Record<string, string> = {
      'User-Agent': 'curl/8.7.1',
      Accept: acceptHeader,
      'Cache-Control': 'no-cache',
      Connection: 'close',
    };

    const handleResponse = (res: http.IncomingMessage) => {
      res.on('error', (err) => {
        finish(err);
      });

      const code = res.statusCode || 0;

      if (REDIRECT_STATUS_CODES.has(code) && res.headers.location && redirectsLeft > 0) {
        const locationHeader = res.headers.location;
        res.destroy();
        clearTimeout(hardDeadline);
        if (settled) return;
        settled = true;

        let nextUrl: string;
        try {
          nextUrl = resolveSafeRedirectUrl(parsedUrl, locationHeader, allowLocalhost);
        } catch (err) {
          reject(err instanceof Error ? err : new Error(String(err)));
          return;
        }

        if (deadlineAt - Date.now() <= 0) {
          reject(new Error('连接超时'));
          return;
        }

        requestTextViaProxyOnce(
          nextUrl,
          normalizedProxy,
          deadlineAt,
          acceptHeader,
          redirectsLeft - 1,
          allowLocalhost
        )
          .then(resolve)
          .catch(reject);
        return;
      }

      if (code < 200 || code >= 300) {
        res.destroy();
        finish(new Error(`HTTP 状态码 ${code}`));
        return;
      }

      const chunks: Buffer[] = [];
      let totalBytes = 0;

      res.on('data', (chunk: Buffer | string) => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalBytes += buf.length;
        if (totalBytes > MAX_RESPONSE_BYTES) {
          res.destroy();
          req?.destroy();
          finish(new Error('响应体积超出安全上限'));
          return;
        }
        chunks.push(buf);
      });

      res.on('end', () => {
        finish(null, Buffer.concat(chunks).toString('utf-8'));
      });
    };

    try {
      if (normalizedProxy && !normalizedProxy.toLowerCase().startsWith('socks') && !isHttps) {
        // 明文 HTTP 目标经由 HTTP 代理：直接发送标准正向代理请求，无需 CONNECT 隧道
        const proxyParsed = new URL(normalizedProxy);
        const headers: Record<string, string> = {
          ...baseHeaders,
          Host: parsedUrl.host,
        };
        if (proxyParsed.username || proxyParsed.password) {
          const auth = Buffer.from(
            `${decodeURIComponent(proxyParsed.username)}:${decodeURIComponent(proxyParsed.password)}`
          ).toString('base64');
          headers['Proxy-Authorization'] = `Basic ${auth}`;
        }
        const proxyTransport = proxyParsed.protocol === 'https:' ? https : http;
        req = proxyTransport.request(
          {
            hostname: proxyParsed.hostname.replace(/^\[|\]$/g, ''),
            port: proxyParsed.port || (proxyParsed.protocol === 'https:' ? 443 : 80),
            method: 'GET',
            path: parsedUrl.toString(),
            timeout: budgetMs,
            maxHeaderSize: MAX_HEADER_BYTES,
            headers,
          },
          handleResponse
        );
      } else {
        let agent: http.Agent;
        if (normalizedProxy) {
          agent = normalizedProxy.toLowerCase().startsWith('socks')
            ? new SocksProxyAgent(normalizedProxy, { keepAlive: false, timeout: budgetMs })
            : new HttpsProxyAgent(normalizedProxy, { keepAlive: false, timeout: budgetMs });
        } else {
          agent = isHttps
            ? new https.Agent({ keepAlive: false, timeout: budgetMs })
            : new http.Agent({ keepAlive: false, timeout: budgetMs });
        }

        const transport = isHttps ? https : http;
        req = transport.request(
          parsedUrl,
          {
            method: 'GET',
            agent,
            timeout: budgetMs,
            maxHeaderSize: MAX_HEADER_BYTES,
            headers: baseHeaders,
          },
          handleResponse
        );
      }

      req.on('timeout', () => {
        req?.destroy(new Error('连接超时'));
      });

      req.on('error', (err) => {
        finish(err);
      });

      req.end();
    } catch (err) {
      finish(err instanceof Error ? err : new Error(String(err)));
    }
  });
}

export async function requestJsonViaProxy<T = Record<string, unknown>>(
  targetUrl: string,
  proxyUrl: string | null,
  timeoutMs: number,
  redirectsLeft = 2,
  allowLocalhost = false
): Promise<T> {
  const raw = await requestTextViaProxy(
    targetUrl,
    proxyUrl,
    timeoutMs,
    'application/json',
    redirectsLeft,
    allowLocalhost
  );
  return JSON.parse(raw) as T;
}

export interface DownloadFileOptions {
  targetUrl: string;
  proxyUrl: string | null;
  destFilePath: string;
  timeoutMs: number;
  stallTimeoutMs?: number;
  maxBytes?: number;
  redirectsLeft?: number;
  allowLocalhost?: boolean;
  deadlineAt?: number;
  onProgress?: (downloadedBytes: number, totalBytes: number | null) => void;
}

export async function downloadFileViaProxy(
  options: DownloadFileOptions
): Promise<{ size: number; sha256: string }> {
  const {
    targetUrl,
    proxyUrl,
    destFilePath,
    timeoutMs,
    stallTimeoutMs = 20000,
    maxBytes = 512 * 1024 * 1024,
    redirectsLeft = 6,
    allowLocalhost = false,
    onProgress,
  } = options;

  const deadlineAt = options.deadlineAt ?? Date.now() + timeoutMs;

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    throw new Error(`下载 URL 格式无效: ${targetUrl}`);
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new Error(`不支持的下载 URL 协议: ${parsedUrl.protocol}`);
  }

  const budgetMs = deadlineAt - Date.now();
  if (budgetMs <= 0) {
    throw new Error('下载总时长超出上限');
  }

  await rawFs.promises.mkdir(path.dirname(destFilePath), { recursive: true });

  const normalizedProxy = proxyUrl ? normalizeProxyUrlScheme(proxyUrl) : null;
  const effectiveStallMs = Math.min(stallTimeoutMs, budgetMs);

  return new Promise<{ size: number; sha256: string }>((resolve, reject) => {
    let settled = false;
    let req: http.ClientRequest | null = null;
    let fileStream: fs.WriteStream | null = null;
    let stallTimer: NodeJS.Timeout | null = null;

    const clearStall = () => {
      if (stallTimer) {
        clearTimeout(stallTimer);
        stallTimer = null;
      }
    };

    const armStall = () => {
      clearStall();
      stallTimer = setTimeout(() => {
        req?.destroy(new Error('下载连接停滞超时'));
        finish(new Error('下载连接停滞超时'));
      }, effectiveStallMs);
    };

    const cleanupPartialFile = () => {
      const ws = fileStream;
      fileStream = null;
      const removeBestEffort = () => {
        try {
          if (rawFs.existsSync(destFilePath)) {
            rawFs.rmSync(destFilePath, { force: true });
          }
        } catch {
          // ignore
        }
      };
      if (ws) {
        ws.once('close', removeBestEffort);
        try {
          ws.destroy();
        } catch {
          removeBestEffort();
        }
      } else {
        removeBestEffort();
      }
    };

    const finish = (err: Error | null, result?: { size: number; sha256: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardDeadline);
      clearStall();
      if (err) {
        cleanupPartialFile();
        reject(err);
      } else if (result) {
        resolve(result);
      }
    };

    const hardDeadline = setTimeout(() => {
      req?.destroy(new Error('下载总时长超出上限'));
      finish(new Error('下载总时长超出上限'));
    }, budgetMs);

    armStall();

    const isHttps = parsedUrl.protocol === 'https:';
    const baseHeaders: Record<string, string> = {
      'User-Agent': 'ProxyRegionGuard-Updater/1.0',
      Accept: 'application/octet-stream, */*',
      'Cache-Control': 'no-cache',
      Connection: 'close',
    };

    const handleResponse = (res: http.IncomingMessage) => {
      res.on('error', (err) => {
        finish(err);
      });

      armStall();
      const code = res.statusCode || 0;

      if (REDIRECT_STATUS_CODES.has(code) && res.headers.location && redirectsLeft > 0) {
        const locationHeader = res.headers.location;
        res.destroy();
        clearTimeout(hardDeadline);
        clearStall();
        if (settled) return;
        settled = true;

        let nextUrl: string;
        try {
          nextUrl = resolveSafeRedirectUrl(parsedUrl, locationHeader, allowLocalhost);
        } catch (err) {
          reject(err instanceof Error ? err : new Error(String(err)));
          return;
        }

        const remainingMs = deadlineAt - Date.now();
        if (remainingMs <= 0) {
          reject(new Error('下载总时长超出上限'));
          return;
        }

        downloadFileViaProxy({
          ...options,
          targetUrl: nextUrl,
          proxyUrl: normalizedProxy,
          timeoutMs: remainingMs,
          deadlineAt,
          redirectsLeft: redirectsLeft - 1,
        })
          .then(resolve)
          .catch(reject);
        return;
      }

      if (code < 200 || code >= 300) {
        res.destroy();
        finish(new Error(`下载返回异常 HTTP 状态码 ${code}`));
        return;
      }

      const contentLengthHeader = res.headers['content-length'];
      const rawTotal = contentLengthHeader ? Number(contentLengthHeader) : NaN;
      const totalBytes = Number.isFinite(rawTotal) && rawTotal > 0 ? rawTotal : null;
      if (totalBytes !== null && totalBytes > maxBytes) {
        res.destroy();
        req?.destroy();
        finish(new Error('下载文件体积超出安全上限'));
        return;
      }

      const hash = crypto.createHash('sha256');
      let downloadedBytes = 0;
      fileStream = rawFs.createWriteStream(destFilePath, { flags: 'w' });

      fileStream.on('error', (err) => {
        res.destroy();
        req?.destroy();
        finish(err);
      });

      res.on('data', (chunk: Buffer | string) => {
        if (settled) return;
        armStall();
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        downloadedBytes += buf.length;
        if (downloadedBytes > maxBytes) {
          res.destroy();
          req?.destroy();
          finish(new Error('下载文件体积超出安全上限'));
          return;
        }
        hash.update(buf);
        if (fileStream && !fileStream.write(buf)) {
          res.pause();
          fileStream.once('drain', () => {
            if (!settled) res.resume();
          });
        }
        onProgress?.(downloadedBytes, totalBytes);
      });

      res.on('end', () => {
        if (settled) return;
        if (totalBytes !== null && downloadedBytes !== totalBytes) {
          finish(new Error(`下载文件不完整 (${downloadedBytes}/${totalBytes} 字节)`));
          return;
        }
        const ws = fileStream;
        fileStream = null;
        if (!ws) {
          finish(new Error('文件写入流意外关闭'));
          return;
        }
        const digest = hash.digest('hex').toLowerCase();
        ws.once('error', (err) => finish(err));
        ws.once('close', () => {
          finish(null, {
            size: downloadedBytes,
            sha256: digest,
          });
        });
        ws.end();
      });
    };

    try {
      if (normalizedProxy && !normalizedProxy.toLowerCase().startsWith('socks') && !isHttps) {
        const proxyParsed = new URL(normalizedProxy);
        const headers: Record<string, string> = {
          ...baseHeaders,
          Host: parsedUrl.host,
        };
        if (proxyParsed.username || proxyParsed.password) {
          const auth = Buffer.from(
            `${decodeURIComponent(proxyParsed.username)}:${decodeURIComponent(proxyParsed.password)}`
          ).toString('base64');
          headers['Proxy-Authorization'] = `Basic ${auth}`;
        }
        const proxyTransport = proxyParsed.protocol === 'https:' ? https : http;
        req = proxyTransport.request(
          {
            hostname: proxyParsed.hostname.replace(/^\[|\]$/g, ''),
            port: proxyParsed.port || (proxyParsed.protocol === 'https:' ? 443 : 80),
            method: 'GET',
            path: parsedUrl.toString(),
            timeout: effectiveStallMs,
            maxHeaderSize: MAX_HEADER_BYTES,
            headers,
          },
          handleResponse
        );
      } else {
        let agent: http.Agent;
        if (normalizedProxy) {
          agent = normalizedProxy.toLowerCase().startsWith('socks')
            ? new SocksProxyAgent(normalizedProxy, { keepAlive: false, timeout: effectiveStallMs })
            : new HttpsProxyAgent(normalizedProxy, { keepAlive: false, timeout: effectiveStallMs });
        } else {
          agent = isHttps
            ? new https.Agent({ keepAlive: false, timeout: effectiveStallMs })
            : new http.Agent({ keepAlive: false, timeout: effectiveStallMs });
        }

        const transport = isHttps ? https : http;
        req = transport.request(
          parsedUrl,
          {
            method: 'GET',
            agent,
            timeout: effectiveStallMs,
            maxHeaderSize: MAX_HEADER_BYTES,
            headers: baseHeaders,
          },
          handleResponse
        );
      }

      req.on('timeout', () => {
        req?.destroy(new Error('下载套接字读取超时'));
      });

      req.on('error', (err) => {
        finish(err);
      });

      req.end();
    } catch (err) {
      finish(err instanceof Error ? err : new Error(String(err)));
    }
  });
}
