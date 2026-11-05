import * as http from 'node:http';
import * as https from 'node:https';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';

const MAX_RESPONSE_BYTES = 64 * 1024;
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

export async function requestTextViaProxy(
  targetUrl: string,
  proxyUrl: string | null,
  timeoutMs: number,
  acceptHeader = 'text/plain, */*',
  redirectsLeft = 2
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

  const startedAt = Date.now();
  const normalizedProxy = proxyUrl ? normalizeProxyUrlScheme(proxyUrl) : null;

  return new Promise<string>((resolve, reject) => {
    let settled = false;
    let req: http.ClientRequest | null = null;

    const finish = (err: Error | null, body?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardDeadline);
      if (err) {
        reject(err);
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
    }, timeoutMs);

    const isHttps = parsedUrl.protocol === 'https:';
    const baseHeaders: Record<string, string> = {
      'User-Agent': 'curl/8.7.1',
      Accept: acceptHeader,
      'Cache-Control': 'no-cache',
      Connection: 'close',
    };

    const handleResponse = (res: http.IncomingMessage) => {
      const code = res.statusCode || 0;

      if (REDIRECT_STATUS_CODES.has(code) && res.headers.location && redirectsLeft > 0) {
        res.resume();
        clearTimeout(hardDeadline);
        if (settled) return;
        settled = true;
        const elapsed = Date.now() - startedAt;
        const remainingMs = Math.max(1000, timeoutMs - elapsed);
        let nextUrl: string;
        try {
          nextUrl = new URL(res.headers.location, parsedUrl).toString();
        } catch {
          reject(new Error('重定向地址无效'));
          return;
        }
        requestTextViaProxy(nextUrl, normalizedProxy, remainingMs, acceptHeader, redirectsLeft - 1)
          .then(resolve)
          .catch(reject);
        return;
      }

      if (code < 200 || code >= 300) {
        res.resume();
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

      res.on('error', (err) => {
        finish(err);
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
            timeout: timeoutMs,
            headers,
          },
          handleResponse
        );
      } else {
        let agent: http.Agent;
        if (normalizedProxy) {
          agent = normalizedProxy.toLowerCase().startsWith('socks')
            ? new SocksProxyAgent(normalizedProxy, { keepAlive: false, timeout: timeoutMs })
            : new HttpsProxyAgent(normalizedProxy, { keepAlive: false, timeout: timeoutMs });
        } else {
          agent = isHttps
            ? new https.Agent({ keepAlive: false, timeout: timeoutMs })
            : new http.Agent({ keepAlive: false, timeout: timeoutMs });
        }

        const transport = isHttps ? https : http;
        req = transport.request(
          parsedUrl,
          {
            method: 'GET',
            agent,
            timeout: timeoutMs,
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
  timeoutMs: number
): Promise<T> {
  const raw = await requestTextViaProxy(targetUrl, proxyUrl, timeoutMs, 'application/json');
  return JSON.parse(raw) as T;
}
