import * as http from 'node:http';
import * as https from 'node:https';
import { setTimeout as delay } from 'node:timers/promises';
import { isRegisteredBridgeUpstreamRefusedHeader } from '../bridge';
import {
  formatNetworkErrorMessage,
  isLocalProxyRefusedCause,
  MAX_HEADER_BYTES,
  MAX_RESPONSE_BYTES,
  normalizeProxyUrlScheme,
  REDIRECT_STATUS_CODES,
  resolveSafeRedirectUrl,
} from './proxyUrl';
import { createOneShotAgent, timeoutMsOrBudget } from './scopedProxyAgents';

function isNonRetriableRequestError(msg: string): boolean {
  if (
    /探测 URL 格式无效|不支持的 URL 协议|重定向|安全策略拦截|响应体积超出安全上限|代理响应头超出安全上限|URI malformed/i.test(
      msg
    )
  ) {
    return true;
  }
  const httpCodeMatch = /^HTTP 状态码 (\d+)/.exec(msg);
  if (httpCodeMatch) {
    const statusCode = Number(httpCodeMatch[1]);
    return statusCode !== 408 && statusCode !== 429 && statusCode < 500;
  }
  return false;
}

const RETRY_DELAYS_MS = [200, 600] as const;
const MIN_RETRY_REMAINING_MS = 1400;

export interface ProxyHttpResponse {
  statusCode: number;
  location: string | null;
  finalUrl: string;
  body: string;
}

export interface ProxyHttpRequestOptions {
  acceptHeader?: string;
  redirectsLeft?: number;
  allowLocalhost?: boolean;
  signal?: AbortSignal;
  userAgent?: string;
  headers?: Record<string, string>;
  allowRedirectStatus?: boolean;
  onRedirect?: (info: {
    statusCode: number;
    location: string;
    fromUrl: URL;
  }) => 'follow' | 'stop';
  discardBody?: boolean;
}

export async function requestHttpViaProxy(
  targetUrl: string,
  proxyUrl: string | null,
  timeoutMs: number,
  options: ProxyHttpRequestOptions = {}
): Promise<ProxyHttpResponse> {
  const deadlineAt = Date.now() + timeoutMs;
  const normalizedProxy = proxyUrl ? normalizeProxyUrlScheme(proxyUrl) : null;
  const signal = options.signal;
  const request = () =>
    requestHttpViaProxyOnce(targetUrl, normalizedProxy, deadlineAt, options);
  let attempt = 0;
  while (true) {
    try {
      return await request();
    } catch (error) {
      signal?.throwIfAborted();
      const msg = formatNetworkErrorMessage(error);
      if ((!normalizedProxy && timeoutMs < 5000) || isNonRetriableRequestError(msg)) {
        throw error;
      }
      // 本地代理端口直接拒绝连接时立即外抛，交由上层优先触发监听恢复/重绑，避免在重试延迟内掩盖断口
      if (isLocalProxyRefusedCause(error, normalizedProxy)) {
        throw error;
      }
      const retryDelayMs = RETRY_DELAYS_MS[attempt];
      const code =
        typeof (error as NodeJS.ErrnoException)?.code === 'string'
          ? (error as NodeJS.ErrnoException).code!
          : '';
      const transient =
        /ETIMEDOUT|before secure TLS connection was established|socket hang up|ECONNRESET|EPIPE|EAI_AGAIN/i.test(
          `${code} ${msg}`
        ) ||
        Boolean(normalizedProxy && /ENOTFOUND|^HTTP 状态码 (?:408|429|5\d\d)/i.test(msg));
      if (
        retryDelayMs === undefined ||
        !transient ||
        deadlineAt - Date.now() < MIN_RETRY_REMAINING_MS + retryDelayMs
      ) {
        throw error;
      }
      attempt++;
      await delay(retryDelayMs, undefined, { signal });
    }
  }
}

export async function requestTextViaProxy(
  targetUrl: string,
  proxyUrl: string | null,
  timeoutMs: number,
  acceptHeader = 'text/plain, */*',
  redirectsLeft = 2,
  allowLocalhost = false,
  signal?: AbortSignal
): Promise<string> {
  const res = await requestHttpViaProxy(targetUrl, proxyUrl, timeoutMs, {
    acceptHeader,
    redirectsLeft,
    allowLocalhost,
    signal,
  });
  return res.body;
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

async function requestHttpViaProxyOnce(
  targetUrl: string,
  proxyUrl: string | null,
  deadlineAt: number,
  options: ProxyHttpRequestOptions = {}
): Promise<ProxyHttpResponse> {
  const {
    acceptHeader = 'text/plain, */*',
    redirectsLeft = 2,
    allowLocalhost = false,
    signal,
    userAgent = 'curl/8.7.1',
    headers: extraHeaders,
    allowRedirectStatus = false,
    onRedirect,
    discardBody = false,
  } = options;
  signal?.throwIfAborted();
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

  return new Promise<ProxyHttpResponse>((resolve, reject) => {
    let settled = false;
    let req: http.ClientRequest | null = null;
    let agent: http.Agent | null = null;

    const cleanupTransport = () => {
      try {
        agent?.destroy();
      } catch {
        // ignore
      }
    };

    const finish = (
      err: Error | null,
      result?: ProxyHttpResponse,
      destroyReq = false
    ) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardDeadline);
      signal?.removeEventListener('abort', onAbort);
      if (err || destroyReq) {
        req?.destroy();
      }
      cleanupTransport();
      if (err) {
        const normalizedErr = err.message.trim()
          ? err
          : Object.assign(new Error(formatNetworkErrorMessage(err)), {
              code: (err as NodeJS.ErrnoException).code,
              address: (err as NodeJS.ErrnoException & { address?: string }).address,
              port: (err as NodeJS.ErrnoException & { port?: number }).port,
              errors: (err as Error & { errors?: unknown[] }).errors,
            });
        reject(normalizedErr);
      } else {
        resolve(
          result ?? {
            statusCode: 200,
            location: null,
            finalUrl: parsedUrl.toString(),
            body: '',
          }
        );
      }
    };

    // 硬总时长截止定时器：防止半死连接慢速滴水导致探测引擎永久挂起
    const hardDeadline = setTimeout(() => {
      if (req) {
        req.destroy(new Error('连接超时'));
      }
      finish(new Error('连接超时'));
    }, budgetMs);
    const onAbort = () => {
      const reason = signal?.reason;
      finish(
        reason instanceof Error
          ? reason
          : Object.assign(new Error('探测请求已取消'), { name: 'AbortError' })
      );
    };
    signal?.addEventListener('abort', onAbort, { once: true });

    const isHttps = parsedUrl.protocol === 'https:';
    const baseHeaders: Record<string, string> = {
      'User-Agent': userAgent,
      Accept: acceptHeader,
      'Cache-Control': 'no-cache',
      Connection: 'close',
      ...extraHeaders,
    };

    const handleResponse = (res: http.IncomingMessage) => {
      res.on('error', (err) => {
        finish(err);
      });

      const code = res.statusCode || 0;
      const rawLocation = res.headers.location;
      const locationHeader = Array.isArray(rawLocation) ? rawLocation[0] : rawLocation;

      if (REDIRECT_STATUS_CODES.has(code) && locationHeader) {
        const redirectAction =
          redirectsLeft > 0
            ? onRedirect?.({ statusCode: code, location: locationHeader, fromUrl: parsedUrl }) ??
              'follow'
            : 'stop';

        if (redirectAction === 'follow') {
          if (settled) return;
          settled = true;
          clearTimeout(hardDeadline);
          signal?.removeEventListener('abort', onAbort);
          res.destroy();
          cleanupTransport();

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

          requestHttpViaProxyOnce(nextUrl, normalizedProxy, deadlineAt, {
            ...options,
            redirectsLeft: redirectsLeft - 1,
          })
            .then(resolve)
            .catch(reject);
          return;
        }

        if (allowRedirectStatus) {
          finish(
            null,
            {
              statusCode: code,
              location: locationHeader,
              finalUrl: parsedUrl.toString(),
              body: '',
            },
            true
          );
          res.destroy();
          return;
        }
      }

      if (code < 200 || code >= 300) {
        res.destroy();
        if (
          normalizedProxy &&
          code === 503 &&
          isRegisteredBridgeUpstreamRefusedHeader(normalizedProxy, res.headers)
        ) {
          try {
            const p = new URL(normalizedProxy);
            const pHost = p.hostname.replace(/^\[|\]$/g, '');
            const pPort = Number(p.port || (p.protocol === 'https:' ? 443 : 80));
            finish(
              Object.assign(
                new Error(`connect ECONNREFUSED ${pHost}:${pPort}`),
                { code: 'ECONNREFUSED', address: pHost, port: pPort }
              )
            );
            return;
          } catch {
            // fall through to generic status error
          }
        }
        finish(new Error(`HTTP 状态码 ${code}`));
        return;
      }

      if (discardBody) {
        finish(
          null,
          {
            statusCode: code,
            location: null,
            finalUrl: parsedUrl.toString(),
            body: '',
          },
          true
        );
        res.destroy();
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
        finish(null, {
          statusCode: code,
          location: null,
          finalUrl: parsedUrl.toString(),
          body: Buffer.concat(chunks).toString('utf-8'),
        });
      });
    };

    try {
      if (normalizedProxy && !normalizedProxy.toLowerCase().startsWith('socks') && !isHttps) {
        // 明文 HTTP 目标经由 HTTP 代理：直接发送标准正向代理请求，无需 CONNECT 隧道
        const proxyParsed = new URL(normalizedProxy);
        agent =
          proxyParsed.protocol === 'https:'
            ? new https.Agent({ keepAlive: false, timeout: budgetMs })
            : new http.Agent({ keepAlive: false, timeout: timeoutMsOrBudget(budgetMs) });
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
            agent,
            timeout: budgetMs,
            maxHeaderSize: MAX_HEADER_BYTES,
            headers,
          },
          handleResponse
        );
      } else {
        agent = createOneShotAgent(normalizedProxy, isHttps, budgetMs);

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
