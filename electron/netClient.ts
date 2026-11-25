import * as crypto from 'node:crypto';
import type * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as path from 'node:path';
import * as tls from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';
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

type ProxyConnectOpts = Parameters<HttpsProxyAgent<string>['connect']>[1];

function withTlsServername<T extends { host?: string; servername?: string }>(options: T): T {
  if (options.servername === undefined && options.host && !net.isIP(options.host)) {
    return { ...options, servername: options.host };
  }
  return options;
}

function attachFallbackSocketErrorGuard(sock: net.Socket, req: http.ClientRequest): void {
  sock.on('error', (err) => {
    // 消除 Node ClientRequest.onSocket (process.nextTick(onSocketNT)) 挂载前及 CONNECT cleanup 后的无监听空窗期，
    // 仅在无其他 error 监听器时兜底转发至 req，既杜绝主进程 uncaughtException 又不干扰正常错误传播
    if (sock.listenerCount('error') <= 1 && !req.destroyed) {
      req.destroy(err);
    }
  });
}

class ScopedHttpsProxyAgent extends HttpsProxyAgent<string> {
  private readonly activeSockets = new Set<net.Socket>();
  private readonly controller = new AbortController();

  private trackSocket(sock: net.Socket, req: http.ClientRequest): void {
    attachFallbackSocketErrorGuard(sock, req);
    this.activeSockets.add(sock);
    sock.once('close', () => {
      this.activeSockets.delete(sock);
    });
  }

  override async connect(req: http.ClientRequest, opts: ProxyConnectOpts): Promise<net.Socket> {
    if (!opts.host) {
      throw new TypeError('No "host" provided');
    }
    if (this.controller.signal.aborted || req.destroyed) {
      throw new Error('连接超时');
    }

    const host = net.isIPv6(opts.host) ? `[${opts.host}]` : opts.host;
    const authority = `${host}:${opts.port}`;
    const headers: http.OutgoingHttpHeaders = { Host: authority, 'Proxy-Connection': 'close' };
    if (this.proxy.username || this.proxy.password) {
      const auth = `${decodeURIComponent(this.proxy.username)}:${decodeURIComponent(this.proxy.password)}`;
      headers['Proxy-Authorization'] = `Basic ${Buffer.from(auth).toString('base64')}`;
    }
    const transport = this.proxy.protocol === 'https:' ? https : http;
    const rawSocket = await new Promise<net.Socket>((resolve, reject) => {
      const connectRequest = transport.request({
        hostname: this.connectOpts.host,
        port: this.connectOpts.port,
        method: 'CONNECT',
        path: authority,
        headers,
        agent: false,
        signal: this.controller.signal,
        maxHeaderSize: MAX_HEADER_BYTES,
      });
      connectRequest.once('socket', (sock) => {
        this.activeSockets.add(sock);
        sock.once('close', () => {
          this.activeSockets.delete(sock);
        });
      });
      connectRequest.once('error', reject);
      connectRequest.once('connect', (response, socket, head) => {
        if (response.statusCode !== 200) {
          socket.destroy();
          reject(new Error(`HTTP 状态码 ${response.statusCode}`));
          return;
        }
        this.trackSocket(socket, req);
        if (head.length) socket.unshift(head);
        resolve(socket);
      });
      connectRequest.end();
    });

    try {
      if (this.controller.signal.aborted || req.destroyed) {
        throw new Error('连接超时');
      }

      req.once('socket', (s) => s.resume());

      if (opts.secureEndpoint) {
        const { host: _h, path: _p, port: _port, ...restOpts } = withTlsServername(opts);
        void _h;
        void _p;
        void _port;
        const tlsSocket = tls.connect({
          ...restOpts,
          socket: rawSocket,
        });
        this.trackSocket(tlsSocket, req);
        req.once('close', () => {
          if (!tlsSocket.destroyed) tlsSocket.destroy();
        });
        return tlsSocket;
      }

      return rawSocket;
    } catch (err) {
      rawSocket.destroy();
      throw err;
    }
  }

  override destroy(): void {
    this.controller.abort();
    for (const sock of this.activeSockets) {
      if (!sock.destroyed) sock.destroy();
    }
    this.activeSockets.clear();
    super.destroy();
  }
}

class ScopedSocksProxyAgent extends SocksProxyAgent {
  private readonly activeSockets = new Set<net.Socket>();
  private isDestroyed = false;

  override async connect(req: http.ClientRequest, opts: ProxyConnectOpts): Promise<net.Socket> {
    if (this.isDestroyed || req.destroyed) {
      throw new Error('连接超时');
    }
    const sock = await super.connect(req, opts);
    attachFallbackSocketErrorGuard(sock, req);
    this.activeSockets.add(sock);
    sock.once('close', () => {
      this.activeSockets.delete(sock);
    });
    if (this.isDestroyed || req.destroyed) {
      sock.destroy();
      throw new Error('连接超时');
    }
    req.once('close', () => {
      if (!sock.destroyed) sock.destroy();
    });
    return sock;
  }

  override destroy(): void {
    this.isDestroyed = true;
    for (const sock of this.activeSockets) {
      if (!sock.destroyed) sock.destroy();
    }
    this.activeSockets.clear();
    super.destroy();
  }
}

function createOneShotAgent(
  normalizedProxy: string | null,
  isHttps: boolean,
  timeoutMs: number
): http.Agent {
  if (normalizedProxy) {
    return normalizedProxy.toLowerCase().startsWith('socks')
      ? new ScopedSocksProxyAgent(normalizedProxy, { keepAlive: false, timeout: timeoutMs })
      : new ScopedHttpsProxyAgent(normalizedProxy, { keepAlive: false, timeout: timeoutMs });
  }
  return isHttps
    ? new https.Agent({ keepAlive: false, timeout: timeoutMs })
    : new http.Agent({ keepAlive: false, timeout: timeoutMs });
}

function isNonRetriableRequestError(msg: string): boolean {
  if (/探测 URL 格式无效|不支持的 URL 协议|重定向|安全策略拦截|响应体积超出安全上限|代理响应头超出安全上限|URI malformed/i.test(msg)) {
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
        agent = proxyParsed.protocol === 'https:'
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

function timeoutMsOrBudget(budgetMs: number): number {
  return Math.max(1, budgetMs);
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
    let agent: http.Agent | null = null;
    let fileStream: fs.WriteStream | null = null;
    let stallTimer: NodeJS.Timeout | null = null;

    const cleanupTransport = () => {
      try {
        agent?.destroy();
      } catch {
        // ignore
      }
    };

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
        req?.destroy();
      }
      cleanupTransport();
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
        if (settled) return;
        settled = true;
        clearTimeout(hardDeadline);
        clearStall();
        const locationHeader = res.headers.location;
        res.destroy();
        cleanupTransport();

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
        agent = proxyParsed.protocol === 'https:'
          ? new https.Agent({ keepAlive: false, timeout: effectiveStallMs })
          : new http.Agent({ keepAlive: false, timeout: timeoutMsOrBudget(effectiveStallMs) });
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
            timeout: effectiveStallMs,
            maxHeaderSize: MAX_HEADER_BYTES,
            headers,
          },
          handleResponse
        );
      } else {
        agent = createOneShotAgent(normalizedProxy, isHttps, effectiveStallMs);

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
