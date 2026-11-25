import { randomBytes } from 'node:crypto';
import * as http from 'node:http';
import * as net from 'node:net';

const UPSTREAM_REFUSED_HEADER = 'x-guard-upstream-refused';
const MAX_HEADER_BYTES = 64 * 1024;
const MAX_HANDSHAKE_BODY_BYTES = 256 * 1024;
const HANDSHAKE_TIMEOUT_MS = 15000;
const DNS_CACHE_MAX_ENTRIES = 512;
const MAX_IPV4_CONNECT_ATTEMPTS = 2;

const activeBridgeRefusedTokens = new Map<number, string>();

export function isRegisteredBridgeUpstreamRefusedHeader(
  proxyUrl: string | null | undefined,
  headers: http.IncomingHttpHeaders | undefined
): boolean {
  if (!proxyUrl || !headers) return false;
  const raw = headers[UPSTREAM_REFUSED_HEADER];
  const token = Array.isArray(raw) ? raw[0] : raw;
  if (typeof token !== 'string' || !token.trim()) return false;
  try {
    const parsed = new URL(proxyUrl);
    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
      return false;
    }
    const port = Number(parsed.port);
    if (!Number.isInteger(port) || port <= 0) return false;
    const expected = activeBridgeRefusedTokens.get(port);
    return Boolean(expected && expected === token.trim());
  } catch {
    return false;
  }
}

export interface Ipv4ResolveResult {
  ips: string[];
  ttlSec: number;
}

export type BridgeUpstreamTarget =
  | { status: 'ready'; port: number; generation?: number }
  | { status: 'refused'; port: number; reason: string }
  | { status: 'blocked'; reason: string }
  | { status: 'unavailable'; reason: string };

export interface Ipv4ProxyBridgeOptions {
  bindPort?: number;
  getUpstreamTarget: (signal?: AbortSignal) => Promise<BridgeUpstreamTarget> | BridgeUpstreamTarget;
  resolveIpv4: (hostname: string, signal?: AbortSignal) => Promise<Ipv4ResolveResult>;
  onUnexpectedClose?: (reason: string) => void;
}

class BridgeHttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly statusText: string,
    message: string,
    public readonly socksReplyCode = 0x01,
    public readonly upstreamRefused = false
  ) {
    super(message);
    this.name = 'BridgeHttpError';
  }
}

function isAbortError(err: unknown): boolean {
  return err instanceof Error && err.name === 'AbortError';
}

function makeAbortError(message = '代理连接已取消'): Error {
  return Object.assign(new Error(message), { name: 'AbortError' });
}

function parseConnectAuthority(rawAuthority: string): { host: string; port: number } | null {
  const trimmed = rawAuthority.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('[')) {
    const closeIdx = trimmed.indexOf(']');
    if (closeIdx <= 1 || trimmed[closeIdx + 1] !== ':') return null;
    const host = trimmed.slice(1, closeIdx).trim();
    const port = Number(trimmed.slice(closeIdx + 2));
    if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return null;
    return { host, port };
  }
  const colonIdx = trimmed.lastIndexOf(':');
  if (colonIdx <= 0) return null;
  const host = trimmed.slice(0, colonIdx).trim();
  if (host.includes(':')) return null;
  const port = Number(trimmed.slice(colonIdx + 1));
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

class SocketByteReader {
  private chunks: Buffer[] = [];
  private totalBytes = 0;
  private ended = false;
  private failure: Error | null = null;
  private waiter: (() => void) | null = null;
  private readonly onData: (chunk: Buffer) => void;
  private readonly onEnd: () => void;
  private readonly onClose: () => void;
  private readonly onError: (err: Error) => void;

  constructor(private readonly socket: net.Socket, initialChunk?: Buffer) {
    if (initialChunk && initialChunk.length > 0) {
      this.chunks.push(initialChunk);
      this.totalBytes = initialChunk.length;
    }
    this.onData = (chunk: Buffer) => {
      this.chunks.push(chunk);
      this.totalBytes += chunk.length;
      this.notify();
    };
    this.onEnd = () => {
      this.ended = true;
      this.notify();
    };
    this.onClose = () => {
      this.ended = true;
      this.notify();
    };
    this.onError = (err: Error) => {
      this.failure = err;
      this.notify();
    };
    socket.on('data', this.onData);
    socket.once('end', this.onEnd);
    socket.once('close', this.onClose);
    socket.once('error', this.onError);
  }

  private notify(): void {
    const wake = this.waiter;
    this.waiter = null;
    wake?.();
  }

  private waitForMore(signal: AbortSignal): Promise<void> {
    if (this.failure) return Promise.reject(this.failure);
    if (signal.aborted) return Promise.reject(makeAbortError());
    if (this.ended) return Promise.reject(new Error('连接提前关闭'));
    return new Promise<void>((resolve, reject) => {
      const onAbort = () => {
        if (this.waiter === wake) this.waiter = null;
        reject(makeAbortError());
      };
      const wake = () => {
        signal.removeEventListener('abort', onAbort);
        resolve();
      };
      this.waiter = wake;
      signal.addEventListener('abort', onAbort, { once: true });
    });
  }

  public async readExact(length: number, signal: AbortSignal): Promise<Buffer> {
    while (this.totalBytes < length) {
      await this.waitForMore(signal);
    }
    const merged = this.chunks.length === 1 ? this.chunks[0] : Buffer.concat(this.chunks);
    const out = merged.subarray(0, length);
    const rest = merged.subarray(length);
    this.chunks = rest.length > 0 ? [rest] : [];
    this.totalBytes = rest.length;
    return out;
  }

  public async readUntil(
    delimiter: Buffer,
    maxBytes: number,
    signal: AbortSignal
  ): Promise<{ data: Buffer; rest: Buffer }> {
    while (true) {
      if (this.totalBytes >= delimiter.length) {
        const merged = this.chunks.length === 1 ? this.chunks[0] : Buffer.concat(this.chunks);
        const idx = merged.indexOf(delimiter);
        if (idx !== -1) {
          if (idx > maxBytes) {
            throw new BridgeHttpError(431, 'Request Header Fields Too Large', '请求头超过安全上限');
          }
          const data = merged.subarray(0, idx);
          const rest = merged.subarray(idx + delimiter.length);
          this.chunks = rest.length > 0 ? [rest] : [];
          this.totalBytes = rest.length;
          return { data, rest };
        }
        this.chunks = [merged];
      }
      if (this.totalBytes > maxBytes) {
        throw new BridgeHttpError(431, 'Request Header Fields Too Large', '请求头超过安全上限');
      }
      await this.waitForMore(signal);
    }
  }

  public detachRemaining(pauseSocket = true): Buffer {
    if (pauseSocket && !this.socket.destroyed) {
      this.socket.pause();
    }
    this.socket.removeListener('data', this.onData);
    this.socket.removeListener('end', this.onEnd);
    this.socket.removeListener('close', this.onClose);
    this.socket.removeListener('error', this.onError);
    const merged = this.chunks.length === 0
      ? Buffer.alloc(0)
      : this.chunks.length === 1
      ? this.chunks[0]
      : Buffer.concat(this.chunks);
    this.chunks = [];
    this.totalBytes = 0;
    return merged;
  }
}

interface TunnelHandshakeGuard {
  collectAndDetach: () => Buffer;
  dispose: () => void;
}

/**
 * 在 CONNECT / SOCKS5 握手等待 DNS 或上游建连期间保持客户端套接字可读，
 * 以便立即感知客户端 FIN/RST 取消握手并释放上游连接，同时有限缓冲早到负载字节。
 */
function attachTunnelHandshakeGuard(
  clientSocket: net.Socket,
  initialBytes: Buffer,
  onClientClosed: () => void
): TunnelHandshakeGuard {
  const chunks: Buffer[] = initialBytes.length > 0 ? [initialBytes] : [];
  let bufferedBytes = initialBytes.length;
  let detached = false;

  const onData = (chunk: Buffer) => {
    if (detached) return;
    chunks.push(chunk);
    bufferedBytes += chunk.length;
    if (bufferedBytes >= MAX_HANDSHAKE_BODY_BYTES && !clientSocket.destroyed) {
      clientSocket.pause();
    }
  };
  const onEnd = () => {
    if (!detached) {
      onClientClosed();
    }
  };

  clientSocket.on('data', onData);
  clientSocket.once('end', onEnd);
  if (!clientSocket.destroyed && bufferedBytes < MAX_HANDSHAKE_BODY_BYTES) {
    clientSocket.resume();
  }

  const detach = () => {
    if (detached) return;
    detached = true;
    clientSocket.removeListener('data', onData);
    clientSocket.removeListener('end', onEnd);
  };

  return {
    collectAndDetach: () => {
      detach();
      return chunks.length === 0
        ? Buffer.alloc(0)
        : chunks.length === 1
        ? chunks[0]
        : Buffer.concat(chunks);
    },
    dispose: detach,
  };
}

interface InFlightDnsEntry {
  epoch: number;
  waiters: number;
  controller: AbortController;
  promise: Promise<Ipv4ResolveResult>;
}

/**
 * 本地回环 IPv4 强制代理桥接器（Mixed HTTP + SOCKS5）：
 * 接收 Claude 通道流量（HTTP CONNECT / 明文 HTTP / SOCKS5），
 * 通过私有 Mihomo 内核内置 DoH 仅解析 IPv4 A 记录，
 * 再以 IPv4 字面量转发给私有 Mihomo 内部端口，确保远端代理节点收到 ATYP=IPv4 而无法切至 IPv6 出口。
 */
export class Ipv4ProxyBridge {
  private server: net.Server | null = null;
  private httpServer: http.Server | null = null;
  private startPromise: Promise<number> | null = null;
  private port: number | null = null;
  private refusedToken: string | null = null;
  private closed = false;
  private dnsEpoch = 0;
  private readonly activeSockets = new Set<net.Socket>();
  private readonly activeConnections = new Set<AbortController>();
  private readonly dnsCache = new Map<string, { ips: string[]; expiresAt: number }>();
  private readonly dnsInFlight = new Map<string, InFlightDnsEntry>();

  constructor(private readonly options: Ipv4ProxyBridgeOptions) {}

  public getPort(): number | null {
    return this.port;
  }

  public isListening(): boolean {
    return Boolean(this.server && this.server.listening && this.port !== null && !this.closed);
  }

  public clearDnsCache(): void {
    this.dnsEpoch++;
    this.dnsCache.clear();
    for (const entry of this.dnsInFlight.values()) {
      entry.controller.abort(makeAbortError('DNS 缓存已重置'));
    }
    this.dnsInFlight.clear();
  }

  public disconnectAll(reason = '私有代理通道不可用'): void {
    this.clearDnsCache();
    for (const ctrl of this.activeConnections) {
      if (!ctrl.signal.aborted) {
        ctrl.abort(makeAbortError(reason));
      }
    }
    this.activeConnections.clear();
    for (const sock of this.activeSockets) {
      if (!sock.destroyed) {
        sock.destroy();
      }
    }
    this.activeSockets.clear();
  }

  private createHttpParserServer(): http.Server {
    const httpSrv = http.createServer({
      maxHeaderSize: MAX_HEADER_BYTES,
      keepAliveTimeout: 5000,
    });
    httpSrv.headersTimeout = HANDSHAKE_TIMEOUT_MS;
    httpSrv.on('clientError', (err: NodeJS.ErrnoException, socket) => {
      if (socket.destroyed || !socket.writable) {
        socket.destroy();
        return;
      }
      if (err?.code === 'HPE_HEADER_OVERFLOW') {
        socket.end(
          'HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'
        );
        return;
      }
      socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    });
    httpSrv.on('connect', (req, clientSocket, head) => {
      void this.handleHttpConnect(req, clientSocket as net.Socket, head);
    });
    httpSrv.on('request', (req, res) => {
      void this.handlePlainHttpRequest(req, res);
    });
    return httpSrv;
  }

  public async ensureStarted(bindPortOverride?: number): Promise<number> {
    const requestedPort = bindPortOverride ?? this.options.bindPort ?? 0;
    if (
      this.isListening() &&
      this.port !== null &&
      (requestedPort === 0 || this.port === requestedPort)
    ) {
      return this.port;
    }
    if (this.startPromise) {
      return this.startPromise;
    }
    if (this.isListening()) {
      this.close();
    }
    this.closed = false;
    const starting = new Promise<number>((resolve, reject) => {
      const httpSrv = this.createHttpParserServer();
      const server = net.createServer((clientSocket) => {
        this.handleClientSocket(clientSocket, httpSrv);
      });
      let settled = false;
      server.on('error', (err) => {
        if (!settled) {
          settled = true;
          if (this.server === server) {
            this.server = null;
          }
          reject(err);
          return;
        }
        if (!this.closed && this.server === server) {
          const reason = err instanceof Error ? err.message : String(err);
          this.options.onUnexpectedClose?.(`IPv4 强制代理桥接监听异常：${reason}`);
        }
      });
      server.on('close', () => {
        if (!this.closed && this.server === server) {
          this.server = null;
          const prevPort = this.port;
          this.port = null;
          this.refusedToken = null;
          if (prevPort !== null) {
            activeBridgeRefusedTokens.delete(prevPort);
          }
          this.options.onUnexpectedClose?.('IPv4 强制代理桥接监听意外关闭');
        }
      });
      server.listen(requestedPort, '127.0.0.1', () => {
        const addr = server.address();
        if (!addr || typeof addr === 'string') {
          settled = true;
          server.close();
          reject(new Error('无法获取 IPv4 强制代理桥接监听端口'));
          return;
        }
        if (this.closed) {
          settled = true;
          server.close();
          reject(makeAbortError('IPv4 强制代理桥接已停止'));
          return;
        }
        settled = true;
        this.server = server;
        this.httpServer = httpSrv;
        this.port = addr.port;
        this.refusedToken = randomBytes(16).toString('hex');
        activeBridgeRefusedTokens.set(addr.port, this.refusedToken);
        resolve(addr.port);
      });
    });
    this.startPromise = starting;
    try {
      return await starting;
    } finally {
      if (this.startPromise === starting) {
        this.startPromise = null;
      }
    }
  }

  public close(): void {
    this.closed = true;
    const boundPort = this.port;
    this.port = null;
    this.refusedToken = null;
    if (boundPort !== null) {
      activeBridgeRefusedTokens.delete(boundPort);
    }
    this.clearDnsCache();
    for (const ctrl of this.activeConnections) {
      if (!ctrl.signal.aborted) {
        ctrl.abort(makeAbortError('IPv4 强制代理桥接已关闭'));
      }
    }
    this.activeConnections.clear();
    for (const sock of this.activeSockets) {
      if (!sock.destroyed) {
        sock.destroy();
      }
    }
    this.activeSockets.clear();
    if (this.httpServer) {
      const httpSrv = this.httpServer;
      this.httpServer = null;
      try {
        httpSrv.close();
      } catch {
        // ignore close error
      }
    }
    if (this.server) {
      const srv = this.server;
      this.server = null;
      try {
        srv.close();
      } catch {
        // ignore close error
      }
    }
  }

  private trackSocket(sock: net.Socket): void {
    this.activeSockets.add(sock);
    sock.once('close', () => {
      this.activeSockets.delete(sock);
    });
  }

  private async resolveDomainIpv4Cached(
    cleanHost: string,
    signal: AbortSignal
  ): Promise<string[]> {
    signal.throwIfAborted();
    const now = Date.now();
    const cached = this.dnsCache.get(cleanHost);
    if (cached && cached.expiresAt > now && cached.ips.length > 0) {
      this.dnsCache.delete(cleanHost);
      this.dnsCache.set(cleanHost, cached);
      return cached.ips;
    }
    if (cached) {
      this.dnsCache.delete(cleanHost);
    }

    let entry = this.dnsInFlight.get(cleanHost);
    if (!entry) {
      const epoch = this.dnsEpoch;
      const controller = new AbortController();
      const promise = this.options
        .resolveIpv4(cleanHost, controller.signal)
        .then((res) => {
          const validIps = [...new Set(res.ips.filter((ip) => net.isIPv4(ip)))];
          if (validIps.length === 0) {
            throw new BridgeHttpError(
              502,
              'Bad Gateway',
              `域名 ${cleanHost} 未解析到可用 IPv4 地址`,
              0x04
            );
          }
          const ttlSec = Math.max(15, Math.min(300, Math.round(res.ttlSec || 60)));
          if (!this.closed && this.dnsEpoch === epoch) {
            if (this.dnsCache.size >= DNS_CACHE_MAX_ENTRIES) {
              const oldest = this.dnsCache.keys().next().value;
              if (oldest !== undefined) this.dnsCache.delete(oldest);
            }
            this.dnsCache.set(cleanHost, {
              ips: validIps,
              expiresAt: Date.now() + ttlSec * 1000,
            });
          }
          return { ips: validIps, ttlSec };
        });
      entry = { epoch, waiters: 0, controller, promise };
      this.dnsInFlight.set(cleanHost, entry);
      promise
        .finally(() => {
          if (this.dnsInFlight.get(cleanHost) === entry) {
            this.dnsInFlight.delete(cleanHost);
          }
        })
        .catch(() => undefined);
    }

    entry.waiters++;
    const activeEntry = entry;
    return new Promise<string[]>((resolve, reject) => {
      let settled = false;
      const releaseWaiter = () => {
        activeEntry.waiters = Math.max(0, activeEntry.waiters - 1);
        if (activeEntry.waiters === 0 && !activeEntry.controller.signal.aborted) {
          activeEntry.controller.abort(makeAbortError('DNS 解析等待方已取消'));
        }
      };
      const onAbort = () => {
        if (settled) return;
        settled = true;
        releaseWaiter();
        reject(makeAbortError());
      };
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener('abort', onAbort, { once: true });
      activeEntry.promise.then(
        (res) => {
          if (settled) return;
          settled = true;
          signal.removeEventListener('abort', onAbort);
          activeEntry.waiters = Math.max(0, activeEntry.waiters - 1);
          resolve(res.ips);
        },
        (err) => {
          if (settled) return;
          settled = true;
          signal.removeEventListener('abort', onAbort);
          activeEntry.waiters = Math.max(0, activeEntry.waiters - 1);
          reject(err);
        }
      );
    });
  }

  private connectUpstreamLoopback(upstreamPort: number, signal: AbortSignal): Promise<net.Socket> {
    return new Promise<net.Socket>((resolve, reject) => {
      if (signal.aborted) {
        reject(makeAbortError());
        return;
      }
      const sock = net.connect({ host: '127.0.0.1', port: upstreamPort });
      this.trackSocket(sock);
      sock.on('error', () => {
        if (sock.listenerCount('error') <= 1 && !sock.destroyed) {
          sock.destroy();
        }
      });
      let settled = false;
      const cleanup = () => {
        signal.removeEventListener('abort', onAbort);
        sock.removeListener('connect', onConnect);
        sock.removeListener('error', onError);
      };
      const onAbort = () => {
        if (settled) return;
        settled = true;
        cleanup();
        sock.destroy();
        reject(makeAbortError());
      };
      const onConnect = () => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(sock);
      };
      const onError = (err: NodeJS.ErrnoException) => {
        if (settled) return;
        settled = true;
        cleanup();
        sock.destroy();
        if (err.code === 'ECONNREFUSED') {
          reject(
            new BridgeHttpError(
              503,
              'Service Unavailable',
              `本地私有代理端口 127.0.0.1:${upstreamPort} 拒绝连接`,
              0x05,
              true
            )
          );
          return;
        }
        reject(
          new BridgeHttpError(
            502,
            'Bad Gateway',
            `连接本地私有代理失败：${err.message || err.code || 'unknown'}`,
            0x01
          )
        );
      };
      signal.addEventListener('abort', onAbort, { once: true });
      sock.once('connect', onConnect);
      sock.once('error', onError);
    });
  }

  private async sendUpstreamConnect(
    upstreamSock: net.Socket,
    targetIp: string,
    targetPort: number,
    signal: AbortSignal
  ): Promise<Buffer> {
    signal.throwIfAborted();
    const authority = `${targetIp}:${targetPort}`;
    const reader = new SocketByteReader(upstreamSock);
    const reqText =
      `CONNECT ${authority} HTTP/1.1\r\n` +
      `Host: ${authority}\r\n` +
      `Proxy-Connection: close\r\n\r\n`;
    try {
      await new Promise<void>((resolve, reject) => {
        if (signal.aborted) {
          reject(makeAbortError());
          return;
        }
        upstreamSock.write(reqText, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      const { data } = await reader.readUntil(
        Buffer.from('\r\n\r\n'),
        MAX_HEADER_BYTES,
        signal
      );
      const statusLine = data.toString('latin1').split('\r\n')[0] || '';
      const match = /^HTTP\/\d\.\d\s+(\d{3})\b/i.exec(statusLine);
      const statusCode = match ? Number(match[1]) : 0;
      if (statusCode !== 200) {
        throw new BridgeHttpError(
          502,
          'Bad Gateway',
          `私有代理 CONNECT ${authority} 返回 HTTP ${statusCode || 'invalid'}`,
          0x04
        );
      }
      return reader.detachRemaining(true);
    } catch (err) {
      reader.detachRemaining(true);
      throw err;
    }
  }

  private async resolveVerifiedUpstreamTarget(
    signal: AbortSignal
  ): Promise<{ port: number; generation?: number }> {
    signal.throwIfAborted();
    const target = await this.options.getUpstreamTarget(signal);
    signal.throwIfAborted();
    if (target.status === 'refused') {
      throw new BridgeHttpError(
        503,
        'Service Unavailable',
        target.reason || `本地私有代理端口 127.0.0.1:${target.port} 拒绝连接`,
        0x05,
        true
      );
    }
    if (target.status === 'blocked') {
      throw new BridgeHttpError(
        503,
        'Service Unavailable',
        target.reason || '私有代理端口归属异常，已阻断转发',
        0x02,
        false
      );
    }
    if (
      target.status !== 'ready' ||
      !Number.isInteger(target.port) ||
      target.port < 1 ||
      target.port > 65535
    ) {
      throw new BridgeHttpError(
        503,
        'Service Unavailable',
        target.status === 'unavailable' ? target.reason : '本地私有代理端口尚未就绪',
        0x05,
        false
      );
    }
    return { port: target.port, generation: target.generation };
  }

  private async openUpstreamIpv4Tunnel(
    rawHost: string,
    targetPort: number,
    signal: AbortSignal
  ): Promise<{ upstreamSocket: net.Socket; upHead: Buffer }> {
    signal.throwIfAborted();
    const cleanHost = rawHost.trim().replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
    if (!cleanHost) {
      throw new BridgeHttpError(400, 'Bad Request', '目标主机名为空', 0x01);
    }
    if (net.isIPv6(cleanHost)) {
      throw new BridgeHttpError(
        403,
        'Forbidden',
        `已开启强制 IPv4 出站，已拦截 IPv6 目标 ${cleanHost}`,
        0x02
      );
    }
    const initialTarget = await this.resolveVerifiedUpstreamTarget(signal);
    const upstreamPort = initialTarget.port;
    const upstreamGeneration = initialTarget.generation;

    let ips: string[];
    let preconnectedSocket: net.Socket | null = null;

    if (net.isIPv4(cleanHost)) {
      ips = [cleanHost];
    } else if (cleanHost === 'localhost') {
      ips = ['127.0.0.1'];
    } else {
      const stepCtrl = new AbortController();
      const stepSignal = AbortSignal.any([signal, stepCtrl.signal]);
      const tcpState: { sock: net.Socket | null; err: unknown; done: boolean; handedOff: boolean } = {
        sock: null,
        err: null,
        done: false,
        handedOff: false,
      };

      const tcpPromise = this.connectUpstreamLoopback(upstreamPort, stepSignal)
        .then((sock) => {
          if (stepSignal.aborted) {
            sock.destroy();
            tcpState.done = true;
            return null;
          }
          tcpState.sock = sock;
          tcpState.done = true;
          return sock;
        })
        .catch((err) => {
          tcpState.err = err;
          tcpState.done = true;
          if (err instanceof BridgeHttpError && err.upstreamRefused) {
            stepCtrl.abort(err);
          }
          return null;
        });

      try {
        ips = await this.resolveDomainIpv4Cached(cleanHost, stepSignal);
        const connectedSock = await tcpPromise;
        if (tcpState.err) {
          throw tcpState.err;
        }
        // 建连后二次核验端口与世代：仅当私有内核在建连前后同一世代持续持有该端口时才复用预连接
        const verifiedAfterDns = await this.resolveVerifiedUpstreamTarget(signal);
        if (
          verifiedAfterDns.port === upstreamPort &&
          verifiedAfterDns.generation === upstreamGeneration
        ) {
          preconnectedSocket = connectedSock;
          tcpState.handedOff = true;
        } else if (connectedSock && !connectedSock.destroyed) {
          connectedSock.destroy();
        }
      } catch (err) {
        if (tcpState.sock && !tcpState.sock.destroyed) {
          tcpState.sock.destroy();
        }
        if (tcpState.err instanceof BridgeHttpError && tcpState.err.upstreamRefused) {
          throw tcpState.err;
        }
        if (!tcpState.done && !signal.aborted) {
          try {
            const recheckTarget = await this.resolveVerifiedUpstreamTarget(signal);
            const probeCtrl = new AbortController();
            const probeTimer = setTimeout(() => probeCtrl.abort(), 1500);
            probeTimer.unref?.();
            try {
              await this.connectUpstreamLoopback(
                recheckTarget.port,
                AbortSignal.any([signal, probeCtrl.signal])
              ).then((s) => s.destroy());
            } catch (connectErr) {
              if (connectErr instanceof BridgeHttpError && connectErr.upstreamRefused) {
                throw connectErr;
              }
            } finally {
              clearTimeout(probeTimer);
              stepCtrl.abort();
            }
          } catch (recheckErr) {
            stepCtrl.abort();
            if (recheckErr instanceof BridgeHttpError && recheckErr.upstreamRefused) {
              throw recheckErr;
            }
          }
        } else {
          stepCtrl.abort();
        }
        if (err instanceof BridgeHttpError) throw err;
        if (isAbortError(err)) throw err;
        throw new BridgeHttpError(
          502,
          'Bad Gateway',
          err instanceof Error ? err.message : String(err),
          0x04
        );
      } finally {
        stepCtrl.abort();
        if (!tcpState.handedOff && tcpState.sock && !tcpState.sock.destroyed) {
          tcpState.sock.destroy();
        }
      }
    }

    const candidates = ips.slice(0, MAX_IPV4_CONNECT_ATTEMPTS);
    let lastError: unknown = new BridgeHttpError(502, 'Bad Gateway', '无法建立 IPv4 代理隧道', 0x04);
    const destroyPreconnected = () => {
      if (preconnectedSocket && !preconnectedSocket.destroyed) {
        preconnectedSocket.destroy();
      }
      preconnectedSocket = null;
    };
    signal.addEventListener('abort', destroyPreconnected, { once: true });
    try {
      for (let i = 0; i < candidates.length; i++) {
        const targetIp = candidates[i];
        let sock: net.Socket | null = null;
        const verifiedBeforeDial = await this.resolveVerifiedUpstreamTarget(signal);
        if (
          i === 0 &&
          verifiedBeforeDial.port === upstreamPort &&
          verifiedBeforeDial.generation === upstreamGeneration &&
          preconnectedSocket &&
          !preconnectedSocket.destroyed &&
          preconnectedSocket.readable &&
          preconnectedSocket.writable
        ) {
          sock = preconnectedSocket;
          preconnectedSocket = null;
        } else {
          destroyPreconnected();
          sock = await this.connectUpstreamLoopback(verifiedBeforeDial.port, signal);
          // 建连完成、写出任何目标地址字节前再次核验同一世代与端口仍由私有内核持有，消除建连瞬间 TOCTOU
          let verifiedAfterDial: { port: number; generation?: number };
          try {
            verifiedAfterDial = await this.resolveVerifiedUpstreamTarget(signal);
          } catch (verifyErr) {
            if (!sock.destroyed) sock.destroy();
            throw verifyErr;
          }
          if (
            sock.destroyed ||
            verifiedAfterDial.port !== verifiedBeforeDial.port ||
            verifiedAfterDial.generation !== verifiedBeforeDial.generation
          ) {
            if (!sock.destroyed) sock.destroy();
            throw new BridgeHttpError(
              503,
              'Service Unavailable',
              '私有代理端口在建连期间发生变更或归属失效，已阻断转发',
              0x02,
              false
            );
          }
        }
        try {
          const upHead = await this.sendUpstreamConnect(sock, targetIp, targetPort, signal);
          return { upstreamSocket: sock, upHead };
        } catch (err) {
          if (!sock.destroyed) sock.destroy();
          lastError = err;
          if (
            signal.aborted ||
            (err instanceof BridgeHttpError && err.upstreamRefused) ||
            isAbortError(err)
          ) {
            throw err;
          }
        }
      }
      throw lastError;
    } finally {
      signal.removeEventListener('abort', destroyPreconnected);
      destroyPreconnected();
    }
  }

  private pipeBidirectional(
    clientSocket: net.Socket,
    upstreamSocket: net.Socket,
    initialToClient: Buffer,
    initialToUpstream: Buffer
  ): void {
    const closePeer = (peer: net.Socket, hadError: boolean) => {
      if (peer.destroyed) return;
      if (hadError) {
        peer.destroy();
        return;
      }
      peer.end();
      const grace = setTimeout(() => {
        if (!peer.destroyed) peer.destroy();
      }, 1000);
      grace.unref?.();
      peer.once('finish', () => {
        clearTimeout(grace);
        if (!peer.destroyed) peer.destroy();
      });
    };

    clientSocket.on('error', () => {
      if (!upstreamSocket.destroyed) upstreamSocket.destroy();
    });
    upstreamSocket.on('error', () => {
      if (!clientSocket.destroyed) clientSocket.destroy();
    });
    clientSocket.once('close', (hadError) => closePeer(upstreamSocket, hadError));
    upstreamSocket.once('close', (hadError) => closePeer(clientSocket, hadError));

    if (initialToClient.length > 0 && !clientSocket.destroyed) {
      clientSocket.write(initialToClient);
    }
    if (initialToUpstream.length > 0 && !upstreamSocket.destroyed) {
      upstreamSocket.write(initialToUpstream);
    }
    if (!clientSocket.destroyed && !upstreamSocket.destroyed) {
      clientSocket.pipe(upstreamSocket);
      upstreamSocket.pipe(clientSocket);
    }
  }

  private toBridgeHttpError(err: unknown): BridgeHttpError {
    return err instanceof BridgeHttpError
      ? err
      : new BridgeHttpError(
          502,
          'Bad Gateway',
          err instanceof Error ? err.message : String(err)
        );
  }

  private writeHttpErrorAndClose(clientSocket: net.Socket, err: unknown): void {
    if (clientSocket.destroyed || !clientSocket.writable) return;
    const bridgeErr = this.toBridgeHttpError(err);
    const extraHeader =
      bridgeErr.upstreamRefused && this.refusedToken
        ? `${UPSTREAM_REFUSED_HEADER}: ${this.refusedToken}\r\n`
        : '';
    const body = Buffer.from(bridgeErr.message || bridgeErr.statusText, 'utf8');
    const payload =
      `HTTP/1.1 ${bridgeErr.statusCode} ${bridgeErr.statusText}\r\n` +
      extraHeader +
      `Content-Type: text/plain; charset=utf-8\r\n` +
      `Content-Length: ${body.length}\r\n` +
      `Connection: close\r\n\r\n`;
    clientSocket.end(Buffer.concat([Buffer.from(payload, 'latin1'), body]));
  }

  private writeHttpResponseError(res: http.ServerResponse, err: unknown): void {
    if (res.destroyed || res.writableEnded) return;
    const bridgeErr = this.toBridgeHttpError(err);
    const body = Buffer.from(bridgeErr.message || bridgeErr.statusText, 'utf8');
    const headers: http.OutgoingHttpHeaders = {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Length': String(body.length),
      Connection: 'close',
    };
    if (bridgeErr.upstreamRefused && this.refusedToken) {
      headers[UPSTREAM_REFUSED_HEADER] = this.refusedToken;
    }
    if (!res.headersSent) {
      res.writeHead(bridgeErr.statusCode, bridgeErr.statusText, headers);
    }
    res.end(body);
  }

  private writeSocksErrorAndClose(clientSocket: net.Socket, err: unknown): void {
    if (clientSocket.destroyed || !clientSocket.writable) return;
    const rep = err instanceof BridgeHttpError ? err.socksReplyCode : 0x01;
    clientSocket.end(Buffer.from([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
  }

  private handleClientSocket(clientSocket: net.Socket, httpSrv: http.Server): void {
    if (this.closed) {
      clientSocket.destroy();
      return;
    }
    this.trackSocket(clientSocket);

    const firstByteTimer = setTimeout(() => {
      if (!clientSocket.destroyed) clientSocket.destroy();
    }, HANDSHAKE_TIMEOUT_MS);
    firstByteTimer.unref?.();

    const clearFirstByteTimer = () => clearTimeout(firstByteTimer);
    clientSocket.once('close', clearFirstByteTimer);
    clientSocket.on('error', () => {
      clearFirstByteTimer();
      if (!clientSocket.destroyed) clientSocket.destroy();
    });

    const onFirstChunk = (firstChunk: Buffer) => {
      if (firstChunk.length === 0) {
        clientSocket.once('data', onFirstChunk);
        return;
      }
      clearFirstByteTimer();
      if (firstChunk[0] === 0x05) {
        void this.handleSocks5Connection(clientSocket, firstChunk);
      } else {
        // 交由 Node 原生 HTTP 解析器处理 CONNECT 与明文 HTTP，准确区分请求头与大体积请求体
        clientSocket.pause();
        clientSocket.unshift(firstChunk);
        httpSrv.emit('connection', clientSocket);
        clientSocket.resume();
      }
    };

    clientSocket.once('data', onFirstChunk);
  }

  private async handleHttpConnect(
    req: http.IncomingMessage,
    clientSocket: net.Socket,
    head: Buffer
  ): Promise<void> {
    if (this.closed) {
      clientSocket.destroy();
      return;
    }
    const connCtrl = new AbortController();
    this.activeConnections.add(connCtrl);
    const handshakeTimer = setTimeout(() => {
      connCtrl.abort(makeAbortError('代理握手超时'));
      if (!clientSocket.destroyed) clientSocket.destroy();
    }, HANDSHAKE_TIMEOUT_MS);
    handshakeTimer.unref?.();

    const abortConn = (reason: string) => {
      if (!connCtrl.signal.aborted) {
        connCtrl.abort(makeAbortError(reason));
      }
    };
    const cleanupHandshake = () => {
      clearTimeout(handshakeTimer);
    };
    const cleanupConn = () => {
      cleanupHandshake();
      this.activeConnections.delete(connCtrl);
      abortConn('客户端连接已关闭');
    };

    clientSocket.once('close', cleanupConn);
    clientSocket.once('error', () => {
      cleanupConn();
      if (!clientSocket.destroyed) clientSocket.destroy();
    });

    const handshakeGuard = attachTunnelHandshakeGuard(clientSocket, head, () => {
      abortConn('客户端在隧道握手期间关闭连接');
    });

    try {
      const parsed = parseConnectAuthority(req.url || '');
      if (!parsed) {
        throw new BridgeHttpError(400, 'Bad Request', `无效的 CONNECT 目标：${req.url || ''}`);
      }
      const { upstreamSocket, upHead } = await this.openUpstreamIpv4Tunnel(
        parsed.host,
        parsed.port,
        connCtrl.signal
      );
      cleanupHandshake();
      const clientRemainder = handshakeGuard.collectAndDetach();
      if (clientSocket.destroyed || connCtrl.signal.aborted) {
        upstreamSocket.destroy();
        return;
      }
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      this.pipeBidirectional(clientSocket, upstreamSocket, upHead, clientRemainder);
    } catch (err) {
      handshakeGuard.dispose();
      cleanupHandshake();
      if (!isAbortError(err) && !clientSocket.destroyed) {
        this.writeHttpErrorAndClose(clientSocket, err);
      } else if (!clientSocket.destroyed) {
        clientSocket.destroy();
      }
    }
  }

  private async handlePlainHttpRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): Promise<void> {
    if (this.closed) {
      res.destroy();
      return;
    }
    const connCtrl = new AbortController();
    this.activeConnections.add(connCtrl);
    const handshakeTimer = setTimeout(() => {
      connCtrl.abort(makeAbortError('代理握手超时'));
      if (!res.destroyed) res.destroy();
    }, HANDSHAKE_TIMEOUT_MS);
    handshakeTimer.unref?.();

    const abortConn = (reason: string) => {
      if (!connCtrl.signal.aborted) {
        connCtrl.abort(makeAbortError(reason));
      }
    };
    const cleanupHandshake = () => {
      clearTimeout(handshakeTimer);
    };
    const onClientAbort = () => abortConn('客户端取消了 HTTP 请求');
    const cleanupConn = () => {
      cleanupHandshake();
      this.activeConnections.delete(connCtrl);
      req.removeListener('aborted', onClientAbort);
      req.socket?.removeListener('close', onClientAbort);
      abortConn('客户端请求已关闭');
    };

    req.once('aborted', onClientAbort);
    req.socket?.once('close', onClientAbort);
    res.once('close', () => {
      if (!res.writableEnded) {
        onClientAbort();
      }
      cleanupConn();
    });

    // 握手期间主动缓冲请求体（有上限背压），同时保持底层 socket 活跃以立即感知客户端断开
    const bodyChunks: Buffer[] = [];
    let bufferedBytes = 0;
    let reqEnded = false;
    let detachedReq = false;
    const onReqData = (chunk: Buffer) => {
      if (detachedReq) return;
      bodyChunks.push(chunk);
      bufferedBytes += chunk.length;
      if (bufferedBytes >= MAX_HANDSHAKE_BODY_BYTES) {
        req.pause();
      }
    };
    const onReqEnd = () => {
      reqEnded = true;
    };
    req.on('data', onReqData);
    req.once('end', onReqEnd);

    const detachReqBuffering = () => {
      if (detachedReq) return;
      detachedReq = true;
      req.removeListener('data', onReqData);
      req.removeListener('end', onReqEnd);
    };

    try {
      const target = req.url || '';
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(target);
      } catch {
        throw new BridgeHttpError(400, 'Bad Request', `无效的代理请求 URL：${target}`);
      }
      if (parsedUrl.protocol !== 'http:') {
        throw new BridgeHttpError(400, 'Bad Request', `不支持的明文代理协议：${parsedUrl.protocol}`);
      }
      const targetPort = parsedUrl.port ? Number(parsedUrl.port) : 80;
      if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
        throw new BridgeHttpError(400, 'Bad Request', `无效的目标端口：${parsedUrl.port}`);
      }

      const { upstreamSocket, upHead } = await this.openUpstreamIpv4Tunnel(
        parsedUrl.hostname,
        targetPort,
        connCtrl.signal
      );
      cleanupHandshake();
      if (res.destroyed || connCtrl.signal.aborted) {
        detachReqBuffering();
        upstreamSocket.destroy();
        return;
      }

      if (upHead.length > 0) {
        upstreamSocket.unshift(upHead);
      }
      if (!upstreamSocket.destroyed) {
        upstreamSocket.resume();
      }

      const forwardedHeaders: http.OutgoingHttpHeaders = {};
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        const rawKey = req.rawHeaders[i];
        const rawVal = req.rawHeaders[i + 1];
        const lower = rawKey.toLowerCase();
        if (lower === 'proxy-connection' || lower === 'proxy-authorization' || lower === 'connection') {
          continue;
        }
        const existing = forwardedHeaders[rawKey];
        if (existing === undefined) {
          forwardedHeaders[rawKey] = rawVal;
        } else if (Array.isArray(existing)) {
          existing.push(rawVal);
        } else {
          forwardedHeaders[rawKey] = [String(existing), rawVal];
        }
      }
      if (!Object.keys(forwardedHeaders).some((k) => k.toLowerCase() === 'host')) {
        forwardedHeaders.Host = parsedUrl.host;
      }
      forwardedHeaders.Connection = 'close';

      const originPath = `${parsedUrl.pathname || '/'}${parsedUrl.search}`;
      const upReq = http.request({
        method: req.method || 'GET',
        path: originPath,
        headers: forwardedHeaders,
        createConnection: () => upstreamSocket,
      });

      const onUpstreamAbort = () => {
        upReq.destroy();
        if (!upstreamSocket.destroyed) upstreamSocket.destroy();
      };
      connCtrl.signal.addEventListener('abort', onUpstreamAbort, { once: true });

      upReq.once('response', (upRes) => {
        const responseHeaders: http.OutgoingHttpHeaders = { ...upRes.headers, connection: 'close' };
        if (!res.headersSent && !res.destroyed) {
          res.writeHead(upRes.statusCode || 502, upRes.statusMessage, responseHeaders);
        }
        upRes.pipe(res);
        upRes.once('error', () => {
          if (!res.destroyed) res.destroy();
        });
      });
      upReq.once('error', (err) => {
        if (!res.headersSent && !res.destroyed) {
          this.writeHttpResponseError(res, err);
        } else if (!res.destroyed) {
          res.destroy();
        }
      });
      upReq.once('close', () => {
        connCtrl.signal.removeEventListener('abort', onUpstreamAbort);
      });

      detachReqBuffering();
      for (const chunk of bodyChunks) {
        if (upReq.destroyed) break;
        upReq.write(chunk);
      }
      bodyChunks.length = 0;

      // 仅以请求流实际触发 end（已交付全部内部缓冲字节）为准；不可用 req.complete 判断，
      // 否则在握手期间因达到背压上限 pause() 且 parser 已读完 EOF 时会过早结束上游请求并截断请求体。
      if (reqEnded) {
        if (!upReq.destroyed) upReq.end();
      } else {
        req.pipe(upReq);
        req.resume();
      }
    } catch (err) {
      detachReqBuffering();
      cleanupHandshake();
      if (!isAbortError(err) && !res.destroyed) {
        this.writeHttpResponseError(res, err);
      } else if (!res.destroyed) {
        res.destroy();
      }
    }
  }

  private async handleSocks5Connection(
    clientSocket: net.Socket,
    firstChunk: Buffer
  ): Promise<void> {
    if (this.closed) {
      clientSocket.destroy();
      return;
    }
    const connCtrl = new AbortController();
    this.activeConnections.add(connCtrl);
    const handshakeTimer = setTimeout(() => {
      connCtrl.abort(makeAbortError('代理握手超时'));
      if (!clientSocket.destroyed) clientSocket.destroy();
    }, HANDSHAKE_TIMEOUT_MS);
    handshakeTimer.unref?.();

    const abortConn = (reason: string) => {
      if (!connCtrl.signal.aborted) {
        connCtrl.abort(makeAbortError(reason));
      }
    };
    const cleanupHandshake = () => {
      clearTimeout(handshakeTimer);
    };
    const cleanupConn = () => {
      cleanupHandshake();
      this.activeConnections.delete(connCtrl);
      abortConn('客户端连接已关闭');
    };

    clientSocket.once('close', cleanupConn);
    clientSocket.once('error', () => {
      cleanupConn();
      if (!clientSocket.destroyed) clientSocket.destroy();
    });

    const reader = new SocketByteReader(clientSocket, firstChunk);
    let handshakeGuard: TunnelHandshakeGuard | null = null;
    try {
      const greeting = await reader.readExact(2, connCtrl.signal);
      if (greeting[0] !== 0x05) {
        throw new BridgeHttpError(400, 'Bad Request', '无效的 SOCKS5 版本', 0x01);
      }
      const nmethods = greeting[1];
      const methods = await reader.readExact(nmethods, connCtrl.signal);
      if (!methods.includes(0x00)) {
        clientSocket.end(Buffer.from([0x05, 0xff]));
        reader.detachRemaining(false);
        cleanupHandshake();
        return;
      }
      clientSocket.write(Buffer.from([0x05, 0x00]));

      const header = await reader.readExact(4, connCtrl.signal);
      if (header[0] !== 0x05) {
        throw new BridgeHttpError(400, 'Bad Request', '无效的 SOCKS5 请求头', 0x01);
      }
      const cmd = header[1];
      const atyp = header[3];

      let targetHost: string;
      if (atyp === 0x01) {
        const rawIp = await reader.readExact(4, connCtrl.signal);
        targetHost = `${rawIp[0]}.${rawIp[1]}.${rawIp[2]}.${rawIp[3]}`;
      } else if (atyp === 0x03) {
        const lenBuf = await reader.readExact(1, connCtrl.signal);
        const domainBuf = await reader.readExact(lenBuf[0], connCtrl.signal);
        targetHost = domainBuf.toString('utf8');
      } else if (atyp === 0x04) {
        await reader.readExact(18, connCtrl.signal);
        throw new BridgeHttpError(403, 'Forbidden', '已开启强制 IPv4 出站，已拦截 SOCKS5 IPv6 请求', 0x02);
      } else {
        throw new BridgeHttpError(400, 'Bad Request', `不支持的 SOCKS5 地址类型：${atyp}`, 0x08);
      }

      const portBuf = await reader.readExact(2, connCtrl.signal);
      const targetPort = portBuf.readUInt16BE(0);
      const initialRemainder = reader.detachRemaining(false);

      if (cmd !== 0x01) {
        throw new BridgeHttpError(400, 'Bad Request', `不支持的 SOCKS5 命令：${cmd}`, 0x07);
      }

      handshakeGuard = attachTunnelHandshakeGuard(clientSocket, initialRemainder, () => {
        abortConn('SOCKS5 客户端在握手期间关闭连接');
      });

      const { upstreamSocket, upHead } = await this.openUpstreamIpv4Tunnel(
        targetHost,
        targetPort,
        connCtrl.signal
      );
      cleanupHandshake();
      const clientRemainder = handshakeGuard.collectAndDetach();
      if (clientSocket.destroyed || connCtrl.signal.aborted) {
        upstreamSocket.destroy();
        return;
      }

      clientSocket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      this.pipeBidirectional(clientSocket, upstreamSocket, upHead, clientRemainder);
    } catch (err) {
      handshakeGuard?.dispose();
      reader.detachRemaining(false);
      cleanupHandshake();
      if (!isAbortError(err) && !clientSocket.destroyed) {
        this.writeSocksErrorAndClose(clientSocket, err);
      } else if (!clientSocket.destroyed) {
        clientSocket.destroy();
      }
    }
  }
}
