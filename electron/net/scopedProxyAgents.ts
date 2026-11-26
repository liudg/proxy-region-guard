import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { isRegisteredBridgeUpstreamRefusedHeader } from '../bridge';
import { MAX_HEADER_BYTES } from './proxyUrl';

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

export class ScopedHttpsProxyAgent extends HttpsProxyAgent<string> {
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
          if (
            response.statusCode === 503 &&
            isRegisteredBridgeUpstreamRefusedHeader(this.proxy.href, response.headers)
          ) {
            const proxyHost = String(this.connectOpts.host || '127.0.0.1');
            const proxyPort = Number(this.connectOpts.port);
            reject(
              Object.assign(
                new Error(`connect ECONNREFUSED ${proxyHost}:${proxyPort}`),
                { code: 'ECONNREFUSED', address: proxyHost, port: proxyPort }
              )
            );
            return;
          }
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

export class ScopedSocksProxyAgent extends SocksProxyAgent {
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

export function createOneShotAgent(
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

export function timeoutMsOrBudget(budgetMs: number): number {
  return Math.max(1, budgetMs);
}
