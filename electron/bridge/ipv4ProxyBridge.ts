import { randomBytes } from 'node:crypto';
import * as http from 'node:http';
import * as net from 'node:net';
import {
  BridgeHttpError,
  HANDSHAKE_TIMEOUT_MS,
  Ipv4ProxyBridgeOptions,
  isAbortError,
  makeAbortError,
  MAX_HANDSHAKE_BODY_BYTES,
  MAX_HEADER_BYTES,
  parseConnectAuthority,
  registerBridgeRefusedToken,
  unregisterBridgeRefusedToken,
  UPSTREAM_REFUSED_HEADER,
} from './bridgeTypes';
import { Ipv4DnsResolverCache } from './ipv4DnsCache';
import {
  attachTunnelHandshakeGuard,
  pipeBidirectional,
  SocketByteReader,
  TunnelHandshakeGuard,
} from './socketStreamUtils';
import { UpstreamIpv4TunnelDialer } from './upstreamIpv4Tunnel';

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
  private readonly activeSockets = new Set<net.Socket>();
  private readonly activeConnections = new Set<AbortController>();
  private readonly dnsCache: Ipv4DnsResolverCache;
  private readonly tunnelDialer: UpstreamIpv4TunnelDialer;

  constructor(private readonly options: Ipv4ProxyBridgeOptions) {
    this.dnsCache = new Ipv4DnsResolverCache(options.resolveIpv4);
    this.tunnelDialer = new UpstreamIpv4TunnelDialer(
      options.getUpstreamTarget,
      this.dnsCache,
      (sock) => this.trackSocket(sock)
    );
  }

  public getPort(): number | null {
    return this.port;
  }

  public isListening(): boolean {
    return Boolean(this.server && this.server.listening && this.port !== null && !this.closed);
  }

  public clearDnsCache(): void {
    this.dnsCache.clear();
  }

  public disconnectAll(reason = '私有代理通道不可用'): void {
    this.dnsCache.clear();
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
    this.dnsCache.reopen();
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
          unregisterBridgeRefusedToken(prevPort);
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
        registerBridgeRefusedToken(addr.port, this.refusedToken);
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
    unregisterBridgeRefusedToken(boundPort);
    this.dnsCache.close();
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
      const { upstreamSocket, upHead } = await this.tunnelDialer.openTunnel(
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
      pipeBidirectional(clientSocket, upstreamSocket, upHead, clientRemainder);
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

      const { upstreamSocket, upHead } = await this.tunnelDialer.openTunnel(
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

      // 仅以请求流实际触发 end（已交付全部内部缓冲字节）为准；不可用 req.complete 判断
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

      const { upstreamSocket, upHead } = await this.tunnelDialer.openTunnel(
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
      pipeBidirectional(clientSocket, upstreamSocket, upHead, clientRemainder);
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
