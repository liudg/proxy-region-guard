import * as net from 'node:net';
import {
  BridgeHttpError,
  BridgeUpstreamTarget,
  isAbortError,
  makeAbortError,
  MAX_HEADER_BYTES,
  MAX_IPV4_CONNECT_ATTEMPTS,
} from './bridgeTypes';
import { Ipv4DnsResolverCache } from './ipv4DnsCache';
import { SocketByteReader } from './socketStreamUtils';

export class UpstreamIpv4TunnelDialer {
  constructor(
    private readonly getUpstreamTarget: (
      signal?: AbortSignal
    ) => Promise<BridgeUpstreamTarget> | BridgeUpstreamTarget,
    private readonly dnsCache: Ipv4DnsResolverCache,
    private readonly trackSocket: (sock: net.Socket) => void
  ) {}

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
    const target = await this.getUpstreamTarget(signal);
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

  public async openTunnel(
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
        ips = await this.dnsCache.resolveDomainCached(cleanHost, stepSignal);
        const connectedSock = await tcpPromise;
        if (tcpState.err) {
          throw tcpState.err;
        }
        // 建连后二次核验端口与世代：若解析期间端口或内核世代已变更，销毁预连接并阻断旧请求转发
        const verifiedAfterDns = await this.resolveVerifiedUpstreamTarget(signal);
        if (
          verifiedAfterDns.port !== upstreamPort ||
          verifiedAfterDns.generation !== upstreamGeneration
        ) {
          if (connectedSock && !connectedSock.destroyed) {
            connectedSock.destroy();
          }
          throw new BridgeHttpError(
            503,
            'Service Unavailable',
            '私有代理端口或内核世代在解析期间发生变更，已阻断旧请求转发',
            0x02,
            false
          );
        }
        preconnectedSocket = connectedSock;
        tcpState.handedOff = true;
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
          verifiedBeforeDial.port !== upstreamPort ||
          verifiedBeforeDial.generation !== upstreamGeneration
        ) {
          destroyPreconnected();
          throw new BridgeHttpError(
            503,
            'Service Unavailable',
            '私有代理端口或内核世代在建连前发生变更，已阻断旧请求转发',
            0x02,
            false
          );
        }
        if (
          i === 0 &&
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
}
