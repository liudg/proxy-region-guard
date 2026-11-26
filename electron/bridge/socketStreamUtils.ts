import * as net from 'node:net';
import {
  BridgeHttpError,
  makeAbortError,
  MAX_HANDSHAKE_BODY_BYTES,
} from './bridgeTypes';

export class SocketByteReader {
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
    const merged =
      this.chunks.length === 0
        ? Buffer.alloc(0)
        : this.chunks.length === 1
        ? this.chunks[0]
        : Buffer.concat(this.chunks);
    this.chunks = [];
    this.totalBytes = 0;
    return merged;
  }
}

export interface TunnelHandshakeGuard {
  collectAndDetach: () => Buffer;
  dispose: () => void;
}

/**
 * 在 CONNECT / SOCKS5 握手等待 DNS 或上游建连期间保持客户端套接字可读，
 * 以便立即感知客户端 FIN/RST 取消握手并释放上游连接，同时有限缓冲早到负载字节。
 */
export function attachTunnelHandshakeGuard(
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

export function pipeBidirectional(
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
