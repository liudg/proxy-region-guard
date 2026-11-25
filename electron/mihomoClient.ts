import * as http from 'node:http';
import * as net from 'node:net';

export interface MihomoEndpoint {
  pipePath?: string;
  host?: string;
  port?: number;
  secret: string;
}

export function mihomoRequest<T>(
  endpoint: MihomoEndpoint,
  route: string,
  method = 'GET',
  body?: unknown,
  signal?: AbortSignal,
  timeoutMs = 3000
): Promise<T> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? Object.assign(new Error('内核控制接口请求已取消'), { name: 'AbortError' }));
      return;
    }
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const request = http.request({
      socketPath: endpoint.pipePath,
      hostname: endpoint.host || '127.0.0.1',
      port: endpoint.port,
      path: route,
      method,
      headers: {
        Authorization: `Bearer ${endpoint.secret}`,
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
      agent: false,
    }, (response) => {
      const chunks: Buffer[] = [];
      let bytes = 0;
      response.on('data', (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > 8 * 1024 * 1024) response.destroy(new Error('内核控制接口响应超过大小限制'));
        else chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => {
        if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
          reject(new Error(`内核控制接口 ${method} ${route} 返回 HTTP ${response.statusCode}`));
          return;
        }
        try {
          const text = Buffer.concat(chunks).toString('utf8');
          resolve((text ? JSON.parse(text) : undefined) as T);
        } catch (error) { reject(error); }
      });
    });
    const onAbort = () => {
      request.destroy(
        signal?.reason instanceof Error
          ? signal.reason
          : Object.assign(new Error('内核控制接口请求已取消'), { name: 'AbortError' })
      );
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    const deadline = setTimeout(() => request.destroy(new Error('内核控制接口请求超时')), Math.max(100, timeoutMs));
    request.on('close', () => {
      clearTimeout(deadline);
      signal?.removeEventListener('abort', onAbort);
    });
    request.on('error', reject);
    request.end(payload);
  });
}

export function isLocalPortListening(port: number, timeoutMs = 800, signal?: AbortSignal): Promise<boolean> {
  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve(false);
      return;
    }
    const socket = net.connect({ host: '127.0.0.1', port });
    let settled = false;
    const onAbort = () => finish(false);
    const finish = (result: boolean) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      socket.destroy();
      resolve(result);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.setTimeout(timeoutMs, () => finish(false));
  });
}
