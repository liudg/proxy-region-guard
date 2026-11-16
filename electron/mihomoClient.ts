import * as http from 'node:http';
import * as net from 'node:net';

export interface MihomoEndpoint {
  pipePath?: string;
  host?: string;
  port?: number;
  secret: string;
}

export function mihomoRequest<T>(endpoint: MihomoEndpoint, route: string, method = 'GET', body?: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
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
    const deadline = setTimeout(() => request.destroy(new Error('内核控制接口请求超时')), 3000);
    request.on('close', () => clearTimeout(deadline));
    request.on('error', reject);
    request.end(payload);
  });
}

export function isLocalPortListening(port: number, timeoutMs = 800): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    const finish = (result: boolean) => { socket.destroy(); resolve(result); };
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.setTimeout(timeoutMs, () => finish(false));
  });
}
