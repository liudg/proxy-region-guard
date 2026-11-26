import { app } from 'electron';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { MihomoEndpoint, mihomoRequest } from '../../electron/clash';
import { PrivateProxyService } from '../../electron/kernel';
import { TraceEndpoint } from '../../electron/probe';

assert.ok(process.env.GUARD_TEST_DATA);
export const root = process.env.GUARD_TEST_DATA;
fs.mkdirSync(root, { recursive: true });
app.setPath('userData', root);

const activeServices = new Set<PrivateProxyService>();

export function trackService(svc: PrivateProxyService): PrivateProxyService {
  activeServices.add(svc);
  return svc;
}

export function untrackService(svc: PrivateProxyService): void {
  activeServices.delete(svc);
}

export function hasTrackedService(svc: PrivateProxyService): boolean {
  return activeServices.has(svc);
}

export async function shutdownAllServices(): Promise<void> {
  const pending = [...activeServices];
  activeServices.clear();
  await Promise.allSettled(pending.map((svc) => svc.shutdown()));
}

export async function listen(server: net.Server, host = '127.0.0.1'): Promise<number> {
  server.listen(0, host);
  await once(server, 'listening');
  return (server.address() as net.AddressInfo).port;
}

export async function freePort(): Promise<number> {
  const srv = net.createServer();
  const port = await listen(srv, '127.0.0.1');
  await new Promise<void>((resolve) => srv.close(() => resolve()));
  return port;
}

export function readLeaseEndpoint(kernelChannelDir: string): {
  endpoint: MihomoEndpoint;
  configPath: string;
  configText: string;
} {
  const lease = JSON.parse(
    fs.readFileSync(path.join(kernelChannelDir, 'runtime.json'), 'utf8')
  ) as {
    revision: string;
    endpoint: MihomoEndpoint;
  };
  const configPath = path.join(kernelChannelDir, lease.revision, 'config.yaml');
  return {
    endpoint: lease.endpoint,
    configPath,
    configText: fs.readFileSync(configPath, 'utf8'),
  };
}

export async function reloadKernelConfig(
  endpoint: MihomoEndpoint,
  payload: string
): Promise<void> {
  await mihomoRequest(endpoint, '/configs?force=true', 'PUT', { payload });
}

export function extractEchoIpFromBody(
  raw: string,
  format: TraceEndpoint['format']
): string {
  const text = raw.trim();
  if (format === 'cf-trace' || /^ip=/m.test(text)) {
    return /^ip=(.+)$/m.exec(text)?.[1].trim() ?? '';
  }
  return text.split(/\r?\n/)[0]?.trim() ?? '';
}

export function parseHttpConnectAuthority(
  authority: string | undefined
): { host: string; port: number } | null {
  if (!authority) return null;
  try {
    const parsed = new URL(`http://${authority.trim()}`);
    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    const port = Number(parsed.port);
    if (!host || !Number.isInteger(port) || port <= 0) return null;
    return { host, port };
  } catch {
    return null;
  }
}

export function parseHttpHostHeader(rawHost: string | undefined): string | null {
  if (!rawHost) return null;
  try {
    const parsed = new URL(`http://${rawHost.trim()}`);
    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    return host || null;
  } catch {
    return null;
  }
}
