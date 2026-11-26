import * as http from 'node:http';

export const UPSTREAM_REFUSED_HEADER = 'x-guard-upstream-refused';
export const MAX_HEADER_BYTES = 64 * 1024;
export const MAX_HANDSHAKE_BODY_BYTES = 256 * 1024;
export const HANDSHAKE_TIMEOUT_MS = 15000;
export const DNS_CACHE_MAX_ENTRIES = 512;
export const MAX_IPV4_CONNECT_ATTEMPTS = 2;

const activeBridgeRefusedTokens = new Map<number, string>();

export function registerBridgeRefusedToken(port: number, token: string): void {
  activeBridgeRefusedTokens.set(port, token);
}

export function unregisterBridgeRefusedToken(port: number | null): void {
  if (port !== null) {
    activeBridgeRefusedTokens.delete(port);
  }
}

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

export class BridgeHttpError extends Error {
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

export function isAbortError(err: unknown): boolean {
  return err instanceof Error && err.name === 'AbortError';
}

export function makeAbortError(message = '代理连接已取消'): Error {
  return Object.assign(new Error(message), { name: 'AbortError' });
}

export function parseConnectAuthority(rawAuthority: string): { host: string; port: number } | null {
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
