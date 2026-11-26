import * as net from 'node:net';
import {
  BridgeHttpError,
  DNS_CACHE_MAX_ENTRIES,
  Ipv4ResolveResult,
  makeAbortError,
} from './bridgeTypes';

interface InFlightDnsEntry {
  epoch: number;
  waiters: number;
  controller: AbortController;
  promise: Promise<Ipv4ResolveResult>;
}

export class Ipv4DnsResolverCache {
  private dnsEpoch = 0;
  private closed = false;
  private readonly dnsCache = new Map<string, { ips: string[]; expiresAt: number }>();
  private readonly dnsInFlight = new Map<string, InFlightDnsEntry>();

  constructor(
    private readonly resolveIpv4Fn: (
      hostname: string,
      signal?: AbortSignal
    ) => Promise<Ipv4ResolveResult>
  ) {}

  public reopen(): void {
    this.closed = false;
  }

  public clear(): void {
    this.dnsEpoch++;
    this.dnsCache.clear();
    for (const entry of this.dnsInFlight.values()) {
      entry.controller.abort(makeAbortError('DNS 缓存已重置'));
    }
    this.dnsInFlight.clear();
  }

  public close(): void {
    this.closed = true;
    this.clear();
  }

  public async resolveDomainCached(cleanHost: string, signal: AbortSignal): Promise<string[]> {
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
      const promise = this.resolveIpv4Fn(cleanHost, controller.signal).then((res) => {
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
}
