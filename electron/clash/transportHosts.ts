import * as net from 'node:net';

export interface TraceEndpoint {
  name: string;
  url: string;
  format: 'cf-trace' | 'plain-ip';
  registrableDomain: string;
}

export const BUILTIN_TRACE_ENDPOINTS: readonly TraceEndpoint[] = [
  {
    name: 'Cloudflare IPv4 Trace',
    url: 'https://ipv4.icanhazip.com/cdn-cgi/trace',
    format: 'cf-trace',
    registrableDomain: 'icanhazip.com',
  },
  {
    name: 'AWS CheckIP (IPv4)',
    url: 'https://checkip.amazonaws.com',
    format: 'plain-ip',
    registrableDomain: 'amazonaws.com',
  },
  {
    name: 'IPify IPv4',
    url: 'https://api.ipify.org',
    format: 'plain-ip',
    registrableDomain: 'ipify.org',
  },
  {
    name: 'Cloudflare Connectivity Trace',
    url: 'https://cp.cloudflare.com/cdn-cgi/trace',
    format: 'cf-trace',
    registrableDomain: 'cloudflare.com',
  },
  {
    name: 'IdentMe Echo',
    url: 'https://ident.me',
    format: 'plain-ip',
    registrableDomain: 'ident.me',
  },
];

export function doesHostShareDomain(rawHost: string, registrableDomain: string): boolean {
  const host = rawHost.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const domain = registrableDomain.trim().toLowerCase().replace(/\.$/, '');
  if (!host || !domain || net.isIP(host) !== 0) return false;
  return host === domain || host.endsWith(`.${domain}`);
}

export function selectProbeEndpointsForTransportHosts(
  endpoints: readonly TraceEndpoint[],
  transportHosts: readonly string[]
): TraceEndpoint[] {
  if (transportHosts.length === 0) return [...endpoints];
  return endpoints.filter(
    (ep) => !transportHosts.some((host) => doesHostShareDomain(host, ep.registrableDomain))
  );
}

function collectTransportHostValue(raw: unknown, out: Set<string>): void {
  if (Array.isArray(raw)) {
    for (const item of raw) collectTransportHostValue(item, out);
    return;
  }
  if (typeof raw !== 'string') return;
  let host = raw.trim().toLowerCase();
  if (!host) return;
  if (host.startsWith('[') && host.includes(']')) {
    host = host.slice(1, host.indexOf(']'));
  } else {
    const firstColon = host.indexOf(':');
    if (firstColon > 0 && host.indexOf(':', firstColon + 1) === -1) {
      host = host.slice(0, firstColon);
    }
  }
  host = host.replace(/\.$/, '');
  if (!host || net.isIP(host) !== 0) return;
  out.add(host);
}

function collectHeadersHostField(headersRaw: unknown, out: Set<string>): void {
  if (!headersRaw || typeof headersRaw !== 'object' || Array.isArray(headersRaw)) return;
  for (const [k, v] of Object.entries(headersRaw as Record<string, unknown>)) {
    if (k.trim().toLowerCase() === 'host') {
      collectTransportHostValue(v, out);
    }
  }
}

export function extractProxyTransportHosts(
  proxies: ReadonlyArray<Record<string, unknown>> | null | undefined
): string[] {
  if (!proxies || proxies.length === 0) return [];
  const hosts = new Set<string>();
  for (const proxyObj of proxies) {
    if (!proxyObj || typeof proxyObj !== 'object') continue;
    const proxyType = String(proxyObj['type'] || '').trim().toLowerCase();
    const network = String(proxyObj['network'] || 'tcp').trim().toLowerCase();
    const tlsEnabled = proxyObj['tls'] === true;

    collectTransportHostValue(proxyObj['server'], hosts);

    if (proxyType === 'direct' || proxyType === 'reject') {
      continue;
    }

    if (proxyType === 'http') {
      collectHeadersHostField(proxyObj['headers'], hosts);
      if (tlsEnabled) {
        collectTransportHostValue(proxyObj['sni'], hosts);
      }
      continue;
    }

    if (proxyType === 'socks5') {
      if (tlsEnabled) {
        collectTransportHostValue(proxyObj['sni'], hosts);
      }
      continue;
    }

    if (proxyType === 'vmess' || proxyType === 'vless' || proxyType === 'trojan') {
      const realityOpts = proxyObj['reality-opts'];
      const hasReality =
        Boolean(realityOpts) && typeof realityOpts === 'object' && !Array.isArray(realityOpts);
      if (proxyType === 'trojan' || tlsEnabled || hasReality) {
        collectTransportHostValue(proxyObj['servername'], hosts);
        collectTransportHostValue(proxyObj['sni'], hosts);
        if (hasReality) {
          collectTransportHostValue((realityOpts as Record<string, unknown>)['servername'], hosts);
        }
      }
      if (network === 'ws') {
        const wsOpts = proxyObj['ws-opts'];
        if (wsOpts && typeof wsOpts === 'object' && !Array.isArray(wsOpts)) {
          collectHeadersHostField((wsOpts as Record<string, unknown>)['headers'], hosts);
        }
      } else if (network === 'http') {
        const httpOpts = proxyObj['http-opts'];
        if (httpOpts && typeof httpOpts === 'object' && !Array.isArray(httpOpts)) {
          collectHeadersHostField((httpOpts as Record<string, unknown>)['headers'], hosts);
        }
      } else if (network === 'h2') {
        const h2Opts = proxyObj['h2-opts'];
        if (h2Opts && typeof h2Opts === 'object' && !Array.isArray(h2Opts)) {
          collectTransportHostValue((h2Opts as Record<string, unknown>)['host'], hosts);
        }
      } else if (network === 'grpc') {
        collectTransportHostValue(proxyObj['servername'], hosts);
      } else if (proxyType === 'vless' && network === 'xhttp') {
        const xhttpOpts = proxyObj['xhttp-opts'];
        const xo =
          xhttpOpts && typeof xhttpOpts === 'object' && !Array.isArray(xhttpOpts)
            ? (xhttpOpts as Record<string, unknown>)
            : null;
        const primaryHost = typeof xo?.['host'] === 'string' ? xo['host'].trim() : '';
        if (xo) {
          // Mihomo XHTTP 仅发送 xhttp-opts.host（缺省回退 servername/server），req.Header 中的 Host 会被 HTTP 客户端忽略
          collectTransportHostValue(xo['host'], hosts);
        }
        if (!primaryHost) {
          collectTransportHostValue(proxyObj['servername'], hosts);
        }
        const downloadSettings = xo?.['download-settings'];
        if (
          downloadSettings &&
          typeof downloadSettings === 'object' &&
          !Array.isArray(downloadSettings)
        ) {
          const ds = downloadSettings as Record<string, unknown>;
          collectTransportHostValue(ds['server'], hosts);
          collectTransportHostValue(ds['host'], hosts);
          const effectiveDsHost =
            typeof ds['host'] === 'string' ? ds['host'].trim() : primaryHost;
          const dsTls = typeof ds['tls'] === 'boolean' ? ds['tls'] : tlsEnabled;
          const dsReality = ds['reality-opts'];
          const dsHasReality =
            Boolean(dsReality) && typeof dsReality === 'object' && !Array.isArray(dsReality);
          if (dsTls || dsHasReality || !effectiveDsHost) {
            collectTransportHostValue(ds['servername'], hosts);
            if (typeof ds['servername'] !== 'string' || !ds['servername'].trim()) {
              collectTransportHostValue(proxyObj['servername'], hosts);
            }
          }
          if (dsHasReality) {
            collectTransportHostValue((dsReality as Record<string, unknown>)['servername'], hosts);
          }
        }
      }
      continue;
    }

    if (proxyType === 'ss') {
      if (typeof proxyObj['plugin'] === 'string' && proxyObj['plugin'].trim()) {
        const pluginOpts = proxyObj['plugin-opts'];
        if (pluginOpts && typeof pluginOpts === 'object' && !Array.isArray(pluginOpts)) {
          const po = pluginOpts as Record<string, unknown>;
          collectTransportHostValue(po['host'], hosts);
          collectTransportHostValue(po['tls-host'], hosts);
          collectTransportHostValue(po['sni'], hosts);
          collectHeadersHostField(po['headers'], hosts);
        }
      }
      continue;
    }

    if (proxyType === 'ssr') {
      const obfs = String(proxyObj['obfs'] || '').trim().toLowerCase();
      if (obfs === 'http_simple' || obfs === 'http_post' || obfs === 'tls1.2_ticket_auth') {
        collectTransportHostValue(proxyObj['obfs-param'], hosts);
      }
      continue;
    }

    if (proxyType === 'snell') {
      const obfsOpts = proxyObj['obfs-opts'];
      if (obfsOpts && typeof obfsOpts === 'object' && !Array.isArray(obfsOpts)) {
        collectTransportHostValue((obfsOpts as Record<string, unknown>)['host'], hosts);
      }
      continue;
    }

    // hysteria / hysteria2 / tuic / anytls 等默认基于 TLS/QUIC 的协议
    collectTransportHostValue(proxyObj['servername'], hosts);
    collectTransportHostValue(proxyObj['sni'], hosts);
  }
  return [...hosts].sort();
}

export function extractSnapshotTransportHosts(
  snapshot: { proxies: ReadonlyArray<Record<string, unknown>> } | null | undefined
): string[] {
  return extractProxyTransportHosts(snapshot?.proxies);
}
