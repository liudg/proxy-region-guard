import { isIP } from 'node:net';

type Document = Record<string, unknown>;

export function dnsAddress(value: string): URL {
  if (value === 'system' || value.startsWith('dhcp://')) {
    throw new Error('专属节点 DNS 必须配置独立上游地址，无法保存系统或 DHCP DNS 依赖');
  }
  if (isIP(value) === 6) return new URL(`udp://[${value}]`);
  return new URL(value.includes('://') ? value : `udp://${value}`);
}

function isLocal(address: URL): boolean {
  const host = address.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === '::1' ||
    host === '::' ||
    host === '0.0.0.0' ||
    host.startsWith('127.') ||
    host.startsWith('::ffff:7f')
  );
}

function resolverList(value: unknown): string[] {
  const list = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(list) || !list.length || list.some((item) => typeof item !== 'string' || !item)) {
    throw new Error('节点 DNS 上游必须是非空地址列表');
  }
  return list;
}

/** 将本机 Clash DNS 转发引用展开为保存的独立上游，拒绝无法确定的本机依赖。 */
export function independentNodeDns(source: Document, runtime: Document): Document {
  const result = structuredClone(source);
  const policy =
    source['proxy-server-nameserver-policy'] ||
    (source['proxy-server-nameserver'] ? {} : source['nameserver-policy']) ||
    {};
  const policies: Document = structuredClone(policy as Document);
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new Error('节点 DNS 策略格式无效');
  }
  const expand = (value: unknown, seen: Set<string>): string[] =>
    resolverList(value).flatMap((resolver) => {
      const address = dnsAddress(resolver);
      if (!isLocal(address)) return [resolver];
      if (seen.has(resolver)) throw new Error('节点 DNS 的本地转发依赖存在循环');
      if (
        !['udp:', 'tcp:'].includes(address.protocol) ||
        (address.hash && address.hash !== '#DIRECT')
      ) {
        throw new Error(`无法展开带有加密协议或代理参数的本机 DNS ${address.host}`);
      }
      const upstream = [runtime, source].find((dns) => {
        if (typeof dns.listen !== 'string' || dns.listen.includes('://')) return false;
        const listener = dnsAddress(dns.listen);
        const targetHost = address.hostname === 'localhost' ? '127.0.0.1' : address.hostname;
        const listenerHost = listener.hostname === 'localhost' ? '127.0.0.1' : listener.hostname;
        const matchesAddress =
          listenerHost === targetHost ||
          (listenerHost === '0.0.0.0' && isIP(targetHost) === 4) ||
          (listenerHost === '[::]' && isIP(targetHost.replace(/^\[|\]$/g, '')) === 6);
        return matchesAddress && (listener.port || '53') === (address.port || '53');
      });
      if (!upstream || !upstream.nameserver) {
        throw new Error(`无法确定本机 DNS ${address.host} 的独立上游，请在订阅中配置明确的 DNS 上游`);
      }
      if (upstream.fallback || upstream['respect-rules']) {
        throw new Error('本机 DNS 使用动态分流策略，请为专属节点明确配置 proxy-server-nameserver');
      }
      const next = new Set(seen).add(resolver);
      const inheritedPolicy = upstream['nameserver-policy'];
      if (inheritedPolicy && typeof inheritedPolicy === 'object' && !Array.isArray(inheritedPolicy)) {
        for (const [domain, servers] of Object.entries(inheritedPolicy)) {
          if (!(domain in policies)) policies[domain] = expand(servers, next);
        }
      }
      return expand(upstream.nameserver, next);
    });
  result['proxy-server-nameserver'] = expand(
    source['proxy-server-nameserver'] || source.nameserver || ['https://223.5.5.5/dns-query'],
    new Set()
  );
  for (const domain of Object.keys(policies)) {
    policies[domain] = expand(policies[domain], new Set());
  }
  result['proxy-server-nameserver-policy'] = policies;
  return result;
}

export function dnsProxyReferences(dns: Document, names: ReadonlySet<string>): string[] {
  const references = new Set<string>();
  const collect = (value: unknown): void => {
    if (Array.isArray(value)) {
      value.forEach(collect);
      return;
    }
    if (value && typeof value === 'object') {
      Object.values(value).forEach(collect);
      return;
    }
    if (typeof value !== 'string') return;
    const address = dnsAddress(value);
    const exactName = decodeURIComponent(address.hash.slice(1));
    if (names.has(exactName)) {
      references.add(exactName);
      return;
    }
    for (const [name] of new URLSearchParams(address.hash.slice(1))) {
      if (names.has(name)) references.add(name);
    }
  };
  collect(dns['proxy-server-nameserver']);
  collect(dns['proxy-server-nameserver-policy']);
  return [...references];
}
