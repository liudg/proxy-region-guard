import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import * as os from 'node:os';
import { createHash } from 'node:crypto';
import { Script, createContext } from 'node:vm';
import * as yaml from 'js-yaml';
import { ClashProfileGroupOption } from '../src/shared/types';
import { independentNodeDns, dnsProxyReferences } from './nodeDns';

type Document = Record<string, unknown>;
export interface NodeSnapshot {
  schema: 1;
  profileUid: string;
  profileName: string;
  nodeName: string;
  proxies: Document[];
  hosts: Document;
  dns: Document;
  files: Record<string, string>;
  fingerprint: string;
}

export function readYaml(file: string, allowEmpty = false): Document {
  const value = yaml.load(fs.readFileSync(file, 'utf8'));
  if (allowEmpty && (value === null || value === undefined)) return {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`配置必须是 YAML 对象：${path.basename(file)}`);
  return value as Document;
}

export function findVergeDirectory(): string | null {
  const roaming = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
  const local = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  return [path.join(roaming, 'io.github.clash-verge-rev.clash-verge-rev'), path.join(roaming, 'clash-verge'),
    path.join(local, 'io.github.clash-verge-rev.clash-verge-rev')]
    .find((directory) => fs.existsSync(path.join(directory, 'profiles.yaml'))) || null;
}

function object(value: unknown): Document {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Document : {};
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => [key, canonical(entry)]));
  return value;
}

function mergeDocument(base: Document, extra: Document): Document {
  const result = structuredClone(base);
  for (const [key, value] of Object.entries(extra)) {
    if (key.startsWith('prepend-') || key.startsWith('append-')) {
      const field = key.slice(key.indexOf('-') + 1);
      if (!Array.isArray(value)) throw new Error(`扩展配置 ${key} 必须是列表`);
      const current = Array.isArray(result[field]) ? result[field] as unknown[] : [];
      result[field] = key.startsWith('prepend-') ? [...value, ...current] : [...current, ...value];
    } else if (value && typeof value === 'object' && !Array.isArray(value)) {
      result[key] = mergeDocument(object(result[key]), value as Document);
    } else result[key] = structuredClone(value);
  }
  return result;
}

export function snapshotFingerprint(value: Omit<NodeSnapshot, 'fingerprint'>): string {
  return createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
}

interface Profile {
  group: ClashProfileGroupOption;
  nodes: Map<string, Document>;
  hosts: Document;
  dns: Document;
  directory: string;
}

export class SubscriptionCatalog {
  private profiles = new Map<string, Profile>();
  public groups: ClashProfileGroupOption[] = [];
  public errors: string[] = [];

  constructor(public readonly directory: string | null = findVergeDirectory()) {}

  private profileFile(item: Document): string {
    const file = String(item.file || `${item.uid}.yaml`);
    const candidates = path.isAbsolute(file) ? [file] : [path.join(this.directory!, 'profiles', file), path.join(this.directory!, file)];
    const found = candidates.find((candidate) => fs.existsSync(candidate));
    if (!found) throw new Error(`订阅文件不存在：${file}`);
    return found;
  }

  private readNodes(document: Document, nodes: Map<string, Document>): void {
    const append = (entries: unknown, provider: Document = {}) => {
      if (!Array.isArray(entries)) return;
      for (const entry of entries) {
        const proxy = object(entry);
        if (typeof proxy.name !== 'string' || typeof proxy.type !== 'string') throw new Error('节点缺少名称或协议类型');
        if (typeof provider.filter === 'string' && !new RegExp(provider.filter).test(proxy.name)) continue;
        if (typeof provider['exclude-filter'] === 'string' && new RegExp(provider['exclude-filter']).test(proxy.name)) continue;
        if (typeof provider['exclude-type'] === 'string' && provider['exclude-type'].split('|').includes(proxy.type)) continue;
        if (provider['include-filter']) throw new Error('当前节点集合使用了尚未支持的 include-filter 表达式');
        const override = object(provider.override);
        let name = proxy.name;
        if (Array.isArray(override['proxy-name'])) for (const rule of override['proxy-name']) {
          const rename = object(rule);
          name = name.replace(new RegExp(String(rename.pattern), 'g'), String(rename.target));
        }
        name = `${override['additional-prefix'] || ''}${name}${override['additional-suffix'] || ''}`;
        const properties = Object.fromEntries(Object.entries(override).filter(([key]) => !['additional-prefix', 'additional-suffix', 'proxy-name'].includes(key)));
        nodes.set(name, { ...structuredClone(proxy), ...properties, name });
      }
    };
    for (const key of ['prepend', 'prepend-proxies', 'proxies', 'append', 'append-proxies']) append(document[key]);
    for (const entry of Object.values(object(document['proxy-providers']))) {
      const provider = object(entry);
      if (provider.type === 'inline') append(provider.payload, provider);
      else {
        if (typeof provider.path !== 'string') throw new Error('订阅 provider 缺少本地缓存路径');
        const providerPath = path.resolve(this.directory!, provider.path);
        append(readYaml(providerPath).proxies, provider);
      }
    }
  }

  private applyExtension(document: Document, item: Document, name: string): Document {
    const file = this.profileFile(item);
    if (item.type !== 'script') return mergeDocument(document, readYaml(file, true));
    const context = createContext(Object.assign(Object.create(null), { inputJson: JSON.stringify(document), profileName: name }),
      { codeGeneration: { strings: false, wasm: false }, microtaskMode: 'afterEvaluate' });
    const script = new Script(`${fs.readFileSync(file, 'utf8')}\nJSON.stringify(main(JSON.parse(inputJson), profileName));`, { filename: path.basename(file) });
    const result = JSON.parse(script.runInContext(context, { timeout: 500 }));
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('订阅扩展脚本必须返回配置对象');
    return result;
  }

  public refresh(): void {
    this.errors = [];
    this.profiles.clear();
    this.groups = [];
    if (!this.directory || !fs.existsSync(path.join(this.directory, 'profiles.yaml'))) return;
    const index = readYaml(path.join(this.directory, 'profiles.yaml'));
    if (!Array.isArray(index.items)) throw new Error('Clash Verge 订阅索引缺少 items');
    const items = index.items.map(object);
    const current = new Set(Array.isArray(index.current) ? index.current.map(String) : [String(index.current)]);
    const byId = new Map(items.map((item) => [String(item.uid), item]));
    const chain = Array.isArray(index.chain) ? index.chain.map(String) : ['Merge', 'Script'];
    let dnsOverride: Document = {};
    const dnsSettings = path.join(this.directory, 'dns_config.yaml');
    const vergeSettings = path.join(this.directory, 'verge.yaml');
    if (fs.existsSync(dnsSettings) && fs.existsSync(vergeSettings) && readYaml(vergeSettings).enable_dns_settings === true) {
      const document = readYaml(dnsSettings);
      dnsOverride = { hosts: object(document.hosts), dns: object(document.dns) };
    }
    for (const item of items) {
      if (item.type !== 'remote' && item.type !== 'local') continue;
      try {
        const file = this.profileFile(item);
        let document = readYaml(file);
        const name = String(item.name || item.uid);
        for (const key of ['proxies', 'groups', 'rules']) {
          const companion = byId.get(String(object(item.option)[key]));
          if (!companion) continue;
          const extra = readYaml(this.profileFile(companion), true);
          const field = key === 'groups' ? 'proxy-groups' : key;
          document = mergeDocument(document, { [`prepend-${field}`]: extra.prepend || [], [`append-${field}`]: extra.append || [] });
          if (Array.isArray(extra.delete)) {
            const removed = new Set(extra.delete);
            document[field] = (document[field] as unknown[] || []).filter((entry) => !removed.has(typeof entry === 'string' ? entry : object(entry).name));
          }
        }
        document = mergeDocument(document, dnsOverride);
        for (const uid of chain) {
          const extension = byId.get(uid);
          if (extension) document = this.applyExtension(document, extension, name);
        }
        for (const key of ['merge', 'script']) {
          const extension = byId.get(String(object(item.option)[key]));
          if (extension) document = this.applyExtension(document, extension, name);
        }
        const nodes = new Map<string, Document>();
        this.readNodes(document, nodes);
        const hosts = object(document.hosts);
        const dns = object(document.dns);
        const uid = String(item.uid);
        const group: ClashProfileGroupOption = {
          uid, name, type: String(item.type), isActive: current.has(uid), nodeCount: nodes.size,
          nodes: [...nodes].map(([nodeName, proxy]) => ({ name: nodeName, type: String(proxy.type), isGroup: false,
            server: typeof proxy.server === 'string' ? proxy.server : undefined,
            port: typeof proxy.port === 'number' ? proxy.port : undefined, profileUid: uid, profileName: name })),
        };
        this.profiles.set(uid, { group, nodes, hosts, dns, directory: path.dirname(file) });
        this.groups.push(group);
      } catch (error) {
        this.errors.push(`${String(item.name || item.uid)}：${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  public capture(profileUid: string, nodeName: string): NodeSnapshot {
    const profile = this.profiles.get(profileUid);
    if (!profile) throw new Error('指定订阅不存在或读取失败，请检查订阅状态');
    const proxies: Document[] = [];
    const visited = new Set<string>();
    const files: Record<string, string> = {};
    const copyResources = (value: Document, protocol: string): void => {
      for (const [key, entry] of Object.entries(value)) {
        if (entry && typeof entry === 'object' && !Array.isArray(entry)) copyResources(entry as Document, protocol);
        if (protocol === 'wireguard' && key === 'private-key') continue;
        if (!['certificate', 'private-key', 'ca', 'ca-cert', 'client-cert', 'client-key'].includes(key) || typeof entry !== 'string' || entry.includes('-----BEGIN')) continue;
        const resource = [path.resolve(this.directory!, entry), path.resolve(profile.directory, entry)].find((file) => fs.existsSync(file));
        if (!resource) throw new Error(`节点依赖文件不存在：${key}`);
        const bytes = fs.readFileSync(resource);
        const resourceName = `${createHash('sha256').update(bytes).digest('hex')}${path.extname(resource)}`;
        files[resourceName] = bytes.toString('base64');
        value[key] = `assets/${resourceName}`;
      }
    };
    const runtimeFile = path.join(this.directory!, 'clash-verge.yaml');
    const runtimeDns = fs.existsSync(runtimeFile) ? object(readYaml(runtimeFile).dns) : {};
    const dns = independentNodeDns(profile.dns, runtimeDns);
    const visiting = new Set<string>();
    const captureProxy = (name: string): void => {
      if (visiting.has(name)) throw new Error(`链式代理存在循环：${name}`);
      if (visited.has(name)) return;
      visiting.add(name);
      visited.add(name);
      const source = profile.nodes.get(name);
      if (!source) throw new Error(`节点或链式代理依赖不存在：${name}`);
      const proxy = structuredClone(source);
      copyResources(proxy, String(proxy.type));
      proxies.push(proxy);
      const dialer = typeof proxy['dialer-proxy'] === 'string' ? proxy['dialer-proxy'] : null;
      if (dialer && dialer !== 'DIRECT') captureProxy(dialer);
      visiting.delete(name);
    };
    captureProxy(nodeName);
    for (const name of dnsProxyReferences(dns, new Set(profile.nodes.keys()))) captureProxy(name);
    const value: Omit<NodeSnapshot, 'fingerprint'> = { schema: 1, profileUid, profileName: profile.group.name,
      nodeName, proxies, hosts: structuredClone(profile.hosts), dns, files };
    return { ...value, fingerprint: snapshotFingerprint(value) };
  }
}

export function doesHostShareDomain(rawHost: string, registrableDomain: string): boolean {
  const host = rawHost.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const domain = registrableDomain.trim().toLowerCase().replace(/\.$/, '');
  if (!host || !domain || net.isIP(host) !== 0) return false;
  return host === domain || host.endsWith(`.${domain}`);
}

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
  snapshot: Pick<NodeSnapshot, 'proxies'> | null | undefined
): string[] {
  return extractProxyTransportHosts(snapshot?.proxies);
}
