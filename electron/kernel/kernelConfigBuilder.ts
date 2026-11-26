import { execFile } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { promisify } from 'node:util';
import * as yaml from 'js-yaml';
import { PrivateChannelId } from '../../src/shared/types';
import { MihomoEndpoint, mihomoRequest, snapshotFingerprint } from '../clash';
import { isKernelPidAlive, KernelLease, SavedChannel } from './kernelTypes';

const execute = promisify(execFile);

interface MihomoDnsQueryAnswer {
  type?: number;
  TTL?: number;
  data?: string;
}

interface MihomoDnsQueryResponse {
  Status?: number;
  Answer?: MihomoDnsQueryAnswer[];
}

function matchesMihomoHostPattern(patternRaw: string, hostname: string): boolean {
  const pattern = patternRaw.trim().toLowerCase().replace(/\.$/, '');
  if (!pattern) return false;
  if (pattern === hostname) return true;
  if (pattern.startsWith('+.')) {
    const suffix = pattern.slice(2);
    return Boolean(suffix && (hostname === suffix || hostname.endsWith(`.${suffix}`)));
  }
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(2);
    if (!suffix || !hostname.endsWith(`.${suffix}`)) return false;
    const prefix = hostname.slice(0, -(suffix.length + 1));
    return Boolean(prefix && !prefix.includes('.'));
  }
  if (pattern.startsWith('.')) {
    const suffix = pattern.slice(1);
    return Boolean(suffix && hostname.endsWith(`.${suffix}`));
  }
  return false;
}

export function lookupSnapshotHostsIpv4(
  hosts: Record<string, unknown> | undefined,
  hostname: string
): { matchedIpEntry: boolean; ips: string[] } {
  if (!hosts || typeof hosts !== 'object' || Array.isArray(hosts)) {
    return { matchedIpEntry: false, ips: [] };
  }
  const entries = Object.entries(hosts);
  const exact = entries.find(([key]) => key.trim().toLowerCase().replace(/\.$/, '') === hostname);
  const chosen = exact ?? entries.find(([key]) => matchesMihomoHostPattern(key, hostname));
  if (!chosen) return { matchedIpEntry: false, ips: [] };
  const rawValues = Array.isArray(chosen[1]) ? chosen[1] : [chosen[1]];
  const stringValues = rawValues
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim().replace(/^\[|\]$/g, ''))
    .filter(Boolean);
  if (stringValues.length === 0 || !stringValues.every((item) => net.isIP(item) !== 0)) {
    return { matchedIpEntry: false, ips: [] };
  }
  const ipv4s = [...new Set(stringValues.filter((item) => net.isIPv4(item)))];
  return { matchedIpEntry: true, ips: ipv4s };
}

export async function resolveKernelIpv4ViaDoh(
  saved: SavedChannel | null,
  lease: KernelLease | null,
  hostname: string,
  signal?: AbortSignal,
  timeoutMs = 6000
): Promise<{ ips: string[]; ttlSec: number }> {
  signal?.throwIfAborted();
  const clean = hostname.trim().replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (!clean) {
    throw new Error('目标主机名为空');
  }
  if (net.isIPv6(clean)) {
    throw new Error(`已开启强制 IPv4 出站，禁止直连 IPv6 地址 (${clean})`);
  }
  if (net.isIPv4(clean)) {
    return { ips: [clean], ttlSec: 300 };
  }
  if (clean === 'localhost') {
    return { ips: ['127.0.0.1'], ttlSec: 300 };
  }
  const hostMatch = lookupSnapshotHostsIpv4(saved?.snapshot.hosts, clean);
  if (hostMatch.matchedIpEntry) {
    if (hostMatch.ips.length > 0) {
      return { ips: hostMatch.ips, ttlSec: 300 };
    }
    throw new Error(`域名 ${clean} 在节点 hosts 中仅配置了 IPv6 地址（已开启强制 IPv4 出站）`);
  }
  if (!lease || !isKernelPidAlive(lease.pid)) {
    throw new Error('私有内核尚未就绪');
  }
  const resp = await mihomoRequest<MihomoDnsQueryResponse>(
    lease.endpoint,
    `/dns/query?name=${encodeURIComponent(clean)}&type=A`,
    'GET',
    undefined,
    signal,
    timeoutMs
  );
  const ips: string[] = [];
  const seen = new Set<string>();
  let minTtl = Number.POSITIVE_INFINITY;
  for (const answer of Array.isArray(resp?.Answer) ? resp.Answer : []) {
    if (answer?.type !== 1 || typeof answer.data !== 'string') continue;
    const ip = answer.data.trim();
    if (!net.isIPv4(ip) || seen.has(ip)) continue;
    seen.add(ip);
    ips.push(ip);
    if (typeof answer.TTL === 'number' && Number.isFinite(answer.TTL) && answer.TTL > 0) {
      minTtl = Math.min(minTtl, answer.TTL);
    }
  }
  if (ips.length === 0) {
    throw new Error(`域名 ${clean} 未解析到可用 IPv4 地址（已开启强制 IPv4 出站）`);
  }
  const ttlSec = Number.isFinite(minTtl) ? Math.max(15, Math.min(300, Math.round(minTtl))) : 60;
  return { ips, ttlSec };
}

export function getEffectiveMihomoPort(saved: SavedChannel | null): number | null {
  if (!saved) return null;
  return saved.ipv4Only ? (saved.internalPort ?? null) : saved.port;
}

export function validateSavedChannel(saved: SavedChannel): void {
  if (
    saved.schema !== 1 ||
    !saved.snapshot ||
    !Number.isInteger(saved.port) ||
    saved.port < 1 ||
    saved.port > 65535
  ) {
    throw new Error('私有节点副本格式无效');
  }
  if (
    saved.ipv4Only &&
    (!Number.isInteger(saved.internalPort) ||
      saved.internalPort! < 1 ||
      saved.internalPort! > 65535 ||
      saved.internalPort === saved.port)
  ) {
    throw new Error('私有节点副本内部端口无效');
  }
  if (!/^[0-9a-f-]{36}$/.test(saved.revision)) {
    throw new Error('私有节点副本目录标识无效');
  }
  const { fingerprint, ...definition } = saved.snapshot;
  if (snapshotFingerprint(definition) !== fingerprint) {
    throw new Error('私有节点副本校验失败');
  }
}

export function buildMihomoKernelConfig(
  saved: SavedChannel,
  endpoint: MihomoEndpoint
): Record<string, unknown> {
  const snapshot = saved.snapshot;
  const policy =
    snapshot.dns['proxy-server-nameserver-policy'] ||
    (snapshot.dns['proxy-server-nameserver'] ? {} : snapshot.dns['nameserver-policy']) ||
    {};
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new Error('节点 DNS 策略格式无效');
  }
  if (Object.keys(policy).some((key) => key.includes('rule-set:') || key.includes('geosite:'))) {
    throw new Error('节点 DNS 策略包含外部规则集，请将节点域名解析配置为明确域名');
  }
  const resolvers = snapshot.dns['proxy-server-nameserver'] ||
    snapshot.dns.nameserver || ['https://223.5.5.5/dns-query'];
  const names = new Set(snapshot.proxies.map((proxy) => String(proxy.name)));
  if (!names.has(snapshot.nodeName)) throw new Error('节点副本缺少选中的代理定义');
  let outbound = 'guard-selected-outbound';
  while (names.has(outbound)) outbound += '-private';
  const ipv4Only = Boolean(saved.ipv4Only);
  const mihomoPort = getEffectiveMihomoPort(saved);
  if (!mihomoPort || !Number.isInteger(mihomoPort) || mihomoPort < 1 || mihomoPort > 65535) {
    throw new Error('私有内核监听端口无效');
  }
  const proxies = snapshot.proxies.map((proxy) =>
    proxy['ip-version'] ? { ...proxy } : { ...proxy, 'ip-version': 'ipv4-prefer' }
  );
  const rules = ipv4Only
    ? [
        `IP-CIDR6,::1/128,${outbound},no-resolve`,
        'IP-CIDR6,::/0,REJECT,no-resolve',
        `MATCH,${outbound}`,
      ]
    : [`MATCH,${outbound}`];
  return {
    'mixed-port': mihomoPort,
    'bind-address': '127.0.0.1',
    'allow-lan': false,
    mode: 'rule',
    ipv6: true,
    'tcp-concurrent': true,
    'log-level': 'warning',
    'find-process-mode': 'off',
    'external-controller-pipe': endpoint.pipePath,
    secret: endpoint.secret,
    tun: { enable: false },
    profile: { 'store-selected': false, 'store-fake-ip': false },
    dns: {
      enable: true,
      ipv6: !ipv4Only,
      'enhanced-mode': 'redir-host',
      'use-system-hosts': false,
      'default-nameserver': ['223.5.5.5'],
      'proxy-server-nameserver': resolvers,
      'proxy-server-nameserver-policy': policy,
      nameserver: [
        `https://1.1.1.1/dns-query#${outbound}`,
        `https://8.8.8.8/dns-query#${outbound}`,
      ],
    },
    hosts: snapshot.hosts,
    proxies,
    'proxy-groups': [{ name: outbound, type: 'select', proxies: [snapshot.nodeName] }],
    rules,
  };
}

export async function prepareKernelRevision(
  channel: PrivateChannelId,
  directory: string,
  executable: string,
  saved: SavedChannel
): Promise<MihomoEndpoint> {
  const revisionDirectory = path.join(directory, saved.revision);
  fs.mkdirSync(path.join(revisionDirectory, 'assets'), { recursive: true });
  for (const [name, contents] of Object.entries(saved.snapshot.files)) {
    if (path.basename(name) !== name) throw new Error('节点资源文件名无效');
    fs.writeFileSync(
      path.join(revisionDirectory, 'assets', name),
      Buffer.from(contents, 'base64'),
      { mode: 0o600 }
    );
  }
  const endpoint: MihomoEndpoint = {
    pipePath: `\\\\.\\pipe\\proxy-region-guard-${channel}-${randomUUID()}`,
    secret: randomBytes(32).toString('hex'),
  };
  const configuration = buildMihomoKernelConfig(saved, endpoint);
  fs.writeFileSync(
    path.join(revisionDirectory, 'config.yaml'),
    yaml.dump(configuration, { noRefs: true, lineWidth: -1 }),
    { mode: 0o600 }
  );
  await execute(
    executable,
    ['-t', '-d', revisionDirectory, '-f', path.join(revisionDirectory, 'config.yaml')],
    { windowsHide: true, timeout: 15000 }
  );
  return endpoint;
}
