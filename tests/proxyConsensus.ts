import { app } from 'electron';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as path from 'node:path';
import type { Duplex } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import * as yaml from 'js-yaml';
import { ConfigStore } from '../electron/configStore';
import { ClashMonitor } from '../electron/clashMonitor';
import { GeoIpService } from '../electron/geoipService';
import { isLocalPortListening, mihomoRequest, MihomoEndpoint } from '../electron/mihomoClient';
import { isLocalProxyRefusedCause, requestTextViaProxy } from '../electron/netClient';
import { PrivateProxyService, verifyCore } from '../electron/privateKernel';
import {
  BUILTIN_TRACE_ENDPOINTS,
  doesHostShareDomain,
  evaluateClaudeNodeProbeSafety,
  interpretClaudeTracePayload,
  isProbeRegionMismatched,
  MIN_CONSENSUS_MATCHES,
  ProbeEngine,
  resolveAlertActualMismatchFields,
  selectProbeEndpointsForTransportHosts,
  TraceEndpoint,
} from '../electron/probeEngine';
import {
  extractProxyTransportHosts,
  extractSnapshotTransportHosts,
  readYaml,
  SubscriptionCatalog,
} from '../electron/subscriptionCatalog';
import { ClaudeVerificationRecovery } from '../electron/claudeVerificationRecovery';
import { getTargetServiceVerificationError } from '../src/shared/probeValidation';
import { resolveWindowsTimeZoneForCountry } from '../src/shared/timezones';
import type { ProbeResult, WindowsLocaleState } from '../src/shared/types';

assert.ok(process.env.GUARD_TEST_DATA);
const root = process.env.GUARD_TEST_DATA;
fs.mkdirSync(root, { recursive: true });
app.setPath('userData', root);

const activeServices = new Set<PrivateProxyService>();
function trackService(svc: PrivateProxyService): PrivateProxyService {
  activeServices.add(svc);
  return svc;
}
async function shutdownAllServices(): Promise<void> {
  const pending = [...activeServices];
  activeServices.clear();
  await Promise.allSettled(pending.map((svc) => svc.shutdown()));
}

async function listen(server: net.Server, host = '127.0.0.1'): Promise<number> {
  server.listen(0, host);
  await once(server, 'listening');
  return (server.address() as net.AddressInfo).port;
}

async function freePort(): Promise<number> {
  const srv = net.createServer();
  const port = await listen(srv, '127.0.0.1');
  await new Promise<void>((resolve) => srv.close(() => resolve()));
  return port;
}

function readLeaseEndpoint(kernelChannelDir: string): {
  endpoint: MihomoEndpoint;
  configPath: string;
  configText: string;
} {
  const lease = JSON.parse(fs.readFileSync(path.join(kernelChannelDir, 'runtime.json'), 'utf8')) as {
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

async function reloadKernelConfig(endpoint: MihomoEndpoint, payload: string): Promise<void> {
  await mihomoRequest(endpoint, '/configs?force=true', 'PUT', { payload });
}

function extractEchoIpFromBody(raw: string, format: TraceEndpoint['format']): string {
  const text = raw.trim();
  if (format === 'cf-trace' || /^ip=/m.test(text)) {
    return /^ip=(.+)$/m.exec(text)?.[1].trim() ?? '';
  }
  return text.split(/\r?\n/)[0]?.trim() ?? '';
}

function parseHttpConnectAuthority(authority: string | undefined): { host: string; port: number } | null {
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

function parseHttpHostHeader(rawHost: string | undefined): string | null {
  if (!rawHost) return null;
  try {
    const parsed = new URL(`http://${rawHost.trim()}`);
    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    return host || null;
  } catch {
    return null;
  }
}

function verifyTransportHostsAndPureSafety(): void {
  assert.equal(MIN_CONSENSUS_MATCHES, 2);
  const uniqueDomains = new Set(BUILTIN_TRACE_ENDPOINTS.map((item) => item.registrableDomain));
  assert.equal(uniqueDomains.size, BUILTIN_TRACE_ENDPOINTS.length, '常规探测池各源必须具备互不相同的独立注册主域');
  assert.equal(doesHostShareDomain('www.cloudflare.com', 'cloudflare.com'), true);
  assert.equal(doesHostShareDomain('ipv4.icanhazip.com', 'cloudflare.com'), false);

  const sampleTransportHosts = extractProxyTransportHosts([
    {
      type: 'vless',
      tls: true,
      network: 'ws',
      server: '121.54.188.12',
      servername: 'www.cloudflare.com',
      'ws-opts': { headers: { Host: 'edge.amazonaws.com:443' } },
    },
    { type: 'trojan', server: 'relay.example.net', sni: 'node.ipify.org.' },
  ]);
  assert.deepEqual(sampleTransportHosts, [
    'edge.amazonaws.com',
    'node.ipify.org',
    'relay.example.net',
    'www.cloudflare.com',
  ]);

  assert.deepEqual(
    extractProxyTransportHosts([
      {
        type: 'http',
        server: '127.0.0.1',
        sni: 'unused.ident.me',
        servername: 'unused.cloudflare.com',
        'h2-opts': { host: ['unused.icanhazip.com'] },
        'ws-opts': { headers: { Host: 'unused.ipify.org' } },
      },
    ]),
    [],
    '明文 HTTP 节点不得采集不会读取的 h2-opts / ws-opts / 非 TLS sni 字段'
  );

  assert.deepEqual(
    extractProxyTransportHosts([
      {
        type: 'http',
        tls: true,
        server: 'hop.icanhazip.com',
        sni: 'tls.ident.me',
        headers: { host: 'edge.amazonaws.com:8080' },
      },
    ]),
    ['edge.amazonaws.com', 'hop.icanhazip.com', 'tls.ident.me'],
    'HTTP 节点应准确提取 server、顶层 headers.Host 及开启 TLS 时的 sni'
  );

  const vlessXhttpHosts = extractProxyTransportHosts([
    {
      type: 'vless',
      tls: true,
      network: 'xhttp',
      server: '198.51.100.20',
      servername: 'up.icanhazip.com',
      'xhttp-opts': {
        host: 'cp.cloudflare.com',
        headers: { Host: 'hdr.amazonaws.com:443' },
        'download-settings': {
          server: 'dl.ident.me',
          host: 'api.ipify.org',
          headers: { Host: 'dl-hdr.amazonaws.com:443' },
          servername: 'sni.example.org',
        },
      },
    },
  ]);
  assert.deepEqual(
    vlessXhttpHosts,
    ['api.ipify.org', 'cp.cloudflare.com', 'dl.ident.me', 'sni.example.org', 'up.icanhazip.com'],
    'VLESS XHTTP 应提取 xhttp-opts.host 与 download-settings 的请求/下载主机及 SNI，不得误采不会被发送的 headers.Host'
  );
  assert.equal(
    selectProbeEndpointsForTransportHosts(BUILTIN_TRACE_ENDPOINTS, vlessXhttpHosts).some(
      (ep) => ep.registrableDomain === 'amazonaws.com'
    ),
    true
  );
  assert.deepEqual(
    extractProxyTransportHosts([
      {
        type: 'vless',
        tls: false,
        network: 'xhttp',
        server: '198.51.100.22',
        servername: 'fallback.amazonaws.com',
        'xhttp-opts': {
          'download-settings': {
            server: '198.51.100.23',
            tls: false,
            host: 'dl-only.ident.me',
            servername: 'unused-dl-sni.ipify.org',
          },
        },
      },
    ]),
    ['dl-only.ident.me', 'fallback.amazonaws.com']
  );
  assert.deepEqual(
    extractProxyTransportHosts([
      {
        type: 'vmess',
        network: 'xhttp',
        server: '198.51.100.24',
        'xhttp-opts': { host: 'unused-vmess.cloudflare.com' },
      },
    ]),
    [],
    '非 VLESS 协议不得误采 xhttp-opts'
  );

  const decoupled = selectProbeEndpointsForTransportHosts(BUILTIN_TRACE_ENDPOINTS, sampleTransportHosts);
  assert.equal(decoupled.length, 2);
  const oneLeftHosts = BUILTIN_TRACE_ENDPOINTS.slice(0, -1).map((ep) => `hop.${ep.registrableDomain}`);
  assert.deepEqual(selectProbeEndpointsForTransportHosts(BUILTIN_TRACE_ENDPOINTS, oneLeftHosts), [
    BUILTIN_TRACE_ENDPOINTS.at(-1)!,
  ]);
  const zeroLeftHosts = BUILTIN_TRACE_ENDPOINTS.map((ep) => `hop.${ep.registrableDomain}`);
  assert.deepEqual(selectProbeEndpointsForTransportHosts(BUILTIN_TRACE_ENDPOINTS, zeroLeftHosts), []);

  const makeOfflineGeoMissingProbe = (countryCode: string): ProbeResult => ({
    ip: countryCode === 'US' ? '198.51.100.1' : '198.51.100.2',
    countryCode,
    countryName: countryCode === 'US' ? '美国' : '日本',
    viaChannel: '测试通道',
    latencyMs: 50,
    checkedAt: Date.now(),
    claudeTraceLoc: 'JP',
    claudeTraceIp: '203.0.113.10',
    claudeTraceCountryCode: undefined,
    claudeTraceError: '离线 GeoIP 数据库无法确定出口 203.0.113.10 的国家',
    claudeTraceCheckedAt: Date.now(),
    regionMismatchDetail: null,
  });

  assert.equal(isProbeRegionMismatched(makeOfflineGeoMissingProbe('US')), false);
  assert.equal(isProbeRegionMismatched(makeOfflineGeoMissingProbe('JP')), false);
  assert.ok(getTargetServiceVerificationError(makeOfflineGeoMissingProbe('US'), 'claude')?.includes('离线 GeoIP'));
  assert.equal(
    isProbeRegionMismatched({
      ...makeOfflineGeoMissingProbe('US'),
      claudeTraceError: undefined,
      claudeTraceCountryCode: 'JP',
    }),
    true
  );

  for (const sampleCountry of ['US', 'JP']) {
    const unknownGeoSameIp = evaluateClaudeNodeProbeSafety(makeOfflineGeoMissingProbe(sampleCountry), {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: '203.0.113.10',
    });
    assert.equal(unknownGeoSameIp?.alertType, 'verification-unavailable');

    const unknownGeoDriftedIp = evaluateClaudeNodeProbeSafety(makeOfflineGeoMissingProbe(sampleCountry), {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: '198.51.100.9',
    });
    assert.equal(unknownGeoDriftedIp?.alertType, 'ip-change');
    assert.equal(unknownGeoDriftedIp?.expectedIp, '198.51.100.9');
    assert.equal(unknownGeoDriftedIp?.actualIp, '203.0.113.10');

    const unknownGeoAlert = resolveAlertActualMismatchFields({
      isClaudeSource: true,
      alertType: 'ip-change',
      expectedCode: 'JP',
      explicitActualIp: '203.0.113.10',
      refProbe: makeOfflineGeoMissingProbe(sampleCountry),
    });
    assert.equal(unknownGeoAlert.actualCode, null);
    assert.equal(unknownGeoAlert.actualName, '归属地未知');
    assert.equal(unknownGeoAlert.actualIp, '203.0.113.10');

    const unknownGeoUnlockedIp = evaluateClaudeNodeProbeSafety(makeOfflineGeoMissingProbe(sampleCountry), {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: false,
      sessionInitialIp: '198.51.100.9',
    });
    assert.equal(unknownGeoUnlockedIp?.alertType, 'verification-unavailable');
  }

  // ClaudeVerificationRecovery 归一化去重（含通道前缀、乱序多源、URL 冒号变体、复核未完成）
  const dedup = new ClaudeVerificationRecovery(async () => undefined, 60_000);
  try {
    assert.deepEqual(
      dedup.recordFailure(
        'Claude 专属节点出口不可达 (Claude 专属节点 [A] (127.0.0.1:27897)：Cloudflare IPv4 Trace：连接超时；AWS CheckIP (IPv4)：Client network socket disconnected before secure TLS connection was established)'
      ),
      { shouldLog: true, stateChanged: true }
    );
    assert.deepEqual(
      dedup.recordFailure(
        'Claude 专属节点出口不可达 (Claude 专属节点 [A] (127.0.0.1:27897)：IdentMe Echo：Client network socket disconnected before secure TLS connection was established；IPify IPv4：连接超时)'
      ),
      { shouldLog: false, stateChanged: true }
    );
    assert.deepEqual(
      dedup.recordFailure(
        'Claude 专属节点出口不可达 (Claude 专属节点 [A] (127.0.0.1:27897)：常规出口复核未完成：单源 CN 与 Claude (JP) 待核实；AWS CheckIP (IPv4)：连接超时；IPify IPv4：连接超时)'
      ),
      { shouldLog: true, stateChanged: true }
    );
    assert.deepEqual(
      dedup.recordFailure(
        'Claude 专属节点出口不可达 (Claude 专属节点 [A] (127.0.0.1:27897)：常规出口复核未完成：单源 CN 与 Claude (JP) 待核实；IdentMe Echo：连接超时)'
      ),
      { shouldLog: false, stateChanged: true }
    );
    assert.deepEqual(
      dedup.recordFailure('目标服务地区校验未通过：https://claude.ai/cdn-cgi/trace：连接超时'),
      { shouldLog: true, stateChanged: true }
    );
    assert.deepEqual(
      dedup.recordFailure('目标服务地区校验未通过：https://claude.ai/cdn-cgi/trace:连接超时'),
      { shouldLog: false, stateChanged: true }
    );
  } finally {
    dedup.clear();
  }

  console.log('通过：独立探测池、传输层域名提取过滤、离线归属未知优先级与后台复核去重校验');
}

async function verifyLocalNetClientAndKernelRecovery(coreDir: string): Promise<void> {
  // 1. 本地代理端口 ECONNREFUSED 立即失败（不延迟重试）且精准区分本地代理拒绝与远端目标拒绝
  const closedPort = await freePort();
  const refusedStart = Date.now();
  await assert.rejects(
    requestTextViaProxy('https://example.com', `http://127.0.0.1:${closedPort}`, 5000),
    (err: unknown) => {
      assert.equal(isLocalProxyRefusedCause(err, `http://127.0.0.1:${closedPort}`), true);
      assert.equal(isLocalProxyRefusedCause(err, 'http://127.0.0.1:1'), false);
      return true;
    }
  );
  assert.ok(Date.now() - refusedStart < 1500, '本地代理端口拒绝连接应立即外抛而非等待重试退避');

  // 2. 前两次瞬断后第三次重试恢复 + AbortSignal 立即取消释放 socket
  const originServer = http.createServer((_req, res) => res.end('ok-body'));
  const originPort = await listen(originServer, '127.0.0.1');
  const relayClients = new Set<net.Socket>();
  let relayHits = 0;
  let relayBehavior: 'drop-first-two' | 'hang' = 'drop-first-two';
  const relayServer = http.createServer((_req, res) => {
    res.writeHead(502);
    res.end();
  });
  relayServer.on('connection', (sock) => {
    relayClients.add(sock);
    sock.once('close', () => relayClients.delete(sock));
  });
  relayServer.on('connect', (_req, client) => {
    const hit = ++relayHits;
    client.on('error', () => client.destroy());
    if (relayBehavior === 'drop-first-two' && hit <= 2) {
      client.write('HTTP/1.1 200 Connection established\r\n\r\n');
      client.destroy();
      return;
    }
    if (relayBehavior === 'hang') {
      client.once('end', () => client.end());
      client.resume();
      return;
    }
    client.write('HTTP/1.1 200 Connection established\r\n\r\n');
    const up = net.connect(originPort, '127.0.0.1', () => {
      client.pipe(up);
      up.pipe(client);
    });
    up.on('error', () => client.destroy());
    client.on('error', () => up.destroy());
  });
  // 对于明文 HTTP 请求，直接通过正向上游转发验证 drop-first-two：
  const forwardClients = new Set<net.Socket>();
  let forwardHits = 0;
  const forwardRelay = http.createServer((req, res) => {
    const hit = ++forwardHits;
    if (relayBehavior === 'drop-first-two' && hit <= 2) {
      req.socket.destroy();
      return;
    }
    if (relayBehavior === 'hang') {
      return;
    }
    const target = new URL(req.url!);
    const upReq = http.request(
      { host: target.hostname, port: target.port || 80, path: target.pathname },
      (upRes) => {
        res.writeHead(upRes.statusCode || 200, upRes.headers);
        upRes.pipe(res);
      }
    );
    upReq.on('error', () => res.destroy());
    upReq.end();
  });
  forwardRelay.on('connection', (sock) => {
    forwardClients.add(sock);
    sock.once('close', () => forwardClients.delete(sock));
  });
  const relayPort = await listen(relayServer, '127.0.0.1');
  const forwardPort = await listen(forwardRelay, '127.0.0.1');

  const localTlsCertPath = process.env.GUARD_TEST_TLS_CERT;
  const localTlsKeyPath = process.env.GUARD_TEST_TLS_KEY;
  assert.ok(
    localTlsCertPath && localTlsKeyPath && fs.existsSync(localTlsCertPath) && fs.existsSync(localTlsKeyPath),
    '缺少本地回归真实 TLS 转发服务证书环境变量（请通过 npm test 运行）'
  );
  const localTlsOrigin = https.createServer(
    { key: fs.readFileSync(localTlsKeyPath, 'utf8'), cert: fs.readFileSync(localTlsCertPath, 'utf8') },
    (req, res) => {
      if ((req.url || '/').startsWith('/cdn-cgi/trace')) {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(`fl=29f1\nip=1.0.16.1\nts=${Math.floor(Date.now() / 1000)}\nloc=JP\n`);
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('1.0.16.1\n');
    }
  );
  const localTlsOriginPort = await listen(localTlsOrigin, '127.0.0.1');
  const localExitClients = new Set<Duplex>();
  const localExitProxy = http.createServer((req, res) => {
    const target = new URL(req.url || `http://127.0.0.1:${originPort}/`);
    const upReq = http.request(
      { host: target.hostname, port: target.port || 80, path: target.pathname + target.search, method: req.method },
      (upRes) => {
        res.writeHead(upRes.statusCode || 200, upRes.headers);
        upRes.pipe(res);
      }
    );
    upReq.on('error', () => res.destroy());
    upReq.end();
  });
  localExitProxy.on('clientError', (_err, sock) => sock.destroy());
  localExitProxy.on('connect', (req, client, head) => {
    localExitClients.add(client);
    const parsed = parseHttpConnectAuthority(req.url);
    const targetPort = parsed && parsed.host === '127.0.0.1' && parsed.port === originPort ? originPort : localTlsOriginPort;
    const up = net.connect(targetPort, '127.0.0.1', () => {
      client.write('HTTP/1.1 200 Connection established\r\n\r\n');
      if (head.length > 0) up.write(head);
      client.pipe(up);
      up.pipe(client);
    });
    up.on('error', () => client.destroy());
    client.on('error', () => up.destroy());
    client.once('end', () => client.end());
    client.once('close', () => {
      up.destroy();
      localExitClients.delete(client);
    });
  });
  const localExitProxyPort = await listen(localExitProxy, '127.0.0.1');

  const localRoot = path.join(root, 'local-kernel-recovery');
  const localSubDir = path.join(localRoot, 'verge');
  fs.mkdirSync(path.join(localSubDir, 'profiles'), { recursive: true });
  const allFiveDomains = BUILTIN_TRACE_ENDPOINTS.map((ep) => ep.registrableDomain);
  const hopHosts = Object.fromEntries(allFiveDomains.map((d) => [`hop.${d}`, '127.0.0.1']));
  const dummyPort = await freePort();
  fs.writeFileSync(
    path.join(localSubDir, 'profiles.yaml'),
    yaml.dump({
      current: 'local-prof',
      items: [{ uid: 'local-prof', name: '本地测试订阅', type: 'local', file: 'local-prof.yaml' }],
    }),
    'utf8'
  );
  fs.writeFileSync(
    path.join(localSubDir, 'profiles', 'local-prof.yaml'),
    yaml.dump({
      hosts: hopHosts,
      proxies: [
        { name: '直连测试节点', type: 'http', server: '127.0.0.1', port: localExitProxyPort },
        {
          name: '零源跳板-2',
          type: 'http',
          server: `hop.${allFiveDomains[4]}`,
          port: dummyPort,
          headers: { Host: `edge.${allFiveDomains[3]}` },
        },
        {
          name: '零源跳板-1',
          type: 'http',
          server: `hop.${allFiveDomains[2]}`,
          port: dummyPort,
          headers: { Host: `edge.${allFiveDomains[1]}` },
          'dialer-proxy': '零源跳板-2',
        },
        {
          name: '全重合零源节点',
          type: 'http',
          server: `hop.${allFiveDomains[0]}`,
          port: dummyPort,
          'dialer-proxy': '零源跳板-1',
        },
      ],
    }),
    'utf8'
  );

  const localService = trackService(new PrivateProxyService(path.join(localRoot, 'kernels'), coreDir));
  const localCatalog = new SubscriptionCatalog(localSubDir);
  localCatalog.refresh();
  const localGeo = new GeoIpService();
  await localGeo.init(process.cwd());

  // 验证离线 GeoIP 严格查询命中缓存时不重读磁盘 mmdb
  const cachedFirst = localGeo.lookupOfflineStrict('8.8.8.8');
  assert.equal(cachedFirst.countryCode, 'US');
  const savedReader = (localGeo as unknown as { reader: unknown }).reader;
  (localGeo as unknown as { reader: unknown }).reader = null;
  const cachedSecond = localGeo.lookupOfflineStrict('8.8.8.8');
  assert.equal(cachedSecond.countryCode, 'US');
  assert.equal((localGeo as unknown as { reader: unknown }).reader, null, '命中缓存时不得重新加载 mmdb 读取器');
  (localGeo as unknown as { reader: unknown }).reader = savedReader;

  // 验证 Claude trace 返回有效出口 IP 但 loc=XX 时（含离线 mmdb 命中与未命中两种情况），均保留 claudeTraceIp 以检测运行中 IP 漂移
  const locXxKnownGeo = interpretClaudeTracePayload(
    'fl=29f1\nip=8.8.4.4\nloc=XX\nts=1700000000\n',
    (ip) => localGeo.lookupOfflineStrict(ip),
    Date.now(),
    35
  );
  assert.equal(locXxKnownGeo.kind, 'trace-error');
  assert.equal(locXxKnownGeo.claudeTraceIp, '8.8.4.4');
  assert.equal(locXxKnownGeo.claudeTraceCountryCode, 'US', 'loc=XX 且 mmdb 命中时应保留离线归属国家');
  assert.match(locXxKnownGeo.claudeTraceError, /未解析到有效国家\/地区代码/);

  const locXxUnknownGeo = interpretClaudeTracePayload(
    'fl=29f1\nip=203.0.113.10\nloc=XX\nts=1700000000\n',
    (ip) => localGeo.lookupOfflineStrict(ip),
    Date.now(),
    35
  );
  assert.equal(locXxUnknownGeo.kind, 'trace-error');
  assert.equal(locXxUnknownGeo.claudeTraceIp, '203.0.113.10');
  assert.equal(locXxUnknownGeo.claudeTraceCountryCode, undefined);
  assert.match(locXxUnknownGeo.claudeTraceError, /未解析到有效国家\/地区代码/);

  for (const outcome of [locXxKnownGeo, locXxUnknownGeo]) {
    const locXxProbe: ProbeResult = {
      ip: outcome.claudeTraceIp!,
      countryCode: 'UNKNOWN',
      countryName: '未知',
      viaChannel: '测试通道',
      latencyMs: outcome.latencyMs ?? 35,
      checkedAt: outcome.claudeTraceCheckedAt ?? Date.now(),
      claudeTraceIp: outcome.claudeTraceIp,
      claudeTraceCountryCode: outcome.claudeTraceCountryCode,
      claudeTraceError: outcome.claudeTraceError,
      claudeTraceCheckedAt: outcome.claudeTraceCheckedAt,
      regionMismatchDetail: null,
    };
    const locXxDriftCheck = evaluateClaudeNodeProbeSafety(locXxProbe, {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: '8.8.8.8',
    });
    assert.equal(locXxDriftCheck?.alertType, 'ip-change', 'loc=XX 返回有效漂移 IP 时必须触发 ip-change');
    assert.equal(locXxDriftCheck?.expectedIp, '8.8.8.8');
    assert.equal(locXxDriftCheck?.actualIp, outcome.claudeTraceIp);
    const locXxSameIpCheck = evaluateClaudeNodeProbeSafety(locXxProbe, {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: outcome.claudeTraceIp,
    });
    assert.equal(locXxSameIpCheck?.alertType, 'verification-unavailable');
  }

  // 验证 loc=XX 但已知 claudeTraceCountryCode 时，告警字段与 claudeTraceIp 同源配对而非误取常规源国家代码
  const locXxCrossGeneralProbe: ProbeResult = {
    ip: '198.51.100.2',
    countryCode: 'JP',
    countryName: '日本',
    viaChannel: '测试通道',
    latencyMs: 35,
    checkedAt: Date.now(),
    claudeTraceIp: '8.8.4.4',
    claudeTraceCountryCode: 'US',
    claudeTraceError: locXxKnownGeo.claudeTraceError,
    claudeTraceCheckedAt: Date.now(),
    regionMismatchDetail: null,
  };
  const locXxAlertPaired = resolveAlertActualMismatchFields({
    isClaudeSource: true,
    alertType: 'ip-change',
    expectedCode: 'JP',
    refProbe: locXxCrossGeneralProbe,
  });
  assert.equal(locXxAlertPaired.actualIp, '8.8.4.4');
  assert.equal(locXxAlertPaired.actualCode, 'US', 'claudeTraceIp 已知离线国家时不得误取常规源国家代码');
  assert.equal(locXxAlertPaired.actualName, '美国');

  const localStore = new ConfigStore();
  // 在构造 ProbeEngine 之前先关闭进程守护，避免前置断言失败进入 finally 调用 stop() 时误杀宿主机 Claude
  localStore.update({
    selectedClashNode: null,
    selectedClashProfileUid: null,
    selectedClashProfileName: null,
    claudeExclusiveGuard: false,
    killProcessesEnabled: false,
  });
  const localEngine = new ProbeEngine(localStore, localGeo, new ClashMonitor(localSubDir), localService);
  try {
    const recovered = await requestTextViaProxy(
      `http://127.0.0.1:${originPort}/`,
      `http://127.0.0.1:${forwardPort}`,
      5000,
      undefined,
      0,
      true
    );
    assert.equal(recovered, 'ok-body');
    assert.equal(forwardHits, 3, '前两次瞬断后第三次重试应成功取得响应');

    relayBehavior = 'hang';
    const cancelCtrl = new AbortController();
    const cancelTimer = setTimeout(() => cancelCtrl.abort(new Error('主动取消握手')), 250);
    const startCancel = Date.now();
    await assert.rejects(
      requestTextViaProxy('https://example.com', `http://127.0.0.1:${relayPort}`, 8000, undefined, 0, false, cancelCtrl.signal),
      (err) => err === cancelCtrl.signal.reason
    );
    clearTimeout(cancelTimer);
    assert.ok(Date.now() - startCancel < 1500, 'AbortSignal 必须立即终止代理握手');
    const closeDeadline = Date.now() + 1000;
    while (relayClients.size > 0 && Date.now() < closeDeadline) await delay(20);
    assert.equal(relayClients.size, 0, '取消后必须关闭全部代理连接 socket');

    // 3. 验证全重合零源节点在真实 guard-mihomo.exe + ProbeEngine 中 Fail-Closed 阻断
    const zeroPort = await freePort();
    const zeroSnap = localCatalog.capture('local-prof', '全重合零源节点');
    assert.equal(
      selectProbeEndpointsForTransportHosts(BUILTIN_TRACE_ENDPOINTS, extractSnapshotTransportHosts(zeroSnap)).length,
      0,
      '全重合节点不得恢复已排除传输层域名'
    );
    await localService.channels.claude.select(zeroSnap, zeroPort);
    assert.equal(localService.channels.claude.getState().phase, 'ready');
    assert.match(localService.channels.claude.getState().verificationError || '', /传输层域名重合/);
    localStore.update({
      selectedClashNode: '全重合零源节点',
      selectedClashProfileUid: 'local-prof',
      selectedClashProfileName: '本地测试订阅',
      dedicatedProxyPort: zeroPort,
      claudeExclusiveGuard: false,
      killProcessesEnabled: false,
    });
    const zeroResult = await localEngine.probeClaudeNodeNow('全重合零源节点 Fail-Closed 校验', true);
    assert.equal(zeroResult.claudeState.nodeProbe, null);
    assert.equal(zeroResult.claudeState.canLaunch, false);
    assert.match(zeroResult.claudeState.nodeProbeError || '', /传输层域名重合/);
    localStore.update({
      selectedClashNode: null,
      selectedClashProfileUid: null,
      selectedClashProfileName: null,
    });

    // 4. 验证真实 guard-mihomo.exe 端口关闭（mixed-port: 0）后：
    //    (a) 若端口被其他进程抢占，recoverListenerIfNeeded 必须核验 OwningProcess 并 Fail-Closed 返回 failed；
    //    (b) 抢占进程释放后，recoverListenerIfNeeded 精准重绑并恢复转发。
    const directPort = await freePort();
    const directSnap = localCatalog.capture('local-prof', '直连测试节点');
    await localService.channels.claude.select(directSnap, directPort);
    assert.equal(await isLocalPortListening(directPort), true);
    const leaseInfo = readLeaseEndpoint(path.join(localRoot, 'kernels', 'claude'));
    let readyEvents = 0;
    localService.channels.claude.on('ready', () => readyEvents++);
    await mihomoRequest(leaseInfo.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
    const dropDeadline = Date.now() + 3000;
    while ((await isLocalPortListening(directPort)) && Date.now() < dropDeadline) await delay(50);
    assert.equal(await isLocalPortListening(directPort), false, '测试已关闭本地专属监听端口');

    const hijacker = net.createServer((sock) => sock.destroy());
    hijacker.listen(directPort, '127.0.0.1');
    await once(hijacker, 'listening');
    try {
      localStore.update({
        selectedClashNode: '直连测试节点',
        selectedClashProfileUid: 'local-prof',
        selectedClashProfileName: '本地测试订阅',
        dedicatedProxyPort: directPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const hijackedSnap = await localEngine.probeClaudeNodeNow('端口被外部进程占用时运行期判定', true);
      assert.equal(readyEvents, 0, '端口归属不匹配时不得恢复为 ready');
      assert.equal(localService.channels.claude.getState().phase, 'error', '端口被外部进程占用时内核状态不得保持 ready');
      assert.equal(hijackedSnap.privateChannels.claude.phase, 'error');
      assert.match(localService.channels.claude.getState().verificationError || '', /监听归属/);
      assert.match(localService.channels.claude.getState().error || '', /监听归属/);
      const hijackedSafety = localEngine.evaluateClaudeSafety(true);
      assert.equal(hijackedSafety.safe, false);
      assert.equal(
        hijackedSafety.alertType,
        'disconnect',
        `端口归属冲突时运行中会话必须按代理绑定失效 (disconnect) 熔断而非保留会话，实际: ${hijackedSafety.alertType} (${hijackedSafety.reason})`
      );
      assert.match(hijackedSafety.reason, /代理绑定失效/);
      assert.match(hijackedSafety.reason, /监听归属/);
    } finally {
      localStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
      });
      await new Promise<void>((resolve) => hijacker.close(() => resolve()));
    }

    const outcome = await localService.channels.claude.recoverListenerIfNeeded();
    assert.equal(outcome, 'rebound');
    assert.equal(readyEvents, 1);
    assert.equal(localService.channels.claude.getState().phase, 'ready');
    assert.equal(localService.channels.claude.getState().error, null);
    assert.equal(localService.channels.claude.getState().verificationError, null);
    assert.equal(await isLocalPortListening(directPort), true);
    assert.equal(
      await requestTextViaProxy(`http://127.0.0.1:${originPort}/`, `http://127.0.0.1:${directPort}`, 5000, undefined, 0, true),
      'ok-body'
    );

    // 4b. 验证 Windows 双栈 :: 监听抢占 127.0.0.1 专属端口时同样进入 error 并触发 disconnect，且恢复后进程退出仍正常发射 lost 事件
    await mihomoRequest(leaseInfo.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
    const dropDualDeadline = Date.now() + 3000;
    while ((await isLocalPortListening(directPort)) && Date.now() < dropDualDeadline) await delay(50);
    assert.equal(await isLocalPortListening(directPort), false);
    const dualStackHijacker = net.createServer((sock) => sock.destroy());
    dualStackHijacker.listen({ port: directPort, host: '::', ipv6Only: false });
    await once(dualStackHijacker, 'listening');
    try {
      assert.equal(await isLocalPortListening(directPort), true, 'Windows 双栈 :: 监听应接受 127.0.0.1 连接');
      localStore.update({
        selectedClashNode: '直连测试节点',
        selectedClashProfileUid: 'local-prof',
        selectedClashProfileName: '本地测试订阅',
        dedicatedProxyPort: directPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const readyBeforeDual = readyEvents;
      const dualSnap = await localEngine.probeClaudeNodeNow('双栈 :: 端口抢占运行期判定', true);
      assert.equal(readyEvents, readyBeforeDual, '双栈 :: 监听抢占时不得恢复为 ready');
      assert.equal(localService.channels.claude.getState().phase, 'error', '双栈 :: 抢占时内核必须进入 error');
      assert.equal(dualSnap.privateChannels.claude.phase, 'error');
      const dualSafety = localEngine.evaluateClaudeSafety(true);
      assert.equal(dualSafety.safe, false);
      assert.equal(dualSafety.alertType, 'disconnect', '双栈 :: 抢占时必须按代理绑定失效 (disconnect) 处理');
    } finally {
      localStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
      });
      await new Promise<void>((resolve) => dualStackHijacker.close(() => resolve()));
    }
    assert.equal(await localService.channels.claude.recoverListenerIfNeeded(), 'rebound');
    assert.equal(localService.channels.claude.getState().phase, 'ready');

    // 验证从 error 恢复为 ready 后，内核子进程意外退出不会因残留 booting 漏发 lost 事件
    let lostEventsAfterRecover = 0;
    const onLostAfterRecover = () => lostEventsAfterRecover++;
    localService.channels.claude.on('lost', onLostAfterRecover);
    try {
      const pidBeforeKill = localService.channels.claude.getState().pid!;
      assert.ok(pidBeforeKill > 0);
      process.kill(pidBeforeKill);
      const lostDeadline = Date.now() + 3000;
      while (lostEventsAfterRecover === 0 && Date.now() < lostDeadline) await delay(50);
      assert.equal(lostEventsAfterRecover, 1, '恢复为 ready 后的内核意外退出必须立即触发 lost 事件');
      const restartDeadline = Date.now() + 15000;
      while (
        (localService.channels.claude.getState().phase !== 'ready' ||
          localService.channels.claude.getState().pid === pidBeforeKill) &&
        Date.now() < restartDeadline
      ) {
        await delay(100);
      }
      assert.equal(localService.channels.claude.getState().phase, 'ready');
    } finally {
      localService.channels.claude.off('lost', onLostAfterRecover);
    }
    const refreshedLeaseInfo = readLeaseEndpoint(path.join(localRoot, 'kernels', 'claude'));

    // 4c. 验证健康检查等待 getLocalPortOwnerPids() 期间子进程退出，丢弃过期端口归属结果且零未处理 Promise 拒绝
    await mihomoRequest(refreshedLeaseInfo.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
    const dropExitRaceDeadline = Date.now() + 3000;
    while ((await isLocalPortListening(directPort)) && Date.now() < dropExitRaceDeadline) await delay(50);
    assert.equal(await isLocalPortListening(directPort), false);
    const pidBeforeHealthRace = localService.channels.claude.getState().pid!;
    assert.ok(pidBeforeHealthRace > 0);
    let raceHijackHits = 0;
    let killedDuringOwnerLookup = false;
    let racePortConflictCount = 0;
    let raceLostCount = 0;
    const onRacePortConflict = () => racePortConflictCount++;
    const onRaceLost = () => raceLostCount++;
    localService.channels.claude.on('port-conflict', onRacePortConflict);
    localService.channels.claude.on('lost', onRaceLost);
    const raceHijacker = net.createServer((sock) => {
      raceHijackHits++;
      sock.destroy();
      // 第 1 次连接来自 verifyListener()，第 2 次来自 catch 分支 isLocalPortListening()；随后立即进入 getLocalPortOwnerPids()
      if (raceHijackHits === 2 && !killedDuringOwnerLookup) {
        killedDuringOwnerLookup = true;
        setTimeout(() => {
          try {
            process.kill(pidBeforeHealthRace);
          } catch {
            // 若已退出则忽略
          }
        }, 30);
      }
    });
    raceHijacker.listen(directPort, '127.0.0.1');
    await once(raceHijacker, 'listening');
    try {
      const raceDeadline = Date.now() + 8000;
      while ((!killedDuringOwnerLookup || raceLostCount === 0) && Date.now() < raceDeadline) {
        await delay(50);
      }
      assert.equal(killedDuringOwnerLookup, true, '应在健康检查进入端口归属查询期间触发子进程退出');
      assert.equal(raceLostCount, 1, '子进程退出必须正常触发 lost 事件');
      // 等待后台 PowerShell getLocalPortOwnerPids() 返回并确认未产生 port-conflict 或未处理异常
      await delay(1200);
      assert.equal(racePortConflictCount, 0, '内核已退出后返回的过期端口归属结果必须被丢弃，不得误报 port-conflict');
    } finally {
      localService.channels.claude.off('port-conflict', onRacePortConflict);
      localService.channels.claude.off('lost', onRaceLost);
      await new Promise<void>((resolve) => raceHijacker.close(() => resolve()));
    }
    const postRaceReadyDeadline = Date.now() + 18000;
    while (
      (localService.channels.claude.getState().phase !== 'ready' ||
        localService.channels.claude.getState().pid === pidBeforeHealthRace) &&
      Date.now() < postRaceReadyDeadline
    ) {
      await delay(100);
    }
    assert.equal(localService.channels.claude.getState().phase, 'ready', '竞态结束后内核应自动恢复就绪');
    let postRaceLeaseInfo = readLeaseEndpoint(path.join(localRoot, 'kernels', 'claude'));

    // 4d. 验证私有内核存活且独占端口归属有效、但 Mihomo 控制接口临时超时时：
    //     不将通道标为 error/disconnect，阻断新启动并保留运行中 Claude 会话（verification-unavailable）交由 5s 后台复核。
    const suspendedPid = localService.channels.claude.getState().pid!;
    assert.ok(suspendedPid > 0);
    try {
      execFileSync(
        'powershell.exe',
        [
          '-NoProfile',
          '-NonInteractive',
          '-File',
          path.resolve('tests/suspendKernel.ps1'),
          '-KernelPid',
          String(suspendedPid),
          '-ExpectedExecutable',
          verifyCore(coreDir),
        ],
        { windowsHide: true, stdio: 'pipe' }
      );
      localStore.update({
        selectedClashNode: '直连测试节点',
        selectedClashProfileUid: 'local-prof',
        selectedClashProfileName: '本地测试订阅',
        dedicatedProxyPort: directPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const timeoutSnap = await localEngine.probeClaudeNodeNow('控制接口临时超时保留运行会话', true);
      assert.equal(
        localService.channels.claude.getState().phase,
        'ready',
        '私有内核存活且无端口冲突时，控制接口超时不得将通道标为 error'
      );
      assert.match(localService.channels.claude.getState().verificationError || '', /超时/);
      assert.equal(timeoutSnap.claudeState.canLaunch, false, '控制接口超时期间必须阻止新启动');
      const timeoutSafety = localEngine.evaluateClaudeSafety(true);
      assert.equal(timeoutSafety.safe, false);
      assert.equal(
        timeoutSafety.alertType,
        'verification-unavailable',
        `控制接口超时且无端口冲突时必须归为 verification-unavailable 保留会话，实际：${timeoutSafety.alertType} (${timeoutSafety.reason})`
      );
    } finally {
      localStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
      });
      await localService.channels.claude.restart();
      assert.equal(localService.channels.claude.getState().phase, 'ready');
      assert.notEqual(localService.channels.claude.getState().pid, suspendedPid);
      postRaceLeaseInfo = readLeaseEndpoint(path.join(localRoot, 'kernels', 'claude'));
    }

    // 4e. 验证 stopMonitoring() 取消后台端口归属查询且保留私有内核进程（托盘退出保留 Antigravity 内核），
    //     同时验证 shutdown() 立即取消在途端口归属查询而不阻塞长达 10 秒。
    const monitorStopService = trackService(
      new PrivateProxyService(path.join(localRoot, 'monitor-stop-kernels'), coreDir)
    );
    const monitorAgPort = await freePort();
    const monitorClaudePort = await freePort();
    try {
      await Promise.all([
        monitorStopService.channels.antigravity.select(directSnap, monitorAgPort),
        monitorStopService.channels.claude.select(directSnap, monitorClaudePort),
      ]);
      const agMonitorPid = monitorStopService.channels.antigravity.getState().pid!;
      assert.ok(agMonitorPid > 0);
      const agMonitorLease = readLeaseEndpoint(path.join(localRoot, 'monitor-stop-kernels', 'antigravity'));
      await mihomoRequest(agMonitorLease.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
      const dropAgMonDeadline = Date.now() + 3000;
      while ((await isLocalPortListening(monitorAgPort)) && Date.now() < dropAgMonDeadline) await delay(40);
      let agMonHits = 0;
      let stoppedMonitoring = false;
      let agMonConflictCount = 0;
      monitorStopService.channels.antigravity.on('port-conflict', () => agMonConflictCount++);
      const agMonHijacker = net.createServer((sock) => {
        agMonHits++;
        sock.destroy();
        if (agMonHits === 2 && !stoppedMonitoring) {
          stoppedMonitoring = true;
          setTimeout(() => {
            monitorStopService.channels.antigravity.stopMonitoring();
          }, 30);
        }
      });
      agMonHijacker.listen(monitorAgPort, '127.0.0.1');
      await once(agMonHijacker, 'listening');
      try {
        const waitAgMon = Date.now() + 8000;
        while (!stoppedMonitoring && Date.now() < waitAgMon) await delay(40);
        assert.equal(stoppedMonitoring, true, '应在 Antigravity 健康检查进入端口归属查询后触发 stopMonitoring()');
        await delay(600);
        assert.equal(agMonConflictCount, 0, 'stopMonitoring() 取消在途端口归属查询后不得继续发出 port-conflict');
        assert.doesNotThrow(
          () => process.kill(agMonitorPid, 0),
          'stopMonitoring() 必须保留 Antigravity 私有内核进程继续运行'
        );
      } finally {
        await new Promise<void>((resolve) => agMonHijacker.close(() => resolve()));
      }

      // 触发 Claude 通道健康检查进入 getLocalPortOwnerPids() 并立即 shutdown()，验证不会阻塞 10 秒
      const claudeMonitorLease = readLeaseEndpoint(path.join(localRoot, 'monitor-stop-kernels', 'claude'));
      await mihomoRequest(claudeMonitorLease.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
      const dropClMonDeadline = Date.now() + 3000;
      while ((await isLocalPortListening(monitorClaudePort)) && Date.now() < dropClMonDeadline) await delay(40);
      let clMonHits = 0;
      let shutdownPromise: Promise<void> | null = null;
      let shutdownStartedAt = 0;
      const clMonHijacker = net.createServer((sock) => {
        clMonHits++;
        sock.destroy();
        if (clMonHits === 2 && !shutdownPromise) {
          setTimeout(() => {
            shutdownStartedAt = Date.now();
            shutdownPromise = monitorStopService.shutdown();
          }, 30);
        }
      });
      clMonHijacker.listen(monitorClaudePort, '127.0.0.1');
      await once(clMonHijacker, 'listening');
      try {
        const waitClMon = Date.now() + 8000;
        while (!shutdownPromise && Date.now() < waitClMon) await delay(40);
        assert.ok(shutdownPromise, '应在 Claude 健康检查进入端口归属查询后触发 shutdown()');
        await shutdownPromise;
        const shutdownElapsed = Date.now() - shutdownStartedAt;
        assert.ok(
          shutdownElapsed < 5000,
          `shutdown() 应立即取消在途端口归属查询并快速停机，而非等待 10s PowerShell 超时 (实际 ${shutdownElapsed}ms)`
        );
      } finally {
        await new Promise<void>((resolve) => clMonHijacker.close(() => resolve()));
      }
    } finally {
      await monitorStopService.shutdown();
      activeServices.delete(monitorStopService);
    }

    // 4f. 验证切换节点因新端口被占用提前失败时，仍恢复原内核的后台健康巡检定时器
    const occupiedSwitchPort = await freePort();
    const occupiedSwitchServer = net.createServer((sock) => sock.destroy());
    occupiedSwitchServer.listen(occupiedSwitchPort, '127.0.0.1');
    await once(occupiedSwitchServer, 'listening');
    try {
      const pidBeforeFailedSwitch = localService.channels.claude.getState().pid!;
      await assert.rejects(localService.channels.claude.select(directSnap, occupiedSwitchPort), /占用/);
      assert.equal(localService.channels.claude.getState().phase, 'ready');
      assert.equal(localService.channels.claude.getState().pid, pidBeforeFailedSwitch);
      assert.notEqual(
        (localService.channels.claude as unknown as { timer: NodeJS.Timeout | null }).timer,
        null,
        '节点切换提前失败保留原内核时，必须继续排期原内核的健康巡检定时器'
      );
    } finally {
      await new Promise<void>((resolve) => occupiedSwitchServer.close(() => resolve()));
    }

    // 4g. 验证托盘退出 stopMonitoring() 在启动期转发校验阶段保留已过监听校验的 Antigravity 内核，
    //     且更新停机 shutdown() 立即取消启动期校验并清理全部私有内核。
    const startupHoldClients = new Set<Duplex>();
    const startupHoldServer = http.createServer();
    startupHoldServer.on('clientError', (_err, sock) => sock.destroy());
    startupHoldServer.on('connect', (_req, client) => {
      startupHoldClients.add(client);
      client.on('error', () => client.destroy());
      client.write('HTTP/1.1 200 Connection established\r\n\r\n');
      client.once('end', () => client.end());
      client.once('close', () => startupHoldClients.delete(client));
      client.resume();
    });
    const startupHoldPort = await listen(startupHoldServer, '127.0.0.1');
    const startupVergeDir = path.join(localRoot, 'startup-hold-verge');
    fs.mkdirSync(path.join(startupVergeDir, 'profiles'), { recursive: true });
    fs.writeFileSync(
      path.join(startupVergeDir, 'profiles.yaml'),
      yaml.dump({
        current: 'startup-prof',
        items: [{ uid: 'startup-prof', name: '启动校验订阅', type: 'local', file: 'startup-prof.yaml' }],
      }),
      'utf8'
    );
    fs.writeFileSync(
      path.join(startupVergeDir, 'profiles', 'startup-prof.yaml'),
      yaml.dump({
        proxies: [{ name: '启动转发挂起节点', type: 'http', server: '127.0.0.1', port: startupHoldPort }],
      }),
      'utf8'
    );
    const startupCat = new SubscriptionCatalog(startupVergeDir);
    startupCat.refresh();
    const hangForwardSnap = startupCat.capture('startup-prof', '启动转发挂起节点');
    const trayExitService = trackService(
      new PrivateProxyService(path.join(localRoot, 'tray-exit-kernels'), coreDir)
    );
    const agTrayPort = await freePort();
    const clTrayPort = await freePort();
    try {
      const agStartTask = trayExitService.channels.antigravity.select(hangForwardSnap, agTrayPort);
      const waitAgForward = Date.now() + 10000;
      while (
        (startupHoldClients.size === 0 || !(await isLocalPortListening(agTrayPort))) &&
        Date.now() < waitAgForward
      ) {
        await delay(30);
      }
      assert.ok(startupHoldClients.size >= 1, 'Antigravity 内核应已通过监听校验并进入启动期转发校验');
      trayExitService.channels.antigravity.stopMonitoring();
      await agStartTask;
      const preservedAgPid = trayExitService.channels.antigravity.getState().pid!;
      assert.ok(preservedAgPid > 0, '托盘退出后 Antigravity 内核 PID 应保持记录');
      assert.doesNotThrow(
        () => process.kill(preservedAgPid, 0),
        '托盘退出 stopMonitoring() 取消启动期转发校验时不得终止已启动的 Antigravity 私有内核'
      );
      assert.equal(await isLocalPortListening(agTrayPort), true, '托盘退出后 Antigravity 专属监听应保持活跃');

      const clStartTask = trayExitService.channels.claude.select(hangForwardSnap, clTrayPort);
      const waitClSpawn = Date.now() + 5000;
      while (trayExitService.channels.claude.getState().pid === null && Date.now() < waitClSpawn) {
        await delay(25);
      }
      assert.ok(trayExitService.channels.claude.getState().pid !== null, 'Claude 内核应已启动进入启动校验阶段');
      const shutdownDuringStartAt = Date.now();
      await trayExitService.shutdown();
      await clStartTask.catch(() => undefined);
      assert.ok(
        Date.now() - shutdownDuringStartAt < 5000,
        `shutdown() 应立即取消启动阶段归属/转发校验并快速退出 (实际 ${Date.now() - shutdownDuringStartAt}ms)`
      );
    } finally {
      await trayExitService.shutdown();
      activeServices.delete(trayExitService);
      for (const sock of startupHoldClients) sock.destroy();
      await new Promise<void>((resolve) => startupHoldServer.close(() => resolve()));
    }

    // 5. 验证在 checkPrivateReady 或 recoverListenerIfNeeded 期间调用 stop()，不会继续发起新请求或重载内核配置
    let requestsAfterStop = 0;
    const stopGuardServer = http.createServer();
    stopGuardServer.on('connect', (_req, client) => {
      requestsAfterStop++;
      client.destroy();
    });
    const stopGuardPort = await listen(stopGuardServer, '127.0.0.1');
    try {
      const stopGuardStore = new ConfigStore();
      stopGuardStore.update({
        selectedClashNode: '直连测试节点',
        selectedClashProfileUid: 'local-prof',
        selectedClashProfileName: '本地测试订阅',
        dedicatedProxyPort: stopGuardPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const stopGuardEngine = new ProbeEngine(stopGuardStore, localGeo, new ClashMonitor(localSubDir), localService);
      const pendingProbe = stopGuardEngine.probeClaudeNodeNow('验证停止后不再发起新网络请求', true);
      stopGuardEngine.stop();
      await pendingProbe;
      await delay(200);
      assert.equal(requestsAfterStop, 0, 'stop() 在就绪检查期间触发后不得继续发起新的代理请求');
    } finally {
      await new Promise<void>((resolve) => stopGuardServer.close(() => resolve()));
    }

    // 5b. 验证端口恢复已进入监听归属核验时触发 stop()，不会继续向内核发送配置重载请求
    await mihomoRequest(postRaceLeaseInfo.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
    const dropAgainDeadline = Date.now() + 3000;
    while ((await isLocalPortListening(directPort)) && Date.now() < dropAgainDeadline) await delay(50);
    assert.equal(await isLocalPortListening(directPort), false);
    let holderConnections = 0;
    const transientHolder = net.createServer((sock) => {
      holderConnections++;
      sock.destroy();
    });
    transientHolder.listen(directPort, '127.0.0.1');
    await once(transientHolder, 'listening');
    try {
      const readyBeforeStop = readyEvents;
      const cancelRecoveryStore = new ConfigStore();
      cancelRecoveryStore.update({
        selectedClashNode: '直连测试节点',
        selectedClashProfileUid: 'local-prof',
        selectedClashProfileName: '本地测试订阅',
        dedicatedProxyPort: directPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const cancelRecoveryEngine = new ProbeEngine(
        cancelRecoveryStore,
        localGeo,
        new ClashMonitor(localSubDir),
        localService
      );
      const inflightRecoveryProbe = cancelRecoveryEngine.probeClaudeNodeNow(
        '验证恢复期间停止不重载内核配置',
        true
      );
      // 第 1 次连接来自 checkPrivateReady；第 2 次连接确认已进入 recoverListenerIfNeeded -> verifyListener(true)
      const enterRecoveryDeadline = Date.now() + 3000;
      while (holderConnections < 2 && Date.now() < enterRecoveryDeadline) {
        await delay(10);
      }
      assert.ok(holderConnections >= 2, '应在进入 recoverListenerIfNeeded 监听核验后再触发取消');
      await new Promise<void>((resolve) => transientHolder.close(() => resolve()));
      cancelRecoveryEngine.stop();
      await inflightRecoveryProbe;
      await delay(250);
      const cfgAfterStop = await mihomoRequest<Record<string, unknown>>(postRaceLeaseInfo.endpoint, '/configs');
      assert.equal(cfgAfterStop['mixed-port'], 0, 'stop() 触发后恢复流程不得继续向内核发出配置重载');
      assert.equal(readyEvents, readyBeforeStop, 'stop() 取消恢复后不得触发 ready');
    } finally {
      if (transientHolder.listening) {
        await new Promise<void>((resolve) => transientHolder.close(() => resolve()));
      }
      localStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
      });
    }
    assert.equal(await localService.channels.claude.recoverListenerIfNeeded(), 'rebound');

    // 5c. 验证停止 Antigravity 探测时立即中断已建立的代理隧道连接，不残留 14 秒慢连接
    const agHeldSockets = new Set<Duplex>();
    let agHoldConnects = false;
    const agUpstreamRelay = http.createServer();
    agUpstreamRelay.on('clientError', (_err, sock) => sock.destroy());
    agUpstreamRelay.on('connect', (_req, client) => {
      if (!agHoldConnects) {
        client.destroy();
        return;
      }
      agHeldSockets.add(client);
      client.on('error', () => client.destroy());
      client.write('HTTP/1.1 200 Connection established\r\n\r\n');
      client.once('end', () => client.end());
      client.once('close', () => agHeldSockets.delete(client));
      client.resume();
    });
    const agUpstreamRelayPort = await listen(agUpstreamRelay, '127.0.0.1');
    const agTestPort = await freePort();
    try {
      const agVergeDir = path.join(localRoot, 'ag-verge');
      fs.mkdirSync(path.join(agVergeDir, 'profiles'), { recursive: true });
      fs.writeFileSync(
        path.join(agVergeDir, 'profiles.yaml'),
        yaml.dump({
          current: 'ag-prof',
          items: [{ uid: 'ag-prof', name: 'AG测试订阅', type: 'local', file: 'ag-prof.yaml' }],
        }),
        'utf8'
      );
      fs.writeFileSync(
        path.join(agVergeDir, 'profiles', 'ag-prof.yaml'),
        yaml.dump({
          hosts: Object.fromEntries(
            BUILTIN_TRACE_ENDPOINTS.map((ep) => [new URL(ep.url).hostname, '198.51.100.10'])
          ),
          proxies: [{ name: 'AG挂起测试节点', type: 'http', server: '127.0.0.1', port: agUpstreamRelayPort }],
        }),
        'utf8'
      );
      const agCat = new SubscriptionCatalog(agVergeDir);
      agCat.refresh();
      await localService.channels.antigravity.select(agCat.capture('ag-prof', 'AG挂起测试节点'), agTestPort);
      assert.equal(localService.channels.antigravity.getState().phase, 'ready');

      agHoldConnects = true;
      const agStopStore = new ConfigStore();
      agStopStore.update({
        selectedClashNode: null,
        antigravityClashNode: 'AG挂起测试节点',
        antigravityClashProfileUid: 'ag-prof',
        antigravityClashProfileName: 'AG测试订阅',
        antigravityDedicatedPort: agTestPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const agStopEngine = new ProbeEngine(agStopStore, localGeo, new ClashMonitor(agVergeDir), localService);
      const agProbeTask = agStopEngine.probeAntigravityNodeNow();
      const waitTunnelDeadline = Date.now() + 3000;
      while (agHeldSockets.size === 0 && Date.now() < waitTunnelDeadline) {
        await delay(25);
      }
      assert.ok(agHeldSockets.size >= 1, 'Antigravity 探测应已通过真实私有内核建立代理隧道');
      const stopStartedAt = Date.now();
      agStopEngine.stop();
      await agProbeTask;
      assert.ok(
        Date.now() - stopStartedAt < 2000,
        `stop() 后 Antigravity 探测必须立即返回而非等待超时 (实际 ${Date.now() - stopStartedAt}ms)`
      );
      const agCloseDeadline = Date.now() + 1000;
      while (agHeldSockets.size > 0 && Date.now() < agCloseDeadline) {
        await delay(20);
      }
      assert.equal(agHeldSockets.size, 0, 'stop() 后 Antigravity 探测已建立的代理连接必须全部关闭');
    } finally {
      localStore.update({
        antigravityClashNode: null,
        antigravityClashProfileUid: null,
        antigravityClashProfileName: null,
      });
      for (const sock of agHeldSockets) sock.destroy();
      await new Promise<void>((resolve) => agUpstreamRelay.close(() => resolve()));
    }

    console.log('通过：离线 GeoIP 缓存零重读、本地代理瞬断重试与取消、全重合零源阻断、端口归属 Fail-Closed 恢复与停机零新请求');
  } finally {
    localEngine.stop();
    await localService.shutdown();
    activeServices.delete(localService);
    for (const sock of relayClients) sock.destroy();
    for (const sock of forwardClients) sock.destroy();
    for (const sock of localExitClients) sock.destroy();
    await Promise.all([
      new Promise<void>((resolve) => relayServer.close(() => resolve())),
      new Promise<void>((resolve) => forwardRelay.close(() => resolve())),
      new Promise<void>((resolve) => localExitProxy.close(() => resolve())),
      new Promise<void>((resolve) => localTlsOrigin.close(() => resolve())),
      new Promise<void>((resolve) => originServer.close(() => resolve())),
    ]);
  }
}

async function verifyMultiSourceConsensus(coreDir: string): Promise<void> {
  const tlsCertPath = process.env.GUARD_TEST_TLS_CERT;
  const tlsKeyPath = process.env.GUARD_TEST_TLS_KEY;
  assert.ok(
    tlsCertPath &&
      tlsKeyPath &&
      process.env.NODE_EXTRA_CA_CERTS &&
      fs.existsSync(tlsCertPath) &&
      fs.existsSync(tlsKeyPath),
    '缺少多源共识真实 HTTPS 回归所需的测试 TLS 证书环境变量（请通过 npm test 运行）'
  );
  const tlsCert = fs.readFileSync(tlsCertPath, 'utf8');
  const tlsKey = fs.readFileSync(tlsKeyPath, 'utf8');

  const liveRoot = path.join(root, 'live-consensus');
  const upstreamService = trackService(new PrivateProxyService(path.join(liveRoot, 'upstream-kernels'), coreDir));
  const subService = trackService(new PrivateProxyService(path.join(liveRoot, 'sub-kernels'), coreDir));
  const geo = new GeoIpService();
  await geo.init(process.cwd());

  const expectedProxyIp = '1.0.16.1';
  const expectedProxyDriftedIp = '1.0.16.2';
  const expectedForeignIp = '8.8.8.8';
  const expectedProxyCountry = geo.lookupOfflineStrict(expectedProxyIp).countryCode;
  assert.equal(
    geo.lookupOfflineStrict(expectedProxyDriftedIp).countryCode,
    expectedProxyCountry,
    '同国漂移测试 IP 应与主出口同属离线国家'
  );
  const expectedForeignCountry = geo.lookupOfflineStrict(expectedForeignIp).countryCode;
  assert.notEqual(
    expectedProxyCountry,
    expectedForeignCountry,
    `独立测试主出口 (${expectedProxyCountry}) 与异国出口 (${expectedForeignCountry}) 必须分属不同国家`
  );

  // 创建本地真实转发中继与独立真实 TLS 回显服务（全流程使用真实 guard-mihomo.exe + 真实 HTTPS/TLS + 真实离线 mmdb，无任何外部订阅依赖）
  const allSockets = new Set<Duplex>();
  let proxyClaudeTraceMode: 'normal' | 'bad-first-then-ok' | 'loc-xx-then-fail' | 'drift-loc-xx-then-old-ok' = 'normal';
  let proxyClaudeTraceHits = 0;
  let foreignClaudeTraceMode: 'normal' | 'loc-xx-proxy-ip' = 'normal';
  const createRealTlsExitOrigin = (exitIp: string, exitCountry: string, isProxySide: boolean) =>
    https.createServer({ key: tlsKey, cert: tlsCert }, (req, res) => {
      const host = String(req.headers.host || '').split(':')[0].toLowerCase();
      const reqPath = req.url || '/';
      if (reqPath.startsWith('/cdn-cgi/trace')) {
        if (isProxySide && host === 'claude.ai') {
          const hit = ++proxyClaudeTraceHits;
          if (proxyClaudeTraceMode === 'bad-first-then-ok' && hit === 1) {
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('ok-without-valid-ip\n');
            return;
          }
          if (proxyClaudeTraceMode === 'loc-xx-then-fail') {
            if (hit === 1) {
              res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
              res.end(`fl=29f1\nh=claude.ai\nip=${expectedForeignIp}\nts=${Math.floor(Date.now() / 1000)}\nloc=XX\n`);
              return;
            }
            res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('bad gateway');
            return;
          }
          if (proxyClaudeTraceMode === 'drift-loc-xx-then-old-ok' && hit === 1) {
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end(`fl=29f1\nh=claude.ai\nip=${expectedProxyDriftedIp}\nts=${Math.floor(Date.now() / 1000)}\nloc=XX\n`);
            return;
          }
        }
        if (!isProxySide && host === 'claude.ai' && foreignClaudeTraceMode === 'loc-xx-proxy-ip') {
          res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end(`fl=29f1\nh=claude.ai\nip=${expectedProxyIp}\nts=${Math.floor(Date.now() / 1000)}\nloc=XX\n`);
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(`fl=29f1\nh=${host}\nip=${exitIp}\nts=${Math.floor(Date.now() / 1000)}\nloc=${exitCountry}\n`);
        return;
      }
      if (reqPath.startsWith('/sw.js_data')) {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(`)]}'\n["yt.sw.adr",null,[[["","${exitCountry}",null,"${exitIp}"]]]]`);
        return;
      }
      if (host.includes('google.com')) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!doctype html><html><script>var cfg={"MgUcDb":"${exitCountry}"};</script></html>`);
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`${exitIp}\n`);
    });

  const proxyOriginServer = createRealTlsExitOrigin(expectedProxyIp, expectedProxyCountry, true);
  const foreignOriginServer = createRealTlsExitOrigin(expectedForeignIp, expectedForeignCountry, false);
  const [proxyOriginPort, foreignOriginPort] = await Promise.all([
    listen(proxyOriginServer, '127.0.0.1'),
    listen(foreignOriginServer, '127.0.0.1'),
  ]);

  const createConnectUpstreamProxy = (targetOriginPort: number) => {
    const srv = http.createServer();
    srv.on('clientError', (_err, sock) => sock.destroy());
    srv.on('connect', (_req, client, head) => {
      allSockets.add(client);
      const up = net.connect(targetOriginPort, '127.0.0.1', () => {
        client.write('HTTP/1.1 200 Connection established\r\n\r\n');
        if (head.length > 0) up.write(head);
        client.pipe(up);
        up.pipe(client);
      });
      up.on('error', () => client.destroy());
      client.on('error', () => up.destroy());
      client.once('end', () => client.end());
      client.once('close', () => {
        up.destroy();
        allSockets.delete(client);
      });
    });
    return srv;
  };
  const proxyExitProxyServer = createConnectUpstreamProxy(proxyOriginPort);
  const foreignExitProxyServer = createConnectUpstreamProxy(foreignOriginPort);
  const [proxyExitProxyPort, foreignExitProxyPort] = await Promise.all([
    listen(proxyExitProxyServer, '127.0.0.1'),
    listen(foreignExitProxyServer, '127.0.0.1'),
  ]);

  const upstreamVergeDir = path.join(liveRoot, 'upstream-verge');
  fs.mkdirSync(path.join(upstreamVergeDir, 'profiles'), { recursive: true });
  fs.writeFileSync(
    path.join(upstreamVergeDir, 'profiles.yaml'),
    yaml.dump({
      current: 'upstream-prof',
      items: [{ uid: 'upstream-prof', name: '独立回归上游订阅', type: 'local', file: 'upstream-prof.yaml' }],
    }),
    'utf8'
  );
  fs.writeFileSync(
    path.join(upstreamVergeDir, 'profiles', 'upstream-prof.yaml'),
    yaml.dump({
      proxies: [
        { name: '独立主出口节点', type: 'http', server: '127.0.0.1', port: proxyExitProxyPort },
        { name: '独立异国出口节点', type: 'http', server: '127.0.0.1', port: foreignExitProxyPort },
      ],
    }),
    'utf8'
  );
  const upstreamCatalog = new SubscriptionCatalog(upstreamVergeDir);
  upstreamCatalog.refresh();

  const upstreamPort = await freePort();
  const directUpstreamPort = await freePort();
  const baseUpstreamPort = await freePort();
  const subPort = await freePort();

  // 启动独立的上游真实测试节点私有内核（纯本地独立配置，不依赖宿主 Clash Verge 订阅）
  const primarySnapshot = upstreamCatalog.capture('upstream-prof', '独立主出口节点');
  const foreignSnapshot = upstreamCatalog.capture('upstream-prof', '独立异国出口节点');

  let relayMode: 'delay-target' | 'delay-target-short' | 'stall-first' = 'delay-target';
  let relayHits = 0;
  const relayServer = net.createServer((client) => {
    allSockets.add(client);
    const hit = ++relayHits;
    let timer: NodeJS.Timeout | undefined;
    const up = net.connect(baseUpstreamPort, '127.0.0.1');
    client.pipe(up);
    if (relayMode === 'delay-target' || relayMode === 'delay-target-short') {
      const waitMs = relayMode === 'delay-target-short' ? 2400 : 5000;
      up.once('data', (chunk) => {
        up.pause();
        client.write(chunk);
        timer = setTimeout(() => up.pipe(client), waitMs);
      });
    } else if (relayMode === 'stall-first' && hit === 1) {
      up.once('data', (chunk) => {
        up.pause();
        client.write(chunk);
        timer = setTimeout(() => {
          up.destroy();
          client.end();
        }, 10000);
      });
    } else {
      up.pipe(client);
    }
    up.on('error', () => client.destroy());
    client.on('error', () => up.destroy());
    client.once('close', () => {
      if (timer) clearTimeout(timer);
      up.destroy();
      allSockets.delete(client);
    });
  });
  const relayPort = await listen(relayServer, '127.0.0.1');

  const directDelayServer = net.createServer((client) => {
    allSockets.add(client);
    let timer: NodeJS.Timeout | undefined;
    const up = net.connect(directUpstreamPort, '127.0.0.1');
    client.pipe(up);
    up.once('data', (chunk) => {
      up.pause();
      client.write(chunk);
      timer = setTimeout(() => up.pipe(client), 2400);
    });
    up.on('error', () => client.destroy());
    client.on('error', () => up.destroy());
    client.once('close', () => {
      if (timer) clearTimeout(timer);
      up.destroy();
      allSockets.delete(client);
    });
  });
  const directDelayPort = await listen(directDelayServer, '127.0.0.1');

  const observedHopTargets = new Set<string>();
  const observedHopHosts = new Set<string>();
  const connectHopServer = http.createServer();
  connectHopServer.on('clientError', (_err, sock) => sock.destroy());
  connectHopServer.on('connect', (req, client, head) => {
    allSockets.add(client);
    const target = parseHttpConnectAuthority(req.url);
    const hostHdr = parseHttpHostHeader(typeof req.headers.host === 'string' ? req.headers.host : undefined);
    if (target) observedHopTargets.add(target.host);
    if (hostHdr) observedHopHosts.add(hostHdr);
    if (!target) {
      client.destroy();
      return;
    }
    const up = net.connect(target.port, '127.0.0.1', () => {
      client.write('HTTP/1.1 200 Connection established\r\n\r\n');
      if (head.length > 0) up.write(head);
      client.pipe(up);
      up.pipe(client);
    });
    up.on('error', () => client.destroy());
    client.on('error', () => up.destroy());
    client.once('end', () => client.end());
    client.once('close', () => {
      up.destroy();
      allSockets.delete(client);
    });
  });
  const connectHopPort = await listen(connectHopServer, '127.0.0.1');

  const acceptedPassHosts = new Set<string>();
  let onPassHostAccepted: (() => void) | null = null;
  let beforePassTunnelReady: ((host: string) => Promise<void>) | null = null;
  const countedPassServer = http.createServer();
  countedPassServer.on('clientError', (_err, sock) => sock.destroy());
  countedPassServer.on('connect', (req, client, head) => {
    allSockets.add(client);
    const target = parseHttpConnectAuthority(req.url);
    let upSock: net.Socket | null = null;
    const upReq = http.request({
      host: '127.0.0.1',
      port: baseUpstreamPort,
      method: 'CONNECT',
      path: req.url,
      agent: false,
      headers: { Host: req.headers.host || req.url || '' },
    });
    upReq.once('connect', (upRes, upstream, upHead) => {
      if (client.destroyed || upRes.statusCode !== 200) {
        upstream.destroy();
        client.destroy();
        return;
      }
      upSock = upstream;
      upstream.on('error', () => client.destroy());
      const establish = () => {
        if (client.destroyed || upstream.destroyed) return;
        client.write('HTTP/1.1 200 Connection established\r\n\r\n');
        if (upHead.length > 0) client.write(upHead);
        if (head.length > 0) upstream.write(head);
        client.pipe(upstream);
        upstream.pipe(client);
        if (target) {
          acceptedPassHosts.add(target.host);
          onPassHostAccepted?.();
        }
      };
      if (target && beforePassTunnelReady) {
        upstream.pause();
        beforePassTunnelReady(target.host)
          .catch(() => undefined)
          .finally(() => {
            establish();
            upstream.resume();
          });
        return;
      }
      establish();
    });
    upReq.on('error', () => client.destroy());
    upReq.end();
    client.on('error', () => {
      upReq.destroy();
      upSock?.destroy();
    });
    client.once('end', () => client.end());
    client.once('close', () => {
      upReq.destroy();
      upSock?.destroy();
      allSockets.delete(client);
    });
  });
  const countedPassPort = await listen(countedPassServer, '127.0.0.1');

  const heldDropClients = new Set<Duplex>();
  let onHeldDropReady: (() => void) | null = null;
  const holdBeforeTlsServer = http.createServer();
  holdBeforeTlsServer.on('clientError', (_err, sock) => sock.destroy());
  holdBeforeTlsServer.on('connect', (_req, client) => {
    allSockets.add(client);
    heldDropClients.add(client);
    client.on('error', () => client.destroy());
    client.write('HTTP/1.1 200 Connection established\r\n\r\n');
    client.once('end', () => client.end());
    client.once('close', () => {
      heldDropClients.delete(client);
      allSockets.delete(client);
    });
    client.resume();
    onHeldDropReady?.();
  });
  const holdBeforeTlsPort = await listen(holdBeforeTlsServer, '127.0.0.1');

  const claudeHoldClients = new Set<Duplex>();
  let holdClaudePrimary = false;
  let onClaudeHoldReady: (() => void) | null = null;
  let claudeHoldReleasedCount = 0;
  let claudeHoldClosedBeforeReleaseCount = 0;
  const claudeHoldServer = http.createServer();
  claudeHoldServer.on('clientError', (_err, sock) => sock.destroy());
  claudeHoldServer.on('connect', (req, client, head) => {
    allSockets.add(client);
    claudeHoldClients.add(client);
    let upSock: net.Socket | null = null;
    let releaseTimer: NodeJS.Timeout | undefined;
    const shouldHold = holdClaudePrimary;
    let released = !shouldHold;
    const upReq = http.request({
      host: '127.0.0.1',
      port: baseUpstreamPort,
      method: 'CONNECT',
      path: req.url,
      agent: false,
      headers: { Host: req.headers.host || req.url || 'claude.ai:443' },
    });
    if (shouldHold) {
      client.write('HTTP/1.1 200 Connection established\r\n\r\n');
      const buffered: Buffer[] = head.length > 0 ? [head] : [];
      const onData = (chunk: Buffer) => buffered.push(chunk);
      client.on('data', onData);
      onClaudeHoldReady?.();
      upReq.once('connect', (upRes, upstream, upHead) => {
        if (client.destroyed || upRes.statusCode !== 200) {
          upstream.destroy();
          client.destroy();
          return;
        }
        upSock = upstream;
        upstream.pause();
        client.off('data', onData);
        for (const chunk of buffered) upstream.write(chunk);
        buffered.length = 0;
        client.pipe(upstream);
        releaseTimer = setTimeout(() => {
          released = true;
          claudeHoldReleasedCount++;
          if (upHead.length > 0) client.write(upHead);
          upstream.pipe(client);
        }, 8500);
        upstream.on('error', () => client.destroy());
      });
    } else {
      upReq.once('connect', (upRes, upstream, upHead) => {
        if (client.destroyed || upRes.statusCode !== 200) {
          upstream.destroy();
          client.destroy();
          return;
        }
        upSock = upstream;
        client.write('HTTP/1.1 200 Connection established\r\n\r\n');
        if (upHead.length > 0) client.write(upHead);
        if (head.length > 0) upstream.write(head);
        client.pipe(upstream);
        upstream.pipe(client);
        upstream.on('error', () => client.destroy());
      });
    }
    upReq.on('error', () => client.destroy());
    upReq.end();
    client.on('error', () => {
      upReq.destroy();
      upSock?.destroy();
    });
    client.once('end', () => {
      client.end();
    });
    client.once('close', () => {
      if (releaseTimer) clearTimeout(releaseTimer);
      if (shouldHold && !released) claudeHoldClosedBeforeReleaseCount++;
      upReq.destroy();
      upSock?.destroy();
      claudeHoldClients.delete(client);
      allSockets.delete(client);
    });
  });
  const claudeHoldPort = await listen(claudeHoldServer, '127.0.0.1');

  let subEngine: ProbeEngine | null = null;
  let onSubGeoLookup: ((countryCode: string) => void) | null = null;
  try {
    await upstreamService.channels.claude.select(primarySnapshot, upstreamPort);
    assert.equal(upstreamService.channels.claude.getState().phase, 'ready');

    const upLease = readLeaseEndpoint(path.join(liveRoot, 'upstream-kernels', 'claude'));
    const upBaseCfg = readYaml(upLease.configPath);
    const upProxies = Array.isArray(upBaseCfg.proxies) ? (upBaseCfg.proxies as Array<Record<string, unknown>>) : [];
    const upHosts = (upBaseCfg.hosts && typeof upBaseCfg.hosts === 'object' ? upBaseCfg.hosts : {}) as Record<string, unknown>;
    const outboundGroup = 'guard-selected-outbound';
    const foreignTarget = foreignSnapshot.nodeName;
    const extraForeignProxies: Array<Record<string, unknown>> = foreignSnapshot.proxies.map((p) => ({ ...p }));
    const extraForeignHosts: Record<string, unknown> = { ...foreignSnapshot.hosts };
    const makeUpstreamConfig = (rules: string[]) =>
      yaml.dump({
        ...upBaseCfg,
        hosts: { ...upHosts, ...extraForeignHosts },
        listeners: [
          { name: 'test-base-upstream', type: 'mixed', port: baseUpstreamPort, listen: '127.0.0.1', proxy: outboundGroup },
          { name: 'test-direct-upstream', type: 'mixed', port: directUpstreamPort, listen: '127.0.0.1', proxy: foreignTarget },
        ],
        proxies: [
          ...upProxies,
          ...extraForeignProxies,
          { name: 'test-delay', type: 'http', server: '127.0.0.1', port: relayPort },
          { name: 'test-direct-delay', type: 'http', server: '127.0.0.1', port: directDelayPort },
          { name: 'test-counted-pass', type: 'http', server: '127.0.0.1', port: countedPassPort },
          { name: 'test-hold-drop', type: 'http', server: '127.0.0.1', port: holdBeforeTlsPort },
          { name: 'test-claude-hold', type: 'http', server: '127.0.0.1', port: claudeHoldPort },
        ],
        rules: [...rules, `MATCH,${outboundGroup}`],
      });

    // 探测上游代理出口国家与异国对比候选源
    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    const claudeTraceRaw = await requestTextViaProxy(
      'https://claude.ai/cdn-cgi/trace',
      `http://127.0.0.1:${upstreamPort}`,
      12000
    );
    const proxyExitIp = extractEchoIpFromBody(claudeTraceRaw, 'cf-trace');
    const proxyCountry = geo.lookupOfflineStrict(proxyExitIp).countryCode;
    assert.equal(proxyExitIp, expectedProxyIp);
    assert.equal(proxyCountry, expectedProxyCountry);
    console.log(`独立回归上游节点就绪，主出口：${proxyExitIp} (${proxyCountry})，异国出口：${expectedForeignIp} (${expectedForeignCountry})`);

    const probeForeignCandidates = async () => {
      const checks = await Promise.all(
        BUILTIN_TRACE_ENDPOINTS.map(async (ep) => {
          try {
            const raw = await requestTextViaProxy(ep.url, `http://127.0.0.1:${directUpstreamPort}`, 5000);
            const echoIp = extractEchoIpFromBody(raw, ep.format);
            if (!echoIp) return null;
            const offlineGeo = geo.lookupOfflineStrict(echoIp);
            if (offlineGeo.countryCode !== proxyCountry) {
              return { endpoint: ep, host: new URL(ep.url).hostname, countryCode: offlineGeo.countryCode };
            }
          } catch {
            // 跳过不可达的回显源
          }
          return null;
        })
      );
      return checks.filter(
        (item): item is { endpoint: TraceEndpoint; host: string; countryCode: string } => item !== null
      );
    };

    const directCandidates = await probeForeignCandidates();
    assert.ok(
      directCandidates.length >= 2,
      `需要至少 2 个独立回显源可通过对比通道返回异于代理 (${proxyCountry}) 的离线国家，实际 ${directCandidates.length} 个`
    );
    const [direct1, direct2] = directCandidates;
    const proxySideEndpoints = BUILTIN_TRACE_ENDPOINTS.filter(
      (ep) =>
        ep.registrableDomain !== direct1.endpoint.registrableDomain &&
        ep.registrableDomain !== direct2.endpoint.registrableDomain
    );
    assert.ok(proxySideEndpoints.length >= MIN_CONSENSUS_MATCHES);

    // 构造受限探测源测试订阅（五源全量、四源复核、双源受限、单源受限）
    const keptTwoPair = [direct1.endpoint, proxySideEndpoints[0]];
    const excludedThreeDomains = BUILTIN_TRACE_ENDPOINTS.filter(
      (ep) => !keptTwoPair.some((k) => k.registrableDomain === ep.registrableDomain)
    ).map((ep) => ep.registrableDomain);
    const fourKeptSet = new Set([
      direct1.endpoint.registrableDomain,
      direct2.endpoint.registrableDomain,
      proxySideEndpoints[0].registrableDomain,
      proxySideEndpoints[1].registrableDomain,
    ]);
    const fifthExcludedDomain = BUILTIN_TRACE_ENDPOINTS.find(
      (ep) => !fourKeptSet.has(ep.registrableDomain)
    )!.registrableDomain;
    const singleKeptDomain = proxySideEndpoints[0].registrableDomain;
    const allFiveOrdered = [
      singleKeptDomain,
      ...BUILTIN_TRACE_ENDPOINTS.map((ep) => ep.registrableDomain).filter((d) => d !== singleKeptDomain),
    ];
    const hopHostsMap = Object.fromEntries(allFiveOrdered.map((d) => [`hop.${d}`, '127.0.0.1']));

    const subVergeDir = path.join(liveRoot, 'sub-verge');
    fs.mkdirSync(path.join(subVergeDir, 'profiles'), { recursive: true });
    fs.writeFileSync(
      path.join(subVergeDir, 'profiles.yaml'),
      yaml.dump({
        current: 'reduced-prof',
        items: [{ uid: 'reduced-prof', name: '受限源测试订阅', type: 'local', file: 'reduced-prof.yaml' }],
      }),
      'utf8'
    );
    fs.writeFileSync(
      path.join(subVergeDir, 'profiles', 'reduced-prof.yaml'),
      yaml.dump({
        hosts: hopHostsMap,
        proxies: [
          { name: '五源标准节点', type: 'http', server: '127.0.0.1', port: upstreamPort },
          {
            name: '受限前置跳板',
            type: 'http',
            server: `hop.${excludedThreeDomains[2]}`,
            port: connectHopPort,
            headers: { Host: `edge.${excludedThreeDomains[1]}` },
          },
          {
            name: '双源受限节点',
            type: 'http',
            server: `hop.${excludedThreeDomains[0]}`,
            port: upstreamPort,
            'dialer-proxy': '受限前置跳板',
          },
          {
            name: '四源复核节点',
            type: 'http',
            server: `hop.${fifthExcludedDomain}`,
            port: upstreamPort,
          },
          {
            name: '单源跳板-2',
            type: 'http',
            server: `hop.${allFiveOrdered[4]}`,
            port: connectHopPort,
            headers: { Host: `edge.${allFiveOrdered[3]}` },
          },
          {
            name: '单源跳板-1',
            type: 'http',
            server: `hop.${allFiveOrdered[2]}`,
            port: connectHopPort,
            headers: { Host: `edge.${allFiveOrdered[1]}` },
            'dialer-proxy': '单源跳板-2',
          },
          {
            name: '单源受限节点',
            type: 'http',
            server: '127.0.0.1',
            port: upstreamPort,
            'dialer-proxy': '单源跳板-1',
          },
          {
            name: '全重合零源可达节点',
            type: 'http',
            server: `hop.${allFiveOrdered[0]}`,
            port: upstreamPort,
            'dialer-proxy': '单源跳板-1',
          },
        ],
      }),
      'utf8'
    );

    const subCat = new SubscriptionCatalog(subVergeDir);
    subCat.refresh();
    const subStore = new ConfigStore();
    // 构造 ProbeEngine 前先显式关闭进程守护，杜绝任何异常提前退出时误杀宿主机 Claude
    subStore.update({
      selectedClashNode: null,
      selectedClashProfileUid: null,
      selectedClashProfileName: null,
      antigravityClashNode: null,
      antigravityClashProfileUid: null,
      antigravityClashProfileName: null,
      claudeExclusiveGuard: false,
      killProcessesEnabled: false,
    });
    const trackedGeo = new Proxy(geo, {
      get(target, prop, receiver) {
        const val = Reflect.get(target, prop, receiver);
        if ((prop === 'lookupOfflineStrict' || prop === 'lookup') && typeof val === 'function') {
          return (...args: unknown[]) => {
            const res = (val as (...a: unknown[]) => { countryCode: string; countryName: string }).apply(target, args);
            onSubGeoLookup?.(res.countryCode);
            return res;
          };
        }
        return typeof val === 'function' ? val.bind(target) : val;
      },
    });
    subEngine = new ProbeEngine(subStore, trackedGeo, new ClashMonitor(subVergeDir), subService);

    const bindSubNode = async (nodeName: string) => {
      subStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const snap = subCat.capture('reduced-prof', nodeName);
      await subService.channels.claude.select(snap, subPort);
      assert.equal(subService.channels.claude.getState().phase, 'ready');
      subStore.update({
        selectedClashNode: nodeName,
        selectedClashProfileUid: 'reduced-prof',
        selectedClashProfileName: '受限源测试订阅',
        dedicatedProxyPort: subPort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
    };

    // (0) 验证前 3 个转发探测源全部挂起（REJECT-DROP）时，PrivateKernel.probeForwarding 仍可在 10s 内通过第 4/5 源验证通过
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([
        'DOMAIN,ipv4.icanhazip.com,REJECT-DROP',
        'DOMAIN,checkip.amazonaws.com,REJECT-DROP',
        'DOMAIN,api.ipify.org,REJECT-DROP',
      ])
    );
    await bindSubNode('五源标准节点');
    assert.equal(
      subService.channels.claude.getState().verificationError,
      null,
      `前三个转发探测源挂起时，第 4/5 源应能成功验证转发，实际错误：${subService.channels.claude.getState().verificationError}`
    );

    // (0b) 验证 Antigravity 探测进入第二阶段 Google/YouTube 地区核验后调用 stop()，立即中断已建立连接并返回
    const agLivePort = await freePort();
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([
        'DOMAIN-SUFFIX,youtube.com,test-hold-drop',
        'DOMAIN-SUFFIX,google.com,test-hold-drop',
      ])
    );
    await subService.channels.antigravity.select(subCat.capture('reduced-prof', '五源标准节点'), agLivePort);
    assert.equal(subService.channels.antigravity.getState().phase, 'ready');
    heldDropClients.clear();
    try {
      const agLiveStore = new ConfigStore();
      agLiveStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
        antigravityClashNode: '五源标准节点',
        antigravityClashProfileUid: 'reduced-prof',
        antigravityClashProfileName: '受限源测试订阅',
        antigravityDedicatedPort: agLivePort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const agLiveEngine = new ProbeEngine(agLiveStore, geo, new ClashMonitor(subVergeDir), subService);
      const agGoogleProbeTask = agLiveEngine.probeAntigravityNodeNow();
      const waitGoogleHold = Date.now() + 8000;
      while (heldDropClients.size === 0 && Date.now() < waitGoogleHold) {
        await delay(30);
      }
      assert.ok(heldDropClients.size >= 1, 'Antigravity 探测应已进入 Google/YouTube 地区校验阶段并建立隧道');
      const googleStopAt = Date.now();
      agLiveEngine.stop();
      await agGoogleProbeTask;
      assert.ok(
        Date.now() - googleStopAt < 2000,
        `Google 地区请求阶段调用 stop() 后应立即返回 (实际 ${Date.now() - googleStopAt}ms)`
      );
      const waitGoogleClose = Date.now() + 1000;
      while (heldDropClients.size > 0 && Date.now() < waitGoogleClose) {
        await delay(20);
      }
      assert.equal(heldDropClients.size, 0, 'stop() 后 Google/YouTube 地区校验连接必须全部关闭');

      // (0c) 验证 Antigravity 等待 Google 地区响应期间发生端口归属冲突：
      //      必须立即取消在途探测并使旧样本失效，禁止写回界面；端口恢复后自动重测确认出口。
      claudeHoldReleasedCount = 0;
      claudeHoldClosedBeforeReleaseCount = 0;
      holdClaudePrimary = true;
      await reloadKernelConfig(
        upLease.endpoint,
        makeUpstreamConfig([
          'DOMAIN-SUFFIX,youtube.com,test-claude-hold',
          'DOMAIN-SUFFIX,google.com,test-claude-hold',
        ])
      );
      const agConflictStore = new ConfigStore();
      agConflictStore.update({
        selectedClashNode: null,
        selectedClashProfileUid: null,
        selectedClashProfileName: null,
        antigravityClashNode: '五源标准节点',
        antigravityClashProfileUid: 'reduced-prof',
        antigravityClashProfileName: '受限源测试订阅',
        antigravityDedicatedPort: agLivePort,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const agConflictEngine = new ProbeEngine(agConflictStore, geo, new ClashMonitor(subVergeDir), subService);
      const agSubLease = readLeaseEndpoint(path.join(liveRoot, 'sub-kernels', 'antigravity'));
      const agConflictHijacker = net.createServer((sock) => sock.destroy());
      try {
        const agConflictProbeTask = agConflictEngine.probeAntigravityNodeNow();
        const waitAgGoogleHold = Date.now() + 8000;
        while (claudeHoldClients.size === 0 && Date.now() < waitAgGoogleHold) {
          await delay(30);
        }
        assert.ok(claudeHoldClients.size >= 1, 'Antigravity 探测应已进入 Google/YouTube 地区响应等待阶段');
        // 关闭私有内核监听并由外部进程抢占端口，触发真实 port-conflict 事件
        await mihomoRequest(agSubLease.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
        const agDropDeadline = Date.now() + 3000;
        while ((await isLocalPortListening(agLivePort)) && Date.now() < agDropDeadline) {
          await delay(30);
        }
        agConflictHijacker.listen(agLivePort, '127.0.0.1');
        await once(agConflictHijacker, 'listening');
        assert.equal(await subService.channels.antigravity.recoverListenerIfNeeded(), 'failed');
        assert.equal(subService.channels.antigravity.getState().phase, 'error');

        await agConflictProbeTask;
        const waitAgConflictClose = Date.now() + 1500;
        while (claudeHoldClients.size > 0 && Date.now() < waitAgConflictClose) {
          await delay(20);
        }
        assert.equal(claudeHoldClients.size, 0, 'port-conflict 后正在等待 Google 地区响应的代理连接必须全部关闭');
        assert.equal(claudeHoldReleasedCount, 0, '冲突前启动的 Google 探测不得等到延迟释放后写回');
        assert.ok(claudeHoldClosedBeforeReleaseCount >= 1, '冲突前启动的 Google 探测连接应在释放前被取消');
        const conflictSnap = agConflictEngine.getSnapshot();
        assert.equal(conflictSnap.antigravityState.nodeProbe, null, '端口冲突后不得保留或写回旧出口样本');
        assert.match(conflictSnap.antigravityState.nodeProbeError || '', /监听归属/);

        // 释放端口抢占并恢复正常上游路由，验证端口恢复后自动重测确认出口
        holdClaudePrimary = false;
        await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
        await new Promise<void>((resolve) => agConflictHijacker.close(() => resolve()));
        assert.equal(await subService.channels.antigravity.recoverListenerIfNeeded(), 'rebound');
        const recoveryProbeDeadline = Date.now() + 8000;
        while (
          (!agConflictEngine.getSnapshot().antigravityState.nodeProbe?.googleCountryCode ||
            agConflictEngine.getSnapshot().antigravityState.nodeProbeError !== null) &&
          Date.now() < recoveryProbeDeadline
        ) {
          await delay(50);
        }
        const recoveredAgSnap = agConflictEngine.getSnapshot();
        assert.equal(recoveredAgSnap.antigravityState.nodeProbe?.countryCode, proxyCountry);
        assert.equal(recoveredAgSnap.antigravityState.nodeProbe?.googleCountryCode, proxyCountry);
        assert.equal(recoveredAgSnap.antigravityState.nodeProbeError, null);

        // (0d) 验证端口重新绑定成功但上游转发仍不可达时，不得清除 verificationError，保持拦截 Antigravity 启动直至真实转发恢复
        const agRejectHosts = BUILTIN_TRACE_ENDPOINTS.map((ep) => new URL(ep.url).hostname);
        await reloadKernelConfig(
          upLease.endpoint,
          makeUpstreamConfig(agRejectHosts.map((h) => `DOMAIN,${h},REJECT`))
        );
        await mihomoRequest(agSubLease.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
        const agRebindDropDeadline = Date.now() + 3000;
        while ((await isLocalPortListening(agLivePort)) && Date.now() < agRebindDropDeadline) {
          await delay(30);
        }
        assert.equal(await isLocalPortListening(agLivePort), false, '(0d) PATCH mixed-port: 0 后应已关闭 agLivePort');
        assert.equal(await subService.channels.antigravity.recoverListenerIfNeeded(), 'rebound');
        assert.equal(subService.channels.antigravity.getState().phase, 'ready');
        assert.match(
          subService.channels.antigravity.getState().verificationError || '',
          /专属代理请求失败/,
          '重新绑定端口但上游仍不可达时不得清除 verificationError'
        );
        assert.equal(
          agConflictEngine.getSnapshot().antigravityState.canLaunch,
          false,
          '转发校验未通过时必须禁止启动 Antigravity'
        );
        await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
        const agRecoveredForwardDeadline = Date.now() + 8000;
        while (
          subService.channels.antigravity.getState().verificationError !== null &&
          Date.now() < agRecoveredForwardDeadline
        ) {
          await delay(100);
        }
        assert.equal(
          subService.channels.antigravity.getState().verificationError,
          null,
          '上游恢复后后台健康检查应重新验证转发并清除 verificationError'
        );
      } finally {
        holdClaudePrimary = false;
        agConflictEngine.stop();
        if (agConflictHijacker.listening) {
          await new Promise<void>((resolve) => agConflictHijacker.close(() => resolve()));
        }
      }
    } finally {
      for (const sock of heldDropClients) sock.destroy();
      heldDropClients.clear();
      subStore.update({
        antigravityClashNode: null,
        antigravityClashProfileUid: null,
        antigravityClashProfileName: null,
      });
      await subService.channels.antigravity.select(null, agLivePort);
      await bindSubNode('五源标准节点');
    }

    // (1) 五源标准节点：慢连接错峰对冲、单源旁路多主域共识通过、全常规源失败保留 Claude IP 漂移检测、单源异常+其余断流 Fail-Closed、异国源先回+Claude校验失败不误判 mismatch、多源跨国分流双序确认与告警同源配对
    // (1a) 错峰对冲绕过首连卡死
    relayMode = 'stall-first';
    relayHits = 0;
    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig(['DOMAIN,claude.ai,test-delay']));
    const hedgeStart = Date.now();
    const hedgedSnap = await subEngine.probeClaudeNodeNow('验证 Claude 慢连接错峰对冲', true);
    const hedgeElapsed = Date.now() - hedgeStart;
    const hedgedProbe = hedgedSnap.claudeState.nodeProbe;
    assert.ok(
      hedgedProbe && getTargetServiceVerificationError(hedgedProbe, 'claude') === null,
      `错峰对冲应绕过首连卡死并通过校验: err=${hedgedSnap.claudeState.nodeProbeError} verify=${getTargetServiceVerificationError(hedgedProbe, 'claude')}`
    );
    assert.ok(relayHits >= 2, '首连卡死超过 2.8s 应触发错峰对冲连接');
    const claudeOffsetFromStart = hedgedProbe.claudeTraceCheckedAt! - hedgeStart;
    assert.ok(
      claudeOffsetFromStart >= 2700 && claudeOffsetFromStart < 9500,
      `对冲连接应在 2.8s 后触发并在首连 10s 断连前完成 (total=${hedgeElapsed}ms, claudeOffset=${claudeOffsetFromStart}ms, hits=${relayHits})`
    );

    // (1a-1) 校验 Claude trace 响应内容后再取消备用请求，并保留可用于判定 IP 漂移的部分结果
    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    try {
      proxyClaudeTraceMode = 'bad-first-then-ok';
      proxyClaudeTraceHits = 0;
      const badFirstSnap = await subEngine.probeClaudeNodeNow('首路 HTTP 200 无效正文不得取消有效对冲响应', true);
      const badFirstProbe = badFirstSnap.claudeState.nodeProbe;
      assert.ok(
        badFirstProbe && getTargetServiceVerificationError(badFirstProbe, 'claude') === null,
        `首路返回无效 200 正文时备用对冲请求应继续完成校验: err=${badFirstSnap.claudeState.nodeProbeError} verify=${getTargetServiceVerificationError(badFirstProbe, 'claude')}`
      );
      assert.ok(proxyClaudeTraceHits >= 2, '首路正文无效时必须继续执行备用对冲请求');
      assert.equal(badFirstProbe.claudeTraceIp, proxyExitIp);

      proxyClaudeTraceMode = 'loc-xx-then-fail';
      proxyClaudeTraceHits = 0;
      const partialPreservedSnap = await subEngine.probeClaudeNodeNow('两路均无完整结果时保留含 IP 的部分结果', true);
      const partialPreservedProbe = partialPreservedSnap.claudeState.nodeProbe;
      assert.ok(partialPreservedProbe, '首路返回 loc=XX 且含有效 IP、次路 502 时应保留部分结果');
      assert.ok(proxyClaudeTraceHits >= 2, '部分结果后仍应尝试对冲请求以争取完整响应');
      assert.equal(partialPreservedProbe.claudeTraceIp, expectedForeignIp);
      assert.equal(partialPreservedProbe.claudeTraceCountryCode, expectedForeignCountry);
      assert.match(partialPreservedProbe.claudeTraceError || '', /未解析到有效国家\/地区代码/);
      const partialDriftCheck = evaluateClaudeNodeProbeSafety(partialPreservedProbe, {
        claudeRunning: true,
        claudeExternalBaselinePending: false,
        claudeLockExitIp: true,
        sessionInitialIp: proxyExitIp,
      });
      assert.equal(
        partialDriftCheck?.alertType,
        'ip-change',
        '保留的部分 trace IP 必须仍能触发运行期 IP 漂移熔断'
      );

      // (1a-1b) 锁定 IP 会话中首路返回漂移新 IP + loc=XX、对冲路可返回旧 IP + 完整地区时，
      //         必须立即保留首路已确认的 IP 漂移，严禁被后续对冲响应覆盖吞掉。
      const driftGuardFields = subEngine as unknown as {
        claudeSessionInitialIp: string | null;
        winLocale: WindowsLocaleState;
      };
      const savedWinLocale = { ...driftGuardFields.winLocale };
      try {
        const matchedTz = resolveWindowsTimeZoneForCountry(proxyCountry).windowsTimeZoneId || savedWinLocale.timeZoneId;
        driftGuardFields.winLocale = {
          timeZoneId: matchedTz,
          timeZoneDisplayName: matchedTz,
          regionCode: proxyCountry,
          regionName: proxyCountry,
        };
        subStore.update({ claudeLockExitIp: true, claudeExclusiveGuard: false, killProcessesEnabled: false });
        driftGuardFields.claudeSessionInitialIp = proxyExitIp;
        proxyClaudeTraceMode = 'drift-loc-xx-then-old-ok';
        proxyClaudeTraceHits = 0;
        const confirmedDriftSnap = await subEngine.probeClaudeNodeNow(
          '首路部分结果已确认 IP 漂移时不得被对冲旧 IP 覆盖',
          true
        );
        assert.equal(
          confirmedDriftSnap.claudeState.nodeProbe?.claudeTraceIp,
          expectedProxyDriftedIp,
          '首路已确认漂移的新 IP 必须保留，不得被对冲路返回的旧 IP 覆盖'
        );
        assert.equal(proxyClaudeTraceHits, 1, '首路部分结果已确认违规时应立即结束，无需再采信备用请求');
        const driftSafetyAfterPartial = subEngine.evaluateClaudeSafety(true);
        assert.equal(driftSafetyAfterPartial.alertType, 'ip-change');
        assert.equal(driftSafetyAfterPartial.expectedIp, proxyExitIp);
        assert.equal(driftSafetyAfterPartial.actualIp, expectedProxyDriftedIp);
      } finally {
        driftGuardFields.claudeSessionInitialIp = null;
        driftGuardFields.winLocale = savedWinLocale;
      }
    } finally {
      proxyClaudeTraceMode = 'normal';
      proxyClaudeTraceHits = 0;
    }

    // (1a-2) 全部常规探测源均超时/阻断，但 claude.ai 可达：
    //        (i) 必须在 15s 单轮时限内完成（并发启动）；
    //        (ii) 保留 claudeTraceIp 与 claudeTraceCountryCode，使运行期锁定 IP 漂移仍可立即触发 ip-change；
    //        (iii) 未漂移时归入 verification-unavailable 且阻止新启动（Fail-Closed）。
    const allGeneralHosts = BUILTIN_TRACE_ENDPOINTS.map((ep) => new URL(ep.url).hostname);
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig(allGeneralHosts.map((h) => `DOMAIN,${h},REJECT-DROP`))
    );
    const allGeneralFailStart = Date.now();
    const allGeneralFailSnap = await subEngine.probeClaudeNodeNow('全部常规源失败时保留 Claude IP 漂移检测', true);
    const allGeneralFailElapsed = Date.now() - allGeneralFailStart;
    assert.ok(allGeneralFailElapsed < 15000, `全常规源失败时并发探测必须在 15s 总期限内完成 (实际 ${allGeneralFailElapsed}ms)`);
    const claudeOnlyProbe = allGeneralFailSnap.claudeState.nodeProbe;
    assert.ok(claudeOnlyProbe, '全部常规源失败但 Claude 可达时仍须保留 Claude 实测样本');
    assert.equal(allGeneralFailSnap.claudeState.canLaunch, false, '全部常规源失败时必须 Fail-Closed 阻断新启动');
    assert.ok(claudeOnlyProbe.claudeTraceIp, '必须取得实时 Claude 出口 IP');
    assert.equal(claudeOnlyProbe.claudeTraceCountryCode, proxyCountry);
    assert.match(claudeOnlyProbe.claudeTraceError || '', /常规出口探测均不可达/);
    assert.equal(isProbeRegionMismatched(claudeOnlyProbe), false);
    const sameIpCheck = evaluateClaudeNodeProbeSafety(claudeOnlyProbe, {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: claudeOnlyProbe.claudeTraceIp,
    });
    assert.equal(sameIpCheck?.alertType, 'verification-unavailable');
    const driftedIpCheck = evaluateClaudeNodeProbeSafety(claudeOnlyProbe, {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: '198.51.100.77',
    });
    assert.equal(driftedIpCheck?.alertType, 'ip-change', '全常规源失败但 Claude 出口 IP 已变更时必须立即触发 ip-change');
    assert.equal(driftedIpCheck?.actualIp, claudeOnlyProbe.claudeTraceIp);
    const driftedAlertFields = resolveAlertActualMismatchFields({
      isClaudeSource: true,
      alertType: 'ip-change',
      expectedCode: proxyCountry,
      explicitActualIp: claudeOnlyProbe.claudeTraceIp,
      refProbe: claudeOnlyProbe,
    });
    assert.equal(driftedAlertFields.actualCode, proxyCountry, 'Claude IP 具备有效离线归属时告警应显示准确国家代码而非 UNKNOWN');

    // (1a-3) 常规样本缺失带有 claudeTraceError 但已确认 Claude 出口 IP 漂移时，即使此时端口可恢复重绑也不得进入下一轮丢弃本次漂移
    const subDriftLease = readLeaseEndpoint(path.join(liveRoot, 'sub-kernels', 'claude'));
    let droppedPortAfterClaudeDrift = false;
    let driftReadyCount = 0;
    const onDriftReady = () => driftReadyCount++;
    subService.channels.claude.on('ready', onDriftReady);
    const engineSessionFields = subEngine as unknown as {
      claudeSessionInitialIp: string | null;
      winLocale: WindowsLocaleState;
    };
    const prevWinLocale = { ...engineSessionFields.winLocale };
    beforePassTunnelReady = async (host) => {
      if (droppedPortAfterClaudeDrift || host !== 'claude.ai') return;
      droppedPortAfterClaudeDrift = true;
      await delay(80);
      await mihomoRequest(subDriftLease.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
      const dropDeadline = Date.now() + 2000;
      while ((await isLocalPortListening(subPort)) && Date.now() < dropDeadline) {
        await delay(30);
      }
      await reloadKernelConfig(
        upLease.endpoint,
        makeUpstreamConfig(['DOMAIN,claude.ai,REJECT', ...allGeneralHosts.map((h) => `DOMAIN,${h},REJECT-DROP`)])
      );
    };
    try {
      const matchedTz = resolveWindowsTimeZoneForCountry(proxyCountry).windowsTimeZoneId || prevWinLocale.timeZoneId;
      engineSessionFields.winLocale = {
        timeZoneId: matchedTz,
        timeZoneDisplayName: matchedTz,
        regionCode: proxyCountry,
        regionName: proxyCountry,
      };
      // 严禁设置 claudeRunning = true，仅注入会话初始锁定基线 IP（未 start 实例即使收到 lost 亦绝不触发任何宿主进程终止）
      subStore.update({ claudeLockExitIp: true, claudeExclusiveGuard: false, killProcessesEnabled: false });
      engineSessionFields.claudeSessionInitialIp = '198.51.100.77';
      await reloadKernelConfig(
        upLease.endpoint,
        makeUpstreamConfig([
          'DOMAIN,claude.ai,test-counted-pass',
          ...allGeneralHosts.map((h) => `DOMAIN,${h},REJECT-DROP`),
        ])
      );
      const driftNoRetrySnap = await subEngine.probeClaudeNodeNow(
        '常规源缺失且端口可重绑时不得丢弃已确认 IP 漂移',
        true
      );
      assert.equal(droppedPortAfterClaudeDrift, true, '应在 Claude 隧道建立后先行关闭本地专属监听端口');
      assert.equal(await isLocalPortListening(subPort), false, '已确认 IP 漂移时不得为常规样本缺失触发端口重绑进入下一轮');
      assert.equal(driftReadyCount, 0, '已确认 IP 漂移时不得重绑重试丢弃本轮样本');
      const observedDriftedIp = driftNoRetrySnap.claudeState.nodeProbe?.claudeTraceIp;
      assert.ok(
        observedDriftedIp && observedDriftedIp !== '198.51.100.77',
        '不得因常规样本缺失触发端口重绑重测而覆盖本轮已确认的漂移 IP'
      );
      const liveRuntimeSafety = subEngine.evaluateClaudeSafety(true);
      assert.equal(liveRuntimeSafety.alertType, 'ip-change', '本轮已确认漂移 IP 必须直接触发 ip-change 判定');
      assert.equal(liveRuntimeSafety.expectedIp, '198.51.100.77');
      assert.equal(liveRuntimeSafety.actualIp, observedDriftedIp);
    } finally {
      beforePassTunnelReady = null;
      subService.channels.claude.off('ready', onDriftReady);
      engineSessionFields.claudeSessionInitialIp = null;
      engineSessionFields.winLocale = prevWinLocale;
      await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
      assert.equal(await subService.channels.claude.recoverListenerIfNeeded(), 'rebound');
    }

    // (1a-4) 全重合零常规源链式节点（五个常规源均被传输层域名过滤），但 claude.ai/cdn-cgi/trace 仍可达：
    //        (i) 对新启动保持 Fail-Closed（canLaunch === false）；
    //        (ii) 仍必须执行独立 trace 检查，确认实际出口国家与系统区域不符时触发 locale-mismatch、IP 变更时触发 ip-change。
    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    await bindSubNode('全重合零源可达节点');
    assert.equal(
      selectProbeEndpointsForTransportHosts(
        BUILTIN_TRACE_ENDPOINTS,
        subService.channels.claude.getBoundTransportHosts()
      ).length,
      0,
      '全重合零源可达节点的常规探测池必须为空'
    );
    try {
      const zeroReachableSnap = await subEngine.probeClaudeNodeNow('零常规源链式节点仍检 Claude 实际出口', true);
      const zeroReachableProbe = zeroReachableSnap.claudeState.nodeProbe;
      assert.equal(zeroReachableSnap.claudeState.canLaunch, false, '零常规源节点对新启动必须维持 Fail-Closed 阻断');
      assert.ok(zeroReachableProbe, '零常规源节点在 trace 可达时仍须返回 Claude 实际出口样本');
      assert.equal(zeroReachableProbe.countryCode, 'UNKNOWN');
      assert.equal(zeroReachableProbe.claudeTraceIp, proxyExitIp);
      assert.equal(zeroReachableProbe.claudeTraceCountryCode, proxyCountry);
      assert.match(zeroReachableProbe.claudeTraceError || '', /传输层域名重合/);

      const foreignTz = resolveWindowsTimeZoneForCountry(expectedForeignCountry).windowsTimeZoneId || prevWinLocale.timeZoneId;
      engineSessionFields.winLocale = {
        timeZoneId: foreignTz,
        timeZoneDisplayName: foreignTz,
        regionCode: expectedForeignCountry,
        regionName: expectedForeignCountry,
      };
      const zeroLocaleMismatch = subEngine.evaluateClaudeSafety(false);
      assert.equal(
        zeroLocaleMismatch.alertType,
        'locale-mismatch',
        `零常规源节点 trace 确认实际出口 (${proxyCountry}) 与系统区域 (${expectedForeignCountry}) 不符时必须触发 locale-mismatch，实际：${zeroLocaleMismatch.alertType} (${zeroLocaleMismatch.reason})`
      );

      const matchedTz = resolveWindowsTimeZoneForCountry(proxyCountry).windowsTimeZoneId || prevWinLocale.timeZoneId;
      engineSessionFields.winLocale = {
        timeZoneId: matchedTz,
        timeZoneDisplayName: matchedTz,
        regionCode: proxyCountry,
        regionName: proxyCountry,
      };
      subStore.update({ claudeLockExitIp: true, claudeExclusiveGuard: false, killProcessesEnabled: false });
      engineSessionFields.claudeSessionInitialIp = '198.51.100.77';
      const zeroIpDrift = subEngine.evaluateClaudeSafety(false);
      assert.equal(zeroIpDrift.alertType, 'ip-change', '零常规源节点 trace 确认出口 IP 漂移时必须触发 ip-change');
      assert.equal(zeroIpDrift.actualIp, proxyExitIp);

      engineSessionFields.claudeSessionInitialIp = proxyExitIp;
      const zeroMatchedSameIp = subEngine.evaluateClaudeSafety(false);
      assert.equal(zeroMatchedSameIp.alertType, 'verification-unavailable');
    } finally {
      engineSessionFields.claudeSessionInitialIp = null;
      engineSessionFields.winLocale = prevWinLocale;
      await bindSubNode('五源标准节点');
    }

    // (1b) 单探测源被旁路至异国，其余 >=2 个独立主域与 Claude 一致 -> 共识通过，不采信旁路源
    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([`DOMAIN,${direct1.host},${foreignTarget}`]));
    const singleOutlierSnap = await subEngine.probeClaudeNodeNow('验证单源旁路多主域共识', true);
    const singleOutlierProbe = singleOutlierSnap.claudeState.nodeProbe;
    assert.ok(singleOutlierProbe, '单源旁路其余一致时应共识通过');
    assert.equal(getTargetServiceVerificationError(singleOutlierProbe, 'claude'), null);
    assert.equal(isProbeRegionMismatched(singleOutlierProbe), false);
    assert.equal(singleOutlierProbe.countryCode, proxyCountry, '被旁路的单点异国源不得被采信为最终基准');
    assert.equal(geo.lookupOfflineStrict(singleOutlierProbe.ip).countryCode, proxyCountry);

    // (1c) 单探测源异常且其余复核源全部拥塞断流 -> Fail-Closed 归为常规出口复核未完成
    const otherHosts = BUILTIN_TRACE_ENDPOINTS.filter(
      (ep) => ep.registrableDomain !== direct1.endpoint.registrableDomain
    ).map((ep) => new URL(ep.url).hostname);
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([`DOMAIN,${direct1.host},${foreignTarget}`, ...otherHosts.map((h) => `DOMAIN,${h},REJECT-DROP`)])
    );
    const inconclusiveSnap = await subEngine.probeClaudeNodeNow('单源异常其余源断流', true);
    assert.equal(inconclusiveSnap.claudeState.nodeProbe, null);
    assert.equal(inconclusiveSnap.claudeState.canLaunch, false);
    assert.match(inconclusiveSnap.claudeState.nodeProbeError || '', /常规出口复核未完成/);

    // (1d) 异国常规源先回 + Claude 校验失败 -> claudeTraceError 存在、绝不判为 mismatch
    relayMode = 'delay-target-short';
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([
        `DOMAIN,${direct1.host},${foreignTarget}`,
        ...otherHosts.map((h) => `DOMAIN,${h},test-delay`),
        'DOMAIN,claude.ai,REJECT',
      ])
    );
    const traceErrSnap = await subEngine.probeClaudeNodeNow('异国源先回叠加 Claude 失败', true);
    const traceErrProbe = traceErrSnap.claudeState.nodeProbe;
    assert.ok(traceErrProbe?.claudeTraceError, '应记录 Claude 校验失败');
    assert.equal(traceErrProbe.countryCode, direct1.countryCode);
    assert.equal(isProbeRegionMismatched(traceErrProbe), false, '存在 claudeTraceError 时不得判为 mismatch');
    const traceErrSafety = evaluateClaudeNodeProbeSafety(traceErrProbe, {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: proxyExitIp,
    });
    assert.equal(traceErrSafety?.alertType, 'verification-unavailable');

    // (1d-2) 单异国旁路源先回 + 同国 Claude 出口 IP 漂移提前中止 -> 必须精准判为 ip-change，绝不凭单源伪造跨国分流 mismatch
    try {
      const matchedTz = resolveWindowsTimeZoneForCountry(proxyCountry).windowsTimeZoneId || prevWinLocale.timeZoneId;
      engineSessionFields.winLocale = {
        timeZoneId: matchedTz,
        timeZoneDisplayName: matchedTz,
        regionCode: proxyCountry,
        regionName: proxyCountry,
      };
      subStore.update({ claudeLockExitIp: true, claudeExclusiveGuard: false, killProcessesEnabled: false });
      engineSessionFields.claudeSessionInitialIp = '198.51.100.88';
      await reloadKernelConfig(
        upLease.endpoint,
        makeUpstreamConfig([
          `DOMAIN,${direct1.host},${foreignTarget}`,
          ...otherHosts.map((h) => `DOMAIN,${h},test-delay`),
        ])
      );
      const earlyDriftSnap = await subEngine.probeClaudeNodeNow('单源旁路叠加同国 IP 漂移提前中止', true);
      const earlyDriftProbe = earlyDriftSnap.claudeState.nodeProbe;
      assert.ok(earlyDriftProbe, '应返回含 Claude 漂移 IP 的探测结果');
      assert.equal(isProbeRegionMismatched(earlyDriftProbe), false, '未达 2 源共识的单点异国旁路源不得伪造跨国 mismatch');
      assert.notEqual(earlyDriftProbe.countryCode, direct1.countryCode, '提前中止时不得采信单点旁路源国家代码');
      const earlyDriftCheck = evaluateClaudeNodeProbeSafety(earlyDriftProbe, {
        claudeRunning: true,
        claudeExternalBaselinePending: false,
        claudeLockExitIp: true,
        sessionInitialIp: '198.51.100.88',
      });
      assert.equal(earlyDriftCheck?.alertType, 'ip-change', '同国 IP 轮换必须触发 ip-change 而非跨国 mismatch');
    } finally {
      engineSessionFields.claudeSessionInitialIp = null;
      engineSessionFields.winLocale = prevWinLocale;
    }

    // (1e) 跨国分流双序验证 + 告警同源配对校验
    const proxySideHosts = proxySideEndpoints.map((ep) => new URL(ep.url).hostname);
    relayMode = 'delay-target-short';
    // 顺序一：代理国先回，两个异国源均延迟 2.4s 返回
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([`DOMAIN,${direct1.host},test-direct-delay`, `DOMAIN,${direct2.host},test-direct-delay`])
    );
    const order1Start = Date.now();
    const order1Snap = await subEngine.probeClaudeNodeNow('跨国分流顺序一', true);
    const order1Elapsed = Date.now() - order1Start;
    assert.ok(order1Elapsed >= 2100, `代理国先回时仍须等待剩余可能凑够 2 异议的慢速源 (实际 ${order1Elapsed}ms)`);
    const order1Probe = order1Snap.claudeState.nodeProbe!;
    assert.ok(order1Probe?.regionMismatchDetail);
    assert.equal(isProbeRegionMismatched(order1Probe), true);
    const order1Safety = evaluateClaudeNodeProbeSafety(order1Probe, {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      sessionInitialIp: order1Probe.claudeTraceIp,
    });
    assert.equal(order1Safety?.alertType, 'mismatch');
    const order1Alert = resolveAlertActualMismatchFields({
      isClaudeSource: true,
      alertType: 'mismatch',
      expectedCode: proxyCountry,
      refProbe: order1Probe,
    });
    assert.equal(order1Alert.actualCode, direct1.countryCode);
    assert.ok(order1Alert.actualIp && order1Alert.actualIp !== order1Probe.claudeTraceIp);
    assert.equal(geo.lookupOfflineStrict(order1Alert.actualIp).countryCode, order1Alert.actualCode);

    // 顺序二：两个异国源先回，代理国源均延迟 2.4s 返回
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([
        `DOMAIN,${direct1.host},${foreignTarget}`,
        `DOMAIN,${direct2.host},${foreignTarget}`,
        ...proxySideHosts.map((h) => `DOMAIN,${h},test-delay`),
      ])
    );
    const order2Snap = await subEngine.probeClaudeNodeNow('跨国分流顺序二', true);
    const order2Probe = order2Snap.claudeState.nodeProbe!;
    assert.ok(order2Probe?.regionMismatchDetail);
    assert.equal(isProbeRegionMismatched(order2Probe), true);
    const order2Alert = resolveAlertActualMismatchFields({
      isClaudeSource: true,
      alertType: 'mismatch',
      expectedCode: proxyCountry,
      refProbe: order2Probe,
    });
    assert.equal(order2Alert.actualCode, direct1.countryCode);
    assert.ok(order2Alert.actualIp && order2Alert.actualIp !== order2Probe.claudeTraceIp);
    assert.equal(geo.lookupOfflineStrict(order2Alert.actualIp).countryCode, order2Alert.actualCode);

    // (1f) 基于真实私有内核与本地转发探测生成时区同步前后的 Claude 状态，验证待复核保留/异国终止/未校验阻断策略
    const localeStore = new ConfigStore();
    localeStore.update({
      selectedClashNode: '五源标准节点',
      selectedClashProfileUid: 'reduced-prof',
      selectedClashProfileName: '受限源测试订阅',
      dedicatedProxyPort: subPort,
      claudeExclusiveGuard: false,
      killProcessesEnabled: false,
    });
    const localeEngine = new ProbeEngine(localeStore, geo, new ClashMonitor(subVergeDir), subService);
    const makeForeignDefaultUpstreamConfig = (rules: string[]) =>
      yaml.dump({
        ...upBaseCfg,
        hosts: { ...upHosts, ...extraForeignHosts },
        listeners: [
          { name: 'test-base-upstream', type: 'mixed', port: baseUpstreamPort, listen: '127.0.0.1', proxy: outboundGroup },
          { name: 'test-direct-upstream', type: 'mixed', port: directUpstreamPort, listen: '127.0.0.1', proxy: foreignTarget },
        ],
        proxies: [
          ...upProxies,
          ...extraForeignProxies,
          { name: 'test-delay', type: 'http', server: '127.0.0.1', port: relayPort },
          { name: 'test-direct-delay', type: 'http', server: '127.0.0.1', port: directDelayPort },
          { name: 'test-counted-pass', type: 'http', server: '127.0.0.1', port: countedPassPort },
          { name: 'test-hold-drop', type: 'http', server: '127.0.0.1', port: holdBeforeTlsPort },
          { name: 'test-claude-hold', type: 'http', server: '127.0.0.1', port: claudeHoldPort },
        ],
        rules: [...rules, `MATCH,${foreignTarget}`],
      });
    try {
      // (1f-1) 尚未完成过任何有效校验、仅常规回显成功而 trace 失败 -> 禁止用于同步且切时区必须终止
      await reloadKernelConfig(upLease.endpoint, makeForeignDefaultUpstreamConfig(['DOMAIN,claude.ai,REJECT']));
      const unverifiedSnap = await localeEngine.probeClaudeNodeNow('未校验节点 trace 失败', true);
      assert.ok(unverifiedSnap.claudeState.nodeProbe?.claudeTraceError);
      const blockedLocaleSync = localeEngine.resolveLocaleSyncTarget('claude');
      assert.equal(blockedLocaleSync.ok, false, '未通过真实校验的节点不得触发系统时区同步');
      assert.match(blockedLocaleSync.message, /校验未通过/);
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('US', 'Eastern Standard Time'),
        true,
        '从未通过真实校验的节点在切换系统时区前必须 Fail-Closed 终止 Claude'
      );

      // (1f-2) 真实探测通过 US 校验（自然写入 claudeLastVerifiedRegion），随后 trace 暂时不可达
      await reloadKernelConfig(upLease.endpoint, makeForeignDefaultUpstreamConfig([]));
      const verifiedUsSnap = await localeEngine.probeClaudeNodeNow('真实探测确立 US 基线', true);
      assert.equal(verifiedUsSnap.claudeState.proxyCountryCode, expectedForeignCountry);
      assert.equal(getTargetServiceVerificationError(verifiedUsSnap.claudeState.nodeProbe, 'claude'), null);
      const allowedLocaleSync = localeEngine.resolveLocaleSyncTarget('claude');
      assert.equal(allowedLocaleSync.ok, true);
      if (allowedLocaleSync.ok) {
        assert.equal(allowedLocaleSync.targetCode, expectedForeignCountry);
      }

      await reloadKernelConfig(upLease.endpoint, makeForeignDefaultUpstreamConfig(['DOMAIN,claude.ai,REJECT']));
      const pendingTraceSnap = await localeEngine.probeClaudeNodeNow('US 基线确立后 trace 暂不可达', true);
      assert.ok(pendingTraceSnap.claudeState.nodeProbe?.claudeTraceError);
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('US', 'Eastern Standard Time'),
        false,
        '真实确立 US 基线后若仅 trace 暂不可达，切往同属 US 的另一时区必须保留待复核会话'
      );
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('JP', 'Tokyo Standard Time'),
        true,
        '目标时区与真实确立的 US 基线不符时必须终止待复核 Claude 会话'
      );

      // (1f-3) 全源暂时不可达导致真实探测清空 nodeProbe -> 仍按上次真实确认地区判定
      await reloadKernelConfig(
        upLease.endpoint,
        makeForeignDefaultUpstreamConfig(['DOMAIN,claude.ai,REJECT', ...allGeneralHosts.map((h) => `DOMAIN,${h},REJECT`)])
      );
      const allFailPendingSnap = await localeEngine.probeClaudeNodeNow('US 基线确立后全源暂不可达', true);
      assert.equal(allFailPendingSnap.claudeState.nodeProbe, null);
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('US', 'Central Standard Time'),
        false,
        '全源暂不可达但上次真实确认地区仍匹配目标 US 时区时应保留待复核会话'
      );
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('GB', 'GMT Standard Time'),
        true,
        '全源暂不可达且目标时区与上次真实确认地区不符时必须终止 Claude'
      );

      // (1f-4) trace 返回 loc=XX 但离线 mmdb 确认实际出口为异国 (JP) -> 必须终止
      foreignClaudeTraceMode = 'loc-xx-proxy-ip';
      await reloadKernelConfig(upLease.endpoint, makeForeignDefaultUpstreamConfig([]));
      const locXxForeignSnap = await localeEngine.probeClaudeNodeNow('trace 返回 loc=XX 且离线归属为 JP', true);
      assert.equal(locXxForeignSnap.claudeState.nodeProbe?.claudeTraceCountryCode, expectedProxyCountry);
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('US', 'Eastern Standard Time'),
        true,
        'trace 离线归属已确认不匹配目标 US 时区时必须终止 Claude'
      );
      foreignClaudeTraceMode = 'normal';

      // (1f-5) 真实跨国分流（两个常规源指向 JP、claude.ai 仍在 US）-> 已确认地区异常必须终止
      await reloadKernelConfig(
        upLease.endpoint,
        makeForeignDefaultUpstreamConfig([
          `DOMAIN,${direct1.host},${outboundGroup}`,
          `DOMAIN,${direct2.host},${outboundGroup}`,
        ])
      );
      const realSplitSnap = await localeEngine.probeClaudeNodeNow('真实探测触发跨国分流', true);
      assert.equal(isProbeRegionMismatched(realSplitSnap.claudeState.nodeProbe), true);
      assert.equal(
        localeEngine.shouldStopClaudeBeforeLocaleChange('US', 'Eastern Standard Time'),
        true,
        '真实探测确认跨国分流时即使目标时区仍为 US 也必须终止 Claude'
      );
    } finally {
      foreignClaudeTraceMode = 'normal';
      localeEngine.stop();
      await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    }

    // (2) 双源受限节点（真实 HTTP CONNECT + headers.Host + dialer-proxy 链）的双序 1:1 冲突校验
    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    observedHopTargets.clear();
    observedHopHosts.clear();
    await bindSubNode('双源受限节点');
    assert.equal(
      selectProbeEndpointsForTransportHosts(
        BUILTIN_TRACE_ENDPOINTS,
        subService.channels.claude.getBoundTransportHosts()
      ).length,
      2
    );
    const twoOk = await subEngine.probeClaudeNodeNow('双源受限节点正常校验', true);
    assert.ok(twoOk.claudeState.nodeProbe && getTargetServiceVerificationError(twoOk.claudeState.nodeProbe, 'claude') === null);
    assert.equal(observedHopTargets.has(`hop.${excludedThreeDomains[0]}`), true);
    assert.equal(observedHopHosts.has(`edge.${excludedThreeDomains[1]}`), true);

    const keptProxyHost = new URL(proxySideEndpoints[0].url).hostname;
    relayMode = 'delay-target-short';
    // 双源顺序一：代理国先回，异国延迟 2.4s
    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([`DOMAIN,${direct1.host},test-direct-delay`]));
    const tie1Start = Date.now();
    const tie1Snap = await subEngine.probeClaudeNodeNow('双源 1:1 冲突顺序一', true);
    assert.ok(Date.now() - tie1Start >= 2100);
    assert.equal(tie1Snap.claudeState.nodeProbe, null);
    assert.match(tie1Snap.claudeState.nodeProbeError || '', /常规出口复核未完成/);

    // 双源顺序二：异国先回，代理国延迟 2.4s
    await reloadKernelConfig(
      upLease.endpoint,
      makeUpstreamConfig([`DOMAIN,${direct1.host},${foreignTarget}`, `DOMAIN,${keptProxyHost},test-delay`])
    );
    const tie2Start = Date.now();
    const tie2Snap = await subEngine.probeClaudeNodeNow('双源 1:1 冲突顺序二', true);
    assert.ok(Date.now() - tie2Start >= 2100);
    assert.equal(tie2Snap.claudeState.nodeProbe, null);
    assert.match(tie2Snap.claudeState.nodeProbeError || '', /常规出口复核未完成/);

    // (3) 单源受限节点：Claude 主连接存活期间本地端口关闭，错峰备用请求 ECONNREFUSED 立即中断主连接并触发私有内核重绑
    await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    await bindSubNode('单源受限节点');
    assert.equal(
      selectProbeEndpointsForTransportHosts(
        BUILTIN_TRACE_ENDPOINTS,
        subService.channels.claude.getBoundTransportHosts()
      ).length,
      1
    );
    const subOneLease = readLeaseEndpoint(path.join(liveRoot, 'sub-kernels', 'claude'));
    claudeHoldReleasedCount = 0;
    claudeHoldClosedBeforeReleaseCount = 0;
    holdClaudePrimary = true;
    let preHedgeLookups = 0;
    let triggeredHedgeRefusal = false;
    let primaryStillOpenAfterClose = false;
    let hedgeReadyCount = 0;
    let hedgeFaultTask: Promise<void> = Promise.resolve();
    const onHedgeReady = () => hedgeReadyCount++;
    subService.channels.claude.on('ready', onHedgeReady);
    const maybeTriggerHedgeRefusal = () => {
      if (triggeredHedgeRefusal || claudeHoldClients.size === 0 || preHedgeLookups < 1) return;
      triggeredHedgeRefusal = true;
      holdClaudePrimary = false;
      hedgeFaultTask = (async () => {
        await delay(40);
        await mihomoRequest(subOneLease.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
        await delay(150);
        primaryStillOpenAfterClose = claudeHoldClients.size > 0;
      })();
      hedgeFaultTask.catch(() => undefined);
    };
    onClaudeHoldReady = maybeTriggerHedgeRefusal;
    onSubGeoLookup = (code) => {
      if (triggeredHedgeRefusal) return;
      if (code === proxyCountry) preHedgeLookups++;
      maybeTriggerHedgeRefusal();
    };
    try {
      await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig(['DOMAIN,claude.ai,test-claude-hold']));
      const hedgeRefusedSnap = await subEngine.probeClaudeNodeNow('Claude 对冲端口拒绝重绑', true);
      await hedgeFaultTask;
      assert.equal(triggeredHedgeRefusal, true, '应触发 Claude 对冲端口关闭故障');
      assert.equal(primaryStillOpenAfterClose, true, '关闭监听端口后已建立的 Claude 主连接应保持存活');
      assert.equal(claudeHoldReleasedCount, 0, '错峰备用请求 ECONNREFUSED 后必须立即中断挂起的主连接');
      assert.ok(claudeHoldClosedBeforeReleaseCount >= 1, '被中断的主连接应在释放前关闭');
      assert.equal(hedgeReadyCount, 1, 'Claude 对冲端口拒绝必须触发私有内核重绑');
      assert.equal(await isLocalPortListening(subPort), true, '重绑后专属端口应恢复监听');
      assert.ok(
        hedgeRefusedSnap.claudeState.nodeProbe &&
          getTargetServiceVerificationError(hedgeRefusedSnap.claudeState.nodeProbe, 'claude') === null,
        `重绑后应校验通过: err=${hedgeRefusedSnap.claudeState.nodeProbeError}`
      );
    } finally {
      holdClaudePrimary = false;
      onClaudeHoldReady = null;
      onSubGeoLookup = null;
      subService.channels.claude.off('ready', onHedgeReady);
      await hedgeFaultTask.catch(() => undefined);
      await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    }

    // (4) 四源复核节点：已取得 >=2 匹配样本 + 1 异国样本 + Claude 后，关闭本地端口使第 4 源触发 ECONNREFUSED，仍优先重绑
    await bindSubNode('四源复核节点');
    const subFourLease = readLeaseEndpoint(path.join(liveRoot, 'sub-kernels', 'claude'));
    const passHost0 = new URL(proxySideEndpoints[0].url).hostname.toLowerCase();
    const passHost1 = new URL(proxySideEndpoints[1].url).hostname.toLowerCase();
    acceptedPassHosts.clear();
    let preRefusalProxyLookups = 0;
    let preRefusalForeignLookups = 0;
    let triggeredRefusal = false;
    let fourReadyCount = 0;
    let fourFaultTask: Promise<void> = Promise.resolve();
    const onFourReady = () => fourReadyCount++;
    subService.channels.claude.on('ready', onFourReady);
    const maybeTriggerFourRefusal = () => {
      if (
        triggeredRefusal ||
        heldDropClients.size === 0 ||
        !acceptedPassHosts.has(passHost0) ||
        !acceptedPassHosts.has(passHost1) ||
        !acceptedPassHosts.has('claude.ai') ||
        preRefusalProxyLookups < MIN_CONSENSUS_MATCHES + 1 ||
        preRefusalForeignLookups < 1
      ) {
        return;
      }
      triggeredRefusal = true;
      fourFaultTask = (async () => {
        await delay(40);
        await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
        await mihomoRequest(subFourLease.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
        const closeDeadline = Date.now() + 2000;
        while ((await isLocalPortListening(subPort)) && Date.now() < closeDeadline) {
          await delay(20);
        }
        for (const sock of heldDropClients) sock.destroy();
      })();
      fourFaultTask.catch(() => undefined);
    };
    onPassHostAccepted = maybeTriggerFourRefusal;
    onHeldDropReady = maybeTriggerFourRefusal;
    onSubGeoLookup = (code) => {
      if (triggeredRefusal) return;
      if (code === proxyCountry) preRefusalProxyLookups++;
      else preRefusalForeignLookups++;
      maybeTriggerFourRefusal();
    };
    try {
      await reloadKernelConfig(
        upLease.endpoint,
        makeUpstreamConfig([
          `DOMAIN,${direct1.host},${foreignTarget}`,
          `DOMAIN,${passHost0},test-counted-pass`,
          `DOMAIN,${passHost1},test-counted-pass`,
          'DOMAIN,claude.ai,test-counted-pass',
          `DOMAIN,${direct2.host},test-hold-drop`,
        ])
      );
      const refusedRecoveredSnap = await subEngine.probeClaudeNodeNow('两源匹配后本地端口拒绝优先重绑', true);
      await fourFaultTask;
      assert.equal(
        triggeredRefusal,
        true,
        `应触发四源匹配后端口拒绝: accepted=${[...acceptedPassHosts].join(',')}, proxyLookups=${preRefusalProxyLookups}, foreignLookups=${preRefusalForeignLookups}, held=${heldDropClients.size}`
      );
      assert.ok(preRefusalProxyLookups >= MIN_CONSENSUS_MATCHES + 1, '触发前应有至少两源匹配+Claude校验');
      assert.ok(preRefusalForeignLookups >= 1, '触发前应有至少一个异国常规样本');
      assert.equal(fourReadyCount, 1, '已匹配两源后遭遇本地端口拒绝必须优先触发重绑');
      assert.equal(await isLocalPortListening(subPort), true, '四源重绑后端口应恢复监听');
      assert.ok(
        refusedRecoveredSnap.claudeState.nodeProbe &&
          getTargetServiceVerificationError(refusedRecoveredSnap.claudeState.nodeProbe, 'claude') === null,
        `四源重绑后应校验通过: err=${refusedRecoveredSnap.claudeState.nodeProbeError}`
      );
    } finally {
      onPassHostAccepted = null;
      onHeldDropReady = null;
      onSubGeoLookup = null;
      subService.channels.claude.off('ready', onFourReady);
      await fourFaultTask.catch(() => undefined);
      await reloadKernelConfig(upLease.endpoint, makeUpstreamConfig([]));
    }

    console.log(
      '通过：基于独立真实测试节点完成错峰对冲、零常规源 Claude 出口检查、单源旁路共识、双源 1:1 双序冲突、多源跨国分流双序与告警同源配对、Antigravity 冲突取消重测及对冲/复核期端口拒绝自动重绑'
    );
  } finally {
    onPassHostAccepted = null;
    beforePassTunnelReady = null;
    onHeldDropReady = null;
    onClaudeHoldReady = null;
    onSubGeoLookup = null;
    subEngine?.stop();
    await Promise.all([subService.shutdown(), upstreamService.shutdown()]);
    activeServices.delete(subService);
    activeServices.delete(upstreamService);
    for (const sock of allSockets) sock.destroy();
    await Promise.all([
      new Promise<void>((resolve) => relayServer.close(() => resolve())),
      new Promise<void>((resolve) => directDelayServer.close(() => resolve())),
      new Promise<void>((resolve) => connectHopServer.close(() => resolve())),
      new Promise<void>((resolve) => countedPassServer.close(() => resolve())),
      new Promise<void>((resolve) => holdBeforeTlsServer.close(() => resolve())),
      new Promise<void>((resolve) => claudeHoldServer.close(() => resolve())),
      new Promise<void>((resolve) => proxyExitProxyServer.close(() => resolve())),
      new Promise<void>((resolve) => foreignExitProxyServer.close(() => resolve())),
      new Promise<void>((resolve) => proxyOriginServer.close(() => resolve())),
      new Promise<void>((resolve) => foreignOriginServer.close(() => resolve())),
    ]);
  }
}

async function run(): Promise<void> {
  const coreDir = path.join(root, 'core');
  fs.cpSync(path.resolve('resources/mihomo'), coreDir, { recursive: true });
  verifyTransportHostsAndPureSafety();
  await verifyLocalNetClientAndKernelRecovery(coreDir);
  await verifyMultiSourceConsensus(coreDir);
}

let fatalExiting = false;
const handleFatalExit = () => {
  if (fatalExiting) return;
  fatalExiting = true;
  void shutdownAllServices().finally(() => app.exit(1));
};
process.on('uncaughtException', handleFatalExit);
process.on('unhandledRejection', handleFatalExit);

app.whenReady()
  .then(run)
  .then(() => shutdownAllServices())
  .then(() => app.exit(0))
  .catch(async (error) => {
    console.error(error);
    await shutdownAllServices();
    app.exit(1);
  });
