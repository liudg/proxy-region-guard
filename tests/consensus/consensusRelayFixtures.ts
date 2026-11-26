import { BinaryWriter, WireType } from '@bufbuild/protobuf/wire';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as path from 'node:path';
import type { Duplex } from 'node:stream';
import * as yaml from 'js-yaml';
import { NodeSnapshot, SubscriptionCatalog } from '../../electron/clash';
import { GeoIpService } from '../../electron/system';
import {
  freePort,
  listen,
  parseHttpConnectAuthority,
  parseHttpHostHeader,
} from './testHarness';

export type ProxyClaudeTraceMode =
  | 'normal'
  | 'bad-first-then-ok'
  | 'loc-xx-then-fail'
  | 'drift-loc-xx-then-old-ok'
  | 'foreign-loc-xx-then-proxy-ok'
  | 'proxy-loc-xx-then-foreign-ok';

export type ForeignClaudeTraceMode = 'normal' | 'loc-xx-proxy-ip';

export type ProxyGoogleMode =
  | 'normal'
  | 'cn-songzhong-hkredirect'
  | 'cn-songzhong-hkredirect-yt-fallback-us'
  | 'cn-songzhong-yt-protobuf-only'
  | 'same-country-ai-unsupported';

export type RelayTimingMode = 'delay-target' | 'delay-target-short' | 'stall-first';

export interface ConsensusRelayRig {
  expectedProxyIp: string;
  expectedProxyDriftedIp: string;
  expectedForeignIp: string;
  expectedProxyCountry: string;
  expectedForeignCountry: string;
  upstreamPort: number;
  directUpstreamPort: number;
  baseUpstreamPort: number;
  subPort: number;
  relayPort: number;
  directDelayPort: number;
  connectHopPort: number;
  countedPassPort: number;
  holdBeforeTlsPort: number;
  claudeHoldPort: number;
  primarySnapshot: NodeSnapshot;
  foreignSnapshot: NodeSnapshot;
  observedHopTargets: Set<string>;
  observedHopHosts: Set<string>;
  acceptedPassHosts: Set<string>;
  heldDropClients: Set<Duplex>;
  claudeHoldClients: Set<Duplex>;
  state: {
    proxyClaudeTraceMode: ProxyClaudeTraceMode;
    proxyClaudeTraceHits: number;
    foreignClaudeTraceMode: ForeignClaudeTraceMode;
    proxyGoogleMode: ProxyGoogleMode;
    proxyGoogleHkRedirectFollowHits: number;
    proxyNotebookDomainMigrationHits: number;
    relayMode: RelayTimingMode;
    relayHits: number;
    holdClaudePrimary: boolean;
    claudeHoldReleasedCount: number;
    claudeHoldClosedBeforeReleaseCount: number;
    onPassHostAccepted: (() => void) | null;
    beforePassTunnelReady: ((host: string) => Promise<void>) | null;
    onHeldDropReady: (() => void) | null;
    onClaudeHoldReady: (() => void) | null;
    onProxyClaudeTraceHit1: (() => Promise<void> | void) | null;
  };
  cleanup: () => Promise<void>;
}

function encodeTestYoutubeVisitorData(
  countryCode: string,
  visitorId = 'B_0FWZLX6ec',
  ts = 1795570159
): string {
  const geoWriter = new BinaryWriter();
  geoWriter.tag(1, WireType.LengthDelimited).string(countryCode);
  geoWriter
    .tag(2, WireType.LengthDelimited)
    .bytes(new Uint8Array([0x1a, 0x00, 0x20, 0x64]));
  const rootWriter = new BinaryWriter();
  rootWriter.tag(1, WireType.LengthDelimited).string(visitorId);
  rootWriter.tag(5, WireType.Varint).uint64(ts);
  rootWriter.tag(6, WireType.LengthDelimited).bytes(geoWriter.finish());
  rootWriter.tag(9, WireType.Varint).uint32(1);
  return Buffer.from(rootWriter.finish())
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export async function createConsensusRelayRig(
  liveRoot: string,
  tlsCert: string,
  tlsKey: string,
  geo: GeoIpService
): Promise<ConsensusRelayRig> {
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

  const allSockets = new Set<Duplex>();
  const state: ConsensusRelayRig['state'] = {
    proxyClaudeTraceMode: 'normal',
    proxyClaudeTraceHits: 0,
    foreignClaudeTraceMode: 'normal',
    proxyGoogleMode: 'normal',
    proxyGoogleHkRedirectFollowHits: 0,
    proxyNotebookDomainMigrationHits: 0,
    relayMode: 'delay-target',
    relayHits: 0,
    holdClaudePrimary: false,
    claudeHoldReleasedCount: 0,
    claudeHoldClosedBeforeReleaseCount: 0,
    onPassHostAccepted: null,
    beforePassTunnelReady: null,
    onHeldDropReady: null,
    onClaudeHoldReady: null,
    onProxyClaudeTraceHit1: null,
  };

  const createRealTlsExitOrigin = (
    exitIp: string,
    exitCountry: string,
    isProxySide: boolean
  ) =>
    https.createServer({ key: tlsKey, cert: tlsCert }, (req, res) => {
      const host = String(req.headers.host || '')
        .split(':')[0]
        .toLowerCase();
      const reqPath = req.url || '/';
      if (reqPath.startsWith('/cdn-cgi/trace')) {
        if (isProxySide && host === 'claude.ai') {
          const hit = ++state.proxyClaudeTraceHits;
          if (state.proxyClaudeTraceMode === 'bad-first-then-ok' && hit === 1) {
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('ok-without-valid-ip\n');
            return;
          }
          if (state.proxyClaudeTraceMode === 'loc-xx-then-fail') {
            if (hit === 1) {
              res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
              res.end(
                `fl=29f1\nh=claude.ai\nip=${expectedForeignIp}\nts=${Math.floor(
                  Date.now() / 1000
                )}\nloc=XX\n`
              );
              return;
            }
            res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('bad gateway');
            return;
          }
          if (state.proxyClaudeTraceMode === 'drift-loc-xx-then-old-ok' && hit === 1) {
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end(
              `fl=29f1\nh=claude.ai\nip=${expectedProxyDriftedIp}\nts=${Math.floor(
                Date.now() / 1000
              )}\nloc=XX\n`
            );
            return;
          }
          if (state.proxyClaudeTraceMode === 'foreign-loc-xx-then-proxy-ok' && hit === 1) {
            void Promise.resolve(state.onProxyClaudeTraceHit1?.()).then(() => {
              res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
              res.end(
                `fl=29f1\nh=claude.ai\nip=${expectedForeignIp}\nts=${Math.floor(
                  Date.now() / 1000
                )}\nloc=XX\n`
              );
            });
            return;
          }
          if (state.proxyClaudeTraceMode === 'proxy-loc-xx-then-foreign-ok') {
            if (hit === 1) {
              void Promise.resolve(state.onProxyClaudeTraceHit1?.()).then(() => {
                res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
                res.end(
                  `fl=29f1\nh=claude.ai\nip=${expectedProxyIp}\nts=${Math.floor(
                    Date.now() / 1000
                  )}\nloc=XX\n`
                );
              });
              return;
            }
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end(
              `fl=29f1\nh=claude.ai\nip=${expectedForeignIp}\nts=${Math.floor(
                Date.now() / 1000
              )}\nloc=${expectedForeignCountry}\n`
            );
            return;
          }
        }
        if (
          !isProxySide &&
          host === 'claude.ai' &&
          state.foreignClaudeTraceMode === 'loc-xx-proxy-ip'
        ) {
          res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end(
            `fl=29f1\nh=claude.ai\nip=${expectedProxyIp}\nts=${Math.floor(
              Date.now() / 1000
            )}\nloc=XX\n`
          );
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(
          `fl=29f1\nh=${host}\nip=${exitIp}\nts=${Math.floor(
            Date.now() / 1000
          )}\nloc=${exitCountry}\n`
        );
        return;
      }
      if (reqPath.startsWith('/sw.js_data')) {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        if (
          isProxySide &&
          state.proxyGoogleMode === 'cn-songzhong-hkredirect-yt-fallback-us'
        ) {
          res.end(`)]}'\n[["yt.sw.adr",null,[[["en","US",null,"${exitIp}"]]]]]`);
          return;
        }
        if (
          isProxySide &&
          (state.proxyGoogleMode === 'cn-songzhong-hkredirect' ||
            state.proxyGoogleMode === 'cn-songzhong-yt-protobuf-only')
        ) {
          const cnVisitor = encodeTestYoutubeVisitorData('CN');
          res.end(
            `)]}'\n[["yt.sw.adr",null,[[["en","US",null,"${exitIp}",null,null,null,null,null,null,null,"Robot","Bot or Crawler","${cnVisitor}"]]]]]`
          );
          return;
        }
        const visitor = encodeTestYoutubeVisitorData(exitCountry);
        res.end(
          `)]}'\n[["yt.sw.adr",null,[[["en","${exitCountry}",null,"${exitIp}",null,null,null,null,null,null,null,"Robot","Bot or Crawler","${visitor}"]]]]]`
        );
        return;
      }
      if (host === 'notebooklm.google.com') {
        if (
          isProxySide &&
          (state.proxyGoogleMode === 'cn-songzhong-hkredirect' ||
            state.proxyGoogleMode === 'cn-songzhong-hkredirect-yt-fallback-us')
        ) {
          res.writeHead(302, {
            Location: 'https://notebooklm.google?location=unsupported',
          });
          res.end();
          return;
        }
        res.writeHead(301, {
          Location: 'https://notebook.google.com/',
        });
        res.end();
        return;
      }
      if (host === 'notebook.google.com') {
        if (isProxySide) state.proxyNotebookDomainMigrationHits++;
        if (isProxySide && state.proxyGoogleMode === 'same-country-ai-unsupported') {
          res.writeHead(302, {
            Location: 'https://notebook.google?location=unsupported',
          });
          res.end();
          return;
        }
        res.writeHead(302, {
          Location:
            'https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fnotebook.google.com%2F',
        });
        res.end();
        return;
      }
      if (host === 'www.google.com.hk') {
        if (isProxySide) state.proxyGoogleHkRedirectFollowHits++;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(
          '<!doctype html><html><script>var cfg=["",2,1,200,"CHN",null];</script></html>'
        );
        return;
      }
      if (host.includes('google.com')) {
        if (
          isProxySide &&
          (state.proxyGoogleMode === 'cn-songzhong-hkredirect' ||
            state.proxyGoogleMode === 'cn-songzhong-hkredirect-yt-fallback-us')
        ) {
          res.writeHead(302, {
            Location:
              'https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/%3Fhl%3Den',
          });
          res.end();
          return;
        }
        if (
          isProxySide &&
          state.proxyGoogleMode === 'cn-songzhong-yt-protobuf-only'
        ) {
          res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end('bad gateway');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(
          `<!doctype html><html><script>var cfg={"MgUcDb":"${exitCountry}"};</script></html>`
        );
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`${exitIp}\n`);
    });

  const proxyOriginServer = createRealTlsExitOrigin(
    expectedProxyIp,
    expectedProxyCountry,
    true
  );
  const foreignOriginServer = createRealTlsExitOrigin(
    expectedForeignIp,
    expectedForeignCountry,
    false
  );
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
      items: [
        {
          uid: 'upstream-prof',
          name: '独立回归上游订阅',
          type: 'local',
          file: 'upstream-prof.yaml',
        },
      ],
    }),
    'utf8'
  );
  fs.writeFileSync(
    path.join(upstreamVergeDir, 'profiles', 'upstream-prof.yaml'),
    yaml.dump({
      proxies: [
        {
          name: '独立主出口节点',
          type: 'http',
          server: '127.0.0.1',
          port: proxyExitProxyPort,
        },
        {
          name: '独立异国出口节点',
          type: 'http',
          server: '127.0.0.1',
          port: foreignExitProxyPort,
        },
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

  const primarySnapshot = upstreamCatalog.capture('upstream-prof', '独立主出口节点');
  const foreignSnapshot = upstreamCatalog.capture(
    'upstream-prof',
    '独立异国出口节点'
  );

  const relayServer = net.createServer((client) => {
    allSockets.add(client);
    const hit = ++state.relayHits;
    let timer: NodeJS.Timeout | undefined;
    const up = net.connect(baseUpstreamPort, '127.0.0.1');
    client.pipe(up);
    if (
      state.relayMode === 'delay-target' ||
      state.relayMode === 'delay-target-short'
    ) {
      const waitMs = state.relayMode === 'delay-target-short' ? 2400 : 5000;
      up.once('data', (chunk) => {
        up.pause();
        client.write(chunk);
        timer = setTimeout(() => up.pipe(client), waitMs);
      });
    } else if (state.relayMode === 'stall-first' && hit === 1) {
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
    const hostHdr = parseHttpHostHeader(
      typeof req.headers.host === 'string' ? req.headers.host : undefined
    );
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
          state.onPassHostAccepted?.();
        }
      };
      if (target && state.beforePassTunnelReady) {
        upstream.pause();
        state
          .beforePassTunnelReady(target.host)
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
    state.onHeldDropReady?.();
  });
  const holdBeforeTlsPort = await listen(holdBeforeTlsServer, '127.0.0.1');

  const claudeHoldClients = new Set<Duplex>();
  const claudeHoldServer = http.createServer();
  claudeHoldServer.on('clientError', (_err, sock) => sock.destroy());
  claudeHoldServer.on('connect', (req, client, head) => {
    allSockets.add(client);
    claudeHoldClients.add(client);
    let upSock: net.Socket | null = null;
    let releaseTimer: NodeJS.Timeout | undefined;
    const shouldHold = state.holdClaudePrimary;
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
      state.onClaudeHoldReady?.();
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
          state.claudeHoldReleasedCount++;
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
      if (shouldHold && !released) state.claudeHoldClosedBeforeReleaseCount++;
      upReq.destroy();
      upSock?.destroy();
      claudeHoldClients.delete(client);
      allSockets.delete(client);
    });
  });
  const claudeHoldPort = await listen(claudeHoldServer, '127.0.0.1');

  const cleanup = async () => {
    state.onPassHostAccepted = null;
    state.beforePassTunnelReady = null;
    state.onHeldDropReady = null;
    state.onClaudeHoldReady = null;
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
  };

  return {
    expectedProxyIp,
    expectedProxyDriftedIp,
    expectedForeignIp,
    expectedProxyCountry,
    expectedForeignCountry,
    upstreamPort,
    directUpstreamPort,
    baseUpstreamPort,
    subPort,
    relayPort,
    directDelayPort,
    connectHopPort,
    countedPassPort,
    holdBeforeTlsPort,
    claudeHoldPort,
    primarySnapshot,
    foreignSnapshot,
    observedHopTargets,
    observedHopHosts,
    acceptedPassHosts,
    heldDropClients,
    claudeHoldClients,
    state,
    cleanup,
  };
}
