import assert from 'node:assert/strict';
import { once } from 'node:events';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as net from 'node:net';
import * as path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import * as yaml from 'js-yaml';
import { Ipv4ProxyBridge } from '../../electron/bridge';
import {
  ClashMonitor,
  isLocalPortListening,
  mihomoRequest,
  readYaml,
} from '../../electron/clash';
import { evaluateClaudeNodeProbeSafety, ProbeEngine } from '../../electron/guard';
import { PrivateProxyService } from '../../electron/kernel';
import { isLocalProxyRefusedCause, requestTextViaProxy } from '../../electron/net';
import {
  ConfigStore,
  DEFAULT_CONFIG,
  GeoIpService,
  spawnClaudeWithDedicatedProxy,
} from '../../electron/system';
import { getRawFs } from '../../electron/utils/rawFs';
import { getTargetServiceVerificationError } from '../../src/shared/probeValidation';
import { createIpv4VlessTestRig } from './ipv4VlessFixtures';
import {
  freePort,
  hasTrackedService,
  listen,
  readLeaseEndpoint,
  reloadKernelConfig,
  root,
  trackService,
  untrackService,
} from './testHarness';

export async function verifyClaudeIpv4Enforcement(coreDir: string): Promise<void> {
  const ipv4Root = path.join(root, 'claude-ipv4-enforcement');
  fs.mkdirSync(ipv4Root, { recursive: true });

  // 1. 验证默认配置启用强制仅走 IPv4 出站，且 IPv4 -> IPv6 漂移与强 IPv4 违规检测准确生效
  assert.equal(
    DEFAULT_CONFIG.claudeForceIpv4,
    true,
    '默认配置应开启 Claude 通道强制仅走 IPv4 出站'
  );
  const ipv6DriftCheck = evaluateClaudeNodeProbeSafety(
    {
      ip: '35.75.214.251',
      countryCode: 'JP',
      countryName: '日本',
      viaChannel: 'test',
      latencyMs: 50,
      checkedAt: Date.now(),
      claudeTraceLoc: 'JP',
      claudeTraceIp: '2406:da14:428:8701:8627:42b:8d6d:ac89',
      claudeTraceCountryCode: 'JP',
      claudeTraceCheckedAt: Date.now(),
    },
    {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: true,
      claudeForceIpv4: true,
      sessionInitialIp: '35.75.214.251',
    }
  );
  assert.equal(ipv6DriftCheck?.alertType, 'ip-change');
  assert.match(ipv6DriftCheck?.reason || '', /IPv6/);

  const unlockedIpv4Switch = evaluateClaudeNodeProbeSafety(
    {
      ip: '35.75.214.252',
      countryCode: 'JP',
      countryName: '日本',
      viaChannel: 'test',
      latencyMs: 40,
      checkedAt: Date.now(),
      claudeTraceLoc: 'JP',
      claudeTraceIp: '35.75.214.252',
      claudeTraceCountryCode: 'JP',
      claudeTraceCheckedAt: Date.now(),
    },
    {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: false,
      claudeForceIpv4: true,
      sessionInitialIp: '35.75.214.251',
    }
  );
  assert.equal(unlockedIpv4Switch, null, '未锁定出口 IP 时同国 IPv4 切换应允许');

  const unlockedIpv6Violation = evaluateClaudeNodeProbeSafety(
    {
      ip: '35.75.214.251',
      countryCode: 'JP',
      countryName: '日本',
      viaChannel: 'test',
      latencyMs: 40,
      checkedAt: Date.now(),
      claudeTraceLoc: 'JP',
      claudeTraceIp: '2406:da14:428:8701:8627:42b:8d6d:ac89',
      claudeTraceCountryCode: 'JP',
      claudeTraceCheckedAt: Date.now(),
    },
    {
      claudeRunning: true,
      claudeExternalBaselinePending: false,
      claudeLockExitIp: false,
      claudeForceIpv4: true,
      sessionInitialIp: null,
    }
  );
  assert.equal(
    unlockedIpv6Violation?.alertType,
    'ip-change',
    '关闭出口 IP 锁定但开启强制 IPv4 时，运行期收到 IPv6 出口仍须立即触发熔断'
  );
  assert.match(unlockedIpv6Violation?.reason || '', /IPv6/);

  const tlsCertPath = process.env.GUARD_TEST_TLS_CERT;
  const tlsKeyPath = process.env.GUARD_TEST_TLS_KEY;
  assert.ok(tlsCertPath && tlsKeyPath, '缺少测试 TLS 证书环境变量');
  const tlsCert = fs.readFileSync(tlsCertPath, 'utf8');
  const tlsKey = fs.readFileSync(tlsKeyPath, 'utf8');

  const geo = new GeoIpService();
  await geo.init(process.cwd());
  const expectedIpv4Exit = '35.75.214.251';
  const expectedIpv6Exit = '2406:da14:428:8701:8627:42b:8d6d:ac89';
  assert.equal(geo.lookupOfflineStrict(expectedIpv4Exit).countryCode, 'JP');
  assert.equal(geo.lookupOfflineStrict(expectedIpv6Exit).countryCode, 'JP');

  const rig = await createIpv4VlessTestRig(
    ipv4Root,
    tlsCert,
    tlsKey,
    expectedIpv4Exit
  );
  const {
    dnsPort,
    dnsQueries,
    plainHostHeaders,
    vlessTargets,
    vergeDir,
    vlessSnap,
  } = rig;

  const kernelDir = path.join(ipv4Root, 'kernels');
  const svc = trackService(new PrivateProxyService(kernelDir, coreDir));
  const claudePort = await freePort();
  let engine: ProbeEngine | null = null;
  let isolatedClientPid: number | null = null;

  try {
    // 5. 验证 select(..., { ipv4Only: true }) 写出 dns.ipv6=false 与 IP-CIDR6 阻断规则
    await svc.channels.claude.select(vlessSnap, claudePort, { ipv4Only: true });
    assert.equal(svc.channels.claude.getState().phase, 'ready');
    assert.equal(svc.channels.claude.getIpv4Only(), true);
    const internalPort = svc.channels.claude.getInternalPort()!;
    assert.ok(
      Number.isInteger(internalPort) && internalPort > 0 && internalPort !== claudePort,
      `ipv4Only 模式下私有内核必须使用独立内部回环端口 (public=${claudePort}, internal=${internalPort})`
    );
    const lease = readLeaseEndpoint(path.join(kernelDir, 'claude'));
    const writtenCfg = readYaml(lease.configPath);
    assert.equal(
      writtenCfg['mixed-port'],
      internalPort,
      'Mihomo config.yaml 必须绑定内部回环端口'
    );
    assert.equal(
      (writtenCfg.dns as Record<string, unknown>).ipv6,
      false,
      'Claude IPv4-only 内核必须关闭 dns.ipv6'
    );
    const writtenRules = writtenCfg.rules as string[];
    assert.ok(
      writtenRules.includes('IP-CIDR6,::/0,REJECT,no-resolve'),
      'Claude IPv4-only 内核必须写入 IP-CIDR6,::/0,REJECT,no-resolve 规则'
    );

    const offlineDnsCfg = yaml.dump({
      ...writtenCfg,
      dns: {
        ...(writtenCfg.dns as Record<string, unknown>),
        nameserver: [`127.0.0.1:${dnsPort}`],
      },
    });
    fs.writeFileSync(lease.configPath, offlineDnsCfg, 'utf8');
    await reloadKernelConfig(lease.endpoint, offlineDnsCfg);

    // 5b. 验证 PrivateKernel.probeForwarding() 在 ipv4Only=true 时仅向 VLESS 发送 ATYP=1 (IPv4)
    await mihomoRequest(lease.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
    const dropForProbeForwardDeadline = Date.now() + 3000;
    while (
      (await isLocalPortListening(internalPort)) &&
      Date.now() < dropForProbeForwardDeadline
    ) {
      await delay(30);
    }
    vlessTargets.length = 0;
    dnsQueries.length = 0;
    const forwardCheckResult = await svc.channels.claude.recoverListenerIfNeeded();
    assert.equal(
      forwardCheckResult,
      'rebound',
      '关闭内部监听后 recoverListenerIfNeeded 应重载并完成转发验证'
    );
    assert.equal(
      svc.channels.claude.getState().verificationError,
      null,
      `ipv4Only 私有内核转发校验应通过: ${svc.channels.claude.getState().verificationError}`
    );
    assert.ok(
      vlessTargets.length >= 1,
      'probeForwarding 应至少发起 1 条 VLESS 转发校验连接'
    );
    for (const target of vlessTargets) {
      assert.equal(
        target.atyp,
        1,
        `ipv4Only 模式下 PrivateKernel.probeForwarding() 也必须仅发送 ATYP=1 IPv4，但收到 ${JSON.stringify(
          target
        )}`
      );
      assert.equal(target.addr, '160.79.104.10');
    }
    assert.equal(
      dnsQueries.some((q) => q.qtype === 28),
      false,
      'probeForwarding 在 ipv4Only 模式下不得发起 AAAA 查询'
    );

    const store = new ConfigStore();
    store.update({
      selectedClashNode: '双栈VLESS测试节点',
      selectedClashProfileUid: 'vless-prof',
      selectedClashProfileName: 'VLESS IPv4 测试订阅',
      dedicatedProxyPort: claudePort,
      claudeExclusiveGuard: false,
      claudeForceIpv4: true,
      claudeLockExitIp: true,
      killProcessesEnabled: false,
    });
    engine = new ProbeEngine(store, geo, new ClashMonitor(vergeDir), svc);

    // 6. 验证全链路 ProbeEngine 探测线缆层全部为 ATYP=1 (IPv4) 且无 AAAA 查询
    vlessTargets.length = 0;
    dnsQueries.length = 0;
    const probeSnap = await engine.probeClaudeNodeNow(
      'IPv4 强制出站线缆层验证',
      true
    );
    assert.ok(
      probeSnap.claudeState.nodeProbe &&
        getTargetServiceVerificationError(
          probeSnap.claudeState.nodeProbe,
          'claude'
        ) === null,
      `IPv4 强制出站探测应通过校验: err=${probeSnap.claudeState.nodeProbeError}`
    );
    assert.equal(probeSnap.claudeState.nodeProbe.claudeTraceIp, expectedIpv4Exit);
    assert.ok(
      vlessTargets.length >= 3,
      `VLESS 服务端应收到至少 3 条探测连接，实际 ${vlessTargets.length}`
    );
    for (const target of vlessTargets) {
      assert.equal(
        target.atyp,
        1,
        `强制 IPv4 模式下 VLESS 线缆层必须全部为 ATYP=1 (IPv4)，但收到 ${JSON.stringify(
          target
        )}`
      );
      assert.equal(target.addr, '160.79.104.10');
    }
    assert.equal(
      dnsQueries.some((q) => q.qtype === 28),
      false,
      `强制 IPv4 模式下不得发起 AAAA 查询，实际查询：${JSON.stringify(dnsQueries)}`
    );

    // 7. 直接通过公开的 dedicatedProxyPort 验证外部客户端同路径强制 IPv4
    const publicHttpUrl = `http://127.0.0.1:${claudePort}`;
    const publicSocksUrl = `socks5h://127.0.0.1:${claudePort}`;

    vlessTargets.length = 0;
    const socksTrace = await requestTextViaProxy(
      'https://claude.ai/cdn-cgi/trace',
      publicSocksUrl,
      6000
    );
    assert.match(socksTrace, /ip=35\.75\.214\.251/);
    assert.equal(vlessTargets.length, 1);
    assert.equal(
      vlessTargets[0].atyp,
      1,
      '公开端口 SOCKS5 域名请求经桥接后 VLESS 必须收到 ATYP=1 IPv4'
    );
    assert.equal(vlessTargets[0].addr, '160.79.104.10');

    vlessTargets.length = 0;
    plainHostHeaders.length = 0;
    const plainBody = await requestTextViaProxy(
      'http://claude.ai/hello',
      publicHttpUrl,
      6000
    );
    assert.equal(plainBody, 'plain-http-ipv4-ok');
    assert.equal(
      plainHostHeaders[0],
      'claude.ai',
      '明文 HTTP 代理转发必须保留原始 Host 头'
    );
    assert.equal(vlessTargets.length, 1);
    assert.equal(
      vlessTargets[0].atyp,
      1,
      '公开端口明文 HTTP 域名请求经桥接后 VLESS 必须收到 ATYP=1 IPv4'
    );
    assert.equal(vlessTargets[0].addr, '160.79.104.10');

    // 7b1. 短请求头 + 80KiB 大请求体通过，超大请求头返回 431
    const largePostBody = 'B'.repeat(80 * 1024);
    const largePostResp = await new Promise<string>((resolve, reject) => {
      const sock = net.connect(claudePort, '127.0.0.1', () => {
        sock.write(
          `POST http://claude.ai/echo HTTP/1.1\r\n` +
            `Host: claude.ai\r\n` +
            `Content-Length: ${Buffer.byteLength(largePostBody)}\r\n` +
            `Connection: close\r\n\r\n` +
            largePostBody
        );
      });
      const timeout = setTimeout(
        () => sock.destroy(new Error('大请求体 POST 超时')),
        6000
      );
      const chunks: Buffer[] = [];
      sock.on('data', (chunk: Buffer) => chunks.push(chunk));
      sock.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
      sock.on('end', () => {
        clearTimeout(timeout);
        resolve(Buffer.concat(chunks).toString('utf8'));
      });
    });
    const largeSplitIdx = largePostResp.indexOf('\r\n\r\n');
    assert.ok(largeSplitIdx > 0, '大请求体 POST 应返回完整 HTTP 响应');
    assert.match(largePostResp.slice(0, largeSplitIdx), /^HTTP\/1\.1 200 /);
    assert.equal(
      largePostResp.slice(largeSplitIdx + 4),
      largePostBody,
      '短请求头配 80KiB 大请求体不得被误判为 431 头部超限，且字节必须完整送达'
    );

    const oversizedHeaderResp = await new Promise<string>((resolve, reject) => {
      const sock = net.connect(claudePort, '127.0.0.1', () => {
        sock.write(
          `GET http://claude.ai/hello HTTP/1.1\r\nHost: claude.ai\r\nX-Pad: ${'H'.repeat(
            70 * 1024
          )}\r\n\r\n`
        );
      });
      const timeout = setTimeout(
        () => sock.destroy(new Error('超大请求头测试超时')),
        4000
      );
      const chunks: Buffer[] = [];
      sock.on('data', (chunk: Buffer) => chunks.push(chunk));
      sock.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
      sock.on('end', () => {
        clearTimeout(timeout);
        resolve(Buffer.concat(chunks).toString('utf8'));
      });
    });
    assert.match(
      oversizedHeaderResp,
      /^HTTP\/1\.1 431 /,
      `超过 64KiB 的请求头必须返回 431，实际：${oversizedHeaderResp.slice(0, 120)}`
    );

    // 7b2. 明文 HTTP POST 分包请求体 + 400KiB chunked POST 背压零丢字节
    const slowBodyBridge = new Ipv4ProxyBridge({
      getUpstreamTarget: () => ({ status: 'ready', port: internalPort }),
      resolveIpv4: async (hostname, signal) => {
        await delay(150, undefined, { signal });
        return svc.channels.claude.resolveIpv4(hostname, signal);
      },
    });
    try {
      const slowBridgePort = await slowBodyBridge.ensureStarted();
      const postChunk1 = 'alpha-body-part-1|';
      const postChunk2 = 'beta-body-part-2-arriving-during-dns|';
      const postChunk3 = 'gamma-final-body-part-3';
      const fullPostBody = `${postChunk1}${postChunk2}${postChunk3}`;
      const rawHttpResp = await new Promise<string>((resolve, reject) => {
        const sock = net.connect(slowBridgePort, '127.0.0.1', () => {
          sock.write(
            `POST http://claude.ai/echo HTTP/1.1\r\n` +
              `Host: claude.ai\r\n` +
              `Content-Length: ${Buffer.byteLength(fullPostBody)}\r\n` +
              `Connection: close\r\n\r\n` +
              postChunk1
          );
          setTimeout(() => {
            if (!sock.destroyed) sock.write(postChunk2);
          }, 25);
          setTimeout(() => {
            if (!sock.destroyed) sock.write(postChunk3);
          }, 70);
        });
        const timeout = setTimeout(() => {
          sock.destroy(new Error('POST 回显请求超时'));
        }, 6000);
        const respChunks: Buffer[] = [];
        sock.on('data', (chunk: Buffer) => respChunks.push(chunk));
        sock.on('error', (err) => {
          clearTimeout(timeout);
          reject(err);
        });
        sock.on('end', () => {
          clearTimeout(timeout);
          resolve(Buffer.concat(respChunks).toString('utf8'));
        });
      });
      const splitIdx = rawHttpResp.indexOf('\r\n\r\n');
      assert.ok(splitIdx > 0, `应收到完整 HTTP 响应头，实际：${rawHttpResp}`);
      assert.match(rawHttpResp.slice(0, splitIdx), /^HTTP\/1\.1 200 /);
      assert.equal(
        rawHttpResp.slice(splitIdx + 4),
        fullPostBody,
        '上游 DNS 握手期间分段到达的明文 HTTP POST 请求体不得丢弃任何字节'
      );

      const chunked400kBody = 'Z'.repeat(400 * 1024);
      const chunkedResp = await new Promise<string>((resolve, reject) => {
        const sock = net.connect(slowBridgePort, '127.0.0.1', () => {
          sock.write(
            `POST http://claude.ai/echo HTTP/1.1\r\n` +
              `Host: claude.ai\r\n` +
              `Transfer-Encoding: chunked\r\n` +
              `Connection: close\r\n\r\n` +
              `${chunked400kBody.length.toString(16)}\r\n` +
              `${chunked400kBody}\r\n` +
              `0\r\n\r\n`
          );
        });
        const timeout = setTimeout(
          () => sock.destroy(new Error('400KiB chunked POST 超时')),
          8000
        );
        const chunks: Buffer[] = [];
        sock.on('data', (chunk: Buffer) => chunks.push(chunk));
        sock.on('error', (err) => {
          clearTimeout(timeout);
          reject(err);
        });
        sock.on('end', () => {
          clearTimeout(timeout);
          resolve(Buffer.concat(chunks).toString('utf8'));
        });
      });
      const chunkedSplitIdx = chunkedResp.indexOf('\r\n\r\n');
      assert.ok(chunkedSplitIdx > 0, '400KiB chunked POST 应返回完整响应头');
      assert.match(chunkedResp.slice(0, chunkedSplitIdx), /^HTTP\/1\.1 200 /);
      assert.equal(
        chunkedResp.slice(chunkedSplitIdx + 4).length,
        chunked400kBody.length,
        '触发 256KiB 握手背压暂停后 400KiB chunked POST 请求体不得被 req.complete 过早截断'
      );
      assert.equal(chunkedResp.slice(chunkedSplitIdx + 4), chunked400kBody);
    } finally {
      slowBodyBridge.close();
    }

    // 7b2b. 客户端在 DNS 等待期间正常关闭必须立即取消 DNS 并释放预连接上游套接字
    const cancelUpstreamSockets = new Set<net.Socket>();
    let cancelUpstreamOpenCount = 0;
    let cancelUpstreamClosedAt = 0;
    const cancelUpstream = net.createServer((sock) => {
      cancelUpstreamSockets.add(sock);
      cancelUpstreamOpenCount++;
      sock.on('error', () => sock.destroy());
      sock.once('close', () => {
        cancelUpstreamSockets.delete(sock);
        cancelUpstreamClosedAt = Date.now();
      });
    });
    const cancelUpstreamPort = await listen(cancelUpstream, '127.0.0.1');
    let cancelDnsAbortedAt = 0;
    const cancelBridge = new Ipv4ProxyBridge({
      getUpstreamTarget: () => ({ status: 'ready', port: cancelUpstreamPort }),
      resolveIpv4: (_hostname, signal) =>
        new Promise((_resolve, reject) => {
          const timer = setTimeout(
            () => reject(new Error('DNS 未被及时取消')),
            8000
          );
          timer.unref?.();
          signal?.addEventListener(
            'abort',
            () => {
              clearTimeout(timer);
              cancelDnsAbortedAt = Date.now();
              reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
            },
            { once: true }
          );
        }),
    });
    try {
      const cancelBridgePort = await cancelBridge.ensureStarted();
      const connectCancelClient = net.connect(cancelBridgePort, '127.0.0.1', () => {
        connectCancelClient.write(
          'CONNECT slow-cancel.claude.test:443 HTTP/1.1\r\nHost: slow-cancel.claude.test:443\r\n\r\nearly-payload'
        );
      });
      const waitOpen1 = Date.now() + 2000;
      while (cancelUpstreamOpenCount < 1 && Date.now() < waitOpen1) await delay(15);
      assert.equal(cancelUpstreamOpenCount, 1, 'CONNECT 握手应已并发建立上游预连接');
      const connectClosedAt = Date.now();
      connectCancelClient.end();
      const waitAbort1 = Date.now() + 1500;
      while (
        (!cancelDnsAbortedAt || !cancelUpstreamClosedAt) &&
        Date.now() < waitAbort1
      ) {
        await delay(15);
      }
      assert.ok(cancelDnsAbortedAt > 0, 'CONNECT 客户端关闭后必须立即取消在途 DNS 解析');
      assert.ok(
        cancelUpstreamClosedAt > 0,
        'CONNECT 客户端关闭后必须立即销毁上游预连接套接字'
      );
      assert.ok(
        cancelUpstreamClosedAt - connectClosedAt < 1000,
        `CONNECT 取消释放上游套接字耗时过长 (${
          cancelUpstreamClosedAt - connectClosedAt
        }ms)`
      );
      connectCancelClient.destroy();

      cancelDnsAbortedAt = 0;
      cancelUpstreamClosedAt = 0;
      const postCancelClient = net.connect(cancelBridgePort, '127.0.0.1', () => {
        postCancelClient.write(
          'POST http://slow-post-cancel.claude.test/echo HTTP/1.1\r\nHost: slow-post-cancel.claude.test\r\nContent-Length: 200\r\n\r\npartial-body'
        );
      });
      const waitOpen2 = Date.now() + 2000;
      while (cancelUpstreamOpenCount < 2 && Date.now() < waitOpen2) await delay(15);
      assert.equal(cancelUpstreamOpenCount, 2, '明文 POST 握手应已并发建立上游预连接');
      const postClosedAt = Date.now();
      postCancelClient.end();
      const waitAbort2 = Date.now() + 1500;
      while (
        (!cancelDnsAbortedAt || !cancelUpstreamClosedAt) &&
        Date.now() < waitAbort2
      ) {
        await delay(15);
      }
      assert.ok(
        cancelDnsAbortedAt > 0,
        '明文 POST 客户端提前关闭后必须立即取消在途 DNS 解析'
      );
      assert.ok(
        cancelUpstreamClosedAt > 0,
        '明文 POST 客户端提前关闭后必须立即销毁上游预连接套接字'
      );
      assert.ok(
        cancelUpstreamClosedAt - postClosedAt < 1000,
        `明文 POST 取消释放上游套接字耗时过长 (${
          cancelUpstreamClosedAt - postClosedAt
        }ms)`
      );
      postCancelClient.destroy();
    } finally {
      cancelBridge.close();
      for (const s of cancelUpstreamSockets) s.destroy();
      await new Promise<void>((resolve) => cancelUpstream.close(() => resolve()));
    }

    // 7b3. 并发预连接在等待 DNS 期间遭上游重置时自动重连成功
    let flakyConnCount = 0;
    const flakySockets = new Set<net.Socket>();
    const flakyUpstream = net.createServer((client) => {
      flakySockets.add(client);
      flakyConnCount++;
      if (flakyConnCount === 1) {
        setTimeout(() => {
          if (!client.destroyed) client.resetAndDestroy();
        }, 15);
        client.once('close', () => flakySockets.delete(client));
        return;
      }
      const up = net.connect(internalPort, '127.0.0.1');
      client.pipe(up);
      up.pipe(client);
      up.on('error', () => client.destroy());
      client.on('error', () => up.destroy());
      client.once('close', () => {
        up.destroy();
        flakySockets.delete(client);
      });
    });
    const flakyUpstreamPort = await listen(flakyUpstream, '127.0.0.1');
    const flakyBridge = new Ipv4ProxyBridge({
      getUpstreamTarget: () => ({ status: 'ready', port: flakyUpstreamPort }),
      resolveIpv4: async (hostname, signal) => {
        await delay(120, undefined, { signal });
        return svc.channels.claude.resolveIpv4(hostname, signal);
      },
    });
    try {
      const flakyBridgePort = await flakyBridge.ensureStarted();
      const flakyResp = await requestTextViaProxy(
        'http://claude.ai/hello',
        `http://127.0.0.1:${flakyBridgePort}`,
        6000
      );
      assert.equal(
        flakyResp,
        'plain-http-ipv4-ok',
        '预连接在 DNS 等待期间被上游重置后应自动重连并成功'
      );
      assert.ok(
        flakyConnCount >= 2,
        `应检测到首连接重置并重连上游，实际连接数 ${flakyConnCount}`
      );
    } finally {
      flakyBridge.close();
      for (const s of flakySockets) s.destroy();
      await new Promise<void>((resolve) => flakyUpstream.close(() => resolve()));
    }

    // 7b4. 建连后写出 CONNECT 前世代变化（TOCTOU 防护）与候选循环核验失败时预连接立即销毁
    let toctouBytesReceived = 0;
    let toctouClosedAt = 0;
    let toctouGen = 1;
    const toctouSockets = new Set<net.Socket>();
    const toctouUpstream = net.createServer((sock) => {
      toctouSockets.add(sock);
      toctouGen++;
      sock.on('data', (buf) => {
        toctouBytesReceived += buf.length;
      });
      sock.on('error', () => sock.destroy());
      sock.once('close', () => {
        toctouSockets.delete(sock);
        toctouClosedAt = Date.now();
      });
    });
    const toctouUpstreamPort = await listen(toctouUpstream, '127.0.0.1');
    const toctouBridge = new Ipv4ProxyBridge({
      getUpstreamTarget: async (_signal) => {
        await delay(15);
        return { status: 'ready', port: toctouUpstreamPort, generation: toctouGen };
      },
      resolveIpv4: (hostname, signal) =>
        svc.channels.claude.resolveIpv4(hostname, signal),
    });
    try {
      const toctouBridgePort = await toctouBridge.ensureStarted();
      await assert.rejects(
        requestTextViaProxy(
          'https://160.79.104.10/',
          `http://127.0.0.1:${toctouBridgePort}`,
          4000
        ),
        /503/,
        '建连后世代/归属发生变化时必须返回 503 阻断转发'
      );
      const waitToctouClose = Date.now() + 1000;
      while (!toctouClosedAt && Date.now() < waitToctouClose) await delay(15);
      assert.equal(
        toctouBytesReceived,
        0,
        '建连后归属二次核验失败前绝不可向对端写出任何目标地址字节'
      );
    } finally {
      toctouBridge.close();
      for (const s of toctouSockets) s.destroy();
      await new Promise<void>((resolve) => toctouUpstream.close(() => resolve()));
    }

    let preconnFailClosedAt = 0;
    let preconnTargetCalls = 0;
    const preconnFailSockets = new Set<net.Socket>();
    const preconnFailUpstream = net.createServer((sock) => {
      preconnFailSockets.add(sock);
      sock.on('error', () => sock.destroy());
      sock.once('close', () => {
        preconnFailSockets.delete(sock);
        preconnFailClosedAt = Date.now();
      });
    });
    const preconnFailUpstreamPort = await listen(preconnFailUpstream, '127.0.0.1');
    const preconnFailBridge = new Ipv4ProxyBridge({
      getUpstreamTarget: () => {
        preconnTargetCalls++;
        if (preconnTargetCalls <= 2) {
          return { status: 'ready', port: preconnFailUpstreamPort, generation: 1 };
        }
        return { status: 'blocked', reason: '最终核验阻断' };
      },
      resolveIpv4: (hostname, signal) =>
        svc.channels.claude.resolveIpv4(hostname, signal),
    });
    try {
      const preconnFailPort = await preconnFailBridge.ensureStarted();
      const startedAt = Date.now();
      await assert.rejects(
        requestTextViaProxy(
          'https://claude.ai/cdn-cgi/trace',
          `http://127.0.0.1:${preconnFailPort}`,
          4000
        ),
        /503/
      );
      const waitClose = Date.now() + 1000;
      while (!preconnFailClosedAt && Date.now() < waitClose) await delay(15);
      assert.ok(
        preconnFailClosedAt > 0,
        '候选循环最终核验失败时已交接的 preconnectedSocket 必须立即销毁'
      );
      assert.ok(
        preconnFailClosedAt - startedAt < 1500,
        'preconnectedSocket 应在错误返回时立即销毁而非等待超时'
      );
    } finally {
      preconnFailBridge.close();
      for (const s of preconnFailSockets) s.destroy();
      await new Promise<void>((resolve) =>
        preconnFailUpstream.close(() => resolve())
      );
    }

    // 7c. CNAME 链解析
    vlessTargets.length = 0;
    const cnameRes = await svc.channels.claude.resolveIpv4('cname.claude.test');
    assert.deepEqual(cnameRes.ips, ['198.51.100.42']);
    const cnameBody = await requestTextViaProxy(
      'http://cname.claude.test/check',
      publicHttpUrl,
      6000
    );
    assert.equal(cnameBody, 'plain-http-ipv4-ok');
    assert.equal(vlessTargets[0]?.atyp, 1);
    assert.equal(vlessTargets[0]?.addr, '198.51.100.42');

    // 7d. 拦截 IPv6 字面量与纯 IPv6 域名
    vlessTargets.length = 0;
    rig.state.ipv6OriginHits = 0;
    await assert.rejects(
      requestTextViaProxy('https://[2607:6bc0::10]/', publicHttpUrl, 4000),
      /403/,
      '公开端口 HTTP CONNECT 公网 IPv6 字面量必须被 403 拦截'
    );
    await assert.rejects(
      requestTextViaProxy('https://[2607:6bc0::10]/', publicSocksUrl, 4000),
      /NotAllowed|0x02|not allowed|rejected/i,
      '公开端口 SOCKS5 公网 IPv6 目标必须被规则拦截'
    );
    await assert.rejects(
      requestTextViaProxy('http://v6only.claude.test/', publicHttpUrl, 4000),
      /502/,
      '公开端口无 A 记录的纯 IPv6 域名必须 Fail-Closed 拒绝，不得回退发送域名'
    );
    await assert.rejects(
      requestTextViaProxy(
        'https://[2607:6bc0::10]/',
        `http://127.0.0.1:${internalPort}`,
        4000
      ),
      /./,
      '内部 Mihomo 端口的公网 IPv6 字面量必须被 IP-CIDR6,::/0,REJECT 拦截'
    );
    assert.equal(
      vlessTargets.length,
      0,
      '任何被拦截的 IPv6 请求都不得抵达 VLESS 服务端'
    );
    assert.equal(
      rig.state.ipv6OriginHits,
      0,
      '强制 IPv4 模式下不得有任何流量抵达 IPv6 源站'
    );

    // 7e. 真实隔离 Electron 客户端回归
    const rawFs = getRawFs();
    const isolatedClientDir = path.join(ipv4Root, 'isolated-claude-client');
    rawFs.cpSync(path.dirname(process.execPath), isolatedClientDir, {
      recursive: true,
    });
    rawFs.rmSync(path.join(isolatedClientDir, 'resources', 'default_app.asar'), {
      force: true,
    });
    const isolatedAppDir = path.join(isolatedClientDir, 'resources', 'app');
    rawFs.mkdirSync(isolatedAppDir, { recursive: true });
    const isolatedExe = path.join(isolatedClientDir, 'guard-test-client.exe');
    rawFs.renameSync(path.join(isolatedClientDir, 'electron.exe'), isolatedExe);
    const isolatedReportPath = path.join(ipv4Root, 'isolated-client-report.json');
    const isolatedUserData = path.join(ipv4Root, 'isolated-client-userdata');
    rawFs.writeFileSync(
      path.join(isolatedAppDir, 'package.json'),
      JSON.stringify({
        name: 'guard-test-client',
        version: '1.0.0',
        main: 'main.cjs',
      }),
      'utf8'
    );
    rawFs.writeFileSync(
      path.join(isolatedAppDir, 'main.cjs'),
      `
const { app } = require('electron');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');

app.setPath('userData', ${JSON.stringify(isolatedUserData)});
const reportPath = ${JSON.stringify(isolatedReportPath)};

function httpGetViaHttpProxy(proxyStr, targetUrl) {
  return new Promise((resolve, reject) => {
    const p = new URL(proxyStr);
    const req = http.request({
      host: p.hostname,
      port: Number(p.port),
      method: 'GET',
      path: targetUrl,
      headers: { Host: new URL(targetUrl).host, Connection: 'close' },
      agent: false,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end();
  });
}

function httpGetViaSocks5h(proxyStr, host, port, pathStr) {
  return new Promise((resolve, reject) => {
    const p = new URL(proxyStr);
    const sock = net.connect(Number(p.port), p.hostname, () => {
      sock.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    let stage = 0;
    const respChunks = [];
    sock.on('data', (chunk) => {
      if (stage === 0) {
        if (chunk.length < 2 || chunk[0] !== 0x05 || chunk[1] !== 0x00) {
          reject(new Error('socks5 greeting failed'));
          sock.destroy();
          return;
        }
        stage = 1;
        const hostBuf = Buffer.from(host, 'utf8');
        const portBuf = Buffer.alloc(2);
        portBuf.writeUInt16BE(port, 0);
        sock.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]), hostBuf, portBuf]));
      } else if (stage === 1) {
        if (chunk.length < 2 || chunk[0] !== 0x05 || chunk[1] !== 0x00) {
          reject(new Error('socks5 connect failed: ' + chunk[1]));
          sock.destroy();
          return;
        }
        stage = 2;
        sock.write('GET ' + pathStr + ' HTTP/1.1\\r\\nHost: ' + host + '\\r\\nConnection: close\\r\\n\\r\\n');
      } else {
        respChunks.push(chunk);
      }
    });
    sock.on('error', reject);
    sock.on('end', () => {
      const text = Buffer.concat(respChunks).toString('utf8');
      const idx = text.indexOf('\\r\\n\\r\\n');
      resolve({ rawHeader: idx > 0 ? text.slice(0, idx) : '', body: idx > 0 ? text.slice(idx + 4) : text });
    });
  });
}

app.whenReady().then(async () => {
  try {
    const httpRes = await httpGetViaHttpProxy(process.env.HTTP_PROXY, 'http://claude.ai/hello');
    const socksRes = await httpGetViaSocks5h(process.env.ALL_PROXY, 'claude.ai', 80, '/hello');
    const payload = {
      pid: process.pid,
      argv: process.argv,
      env: {
        HTTP_PROXY: process.env.HTTP_PROXY,
        HTTPS_PROXY: process.env.HTTPS_PROXY,
        ALL_PROXY: process.env.ALL_PROXY,
        all_proxy: process.env.all_proxy,
        NO_PROXY: process.env.NO_PROXY,
      },
      httpRes,
      socksRes,
    };
    fs.writeFileSync(reportPath + '.tmp', JSON.stringify(payload), 'utf8');
    fs.renameSync(reportPath + '.tmp', reportPath);
  } catch (err) {
    fs.writeFileSync(reportPath + '.tmp', JSON.stringify({ pid: process.pid, error: String(err) }), 'utf8');
    fs.renameSync(reportPath + '.tmp', reportPath);
  } finally {
    app.exit(0);
  }
});
`,
      'utf8'
    );
    vlessTargets.length = 0;
    const spawnRes = await spawnClaudeWithDedicatedProxy(
      isolatedExe,
      null,
      publicHttpUrl
    );
    assert.equal(spawnRes.ok, true, `真实隔离客户端启动应成功: ${spawnRes.error}`);
    const reportDeadline = Date.now() + 15000;
    while (!fs.existsSync(isolatedReportPath) && Date.now() < reportDeadline) {
      await delay(50);
    }
    assert.ok(
      fs.existsSync(isolatedReportPath),
      '隔离客户端应完成真实代理请求并写出报告'
    );
    const clientReport = JSON.parse(
      fs.readFileSync(isolatedReportPath, 'utf8')
    ) as {
      pid: number;
      error?: string;
      argv?: string[];
      env?: Record<string, string | undefined>;
      httpRes?: { status: number; body: string };
      socksRes?: { rawHeader: string; body: string };
    };
    isolatedClientPid = clientReport.pid;
    assert.equal(
      clientReport.error,
      undefined,
      `隔离客户端代理请求出错：${clientReport.error}`
    );
    assert.ok(
      clientReport.argv?.includes(`--proxy-server=${publicHttpUrl}`),
      `客户端命令行必须注入公开专属端口 --proxy-server=${publicHttpUrl}`
    );
    assert.ok(clientReport.argv?.includes('--proxy-bypass-list=<-loopback>'));
    assert.ok(
      clientReport.argv?.includes(
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'
      )
    );
    assert.equal(clientReport.env?.HTTP_PROXY, publicHttpUrl);
    assert.equal(clientReport.env?.HTTPS_PROXY, publicHttpUrl);
    assert.equal(
      clientReport.env?.ALL_PROXY,
      publicSocksUrl,
      'ALL_PROXY 必须使用 socks5h:// 以交由桥接器解析域名'
    );
    assert.equal(clientReport.env?.all_proxy, publicSocksUrl);
    assert.equal(clientReport.env?.NO_PROXY, 'localhost,127.0.0.1,::1');
    assert.equal(clientReport.httpRes?.status, 200);
    assert.equal(clientReport.httpRes?.body, 'plain-http-ipv4-ok');
    assert.match(clientReport.socksRes?.rawHeader || '', /^HTTP\/1\.1 200 /);
    assert.equal(clientReport.socksRes?.body, 'plain-http-ipv4-ok');
    assert.equal(
      vlessTargets.length,
      2,
      '真实客户端的 HTTP 与 SOCKS5h 请求均应抵达 VLESS 服务端'
    );
    for (const target of vlessTargets) {
      assert.equal(
        target.atyp,
        1,
        `真实客户端流量经公开端口转发后 VLESS 必须收到 ATYP=1 IPv4，实际 ${JSON.stringify(
          target
        )}`
      );
      assert.equal(target.addr, '160.79.104.10');
    }

    // 8. 验证内部 Mihomo mixed-port 关闭时，公开端口桥接回传本地 ECONNREFUSED 并触发自动重绑恢复
    await mihomoRequest(lease.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
    const dropDeadline = Date.now() + 3000;
    while (
      (await isLocalPortListening(internalPort)) &&
      Date.now() < dropDeadline
    ) {
      await delay(30);
    }
    assert.equal(await isLocalPortListening(internalPort), false);
    let refusedErr: unknown = null;
    try {
      await requestTextViaProxy(
        'https://claude.ai/cdn-cgi/trace',
        publicHttpUrl,
        5000
      );
    } catch (err) {
      refusedErr = err;
    }
    assert.ok(refusedErr, '内部端口关闭时公开端口桥接请求必须失败');
    assert.equal(
      isLocalProxyRefusedCause(refusedErr, publicHttpUrl),
      true,
      `公开端口桥接回传的上游拒绝必须被识别为本地代理拒绝: ${refusedErr}`
    );

    let rebindCount = 0;
    const onRebind = () => rebindCount++;
    svc.channels.claude.on('ready', onRebind);
    try {
      const recoveredSnap = await engine.probeClaudeNodeNow(
        'IPv4 桥接上游拒绝自动重绑',
        true
      );
      assert.equal(
        rebindCount,
        1,
        '经由公开端口 IPv4 桥接遇到上游拒绝后必须自动触发私有内核重绑'
      );
      assert.equal(await isLocalPortListening(internalPort), true);
      assert.ok(
        recoveredSnap.claudeState.nodeProbe &&
          getTargetServiceVerificationError(
            recoveredSnap.claudeState.nodeProbe,
            'claude'
          ) === null,
        `重绑后探测应恢复通过: err=${recoveredSnap.claudeState.nodeProbeError}`
      );
    } finally {
      svc.channels.claude.off('ready', onRebind);
    }

    // 8b. 验证两类端口归属未确认场景在转发前实时 Fail-Closed 阻断
    await mihomoRequest(lease.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
    const dropForHijackDeadline = Date.now() + 3000;
    while (
      (await isLocalPortListening(internalPort)) &&
      Date.now() < dropForHijackDeadline
    ) {
      await delay(30);
    }
    let hijackHits = 0;
    const hijackServer = net.createServer((sock) => {
      hijackHits++;
      sock.destroy();
    });
    hijackServer.listen(internalPort, '127.0.0.1');
    await once(hijackServer, 'listening');
    try {
      assert.equal(
        svc.channels.claude.getState().phase,
        'ready',
        '模拟健康检查尚未跑到的空窗期'
      );
      let literalBlockedErr: unknown = null;
      try {
        await requestTextViaProxy(
          'http://160.79.104.10/hijack-live',
          publicHttpUrl,
          5000
        );
      } catch (err) {
        literalBlockedErr = err;
      }
      assert.ok(
        literalBlockedErr,
        '空窗期内部端口被抢占时 IPv4 字面量请求必须被实时阻断'
      );
      assert.match(String(literalBlockedErr), /503/);
      assert.equal(
        isLocalProxyRefusedCause(literalBlockedErr, publicHttpUrl),
        false,
        '端口冲突阻断的 503 不应伪装为上游 ECONNREFUSED'
      );
      assert.equal(
        svc.channels.claude.getState().phase,
        'error',
        '转发前实时核验发现内部端口被抢占后必须立即将通道切入 error 冲突态'
      );
      await assert.rejects(
        requestTextViaProxy(
          'https://160.79.104.10/hijack-live',
          publicHttpUrl,
          4000
        ),
        /503/
      );
      assert.equal(
        hijackHits,
        0,
        '端口归属冲突空窗期内任何请求（含 IPv4 字面量）绝不得向抢占进程发出任何连接'
      );
    } finally {
      await new Promise<void>((resolve) => hijackServer.close(() => resolve()));
    }
    assert.equal(await svc.channels.claude.recoverListenerIfNeeded(), 'rebound');
    assert.equal(svc.channels.claude.getState().phase, 'ready');
    assert.equal(
      await requestTextViaProxy('http://claude.ai/hello', publicHttpUrl, 5000),
      'plain-http-ipv4-ok',
      '端口归属恢复后公开端口桥接应自动恢复转发'
    );

    // 在纯内核与桥接层归属/世代测试期间暂停 ProbeEngine 自动恢复重测，防止后台并发探测流量干扰桥接计数与重绑时序
    store.update({ selectedClashNode: null });
    engine.claude.abortActiveProbe('暂停后台重测以执行桥接归属与世代单测');
    try {
      // 8b(b). 真实归属复核失败（PortOwnershipLookupError 与转发期 /configs 异常）保留 ready 期间：
      //        公开端口桥接必须清除归属确认标记并持续 Fail-Closed 阻断，直到 checkReady 重新确认归属
      const savedPathEnv = process.env.PATH;
      try {
        process.env.PATH = '';
        assert.equal(
          await svc.channels.claude.recoverListenerIfNeeded(),
          'failed',
          '真实端口归属查询失败时 recoverListenerIfNeeded 应返回 failed'
        );
        await svc.channels.claude.serial(async () => {
          vlessTargets.length = 0;
          assert.equal(
            svc.channels.claude.getState().phase,
            'ready',
            '端口归属查询失败但进程存活时内核保持 ready'
          );
          assert.match(
            svc.channels.claude.getState().verificationError || '',
            /监听归属复核未完成/,
            '应记录真实的端口归属复核未完成错误'
          );
          await assert.rejects(
            requestTextViaProxy(
              'http://160.79.104.10/unverified-owner',
              publicHttpUrl,
              4000
            ),
            /503/,
            '真实归属复核失败清除确认标记后，公开端口桥接必须返回 503 阻断转发'
          );
          assert.equal(
            vlessTargets.length,
            0,
            '归属未确认期间不得有任何流量转发至上游内核'
          );
        });
      } finally {
        process.env.PATH = savedPathEnv;
      }
      await svc.channels.claude.checkReady();
      svc.channels.claude.clearForwardingError();
      assert.equal(
        await requestTextViaProxy('http://claude.ai/hello', publicHttpUrl, 5000),
        'plain-http-ipv4-ok',
        '重新确认归属后公开端口应恢复转发'
      );

      // 持有 PrivateKernel.serial 队列，防止 3s 后台健康巡检在恢复 rule 与发送断言请求之间抢先复核归属或发起转发探测
      await svc.channels.claude.serial(async () => {
        vlessTargets.length = 0;
        await mihomoRequest(lease.endpoint, '/configs', 'PATCH', { mode: 'direct' });
        await assert.rejects(
          requestTextViaProxy(
            'http://160.79.104.10/mode-mismatch-trigger',
            publicHttpUrl,
            4000
          ),
          /503/,
          '转发前核验发现运行配置异常时必须立即返回 503 并清除归属确认标记'
        );
        await mihomoRequest(lease.endpoint, '/configs', 'PATCH', { mode: 'rule' });
        assert.equal(svc.channels.claude.getState().phase, 'ready');
        await assert.rejects(
          requestTextViaProxy(
            'http://160.79.104.10/still-unverified-after-restore',
            publicHttpUrl,
            4000
          ),
          /503/,
          '配置恢复后在重新完成端口归属核验前，桥接仍必须保持 503 阻断'
        );
        assert.equal(
          vlessTargets.length,
          0,
          '归属重新确认前不得有任何流量抵达上游'
        );
      });
      await svc.channels.claude.checkReady();
      assert.equal(
        await requestTextViaProxy('http://claude.ai/hello', publicHttpUrl, 5000),
        'plain-http-ipv4-ok',
        'checkReady 重新核验归属后公开端口应恢复转发'
      );

      // 8b(c). 通过真实私有内核同进程监听重绑触发世代递增，从公开代理端口验证旧世代请求被 503 阻断且未转发
      plainHostHeaders.length = 0;
      const genBeforeRebind = svc.channels.claude.getState().generation;
      const pidBeforeRebind = svc.channels.claude.getState().pid!;
      let releaseVerifyForwarding = null as (() => void) | null;
      const verifyForwardingGate = new Promise<void>((resolve) => {
        releaseVerifyForwarding = resolve;
      });
      let staleReqPromise = null as Promise<{ statusCode: number; body: string }> | null;
      let rebindPromise = null as Promise<'rebound' | 'already-ready' | 'failed'> | null;
      rig.state.onTraceRequest = async () => {
        if (!staleReqPromise) {
          staleReqPromise = new Promise<{ statusCode: number; body: string }>(
            (resolve, reject) => {
              const req = http.get(
                {
                  host: '127.0.0.1',
                  port: claudePort,
                  path: 'http://gen-rebind.claude.test/stale-gen',
                  headers: {
                    Host: 'gen-rebind.claude.test',
                    Connection: 'close',
                  },
                },
                (res) => {
                  const chunks: Buffer[] = [];
                  res.on('data', (chunk: Buffer) => chunks.push(chunk));
                  res.on('end', () => {
                    resolve({
                      statusCode: res.statusCode ?? 0,
                      body: Buffer.concat(chunks).toString('utf8'),
                    });
                  });
                }
              );
              req.setTimeout(10000, () => req.destroy(new Error('单次旧世代代理请求超时')));
              req.once('error', reject);
            }
          );
        }
        await verifyForwardingGate;
      };
      rig.state.onDnsQuery = async (qname, qtype) => {
        if (qname !== 'gen-rebind.claude.test' || qtype !== 1) {
          return;
        }
        releaseVerifyForwarding?.();
        await rebindPromise;
      };
      try {
        await mihomoRequest(lease.endpoint, '/configs', 'PATCH', { 'mixed-port': 0 });
        const waitDrop = Date.now() + 3000;
        while ((await isLocalPortListening(internalPort)) && Date.now() < waitDrop) {
          await delay(25);
        }
        rebindPromise = svc.channels.claude.recoverListenerIfNeeded();
        const rebindOutcome = await rebindPromise;
        assert.equal(
          rebindOutcome,
          'rebound',
          `真实私有内核应完成同进程监听重绑并递增 generation，当前状态=${JSON.stringify(svc.channels.claude.getState())}`
        );
        assert.ok(staleReqPromise !== null, '应在重绑转发校验窗口内发起真实公开端口请求');
        const staleGenRes = await staleReqPromise!;
        assert.equal(
          staleGenRes.statusCode,
          503,
          `跨越真实私有内核重绑世代递增的单次在途公开端口请求必须返回 503 阻断，实际状态码=${staleGenRes.statusCode} body=${staleGenRes.body}`
        );
        assert.match(
          staleGenRes.body,
          /世代/,
          `503 响应体应明确反映内核世代变更阻断，实际 body=${staleGenRes.body}`
        );
        assert.equal(
          svc.channels.claude.getState().pid,
          pidBeforeRebind,
          '监听重绑应保持同一真实 guard-mihomo.exe 进程存活'
        );
        assert.ok(
          svc.channels.claude.getState().generation > genBeforeRebind,
          `重绑后真实内核世代应递增 (${genBeforeRebind} -> ${svc.channels.claude.getState().generation})`
        );
        assert.equal(
          plainHostHeaders.some((h) => h.toLowerCase().includes('gen-rebind.claude.test')),
          false,
          '旧世代请求被阻断后绝不得转发至目标源站'
        );
        assert.equal(
          await requestTextViaProxy(
            'http://gen-rebind.claude.test/fresh-gen',
            publicHttpUrl,
            5000
          ),
          'plain-http-ipv4-ok',
          '新世代下发起的新请求应正常转发通过'
        );
      } finally {
        releaseVerifyForwarding?.();
        rig.state.onTraceRequest = null;
        rig.state.onDnsQuery = null;
      }
    } finally {
      store.update({
        selectedClashNode: '双栈VLESS测试节点',
        selectedClashProfileUid: 'vless-prof',
        selectedClashProfileName: 'VLESS IPv4 测试订阅',
      });
    }

    // 9. 安全判定与运行期 IPv6 熔断校验
    engine.claude.detectedExe = isolatedExe;
    engine.winLocale = {
      timeZoneId: 'Tokyo Standard Time',
      timeZoneDisplayName: '(UTC+09:00) 大阪，札幌，东京',
      regionCode: 'JP',
      regionName: '日本',
    };
    const ipv4OkBeforeV6 = await engine.probeClaudeNodeNow(
      '恢复后确认 IPv4 出口可启动',
      true
    );
    assert.equal(
      ipv4OkBeforeV6.claudeState.canLaunch,
      true,
      `IPv4 出口且地区时区一致时应允许启动: blockReason=${ipv4OkBeforeV6.claudeState.launchBlockReason}`
    );

    rig.state.traceReplyIp = expectedIpv6Exit;
    const ipv6ForcedFailSnap = await engine.probeClaudeNodeNow(
      '远端仍返回 IPv6 出口 Fail-Closed 拦截',
      true
    );
    assert.equal(
      ipv6ForcedFailSnap.claudeState.nodeProbe?.claudeTraceIp,
      expectedIpv6Exit
    );
    assert.equal(
      ipv6ForcedFailSnap.claudeState.canLaunch,
      false,
      '开启强制 IPv4 出站但远端仍返回 IPv6 时必须禁止启动 Claude'
    );
    assert.match(ipv6ForcedFailSnap.claudeState.launchBlockReason || '', /IPv6/);

    store.update({ claudeLockExitIp: false });
    engine.claude.running = true;
    try {
      const runtimeIpv6Safety = engine.evaluateClaudeSafety(true);
      assert.equal(
        runtimeIpv6Safety.safe,
        false,
        '运行期关闭出口 IP 锁定但开启强制 IPv4 时遇到 IPv6 必须判为不安全'
      );
      assert.equal(runtimeIpv6Safety.alertType, 'ip-change');
      assert.match(runtimeIpv6Safety.reason, /IPv6/);
    } finally {
      engine.claude.running = false;
      store.update({ claudeLockExitIp: true });
      rig.state.traceReplyIp = expectedIpv4Exit;
    }

    // 9b(a). 运行中 Claude 且未传 confirmTerminateClaude -> 拒绝切换
    const pidBeforeConfirmReject = svc.channels.claude.getState().pid;
    engine.claude.running = true;
    try {
      await assert.rejects(
        engine.updateConfig({ claudeForceIpv4: false }),
        /CLAUDE_RUNNING_CONFIRM_REQUIRED/,
        '存在运行中的 Claude 且未显式确认时，切换 IPv4 模式必须要求确认而非静默强杀'
      );
      assert.equal(store.get().claudeForceIpv4, true);
      assert.equal(svc.channels.claude.getIpv4Only(), true);
      assert.equal(svc.channels.claude.getState().pid, pidBeforeConfirmReject);
    } finally {
      engine.claude.running = false;
    }

    // 未绑定节点时切换 claudeForceIpv4
    const unboundStore = new ConfigStore();
    unboundStore.update({
      selectedClashNode: null,
      selectedClashProfileUid: null,
      selectedClashProfileName: null,
      claudeForceIpv4: true,
      claudeExclusiveGuard: false,
      killProcessesEnabled: false,
    });
    const unboundEngine = new ProbeEngine(
      unboundStore,
      geo,
      new ClashMonitor(vergeDir),
      svc
    );
    try {
      unboundEngine.claude.running = true;
      const toggledUnbound = await unboundEngine.updateConfig({
        claudeForceIpv4: false,
      });
      assert.equal(
        toggledUnbound.claudeForceIpv4,
        false,
        '未绑定专属节点时切换 IPv4 开关无需重建通道也不应要求终止 Claude'
      );
    } finally {
      unboundEngine.stop();
    }

    // 9b(b). 端口被占用失败 + 纯 IPv4 切换绝不向外部 Clash Verge 控制接口写入配置
    const blockedPort = await freePort();
    const portBlocker = net.createServer((s) => s.destroy());
    portBlocker.listen(blockedPort, '127.0.0.1');
    await once(portBlocker, 'listening');
    try {
      await assert.rejects(
        engine.updateConfig({
          claudeForceIpv4: false,
          dedicatedProxyPort: blockedPort,
        }),
        /已被其他进程占用/,
        '端口被占用导致私有内核重建失败时 updateConfig 必须显式报错'
      );
      assert.equal(
        store.get().claudeForceIpv4,
        true,
        '端口占用失败后 claudeForceIpv4 必须保持原值 true'
      );
      assert.equal(
        store.get().dedicatedProxyPort,
        claudePort,
        '端口占用失败后专属端口必须保持原值'
      );
      assert.equal(
        svc.channels.claude.getIpv4Only(),
        true,
        '原私有内核应保持 ipv4Only=true 不受破坏'
      );
      assert.equal(svc.channels.claude.getState().phase, 'ready');
    } finally {
      await new Promise<void>((resolve) => portBlocker.close(() => resolve()));
    }

    let legacyClashPutCount = 0;
    const legacyClashApi = http.createServer((req, res) => {
      if (req.method === 'PUT' && (req.url || '').startsWith('/configs')) {
        legacyClashPutCount++;
      }
      if (req.method === 'GET' && req.url === '/proxies') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            proxies: {
              __guard_claude_dedicated_proxy__: {
                type: 'Selector',
                now: 'DIRECT',
              },
            },
          })
        );
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ mode: 'rule' }));
    });
    const legacyClashApiPort = await listen(legacyClashApi, '127.0.0.1');
    const legacyVergeDir = path.join(ipv4Root, 'legacy-clash-verge');
    fs.mkdirSync(path.join(legacyVergeDir, 'profiles'), { recursive: true });
    fs.copyFileSync(
      path.join(vergeDir, 'profiles.yaml'),
      path.join(legacyVergeDir, 'profiles.yaml')
    );
    fs.copyFileSync(
      path.join(vergeDir, 'profiles', 'vless.yaml'),
      path.join(legacyVergeDir, 'profiles', 'vless.yaml')
    );
    fs.writeFileSync(
      path.join(legacyVergeDir, 'clash-verge.yaml'),
      yaml.dump({
        'external-controller': `127.0.0.1:${legacyClashApiPort}`,
        secret: '',
      }),
      'utf8'
    );
    const noLegacyKernelDir = path.join(ipv4Root, 'no-legacy-kernels');
    const noLegacySvc = trackService(
      new PrivateProxyService(noLegacyKernelDir, coreDir)
    );
    const noLegacyPort = await freePort();
    const noLegacyBlocker = net.createServer((s) => s.destroy());
    noLegacyBlocker.listen(noLegacyPort, '127.0.0.1');
    await once(noLegacyBlocker, 'listening');
    try {
      const noLegacyStore = new ConfigStore();
      noLegacyStore.update({
        selectedClashNode: '双栈VLESS测试节点',
        selectedClashProfileUid: 'vless-prof',
        selectedClashProfileName: 'VLESS IPv4 测试订阅',
        dedicatedProxyPort: noLegacyPort,
        claudeForceIpv4: true,
        claudeExclusiveGuard: false,
        killProcessesEnabled: false,
      });
      const noLegacyEngine = new ProbeEngine(
        noLegacyStore,
        geo,
        new ClashMonitor(legacyVergeDir),
        noLegacySvc
      );
      try {
        await assert.rejects(
          noLegacyEngine.updateConfig({ claudeForceIpv4: false }),
          /已被其他进程占用/,
          '纯 IPv4 切换遇到端口占用应直接报错'
        );
        assert.equal(
          legacyClashPutCount,
          0,
          '任何配置切换绝不得写入外部 Clash Verge 控制接口'
        );
      } finally {
        noLegacyEngine.stop();
      }
    } finally {
      await noLegacySvc.shutdown();
      untrackService(noLegacySvc);
      await new Promise<void>((resolve) => noLegacyBlocker.close(() => resolve()));
      await new Promise<void>((resolve) => legacyClashApi.close(() => resolve()));
    }

    // 9b(c). current.json 提交失败 -> 原子回滚
    const currentJsonPath = path.join(kernelDir, 'claude', 'current.json');
    const savedCurrentBackup = `${currentJsonPath}.bak`;
    fs.renameSync(currentJsonPath, savedCurrentBackup);
    fs.mkdirSync(currentJsonPath);
    try {
      await assert.rejects(
        engine.updateConfig({ claudeForceIpv4: false }),
        /./,
        '新副本提交失败时 updateConfig 必须报错'
      );
      assert.equal(
        store.get().claudeForceIpv4,
        true,
        '内核提交失败后 claudeForceIpv4 绝不可被保存为未生效的 false'
      );
      assert.equal(
        svc.channels.claude.getIpv4Only(),
        true,
        '内核提交失败后 PrivateKernel 必须回滚至先前已提交的 ipv4Only=true'
      );
    } finally {
      fs.rmdirSync(currentJsonPath);
      fs.renameSync(savedCurrentBackup, currentJsonPath);
    }
    await svc.channels.claude.restart();
    assert.equal(svc.channels.claude.getState().phase, 'ready');
    assert.equal(
      svc.channels.claude.getIpv4Only(),
      true,
      '故障恢复重启后必须继续使用已生效的 ipv4Only=true'
    );

    // 9b(d). guard-config.json 落盘失败 -> 自动撤销新双栈监听，回滚至原 ipv4Only=true
    const guardConfigPath = path.join(root, 'guard-config.json');
    const guardConfigBackup = `${guardConfigPath}.bak`;
    if (fs.existsSync(guardConfigPath)) {
      fs.renameSync(guardConfigPath, guardConfigBackup);
    }
    fs.mkdirSync(guardConfigPath);
    try {
      await assert.rejects(
        engine.updateConfig({ claudeForceIpv4: false }),
        /./,
        'guard-config.json 写入失败时 updateConfig 必须显式报错'
      );
      assert.equal(
        store.get().claudeForceIpv4,
        true,
        '配置文件写入失败后内存配置必须保持 true'
      );
      assert.equal(
        svc.channels.claude.getIpv4Only(),
        true,
        '配置文件写入失败后必须撤销已切换的双栈监听，回滚至原 ipv4Only=true'
      );
      assert.equal(svc.channels.claude.getState().phase, 'ready');
    } finally {
      fs.rmdirSync(guardConfigPath);
      if (fs.existsSync(guardConfigBackup)) {
        fs.renameSync(guardConfigBackup, guardConfigPath);
      }
    }

    // 9b(e). 模拟切换窗口期卫士崩溃残留 pending.json + 新版 runtime.json
    const crashKernelDir = path.join(ipv4Root, 'crash-pending-kernels');
    const crashPort = await freePort();
    const crashSvc1 = trackService(new PrivateProxyService(crashKernelDir, coreDir));
    try {
      await crashSvc1.channels.claude.select(vlessSnap, crashPort, {
        ipv4Only: true,
      });
      const committedCurrentRaw = fs.readFileSync(
        path.join(crashKernelDir, 'claude', 'current.json'),
        'utf8'
      );
      await crashSvc1.channels.claude.select(vlessSnap, crashPort, {
        ipv4Only: false,
      });
      const pendingNewRaw = fs.readFileSync(
        path.join(crashKernelDir, 'claude', 'current.json'),
        'utf8'
      );
      const pendingPid = crashSvc1.channels.claude.getState().pid!;
      assert.ok(pendingPid > 0, '新版内核应已启动');
      crashSvc1.stopMonitoring();
      untrackService(crashSvc1);

      fs.writeFileSync(
        path.join(crashKernelDir, 'claude', 'current.json'),
        committedCurrentRaw,
        'utf8'
      );
      fs.writeFileSync(
        path.join(crashKernelDir, 'claude', 'pending.json'),
        pendingNewRaw,
        'utf8'
      );

      const crashSvc2 = trackService(
        new PrivateProxyService(crashKernelDir, coreDir)
      );
      try {
        await crashSvc2.restore();
        assert.equal(
          crashSvc2.channels.claude.getState().phase,
          'ready',
          `崩溃重启后应自动清理未提交内核并恢复就绪: err=${
            crashSvc2.channels.claude.getState().error
          }`
        );
        assert.equal(
          crashSvc2.channels.claude.getIpv4Only(),
          true,
          '崩溃重启后应恢复已提交的旧版 ipv4Only=true 副本'
        );
        assert.equal(
          fs.existsSync(path.join(crashKernelDir, 'claude', 'pending.json')),
          false,
          '恢复完成后 pending.json 必须清理'
        );
        let pendingStillAlive = true;
        try {
          process.kill(pendingPid, 0);
        } catch {
          pendingStillAlive = false;
        }
        assert.equal(
          pendingStillAlive,
          false,
          '未提交的旧切换内核进程必须已被核验身份后安全停止'
        );
      } finally {
        await crashSvc2.shutdown();
        untrackService(crashSvc2);
      }
    } finally {
      if (hasTrackedService(crashSvc1)) {
        await crashSvc1.shutdown();
        untrackService(crashSvc1);
      }
    }

    // 9c. 关闭开关后重建双栈内核允许访问纯 IPv6，再切回 claudeForceIpv4=true
    const offCfg = await engine.updateConfig({ claudeForceIpv4: false });
    assert.equal(offCfg.claudeForceIpv4, false);
    assert.equal(
      svc.channels.claude.getIpv4Only(),
      false,
      '关闭开关后 Claude 私有内核必须切换为双栈'
    );
    assert.equal(
      svc.channels.claude.getInternalPort(),
      claudePort,
      '双栈模式下 Mihomo 应直接监听公开专属端口'
    );
    const dualLease = readLeaseEndpoint(path.join(kernelDir, 'claude'));
    const dualWrittenCfg = readYaml(dualLease.configPath);
    assert.equal(
      (dualWrittenCfg.dns as Record<string, unknown>).ipv6,
      true,
      '双栈模式必须开启 dns.ipv6'
    );
    assert.equal(
      (dualWrittenCfg.rules as string[]).includes('IP-CIDR6,::/0,REJECT,no-resolve'),
      false,
      '双栈模式不得包含 IP-CIDR6,::/0,REJECT 拦截规则'
    );
    const offlineDualDnsCfg = yaml.dump({
      ...dualWrittenCfg,
      dns: {
        ...(dualWrittenCfg.dns as Record<string, unknown>),
        nameserver: [`127.0.0.1:${dnsPort}`],
      },
    });
    fs.writeFileSync(dualLease.configPath, offlineDualDnsCfg, 'utf8');
    await reloadKernelConfig(dualLease.endpoint, offlineDualDnsCfg);

    vlessTargets.length = 0;
    rig.state.ipv6OriginHits = 0;
    const v6DomainResp = await requestTextViaProxy(
      'http://v6only.claude.test/dual-check',
      publicHttpUrl,
      6000
    );
    assert.equal(
      v6DomainResp,
      'ipv6-only-origin-ok',
      '关闭强制 IPv4 后应能正常访问纯 IPv6 域名'
    );
    const v6LiteralResp = await requestTextViaProxy(
      'http://[2607:6bc0::10]/dual-check',
      publicHttpUrl,
      6000
    );
    assert.equal(
      v6LiteralResp,
      'ipv6-only-origin-ok',
      '关闭强制 IPv4 后应能正常访问公网 IPv6 字面量'
    );
    assert.ok(
      rig.state.ipv6OriginHits >= 2,
      `双栈模式下 IPv6 源站应收到 2 次请求，实际 ${rig.state.ipv6OriginHits}`
    );
    assert.ok(
      vlessTargets.some((t) => t.atyp === 3),
      `双栈模式下 VLESS 应收到真实 IPv6 (ATYP=3) 连接，实际：${JSON.stringify(
        vlessTargets
      )}`
    );

    const reEnabledCfg = await engine.updateConfig({ claudeForceIpv4: true });
    assert.equal(reEnabledCfg.claudeForceIpv4, true);
    assert.equal(
      svc.channels.claude.getIpv4Only(),
      true,
      '重新开启开关后私有内核必须切回 ipv4Only=true'
    );
    assert.notEqual(
      svc.channels.claude.getInternalPort(),
      claudePort,
      '重新开启仅 IPv4 后 Mihomo 必须切回内部回环端口，由桥接接管公开端口'
    );

    // 10. 验证旧版本无 ipv4Only 字段的已保存副本在升级启动时的无损延后升级与空闲直升
    const legacyKernelDir = path.join(ipv4Root, 'legacy-upgrade-kernels');
    const legacySvc1 = trackService(
      new PrivateProxyService(legacyKernelDir, coreDir)
    );
    const legacyPort = await freePort();
    try {
      await legacySvc1.channels.claude.select(vlessSnap, legacyPort);
      assert.equal(legacySvc1.channels.claude.getIpv4Only(), false);
      const originalLegacyPid = legacySvc1.channels.claude.getState().pid!;
      assert.ok(originalLegacyPid > 0, '旧版本内核应已启动并记录 PID');
      const legacyLease1 = readLeaseEndpoint(path.join(legacyKernelDir, 'claude'));
      assert.equal(
        (readYaml(legacyLease1.configPath).dns as Record<string, unknown>).ipv6,
        true
      );
      legacySvc1.stopMonitoring();
      untrackService(legacySvc1);

      const legacySvcRunning = trackService(
        new PrivateProxyService(legacyKernelDir, coreDir)
      );
      const upgradeStoreRunning = new ConfigStore();
      upgradeStoreRunning.update({
        selectedClashNode: '双栈VLESS测试节点',
        selectedClashProfileUid: 'vless-prof',
        selectedClashProfileName: 'VLESS IPv4 测试订阅',
        dedicatedProxyPort: legacyPort,
        claudeExclusiveGuard: false,
        claudeForceIpv4: true,
        killProcessesEnabled: false,
      });
      const upgradeEngineRunning = new ProbeEngine(
        upgradeStoreRunning,
        geo,
        new ClashMonitor(vergeDir),
        legacySvcRunning
      );
      try {
        upgradeEngineRunning.claude.running = true;
        await upgradeEngineRunning.restorePrivateSelections();
        assert.equal(
          legacySvcRunning.channels.claude.getState().pid,
          originalLegacyPid,
          '升级启动检测到运行中的外部 Claude 会话时绝不得重启或替换原私有内核进程'
        );
        assert.equal(
          legacySvcRunning.channels.claude.getIpv4Only(),
          false,
          '保留外部运行中会话时私有内核应暂留原双栈模式'
        );
        assert.equal(
          upgradeStoreRunning.get().claudeForceIpv4,
          true,
          '延后迁移期间必须保留用户的 claudeForceIpv4=true 设置，绝不得永久覆盖为 false'
        );

        upgradeEngineRunning.claude.running = false;
        const readyAfterDeferred =
          await upgradeEngineRunning.ensurePrivateChannelReadyForLaunch('claude');
        assert.equal(
          readyAfterDeferred.ok,
          true,
          `延后迁移应成功: ${readyAfterDeferred.error}`
        );
        assert.equal(
          legacySvcRunning.channels.claude.getIpv4Only(),
          true,
          '会话结束后下次安全启动前必须自动将私有内核迁移至 ipv4Only=true'
        );
        const deferredUpgradedLease = readLeaseEndpoint(
          path.join(legacyKernelDir, 'claude')
        );
        assert.equal(
          (readYaml(deferredUpgradedLease.configPath).dns as Record<string, unknown>)
            .ipv6,
          false
        );
      } finally {
        upgradeEngineRunning.stop();
        await legacySvcRunning.shutdown();
        untrackService(legacySvcRunning);
      }

      const legacyKernelDirIdle = path.join(ipv4Root, 'legacy-upgrade-kernels-idle');
      const legacySvcIdle1 = trackService(
        new PrivateProxyService(legacyKernelDirIdle, coreDir)
      );
      const legacyPortIdle = await freePort();
      await legacySvcIdle1.channels.claude.select(vlessSnap, legacyPortIdle);
      assert.equal(legacySvcIdle1.channels.claude.getIpv4Only(), false);
      legacySvcIdle1.stopMonitoring();
      untrackService(legacySvcIdle1);

      const legacySvc2 = trackService(
        new PrivateProxyService(legacyKernelDirIdle, coreDir)
      );
      const upgradeStore = new ConfigStore();
      upgradeStore.update({
        selectedClashNode: '双栈VLESS测试节点',
        selectedClashProfileUid: 'vless-prof',
        selectedClashProfileName: 'VLESS IPv4 测试订阅',
        dedicatedProxyPort: legacyPortIdle,
        claudeExclusiveGuard: false,
        claudeForceIpv4: true,
        killProcessesEnabled: false,
      });
      const upgradeEngine = new ProbeEngine(
        upgradeStore,
        geo,
        new ClashMonitor(vergeDir),
        legacySvc2
      );
      try {
        await upgradeEngine.restorePrivateSelections();
        assert.equal(
          legacySvc2.channels.claude.getIpv4Only(),
          true,
          '无运行中 Claude 会话时升级启动应自动将旧私有内核切换至 ipv4Only=true'
        );
        const upgradedLease = readLeaseEndpoint(
          path.join(legacyKernelDirIdle, 'claude')
        );
        assert.equal(
          (readYaml(upgradedLease.configPath).dns as Record<string, unknown>).ipv6,
          false
        );
      } finally {
        upgradeEngine.stop();
        await legacySvc2.shutdown();
        untrackService(legacySvc2);
      }
    } finally {
      if (hasTrackedService(legacySvc1)) {
        await legacySvc1.shutdown();
        untrackService(legacySvc1);
      }
    }

    // 11. 验证 shutdown() 后公开桥接端口与内部端口均已关闭且零残留
    const latestInternalPort = svc.channels.claude.getInternalPort()!;
    engine.stop();
    await svc.shutdown();
    untrackService(svc);
    assert.equal(
      await isLocalPortListening(claudePort),
      false,
      'shutdown 后公开 IPv4 桥接端口必须释放'
    );
    assert.equal(
      await isLocalPortListening(latestInternalPort),
      false,
      'shutdown 后内部 Mihomo 端口必须释放'
    );

    console.log(
      '通过：公开端口强制 IPv4 出站（流式 VLESS ATYP=1 / probeForwarding / HTTP解析器大请求体与431 / 客户端即时取消 / 预连接重置重连 / 真实隔离客户端 socks5h 注入）、空窗期端口冲突与归属不明阻断、提交失败原子回滚、双栈切换纯 IPv6 通行及无损延后升级全部验证通过'
    );
  } finally {
    if (isolatedClientPid) {
      try {
        process.kill(isolatedClientPid);
      } catch {
        // already exited
      }
      const exitWait = Date.now() + 3000;
      while (Date.now() < exitWait) {
        try {
          process.kill(isolatedClientPid, 0);
          await delay(50);
        } catch {
          break;
        }
      }
    }
    engine?.stop();
    if (hasTrackedService(svc)) {
      await svc.shutdown();
      untrackService(svc);
    }
    await rig.cleanup();
  }
}
