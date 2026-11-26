import { BinaryWriter, WireType } from '@bufbuild/protobuf/wire';
import assert from 'node:assert/strict';
import { extractProxyTransportHosts } from '../../electron/clash';
import {
  ClaudeVerificationRecovery,
  evaluateClaudeNodeProbeSafety,
  isProbeRegionMismatched,
  resolveAlertActualMismatchFields,
} from '../../electron/guard';
import {
  BUILTIN_TRACE_ENDPOINTS,
  classifyNotebookLmResponse,
  doesHostShareDomain,
  extractGoogleRedirectCountry,
  extractYoutubeVisitorCountryCode,
  MIN_CONSENSUS_MATCHES,
  parseGoogleSearchHtml,
  parseYoutubeSwJsData,
  selectProbeEndpointsForTransportHosts,
} from '../../electron/probe';
import { getTargetServiceVerificationError } from '../../src/shared/probeValidation';
import type { ProbeResult } from '../../src/shared/types';

export function verifyTransportHostsAndPureSafety(): void {
  assert.equal(MIN_CONSENSUS_MATCHES, 2);
  const uniqueDomains = new Set(
    BUILTIN_TRACE_ENDPOINTS.map((item) => item.registrableDomain)
  );
  assert.equal(
    uniqueDomains.size,
    BUILTIN_TRACE_ENDPOINTS.length,
    '常规探测池各源必须具备互不相同的独立注册主域'
  );
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
    [
      'api.ipify.org',
      'cp.cloudflare.com',
      'dl.ident.me',
      'sni.example.org',
      'up.icanhazip.com',
    ],
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

  const decoupled = selectProbeEndpointsForTransportHosts(
    BUILTIN_TRACE_ENDPOINTS,
    sampleTransportHosts
  );
  assert.equal(decoupled.length, 2);
  const oneLeftHosts = BUILTIN_TRACE_ENDPOINTS.slice(0, -1).map(
    (ep) => `hop.${ep.registrableDomain}`
  );
  assert.deepEqual(
    selectProbeEndpointsForTransportHosts(BUILTIN_TRACE_ENDPOINTS, oneLeftHosts),
    [BUILTIN_TRACE_ENDPOINTS.at(-1)!]
  );
  const zeroLeftHosts = BUILTIN_TRACE_ENDPOINTS.map(
    (ep) => `hop.${ep.registrableDomain}`
  );
  assert.deepEqual(
    selectProbeEndpointsForTransportHosts(BUILTIN_TRACE_ENDPOINTS, zeroLeftHosts),
    []
  );

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
  assert.ok(
    getTargetServiceVerificationError(
      makeOfflineGeoMissingProbe('US'),
      'claude'
    )?.includes('离线 GeoIP')
  );
  assert.equal(
    isProbeRegionMismatched({
      ...makeOfflineGeoMissingProbe('US'),
      claudeTraceError: undefined,
      claudeTraceCountryCode: 'JP',
    }),
    true
  );

  for (const sampleCountry of ['US', 'JP']) {
    const unknownGeoSameIp = evaluateClaudeNodeProbeSafety(
      makeOfflineGeoMissingProbe(sampleCountry),
      {
        claudeRunning: true,
        claudeExternalBaselinePending: false,
        claudeLockExitIp: true,
        sessionInitialIp: '203.0.113.10',
      }
    );
    assert.equal(unknownGeoSameIp?.alertType, 'verification-unavailable');

    const unknownGeoDriftedIp = evaluateClaudeNodeProbeSafety(
      makeOfflineGeoMissingProbe(sampleCountry),
      {
        claudeRunning: true,
        claudeExternalBaselinePending: false,
        claudeLockExitIp: true,
        sessionInitialIp: '198.51.100.9',
      }
    );
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

    const unknownGeoUnlockedIp = evaluateClaudeNodeProbeSafety(
      makeOfflineGeoMissingProbe(sampleCountry),
      {
        claudeRunning: true,
        claudeExternalBaselinePending: false,
        claudeLockExitIp: false,
        sessionInitialIp: '198.51.100.9',
      }
    );
    assert.equal(unknownGeoUnlockedIp?.alertType, 'verification-unavailable');
  }

  // ClaudeVerificationRecovery 归一化去重
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
      dedup.recordFailure(
        '目标服务地区校验未通过：https://claude.ai/cdn-cgi/trace：连接超时'
      ),
      { shouldLog: true, stateChanged: true }
    );
    assert.deepEqual(
      dedup.recordFailure(
        '目标服务地区校验未通过：https://claude.ai/cdn-cgi/trace:连接超时'
      ),
      { shouldLog: false, stateChanged: true }
    );
  } finally {
    dedup.clear();
  }

  // Google 送中与 NotebookLM 地区校验解析器单元测试
  const encodeVisitorToken = (
    country: string | Uint8Array,
    visitorId = 'B_0FWZLX6ec',
    ts = 1795570159
  ): string => {
    const geoWriter = new BinaryWriter();
    geoWriter
      .tag(1, WireType.LengthDelimited)
      .bytes(typeof country === 'string' ? Buffer.from(country, 'utf8') : country);
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
  };

  const cnVisitorToken = encodeVisitorToken('CN');
  const usVisitorToken = encodeVisitorToken('US');
  const invalidHighBitToken = encodeVisitorToken(new Uint8Array([0xc3, 0xce]));
  assert.equal(extractYoutubeVisitorCountryCode(cnVisitorToken), 'CN');
  assert.equal(extractYoutubeVisitorCountryCode(usVisitorToken), 'US');
  assert.equal(
    extractYoutubeVisitorCountryCode(invalidHighBitToken),
    null,
    '非 ASCII 高位字节（如 0xC3 0xCE）不得因剥离最高位被误判为 CN'
  );
  assert.equal(extractYoutubeVisitorCountryCode('not-a-valid-protobuf-token!!!'), null);
  assert.equal(extractYoutubeVisitorCountryCode(''), null);

  const songzhongSw = parseYoutubeSwJsData(
    `)]}'\n[["yt.sw.adr",null,[[["en","US",null,"23.237.50.28",null,null,null,null,null,null,null,"Robot","Bot or Crawler","${cnVisitorToken}"]]]]]`
  );
  assert.equal(
    songzhongSw?.countryCode,
    'CN',
    'sw.js_data 中 inner[1]=US 但 visitorData=CN 时必须优先识别为 CN'
  );
  assert.equal(songzhongSw?.glCountryCode, 'US');
  assert.equal(songzhongSw?.visitorCountryCode, 'CN');
  assert.equal(songzhongSw?.ip, '23.237.50.28');

  const highBitSw = parseYoutubeSwJsData(
    `)]}'\n[["yt.sw.adr",null,[[["en","JP",null,"1.0.16.1",null,null,null,null,null,null,null,"Robot","Bot or Crawler","${invalidHighBitToken}"]]]]]`
  );
  assert.equal(
    highBitSw?.visitorCountryCode,
    undefined,
    '非法高位字节 visitorData 不得覆盖 YouTube 地区字段'
  );
  assert.equal(highBitSw?.countryCode, 'JP');

  const legacySw = parseYoutubeSwJsData(
    `)]}'\n["yt.sw.adr",null,[[["","JP",null,"1.2.3.4"]]]]`
  );
  assert.equal(legacySw?.countryCode, 'JP');
  assert.equal(legacySw?.ip, '1.2.3.4');

  assert.equal(
    extractGoogleRedirectCountry(
      'https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/%3Fhl%3Den'
    ),
    'CN'
  );
  assert.equal(
    extractGoogleRedirectCountry('https://www.google.cn/search?q=test'),
    'CN'
  );
  assert.equal(
    extractGoogleRedirectCountry(
      'https://consent.google.com/m?continue=https://www.google.com/&gl=DE'
    ),
    'DE'
  );
  assert.equal(
    extractGoogleRedirectCountry('https://www.google.com.hk/?hl=en'),
    null
  );

  assert.equal(
    parseGoogleSearchHtml('var x=["",2,1,200,"CHN",null];')?.countryCode,
    'CN'
  );
  assert.equal(parseGoogleSearchHtml('{"MgUcDb":"JP"}')?.countryCode, 'JP');

  assert.equal(
    classifyNotebookLmResponse({
      statusCode: 302,
      location: 'https://notebooklm.google?location=unsupported',
    }),
    false
  );
  assert.equal(
    classifyNotebookLmResponse({
      statusCode: 302,
      location: 'https://notebook.google?location=unsupported',
    }),
    false
  );
  assert.equal(
    classifyNotebookLmResponse({
      statusCode: 301,
      location: 'https://notebook.google.com/',
    }),
    undefined,
    '未跟随完成的域名迁移 301 不得直接判定为支持'
  );
  assert.equal(
    classifyNotebookLmResponse({
      statusCode: 302,
      location:
        'https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fnotebook.google.com%2F',
      finalUrl: 'https://notebook.google.com/',
    }),
    true
  );
  assert.equal(
    classifyNotebookLmResponse({
      statusCode: 302,
      location: 'https://notebook.google/',
      finalUrl: 'https://notebook.google.com/',
    }),
    true
  );
  assert.equal(classifyNotebookLmResponse({ statusCode: 200, location: null }), true);
  assert.equal(
    classifyNotebookLmResponse({
      statusCode: 302,
      location: 'https://www.google.com/sorry/index',
    }),
    undefined
  );

  const aiBlockedAgProbe: ProbeResult = {
    ip: '198.51.100.8',
    countryCode: 'HK',
    countryName: '中国香港',
    viaChannel: '测试通道',
    latencyMs: 42,
    checkedAt: Date.now(),
    googleCountryCode: 'HK',
    googleCountryName: '中国香港',
    googleAiSupported: false,
    regionMismatchDetail: null,
  };
  assert.match(
    getTargetServiceVerificationError(aiBlockedAgProbe, 'antigravity') || '',
    /NotebookLM.*不受支持/
  );

  console.log(
    '通过：独立探测池、传输层域名提取过滤、离线归属未知优先级、后台复核去重与 Google 送中/NotebookLM 解析校验'
  );
}
