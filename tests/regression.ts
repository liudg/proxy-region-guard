import { app, nativeImage } from 'electron';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { channel } from 'node:diagnostics_channel';
import { ClientRequest } from 'node:http';
import { setTimeout as sleep } from 'node:timers/promises';
import * as yaml from 'js-yaml';
import { ConfigStore } from '../electron/configStore';
import {
  buildProfilesSignature,
  buildSlotDefinitionSignature,
  ClashMonitor,
} from '../electron/clashMonitor';
import { GeoIpService } from '../electron/geoipService';
import { CLAUDE_MAX_RUNTIME_POLL_SEC, ProbeEngine } from '../electron/probeEngine';
import {
  assertProcessesStopped,
  listRunningProcesses,
  terminateProtectedProcesses,
} from '../electron/processGuard';
import { readWindowsLocaleState } from '../electron/winSystemLocale';
import { readWindowsSystemProxy } from '../electron/systemProxy';
import { getTargetServiceVerificationError, isValidIpAddress } from '../src/shared/probeValidation';
import {
  COUNTRY_DEFAULT_WINDOWS_TZ,
  isWindowsLocaleMatchingCountry,
  resolveWindowsTimeZoneForCountry,
} from '../src/shared/timezones';
import {
  buildNodeSearchText,
  inferNodeCountryCode,
  matchesNodeSearchToken,
} from '../src/shared/countries';
import { AppStateSnapshot, ClashProfileGroupOption, ProbeResult } from '../src/shared/types';
import { createStatusTrayIcon, createWindowAppIcon } from '../electron/trayIcon';
import { countRunningClaudeProcesses } from '../electron/claudeController';
import { runMihomoIntegration } from './mihomoIntegration';
import { runClaudeVerificationRecoveryTests } from './claudeVerificationRecovery';

assert.ok(process.env.GUARD_TEST_DATA);
const dataDirectory = process.env.GUARD_TEST_DATA;
fs.mkdirSync(dataDirectory, { recursive: true });
app.setPath('userData', dataDirectory);

async function check(name: string, operation: () => void | Promise<void>): Promise<void> {
  await operation();
  console.log(`通过：${name}`);
}

async function run(): Promise<void> {
  assert.equal(process.platform, 'win32', '进程集成测试需要 Windows');
  await check('时区判定拒绝缺失映射、无效国家和错误时区', () => {
    assert.equal(isWindowsLocaleMatchingCountry('Tokyo Standard Time', 'JP', 'JP'), true);
    assert.equal(isWindowsLocaleMatchingCountry('Pacific Standard Time', 'JP', 'JP'), false);
    assert.equal(isWindowsLocaleMatchingCountry('Tokyo Standard Time', 'EC', 'EC'), false);
    assert.equal(isWindowsLocaleMatchingCountry('UTC', 'UNKNOWN', 'UNKNOWN'), false);
    assert.throws(() => resolveWindowsTimeZoneForCountry('EC', 'Asia/Tokyo'), /尚未收录/);
    for (const [country, zone] of Object.entries(COUNTRY_DEFAULT_WINDOWS_TZ)) {
      assert.equal(isWindowsLocaleMatchingCountry(zone, country, country), true, country);
    }
  });

  await check('节点国家/地区智能识别与中英文同义词索引准确无误', () => {
    assert.equal(inferNodeCountryCode('🇺🇸 美国 01'), 'US');
    assert.equal(inferNodeCountryCode('🇺🇲 Silicon Valley BGP'), 'US');
    assert.equal(inferNodeCountryCode('US-SJC-01'), 'US');
    assert.equal(inferNodeCountryCode('🇯🇵 Tokyo IEPL 02'), 'JP');
    assert.equal(inferNodeCountryCode('狮城 BGP 01'), 'SG');
    assert.equal(inferNodeCountryCode('HK01-深港专线'), 'HK');
    assert.equal(inferNodeCountryCode('TW-彰化-01'), 'TW');
    assert.equal(inferNodeCountryCode('No.1 专线'), null);
    assert.equal(inferNodeCountryCode('No.1 英国伦敦'), 'GB');

    const usSearch = buildNodeSearchText('US-SJC-01', 'vless', 'SubA', 'US');
    assert.ok(usSearch.includes('美国'));
    assert.ok(usSearch.includes('united states'));
    assert.ok(usSearch.includes('vless'));

    const jpSearch = buildNodeSearchText('🇯🇵 东京 01', 'trojan', 'SubB', 'JP');
    assert.ok(jpSearch.includes('jp'));
    assert.ok(jpSearch.includes('japan'));
    assert.ok(jpSearch.includes('日本'));
  });

  await check('国家缩写精确匹配并保留协议和多词搜索', () => {
    for (const code of ['US', 'KR', 'RU', 'AU', 'AT']) {
      const text = buildNodeSearchText(`${code}01`, 'vless', 'SubA', code);
      for (const token of ['us', 'usa']) {
        assert.equal(matchesNodeSearchToken(text, code, token), code === 'US');
      }
      assert.ok(matchesNodeSearchToken(text, code, 'vless'));
      assert.ok(matchesNodeSearchToken(text, code, '01'));
    }
    const text = buildNodeSearchText('英国01', 'ss', 'SubA', 'GB');
    for (const token of ['gb', 'uk', 'gbr', '英国', 'ss']) {
      assert.ok(matchesNodeSearchToken(text, 'GB', token));
    }
  });

  await check('节点状态签名区分存活状态、测速归属和节点名称', () => {
    const group: ClashProfileGroupOption = {
      uid: 'subscription', name: '订阅', type: 'remote', isActive: true, nodeCount: 2,
      nodes: [
        { name: 'A', type: 'ss', isGroup: false, alive: false },
        { name: 'B', type: 'ss', isGroup: false, alive: true },
      ],
    };
    const signature = buildProfilesSignature([group]);
    group.nodes[0].alive = true;
    group.nodes[1].alive = false;
    assert.notEqual(buildProfilesSignature([group]), signature);
    group.nodes[1].alive = true;
    group.nodes[0].delay = 100;
    const measured = buildProfilesSignature([group]);
    group.nodes[0].delay = undefined;
    group.nodes[1].delay = 100;
    assert.notEqual(buildProfilesSignature([group]), measured);
    const named = buildProfilesSignature([group]);
    group.nodes[1].name = 'C';
    assert.notEqual(buildProfilesSignature([group]), named);
  });

  await check('专属节点定义签名忽略无关全局域名策略并精确感知目标节点与链路变更', () => {
    const baseDef = {
      profileUid: 'prof-1',
      profileName: '订阅一',
      rawProxy: { name: 'JP-Hy2', type: 'hysteria2', server: 'jp7.example-node.net', port: 443, udp: true },
      dialerChain: [{ name: 'Relay-1', type: 'ss', server: 'relay.transit-host.org', port: 8388 }],
      hosts: {} as Record<string, string>,
      nameserverPolicy: {} as Record<string, string[]>,
    };
    const baseSig = buildSlotDefinitionSignature(baseDef);

    // 无关的运行时全局 hosts / nameserver-policy 与订阅显示名变更不应触发节点定义变化
    const withUnrelatedPolicies = {
      ...baseDef,
      profileName: '订阅一 (重命名)',
      hosts: { 'router.lan': '192.168.1.1', 'other.example.com': '1.2.3.4' },
      nameserverPolicy: {
        '+.quandao.com': ['223.5.5.5'],
        '+.jiandaoyun.com': ['223.5.5.5'],
        'geosite:cn': ['https://dns.alidns.com/dns-query'],
      },
    };
    assert.equal(buildSlotDefinitionSignature(withUnrelatedPolicies), baseSig);

    // 命中目标节点或链式前置节点 server 域名的 DNS 规则或 hosts 变更必须更新签名
    const withMatchingNsPolicy = {
      ...withUnrelatedPolicies,
      nameserverPolicy: {
        ...withUnrelatedPolicies.nameserverPolicy,
        '+.example-node.net': ['https://dns.alidns.com/dns-query'],
      },
    };
    assert.notEqual(buildSlotDefinitionSignature(withMatchingNsPolicy), baseSig);

    const withMatchingDialerHost = {
      ...withUnrelatedPolicies,
      hosts: {
        ...withUnrelatedPolicies.hosts,
        'relay.transit-host.org': '203.0.113.10',
      },
    };
    assert.notEqual(buildSlotDefinitionSignature(withMatchingDialerHost), baseSig);

    const withWildcardDialerHost = {
      ...withUnrelatedPolicies,
      hosts: {
        ...withUnrelatedPolicies.hosts,
        '+.transit-host.org': '203.0.113.11',
      },
    };
    assert.notEqual(buildSlotDefinitionSignature(withWildcardDialerHost), baseSig);

    // 节点自身参数变更必须更新签名
    const withPortChanged = {
      ...baseDef,
      rawProxy: { ...baseDef.rawProxy, port: 8443 },
    };
    assert.notEqual(buildSlotDefinitionSignature(withPortChanged), baseSig);

    // 链式代理前置节点属于运行时动态节点时，应继承运行时 hosts 与 nameserver-policy
    const tempMonitor = new ClashMonitor() as any;
    const rawLeaf = {
      name: 'Static-Leaf',
      type: 'vmess',
      server: 'leaf.static-domain.org',
      port: 443,
      'dialer-proxy': 'Runtime-Relay',
    };
    const rawRelay = {
      name: 'Runtime-Relay',
      type: 'ss',
      server: 'relay.runtime-domain.org',
      port: 8388,
    };
    const fakeProf = {
      uid: 'prof-chain',
      name: '链式测试订阅',
      type: 'local',
      isActive: true,
      nodes: [],
      rawMap: new Map([
        ['Static-Leaf', rawLeaf],
        ['Runtime-Relay', rawRelay],
      ]),
      hosts: {},
      nameserverPolicy: {},
      runtimeNodeNames: new Set(['Runtime-Relay']),
      runtimeHosts: { '+.runtime-domain.org': '198.51.100.8' },
      runtimeNameserverPolicy: { '+.runtime-domain.org': ['223.5.5.5'] },
    };
    const builtChainDef = tempMonitor.buildDefinitionFromProfile(fakeProf, 'Static-Leaf', rawLeaf);
    assert.equal(builtChainDef.hosts['+.runtime-domain.org'], '198.51.100.8');
    assert.deepEqual(builtChainDef.nameserverPolicy['+.runtime-domain.org'], ['223.5.5.5']);
  });

  await check('脚本重命名或改写 server、过滤提示节点与空底板订阅切换均准确归属', async () => {
    const vergeDir = path.join(dataDirectory, 'verge-script-test');
    const profilesDir = path.join(vergeDir, 'profiles');
    fs.mkdirSync(profilesDir, { recursive: true });
    const runtimeYaml = path.join(vergeDir, 'clash-verge.yaml');

    fs.writeFileSync(
      path.join(profilesDir, 'sub-a.yaml'),
      yaml.dump({
        proxies: [
          { name: '剩余流量：99GB', type: 'ss', server: 'info.example.com', port: 8388, password: 'info-pass' },
          { name: 'Tokyo-01', type: 'vless', server: 'origin-jp.example.com', port: 443, uuid: 'uuid-sub-a-jp' },
          { name: 'US-01', type: 'trojan', server: 'origin-us.example.com', port: 443, password: 'pass-sub-a-us' },
          { name: 'SG-01', type: 'ss', server: 'origin-sg.example.com', port: 8388, password: 'pass-sub-a-sg' },
        ],
      })
    );
    fs.writeFileSync(
      path.join(profilesDir, 'sub-b.yaml'),
      yaml.dump({
        proxies: [
          { name: 'Backup-HK', type: 'ss', server: 'hk-backup.example.com', port: 8388, password: 'pass-sub-b-hk' },
          { name: 'SelfHosted-VPS', type: 'vless', server: 'vps.self-hosted.org', port: 443, uuid: 'uuid-self-vps' },
        ],
      })
    );
    fs.writeFileSync(path.join(profilesDir, 'sub-empty.yaml'), yaml.dump({ proxies: [] }));

    const writeProfilesIndex = (currentUid: string) => {
      fs.writeFileSync(
        path.join(vergeDir, 'profiles.yaml'),
        yaml.dump({
          current: currentUid,
          items: [
            { uid: 'sub-a', name: '主力订阅', type: 'local', file: 'sub-a.yaml' },
            { uid: 'sub-b', name: '备用订阅', type: 'local', file: 'sub-b.yaml' },
            { uid: 'sub-empty', name: '空底板脚本订阅', type: 'local', file: 'sub-empty.yaml' },
          ],
        })
      );
    };

    writeProfilesIndex('sub-a');
    // 模拟全局 Script：剔除提示节点、加国旗前缀、原地改写 US-01 server、同时重命名+改写 SG-01、并追加与备用订阅同名的自建节点
    fs.writeFileSync(
      runtimeYaml,
      yaml.dump({
        proxies: [
          { name: '🇯🇵 Tokyo-01', type: 'vless', server: 'origin-jp.example.com', port: 443, uuid: 'uuid-sub-a-jp' },
          { name: 'US-01', type: 'trojan', server: 'transit-us.example.com', port: 8443, password: 'pass-sub-a-us' },
          { name: '🇸🇬 SG-01', type: 'ss', server: 'transit-sg.example.com', port: 9388, password: 'pass-sub-a-sg' },
          { name: 'SelfHosted-VPS', type: 'vless', server: 'vps.self-hosted.org', port: 443, uuid: 'uuid-self-vps' },
        ],
      })
    );

    const m = new ClashMonitor() as any;
    m.currentEndpoint = { label: 'test', yamlFile: runtimeYaml };
    const scanA = m.scanAllClashVergeProfiles({});
    const groupA = scanA.profileGroups.find((g: ClashProfileGroupOption) => g.uid === 'sub-a')!;
    const namesA = groupA.nodes.map((n) => n.name);
    assert.ok(namesA.includes('🇯🇵 Tokyo-01'), '应保留脚本重命名节点');
    assert.ok(namesA.includes('🇸🇬 SG-01'), '应保留脚本同时重命名并改写 server 的节点');
    assert.ok(namesA.includes('SelfHosted-VPS'), '过滤提示节点后不应误删与未激活订阅同名的动态节点');
    const usNode = groupA.nodes.find((n) => n.name === 'US-01')!;
    assert.equal(usNode.server, 'transit-us.example.com');
    assert.equal(usNode.port, 8443);
    const usDef = m.resolveSlotTargetNodeDefinition({
      desiredNodeName: 'US-01',
      desiredProfileUid: 'sub-a',
    });
    assert.equal(usDef.rawProxy.server, 'transit-us.example.com');

    // 切换至空底板订阅瞬间（clash-verge.yaml 尚未更新）：热切换与冷启动均不得混入旧节点
    await sleep(20);
    writeProfilesIndex('sub-empty');
    const scanEmptyLive = m.scanAllClashVergeProfiles({});
    const emptyGroupLive = scanEmptyLive.profileGroups.find(
      (g: ClashProfileGroupOption) => g.uid === 'sub-empty'
    )!;
    assert.deepEqual(emptyGroupLive.nodes, [], '切换至空底板订阅瞬间不应泄漏旧 clash-verge.yaml 节点');

    const coldMonitor = new ClashMonitor() as any;
    coldMonitor.currentEndpoint = { label: 'test', yamlFile: runtimeYaml };
    const scanEmptyCold = coldMonitor.scanAllClashVergeProfiles({});
    const emptyGroupCold = scanEmptyCold.profileGroups.find(
      (g: ClashProfileGroupOption) => g.uid === 'sub-empty'
    )!;
    assert.deepEqual(emptyGroupCold.nodes, [], '冷启动遇到未更新的旧 clash-verge.yaml 也不应泄漏至空订阅');

    // 当空底板订阅的脚本完成生成并落盘 clash-verge.yaml 后，应正常加载脚本产出的节点
    await sleep(20);
    fs.writeFileSync(
      runtimeYaml,
      yaml.dump({
        proxies: [
          { name: 'Script-Gen-01', type: 'vless', server: 'gen.example.org', port: 443, uuid: 'uuid-gen-01' },
        ],
      })
    );
    const scanEmptyReady = m.scanAllClashVergeProfiles({});
    const emptyGroupReady = scanEmptyReady.profileGroups.find(
      (g: ClashProfileGroupOption) => g.uid === 'sub-empty'
    )!;
    assert.deepEqual(
      emptyGroupReady.nodes.map((n) => n.name),
      ['Script-Gen-01']
    );
  });

  await check('增强管线 DNS 与 hosts 优先级严格遵循 原始订阅 < option.merge < 全局 Merge < dns_config.yaml < 运行时覆写', () => {
    const vergeDir = path.join(dataDirectory, 'verge-dns-priority-test');
    const profilesDir = path.join(vergeDir, 'profiles');
    fs.mkdirSync(profilesDir, { recursive: true });
    const runtimeYaml = path.join(vergeDir, 'clash-verge.yaml');

    fs.writeFileSync(
      path.join(profilesDir, 'base-sub.yaml'),
      yaml.dump({
        proxies: [{ name: 'Base-Node', type: 'ss', server: 'k4.example.org', port: 443, password: 'pw' }],
        hosts: {
          'k1.example.org': '10.0.0.1',
          'k2.example.org': '10.0.0.1',
          'k3.example.org': '10.0.0.1',
          'k4.example.org': '10.0.0.1',
        },
        dns: {
          'nameserver-policy': {
            '+.k1.example.org': ['1.1.1.1'],
            '+.k2.example.org': ['1.1.1.1'],
            '+.k3.example.org': ['1.1.1.1'],
            '+.k4.example.org': ['1.1.1.1'],
          },
        },
      })
    );
    fs.writeFileSync(
      path.join(profilesDir, 'opt-merge.yaml'),
      yaml.dump({
        hosts: {
          'k2.example.org': '10.0.0.2',
          'k3.example.org': '10.0.0.2',
          'k4.example.org': '10.0.0.2',
        },
        dns: {
          'nameserver-policy': {
            '+.k2.example.org': ['2.2.2.2'],
            '+.k3.example.org': ['2.2.2.2'],
            '+.k4.example.org': ['2.2.2.2'],
          },
        },
      })
    );
    fs.writeFileSync(
      path.join(profilesDir, 'Merge.yaml'),
      yaml.dump({
        hosts: {
          'k3.example.org': '10.0.0.3',
          'k4.example.org': '10.0.0.3',
        },
        dns: {
          'nameserver-policy': {
            '+.k3.example.org': ['3.3.3.3'],
            '+.k4.example.org': ['3.3.3.3'],
          },
        },
      })
    );
    fs.writeFileSync(path.join(vergeDir, 'verge.yaml'), yaml.dump({ enable_dns_settings: true }));
    fs.writeFileSync(
      path.join(vergeDir, 'dns_config.yaml'),
      yaml.dump({
        hosts: { 'k4.example.org': '10.0.0.4' },
        'nameserver-policy': { '+.k4.example.org': ['4.4.4.4'] },
      })
    );
    fs.writeFileSync(
      path.join(vergeDir, 'profiles.yaml'),
      yaml.dump({
        current: 'base-sub',
        chain: ['Merge'],
        items: [
          {
            uid: 'base-sub',
            name: '基础订阅',
            type: 'local',
            file: 'base-sub.yaml',
            option: { merge: 'opt-merge' },
          },
          { uid: 'opt-merge', type: 'merge', file: 'opt-merge.yaml' },
          { uid: 'Merge', type: 'merge', file: 'Merge.yaml' },
        ],
      })
    );
    fs.writeFileSync(
      runtimeYaml,
      yaml.dump({
        proxies: [
          { name: 'Base-Node', type: 'ss', server: 'k4.example.org', port: 443, password: 'pw' },
          { name: 'Runtime-Only', type: 'ss', server: 'k4.example.org', port: 8443, password: 'pw2' },
        ],
        hosts: { 'k4.example.org': '10.0.0.5' },
        dns: { 'nameserver-policy': { '+.k4.example.org': ['5.5.5.5'] } },
      })
    );

    const m = new ClashMonitor() as any;
    m.currentEndpoint = { label: 'test', yamlFile: runtimeYaml };
    m.scanAllClashVergeProfiles({});

    const staticDef = m.resolveSlotTargetNodeDefinition({
      desiredNodeName: 'Base-Node',
      desiredProfileUid: 'base-sub',
    });
    assert.equal(staticDef.hosts['k1.example.org'], '10.0.0.1');
    assert.equal(staticDef.hosts['k2.example.org'], '10.0.0.2');
    assert.equal(staticDef.hosts['k3.example.org'], '10.0.0.3');
    assert.equal(staticDef.hosts['k4.example.org'], '10.0.0.4');
    assert.deepEqual(staticDef.nameserverPolicy['+.k1.example.org'], ['1.1.1.1']);
    assert.deepEqual(staticDef.nameserverPolicy['+.k2.example.org'], ['2.2.2.2']);
    assert.deepEqual(staticDef.nameserverPolicy['+.k3.example.org'], ['3.3.3.3']);
    assert.deepEqual(staticDef.nameserverPolicy['+.k4.example.org'], ['4.4.4.4']);

    const runtimeDef = m.resolveSlotTargetNodeDefinition({
      desiredNodeName: 'Runtime-Only',
      desiredProfileUid: 'base-sub',
    });
    assert.equal(runtimeDef.hosts['k4.example.org'], '10.0.0.5');
    assert.deepEqual(runtimeDef.nameserverPolicy['+.k4.example.org'], ['5.5.5.5']);
  });

  await check('Antigravity 宽限态不掩码 Claude 控制面 generalError，避免误触发 disconnect 立即强杀', async () => {
    const isolatedStore = new ConfigStore();
    const prevCfg = isolatedStore.get();
    const isolatedMonitor = new ClashMonitor();
    const isolatedGeo = new GeoIpService();
    const isolatedEngine = new ProbeEngine(isolatedStore, isolatedGeo, isolatedMonitor);
    const m = isolatedMonitor as any;
    const e = isolatedEngine as any;

    try {
      const vergeDir = path.join(dataDirectory, 'verge-grace-coupling-test');
      fs.mkdirSync(path.join(vergeDir, 'profiles'), { recursive: true });
      const runtimeYaml = path.join(vergeDir, 'clash-verge.yaml');
      fs.writeFileSync(
        path.join(vergeDir, 'profiles', 'p1.yaml'),
        yaml.dump({
          proxies: [
            { name: 'Claude-Node', type: 'ss', server: '127.0.0.1', port: 18388, password: 'pw1' },
            { name: 'Ag-Node', type: 'ss', server: '127.0.0.1', port: 18389, password: 'pw2' },
          ],
        })
      );
      fs.writeFileSync(
        path.join(vergeDir, 'profiles.yaml'),
        yaml.dump({
          current: 'p1',
          items: [{ uid: 'p1', name: '测试订阅', type: 'local', file: 'p1.yaml' }],
        })
      );
      fs.writeFileSync(runtimeYaml, yaml.dump({ proxies: [], rules: ['MATCH,DIRECT'] }));

      isolatedStore.update({
        selectedClashNode: 'Claude-Node',
        selectedClashProfileUid: 'p1',
        dedicatedProxyPort: 27897,
        antigravityClashNode: 'Ag-Node',
        antigravityClashProfileUid: 'p1',
        antigravityDedicatedPort: 27898,
      });

      m.currentEndpoint = { label: 'MockClash', host: '127.0.0.1', port: 9097, yamlFile: runtimeYaml };
      // Claude 当前不满足宽限条件（prevBoundClaudeNode === null，处于后台复核期），Antigravity 已正常绑定
      Object.assign(m.slots.claude, {
        desiredNodeName: 'Claude-Node',
        desiredProfileUid: 'p1',
        desiredPort: 27897,
        boundNodeName: null,
        boundProfileUid: null,
        boundPort: null,
      });
      Object.assign(m.slots.antigravity, {
        desiredNodeName: 'Ag-Node',
        desiredProfileUid: 'p1',
        desiredPort: 27898,
        boundNodeName: 'Ag-Node',
        boundProfileUid: 'p1',
        boundPort: 27898,
      });
      m.info.connected = true;
      m.info.dedicatedPortListening = false;
      m.info.antigravityPortListening = true;

      m.requestJson = async (_ep: unknown, urlPath: string) => {
        if (urlPath === '/configs') return { mode: 'rule', 'mixed-port': 7890 };
        return { proxies: {} };
      };
      m.queueSyncDedicatedListeners = async () => ({
        claudeListening: false,
        antigravityListening: false,
        generalError: '配置文件无效或非内核配置: clash-verge.yaml',
      });

      await m.tick();
      isolatedMonitor.stop();

      const info = isolatedMonitor.getRuntimeInfo();
      assert.equal(info.antigravityPortListening, true, 'Antigravity 自身应保持宽限掩码');
      assert.equal(info.dedicatedPortListening, false);
      assert.equal(
        info.bindingVerificationError,
        '配置文件无效或非内核配置: clash-verge.yaml',
        'agInGrace 不得抹除 Claude 所需的控制面 generalError'
      );
      assert.equal(e.evaluateClaudeLocalSafety(true), null, '不应误判为本地确定性 disconnect');
      assert.equal(e.evaluateClaudeSafety(true).alertType, 'verification-unavailable');
    } finally {
      isolatedMonitor.stop();
      isolatedEngine.stop();
      isolatedStore.update(prevCfg);
    }
  });

  const store = new ConfigStore();
  const monitor = new ClashMonitor();
  const geo = new GeoIpService();
  const engine = new ProbeEngine(store, geo, monitor);
  // 直接调用真实实现进行检查；不启动守护器、定时器或内核配置写入。
  const monitorInternal = monitor as any;
  const engineInternal = engine as any;

  await check('配置写入失败保留内存状态并释放切换状态，正常保存可重新读取', async () => {
    store.update({ defaultCountryCode: 'JP' });
    const previous = store.get();
    const configPath = path.join(dataDirectory, 'guard-config.json');
    const backup = `${configPath}.saved`;
    fs.renameSync(configPath, backup);
    fs.mkdirSync(configPath);
    try {
      assert.throws(() => store.update({ defaultCountryCode: 'US' }));
      await assert.rejects(engineInternal.selectClashNodeInternal(null));
      assert.equal(engineInternal.claudeSwitchingCount, 0);
      await assert.rejects(engine.selectAntigravityClashNode(null));
      assert.equal(engineInternal.antigravitySwitchingCount, 0);
      assert.equal(engineInternal.applicationChangeInProgress, false);
      assert.deepEqual(store.get(), previous);
      assert.equal(fs.readdirSync(dataDirectory).some((name) => name.endsWith('.tmp')), false);
    } finally {
      monitor.stop();
      monitorInternal.currentEndpoint = null;
      fs.rmdirSync(configPath);
      fs.renameSync(backup, configPath);
    }
    assert.deepEqual(new ConfigStore().get(), previous);
    store.update({ defaultCountryCode: null });
  });

  await check('Electron 原生位图生成全部状态图标及缩放尺寸', () => {
    for (const status of ['ok', 'mismatch', 'error', 'unset', 'checking'] as const) {
      const tray = createStatusTrayIcon(status);
      assert.deepEqual(tray.getScaleFactors(), [1, 1.5, 2]);
      for (const scale of [1, 1.5, 2]) {
        const decoded = nativeImage.createFromBuffer(tray.toPNG({ scaleFactor: scale }));
        assert.deepEqual(decoded.getSize(), { width: 16 * scale, height: 16 * scale });
        assert.equal(decoded.toBitmap()[3], 0);
      }
      const icon = createWindowAppIcon(status);
      assert.deepEqual(icon.getSize(), { width: 64, height: 64 });
      const pixels = icon.toBitmap();
      const ring = (9 * 64 + 32) * 4;
      assert.equal(pixels[ring + 3], 255);
      if (status === 'ok') assert.ok(pixels[ring + 1] > pixels[ring + 2]);
      if (status === 'mismatch') assert.ok(pixels[ring + 2] > pixels[ring + 1]);
    }
  });

  await check('YAML 处理保留用户进程规则并移除卫士内部规则', () => {
    const prepared = monitorInternal.loadAndPrepareCoreYaml(
      path.resolve('tests/fixtures/core.yaml'), []
    );
    assert.deepEqual(prepared.rules, [
      'PROCESS-NAME,Claude.exe,UserProxy',
      'PROCESS-NAME,Antigravity.exe,DIRECT',
      'PROCESS-NAME,language_server.exe,REJECT',
      'MATCH,DIRECT',
    ]);
  });

  await check('真实进程枚举、存活拦截和进程树终止', async () => {
    const executableName = `guard-regression-child-${process.pid}.exe`;
    const executable = path.join(dataDirectory, executableName);
    assert.ok(process.env.GUARD_TEST_NODE);
    fs.copyFileSync(process.env.GUARD_TEST_NODE, executable);
    const descendantFile = path.join(dataDirectory, 'descendant.json');
    const child = spawn(executable, [path.resolve('tests/fixtures/process-tree.cjs'), descendantFile], {
      windowsHide: true, stdio: 'ignore',
    });
    await once(child, 'spawn');
    const exited = once(child, 'exit');
    try {
      for (let attempt = 0; attempt < 50 && !fs.existsSync(descendantFile); attempt++) {
        await sleep(50);
      }
      const descendant = JSON.parse(fs.readFileSync(descendantFile, 'utf8'));
      const running = await listRunningProcesses(true);
      assert.ok(running.some((entry) => entry.pid === child.pid));
      assert.ok(running.some((entry) => entry.pid === descendant.pid));
      const selfReport = await terminateProtectedProcesses([path.basename(process.execPath)]);
      await assert.rejects(
        assertProcessesStopped([path.basename(process.execPath)], selfReport), /仍在运行/
      );
      assert.equal((await countRunningClaudeProcesses(true)).running, false,
        '时区前置检查需要 Claude 未运行，防止影响用户会话');
      const currentLocale = await readWindowsLocaleState();
      const previousConfig = store.get();
      store.update({ defaultCountryCode: currentLocale.regionCode === 'JP' ? 'US' : 'JP',
        protectedProcessPatterns: [executableName], killProcessesEnabled: true, killOnLocaleMismatch: true });
      let report;
      try {
        report = await engineInternal.stopProcessesBeforeLocaleChange(currentLocale.regionCode, currentLocale.timeZoneId);
        store.update({ protectedProcessPatterns: [path.basename(process.execPath)] });
        await assert.rejects(
          engineInternal.stopProcessesBeforeLocaleChange(currentLocale.regionCode, currentLocale.timeZoneId), /仍在运行/
        );
        assert.deepEqual(await readWindowsLocaleState(), currentLocale);
      } finally {
        store.update(previousConfig);
      }
      assert.equal(report.failedPids.length, 0);
      assert.equal(report.killedCount, 2);
      await assertProcessesStopped([executableName], report);
      await exited;
      assert.equal((await listRunningProcesses(true)).some((entry) => entry.pid === child.pid), false);
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        await terminateProtectedProcesses([executableName]);
        await exited;
      }
    }
  });

  await check('时区同步失败返回已结束状态，并拒绝并发配置操作', async () => {
    store.update({ defaultCountryCode: 'EC' });
    const operation = engine.syncSystemLocaleToDefault();
    assert.equal(engine.getSnapshot().isSyncingLocale, true);
    await assert.rejects(engine.updateConfig({ defaultCountryCode: 'JP' }), /正在进行/);
    const result = await operation;
    assert.equal(result.ok, false);
    assert.match(result.message, /尚未收录/);
    assert.equal(result.state.isSyncingLocale, false);
    assert.equal(engine.getSnapshot().isSyncingLocale, false);
  });

  const locale = await readWindowsLocaleState();
  if (COUNTRY_DEFAULT_WINDOWS_TZ[locale.regionCode] === locale.timeZoneId) {
    await check('同步当前真实系统区域后返回已结束状态', async () => {
      store.update({ defaultCountryCode: locale.regionCode });
      const result = await engine.syncSystemLocaleToDefault();
      assert.equal(result.ok, true, result.message);
      assert.equal(result.state.isSyncingLocale, false);
      assert.deepEqual(await readWindowsLocaleState(), locale);
    });
  } else {
    console.log('未执行：当前系统区域与默认时区不同，同步成功路径需要独立测试环境');
  }

  const scanned = monitorInternal.scanAllClashVergeProfiles({});
  const node = scanned.availableNodes[0];
  if (node) {
    await check('真实本地订阅按指定 UID 查找，缺失订阅禁止使用同名节点', () => {
      const slot = { ...monitorInternal.slots.claude,
        desiredNodeName: node.name, desiredProfileUid: node.profileUid };
      const selected = monitorInternal.resolveSlotTargetNodeDefinition(slot);
      assert.ok(selected);
      assert.equal(selected.profileUid, node.profileUid);
      assert.equal(monitorInternal.resolveSlotTargetNodeDefinition({
        ...slot, desiredProfileUid: '__missing_regression_profile__',
        desiredNodeRaw: selected.rawProxy,
      }), null);
      assert.equal(monitorInternal.resolveSlotTargetNodeDefinition({
        ...slot, desiredNodeName: '__missing_regression_node__',
        desiredNodeRaw: selected.rawProxy,
      }), null);
    });
  } else {
    console.log('未执行：没有可读取的本地 Clash 订阅');
  }

  await geo.init(process.cwd());
  const systemProxy = await readWindowsSystemProxy();
  const detected = await engineInternal.probeOnceViaChannel(systemProxy.proxyUrl, '回归验证', 2500);
  assert.ok(detected.result, `真实出口检测失败：${detected.errMsg}`);
  const probe: ProbeResult = detected.result;
  await check('真实出口状态在手动重算和网络检测入口保持一致', async () => {
    const previous = store.get();
    const actualLocale = await readWindowsLocaleState();
    engineInternal.winLocale = actualLocale;
    store.update({ defaultCountryCode: probe.countryCode, protectedProcessPatterns: [] });
    let networkState = await engine.checkNow('回归验证');
    if (networkState.isChecking) {
      networkState = await new Promise<AppStateSnapshot>((resolve, reject) => {
        const timeout = setTimeout(() => {
          engine.off('state-changed', onState);
          reject(new Error('真实出口检测在 90 秒内未完成'));
        }, 90000);
        const onState = (state: AppStateSnapshot) => {
          if (state.isChecking) return;
          clearTimeout(timeout);
          engine.off('state-changed', onState);
          resolve(state);
        };
        engine.on('state-changed', onState);
        onState(engine.getSnapshot());
      });
    }
    assert.ok(networkState.lastProbe, networkState.lastError || '真实出口检测未返回结果');
    const recalculated = engine.evaluateStatusOnly('回归验证');
    assert.equal(recalculated.status, networkState.status);
    store.update({ defaultCountryCode: networkState.lastProbe!.countryCode === 'JP' ? 'US' : 'JP' });
    assert.equal(engine.evaluateStatusOnly('回归验证').status, 'mismatch');
    store.update(previous);
    await sleep(100);
  });
  await check('真实 DoH 返回由 DNS 库解析的 IPv4 地址', async () => {
    const ip = await monitorInternal.resolveHostViaCustomDnsServers('example.com', ['https://dns.alidns.com/dns-query'], true);
    assert.ok(ip, '真实 DoH 查询未返回 IPv4 地址');
  });
  await runMihomoIntegration(dataDirectory, monitor);
  let verifiedClaudeProbe: ProbeResult = probe;
  await check('Claude 真实服务每次实时请求、出口 IP 强校验且禁用缓存复用', async () => {
    const requests: string[] = [];
    const requestChannel = channel('http.client.request.start');
    const recordRequest = (message: unknown) => {
      const request = (message as { request: ClientRequest }).request;
      requests.push(`${request.getHeader('host')}${request.path}`);
    };
    requestChannel.subscribe(recordRequest);
    try {
      const targetProxyUrl = process.env.GUARD_TEST_CLAUDE_PROXY || systemProxy.proxyUrl;
      let actual = { ...probe };
      for (let attempt = 0; attempt < 3; attempt++) {
        requests.length = 0;
        actual = { ...probe };
        await engineInternal.verifyTargetServiceRegion(targetProxyUrl, actual, 'claude', true);
        if (actual.claudeTraceLoc) break;
        await sleep(600);
      }
      assert.ok(actual.claudeTraceLoc, actual.claudeTraceError || 'Claude 真实服务未返回有效地区');
      assert.ok(isValidIpAddress(actual.claudeTraceIp), 'Claude 真实服务未返回有效出口 IP');
      assert.ok(requests.some((url) => url === 'claude.ai/cdn-cgi/trace'));
      assert.ok(requests.every((url) => url.startsWith('claude.ai/')), requests.join(', '));
      assert.equal(actual.googleCountryCode, undefined);
      assert.equal(actual.googleCountryName, undefined);
      assert.equal(engineInternal.targetVerifyCache.size, 0, 'Claude 目标校验不应写入缓存');
      const traceGeo = geo.lookup(actual.claudeTraceIp!);
      const expectedMatch =
        actual.claudeTraceLoc === actual.countryCode &&
        (traceGeo.countryCode === 'UNKNOWN' || traceGeo.countryCode === actual.countryCode);
      assert.equal(getTargetServiceVerificationError(actual) === null, expectedMatch);
      const effectiveCountry =
        traceGeo.countryCode !== 'UNKNOWN' ? traceGeo.countryCode : actual.claudeTraceLoc;
      verifiedClaudeProbe = {
        ...actual,
        countryCode: effectiveCountry,
        claudeTraceLoc: effectiveCountry,
        regionMismatchDetail: null,
      };
      let secondLive = { ...probe };
      for (let attempt = 0; attempt < 3; attempt++) {
        requests.length = 0;
        secondLive = { ...probe };
        await engineInternal.verifyTargetServiceRegion(targetProxyUrl, secondLive, 'claude', false);
        if (secondLive.claudeTraceLoc) break;
        await sleep(600);
      }
      assert.ok(
        requests.some((url) => url === 'claude.ai/cdn-cgi/trace'),
        '未传 forceRefresh 时 Claude 也必须发起实时 trace 请求而非读缓存'
      );
      assert.ok(
        isValidIpAddress(secondLive.claudeTraceIp),
        secondLive.claudeTraceError || '二次实时请求未返回有效出口 IP'
      );
      assert.equal(engineInternal.targetVerifyCache.size, 0);
    } finally {
      requestChannel.unsubscribe(recordRequest);
      engineInternal.targetVerifyCache.clear();
    }
  });
  await check('Claude 专属运行期巡检定时器与全局心跳解耦且上限 10 秒', () => {
    assert.equal(CLAUDE_MAX_RUNTIME_POLL_SEC, 10);
    const timerStore = new ConfigStore();
    const prev = timerStore.get();
    const timerMonitor = new ClashMonitor();
    const timerEngine = new ProbeEngine(timerStore, geo, timerMonitor);
    const timerInternal = timerEngine as any;
    try {
      timerStore.update({ claudeExclusiveGuard: false, heartbeatIntervalSec: 0 });
      timerEngine.restartHeartbeatTimer();
      assert.equal(timerInternal.heartbeatTimer, null, '全局心跳为 0 时不应启动实时监控定时器');
      assert.ok(timerInternal.claudeHeartbeatTimer, '全局心跳为 0 时仍应启动 Claude 专属 10 秒巡检定时器');
      timerStore.update({ heartbeatIntervalSec: 60 });
      timerEngine.restartHeartbeatTimer();
      assert.ok(timerInternal.heartbeatTimer);
      assert.ok(timerInternal.claudeHeartbeatTimer);
    } finally {
      timerEngine.stop();
      assert.equal(timerInternal.heartbeatTimer, null);
      assert.equal(timerInternal.claudeHeartbeatTimer, null);
      timerStore.update(prev);
    }
  });
  await check('真实连接失败阻止目标服务验证通过', async () => {
    await engineInternal.verifyTargetServiceRegion('http://127.0.0.1:1', probe, 'claude', true);
    assert.match(getTargetServiceVerificationError(probe) || '', /claude\.ai\/cdn-cgi\/trace/);
    assert.ok(probe.claudeTraceError);
    assert.equal(engineInternal.targetVerifyCache.size, 0);
  });
  await check('重新验证失败清除已有的目标服务结果', async () => {
    const previous: ProbeResult = {
      ...probe,
      googleCountryCode: probe.countryCode,
      claudeTraceLoc: probe.countryCode,
      claudeTraceIp: probe.ip,
    };
    await engineInternal.verifyTargetServiceRegion('http://127.0.0.1:1', previous, 'claude', true);
    assert.equal(previous.googleCountryCode, undefined);
    assert.equal(previous.claudeTraceLoc, undefined);
    assert.equal(previous.claudeTraceIp, undefined);
    assert.match(getTargetServiceVerificationError(previous) || '', /claude\.ai\/cdn-cgi\/trace/);
  });
  await check('各应用按对应目标服务判定缺失、出口 IP 合法性和地区冲突', () => {
    assert.equal(isValidIpAddress('104.28.12.34'), true);
    assert.equal(isValidIpAddress('2606:4700:4700::1111'), true);
    assert.equal(isValidIpAddress('999.1.1.1'), false);
    assert.equal(isValidIpAddress('not-an-ip'), false);
    assert.equal(isValidIpAddress(''), false);

    const country = probe.countryCode;
    assert.ok(getTargetServiceVerificationError({ ...probe, googleCountryCode: country }));
    assert.ok(
      getTargetServiceVerificationError({ ...probe, claudeTraceLoc: country, claudeTraceIp: undefined }),
      '缺失 claudeTraceIp 必须拒绝通过 Claude 校验'
    );
    assert.ok(
      getTargetServiceVerificationError({ ...probe, claudeTraceLoc: country, claudeTraceIp: 'invalid' }),
      '非法 claudeTraceIp 必须拒绝通过 Claude 校验'
    );
    assert.equal(
      getTargetServiceVerificationError({ ...probe, claudeTraceLoc: country, claudeTraceIp: probe.ip }),
      null
    );
    assert.equal(
      getTargetServiceVerificationError({
        ...probe,
        claudeTraceLoc: country,
        claudeTraceIp: '2606:4700:4700::1111',
      }),
      null
    );
    assert.equal(getTargetServiceVerificationError({
      ...probe, googleCountryCode: country, claudeTraceLoc: country, claudeTraceIp: probe.ip,
    }), null);
    assert.ok(getTargetServiceVerificationError({
      ...probe,
      googleCountryCode: country,
      claudeTraceLoc: country === 'JP' ? 'US' : 'JP',
      claudeTraceIp: probe.ip,
    }));
    assert.equal(getTargetServiceVerificationError({
      ...probe,
      googleCountryCode: country === 'JP' ? 'US' : 'JP',
      claudeTraceLoc: country,
      claudeTraceIp: probe.ip,
    }), null);
    assert.equal(getTargetServiceVerificationError({ ...probe, googleCountryCode: country }, 'antigravity'), null);
    assert.ok(getTargetServiceVerificationError({
      ...probe, claudeTraceLoc: country, claudeTraceIp: probe.ip,
    }, 'antigravity'));
    assert.ok(getTargetServiceVerificationError({
      ...probe, googleCountryCode: country === 'JP' ? 'US' : 'JP',
    }, 'antigravity'));
  });
  await runClaudeVerificationRecoveryTests(dataDirectory, engine, store, verifiedClaudeProbe, probe);
  monitor.stop();
  await sleep(100);
}

app.whenReady().then(async () => {
  try {
    await run();
    app.exit(0);
  } catch (error) {
    console.error(error);
    app.exit(1);
  }
});
