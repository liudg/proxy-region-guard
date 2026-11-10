import { app, nativeImage } from 'electron';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as sleep } from 'node:timers/promises';
import { ConfigStore } from '../electron/configStore';
import { buildProfilesSignature, ClashMonitor } from '../electron/clashMonitor';
import { GeoIpService } from '../electron/geoipService';
import { ProbeEngine } from '../electron/probeEngine';
import {
  assertProcessesStopped,
  listRunningProcesses,
  terminateProtectedProcesses,
} from '../electron/processGuard';
import { readWindowsLocaleState } from '../electron/winSystemLocale';
import { readWindowsSystemProxy } from '../electron/systemProxy';
import { getTargetServiceVerificationError } from '../src/shared/probeValidation';
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
import { ClashProfileGroupOption, ProbeResult } from '../src/shared/types';
import { createStatusTrayIcon, createWindowAppIcon } from '../electron/trayIcon';
import { countRunningClaudeProcesses } from '../electron/claudeController';
import { runMihomoIntegration } from './mihomoIntegration';

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
  assert.ok(detected.result, '真实出口检测失败，无法继续网络集成验证');
  const probe: ProbeResult = detected.result;
  await check('真实出口状态在手动重算和网络检测入口保持一致', async () => {
    const previous = store.get();
    const actualLocale = await readWindowsLocaleState();
    engineInternal.winLocale = actualLocale;
    store.update({ defaultCountryCode: probe.countryCode, protectedProcessPatterns: [] });
    const networkState = await engine.checkNow('回归验证');
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
  await check('真实连接失败阻止目标服务验证通过', async () => {
    await engineInternal.verifyTargetServiceRegion('http://127.0.0.1:1', probe, 'claude', true);
    assert.match(getTargetServiceVerificationError(probe) || '', /Google、Claude/);
    assert.equal(engineInternal.targetVerifyCache.size, 0);
  });
  await check('重新验证失败清除已有的目标服务结果', async () => {
    const previous: ProbeResult = {
      ...probe, googleCountryCode: probe.countryCode, claudeTraceLoc: probe.countryCode,
    };
    await engineInternal.verifyTargetServiceRegion('http://127.0.0.1:1', previous, 'claude', true);
    assert.equal(previous.googleCountryCode, undefined);
    assert.equal(previous.claudeTraceLoc, undefined);
    assert.match(getTargetServiceVerificationError(previous) || '', /Google、Claude/);
  });
  await check('缺失任意目标服务结果均阻止验证通过', () => {
    const country = probe.countryCode;
    assert.ok(getTargetServiceVerificationError({ ...probe, googleCountryCode: country }));
    assert.ok(getTargetServiceVerificationError({ ...probe, claudeTraceLoc: country }));
    assert.equal(getTargetServiceVerificationError({
      ...probe, googleCountryCode: country, claudeTraceLoc: country,
    }), null);
    assert.ok(getTargetServiceVerificationError({
      ...probe, googleCountryCode: country, claudeTraceLoc: country === 'JP' ? 'US' : 'JP',
    }));
  });
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
