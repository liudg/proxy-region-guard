import { app } from 'electron';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { ConfigStore } from '../electron/configStore';
import { ClashMonitor } from '../electron/clashMonitor';
import { GeoIpService } from '../electron/geoipService';
import { ProbeEngine } from '../electron/probeEngine';
import { readWindowsSystemProxy } from '../electron/systemProxy';
import { runClaudeVerificationRecoveryTests } from './claudeVerificationRecovery';

assert.ok(process.env.GUARD_TEST_DATA);
const directory = process.env.GUARD_TEST_DATA;
fs.mkdirSync(directory, { recursive: true });
app.setPath('userData', directory);
app.whenReady().then(async () => {
  try {
    const store = new ConfigStore();
    const geo = new GeoIpService();
    await geo.init(process.cwd());
    const engine = new ProbeEngine(store, geo, new ClashMonitor());
    const systemProxy = await readWindowsSystemProxy();
    assert.ok(systemProxy.proxyUrl);
    const detected = await (engine as any).probeOnceViaChannel(systemProxy.proxyUrl, '运行期测试', 5800);
    assert.ok(detected.result, detected.errMsg);
    await runClaudeVerificationRecoveryTests(directory, engine, store, systemProxy.proxyUrl, detected.result);
    app.exit(0);
  } catch (error) {
    console.error(error);
    app.exit(1);
  }
});
