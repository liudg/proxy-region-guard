import { app } from 'electron';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { ConfigStore } from '../electron/configStore';

const directory = process.env.GUARD_TEST_DATA;
if (!directory) throw new Error('桌面验收需要独立数据目录');
fs.mkdirSync(directory, { recursive: true });
app.setPath('userData', directory);
app.setAppPath(process.cwd());
const store = new ConfigStore();
store.update({ dedicatedProxyPort: 28897, antigravityDedicatedPort: 28898, autoCheckUpdates: false, autoLaunch: false, closeToTray: false, alertSoundEnabled: false });
let administrator = false;
try {
  execFileSync('fltmc.exe', [], { stdio: 'ignore', windowsHide: true });
  administrator = true;
} catch {
  console.error('桌面验收需要在管理员终端运行，临时配置目录不会自动提权。');
}
if (administrator) require(path.resolve('dist-electron/main.js'));
else app.exit(1);
