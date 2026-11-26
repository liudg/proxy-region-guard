import { app, BrowserWindow } from 'electron';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { readUpdateFailureReason, recordUpdateBootEvent, writeUpdateReadyFile } from '../electron/updater';

const root = process.env.GUARD_UPDATER_TEST_ROOT!;
if (!root) throw new Error('更新测试需要独立目录');
app.setPath('userData', path.join(root, `data-${process.pid}`));
const updated = process.argv.some((arg) => arg.startsWith('--updated-from='));
const rolledBack = process.argv.some((arg) => arg.startsWith('--update-rolled-back='));

app.whenReady().then(async () => {
  const win = new BrowserWindow({ show: false });
  await win.loadURL('data:text/html,<title>Updater integration</title>');
  const child = spawn(process.env.GUARD_TEST_NODE!, ['-e', 'setTimeout(() => process.exit(0), 60000)'], {
    detached: true, stdio: 'ignore', windowsHide: true,
  });
  child.unref();
  fs.writeFileSync(path.join(root, `process-${process.pid}.json`), JSON.stringify({ pid: process.pid, child: child.pid, updated, rolledBack }));
  if (rolledBack) {
    fs.writeFileSync(path.join(root, 'rollback-reason.txt'), readUpdateFailureReason(process.argv));
    app.exit(0);
    return;
  }
  if (!updated) return;
  recordUpdateBootEvent('boot-start', '测试应用已创建真实窗口');
  if (process.env.GUARD_UPDATER_TEST_CASE === 'timeout') return;
  if (process.env.GUARD_UPDATER_TEST_CASE === 'write-failure') {
    const readyFile = process.argv.find((arg) => arg.startsWith('--update-ready-file='))!.slice('--update-ready-file='.length);
    fs.mkdirSync(readyFile);
  }
  recordUpdateBootEvent('boot-check-complete', '测试应用启动检查完成');
  writeUpdateReadyFile(process.argv);
}).catch((error: Error) => {
  recordUpdateBootEvent('boot-failed', error.stack || error.message);
  app.exit(1);
});
