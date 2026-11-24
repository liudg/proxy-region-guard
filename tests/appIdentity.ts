import { app } from 'electron';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn, ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { configureAppUserData } from '../electron/appIdentity';

const rawRoot = process.env.GUARD_TEST_DATA;
if (!rawRoot) throw new Error('实例测试需要独立数据目录');
const root: string = rawRoot;
fs.mkdirSync(root, { recursive: true });
app.setPath('appData', root);

const role = process.env.GUARD_IDENTITY_ROLE;
if (role) {
  app.setName(role === 'development' ? 'proxy-region-guard' : '代理地区卫士');
  app.setPath('userData', path.join(root, app.getName()));
  configureAppUserData();
  assert.equal(app.getPath('userData'), path.join(root, '代理地区卫士'));
  const locked = app.requestSingleInstanceLock();
  process.send?.({ locked });
  if (!locked) {
    app.exit(0);
  } else {
    app.on('second-instance', () => process.send?.({ secondInstance: true }));
    process.on('message', (message) => {
      assert.equal(message, 'quit');
      app.quit();
    });
    app.whenReady().then(() => process.send?.({ ready: true }));
  }
} else {
  const children: ChildProcess[] = [];
  function launch(name: string): ChildProcess {
    const child = spawn(process.execPath, [__filename], {
      env: { ...process.env, GUARD_IDENTITY_ROLE: name },
      stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
      windowsHide: true,
    });
    children.push(child);
    return child;
  }

  async function message(child: ChildProcess, key: string): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => finish(new Error(`等待实例消息超时：${key}`)), 15000);
      const onMessage = (value: Record<string, unknown>) => {
        if (key in value) finish(null, value[key]);
      };
      const onExit = (code: number | null) => finish(new Error(`实例提前退出：${code}`));
      const finish = (error: Error | null, value?: unknown) => {
        clearTimeout(timer);
        child.removeListener('message', onMessage);
        child.removeListener('exit', onExit);
        child.removeListener('error', onError);
        if (error) reject(error);
        else resolve(value);
      };
      const onError = (error: Error) => finish(error);
      child.on('message', onMessage);
      child.once('exit', onExit);
      child.once('error', onError);
    });
  }

  async function run(): Promise<void> {
    const customDirectory = path.join(root, 'desktop-acceptance');
    app.setPath('userData', customDirectory);
    configureAppUserData();
    assert.equal(app.getPath('userData'), customDirectory);

    const first = launch('development');
    const firstReady = message(first, 'ready');
    assert.equal(await message(first, 'locked'), true);
    await firstReady;

    const notified = message(first, 'secondInstance');
    const second = launch('packaged');
    const secondExit = once(second, 'exit');
    assert.equal(await message(second, 'locked'), false);
    assert.equal((await secondExit)[0], 0);
    assert.equal(await notified, true);

    const firstExit = once(first, 'exit');
    first.send('quit');
    assert.equal((await firstExit)[0], 0);

    const third = launch('packaged');
    const thirdReady = message(third, 'ready');
    assert.equal(await message(third, 'locked'), true);
    await thirdReady;
    const thirdExit = once(third, 'exit');
    third.send('quit');
    assert.equal((await thirdExit)[0], 0);
    console.log('通过：默认数据目录一致、重复启动通知已有实例、退出释放实例锁、独立验收目录保持有效');
  }

  run().then(() => app.exit(0)).catch((error) => {
    console.error(error);
    for (const child of children) {
      if (child.exitCode === null) child.kill();
    }
    app.exit(1);
  });
}
