import { app } from 'electron';
import assert from 'node:assert/strict';
import * as net from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { ClaudeVerificationRecovery } from '../electron/claudeVerificationRecovery';

const listener = net.createServer((socket) => socket.end());
let port: number;
let attempts = 0;
let failures = 0;
let successes = 0;

async function connect(): Promise<void> {
  const socket = net.createConnection({ host: '127.0.0.1', port });
  try {
    await once(socket, 'connect');
  } finally {
    socket.destroy();
  }
}

const recovery = new ClaudeVerificationRecovery(async () => {
  attempts++;
  try {
    await connect();
  } catch (error) {
    assert.equal((error as NodeJS.ErrnoException).code, 'ECONNREFUSED');
    failures++;
    const result = recovery.recordFailure((error as Error).message);
    assert.equal(result.shouldLog, false);
    return;
  }
  successes++;
  assert.ok(recovery.clear());
});

async function run(): Promise<void> {
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  port = (listener.address() as net.AddressInfo).port;
  await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));

  let reason = '';
  await assert.rejects(connect(), (error: NodeJS.ErrnoException) => {
    assert.equal(error.code, 'ECONNREFUSED');
    reason = error.message;
    return true;
  });
  assert.deepEqual(recovery.recordFailure(reason), { shouldLog: true, stateChanged: true });
  const startedAt = recovery.snapshot!.startedAt;
  await delay(31000);
  assert.ok(Date.now() - startedAt > 30000);
  assert.ok(failures >= 5);
  assert.equal(recovery.snapshot?.startedAt, startedAt);
  assert.equal(recovery.snapshot?.reason, reason);
  console.log('通过：真实连接失败超过 30 秒，后台复核继续运行并保留异常状态');

  const previousAttempts = attempts;
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  port = (listener.address() as net.AddressInfo).port;
  const deadline = Date.now() + 10000;
  while (recovery.snapshot) {
    assert.ok(Date.now() < deadline, '连接恢复后未清除复核状态');
    await delay(100);
  }
  assert.ok(attempts > previousAttempts);
  assert.equal(successes, 1);
  const completedAttempts = attempts;
  await delay(5500);
  assert.equal(attempts, completedAttempts);
  console.log('通过：真实连接恢复后清除异常状态并停止复核计时器');

  recovery.recordFailure(reason);
  assert.ok(recovery.clear());
  assert.equal(recovery.snapshot, null);
  await delay(5500);
  assert.equal(attempts, completedAttempts);
  console.log('通过：主动清除异常状态后停止复核计时器');
}

async function cleanup(): Promise<void> {
  recovery.clear();
  if (listener.listening) {
    await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
  }
}

app.whenReady().then(run).then(cleanup).then(() => app.exit(0)).catch(async (error) => {
  console.error(error);
  try { await cleanup(); }
  finally { app.exit(1); }
});
