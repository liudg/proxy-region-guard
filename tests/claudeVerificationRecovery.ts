import { app } from 'electron';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import * as http from 'node:http';
import * as net from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import {
  ClaudeVerificationRecovery,
  normalizeVerificationFailureSignature,
} from '../electron/guard';

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

async function verifyUnhandledCallbackExitsNonZero(closedPort: number): Promise<void> {
  const capturedErrors: unknown[] = [];
  const handled = new ClaudeVerificationRecovery(
    () => connect(),
    80,
    (err) => {
      capturedErrors.push(err);
    }
  );
  try {
    handled.recordFailure('connect ECONNREFUSED');
    await delay(260);
    assert.ok(capturedErrors.length >= 2, '提供 onRetryError 时应捕获后台复核回调异常');
    assert.equal((capturedErrors[0] as NodeJS.ErrnoException).code, 'ECONNREFUSED');
  } finally {
    handled.clear();
  }

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    GUARD_RECOVERY_UNHANDLED_CHILD: '1',
    GUARD_RECOVERY_CLOSED_PORT: String(closedPort),
  };
  delete env.ELECTRON_RUN_AS_NODE;
  const child = spawn(process.execPath, [process.argv[1]], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  let stderr = '';
  child.stderr?.on('data', (chunk: Buffer) => {
    stderr += chunk.toString('utf8');
  });
  const [exitCode] = (await once(child, 'exit')) as [number | null];
  assert.notEqual(exitCode, 0, `后台复核回调抛出未捕获异常时子进程不得以 0 退出，stderr=${stderr}`);
  assert.match(stderr, /ECONNREFUSED/, '未捕获复核异常输出中应包含真实 ECONNREFUSED 原因');
  console.log('通过：后台复核回调未捕获异常时测试进程以非 0 退出码终止');
}

async function verifyStaleRetryDoesNotOverwriteNextFailure(): Promise<void> {
  const heldSockets: net.Socket[] = [];
  const holdServer = http.createServer((req, res) => {
    heldSockets.push(req.socket);
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.flushHeaders();
  });
  holdServer.listen(0, '127.0.0.1');
  await once(holdServer, 'listening');
  const holdPort = (holdServer.address() as net.AddressInfo).port;

  let staleGuard!: ClaudeVerificationRecovery;
  staleGuard = new ClaudeVerificationRecovery(
    () =>
      new Promise<void>((resolve, reject) => {
        const req = http.get(`http://127.0.0.1:${holdPort}/`, (res) => {
          res.on('data', () => undefined);
          res.on('end', () => resolve());
          res.on('error', reject);
        });
        req.on('error', reject);
      }),
    60,
    (err) => {
      const detail = err instanceof Error ? err.message : String(err);
      staleGuard.recordFailure(detail);
    }
  );

  try {
    staleGuard.recordFailure('第一轮初始故障');
    const waitRound1 = Date.now() + 2000;
    while (heldSockets.length < 1 && Date.now() < waitRound1) {
      await delay(20);
    }
    assert.equal(heldSockets.length >= 1, true, '第一轮后台复核请求应已抵达本地 HTTP 服务');
    const round1Socket = heldSockets[0];

    staleGuard.clear();
    staleGuard.recordFailure('第二轮新故障原因');
    round1Socket.destroy();
    await delay(100);
    assert.equal(
      staleGuard.snapshot?.reason,
      '第二轮新故障原因',
      '已清除的第一轮异步请求断开后不得覆盖第二轮的新故障原因'
    );
    console.log('通过：旧轮次后台复核异步断开不会覆盖新一轮故障原因');
  } finally {
    staleGuard.clear();
    for (const sock of heldSockets) sock.destroy();
    await new Promise<void>((resolve) => holdServer.close(() => resolve()));
  }
}

function verifyFailureSignatureLinearTimeAndFormat(): void {
  const longUrlNoColon = `Claude 专属节点出口不可达 (Claude 专属节点 [节点[含括号] https://${'a'.repeat(40000)}] (127.0.0.1:27897)：连接超时)`;
  const startedAt = Date.now();
  const sig = normalizeVerificationFailureSignature(longUrlNoColon);
  const elapsedMs = Date.now() - startedAt;
  assert.ok(elapsedMs < 200, `超长无冒号 URL 归一化不得发生指数回溯 (实际 ${elapsedMs}ms)`);
  assert.ok(sig.includes('连接超时'));

  assert.equal(
    normalizeVerificationFailureSignature('目标服务地区校验未通过：https://claude.ai/cdn-cgi/trace：连接超时'),
    normalizeVerificationFailureSignature('目标服务地区校验未通过：https://claude.ai/cdn-cgi/trace: 连接超时')
  );
  assert.equal(
    normalizeVerificationFailureSignature('目标服务地区校验未通过：http://[::1]:8080/trace：连接超时'),
    normalizeVerificationFailureSignature('目标服务地区校验未通过：http://127.0.0.1:8080/trace:连接超时')
  );
  assert.equal(
    normalizeVerificationFailureSignature('代理连接失败 http://127.0.0.1:8080'),
    '代理连接失败 http://127.0.0.1:8080',
    '不带错误分隔符的端口 URL 不得误把端口号截断为探测分隔符'
  );
  console.log('通过：复核错误归一化线性耗时（防 ReDoS 回溯）且兼容 IPv6/端口/冒号变体');
}

async function run(): Promise<void> {
  if (process.env.GUARD_RECOVERY_UNHANDLED_CHILD === '1') {
    port = Number(process.env.GUARD_RECOVERY_CLOSED_PORT);
    const throwingRecovery = new ClaudeVerificationRecovery(() => connect(), 80);
    throwingRecovery.recordFailure('connect ECONNREFUSED');
    await delay(400);
    throwingRecovery.clear();
    return;
  }

  verifyFailureSignatureLinearTimeAndFormat();

  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  port = (listener.address() as net.AddressInfo).port;
  await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));

  await verifyUnhandledCallbackExitsNonZero(port);
  await verifyStaleRetryDoesNotOverwriteNextFailure();

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
  try {
    recovery.clear();
  } finally {
    if (listener.listening) {
      await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
    }
  }
}

app.whenReady().then(run).then(cleanup).then(() => app.exit(0)).catch(async (error) => {
  console.error(error);
  try { await cleanup(); }
  finally { app.exit(1); }
});
