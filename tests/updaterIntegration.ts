import { app } from 'electron';
import assert from 'node:assert/strict';
import { getRawFs } from '../electron/utils/rawFs';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { spawn, ChildProcess } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import {
  buildEncodedPowerShellLaunch,
  readUpdateFailureReason,
  resolveWindowsPowerShellExe,
  writeUpdateReadyFile,
} from '../electron/updater';

const root = process.env.GUARD_TEST_DATA!;
const fs = getRawFs();
if (!root) throw new Error('更新测试需要独立数据目录');
fs.mkdirSync(root, { recursive: true });
app.setPath('userData', root);
const children: ChildProcess[] = [];
const trackedPids = new Set<number>();

async function waitUntil(check: () => boolean, label: string): Promise<void> {
  const deadline = Date.now() + 15000;
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`等待超时：${label}`);
    await delay(100);
  }
}

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false; throw error; }
}

function processRecords(directory: string): Array<{ pid: number; child: number; updated: boolean; rolledBack: boolean }> {
  return fs.readdirSync(directory).filter((file) => file.startsWith('process-')).map((file) => {
    const record = JSON.parse(fs.readFileSync(path.join(directory, file), 'utf8'));
    trackedPids.add(record.pid);
    trackedPids.add(record.child);
    return record;
  });
}

async function runCase(name: string, fixture: string, shellDirectory: string): Promise<void> {
  const directory = path.join(root, name);
  fs.mkdirSync(directory, { recursive: true });
  const appDirectory = path.join(directory, '卫士 安装目录 [集成]');
  fs.cpSync(shellDirectory, appDirectory, { recursive: true });
  const resources = path.join(appDirectory, 'resources');
  const exe = path.join(appDirectory, 'electron.exe');
  fs.rmSync(path.join(resources, 'default_app.asar'), { force: true });
  const stage = path.join(directory, 'stage');
  fs.mkdirSync(stage);
  const source = path.join(directory, 'source');
  fs.mkdirSync(source);
  fs.copyFileSync(fixture, path.join(source, 'main.cjs'));
  // 使用 ASAR 官方工具生成两个真实应用包。
  const asar = await import(pathToFileURL(path.join(process.cwd(), 'node_modules', '@electron', 'asar', 'lib', 'asar.js')).href);
  fs.writeFileSync(path.join(source, 'package.json'), JSON.stringify({ name: 'guard-update-integration', version: '1.0.0', main: 'main.cjs' }));
  await asar.createPackage(source, path.join(resources, 'app.asar'));
  const oldHash = createHash('sha256').update(fs.readFileSync(path.join(resources, 'app.asar'))).digest('hex');
  fs.writeFileSync(path.join(source, 'package.json'), JSON.stringify({ name: 'guard-update-integration', version: '2.0.0', main: 'main.cjs' }));
  const payload = path.join(stage, 'payload.bin');
  await asar.createPackage(source, payload);
  const hash = createHash('sha256').update(fs.readFileSync(payload)).digest('hex');
  const diagnostic = path.join(directory, 'diagnostic.jsonl');
  fs.writeFileSync(diagnostic, '');
  const env = { ...process.env, GUARD_UPDATER_TEST_ROOT: directory, GUARD_UPDATER_TEST_CASE: name };
  const old = spawn(exe, [], { env, stdio: 'ignore', windowsHide: true });
  children.push(old);
  await waitUntil(() => processRecords(directory).length > 0, '旧版本启动');
  const original = processRecords(directory)[0];
  if (name === 'launch-failure') {
    old.kill();
    await waitUntil(() => !alive(original.pid), '旧进程退出');
    fs.renameSync(exe, `${exe}.unavailable`);
  }
  const { encodedCommand, scriptGzB64 } = buildEncodedPowerShellLaunch();
  const updater = spawn(resolveWindowsPowerShellExe(), ['-NoProfile', '-NonInteractive', '-EncodedCommand', encodedCommand], {
    env: {
      ...env, GUARD_UPD_SCRIPT_GZ: scriptGzB64, GUARD_UPD_PID: String(name === 'wrong-process' ? original.child : name === 'launch-failure' ? 0 : original.pid),
      GUARD_UPD_MODE: 'asar', GUARD_UPD_APP_DIR: appDirectory, GUARD_UPD_RES_DIR: resources,
      GUARD_UPD_EXE_PATH: exe, GUARD_UPD_FROM_VER: '1.0.0', GUARD_UPD_TO_VER: '2.0.0',
      GUARD_UPD_STAGED_ASAR: payload, GUARD_UPD_ASAR_SHA256: hash,
      GUARD_UPD_STAGE_DIR: stage, GUARD_UPD_READY_FILE: path.join(directory, 'ready.ok'),
      GUARD_UPD_DIAGNOSTIC_FILE: diagnostic, GUARD_UPD_BOOT_CHECK_MS: '8000', GUARD_UPD_WAIT_EXIT_ATTEMPTS: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
  });
  children.push(updater);
  let output = '';
  updater.stdout?.on('data', (data) => { output += data; });
  updater.stderr?.on('data', (data) => { output += data; });
  const exitCode = await new Promise<number | null>((resolve, reject) => {
    const timer = setTimeout(() => { updater.kill(); reject(new Error(`更新脚本超时：${output}`)); }, 40000);
    updater.once('error', reject);
    updater.once('exit', (code) => { clearTimeout(timer); resolve(code); });
  });
  const events = fs.readFileSync(diagnostic, 'utf8').trim().split(/\r?\n/).map((line) => JSON.parse(line));
  const records = processRecords(directory);
  if (name === 'wrong-process') {
    assert.equal(exitCode, 1);
    assert.equal(alive(original.pid), true);
    assert.equal(alive(original.child), true);
    assert.equal(createHash('sha256').update(fs.readFileSync(path.join(resources, 'app.asar'))).digest('hex'), oldHash);
    assert.ok(events.some((event) => event.phase === 'updater-failed' && event.message.includes('路径不匹配')));
    console.log('通过：拒绝终止路径不匹配的真实进程，应用包保持完整');
    return;
  }
  assert.equal(alive(original.pid), false, '旧版本必须退出');
  assert.equal(alive(original.child), true, '旧版本启动的外部进程必须保留');
  assert.equal(exitCode, name === 'success' ? 0 : 2, `${output}\n${JSON.stringify(events)}`);
  const installedHash = createHash('sha256').update(fs.readFileSync(path.join(resources, 'app.asar'))).digest('hex');
  if (name === 'success') {
    assert.equal(installedHash, hash);
    assert.ok(events.some((event) => event.phase === 'complete'));
  } else {
    assert.equal(installedHash, oldHash);
    assert.ok(events.some((event) => event.phase === (name === 'timeout' ? 'boot-timeout' : name === 'launch-failure' ? 'launch-failed' : 'boot-failed')));
    assert.ok(events.some((event) => event.phase === 'rollback-complete'));
    if (name === 'launch-failure') {
      assert.ok(events.find((event) => event.phase === 'launch-failed').message.length > 20);
      console.log('通过：可执行文件缺失时保留系统启动异常并恢复应用包');
      return;
    }
    const updated = records.find((record) => record.updated)!;
    assert.ok(updated);
    assert.equal(alive(updated.child), true, '回滚后新版启动的外部进程必须保留');
    await waitUntil(() => fs.existsSync(path.join(directory, 'rollback-reason.txt')), '回滚原因显示');
    const reason = fs.readFileSync(path.join(directory, 'rollback-reason.txt'), 'utf8');
    assert.match(reason, name === 'timeout' ? /超时/ : /EISDIR|EPERM|EACCES/);
  }
  console.log(`通过：${name}，实际替换应用包，验证诊断结果及外部子进程存活`);
}

async function run(): Promise<void> {
  const readyFile = path.join(root, 'atomic-ready.ok');
  const readyArgs = [`--update-ready-file=${readyFile}`];
  writeUpdateReadyFile(readyArgs);
  assert.match(fs.readFileSync(readyFile, 'utf8'), new RegExp(`^${process.pid}:\\d+\\n$`));
  fs.unlinkSync(readyFile);
  fs.mkdirSync(readyFile);
  assert.throws(() => writeUpdateReadyFile(readyArgs), /EISDIR|EPERM|EACCES/);
  assert.ok(!fs.readdirSync(root).some((file) => file.endsWith('.tmp')));
  const brokenDiagnostic = path.join(root, 'broken-diagnostic.jsonl');
  fs.writeFileSync(brokenDiagnostic, '{"phase":');
  const diagnosticArgs = [`--update-diagnostic-file=${brokenDiagnostic}`];
  assert.match(readUpdateFailureReason(diagnosticArgs), /诊断文件读取或解析失败/);
  assert.ok(readUpdateFailureReason(diagnosticArgs).includes(brokenDiagnostic));
  fs.unlinkSync(brokenDiagnostic);
  assert.match(readUpdateFailureReason(diagnosticArgs), /ENOENT/);
  console.log('通过：就绪标记完整发布、失败清理临时文件，损坏或缺失的诊断文件提供明确提示');
  const fixture = process.env.GUARD_UPDATER_TEST_APP!;
  assert.ok(fixture);
  for (const name of ['success', 'timeout', 'write-failure', 'launch-failure', 'wrong-process']) {
    await runCase(name, fixture, path.dirname(process.execPath));
  }
}

let resultCode = 0;
run().catch((error) => { console.error(error); resultCode = 1; }).finally(async () => {
  for (const directory of fs.readdirSync(root, { withFileTypes: true }).filter((entry) => entry.isDirectory())) {
    processRecords(path.join(root, directory.name));
  }
  for (const child of children) { if (child.exitCode === null) child.kill(); }
  for (const pid of trackedPids) { if (alive(pid)) process.kill(pid); }
  await delay(500);
  app.exit(resultCode);
});
