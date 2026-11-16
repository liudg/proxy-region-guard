import { EventEmitter } from 'node:events';
import { execFile, spawn, ChildProcess } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import * as yaml from 'js-yaml';
import { PrivateChannelId, PrivateChannelState } from '../src/shared/types';
import { MihomoEndpoint, mihomoRequest, isLocalPortListening } from './mihomoClient';
import { NodeSnapshot, SubscriptionCatalog, snapshotFingerprint } from './subscriptionCatalog';
import { requestTextViaProxy } from './netClient';

const execute = promisify(execFile);
interface SavedChannel { schema: 1; snapshot: NodeSnapshot; port: number; revision: string }
interface Lease { pid: number; executable: string; revision: string; endpoint: MihomoEndpoint }

function atomicJson(file: string, value: unknown): void {
  const temporary = `${file}.${randomUUID()}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(value), { mode: 0o600 });
  fs.renameSync(temporary, file);
}

export function verifyCore(directory: string): string {
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json'), 'utf8')) as { version: string; sha256: string };
  const executable = path.join(directory, 'guard-mihomo.exe');
  if (createHash('sha256').update(fs.readFileSync(executable)).digest('hex') !== manifest.sha256) throw new Error('私有 Mihomo 文件完整性校验失败');
  return executable;
}

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false;
    throw error;
  }
}

function errorText(error: unknown): string { return error instanceof Error ? error.message : String(error); }

export class PrivateKernel extends EventEmitter {
  private saved: SavedChannel | null = null;
  private lease: Lease | null = null;
  private child: ChildProcess | null = null;
  private queue: Promise<unknown> = Promise.resolve();
  private timer: NodeJS.Timeout | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private retries: number[] = [];
  private stopped = false;
  private booting = false;
  private recoveryEpoch = 0;
  private readonly state: PrivateChannelState = {
    phase: 'idle', pid: null, port: null, nodeName: null, profileUid: null, profileName: null,
    generation: 0, error: null, verificationError: null, sourceStatus: 'unknown', sourceError: null,
    restartAttempts: 0, nextRetryAt: null,
  };

  constructor(public readonly channel: PrivateChannelId, private readonly directory: string,
    private readonly executable: string) {
    super();
    fs.mkdirSync(directory, { recursive: true });
  }

  public getState(): PrivateChannelState { return { ...this.state }; }
  public getSnapshot(): NodeSnapshot | null { return this.saved ? structuredClone(this.saved.snapshot) : null; }
  private publish(): void { this.emit('state', this.getState()); }

  private async verifyProcessIdentity(lease: Lease): Promise<void> {
    const result = await execute('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      'Get-CimInstance Win32_Process -Filter ("ProcessId=" + $env:GUARD_KERNEL_PID) | Select-Object ExecutablePath,CommandLine | ConvertTo-Json -Compress'],
    { windowsHide: true, env: { ...process.env, GUARD_KERNEL_PID: String(lease.pid) }, timeout: 5000 });
    const identity = JSON.parse(result.stdout);
    const configuration = path.join(this.directory, lease.revision, 'config.yaml');
    if (!identity || String(identity.ExecutablePath).toLowerCase() !== this.executable.toLowerCase() ||
        !String(identity.CommandLine).toLowerCase().includes(configuration.toLowerCase())) {
      throw new Error('私有内核进程身份不匹配');
    }
  }
  private serial<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.queue.then(operation);
    this.queue = pending.then(() => undefined, () => undefined);
    return pending;
  }

  private setSelection(saved: SavedChannel | null): void {
    this.saved = saved;
    Object.assign(this.state, {
      nodeName: saved?.snapshot.nodeName || null, profileUid: saved?.snapshot.profileUid || null,
      profileName: saved?.snapshot.profileName || null, port: saved?.port || null,
      error: null, verificationError: null, generation: this.state.generation + 1,
    });
    this.publish();
  }

  public async restore(): Promise<void> {
    this.stopped = false;
    const file = path.join(this.directory, 'current.json');
    if (!fs.existsSync(file)) return;
    try {
      const saved = JSON.parse(fs.readFileSync(file, 'utf8')) as SavedChannel;
      if (saved.schema !== 1 || !saved.snapshot || !Number.isInteger(saved.port) || saved.port < 1 || saved.port > 65535) throw new Error('私有节点副本格式无效');
      if (!/^[0-9a-f-]{36}$/.test(saved.revision)) throw new Error('私有节点副本目录标识无效');
      const { fingerprint, ...definition } = saved.snapshot;
      if (snapshotFingerprint(definition) !== fingerprint) throw new Error('私有节点副本校验失败');
      this.setSelection(saved);
      const leasePath = path.join(this.directory, 'runtime.json');
      if (fs.existsSync(leasePath)) {
        const lease = JSON.parse(fs.readFileSync(leasePath, 'utf8')) as Lease;
        if (alive(lease.pid)) {
          if (lease.revision !== saved.revision || path.resolve(lease.executable) !== path.resolve(this.executable)) throw new Error('已有私有内核与保存的配置版本不一致');
          await this.verifyProcessIdentity(lease);
          this.lease = lease;
          this.state.pid = lease.pid;
          await this.verifyListener();
          await this.verifyForwarding();
          this.state.phase = 'ready';
          this.publish();
          this.emit('ready');
          this.scheduleHealth();
          return;
        }
      }
      await this.startProcess();
    } catch (error) { this.fail(error); }
  }

  private config(saved: SavedChannel, endpoint: MihomoEndpoint): Record<string, unknown> {
    const snapshot = saved.snapshot;
    const policy = snapshot.dns['proxy-server-nameserver-policy'] ||
      (snapshot.dns['proxy-server-nameserver'] ? {} : snapshot.dns['nameserver-policy']) || {};
    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) throw new Error('节点 DNS 策略格式无效');
    if (Object.keys(policy).some((key) => key.includes('rule-set:') || key.includes('geosite:'))) throw new Error('节点 DNS 策略包含外部规则集，请将节点域名解析配置为明确域名');
    const resolvers = snapshot.dns['proxy-server-nameserver'] || snapshot.dns.nameserver || ['https://223.5.5.5/dns-query'];
    const names = new Set(snapshot.proxies.map((proxy) => String(proxy.name)));
    if (!names.has(snapshot.nodeName)) throw new Error('节点副本缺少选中的代理定义');
    let outbound = 'guard-selected-outbound';
    while (names.has(outbound)) outbound += '-private';
    return {
      'mixed-port': saved.port, 'bind-address': '127.0.0.1', 'allow-lan': false,
      mode: 'rule', ipv6: true, 'log-level': 'warning', 'find-process-mode': 'off',
      'external-controller-pipe': endpoint.pipePath, secret: endpoint.secret,
      tun: { enable: false }, profile: { 'store-selected': false, 'store-fake-ip': false },
      dns: { enable: true, ipv6: true, 'enhanced-mode': 'redir-host', 'use-system-hosts': false,
        'default-nameserver': ['223.5.5.5'], 'proxy-server-nameserver': resolvers,
        'proxy-server-nameserver-policy': policy,
        nameserver: [`https://1.1.1.1/dns-query#${outbound}`] },
      hosts: snapshot.hosts, proxies: snapshot.proxies,
      'proxy-groups': [{ name: outbound, type: 'select', proxies: [snapshot.nodeName] }],
      rules: [`MATCH,${outbound}`],
    };
  }

  private async prepare(saved: SavedChannel): Promise<MihomoEndpoint> {
    const revisionDirectory = path.join(this.directory, saved.revision);
    fs.mkdirSync(path.join(revisionDirectory, 'assets'), { recursive: true });
    for (const [name, contents] of Object.entries(saved.snapshot.files)) {
      if (path.basename(name) !== name) throw new Error('节点资源文件名无效');
      fs.writeFileSync(path.join(revisionDirectory, 'assets', name), Buffer.from(contents, 'base64'), { mode: 0o600 });
    }
    const endpoint: MihomoEndpoint = { pipePath: `\\\\.\\pipe\\proxy-region-guard-${this.channel}-${randomUUID()}`, secret: randomBytes(32).toString('hex') };
    const configuration = this.config(saved, endpoint);
    fs.writeFileSync(path.join(revisionDirectory, 'config.yaml'), yaml.dump(configuration, { noRefs: true, lineWidth: -1 }), { mode: 0o600 });
    await execute(this.executable, ['-t', '-d', revisionDirectory, '-f', path.join(revisionDirectory, 'config.yaml')], { windowsHide: true, timeout: 15000 });
    return endpoint;
  }

  public select(snapshot: NodeSnapshot | null, port: number): Promise<void> {
    return this.serial(async () => {
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('私有代理端口无效');
      const next: SavedChannel | null = snapshot ? { schema: 1, snapshot, port, revision: randomUUID() } : null;
      const endpoint = next ? await this.prepare(next) : null;
      if (next && port !== this.state.port && await isLocalPortListening(port)) throw new Error(`专属端口 ${port} 已被其他进程占用`);
      this.cancelRetry();
      try {
        await this.stopProcess();
        if (next) atomicJson(path.join(this.directory, 'current.json'), next);
        else fs.rmSync(path.join(this.directory, 'current.json'), { force: true });
        this.retries = [];
        this.state.restartAttempts = 0;
        this.setSelection(next);
        if (next) await this.startProcess(endpoint!);
        else { this.state.phase = 'idle'; this.publish(); }
      } catch (error) { this.fail(error); throw error; }
    });
  }

  public restart(): Promise<void> {
    return this.serial(async () => {
      if (!this.saved) throw new Error('尚未保存专属节点');
      this.cancelRetry();
      this.retries = [];
      this.state.restartAttempts = 0;
      try { await this.stopProcess(); await this.startProcess(); }
      catch (error) { this.fail(error); throw error; }
    });
  }

  public async checkReady(): Promise<void> {
    if (this.state.phase !== 'ready') throw new Error(this.state.error || '私有内核尚未就绪');
    await this.verifyListener();
  }

  private async verifyListener(): Promise<void> {
    if (!this.lease || !this.saved || !alive(this.lease.pid)) throw new Error('私有内核进程已退出');
    const config = await mihomoRequest<Record<string, unknown>>(this.lease.endpoint, '/configs');
    if (config['mixed-port'] !== this.saved.port || config.mode !== 'rule') throw new Error('私有内核运行配置与保存的副本不一致');
    const proxies = await mihomoRequest<{ proxies: Record<string, unknown> }>(this.lease.endpoint, '/proxies');
    if (!proxies.proxies[this.saved.snapshot.nodeName] || !await isLocalPortListening(this.saved.port)) throw new Error('私有内核专属监听未就绪');
  }

  private async verifyForwarding(): Promise<void> {
    this.state.verificationError = null;
    try {
      await requestTextViaProxy('https://cp.cloudflare.com/generate_204', `http://127.0.0.1:${this.saved!.port}`, 10000);
    } catch (error) {
      this.state.verificationError = `专属代理请求失败：${errorText(error)}`;
    }
  }

  private async startProcess(preparedEndpoint?: MihomoEndpoint): Promise<void> {
    if (this.stopped || !this.saved) throw new Error('私有内核管理已停止');
    if (await isLocalPortListening(this.saved.port)) throw new Error(`专属端口 ${this.saved.port} 已被其他进程占用`);
    const endpoint = preparedEndpoint || await this.prepare(this.saved);
    const revisionDirectory = path.join(this.directory, this.saved.revision);
    this.state.phase = this.retries.length ? 'recovering' : 'starting';
    this.state.error = null;
    this.state.verificationError = null;
    this.state.nextRetryAt = null;
    this.state.generation++;
    this.publish();
    const logPath = path.join(this.directory, 'kernel.log');
    if (fs.existsSync(logPath) && fs.statSync(logPath).size > 2 * 1024 * 1024) {
      fs.rmSync(path.join(this.directory, 'kernel.previous.log'), { force: true });
      fs.renameSync(logPath, path.join(this.directory, 'kernel.previous.log'));
    }
    const log = fs.openSync(logPath, 'a');
    let child: ChildProcess;
    try {
      child = spawn(this.executable, ['-d', revisionDirectory, '-f', path.join(revisionDirectory, 'config.yaml')],
        { windowsHide: true, detached: true, stdio: ['ignore', log, log] });
    } finally { fs.closeSync(log); }
    this.child = child;
    this.booting = true;
    await new Promise<void>((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
    child.unref();
    this.lease = { pid: child.pid!, endpoint, executable: this.executable, revision: this.saved.revision };
    atomicJson(path.join(this.directory, 'runtime.json'), this.lease);
    this.state.pid = child.pid!;
    child.once('exit', (code, signal) => {
      if (this.child !== child) return;
      this.child = null;
      this.lease = null;
      this.state.pid = null;
      if (this.booting) return;
      this.unexpectedExit(`私有内核退出：${signal || code}`);
    });
    let lastError: unknown;
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      if (child.exitCode !== null || child.signalCode !== null) throw new Error('私有内核在启动期间退出，请查看内核日志');
      try { await this.verifyListener(); lastError = null; break; }
      catch (error) { lastError = error; await delay(150); }
    }
    if (lastError) throw lastError;
    // 通过真实 HTTPS 请求确认专属代理能够完成转发。
    await this.verifyForwarding();
    if (this.child !== child || !this.lease) throw new Error('私有内核在启动校验期间退出');
    this.booting = false;
    this.state.phase = 'ready';
    this.publish();
    this.emit('ready');
    this.scheduleHealth();
  }

  private scheduleHealth(): void {
    if (this.timer) clearTimeout(this.timer);
    if (this.stopped) return;
    this.timer = setTimeout(() => void this.serial(async () => {
      if (!this.lease) return;
      if (!alive(this.lease.pid)) { this.lease = null; this.state.pid = null; this.unexpectedExit('私有内核进程已退出'); return; }
      try {
        await this.verifyListener();
        if (this.state.verificationError && this.saved) {
          await requestTextViaProxy('https://cp.cloudflare.com/generate_204', `http://127.0.0.1:${this.saved.port}`, 10000);
          this.state.verificationError = null;
          this.publish();
        }
      } catch (error) { this.state.verificationError = errorText(error); this.publish(); }
      this.scheduleHealth();
    }), 3000);
  }

  private unexpectedExit(reason: string): void {
    if (this.stopped) return;
    this.state.phase = 'recovering';
    this.state.error = reason;
    this.state.generation++;
    this.publish();
    this.emit('lost', reason);
    this.scheduleRecovery();
  }

  private scheduleRecovery(): void {
    if (this.stopped || !this.saved || this.retryTimer) return;
    this.retries = this.retries.filter((time) => Date.now() - time < 60000);
    if (this.retries.length >= 3) { this.fail(new Error('私有内核在 60 秒内连续恢复失败三次，请处理故障后手动重启')); return; }
    const wait = [1000, 3000, 10000][this.retries.length];
    const epoch = this.recoveryEpoch;
    this.state.phase = 'recovering';
    this.state.nextRetryAt = Date.now() + wait;
    this.publish();
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      void this.serial(async () => {
        if (this.stopped || !this.saved || epoch !== this.recoveryEpoch) return;
        this.retries.push(Date.now());
        this.state.restartAttempts = this.retries.length;
        try { await this.startProcess(); }
        catch (error) {
          if (epoch !== this.recoveryEpoch) return;
          this.state.error = errorText(error);
          try { await this.stopProcess(); }
          catch (stopError) { this.fail(stopError); return; }
          this.scheduleRecovery();
        }
      });
    }, wait);
  }

  private fail(error: unknown): void {
    this.state.phase = 'error'; this.state.error = errorText(error); this.state.nextRetryAt = null;
    this.publish(); this.emit('fault', this.state.error);
  }

  public refreshSource(catalog: SubscriptionCatalog): void {
    if (!this.saved) return;
    try {
      const next = catalog.capture(this.saved.snapshot.profileUid, this.saved.snapshot.nodeName);
      this.state.sourceStatus = next.fingerprint === this.saved.snapshot.fingerprint ? 'current' : 'changed';
      this.state.sourceError = null;
    } catch (error) {
      this.state.sourceStatus = catalog.errors.length ? 'unknown' : 'missing';
      this.state.sourceError = errorText(error);
    }
    this.publish();
  }

  private cancelRetry(): void {
    this.recoveryEpoch++;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
    this.state.nextRetryAt = null;
  }

  private async stopProcess(): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const lease = this.lease;
    const child = this.child;
    if (lease) {
      if (alive(lease.pid) && child?.pid !== lease.pid) await this.verifyProcessIdentity(lease);
      this.child = null;
      this.booting = false;
      if (alive(lease.pid)) process.kill(lease.pid);
      // Windows 结束进程后仍可能正在释放监听，重启必须等待专属端口关闭。
      const deadline = Date.now() + 4000;
      while (alive(lease.pid) || (this.saved && await isLocalPortListening(this.saved.port))) {
        if (Date.now() >= deadline) throw new Error('私有内核退出或专属端口释放超时');
        await delay(100);
      }
    }
    this.child = null;
    this.booting = false;
    this.lease = null;
    this.state.pid = null;
    fs.rmSync(path.join(this.directory, 'runtime.json'), { force: true });
  }

  public async shutdown(): Promise<void> {
    this.stopped = true;
    this.cancelRetry();
    await this.serial(() => this.stopProcess());
    this.state.phase = 'idle';
    this.publish();
  }
}

export class PrivateProxyService extends EventEmitter {
  public readonly channels: Record<PrivateChannelId, PrivateKernel>;
  constructor(directory: string, coreDirectory: string) {
    super();
    const executable = verifyCore(coreDirectory);
    this.channels = {
      claude: new PrivateKernel('claude', path.join(directory, 'claude'), executable),
      antigravity: new PrivateKernel('antigravity', path.join(directory, 'antigravity'), executable),
    };
    for (const channel of ['claude', 'antigravity'] as const) {
      for (const event of ['state', 'ready', 'lost', 'fault']) this.channels[channel].on(event, (value) => this.emit(event, channel, value));
    }
  }
  public getState(): Record<PrivateChannelId, PrivateChannelState> {
    return { claude: this.channels.claude.getState(), antigravity: this.channels.antigravity.getState() };
  }
  public async restore(): Promise<void> { await Promise.all(Object.values(this.channels).map((channel) => channel.restore())); }
  public async shutdown(): Promise<void> { await Promise.all(Object.values(this.channels).map((channel) => channel.shutdown())); }
}
