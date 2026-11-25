import { EventEmitter } from 'node:events';
import { execFile, spawn, ChildProcess } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import * as yaml from 'js-yaml';
import { PrivateChannelId, PrivateChannelState } from '../src/shared/types';
import { MihomoEndpoint, mihomoRequest, isLocalPortListening } from './mihomoClient';
import {
  BUILTIN_TRACE_ENDPOINTS,
  NodeSnapshot,
  SubscriptionCatalog,
  extractSnapshotTransportHosts,
  readYaml,
  selectProbeEndpointsForTransportHosts,
  snapshotFingerprint,
} from './subscriptionCatalog';
import { requestTextViaProxy } from './netClient';
import { BridgeUpstreamTarget, Ipv4ProxyBridge } from './ipv4ProxyBridge';

const execute = promisify(execFile);
interface SavedChannel { schema: 1; snapshot: NodeSnapshot; port: number; internalPort?: number; revision: string; ipv4Only?: boolean }
interface Lease { pid: number; executable: string; revision: string; endpoint: MihomoEndpoint }

async function allocateFreeLoopbackPort(excludePorts: Set<number>): Promise<number> {
  for (let attempt = 0; attempt < 16; attempt++) {
    const port = await new Promise<number>((resolve, reject) => {
      const srv = net.createServer();
      srv.unref();
      srv.once('error', reject);
      srv.listen(0, '127.0.0.1', () => {
        const addr = srv.address();
        const bound = addr && typeof addr !== 'string' ? addr.port : 0;
        srv.close(() => {
          if (bound > 0) resolve(bound);
          else reject(new Error('无法分配私有内核内部回环端口'));
        });
      });
    });
    if (!excludePorts.has(port)) return port;
  }
  throw new Error('无法为私有内核分配可用的内部回环端口');
}

interface MihomoDnsQueryAnswer {
  type?: number;
  TTL?: number;
  data?: string;
}

interface MihomoDnsQueryResponse {
  Status?: number;
  Answer?: MihomoDnsQueryAnswer[];
}

function matchesMihomoHostPattern(patternRaw: string, hostname: string): boolean {
  const pattern = patternRaw.trim().toLowerCase().replace(/\.$/, '');
  if (!pattern) return false;
  if (pattern === hostname) return true;
  if (pattern.startsWith('+.')) {
    const suffix = pattern.slice(2);
    return Boolean(suffix && (hostname === suffix || hostname.endsWith(`.${suffix}`)));
  }
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(2);
    if (!suffix || !hostname.endsWith(`.${suffix}`)) return false;
    const prefix = hostname.slice(0, -(suffix.length + 1));
    return Boolean(prefix && !prefix.includes('.'));
  }
  if (pattern.startsWith('.')) {
    const suffix = pattern.slice(1);
    return Boolean(suffix && hostname.endsWith(`.${suffix}`));
  }
  return false;
}

function lookupSnapshotHostsIpv4(
  hosts: Record<string, unknown> | undefined,
  hostname: string
): { matchedIpEntry: boolean; ips: string[] } {
  if (!hosts || typeof hosts !== 'object' || Array.isArray(hosts)) {
    return { matchedIpEntry: false, ips: [] };
  }
  const entries = Object.entries(hosts);
  const exact = entries.find(([key]) => key.trim().toLowerCase().replace(/\.$/, '') === hostname);
  const chosen = exact ?? entries.find(([key]) => matchesMihomoHostPattern(key, hostname));
  if (!chosen) return { matchedIpEntry: false, ips: [] };
  const rawValues = Array.isArray(chosen[1]) ? chosen[1] : [chosen[1]];
  const stringValues = rawValues
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim().replace(/^\[|\]$/g, ''))
    .filter(Boolean);
  if (stringValues.length === 0 || !stringValues.every((item) => net.isIP(item) !== 0)) {
    return { matchedIpEntry: false, ips: [] };
  }
  const ipv4s = [...new Set(stringValues.filter((item) => net.isIPv4(item)))];
  return { matchedIpEntry: true, ips: ipv4s };
}

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

class PortOwnershipError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PortOwnershipError';
  }
}

class PortOwnershipLookupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PortOwnershipLookupError';
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
  private shuttingDown = false;
  private booting = false;
  private listenerFaultRecoverable = false;
  private listenerOwnershipVerified = false;
  private verifyingForwarding = false;
  private ipv4Bridge: Ipv4ProxyBridge | null = null;
  private recoveryEpoch = 0;
  private forwardingStateSeq = 0;
  private startupAbort: AbortController | null = null;
  private listenerRecoveryAbort: AbortController | null = null;
  private forwardingAbort: AbortController | null = null;
  private healthAbort: AbortController | null = null;
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
  public getIpv4Only(): boolean { return Boolean(this.saved?.ipv4Only); }
  public getInternalPort(): number | null { return this.getMihomoPort(this.saved); }
  public getBoundTransportHosts(): string[] { return extractSnapshotTransportHosts(this.saved?.snapshot); }
  private publish(): void { this.emit('state', this.getState()); }

  private getMihomoPort(saved: SavedChannel | null = this.saved): number | null {
    if (!saved) return null;
    return saved.ipv4Only ? (saved.internalPort ?? null) : saved.port;
  }

  private closeIpv4Bridge(): void {
    if (this.ipv4Bridge) {
      this.ipv4Bridge.close();
      this.ipv4Bridge = null;
    }
  }

  private async ensureIpv4BridgeStarted(saved: SavedChannel): Promise<void> {
    if (!saved.ipv4Only) {
      this.closeIpv4Bridge();
      return;
    }
    if (this.ipv4Bridge?.isListening() && this.ipv4Bridge.getPort() === saved.port) {
      this.ipv4Bridge.clearDnsCache();
      return;
    }
    this.closeIpv4Bridge();
    const bridge = new Ipv4ProxyBridge({
      bindPort: saved.port,
      getUpstreamTarget: (signal) => this.resolveBridgeUpstreamTarget(signal),
      resolveIpv4: (hostname, signal) => this.resolveIpv4(hostname, signal),
      onUnexpectedClose: (reason) => {
        if (!this.stopped && this.saved?.ipv4Only && this.state.phase === 'ready') {
          this.markRecoverableListenerFault(new PortOwnershipError(reason), true);
        }
      },
    });
    try {
      await bridge.ensureStarted(saved.port);
    } catch (error) {
      bridge.close();
      const code = (error as NodeJS.ErrnoException)?.code;
      if (code === 'EADDRINUSE') {
        throw new Error(`专属端口 ${saved.port} 已被其他进程占用`);
      }
      throw error;
    }
    if (this.stopped || this.saved !== saved) {
      bridge.close();
      throw Object.assign(new Error('私有内核已停止或配置已变更'), { name: 'AbortError' });
    }
    this.ipv4Bridge = bridge;
  }

  private async resolveBridgeUpstreamTarget(signal?: AbortSignal): Promise<BridgeUpstreamTarget> {
    signal?.throwIfAborted();
    const saved = this.saved;
    const lease = this.lease;
    const mihomoPort = this.getMihomoPort(saved);
    if (this.stopped || !saved || !mihomoPort) {
      return { status: 'unavailable', reason: '私有内核已停止或未配置' };
    }
    if (this.state.phase === 'error' && !this.verifyingForwarding) {
      return {
        status: 'blocked',
        reason: this.state.error || this.state.verificationError || '专属端口归属异常，已阻断转发',
      };
    }
    if (!lease || !alive(lease.pid)) {
      return { status: 'unavailable', reason: '私有内核进程尚未就绪' };
    }
    if (!this.listenerOwnershipVerified) {
      return {
        status: 'blocked',
        reason:
          this.state.verificationError ||
          `专属端口 ${saved.port} 内部监听归属尚未确认，已阻断转发`,
      };
    }
    // 转发前经命名管道实时核验内核监听配置，防止内核关闭监听后在下次健康检查前被外部进程抢占内部端口
    let config: Record<string, unknown>;
    try {
      config = await mihomoRequest<Record<string, unknown>>(
        lease.endpoint,
        '/configs',
        'GET',
        undefined,
        signal,
        2000
      );
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') throw error;
      if (!alive(lease.pid)) {
        return { status: 'unavailable', reason: '私有内核进程已退出' };
      }
      this.listenerOwnershipVerified = false;
      return {
        status: 'blocked',
        reason: `无法核验私有内核监听归属：${errorText(error)}`,
      };
    }
    if (this.lease !== lease || this.saved !== saved || !alive(lease.pid)) {
      return { status: 'unavailable', reason: '私有内核状态已变更' };
    }
    if (config['mixed-port'] !== mihomoPort || config.mode !== 'rule') {
      this.listenerOwnershipVerified = false;
      // 先通过系统 TCP 表核验内部端口归属，避免在已知外部抢占时向抢占进程发出任何探活连接
      let pids: number[] | null = null;
      try {
        pids = await this.getLocalPortOwnerPids(mihomoPort, signal);
      } catch {
        pids = null;
      }
      if (pids === null) {
        return {
          status: 'blocked',
          reason: `专属端口 ${saved.port} 内部监听归属复核失败，已阻断转发`,
        };
      }
      const foreignPid = pids.some((pid) => pid !== lease.pid);
      if (foreignPid) {
        const conflictErr = new PortOwnershipError(
          `专属端口 ${saved.port} 内部监听 (${mihomoPort}) 归属与当前私有内核进程不匹配`
        );
        this.markRecoverableListenerFault(conflictErr, true);
        return { status: 'blocked', reason: conflictErr.message };
      }
      if (pids.length === 0) {
        const stillListening = await isLocalPortListening(mihomoPort, 500, signal);
        if (!stillListening) {
          return {
            status: 'refused',
            port: saved.port,
            reason: `本地私有代理内部监听 127.0.0.1:${mihomoPort} 已关闭`,
          };
        }
        const conflictErr = new PortOwnershipError(
          `专属端口 ${saved.port} 内部监听 (${mihomoPort}) 归属不明，已阻断转发`
        );
        this.markRecoverableListenerFault(conflictErr, true);
        return { status: 'blocked', reason: conflictErr.message };
      }
      return {
        status: 'blocked',
        reason: `专属端口 ${saved.port} 内部监听配置异常，已阻断转发`,
      };
    }
    return { status: 'ready', port: mihomoPort, generation: this.state.generation };
  }

  public async resolveIpv4(
    hostname: string,
    signal?: AbortSignal,
    timeoutMs = 6000
  ): Promise<{ ips: string[]; ttlSec: number }> {
    signal?.throwIfAborted();
    const clean = hostname.trim().replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
    if (!clean) {
      throw new Error('目标主机名为空');
    }
    if (net.isIPv6(clean)) {
      throw new Error(`已开启强制 IPv4 出站，禁止直连 IPv6 地址 (${clean})`);
    }
    if (net.isIPv4(clean)) {
      return { ips: [clean], ttlSec: 300 };
    }
    if (clean === 'localhost') {
      return { ips: ['127.0.0.1'], ttlSec: 300 };
    }
    const hostMatch = lookupSnapshotHostsIpv4(this.saved?.snapshot.hosts, clean);
    if (hostMatch.matchedIpEntry) {
      if (hostMatch.ips.length > 0) {
        return { ips: hostMatch.ips, ttlSec: 300 };
      }
      throw new Error(`域名 ${clean} 在节点 hosts 中仅配置了 IPv6 地址（已开启强制 IPv4 出站）`);
    }
    const lease = this.lease;
    if (!lease || !alive(lease.pid)) {
      throw new Error('私有内核尚未就绪');
    }
    const resp = await mihomoRequest<MihomoDnsQueryResponse>(
      lease.endpoint,
      `/dns/query?name=${encodeURIComponent(clean)}&type=A`,
      'GET',
      undefined,
      signal,
      timeoutMs
    );
    const ips: string[] = [];
    const seen = new Set<string>();
    let minTtl = Number.POSITIVE_INFINITY;
    for (const answer of Array.isArray(resp?.Answer) ? resp.Answer : []) {
      if (answer?.type !== 1 || typeof answer.data !== 'string') continue;
      const ip = answer.data.trim();
      if (!net.isIPv4(ip) || seen.has(ip)) continue;
      seen.add(ip);
      ips.push(ip);
      if (typeof answer.TTL === 'number' && Number.isFinite(answer.TTL) && answer.TTL > 0) {
        minTtl = Math.min(minTtl, answer.TTL);
      }
    }
    if (ips.length === 0) {
      throw new Error(`域名 ${clean} 未解析到可用 IPv4 地址（已开启强制 IPv4 出站）`);
    }
    const ttlSec = Number.isFinite(minTtl) ? Math.max(15, Math.min(300, Math.round(minTtl))) : 60;
    return { ips, ttlSec };
  }

  private async verifyProcessIdentity(lease: Pick<Lease, 'pid' | 'revision'>): Promise<void> {
    const result = await execute('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $ErrorActionPreference = "Stop"; Get-CimInstance Win32_Process -Filter ("ProcessId=" + $env:GUARD_KERNEL_PID) | Select-Object ExecutablePath,CommandLine | ConvertTo-Json -Compress'],
    { windowsHide: true, env: { ...process.env, GUARD_KERNEL_PID: String(lease.pid) }, timeout: 5000 });
    const identity = result.stdout.trim() ? JSON.parse(result.stdout) : null;
    if (!identity) throw new Error('私有内核进程已退出');
    if (!identity.ExecutablePath || !identity.CommandLine) throw new Error('无法读取私有内核进程身份，请检查进程访问权限');
    const configuration = path.join(this.directory, lease.revision, 'config.yaml');
    if (String(identity.ExecutablePath).toLowerCase() !== this.executable.toLowerCase() ||
        !String(identity.CommandLine).toLowerCase().includes(configuration.toLowerCase())) {
      throw new Error('私有内核进程身份不匹配');
    }
  }

  private abortStartup(reason = '私有内核启动已取消'): void {
    if (this.startupAbort && !this.startupAbort.signal.aborted) {
      this.startupAbort.abort(Object.assign(new Error(reason), { name: 'AbortError' }));
    }
    this.startupAbort = null;
  }

  private abortListenerRecovery(reason = '私有内核恢复已取消'): void {
    if (this.listenerRecoveryAbort && !this.listenerRecoveryAbort.signal.aborted) {
      this.listenerRecoveryAbort.abort(Object.assign(new Error(reason), { name: 'AbortError' }));
    }
    this.listenerRecoveryAbort = null;
  }

  private abortForwardingProbe(reason = '私有内核转发探测已取消'): void {
    if (this.forwardingAbort && !this.forwardingAbort.signal.aborted) {
      this.forwardingAbort.abort(Object.assign(new Error(reason), { name: 'AbortError' }));
    }
    this.forwardingAbort = null;
  }

  private abortHealthCheck(reason = '私有内核健康检查已取消'): void {
    if (this.healthAbort && !this.healthAbort.signal.aborted) {
      this.healthAbort.abort(Object.assign(new Error(reason), { name: 'AbortError' }));
    }
    this.healthAbort = null;
  }

  private markRecoverableListenerFault(error: Error, isPortConflict = error instanceof PortOwnershipError): void {
    const reason = errorText(error);
    const changed = this.state.phase !== 'error' || this.state.error !== reason;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.abortHealthCheck('监听归属异常，停止当前健康检查');
    this.booting = false;
    this.listenerFaultRecoverable = true;
    this.listenerOwnershipVerified = false;
    this.ipv4Bridge?.disconnectAll(reason);
    this.forwardingStateSeq++;
    this.state.phase = 'error';
    this.state.error = reason;
    this.state.verificationError = reason;
    this.state.nextRetryAt = null;
    this.state.generation++;
    this.publish();
    if (isPortConflict && changed) {
      this.emit('port-conflict', reason);
    }
  }

  private async getLocalPortOwnerPids(port: number, signal?: AbortSignal): Promise<number[]> {
    const result = await execute('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $ErrorActionPreference = "Stop"; @(Get-NetTCPConnection -State Listen -LocalPort $env:GUARD_KERNEL_PORT -ErrorAction SilentlyContinue | Select-Object LocalAddress,OwningProcess) | ConvertTo-Json -Compress'],
    { windowsHide: true, env: { ...process.env, GUARD_KERNEL_PORT: String(port) }, timeout: 10000, signal });
    const raw: unknown = result.stdout.trim() ? JSON.parse(result.stdout) : [];
    const rows = (Array.isArray(raw) ? raw : [raw]).filter(
      (item): item is { LocalAddress?: unknown; OwningProcess?: unknown } =>
        Boolean(item && typeof item === 'object')
    );
    const uniqueValidPids = (items: Array<{ OwningProcess?: unknown }>): number[] => [
      ...new Set(
        items
          .map((r) => r.OwningProcess)
          .filter((pid): pid is number => Number.isInteger(pid) && (pid as number) > 0)
      ),
    ];
    // 127.0.0.1 精确绑定优先级最高；无精确绑定时纳入可接受 127.0.0.1 连接的 0.0.0.0 与双栈 :: 监听
    const exactLoopback = uniqueValidPids(
      rows.filter((r) => String(r.LocalAddress || '').trim() === '127.0.0.1')
    );
    if (exactLoopback.length > 0) return exactLoopback;
    return uniqueValidPids(
      rows.filter((r) => {
        const addr = String(r.LocalAddress || '').trim();
        return addr === '0.0.0.0' || addr === '::';
      })
    );
  }

  private async findExistingLease(): Promise<Lease | null> {
    const leasePath = path.join(this.directory, 'runtime.json');
    if (fs.existsSync(leasePath)) {
      const lease = JSON.parse(fs.readFileSync(leasePath, 'utf8')) as Lease;
      if (!Number.isInteger(lease.pid) || lease.pid <= 0) throw new Error('私有内核进程记录无效');
      if (alive(lease.pid)) {
        if (!this.saved || lease.revision !== this.saved.revision ||
            path.resolve(lease.executable).toLowerCase() !== path.resolve(this.executable).toLowerCase()) {
          throw new Error('已有私有内核与保存的配置版本不一致');
        }
        await this.verifyProcessIdentity(lease);
        return lease;
      }
    }
    const mihomoPort = this.getMihomoPort(this.saved);
    if (!this.saved || !mihomoPort || !await isLocalPortListening(mihomoPort)) return null;

    const pids = await this.getLocalPortOwnerPids(mihomoPort);
    if (pids.length !== 1) throw new Error('无法确定专属端口的唯一监听进程');
    await this.verifyProcessIdentity({ pid: pids[0], revision: this.saved.revision });
    const configuration = readYaml(path.join(this.directory, this.saved.revision, 'config.yaml'));
    const pipePath = configuration['external-controller-pipe'];
    const secret = configuration.secret;
    if (configuration['mixed-port'] !== mihomoPort || typeof pipePath !== 'string' ||
        !pipePath.startsWith(`\\\\.\\pipe\\proxy-region-guard-${this.channel}-`) || typeof secret !== 'string' || !secret) {
      throw new Error('私有内核控制接口配置无效');
    }
    const lease: Lease = { pid: pids[0], executable: this.executable, revision: this.saved.revision, endpoint: { pipePath, secret } };
    atomicJson(leasePath, lease);
    return lease;
  }

  private serial<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.queue.then(operation);
    this.queue = pending.then(() => undefined, () => undefined);
    return pending;
  }

  private setSelection(saved: SavedChannel | null): void {
    this.saved = saved;
    this.listenerFaultRecoverable = false;
    this.listenerOwnershipVerified = false;
    this.forwardingStateSeq++;
    Object.assign(this.state, {
      nodeName: saved?.snapshot.nodeName || null, profileUid: saved?.snapshot.profileUid || null,
      profileName: saved?.snapshot.profileName || null, port: saved?.port || null,
      error: null, verificationError: null, generation: this.state.generation + 1,
    });
    this.publish();
  }

  private validateSavedChannel(saved: SavedChannel): void {
    if (saved.schema !== 1 || !saved.snapshot || !Number.isInteger(saved.port) || saved.port < 1 || saved.port > 65535) {
      throw new Error('私有节点副本格式无效');
    }
    if (
      saved.ipv4Only &&
      (!Number.isInteger(saved.internalPort) ||
        saved.internalPort! < 1 ||
        saved.internalPort! > 65535 ||
        saved.internalPort === saved.port)
    ) {
      throw new Error('私有节点副本内部端口无效');
    }
    if (!/^[0-9a-f-]{36}$/.test(saved.revision)) {
      throw new Error('私有节点副本目录标识无效');
    }
    const { fingerprint, ...definition } = saved.snapshot;
    if (snapshotFingerprint(definition) !== fingerprint) {
      throw new Error('私有节点副本校验失败');
    }
  }

  /**
   * 恢复或清理因卫士在切换内核窗口期崩溃留下的未提交切换记录（pending.json）：
   * - 若 current.json 已与 pending 同版本，说明提交已完成，直接删除残留 pending.json；
   * - 若 runtime.json 指向未提交的 pending 版本内核，核验完整进程身份后安全停止该未提交内核并清理记录，
   *   避免下次启动/重启被 findExistingLease() 因版本不匹配永久阻断。
   */
  private async reconcilePendingTransition(): Promise<void> {
    const pendingPath = path.join(this.directory, 'pending.json');
    if (!fs.existsSync(pendingPath)) return;

    const pending = JSON.parse(fs.readFileSync(pendingPath, 'utf8')) as SavedChannel;
    this.validateSavedChannel(pending);

    const currentPath = path.join(this.directory, 'current.json');
    if (fs.existsSync(currentPath)) {
      try {
        const current = JSON.parse(fs.readFileSync(currentPath, 'utf8')) as SavedChannel;
        if (current?.revision === pending.revision) {
          fs.rmSync(pendingPath, { force: true });
          return;
        }
      } catch {
        // current.json 损坏时交由后续 restore 校验处理
      }
    }

    const leasePath = path.join(this.directory, 'runtime.json');
    if (fs.existsSync(leasePath)) {
      const lease = JSON.parse(fs.readFileSync(leasePath, 'utf8')) as Lease;
      if (Number.isInteger(lease.pid) && lease.pid > 0 && lease.revision === pending.revision) {
        if (alive(lease.pid)) {
          if (
            path.resolve(lease.executable).toLowerCase() !==
            path.resolve(this.executable).toLowerCase()
          ) {
            throw new Error('未提交切换内核的可执行路径与当前卫士内核不一致');
          }
          await this.verifyProcessIdentity(lease);
          process.kill(lease.pid);
          const exitDeadline = Date.now() + 4000;
          while (alive(lease.pid)) {
            if (Date.now() >= exitDeadline) {
              throw new Error(`清理未提交切换内核 (PID=${lease.pid}) 退出超时`);
            }
            await delay(100);
          }
          const pendingPort = this.getMihomoPort(pending);
          if (pendingPort) {
            const releaseDeadline = Date.now() + 1500;
            while (Date.now() < releaseDeadline && (await isLocalPortListening(pendingPort))) {
              await delay(100);
            }
          }
        }
        fs.rmSync(leasePath, { force: true });
      }
    }
    fs.rmSync(pendingPath, { force: true });
  }

  public async restore(): Promise<void> {
    this.stopped = false;
    this.shuttingDown = false;
    const file = path.join(this.directory, 'current.json');
    try {
      await this.reconcilePendingTransition();
      if (!fs.existsSync(file)) return;
      const saved = JSON.parse(fs.readFileSync(file, 'utf8')) as SavedChannel;
      this.validateSavedChannel(saved);
      this.setSelection(saved);
      const lease = await this.findExistingLease();
      if (lease) {
        this.lease = lease;
        this.state.pid = lease.pid;
        await this.verifyListener(true);
        await this.ensureIpv4BridgeStarted(saved);
        await this.verifyForwarding();
        this.state.phase = 'ready';
        this.publish();
        this.emit('ready');
        this.scheduleHealth();
        return;
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
    const ipv4Only = Boolean(saved.ipv4Only);
    const mihomoPort = this.getMihomoPort(saved);
    if (!mihomoPort || !Number.isInteger(mihomoPort) || mihomoPort < 1 || mihomoPort > 65535) {
      throw new Error('私有内核监听端口无效');
    }
    const proxies = snapshot.proxies.map((proxy) =>
      proxy['ip-version'] ? { ...proxy } : { ...proxy, 'ip-version': 'ipv4-prefer' }
    );
    const rules = ipv4Only
      ? [`IP-CIDR6,::1/128,${outbound},no-resolve`, 'IP-CIDR6,::/0,REJECT,no-resolve', `MATCH,${outbound}`]
      : [`MATCH,${outbound}`];
    return {
      'mixed-port': mihomoPort, 'bind-address': '127.0.0.1', 'allow-lan': false,
      mode: 'rule', ipv6: true, 'tcp-concurrent': true, 'log-level': 'warning', 'find-process-mode': 'off',
      'external-controller-pipe': endpoint.pipePath, secret: endpoint.secret,
      tun: { enable: false }, profile: { 'store-selected': false, 'store-fake-ip': false },
      dns: { enable: true, ipv6: !ipv4Only, 'enhanced-mode': 'redir-host', 'use-system-hosts': false,
        'default-nameserver': ['223.5.5.5'], 'proxy-server-nameserver': resolvers,
        'proxy-server-nameserver-policy': policy,
        nameserver: [`https://1.1.1.1/dns-query#${outbound}`, `https://8.8.8.8/dns-query#${outbound}`] },
      hosts: snapshot.hosts, proxies,
      'proxy-groups': [{ name: outbound, type: 'select', proxies: [snapshot.nodeName] }],
      rules,
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

  public select(snapshot: NodeSnapshot | null, port: number, options?: { ipv4Only?: boolean }): Promise<void> {
    this.abortStartup('切换专属节点');
    this.abortHealthCheck('切换专属节点');
    this.abortListenerRecovery('切换专属节点');
    this.abortForwardingProbe('切换专属节点');
    return this.serial(async () => {
      let stoppedPrevious = false;
      try {
        if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('私有代理端口无效');
        const ipv4Only = Boolean(options?.ipv4Only);
        const excludePorts = new Set<number>([port]);
        if (this.saved?.internalPort) excludePorts.add(this.saved.internalPort);
        if (this.saved?.port) excludePorts.add(this.saved.port);
        const internalPort = snapshot && ipv4Only
          ? await allocateFreeLoopbackPort(excludePorts)
          : undefined;
        const next: SavedChannel | null = snapshot
          ? {
              schema: 1,
              snapshot,
              port,
              ...(ipv4Only ? { ipv4Only: true, internalPort } : {}),
              revision: randomUUID(),
            }
          : null;
        const endpoint = next ? await this.prepare(next) : null;
        if (next && port !== this.state.port && await isLocalPortListening(port)) throw new Error(`专属端口 ${port} 已被其他进程占用`);
        const previousSaved = this.saved;
        const pendingPath = path.join(this.directory, 'pending.json');
        this.cancelRetry();
        stoppedPrevious = true;
        try {
          await this.reconcilePendingTransition();
          await this.stopProcess();
          this.retries = [];
          this.state.restartAttempts = 0;
          if (next) {
            // 先持久化 pending.json，确保卫士在 startProcess 校验期间意外崩溃后重启仍可识别并清理未提交版本
            atomicJson(pendingPath, next);
            this.setSelection(next);
            await this.startProcess(endpoint!);
            try {
              atomicJson(path.join(this.directory, 'current.json'), next);
            } catch (saveError) {
              await this.stopProcess().catch(() => undefined);
              throw saveError;
            } finally {
              fs.rmSync(pendingPath, { force: true });
            }
          } else {
            fs.rmSync(pendingPath, { force: true });
            fs.rmSync(path.join(this.directory, 'current.json'), { force: true });
            this.setSelection(null);
            this.state.phase = 'idle';
            this.publish();
          }
        } catch (error) {
          fs.rmSync(pendingPath, { force: true });
          // 仅在内核成功就绪并完成持久化后才提交新副本；失败时回滚已保存状态，避免把未生效的配置写死
          if (previousSaved && next) {
            this.setSelection(previousSaved);
          }
          this.fail(error);
          throw error;
        }
      } finally {
        if (!stoppedPrevious && !this.stopped && this.lease && this.state.phase === 'ready' && !this.timer) {
          this.scheduleHealth();
        }
      }
    });
  }

  public restart(): Promise<void> {
    this.abortStartup('重启私有内核');
    this.abortHealthCheck('重启私有内核');
    this.abortListenerRecovery('重启私有内核');
    this.abortForwardingProbe('重启私有内核');
    return this.serial(async () => {
      if (!this.saved) throw new Error('尚未保存专属节点');
      this.cancelRetry();
      this.retries = [];
      this.state.restartAttempts = 0;
      try {
        await this.reconcilePendingTransition();
        await this.stopProcess();
        await this.startProcess();
      }
      catch (error) { this.fail(error); throw error; }
    });
  }

  public async checkReady(signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    if (this.state.phase !== 'ready') throw new Error(this.state.error || '私有内核尚未就绪');
    await this.verifyListener(!this.listenerOwnershipVerified, signal);
  }

  public recoverListenerIfNeeded(signal?: AbortSignal): Promise<'rebound' | 'already-ready' | 'failed'> {
    if (this.stopped || signal?.aborted) return Promise.resolve('failed');
    return this.serial(async () => {
      const canRecoverFromListenerFault =
        this.state.phase === 'error' &&
        this.listenerFaultRecoverable &&
        this.lease !== null &&
        !this.booting;
      if (
        this.stopped ||
        signal?.aborted ||
        !this.saved ||
        (this.state.phase !== 'ready' && !canRecoverFromListenerFault)
      ) {
        return 'failed';
      }
      const savedAtStart = this.saved;
      const generationAtStart = this.state.generation;
      if (!this.lease || !alive(this.lease.pid)) {
        this.lease = null;
        this.state.pid = null;
        this.unexpectedExit('私有内核进程已退出');
        return 'failed';
      }

      const localAbort = new AbortController();
      this.listenerRecoveryAbort = localAbort;
      const recoverySignal = signal
        ? AbortSignal.any([signal, localAbort.signal])
        : localAbort.signal;
      const isSuperseded = () =>
        this.stopped ||
        recoverySignal.aborted ||
        this.saved !== savedAtStart ||
        this.state.generation !== generationAtStart;

      try {
        try {
          await this.verifyListener(true, recoverySignal);
          if (isSuperseded()) return 'failed';
          if (!this.lease || !alive(this.lease.pid)) {
            this.child = null;
            this.lease = null;
            this.state.pid = null;
            this.unexpectedExit('私有内核进程已退出');
            return 'failed';
          }
          const wasNotReady = this.state.phase !== 'ready';
          const prevVerificationError = this.state.verificationError;
          await this.ensureIpv4BridgeStarted(savedAtStart);
          if (isSuperseded()) return 'failed';
          if (wasNotReady || prevVerificationError !== null) {
            await this.verifyForwarding(recoverySignal);
            if (isSuperseded()) return 'failed';
            if (!this.lease || !alive(this.lease.pid)) {
              this.child = null;
              this.lease = null;
              this.state.pid = null;
              this.unexpectedExit('私有内核进程已退出');
              return 'failed';
            }
          }
          this.booting = false;
          this.listenerFaultRecoverable = false;
          let changed = this.state.verificationError !== prevVerificationError;
          if (wasNotReady) {
            this.state.phase = 'ready';
            this.state.error = null;
            this.state.generation++;
            changed = true;
          }
          if (changed) {
            this.publish();
            if (wasNotReady) {
              this.emit('ready');
            }
            this.scheduleHealth();
          }
          return 'already-ready';
        } catch (error) {
          if (isSuperseded()) return 'failed';
          if (error instanceof PortOwnershipError) {
            this.markRecoverableListenerFault(error, true);
            return 'failed';
          }
          if (error instanceof PortOwnershipLookupError) {
            this.listenerOwnershipVerified = false;
            if (!this.lease || !alive(this.lease.pid)) {
              this.child = null;
              this.lease = null;
              this.state.pid = null;
              this.unexpectedExit('私有内核进程已退出');
              return 'failed';
            }
            if (this.state.phase === 'error') {
              this.markRecoverableListenerFault(error, false);
            } else {
              this.state.verificationError = errorText(error);
              this.publish();
              this.scheduleHealth();
            }
            return 'failed';
          }
          // 监听异常或配置漂移时尝试重载本版本已保存的独立配置以恢复本地专属监听
        }

        if (isSuperseded()) return 'failed';
        if (!this.lease || !alive(this.lease.pid)) {
          this.child = null;
          this.lease = null;
          this.state.pid = null;
          this.unexpectedExit('私有内核进程已退出');
          return 'failed';
        }

        try {
          const configPath = path.join(this.directory, this.saved.revision, 'config.yaml');
          const payload = fs.readFileSync(configPath, 'utf8');
          if (isSuperseded()) return 'failed';
          await mihomoRequest(this.lease.endpoint, '/configs?force=true', 'PUT', { payload }, recoverySignal);
          const deadline = Date.now() + 5000;
          let lastVerifyError: unknown = new Error('私有内核专属监听未就绪');
          while (Date.now() < deadline) {
            if (isSuperseded()) return 'failed';
            if (!this.lease || !alive(this.lease.pid)) {
              throw new Error('私有内核进程已退出');
            }
            try {
              await this.verifyListener(true, recoverySignal);
              lastVerifyError = null;
              break;
            } catch (error) {
              if (isSuperseded()) return 'failed';
              lastVerifyError = error;
              await delay(100, undefined, { signal: recoverySignal }).catch(() => undefined);
            }
          }
          if (isSuperseded()) return 'failed';
          if (lastVerifyError) throw lastVerifyError;
          await this.ensureIpv4BridgeStarted(savedAtStart);
          if (isSuperseded()) return 'failed';
          await this.verifyForwarding(recoverySignal);
          if (isSuperseded()) return 'failed';
          if (!this.lease || !alive(this.lease.pid)) {
            this.child = null;
            this.lease = null;
            this.state.pid = null;
            this.unexpectedExit('私有内核进程已退出');
            return 'failed';
          }
          this.booting = false;
          this.listenerFaultRecoverable = false;
          this.state.phase = 'ready';
          this.state.error = null;
          this.state.generation++;
          this.publish();
          this.emit('ready');
          this.scheduleHealth();
          return 'rebound';
        } catch (error) {
          if (isSuperseded()) return 'failed';
          if (!this.lease || !alive(this.lease.pid)) {
            this.child = null;
            this.lease = null;
            this.state.pid = null;
            this.unexpectedExit('私有内核进程已退出');
            return 'failed';
          }
          this.listenerOwnershipVerified = false;
          const normalizedErr = error instanceof Error ? error : new Error(errorText(error));
          if (normalizedErr instanceof PortOwnershipError) {
            this.markRecoverableListenerFault(normalizedErr, true);
            return 'failed';
          }
          if (this.state.phase === 'error') {
            this.markRecoverableListenerFault(normalizedErr, false);
            return 'failed';
          }
          // 私有内核仍存活且未确认为端口冲突时，复核监听归属；确认冲突才标为 error 熔断，
          // 否则保留 ready 并设置 verificationError（阻断新启动、保留运行中 Claude 会话并由 5s 后台复核）。
          const leaseAtFault = this.lease;
          const mihomoPortAtFault = this.getMihomoPort(savedAtStart)!;
          if (await isLocalPortListening(mihomoPortAtFault, 800, recoverySignal)) {
            if (isSuperseded()) return 'failed';
            let pids: number[] | null = null;
            try {
              pids = await this.getLocalPortOwnerPids(mihomoPortAtFault, recoverySignal);
            } catch {
              pids = null;
            }
            if (isSuperseded()) return 'failed';
            if (!this.lease || this.lease !== leaseAtFault || !alive(leaseAtFault.pid)) {
              if (this.lease === leaseAtFault) {
                this.child = null;
                this.lease = null;
                this.state.pid = null;
                this.unexpectedExit('私有内核进程已退出');
              }
              return 'failed';
            }
            if (pids !== null) {
              const foreignPidDetected = pids.some((pid) => pid !== leaseAtFault.pid);
              const stillListeningWithUnknownOwner =
                !foreignPidDetected &&
                pids.length === 0 &&
                (await isLocalPortListening(mihomoPortAtFault, 800, recoverySignal));
              if (isSuperseded()) return 'failed';
              if (foreignPidDetected || stillListeningWithUnknownOwner) {
                this.markRecoverableListenerFault(
                  new PortOwnershipError(
                    `专属端口 ${savedAtStart.port} 监听归属与当前私有内核进程不匹配`
                  ),
                  true
                );
                return 'failed';
              }
            }
          }
          if (isSuperseded()) return 'failed';
          this.state.verificationError = errorText(normalizedErr);
          this.publish();
          this.scheduleHealth();
          return 'failed';
        }
      } finally {
        if (this.listenerRecoveryAbort === localAbort) {
          this.listenerRecoveryAbort = null;
        }
        localAbort.abort();
      }
    });
  }

  private async verifyListener(verifyOwner = false, signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    const lease = this.lease;
    const saved = this.saved;
    const generation = this.state.generation;
    const mihomoPort = this.getMihomoPort(saved);
    const assertLeaseCurrent = () => {
      if (
        this.stopped ||
        this.lease !== lease ||
        this.saved !== saved ||
        this.state.generation !== generation ||
        !lease ||
        !saved ||
        !mihomoPort ||
        !alive(lease.pid)
      ) {
        throw new Error('私有内核进程已退出');
      }
    };
    assertLeaseCurrent();
    if (!await isLocalPortListening(mihomoPort!, 800, signal)) {
      signal?.throwIfAborted();
      assertLeaseCurrent();
      this.listenerOwnershipVerified = false;
      throw new Error('私有内核专属监听未就绪');
    }
    signal?.throwIfAborted();
    assertLeaseCurrent();
    if (verifyOwner) {
      let pids: number[];
      try {
        pids = await this.getLocalPortOwnerPids(mihomoPort!, signal);
      } catch (ownerError) {
        signal?.throwIfAborted();
        assertLeaseCurrent();
        this.listenerOwnershipVerified = false;
        throw new PortOwnershipLookupError(
          `专属端口 ${saved!.port} 监听归属复核未完成：${errorText(ownerError)}`
        );
      }
      signal?.throwIfAborted();
      assertLeaseCurrent();
      if (pids.length !== 1 || pids[0] !== lease!.pid) {
        const foreignPidDetected = pids.some((pid) => pid !== lease!.pid);
        const stillListeningWithUnknownOwner =
          !foreignPidDetected && (await isLocalPortListening(mihomoPort!, 800, signal));
        signal?.throwIfAborted();
        assertLeaseCurrent();
        this.listenerOwnershipVerified = false;
        if (!foreignPidDetected && !stillListeningWithUnknownOwner) {
          throw new Error('私有内核专属监听未就绪');
        }
        throw new PortOwnershipError(
          `专属端口 ${saved!.port} 监听归属与当前私有内核进程不匹配`
        );
      }
    }
    const config = await mihomoRequest<Record<string, unknown>>(lease!.endpoint, '/configs', 'GET', undefined, signal);
    assertLeaseCurrent();
    if (config['mixed-port'] !== mihomoPort || config.mode !== 'rule') {
      this.listenerOwnershipVerified = false;
      throw new Error('私有内核运行配置与保存的副本不一致');
    }
    const proxies = await mihomoRequest<{ proxies: Record<string, unknown> }>(lease!.endpoint, '/proxies', 'GET', undefined, signal);
    assertLeaseCurrent();
    if (!proxies.proxies[saved!.snapshot.nodeName]) {
      this.listenerOwnershipVerified = false;
      throw new Error('私有内核专属监听未就绪');
    }
    if (verifyOwner) {
      this.listenerOwnershipVerified = true;
    }
    if (
      saved!.ipv4Only &&
      !this.booting &&
      this.state.phase === 'ready' &&
      (!this.ipv4Bridge?.isListening() || this.ipv4Bridge.getPort() !== saved!.port)
    ) {
      throw new Error('IPv4 强制代理桥接监听未就绪');
    }
  }

  public clearForwardingError(): void {
    if (this.state.phase === 'ready' && this.state.verificationError !== null) {
      this.forwardingStateSeq++;
      this.state.verificationError = null;
      this.publish();
    }
  }

  private async probeForwarding(port: number, totalTimeoutMs = 10000, signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    const deadlineAt = Date.now() + totalTimeoutMs;
    const activeCandidates = selectProbeEndpointsForTransportHosts(
      BUILTIN_TRACE_ENDPOINTS,
      this.getBoundTransportHosts()
    );
    if (activeCandidates.length === 0) {
      throw new Error('常规探测源均与当前节点传输层域名重合，无法验证转发');
    }

    const proxyUrl = `http://127.0.0.1:${port}`;
    const instanceForwardingCtrl = new AbortController();
    this.forwardingAbort = instanceForwardingCtrl;
    const probeCtrl = new AbortController();
    const backupGateCtrl = new AbortController();
    const combinedSignal = signal
      ? AbortSignal.any([signal, instanceForwardingCtrl.signal, probeCtrl.signal])
      : AbortSignal.any([instanceForwardingCtrl.signal, probeCtrl.signal]);
    const backupDelayMs = Math.min(2500, Math.max(800, Math.round(totalTimeoutMs * 0.25)));
    const probeOne = async (url: string): Promise<void> => {
      combinedSignal.throwIfAborted();
      const remainingMs = deadlineAt - Date.now();
      if (remainingMs <= 0) throw new Error('连接超时');
      await requestTextViaProxy(url, proxyUrl, remainingMs, undefined, undefined, false, combinedSignal);
    };

    try {
      const primary = probeOne(activeCandidates[0].url).catch((err) => {
        backupGateCtrl.abort();
        throw err;
      });
      if (activeCandidates.length === 1) {
        await primary;
        return;
      }
      const gateSignal = AbortSignal.any([combinedSignal, backupGateCtrl.signal]);
      const backups = activeCandidates.slice(1).map(async (item) => {
        await delay(backupDelayMs, undefined, { signal: gateSignal }).catch(() => undefined);
        combinedSignal.throwIfAborted();
        await probeOne(item.url);
      });
      await Promise.any([primary, ...backups]);
    } catch (error) {
      if (signal?.aborted || instanceForwardingCtrl.signal.aborted) {
        throw (signal?.aborted ? signal.reason : instanceForwardingCtrl.signal.reason) ??
          Object.assign(new Error('私有内核转发探测已取消'), { name: 'AbortError' });
      }
      if (error instanceof AggregateError) {
        const nonAbort = error.errors.filter(
          (item) => !(item instanceof Error && item.name === 'AbortError')
        );
        throw nonAbort[nonAbort.length - 1] ?? error.errors[0] ?? error;
      }
      throw error;
    } finally {
      if (this.forwardingAbort === instanceForwardingCtrl) {
        this.forwardingAbort = null;
      }
      backupGateCtrl.abort();
      probeCtrl.abort();
      instanceForwardingCtrl.abort();
    }
  }

  private async verifyForwarding(signal?: AbortSignal): Promise<void> {
    const seq = ++this.forwardingStateSeq;
    const saved = this.saved;
    if (!saved) return;
    this.verifyingForwarding = true;
    try {
      await this.probeForwarding(saved.port, 10000, signal);
      if (!this.stopped && !signal?.aborted && this.forwardingStateSeq === seq) {
        this.state.verificationError = null;
      }
    } catch (error) {
      if (
        !this.stopped &&
        !signal?.aborted &&
        this.forwardingStateSeq === seq &&
        !(error instanceof Error && error.name === 'AbortError')
      ) {
        this.state.verificationError = `专属代理请求失败：${errorText(error)}`;
      }
    } finally {
      this.verifyingForwarding = false;
    }
  }

  private async startProcess(preparedEndpoint?: MihomoEndpoint): Promise<void> {
    if (this.stopped || !this.saved) throw new Error('私有内核管理已停止');
    const saved = this.saved;
    const mihomoPort = this.getMihomoPort(saved);
    if (!mihomoPort) throw new Error('私有内核监听端口无效');
    const bridgeAlreadyHoldingPublicPort =
      Boolean(saved.ipv4Only && this.ipv4Bridge?.isListening() && this.ipv4Bridge.getPort() === saved.port);
    if (!bridgeAlreadyHoldingPublicPort && await isLocalPortListening(saved.port)) {
      throw new Error(`专属端口 ${saved.port} 已被其他进程占用`);
    }
    if (saved.ipv4Only && await isLocalPortListening(mihomoPort)) {
      throw new Error(`私有内核内部端口 ${mihomoPort} 已被其他进程占用`);
    }
    const endpoint = preparedEndpoint || await this.prepare(saved);
    const revisionDirectory = path.join(this.directory, saved.revision);
    this.forwardingStateSeq++;
    this.listenerFaultRecoverable = false;
    this.listenerOwnershipVerified = false;
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
    const startupCtrl = new AbortController();
    this.startupAbort = startupCtrl;
    const startupSignal = startupCtrl.signal;
    let listenerVerified = false;
    try {
      await new Promise<void>((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
      child.unref();
      this.lease = { pid: child.pid!, endpoint, executable: this.executable, revision: saved.revision };
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
        if (this.stopped || startupSignal.aborted) {
          throw Object.assign(new Error('私有内核启动已取消'), { name: 'AbortError' });
        }
        if (child.exitCode !== null || child.signalCode !== null) throw new Error('私有内核在启动期间退出，请查看内核日志');
        try { await this.verifyListener(true, startupSignal); lastError = null; break; }
        catch (error) {
          if (this.stopped || startupSignal.aborted) {
            throw Object.assign(new Error('私有内核启动已取消'), { name: 'AbortError' });
          }
          lastError = error;
          await delay(150, undefined, { signal: startupSignal }).catch(() => undefined);
        }
      }
      if (lastError) throw lastError;
      await this.ensureIpv4BridgeStarted(saved);
      listenerVerified = true;
      // 通过真实 HTTPS 请求确认专属代理（IPv4 模式下即公开的 IPv4 桥接端口）能够完成转发。
      await this.verifyForwarding(startupSignal);
      if (this.stopped && !this.shuttingDown && this.child === child && this.lease && alive(this.lease.pid)) {
        // 托盘退出仅停止后台巡检，监听归属已确认就绪时保留已脱离运行的私有内核（如 Antigravity 内核）
        this.booting = false;
        this.state.phase = 'ready';
        this.publish();
        return;
      }
      if (this.stopped || startupSignal.aborted || this.child !== child || !this.lease) {
        throw new Error('私有内核在启动校验期间退出');
      }
      this.booting = false;
    } catch (error) {
      this.booting = false;
      if (
        this.stopped &&
        !this.shuttingDown &&
        listenerVerified &&
        this.child === child &&
        this.lease &&
        alive(this.lease.pid)
      ) {
        this.state.phase = 'ready';
        this.publish();
        return;
      }
      if (this.child === child || this.lease !== null) {
        try {
          await this.stopProcess();
        } catch (stopError) {
          throw new Error(`${errorText(error)}；且清理残留内核进程失败：${errorText(stopError)}`);
        }
      }
      throw error;
    } finally {
      if (this.startupAbort === startupCtrl) {
        this.startupAbort = null;
      }
      startupCtrl.abort();
    }
    this.state.phase = 'ready';
    this.publish();
    this.emit('ready');
    this.scheduleHealth();
  }

  private scheduleHealth(): void {
    if (this.timer) clearTimeout(this.timer);
    if (this.stopped) return;
    this.timer = setTimeout(() => void this.serial(async () => {
      const leaseAtStart = this.lease;
      const savedAtStart = this.saved;
      const generationAtStart = this.state.generation;
      if (!leaseAtStart || !savedAtStart || this.state.phase !== 'ready') return;
      const healthCtrl = new AbortController();
      this.healthAbort = healthCtrl;
      const healthSignal = healthCtrl.signal;
      const isHealthCheckCurrent = (): boolean =>
        !this.stopped &&
        !healthSignal.aborted &&
        this.lease === leaseAtStart &&
        this.saved === savedAtStart &&
        this.state.phase === 'ready' &&
        this.state.generation === generationAtStart;
      const abortIfSupersededOrDead = (): boolean => {
        if (!isHealthCheckCurrent()) return true;
        if (!alive(leaseAtStart.pid)) {
          this.child = null;
          this.lease = null;
          this.state.pid = null;
          this.unexpectedExit('私有内核进程已退出');
          return true;
        }
        return false;
      };
      try {
        if (abortIfSupersededOrDead()) return;
        const mihomoPortAtStart = this.getMihomoPort(savedAtStart)!;
        try {
          // 若此前曾出现归属核验不确定（listenerOwnershipVerified=false），本轮强制做全量归属核验
          await this.verifyListener(!this.listenerOwnershipVerified, healthSignal);
          if (abortIfSupersededOrDead()) return;
          if (this.state.verificationError) {
            const seq = this.forwardingStateSeq;
            try {
              await this.probeForwarding(savedAtStart.port, 10000, healthSignal);
              if (abortIfSupersededOrDead()) return;
              if (this.forwardingStateSeq === seq) {
                this.forwardingStateSeq++;
                this.state.verificationError = null;
                this.publish();
              }
            } catch (error) {
              if (abortIfSupersededOrDead()) return;
              if (
                this.forwardingStateSeq === seq &&
                this.state.verificationError !== null &&
                !(error instanceof Error && error.name === 'AbortError')
              ) {
                this.state.verificationError = `专属代理请求失败：${errorText(error)}`;
                this.publish();
              }
            }
          }
        } catch (error) {
          if (abortIfSupersededOrDead()) return;
          this.listenerOwnershipVerified = false;
          if (await isLocalPortListening(mihomoPortAtStart, 800, healthSignal)) {
            if (abortIfSupersededOrDead()) return;
            let ownerLookupFailed: unknown = null;
            let pids: number[] = [];
            try {
              pids = await this.getLocalPortOwnerPids(mihomoPortAtStart, healthSignal);
            } catch (ownerError) {
              ownerLookupFailed = ownerError;
            }
            if (abortIfSupersededOrDead()) return;
            if (ownerLookupFailed !== null) {
              this.state.verificationError = `${errorText(error)}（端口归属复核未完成：${errorText(ownerLookupFailed)}）`;
              this.publish();
              this.scheduleHealth();
              return;
            }
            const foreignPidDetected = pids.some((pid) => pid !== leaseAtStart.pid);
            const stillListeningWithUnknownOwner =
              !foreignPidDetected &&
              pids.length === 0 &&
              (await isLocalPortListening(mihomoPortAtStart, 800, healthSignal));
            if (abortIfSupersededOrDead()) return;
            if (foreignPidDetected || stillListeningWithUnknownOwner) {
              this.markRecoverableListenerFault(
                new PortOwnershipError(
                  `专属端口 ${savedAtStart.port} 监听归属与当前私有内核进程不匹配`
                ),
                true
              );
              return;
            }
          }
          if (abortIfSupersededOrDead()) return;
          this.state.verificationError = errorText(error);
          this.publish();
        }
        if (abortIfSupersededOrDead()) return;
        this.scheduleHealth();
      } finally {
        if (this.healthAbort === healthCtrl) {
          this.healthAbort = null;
        }
        healthCtrl.abort();
      }
    }), 3000);
  }

  private unexpectedExit(reason: string): void {
    if (this.stopped) return;
    this.abortHealthCheck('私有内核意外退出');
    this.booting = false;
    this.listenerFaultRecoverable = false;
    this.listenerOwnershipVerified = false;
    this.ipv4Bridge?.disconnectAll(reason);
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
          if (this.child !== null || this.lease !== null) {
            try { await this.stopProcess(); }
            catch (stopError) { this.fail(stopError); return; }
          }
          this.scheduleRecovery();
        }
      });
    }, wait);
  }

  private fail(error: unknown): void {
    this.booting = false;
    this.listenerFaultRecoverable = false;
    this.listenerOwnershipVerified = false;
    this.ipv4Bridge?.disconnectAll(errorText(error));
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
    this.abortStartup('停止私有内核进程');
    this.abortHealthCheck('停止私有内核进程');
    this.abortListenerRecovery('停止私有内核进程');
    this.abortForwardingProbe('停止私有内核进程');
    this.closeIpv4Bridge();
    this.listenerOwnershipVerified = false;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const lease = this.lease || await this.findExistingLease();
    const child = this.child;
    if (lease) {
      if (alive(lease.pid) && child?.pid !== lease.pid) await this.verifyProcessIdentity(lease);
      this.lease = lease;
      this.child = null;
      this.booting = false;
      if (alive(lease.pid)) process.kill(lease.pid);
      const exitDeadline = Date.now() + 4000;
      while (alive(lease.pid)) {
        if (Date.now() >= exitDeadline) {
          throw new Error(`私有内核进程 (PID=${lease.pid}) 退出超时`);
        }
        await delay(100);
      }
      // Windows 结束进程后仍可能正在释放监听，重启必须等待监听端口关闭（若确认已不由该已退出进程持有则结束等待）。
      const mihomoPort = this.getMihomoPort(this.saved);
      if (mihomoPort) {
        const quickReleaseDeadline = Date.now() + 500;
        while (Date.now() < quickReleaseDeadline && await isLocalPortListening(mihomoPort)) {
          await delay(100);
        }
        if (await isLocalPortListening(mihomoPort)) {
          const pids = await this.getLocalPortOwnerPids(mihomoPort);
          if (pids.includes(lease.pid)) {
            const portDeadline = Date.now() + 3500;
            while (await isLocalPortListening(mihomoPort)) {
              if (Date.now() >= portDeadline) {
                throw new Error('私有内核专属端口释放超时');
              }
              await delay(100);
            }
          }
        }
      }
    }
    this.child = null;
    this.booting = false;
    this.listenerFaultRecoverable = false;
    this.listenerOwnershipVerified = false;
    this.lease = null;
    this.state.pid = null;
    fs.rmSync(path.join(this.directory, 'runtime.json'), { force: true });
  }

  /**
   * 停止后台健康巡检、恢复定时器与在途端口/转发查询，同时保留已脱离运行的私有内核进程（如托盘退出时保留 Antigravity 内核）。
   */
  public stopMonitoring(): void {
    this.stopped = true;
    this.cancelRetry();
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.abortStartup('停止私有内核后台巡检');
    this.abortHealthCheck('停止私有内核后台巡检');
    this.abortListenerRecovery('停止私有内核后台巡检');
    this.abortForwardingProbe('停止私有内核后台巡检');
    this.closeIpv4Bridge();
  }

  public async shutdown(): Promise<void> {
    this.shuttingDown = true;
    this.stopMonitoring();
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
      for (const event of ['state', 'ready', 'lost', 'fault', 'port-conflict']) this.channels[channel].on(event, (value) => this.emit(event, channel, value));
    }
  }
  public getState(): Record<PrivateChannelId, PrivateChannelState> {
    return { claude: this.channels.claude.getState(), antigravity: this.channels.antigravity.getState() };
  }
  public async restore(): Promise<void> { await Promise.all(Object.values(this.channels).map((channel) => channel.restore())); }
  public stopMonitoring(): void { for (const channel of Object.values(this.channels)) channel.stopMonitoring(); }
  public async shutdown(): Promise<void> { await Promise.all(Object.values(this.channels).map((channel) => channel.shutdown())); }
}
