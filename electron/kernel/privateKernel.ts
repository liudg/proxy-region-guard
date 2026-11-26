import { ChildProcess, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { PrivateChannelId, PrivateChannelState } from '../../src/shared/types';
import { BridgeUpstreamTarget, Ipv4ProxyBridge } from '../bridge';
import {
  extractSnapshotTransportHosts,
  isLocalPortListening,
  MihomoEndpoint,
  mihomoRequest,
  NodeSnapshot,
  SubscriptionCatalog,
} from '../clash';
import { probeChannelForwarding } from './forwardingVerifier';
import {
  getEffectiveMihomoPort,
  prepareKernelRevision,
  resolveKernelIpv4ViaDoh,
  validateSavedChannel,
} from './kernelConfigBuilder';
import {
  findExistingKernelLease,
  inspectBridgeUpstreamTarget,
  inspectListeningPortConflict,
  reconcilePendingKernelTransition,
  verifyKernelListenerEndpoint,
} from './kernelLeaseInspector';
import {
  getLocalPortOwnerPids,
  verifyKernelProcessIdentity,
} from './kernelProcessOwnership';
import {
  allocateFreeLoopbackPort,
  atomicWriteJsonSync,
  errorText,
  isKernelPidAlive,
  KernelLease,
  PortOwnershipError,
  PortOwnershipLookupError,
  SavedChannel,
} from './kernelTypes';

export class PrivateKernel extends EventEmitter {
  private saved: SavedChannel | null = null;
  private lease: KernelLease | null = null;
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
    phase: 'idle',
    pid: null,
    port: null,
    nodeName: null,
    profileUid: null,
    profileName: null,
    generation: 0,
    error: null,
    verificationError: null,
    sourceStatus: 'unknown',
    sourceError: null,
    restartAttempts: 0,
    nextRetryAt: null,
  };

  constructor(
    public readonly channel: PrivateChannelId,
    private readonly directory: string,
    private readonly executable: string
  ) {
    super();
    fs.mkdirSync(directory, { recursive: true });
  }

  public getState(): PrivateChannelState {
    return { ...this.state };
  }

  public getSnapshot(): NodeSnapshot | null {
    return this.saved ? structuredClone(this.saved.snapshot) : null;
  }

  public getIpv4Only(): boolean {
    return Boolean(this.saved?.ipv4Only);
  }

  public getInternalPort(): number | null {
    return getEffectiveMihomoPort(this.saved);
  }

  public getBoundTransportHosts(): string[] {
    return extractSnapshotTransportHosts(this.saved?.snapshot);
  }

  public hasScheduledHealthTimer(): boolean {
    return this.timer !== null;
  }

  private publish(): void {
    this.emit('state', this.getState());
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

  private resolveBridgeUpstreamTarget(signal?: AbortSignal): Promise<BridgeUpstreamTarget> {
    const saved = this.saved;
    const lease = this.lease;
    const generationAtStart = this.state.generation;
    return inspectBridgeUpstreamTarget({
      stopped: this.stopped,
      saved,
      lease,
      phase: this.state.phase,
      verifyingForwarding: this.verifyingForwarding,
      stateError: this.state.error,
      verificationError: this.state.verificationError,
      listenerOwnershipVerified: this.listenerOwnershipVerified,
      generation: generationAtStart,
      isLeaseProcessCurrent: () =>
        Boolean(
          !this.stopped &&
            lease &&
            this.lease === lease &&
            this.saved === saved &&
            isKernelPidAlive(lease.pid)
        ),
      isGenerationUnchanged: () => this.state.generation === generationAtStart,
      isGenerationAndOwnershipCurrent: () =>
        Boolean(
          this.state.generation === generationAtStart &&
            (this.state.phase !== 'error' || this.verifyingForwarding) &&
            this.listenerOwnershipVerified
        ),
      invalidateOwnership: () => {
        this.listenerOwnershipVerified = false;
      },
      onPortConflict: (conflictErr) => {
        this.markRecoverableListenerFault(conflictErr, true);
      },
      signal,
    });
  }

  public async resolveIpv4(
    hostname: string,
    signal?: AbortSignal,
    timeoutMs = 6000
  ): Promise<{ ips: string[]; ttlSec: number }> {
    return resolveKernelIpv4ViaDoh(this.saved, this.lease, hostname, signal, timeoutMs);
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

  private markRecoverableListenerFault(
    error: Error,
    isPortConflict = error instanceof PortOwnershipError
  ): void {
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

  public serial<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.queue.then(operation);
    this.queue = pending.then(
      () => undefined,
      () => undefined
    );
    return pending;
  }

  private setSelection(saved: SavedChannel | null): void {
    this.saved = saved;
    this.listenerFaultRecoverable = false;
    this.listenerOwnershipVerified = false;
    this.forwardingStateSeq++;
    Object.assign(this.state, {
      nodeName: saved?.snapshot.nodeName || null,
      profileUid: saved?.snapshot.profileUid || null,
      profileName: saved?.snapshot.profileName || null,
      port: saved?.port || null,
      error: null,
      verificationError: null,
      generation: this.state.generation + 1,
    });
    this.publish();
  }

  public async restore(): Promise<void> {
    this.stopped = false;
    this.shuttingDown = false;
    const file = path.join(this.directory, 'current.json');
    try {
      await reconcilePendingKernelTransition(this.directory, this.executable);
      if (!fs.existsSync(file)) return;
      const saved = JSON.parse(fs.readFileSync(file, 'utf8')) as SavedChannel;
      validateSavedChannel(saved);
      this.setSelection(saved);
      const lease = await findExistingKernelLease(
        this.channel,
        this.directory,
        this.executable,
        this.saved
      );
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
    } catch (error) {
      this.fail(error);
    }
  }

  public select(
    snapshot: NodeSnapshot | null,
    port: number,
    options?: { ipv4Only?: boolean }
  ): Promise<void> {
    this.abortStartup('切换专属节点');
    this.abortHealthCheck('切换专属节点');
    this.abortListenerRecovery('切换专属节点');
    this.abortForwardingProbe('切换专属节点');
    return this.serial(async () => {
      let stoppedPrevious = false;
      try {
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          throw new Error('私有代理端口无效');
        }
        const ipv4Only = Boolean(options?.ipv4Only);
        const excludePorts = new Set<number>([port]);
        if (this.saved?.internalPort) excludePorts.add(this.saved.internalPort);
        if (this.saved?.port) excludePorts.add(this.saved.port);
        const internalPort =
          snapshot && ipv4Only ? await allocateFreeLoopbackPort(excludePorts) : undefined;
        const next: SavedChannel | null = snapshot
          ? {
              schema: 1,
              snapshot,
              port,
              ...(ipv4Only ? { ipv4Only: true, internalPort } : {}),
              revision: randomUUID(),
            }
          : null;
        const endpoint = next
          ? await prepareKernelRevision(this.channel, this.directory, this.executable, next)
          : null;
        if (next && port !== this.state.port && (await isLocalPortListening(port))) {
          throw new Error(`专属端口 ${port} 已被其他进程占用`);
        }
        const previousSaved = this.saved;
        const pendingPath = path.join(this.directory, 'pending.json');
        this.cancelRetry();
        stoppedPrevious = true;
        try {
          await reconcilePendingKernelTransition(this.directory, this.executable);
          await this.stopProcess();
          this.retries = [];
          this.state.restartAttempts = 0;
          if (next) {
            atomicWriteJsonSync(pendingPath, next);
            this.setSelection(next);
            await this.startProcess(endpoint!);
            try {
              atomicWriteJsonSync(path.join(this.directory, 'current.json'), next);
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
          if (previousSaved && next) {
            this.setSelection(previousSaved);
          }
          this.fail(error);
          throw error;
        }
      } finally {
        if (
          !stoppedPrevious &&
          !this.stopped &&
          this.lease &&
          this.state.phase === 'ready' &&
          !this.timer
        ) {
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
        await reconcilePendingKernelTransition(this.directory, this.executable);
        await this.stopProcess();
        await this.startProcess();
      } catch (error) {
        this.fail(error);
        throw error;
      }
    });
  }

  public async checkReady(signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    if (this.state.phase !== 'ready') throw new Error(this.state.error || '私有内核尚未就绪');
    await this.verifyListener(!this.listenerOwnershipVerified, signal);
  }

  public recoverListenerIfNeeded(
    signal?: AbortSignal
  ): Promise<'rebound' | 'already-ready' | 'failed'> {
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
      if (!this.lease || !isKernelPidAlive(this.lease.pid)) {
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

      const handleDeadLeaseIfNeeded = (): boolean => {
        if (!this.lease || !isKernelPidAlive(this.lease.pid)) {
          this.child = null;
          this.lease = null;
          this.state.pid = null;
          this.unexpectedExit('私有内核进程已退出');
          return true;
        }
        return false;
      };

      try {
        try {
          await this.verifyListener(true, recoverySignal);
          if (isSuperseded() || handleDeadLeaseIfNeeded()) return 'failed';
          const wasNotReady = this.state.phase !== 'ready';
          const prevVerificationError = this.state.verificationError;
          await this.ensureIpv4BridgeStarted(savedAtStart);
          if (isSuperseded()) return 'failed';
          if (wasNotReady || prevVerificationError !== null) {
            await this.verifyForwarding(recoverySignal);
            if (isSuperseded() || handleDeadLeaseIfNeeded()) return 'failed';
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
            if (handleDeadLeaseIfNeeded()) return 'failed';
            if (this.state.phase === 'error') {
              this.markRecoverableListenerFault(error, false);
            } else {
              this.state.verificationError = errorText(error);
              this.publish();
              this.scheduleHealth();
            }
            return 'failed';
          }
        }

        if (isSuperseded() || handleDeadLeaseIfNeeded()) return 'failed';

        try {
          const configPath = path.join(this.directory, this.saved.revision, 'config.yaml');
          const payload = fs.readFileSync(configPath, 'utf8');
          if (isSuperseded()) return 'failed';
          await mihomoRequest(
            this.lease.endpoint,
            '/configs?force=true',
            'PUT',
            { payload },
            recoverySignal,
            10000
          );
          const deadline = Date.now() + 5000;
          let lastVerifyError: unknown = new Error('私有内核专属监听未就绪');
          while (Date.now() < deadline) {
            if (isSuperseded()) return 'failed';
            if (!this.lease || !isKernelPidAlive(this.lease.pid)) {
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
          if (isSuperseded() || handleDeadLeaseIfNeeded()) return 'failed';
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
          if (isSuperseded() || handleDeadLeaseIfNeeded()) return 'failed';
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
          const leaseAtFault = this.lease!;
          const mihomoPortAtFault = getEffectiveMihomoPort(savedAtStart)!;
          const conflictCheck = await inspectListeningPortConflict(
            mihomoPortAtFault,
            leaseAtFault.pid,
            recoverySignal
          );
          if (isSuperseded()) return 'failed';
          if (!this.lease || this.lease !== leaseAtFault || !isKernelPidAlive(leaseAtFault.pid)) {
            if (this.lease === leaseAtFault) {
              this.child = null;
              this.lease = null;
              this.state.pid = null;
              this.unexpectedExit('私有内核进程已退出');
            }
            return 'failed';
          }
          if (conflictCheck.conflictDetected) {
            this.markRecoverableListenerFault(
              new PortOwnershipError(
                `专属端口 ${savedAtStart.port} 监听归属与当前私有内核进程不匹配`
              ),
              true
            );
            return 'failed';
          }
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
    const lease = this.lease;
    const saved = this.saved;
    const generation = this.state.generation;
    const mihomoPort = getEffectiveMihomoPort(saved);
    await verifyKernelListenerEndpoint({
      lease,
      saved,
      verifyOwner,
      booting: this.booting,
      phase: this.state.phase,
      ipv4Bridge: this.ipv4Bridge,
      assertLeaseCurrent: () => {
        if (
          this.stopped ||
          this.lease !== lease ||
          this.saved !== saved ||
          this.state.generation !== generation ||
          !lease ||
          !saved ||
          !mihomoPort ||
          !isKernelPidAlive(lease.pid)
        ) {
          throw new Error('私有内核进程已退出');
        }
      },
      setOwnershipVerified: (verified) => {
        this.listenerOwnershipVerified = verified;
      },
      signal,
    });
  }

  public clearForwardingError(): void {
    if (this.state.phase === 'ready' && this.state.verificationError !== null) {
      this.forwardingStateSeq++;
      this.state.verificationError = null;
      this.publish();
    }
  }

  private async probeForwarding(
    port: number,
    totalTimeoutMs = 10000,
    signal?: AbortSignal
  ): Promise<void> {
    await probeChannelForwarding(
      port,
      this.getBoundTransportHosts(),
      (ctrl) => {
        if (ctrl !== null || this.forwardingAbort !== null) {
          this.forwardingAbort = ctrl;
        }
      },
      totalTimeoutMs,
      signal
    );
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
    const mihomoPort = getEffectiveMihomoPort(saved);
    if (!mihomoPort) throw new Error('私有内核监听端口无效');
    const bridgeAlreadyHoldingPublicPort = Boolean(
      saved.ipv4Only && this.ipv4Bridge?.isListening() && this.ipv4Bridge.getPort() === saved.port
    );
    if (!bridgeAlreadyHoldingPublicPort && (await isLocalPortListening(saved.port))) {
      throw new Error(`专属端口 ${saved.port} 已被其他进程占用`);
    }
    if (saved.ipv4Only && (await isLocalPortListening(mihomoPort))) {
      throw new Error(`私有内核内部端口 ${mihomoPort} 已被其他进程占用`);
    }
    const endpoint =
      preparedEndpoint ||
      (await prepareKernelRevision(this.channel, this.directory, this.executable, saved));
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
      child = spawn(
        this.executable,
        ['-d', revisionDirectory, '-f', path.join(revisionDirectory, 'config.yaml')],
        { windowsHide: true, detached: true, stdio: ['ignore', log, log] }
      );
    } finally {
      fs.closeSync(log);
    }
    this.child = child;
    this.booting = true;
    const startupCtrl = new AbortController();
    this.startupAbort = startupCtrl;
    const startupSignal = startupCtrl.signal;
    let listenerVerified = false;
    try {
      await new Promise<void>((resolve, reject) => {
        child.once('spawn', resolve);
        child.once('error', reject);
      });
      child.unref();
      this.lease = {
        pid: child.pid!,
        endpoint,
        executable: this.executable,
        revision: saved.revision,
      };
      atomicWriteJsonSync(path.join(this.directory, 'runtime.json'), this.lease);
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
        if (child.exitCode !== null || child.signalCode !== null) {
          throw new Error('私有内核在启动期间退出，请查看内核日志');
        }
        try {
          await this.verifyListener(true, startupSignal);
          lastError = null;
          break;
        } catch (error) {
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
      await this.verifyForwarding(startupSignal);
      if (
        this.stopped &&
        !this.shuttingDown &&
        this.child === child &&
        this.lease &&
        isKernelPidAlive(this.lease.pid)
      ) {
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
        isKernelPidAlive(this.lease.pid)
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
    this.timer = setTimeout(
      () =>
        void this.serial(async () => {
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
            if (!isKernelPidAlive(leaseAtStart.pid)) {
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
            const mihomoPortAtStart = getEffectiveMihomoPort(savedAtStart)!;
            try {
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
              const conflictCheck = await inspectListeningPortConflict(
                mihomoPortAtStart,
                leaseAtStart.pid,
                healthSignal
              );
              if (abortIfSupersededOrDead()) return;
              if (conflictCheck.lookupError !== null) {
                this.state.verificationError = `${errorText(error)}（端口归属复核未完成：${errorText(conflictCheck.lookupError)}）`;
                this.publish();
                this.scheduleHealth();
                return;
              }
              if (conflictCheck.conflictDetected) {
                this.markRecoverableListenerFault(
                  new PortOwnershipError(
                    `专属端口 ${savedAtStart.port} 监听归属与当前私有内核进程不匹配`
                  ),
                  true
                );
                return;
              }
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
        }),
      3000
    );
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
    if (this.retries.length >= 3) {
      this.fail(new Error('私有内核在 60 秒内连续恢复失败三次，请处理故障后手动重启'));
      return;
    }
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
        try {
          await this.startProcess();
        } catch (error) {
          if (epoch !== this.recoveryEpoch) return;
          this.state.error = errorText(error);
          if (this.child !== null || this.lease !== null) {
            try {
              await this.stopProcess();
            } catch (stopError) {
              this.fail(stopError);
              return;
            }
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
    this.state.phase = 'error';
    this.state.error = errorText(error);
    this.state.nextRetryAt = null;
    this.publish();
    this.emit('fault', this.state.error);
  }

  public refreshSource(catalog: SubscriptionCatalog): void {
    if (!this.saved) return;
    try {
      const next = catalog.capture(this.saved.snapshot.profileUid, this.saved.snapshot.nodeName);
      this.state.sourceStatus =
        next.fingerprint === this.saved.snapshot.fingerprint ? 'current' : 'changed';
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
    const lease =
      this.lease ||
      (await findExistingKernelLease(this.channel, this.directory, this.executable, this.saved));
    const child = this.child;
    if (lease) {
      if (isKernelPidAlive(lease.pid) && child?.pid !== lease.pid) {
        await verifyKernelProcessIdentity(this.directory, this.executable, lease);
      }
      this.lease = lease;
      this.child = null;
      this.booting = false;
      if (isKernelPidAlive(lease.pid)) process.kill(lease.pid);
      const exitDeadline = Date.now() + 4000;
      while (isKernelPidAlive(lease.pid)) {
        if (Date.now() >= exitDeadline) {
          throw new Error(`私有内核进程 (PID=${lease.pid}) 退出超时`);
        }
        await delay(100);
      }
      const mihomoPort = getEffectiveMihomoPort(this.saved);
      if (mihomoPort) {
        const quickReleaseDeadline = Date.now() + 500;
        while (Date.now() < quickReleaseDeadline && (await isLocalPortListening(mihomoPort))) {
          await delay(100);
        }
        if (await isLocalPortListening(mihomoPort)) {
          const pids = await getLocalPortOwnerPids(mihomoPort);
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
