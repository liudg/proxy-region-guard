import * as fs from 'node:fs';
import * as path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { PrivateChannelId, PrivateChannelState } from '../../src/shared/types';
import { BridgeUpstreamTarget, Ipv4ProxyBridge } from '../bridge';
import { isLocalPortListening, mihomoRequest, readYaml } from '../clash';
import { getEffectiveMihomoPort, validateSavedChannel } from './kernelConfigBuilder';
import { getLocalPortOwnerPids, verifyKernelProcessIdentity } from './kernelProcessOwnership';
import {
  atomicWriteJsonSync,
  errorText,
  isKernelPidAlive,
  KernelLease,
  PortOwnershipError,
  PortOwnershipLookupError,
  SavedChannel,
} from './kernelTypes';

export interface BridgeUpstreamInspectionParams {
  stopped: boolean;
  saved: SavedChannel | null;
  lease: KernelLease | null;
  phase: PrivateChannelState['phase'];
  verifyingForwarding: boolean;
  stateError: string | null;
  verificationError: string | null;
  listenerOwnershipVerified: boolean;
  generation: number;
  isLeaseProcessCurrent: () => boolean;
  isGenerationUnchanged: () => boolean;
  isGenerationAndOwnershipCurrent: () => boolean;
  invalidateOwnership: () => void;
  onPortConflict: (error: PortOwnershipError) => void;
  signal?: AbortSignal;
}

export async function inspectBridgeUpstreamTarget(
  params: BridgeUpstreamInspectionParams
): Promise<BridgeUpstreamTarget> {
  params.signal?.throwIfAborted();
  const { saved, lease } = params;
  const mihomoPort = getEffectiveMihomoPort(saved);
  if (params.stopped || !saved || !mihomoPort) {
    return { status: 'unavailable', reason: '私有内核已停止或未配置' };
  }
  if (params.phase === 'error' && !params.verifyingForwarding) {
    return {
      status: 'blocked',
      reason: params.stateError || params.verificationError || '专属端口归属异常，已阻断转发',
    };
  }
  if (!lease || !isKernelPidAlive(lease.pid)) {
    return { status: 'unavailable', reason: '私有内核进程尚未就绪' };
  }
  if (!params.listenerOwnershipVerified) {
    return {
      status: 'blocked',
      reason:
        params.verificationError ||
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
      params.signal,
      2000
    );
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') throw error;
    if (!isKernelPidAlive(lease.pid) || !params.isLeaseProcessCurrent()) {
      return { status: 'unavailable', reason: '私有内核进程已退出' };
    }
    if (params.isGenerationUnchanged()) {
      params.invalidateOwnership();
    }
    return {
      status: 'blocked',
      reason: `无法核验私有内核监听归属：${errorText(error)}`,
    };
  }

  if (!params.isLeaseProcessCurrent()) {
    return { status: 'unavailable', reason: '私有内核状态已变更' };
  }
  if (!params.isGenerationUnchanged()) {
    return {
      status: 'blocked',
      reason: '私有内核监听世代已变更，已阻断旧连接转发',
    };
  }

  if (config['mixed-port'] !== mihomoPort || config.mode !== 'rule') {
    params.invalidateOwnership();
    let pids: number[] | null = null;
    try {
      pids = await getLocalPortOwnerPids(mihomoPort, params.signal);
    } catch {
      pids = null;
    }
    if (!params.isLeaseProcessCurrent()) {
      return { status: 'unavailable', reason: '私有内核状态已变更' };
    }
    if (!params.isGenerationUnchanged()) {
      return {
        status: 'blocked',
        reason: '私有内核监听世代已变更，已阻断旧连接转发',
      };
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
      params.onPortConflict(conflictErr);
      return { status: 'blocked', reason: conflictErr.message };
    }
    if (pids.length === 0) {
      const stillListening = await isLocalPortListening(mihomoPort, 500, params.signal);
      if (!params.isLeaseProcessCurrent()) {
        return { status: 'unavailable', reason: '私有内核状态已变更' };
      }
      if (!params.isGenerationUnchanged()) {
        return {
          status: 'blocked',
          reason: '私有内核监听世代已变更，已阻断旧连接转发',
        };
      }
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
      params.onPortConflict(conflictErr);
      return { status: 'blocked', reason: conflictErr.message };
    }
    return {
      status: 'blocked',
      reason: `专属端口 ${saved.port} 内部监听配置异常，已阻断转发`,
    };
  }

  if (!params.isGenerationAndOwnershipCurrent()) {
    return {
      status: 'blocked',
      reason: '私有内核监听世代或归属状态已变更，已阻断旧连接转发',
    };
  }

  return { status: 'ready', port: mihomoPort, generation: params.generation };
}

export async function findExistingKernelLease(
  channel: PrivateChannelId,
  directory: string,
  executable: string,
  saved: SavedChannel | null
): Promise<KernelLease | null> {
  const leasePath = path.join(directory, 'runtime.json');
  if (fs.existsSync(leasePath)) {
    const lease = JSON.parse(fs.readFileSync(leasePath, 'utf8')) as KernelLease;
    if (!Number.isInteger(lease.pid) || lease.pid <= 0) {
      throw new Error('私有内核进程记录无效');
    }
    if (isKernelPidAlive(lease.pid)) {
      if (
        !saved ||
        lease.revision !== saved.revision ||
        path.resolve(lease.executable).toLowerCase() !== path.resolve(executable).toLowerCase()
      ) {
        throw new Error('已有私有内核与保存的配置版本不一致');
      }
      await verifyKernelProcessIdentity(directory, executable, lease);
      return lease;
    }
  }

  const mihomoPort = getEffectiveMihomoPort(saved);
  if (!saved || !mihomoPort || !(await isLocalPortListening(mihomoPort))) return null;

  const pids = await getLocalPortOwnerPids(mihomoPort);
  if (pids.length !== 1) throw new Error('无法确定专属端口的唯一监听进程');
  await verifyKernelProcessIdentity(directory, executable, {
    pid: pids[0],
    revision: saved.revision,
  });
  const configuration = readYaml(path.join(directory, saved.revision, 'config.yaml'));
  const pipePath = configuration['external-controller-pipe'];
  const secret = configuration.secret;
  if (
    configuration['mixed-port'] !== mihomoPort ||
    typeof pipePath !== 'string' ||
    !pipePath.startsWith(`\\\\.\\pipe\\proxy-region-guard-${channel}-`) ||
    typeof secret !== 'string' ||
    !secret
  ) {
    throw new Error('私有内核控制接口配置无效');
  }
  const lease: KernelLease = {
    pid: pids[0],
    executable,
    revision: saved.revision,
    endpoint: { pipePath, secret },
  };
  atomicWriteJsonSync(leasePath, lease);
  return lease;
}

/**
 * 恢复或清理因卫士在切换内核窗口期崩溃留下的未提交切换记录（pending.json）
 */
export async function reconcilePendingKernelTransition(
  directory: string,
  executable: string
): Promise<void> {
  const pendingPath = path.join(directory, 'pending.json');
  if (!fs.existsSync(pendingPath)) return;

  const pending = JSON.parse(fs.readFileSync(pendingPath, 'utf8')) as SavedChannel;
  validateSavedChannel(pending);

  const currentPath = path.join(directory, 'current.json');
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

  const leasePath = path.join(directory, 'runtime.json');
  if (fs.existsSync(leasePath)) {
    const lease = JSON.parse(fs.readFileSync(leasePath, 'utf8')) as KernelLease;
    if (Number.isInteger(lease.pid) && lease.pid > 0 && lease.revision === pending.revision) {
      if (isKernelPidAlive(lease.pid)) {
        if (
          path.resolve(lease.executable).toLowerCase() !== path.resolve(executable).toLowerCase()
        ) {
          throw new Error('未提交切换内核的可执行路径与当前卫士内核不一致');
        }
        await verifyKernelProcessIdentity(directory, executable, lease);
        process.kill(lease.pid);
        const exitDeadline = Date.now() + 4000;
        while (isKernelPidAlive(lease.pid)) {
          if (Date.now() >= exitDeadline) {
            throw new Error(`清理未提交切换内核 (PID=${lease.pid}) 退出超时`);
          }
          await delay(100);
        }
        const pendingPort = getEffectiveMihomoPort(pending);
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

export interface VerifyKernelListenerParams {
  lease: KernelLease | null;
  saved: SavedChannel | null;
  verifyOwner: boolean;
  booting: boolean;
  phase: PrivateChannelState['phase'];
  ipv4Bridge: Ipv4ProxyBridge | null;
  assertLeaseCurrent: () => void;
  setOwnershipVerified: (verified: boolean) => void;
  signal?: AbortSignal;
}

export async function verifyKernelListenerEndpoint(
  params: VerifyKernelListenerParams
): Promise<void> {
  const { lease, saved, verifyOwner, signal, assertLeaseCurrent, setOwnershipVerified } = params;
  signal?.throwIfAborted();
  const mihomoPort = getEffectiveMihomoPort(saved);
  assertLeaseCurrent();

  if (!(await isLocalPortListening(mihomoPort!, 800, signal))) {
    signal?.throwIfAborted();
    assertLeaseCurrent();
    setOwnershipVerified(false);
    throw new Error('私有内核专属监听未就绪');
  }
  signal?.throwIfAborted();
  assertLeaseCurrent();

  if (verifyOwner) {
    let pids: number[];
    try {
      pids = await getLocalPortOwnerPids(mihomoPort!, signal);
    } catch (ownerError) {
      signal?.throwIfAborted();
      assertLeaseCurrent();
      setOwnershipVerified(false);
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
      setOwnershipVerified(false);
      if (!foreignPidDetected && !stillListeningWithUnknownOwner) {
        throw new Error('私有内核专属监听未就绪');
      }
      throw new PortOwnershipError(
        `专属端口 ${saved!.port} 监听归属与当前私有内核进程不匹配`
      );
    }
  }

  const config = await mihomoRequest<Record<string, unknown>>(
    lease!.endpoint,
    '/configs',
    'GET',
    undefined,
    signal
  );
  assertLeaseCurrent();
  if (config['mixed-port'] !== mihomoPort || config.mode !== 'rule') {
    setOwnershipVerified(false);
    throw new Error('私有内核运行配置与保存的副本不一致');
  }

  const proxies = await mihomoRequest<{ proxies: Record<string, unknown> }>(
    lease!.endpoint,
    '/proxies',
    'GET',
    undefined,
    signal
  );
  assertLeaseCurrent();
  if (!proxies.proxies[saved!.snapshot.nodeName]) {
    setOwnershipVerified(false);
    throw new Error('私有内核专属监听未就绪');
  }

  if (verifyOwner) {
    setOwnershipVerified(true);
  }
  if (
    saved!.ipv4Only &&
    !params.booting &&
    params.phase === 'ready' &&
    (!params.ipv4Bridge?.isListening() || params.ipv4Bridge.getPort() !== saved!.port)
  ) {
    throw new Error('IPv4 强制代理桥接监听未就绪');
  }
}

export async function inspectListeningPortConflict(
  mihomoPort: number,
  expectedPid: number,
  signal?: AbortSignal
): Promise<{
  notListening: boolean;
  lookupError: unknown | null;
  conflictDetected: boolean;
}> {
  if (!(await isLocalPortListening(mihomoPort, 800, signal))) {
    return { notListening: true, lookupError: null, conflictDetected: false };
  }
  let pids: number[] = [];
  try {
    pids = await getLocalPortOwnerPids(mihomoPort, signal);
  } catch (ownerError) {
    return { notListening: false, lookupError: ownerError, conflictDetected: false };
  }
  const foreignPidDetected = pids.some((pid) => pid !== expectedPid);
  const stillListeningWithUnknownOwner =
    !foreignPidDetected &&
    pids.length === 0 &&
    (await isLocalPortListening(mihomoPort, 800, signal));
  return {
    notListening: false,
    lookupError: null,
    conflictDetected: foreignPidDetected || stillListeningWithUnknownOwner,
  };
}
