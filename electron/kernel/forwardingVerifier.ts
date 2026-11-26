import { setTimeout as delay } from 'node:timers/promises';
import { BUILTIN_TRACE_ENDPOINTS, selectProbeEndpointsForTransportHosts } from '../clash';
import { requestTextViaProxy } from '../net';

export async function probeChannelForwarding(
  port: number,
  transportHosts: readonly string[],
  registerAbortController: (ctrl: AbortController | null) => void,
  totalTimeoutMs = 10000,
  signal?: AbortSignal
): Promise<void> {
  signal?.throwIfAborted();
  const deadlineAt = Date.now() + totalTimeoutMs;
  const activeCandidates = selectProbeEndpointsForTransportHosts(
    BUILTIN_TRACE_ENDPOINTS,
    transportHosts
  );
  if (activeCandidates.length === 0) {
    throw new Error('常规探测源均与当前节点传输层域名重合，无法验证转发');
  }

  const proxyUrl = `http://127.0.0.1:${port}`;
  const instanceForwardingCtrl = new AbortController();
  registerAbortController(instanceForwardingCtrl);
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
    await requestTextViaProxy(
      url,
      proxyUrl,
      remainingMs,
      undefined,
      undefined,
      false,
      combinedSignal
    );
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
    registerAbortController(null);
    backupGateCtrl.abort();
    probeCtrl.abort();
    instanceForwardingCtrl.abort();
  }
}
