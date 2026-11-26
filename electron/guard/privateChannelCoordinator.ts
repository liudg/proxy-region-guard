import { PrivateChannelId } from '../../src/shared/types';
import { GuardRuntimeContext } from './guardTypes';

export interface BindPrivateSelectionOptions {
  applyUpdate?: boolean;
  ipv4OnlyOverride?: boolean;
  persistSelection?: boolean;
}

export class PrivateChannelCoordinator {
  constructor(private readonly ctx: GuardRuntimeContext) {}

  public persistPrivateSelection(channel: PrivateChannelId): void {
    const state = this.ctx.privateProxies.channels[channel].getState();
    const cfg = this.ctx.configStore.get();
    this.ctx.configStore.update(
      channel === 'claude'
        ? {
            selectedClashNode: state.nodeName,
            selectedClashProfileUid: state.profileUid,
            selectedClashProfileName: state.profileName,
            dedicatedProxyPort: state.port || cfg.dedicatedProxyPort,
          }
        : {
            antigravityClashNode: state.nodeName,
            antigravityClashProfileUid: state.profileUid,
            antigravityClashProfileName: state.profileName,
            antigravityDedicatedPort: state.port || cfg.antigravityDedicatedPort,
          }
    );
  }

  public async checkPrivateReady(
    channel: PrivateChannelId,
    signal?: AbortSignal
  ): Promise<{ ok: boolean; error?: string }> {
    try {
      await this.ctx.privateProxies.channels[channel].checkReady(signal);
      return { ok: true };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  public async bindPrivateSelection(
    channel: PrivateChannelId,
    node: string | null,
    port: number,
    uid: string | null,
    options?: BindPrivateSelectionOptions
  ): Promise<{ ok: boolean; error?: string }> {
    const applyUpdate = options?.applyUpdate ?? false;
    const persistSelection = options?.persistSelection ?? true;
    const kernel = this.ctx.privateProxies.channels[channel];
    let selectionCompleted = false;
    try {
      const current = kernel.getSnapshot();
      const targetIpv4Only =
        channel === 'claude'
          ? options?.ipv4OnlyOverride ?? this.ctx.configStore.get().claudeForceIpv4
          : false;
      if (node && !uid) throw new Error('请选择节点所属的订阅');
      let snapshot = current;
      if (!node) {
        snapshot = null;
      } else if (applyUpdate || current?.nodeName !== node || current.profileUid !== uid) {
        await this.ctx.clashMonitor.refresh();
        snapshot = this.ctx.clashMonitor.catalog.capture(uid!, node);
      }
      if (
        snapshot?.fingerprint === current?.fingerprint &&
        kernel.getState().port === port &&
        kernel.getState().phase === 'ready' &&
        kernel.getIpv4Only() === targetIpv4Only
      ) {
        return { ok: true };
      }
      await kernel.select(snapshot, port, { ipv4Only: targetIpv4Only });
      selectionCompleted = true;
      kernel.refreshSource(this.ctx.clashMonitor.catalog);
      return { ok: true };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    } finally {
      if (persistSelection && (kernel.getSnapshot() || selectionCompleted)) {
        this.persistPrivateSelection(channel);
      }
    }
  }

  public async ensurePrivateChannelReadyForLaunch(
    channel: PrivateChannelId
  ): Promise<{ ok: boolean; error?: string }> {
    if (channel === 'claude') {
      const cfg = this.ctx.configStore.get();
      const kernel = this.ctx.privateProxies.channels.claude;
      if (
        cfg.selectedClashNode &&
        kernel.getSnapshot() &&
        kernel.getIpv4Only() !== cfg.claudeForceIpv4
      ) {
        const migrated = await this.bindPrivateSelection(
          'claude',
          cfg.selectedClashNode,
          cfg.dedicatedProxyPort,
          cfg.selectedClashProfileUid,
          { ipv4OnlyOverride: cfg.claudeForceIpv4 }
        );
        if (!migrated.ok) {
          return migrated;
        }
      }
    }
    let bindRes = await this.checkPrivateReady(channel);
    if (!bindRes.ok || this.ctx.privateProxies.channels[channel].getState().verificationError) {
      const recovered =
        await this.ctx.privateProxies.channels[channel].recoverListenerIfNeeded();
      if (recovered !== 'failed') {
        bindRes = await this.checkPrivateReady(channel);
      }
    }
    return bindRes;
  }
}
