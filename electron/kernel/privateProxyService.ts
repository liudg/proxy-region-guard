import { EventEmitter } from 'node:events';
import * as path from 'node:path';
import { PrivateChannelId, PrivateChannelState } from '../../src/shared/types';
import { verifyCore } from './kernelTypes';
import { PrivateKernel } from './privateKernel';

export class PrivateProxyService extends EventEmitter {
  public readonly channels: Record<PrivateChannelId, PrivateKernel>;

  constructor(directory: string, coreDirectory: string) {
    super();
    const executable = verifyCore(coreDirectory);
    this.channels = {
      claude: new PrivateKernel('claude', path.join(directory, 'claude'), executable),
      antigravity: new PrivateKernel(
        'antigravity',
        path.join(directory, 'antigravity'),
        executable
      ),
    };
    for (const channel of ['claude', 'antigravity'] as const) {
      for (const event of ['state', 'ready', 'lost', 'fault', 'port-conflict']) {
        this.channels[channel].on(event, (value) => this.emit(event, channel, value));
      }
    }
  }

  public getState(): Record<PrivateChannelId, PrivateChannelState> {
    return {
      claude: this.channels.claude.getState(),
      antigravity: this.channels.antigravity.getState(),
    };
  }

  public async restore(): Promise<void> {
    await Promise.all(Object.values(this.channels).map((channel) => channel.restore()));
  }

  public stopMonitoring(): void {
    for (const channel of Object.values(this.channels)) {
      channel.stopMonitoring();
    }
  }

  public async shutdown(): Promise<void> {
    await Promise.all(Object.values(this.channels).map((channel) => channel.shutdown()));
  }
}
