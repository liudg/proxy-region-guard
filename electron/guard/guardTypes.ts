import {
  AlertPayload,
  AppStateSnapshot,
  PrivateChannelId,
  WindowsLocaleState,
} from '../../src/shared/types';
import { ClashMonitor } from '../clash';
import { PrivateProxyService } from '../kernel';
import { ConfigStore, GeoIpService, SystemProxyState } from '../system';
import { GuardAlertInput } from './alertBuilder';
import { EventLogStore } from './eventLogStore';
import { ProcessKillQueue } from './processKillQueue';

export const MAX_IN_FLIGHT_REBOUND_CONTINUES = 2;

export interface GuardRuntimeContext {
  readonly configStore: ConfigStore;
  readonly geoIp: GeoIpService;
  readonly clashMonitor: ClashMonitor;
  readonly privateProxies: PrivateProxyService;
  readonly logs: EventLogStore;
  readonly killQueue: ProcessKillQueue;

  isStarted(): boolean;
  isStopped(): boolean;
  getWinLocale(): WindowsLocaleState;
  setWinLocale(locale: WindowsLocaleState): void;
  isSyncingLocale(): boolean;
  setSyncingLocale(syncing: boolean): void;
  hasActiveApplicationChanges(): boolean;
  runApplicationChange<T>(
    operation: () => Promise<T>,
    channel?: PrivateChannelId | 'global'
  ): Promise<T>;
  getSystemProxyFresh(force?: boolean): Promise<SystemProxyState>;
  emitState(): void;
  emitGuardAlert(input: GuardAlertInput): void;
  emitSystemAlert(alertType: 'tun-enabled' | 'kernel-error', message: string): void;
  emitRecoveredAlert(payload: AlertPayload): void;
  getSnapshot(): AppStateSnapshot;
}
