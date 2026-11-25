import { contextBridge, ipcRenderer } from 'electron';
import {
  AlertPayload,
  AppConfig,
  AppStateSnapshot,
  GuardBridgeAPI,
} from '../src/shared/types';

let pendingOpenUpdateModalOpts: { confirmClaude?: boolean } | null = null;
const openUpdateModalListeners = new Set<(opts: { confirmClaude?: boolean }) => void>();

ipcRenderer.on(
  'guard:open-update-modal',
  (_event: Electron.IpcRendererEvent, opts: { confirmClaude?: boolean }) => {
    const payload = opts || {};
    if (openUpdateModalListeners.size === 0) {
      pendingOpenUpdateModalOpts = payload;
      return;
    }
    for (const listener of openUpdateModalListeners) {
      listener(payload);
    }
  }
);

const api: GuardBridgeAPI = {
  getState: () => ipcRenderer.invoke('guard:get-state'),
  checkNow: (reason?: string) => ipcRenderer.invoke('guard:check-now', reason),
  setDefaultCurrent: () => ipcRenderer.invoke('guard:set-default-current'),
  setDefaultRegion: (code: string | null) => ipcRenderer.invoke('guard:set-default-region', code),
  updateConfig: (partial: Partial<AppConfig>, options?: { confirmTerminateClaude?: boolean }) =>
    ipcRenderer.invoke('guard:update-config', partial, options),
  clearLogs: () => ipcRenderer.invoke('guard:clear-logs'),
  syncSystemLocaleToDefault: (targetSource?: 'monitor' | 'claude') =>
    ipcRenderer.invoke('guard:sync-locale', targetSource),
  restoreDefaultChinaLocale: () => ipcRenderer.invoke('guard:restore-locale'),

  selectClashNode: (nodeName: string | null, profileUid?: string | null) =>
    ipcRenderer.invoke('guard:select-clash-node', nodeName, profileUid),
  probeClaudeNode: (reason?: string) => ipcRenderer.invoke('guard:probe-claude-node', reason),
  launchClaude: () => ipcRenderer.invoke('guard:launch-claude'),
  terminateClaudeNow: () => ipcRenderer.invoke('guard:terminate-claude'),
  browseClaudeExe: () => ipcRenderer.invoke('guard:browse-claude-exe'),

  selectAntigravityClashNode: (nodeName: string | null, profileUid?: string | null) =>
    ipcRenderer.invoke('guard:select-antigravity-node', nodeName, profileUid),
  probeAntigravityNode: () => ipcRenderer.invoke('guard:probe-antigravity-node'),
  launchAntigravity: () => ipcRenderer.invoke('guard:launch-antigravity'),
  terminateAntigravityNow: () => ipcRenderer.invoke('guard:terminate-antigravity'),
  browseAntigravityExe: () => ipcRenderer.invoke('guard:browse-antigravity-exe'),
  applyNodeUpdate: (channel) => ipcRenderer.invoke('guard:apply-node-update', channel),
  restartPrivateKernel: (channel) => ipcRenderer.invoke('guard:restart-private-kernel', channel),

  checkForUpdates: () => ipcRenderer.invoke('guard:check-for-updates'),
  downloadUpdate: () => ipcRenderer.invoke('guard:download-update'),
  applyUpdateNow: (allowTerminateClaude?: boolean) =>
    ipcRenderer.invoke('guard:apply-update', allowTerminateClaude),
  openReleasePage: () => ipcRenderer.invoke('guard:open-release-page'),

  minimizeMain: () => ipcRenderer.send('window:minimize-main'),
  closeMain: () => ipcRenderer.send('window:close-main'),
  openMainFromAlert: () => ipcRenderer.send('window:open-main-from-alert'),
  dismissAlert: () => ipcRenderer.send('window:dismiss-alert'),
  acceptCurrentAsDefaultFromAlert: () => ipcRenderer.invoke('guard:accept-current-from-alert'),
  getAlertData: () => ipcRenderer.invoke('guard:get-alert-data'),

  onStateChanged: (cb: (state: AppStateSnapshot) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, state: AppStateSnapshot) => cb(state);
    ipcRenderer.on('guard:state-changed', handler);
    return () => {
      ipcRenderer.removeListener('guard:state-changed', handler);
    };
  },

  onAlertData: (cb: (payload: AlertPayload) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, payload: AlertPayload) => cb(payload);
    ipcRenderer.on('guard:alert-data', handler);
    return () => {
      ipcRenderer.removeListener('guard:alert-data', handler);
    };
  },

  onOpenUpdateModal: (cb: (opts: { confirmClaude?: boolean }) => void) => {
    openUpdateModalListeners.add(cb);
    if (pendingOpenUpdateModalOpts) {
      queueMicrotask(() => {
        if (pendingOpenUpdateModalOpts && openUpdateModalListeners.has(cb)) {
          const buffered = pendingOpenUpdateModalOpts;
          pendingOpenUpdateModalOpts = null;
          cb(buffered);
        }
      });
    }
    return () => {
      openUpdateModalListeners.delete(cb);
    };
  },
};

contextBridge.exposeInMainWorld('guardAPI', api);
