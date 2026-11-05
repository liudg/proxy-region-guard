import { contextBridge, ipcRenderer } from 'electron';
import {
  AlertPayload,
  AppConfig,
  AppStateSnapshot,
  GuardBridgeAPI,
} from '../src/shared/types';

const api: GuardBridgeAPI = {
  getState: () => ipcRenderer.invoke('guard:get-state'),
  checkNow: (reason?: string) => ipcRenderer.invoke('guard:check-now', reason),
  setDefaultCurrent: () => ipcRenderer.invoke('guard:set-default-current'),
  setDefaultRegion: (code: string | null) => ipcRenderer.invoke('guard:set-default-region', code),
  updateConfig: (partial: Partial<AppConfig>) => ipcRenderer.invoke('guard:update-config', partial),
  clearLogs: () => ipcRenderer.invoke('guard:clear-logs'),
  syncSystemLocaleToDefault: () => ipcRenderer.invoke('guard:sync-locale'),
  restoreDefaultChinaLocale: () => ipcRenderer.invoke('guard:restore-locale'),

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
};

contextBridge.exposeInMainWorld('guardAPI', api);
