import { BrowserWindow } from 'electron';
import { AppStateSnapshot, GuardStatus } from '../../src/shared/types';
import { ConfigStore } from '../system';
import {
  getPreloadPath,
  loadRendererRoute,
  waitForPostUpdateRendererReady,
} from './rendererLoader';
import { createWindowAppIcon } from './trayIcon';

const MAIN_HIDDEN_DESTROY_DELAY_MS = 4000;

export interface MainWindowManagerDeps {
  getConfigStore: () => ConfigStore | undefined;
  getSnapshot: () => AppStateSnapshot | undefined;
  isBootstrapped: () => boolean;
  isQuitting: () => boolean;
  onWindowShownForUpdater: () => void;
  onEnsureTrayHealthyOnHide: () => void;
}

export class MainWindowManager {
  private mainWindow: BrowserWindow | null = null;
  private mainDestroyTimer: NodeJS.Timeout | null = null;
  private mainWindowReadyToShow = false;
  private readonly suppressAutoCheckWindows = new WeakSet<BrowserWindow>();

  constructor(private readonly deps: MainWindowManagerDeps) {}

  private clearDestroyTimer(): void {
    if (this.mainDestroyTimer) {
      clearTimeout(this.mainDestroyTimer);
      this.mainDestroyTimer = null;
    }
  }

  public getWindow(): BrowserWindow | null {
    return this.mainWindow && !this.mainWindow.isDestroyed() ? this.mainWindow : null;
  }

  public isFocusedVisible(): boolean {
    return Boolean(
      this.mainWindow &&
        !this.mainWindow.isDestroyed() &&
        this.mainWindow.isVisible() &&
        this.mainWindow.isFocused()
    );
  }

  public hideToTray(): void {
    this.deps.onEnsureTrayHealthyOnHide();
    if (!this.mainWindow || this.mainWindow.isDestroyed()) return;
    this.mainWindow.hide();
    this.clearDestroyTimer();
    this.mainDestroyTimer = setTimeout(() => {
      this.mainDestroyTimer = null;
      if (this.mainWindow && !this.mainWindow.isDestroyed() && !this.mainWindow.isVisible()) {
        this.mainWindow.destroy();
        this.mainWindow = null;
      }
    }, MAIN_HIDDEN_DESTROY_DELAY_MS);
    this.mainDestroyTimer.unref?.();
  }

  public minimize(): void {
    this.getWindow()?.minimize();
  }

  public closeFromTitlebar(): void {
    if (this.deps.getConfigStore()?.get().closeToTray) {
      this.hideToTray();
    } else {
      this.mainWindow?.destroy();
      this.mainWindow = null;
    }
  }

  public createMainWindow(
    revealOnReady = true,
    initialHash?: string,
    skipInitialAutoCheck = false
  ): BrowserWindow {
    this.clearDestroyTimer();
    this.mainWindowReadyToShow = !revealOnReady;
    let suppressFirstShowAutoCheck = skipInitialAutoCheck;
    const curStatus: GuardStatus = this.deps.getSnapshot()?.status ?? 'unset';
    const icon = createWindowAppIcon(curStatus);

    const win = new BrowserWindow({
      width: 530,
      height: 760,
      minWidth: 480,
      minHeight: 650,
      center: true,
      frame: false,
      transparent: false,
      backgroundColor: '#0B1120',
      show: false,
      icon,
      title: '代理地区卫士',
      webPreferences: {
        preload: getPreloadPath(),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        spellcheck: false,
      },
    });
    this.mainWindow = win;

    loadRendererRoute(win, initialHash);

    if (revealOnReady) {
      let revealed = false;
      let fallbackTimer: NodeJS.Timeout | null = null;

      const reveal = () => {
        if (revealed) return;
        revealed = true;
        this.mainWindowReadyToShow = true;
        if (fallbackTimer) {
          clearTimeout(fallbackTimer);
          fallbackTimer = null;
        }
        if (!win.isDestroyed() && !win.isVisible()) {
          win.show();
          win.focus();
        }
      };

      win.once('ready-to-show', reveal);
      fallbackTimer = setTimeout(reveal, 600);
      fallbackTimer.unref?.();
    }

    win.on('show', () => {
      this.mainWindowReadyToShow = true;
      this.clearDestroyTimer();
      const snap = this.deps.getSnapshot();
      if (snap && !win.isDestroyed()) {
        win.webContents.send('guard:state-changed', snap);
      }
      const skipAuto = suppressFirstShowAutoCheck || this.suppressAutoCheckWindows.has(win);
      suppressFirstShowAutoCheck = false;
      this.suppressAutoCheckWindows.delete(win);
      if (!skipAuto) {
        this.deps.onWindowShownForUpdater();
      }
    });

    win.on('restore', () => {
      if (!this.suppressAutoCheckWindows.has(win)) {
        this.deps.onWindowShownForUpdater();
      }
    });

    win.on('close', (e) => {
      if (!this.deps.isQuitting() && this.deps.getConfigStore()?.get().closeToTray) {
        e.preventDefault();
        this.hideToTray();
      }
    });

    win.on('closed', () => {
      this.clearDestroyTimer();
      if (this.mainWindow === win) {
        this.mainWindow = null;
        this.mainWindowReadyToShow = false;
      }
    });

    return win;
  }

  public showMainWindow(opts: { skipAutoUpdateCheck?: boolean } = {}): void {
    if (!this.deps.isBootstrapped()) return;
    this.clearDestroyTimer();
    if (!this.mainWindow || this.mainWindow.isDestroyed()) {
      this.createMainWindow(true, undefined, Boolean(opts.skipAutoUpdateCheck));
      return;
    }
    const win = this.mainWindow;
    if (!this.mainWindowReadyToShow) {
      if (opts.skipAutoUpdateCheck) {
        this.suppressAutoCheckWindows.add(win);
      }
      return;
    }
    const wasHiddenOrMinimized = !win.isVisible() || win.isMinimized();
    if (opts.skipAutoUpdateCheck) {
      this.suppressAutoCheckWindows.add(win);
    }
    try {
      if (win.isMinimized()) {
        win.restore();
      }
      win.show();
      win.focus();
    } finally {
      this.suppressAutoCheckWindows.delete(win);
    }
    if (!wasHiddenOrMinimized && !opts.skipAutoUpdateCheck) {
      this.deps.onWindowShownForUpdater();
    }
  }

  private sendOpenUpdateModalWhenReady(win: BrowserWindow, confirmClaude: boolean): void {
    if (win.isDestroyed()) return;
    const dispatch = () => {
      if (!win.isDestroyed()) {
        win.webContents.send('guard:open-update-modal', { confirmClaude });
      }
    };
    if (win.webContents.isLoading()) {
      win.webContents.once('did-finish-load', dispatch);
    } else {
      dispatch();
    }
  }

  public openUpdateModal(confirmClaude = false, skipAutoUpdateCheck = false): void {
    if (!this.deps.isBootstrapped()) return;
    this.clearDestroyTimer();
    if (!this.mainWindow || this.mainWindow.isDestroyed()) {
      this.createMainWindow(
        true,
        confirmClaude ? 'update-confirm' : 'update-modal',
        skipAutoUpdateCheck
      );
      return;
    }
    const win = this.mainWindow;
    if (!this.mainWindowReadyToShow) {
      if (skipAutoUpdateCheck) {
        this.suppressAutoCheckWindows.add(win);
      }
      this.sendOpenUpdateModalWhenReady(win, confirmClaude);
      return;
    }
    if (skipAutoUpdateCheck) {
      this.suppressAutoCheckWindows.add(win);
    }
    try {
      if (win.isMinimized()) {
        win.restore();
      }
      win.show();
      win.focus();
    } finally {
      this.suppressAutoCheckWindows.delete(win);
    }
    this.sendOpenUpdateModalWhenReady(win, confirmClaude);
  }

  public updateIcon(status: GuardStatus): void {
    const win = this.getWindow();
    if (win) {
      win.setIcon(createWindowAppIcon(status));
    }
  }

  public broadcastState(state: AppStateSnapshot): void {
    const win = this.getWindow();
    if (win && win.isVisible()) {
      win.webContents.send('guard:state-changed', state);
    }
  }

  public async waitForPostUpdateReady(timeoutMs?: number): Promise<void> {
    const win = this.getWindow();
    if (win) {
      await waitForPostUpdateRendererReady(win, timeoutMs);
    }
  }
}
