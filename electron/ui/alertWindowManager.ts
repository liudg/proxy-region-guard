import { BrowserWindow, screen } from 'electron';
import { AlertPayload } from '../../src/shared/types';
import { getPreloadPath, loadRendererRoute } from './rendererLoader';

const ALERT_HIDDEN_DESTROY_DELAY_MS = 8000;

function estimateTextLines(text: string | undefined | null, cjkPerLine: number): number {
  if (!text) return 0;
  let units = 0;
  for (const ch of text) {
    units += ch.charCodeAt(0) > 255 ? 1 : 0.55;
  }
  return Math.max(1, Math.ceil(units / cjkPerLine));
}

function computeAlertWindowHeight(payload: AlertPayload): number {
  if (payload.source === 'system') {
    return Math.min(420, 170 + estimateTextLines(payload.errorDetail, 24) * 22);
  }
  const hasKilled = Boolean(payload.killedProcesses && payload.killedProcesses.length > 0);
  const hasErr = Boolean(payload.killError);
  const hasIp = Boolean(
    payload.actualIp || (payload.alertType === 'ip-change' && payload.expectedIp)
  );
  const isCompactBox =
    payload.alertType === 'disconnect' ||
    payload.alertType === 'unauthorized-launch' ||
    payload.alertType === 'verification-unavailable';

  let height = isCompactBox ? 228 : 254;
  if (hasIp) height += 22;
  if (hasKilled) height += 38;
  if (hasErr) height += 34;

  const ipMetaText =
    payload.alertType === 'ip-change'
      ? `IP 漂移：${payload.expectedIp || '未知'} → ${payload.actualIp || '未知'}`
      : payload.actualIp
      ? `当前出口 IP：${payload.actualIp}`
      : '';
  const extraIpLines = ipMetaText ? Math.max(0, estimateTextLines(ipMetaText, 27) - 1) : 0;
  const reasonText = `${payload.activeNode ? `[${payload.activeNode}] · ` : ''}${
    payload.triggerReason || ''
  }`;
  const extraReasonLines = Math.max(0, estimateTextLines(reasonText, 24) - 1);
  const extraKilledLines = hasKilled
    ? Math.max(
        0,
        estimateTextLines(`已强杀进程树：${payload.killedProcesses!.join(', ')}`, 25) - 1
      )
    : 0;
  const extraErrLines = hasErr
    ? Math.max(0, estimateTextLines(payload.killError, 27) - 1)
    : 0;

  const extraHeight =
    (extraIpLines + extraReasonLines + extraKilledLines + extraErrLines) * 17;
  return Math.min(420, height + extraHeight);
}

export class AlertWindowManager {
  private alertWindow: BrowserWindow | null = null;
  private latestAlertPayload: AlertPayload | null = null;
  private alertAutoCloseTimer: NodeJS.Timeout | null = null;
  private alertDestroyTimer: NodeJS.Timeout | null = null;
  private alertLoadHooked = false;
  private alertUserDragged = false;
  private suppressAlertMoveTrack = false;

  public getLatestPayload(): AlertPayload | null {
    return this.latestAlertPayload;
  }

  private clearDestroyTimer(): void {
    if (this.alertDestroyTimer) {
      clearTimeout(this.alertDestroyTimer);
      this.alertDestroyTimer = null;
    }
  }

  public hideAlertWindow(): void {
    this.alertUserDragged = false;
    if (this.alertWindow && !this.alertWindow.isDestroyed()) {
      this.alertWindow.hide();
      this.clearDestroyTimer();
      this.alertDestroyTimer = setTimeout(() => {
        this.alertDestroyTimer = null;
        if (
          this.alertWindow &&
          !this.alertWindow.isDestroyed() &&
          !this.alertWindow.isVisible()
        ) {
          this.alertWindow.destroy();
          this.alertWindow = null;
        }
      }, ALERT_HIDDEN_DESTROY_DELAY_MS);
      this.alertDestroyTimer.unref?.();
    }
  }

  private resizeAlertWindow(win: BrowserWindow, width: number, height: number): void {
    const [curW, curH] = win.getSize();
    if (curW === width && curH === height) return;
    this.suppressAlertMoveTrack = true;
    win.setResizable(true);
    win.setSize(width, height, false);
    win.setResizable(false);
    this.suppressAlertMoveTrack = false;
  }

  private positionAlertWindow(win: BrowserWindow): void {
    const primary = screen.getPrimaryDisplay();
    const workArea = primary.workArea;
    const [w, h] = win.getSize();
    const margin = 18;
    const x = Math.round(workArea.x + workArea.width - w - margin);
    const y = Math.round(workArea.y + workArea.height - h - margin);
    this.suppressAlertMoveTrack = true;
    win.setPosition(x, y, false);
    this.suppressAlertMoveTrack = false;
  }

  private ensureAlertWindow(): BrowserWindow {
    this.clearDestroyTimer();
    if (this.alertWindow && !this.alertWindow.isDestroyed()) {
      return this.alertWindow;
    }

    this.alertLoadHooked = false;
    this.alertUserDragged = false;

    const win = new BrowserWindow({
      width: 420,
      height: 276,
      frame: false,
      transparent: true,
      resizable: false,
      movable: true,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      alwaysOnTop: true,
      skipTaskbar: true,
      show: false,
      hasShadow: false,
      webPreferences: {
        preload: getPreloadPath(),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        spellcheck: false,
      },
    });
    this.alertWindow = win;

    win.setAlwaysOnTop(true, 'screen-saver');
    this.positionAlertWindow(win);
    loadRendererRoute(win, 'alert');

    win.on('move', () => {
      if (!this.suppressAlertMoveTrack && this.alertWindow?.isVisible()) {
        this.alertUserDragged = true;
      }
    });

    win.on('closed', () => {
      this.clearDestroyTimer();
      if (this.alertWindow === win) {
        this.alertWindow = null;
        this.alertLoadHooked = false;
        this.alertUserDragged = false;
      }
    });

    return win;
  }

  public showAlertPopup(payload: AlertPayload): void {
    this.clearDestroyTimer();
    if (this.alertAutoCloseTimer) {
      clearTimeout(this.alertAutoCloseTimer);
      this.alertAutoCloseTimer = null;
    }

    this.latestAlertPayload = payload;
    const win = this.ensureAlertWindow();

    const flushLatestAlert = () => {
      this.alertLoadHooked = false;
      if (win.isDestroyed() || !this.latestAlertPayload) return;

      const currentPayload = this.latestAlertPayload;
      const wasVisible = win.isVisible();
      this.resizeAlertWindow(win, 420, computeAlertWindowHeight(currentPayload));
      if (!wasVisible || !this.alertUserDragged) {
        this.positionAlertWindow(win);
      }
      win.setAlwaysOnTop(true, 'screen-saver');
      win.webContents.send('guard:alert-data', currentPayload);
      if (!wasVisible) {
        win.showInactive();
      }
    };

    if (win.webContents.isLoading()) {
      if (!this.alertLoadHooked) {
        this.alertLoadHooked = true;
        win.webContents.once('did-finish-load', flushLatestAlert);
      }
    } else {
      flushLatestAlert();
    }
  }

  public notifyAlertRecovered(payload: AlertPayload): void {
    if (
      !this.alertWindow ||
      this.alertWindow.isDestroyed() ||
      !this.alertWindow.isVisible() ||
      this.latestAlertPayload?.source !== payload.source
    ) {
      return;
    }
    this.latestAlertPayload = payload;
    this.resizeAlertWindow(this.alertWindow, 420, 276);
    if (!this.alertUserDragged) {
      this.positionAlertWindow(this.alertWindow);
    }
    this.alertWindow.webContents.send('guard:alert-data', payload);

    if (this.alertAutoCloseTimer) {
      clearTimeout(this.alertAutoCloseTimer);
    }
    this.alertAutoCloseTimer = setTimeout(() => {
      this.hideAlertWindow();
    }, 2200);
  }
}
