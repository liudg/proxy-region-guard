import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  Menu,
  screen,
  Tray,
} from 'electron';
import { execFileSync } from 'node:child_process';
import * as path from 'node:path';
import { AlertPayload, AppConfig, AppStateSnapshot } from '../src/shared/types';
import { isValidIsoCountryCode } from '../src/shared/countries';
import { isWindowsLocaleMatchingCountry } from '../src/shared/timezones';
import { ConfigStore } from './configStore';
import { GeoIpService } from './geoipService';
import { ClashMonitor } from './clashMonitor';
import { ProbeEngine } from './probeEngine';
import { PrivateProxyService } from './privateKernel';
import { createStatusTrayIcon, createWindowAppIcon } from './trayIcon';
import {
  applyAutoLaunchSetting,
  isLaunchedFromAutoStart,
  reconcileAutoLaunchOnStartup,
  shouldStartSilentlyInTray,
} from './autoLaunch';
import { TrayHealthManager } from './trayHealth';
import {
  quoteWindowsCommandLine,
  resolveWindowsPowerShellExe,
  UpdaterService,
} from './updaterService';

const ELEVATED_RELAUNCH_FLAG = '--elevated-relaunch';
const IS_POST_UPDATE_BOOT = process.argv.some((a) => a.startsWith('--updated-from='));

let postUpdateHandshakeDone = false;
const handlePostUpdateBootFatal = (err: unknown) => {
  if (postUpdateHandshakeDone) return;
  console.error('[Updater Boot Fatal]', err);
  app.exit(1);
};
if (IS_POST_UPDATE_BOOT) {
  process.on('uncaughtException', handlePostUpdateBootFatal);
  process.on('unhandledRejection', handlePostUpdateBootFatal);
}

function isRunningAsWindowsAdmin(): boolean {
  if (process.platform !== 'win32') return true;
  try {
    execFileSync('fltmc.exe', [], { stdio: 'ignore', windowsHide: true, timeout: 1500 });
    return true;
  } catch {
    try {
      execFileSync('net.exe', ['session'], { stdio: 'ignore', windowsHide: true, timeout: 1500 });
      return true;
    } catch {
      return false;
    }
  }
}

function tryRelaunchAsWindowsAdmin(): boolean {
  if (
    process.platform !== 'win32' ||
    process.argv.includes(ELEVATED_RELAUNCH_FLAG) ||
    isRunningAsWindowsAdmin()
  ) {
    return false;
  }

  try {
    const appDir = path.resolve(app.getAppPath());
    const userArgs = (app.isPackaged ? process.argv.slice(1) : [appDir, ...process.argv.slice(2)]).filter(
      (a) => a !== ELEVATED_RELAUNCH_FLAG
    );
    userArgs.push(ELEVATED_RELAUNCH_FLAG);

    const psScript = [
      '$ProgressPreference = "SilentlyContinue"',
      '$ErrorActionPreference = "Stop"',
      '$psi = New-Object System.Diagnostics.ProcessStartInfo',
      '$psi.FileName = $env:GUARD_ELEVATE_EXE',
      'if ($env:GUARD_ELEVATE_CWD) { $psi.WorkingDirectory = $env:GUARD_ELEVATE_CWD }',
      '$psi.UseShellExecute = $true',
      '$psi.Verb = "runas"',
      'if ($env:GUARD_ELEVATE_ARG_LINE) { $psi.Arguments = $env:GUARD_ELEVATE_ARG_LINE }',
      '[System.Diagnostics.Process]::Start($psi) | Out-Null',
    ].join('\r\n');
    const encodedElevate = Buffer.from(psScript, 'utf16le').toString('base64');

    execFileSync(
      resolveWindowsPowerShellExe(),
      ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-EncodedCommand', encodedElevate],
      {
        stdio: 'ignore',
        windowsHide: true,
        timeout: 15000,
        env: {
          ...process.env,
          GUARD_ELEVATE_EXE: process.execPath,
          GUARD_ELEVATE_CWD: process.cwd(),
          GUARD_ELEVATE_ARG_LINE: quoteWindowsCommandLine(userArgs),
        },
      }
    );
    return true;
  } catch {
    return false;
  }
}

if (process.platform === 'win32') {
  app.setAppUserModelId('com.antigravity.proxy-region-guard');
}

// 限制 V8 老生代堆上限并禁用无需使用的 Chromium 后台特性，兼顾大订阅 YAML 解析安全与低内存占用
app.commandLine.appendSwitch('js-flags', '--max-old-space-size=256');
app.commandLine.appendSwitch(
  'disable-features',
  'SpareRendererForSitePerProcess,WinDelaySpellcheckServiceInit,WinRetrieveSuggestionsOnlyOnDemand,CalculateNativeWinOcclusion,HardwareMediaKeyHandling,MediaSessionService'
);
app.commandLine.appendSwitch('disable-spell-checking');
app.commandLine.appendSwitch('renderer-process-limit', '2');

const MAIN_HIDDEN_DESTROY_DELAY_MS = 4000;
const ALERT_HIDDEN_DESTROY_DELAY_MS = 8000;

let mainWindow: BrowserWindow | null = null;
let alertWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let trayHealth: TrayHealthManager | null = null;
let isQuitting = false;
let isBootstrapped = false;

let configStore!: ConfigStore;
let geoIpService!: GeoIpService;
let clashMonitor!: ClashMonitor;
let probeEngine!: ProbeEngine;
let privateProxies!: PrivateProxyService;
let updaterService!: UpdaterService;

let latestAlertPayload: AlertPayload | null = null;
let mainDestroyTimer: NodeJS.Timeout | null = null;
let alertAutoCloseTimer: NodeJS.Timeout | null = null;
let alertDestroyTimer: NodeJS.Timeout | null = null;
let alertLoadHooked = false;
let alertUserDragged = false;
let suppressAlertMoveTrack = false;
let lastTrayMenuSignature = '';
let latestTrayTooltip = '代理地区卫士 · 正在初始化...';
let mainWindowReadyToShow = false;
const suppressAutoCheckWindows = new WeakSet<BrowserWindow>();

function clearMainDestroyTimer(): void {
  if (mainDestroyTimer) {
    clearTimeout(mainDestroyTimer);
    mainDestroyTimer = null;
  }
}

function clearAlertDestroyTimer(): void {
  if (alertDestroyTimer) {
    clearTimeout(alertDestroyTimer);
    alertDestroyTimer = null;
  }
}

function hideMainWindowToTray(): void {
  trayHealth?.ensureHealthyOnHideToTray();
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.hide();
  clearMainDestroyTimer();
  mainDestroyTimer = setTimeout(() => {
    mainDestroyTimer = null;
    if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.isVisible()) {
      mainWindow.destroy();
      mainWindow = null;
    }
  }, MAIN_HIDDEN_DESTROY_DELAY_MS);
  mainDestroyTimer.unref?.();
}

function getPreloadPath(): string {
  return path.join(__dirname, 'preload.js');
}

function loadRendererRoute(win: BrowserWindow, hash?: string): void {
  const handleLoadError = (err: unknown) => {
    const code = (err as { code?: string })?.code || '';
    const msg = err instanceof Error ? err.message : String(err);
    if (code === 'ERR_ABORTED' || msg.includes('ERR_ABORTED') || msg.includes('(-3)')) {
      return;
    }
    console.error('[Renderer Load Error]', err);
  };
  const devUrl = process.env.VITE_DEV_SERVER_URL;
  if (devUrl) {
    const fullUrl = hash ? `${devUrl}#${hash}` : devUrl;
    void win.loadURL(fullUrl).catch(handleLoadError);
  } else {
    const htmlPath = path.join(__dirname, '../dist/index.html');
    void win.loadFile(htmlPath, hash ? { hash } : undefined).catch(handleLoadError);
  }
}

function waitForPostUpdateRendererReady(
  win: BrowserWindow,
  timeoutMs = 4500
): Promise<void> {
  if (win.isDestroyed()) return Promise.resolve();
  const wc = win.webContents;
  if (!wc.isLoading() && wc.getURL() !== '') {
    return Promise.resolve();
  }

  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      clearTimeout(timer);
      if (!win.isDestroyed()) {
        win.removeListener('closed', onClosed);
        wc.removeListener('did-finish-load', onFinish);
        wc.removeListener('did-fail-load', onFail);
        wc.removeListener('render-process-gone', onGone);
      }
    };
    const onFinish = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve();
    };
    const onClosed = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve();
    };
    const onFail = (
      _event: Electron.Event,
      errorCode: number,
      errorDescription: string,
      _validatedURL: string,
      isMainFrame: boolean
    ) => {
      if (!isMainFrame || errorCode === -3 || settled) return;
      settled = true;
      cleanup();
      reject(new Error(`主窗口页面加载失败 (${errorCode}): ${errorDescription}`));
    };
    const onGone = (
      _event: Electron.Event,
      details: Electron.RenderProcessGoneDetails
    ) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error(`渲染进程启动异常退出 (${details.reason})`));
    };
    const timer = setTimeout(onFinish, timeoutMs);
    timer.unref?.();

    win.once('closed', onClosed);
    wc.once('did-finish-load', onFinish);
    wc.on('did-fail-load', onFail);
    wc.once('render-process-gone', onGone);
  });
}

function createMainWindow(
  revealOnReady = true,
  initialHash?: string,
  skipInitialAutoCheck = false
): void {
  clearMainDestroyTimer();
  mainWindowReadyToShow = !revealOnReady;
  let suppressFirstShowAutoCheck = skipInitialAutoCheck;
  const curStatus = probeEngine ? probeEngine.getSnapshot().status : 'unset';
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
  mainWindow = win;

  loadRendererRoute(win, initialHash);

  if (revealOnReady) {
    let revealed = false;
    let fallbackTimer: NodeJS.Timeout | null = null;

    const reveal = () => {
      if (revealed) return;
      revealed = true;
      mainWindowReadyToShow = true;
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
    mainWindowReadyToShow = true;
    clearMainDestroyTimer();
    if (probeEngine && !win.isDestroyed()) {
      win.webContents.send('guard:state-changed', probeEngine.getSnapshot());
    }
    const skipAuto = suppressFirstShowAutoCheck || suppressAutoCheckWindows.has(win);
    suppressFirstShowAutoCheck = false;
    suppressAutoCheckWindows.delete(win);
    if (!skipAuto) {
      void updaterService?.notifyWindowShown();
    }
  });

  win.on('restore', () => {
    if (!suppressAutoCheckWindows.has(win)) {
      void updaterService?.notifyWindowShown();
    }
  });

  win.on('close', (e) => {
    if (!isQuitting && configStore?.get().closeToTray) {
      e.preventDefault();
      hideMainWindowToTray();
    }
  });

  win.on('closed', () => {
    clearMainDestroyTimer();
    if (mainWindow === win) {
      mainWindow = null;
      mainWindowReadyToShow = false;
    }
  });
}

function showMainWindow(opts: { skipAutoUpdateCheck?: boolean } = {}): void {
  if (!isBootstrapped) return;
  clearMainDestroyTimer();
  if (!mainWindow || mainWindow.isDestroyed()) {
    createMainWindow(true, undefined, Boolean(opts.skipAutoUpdateCheck));
    return;
  }
  const win = mainWindow;
  if (!mainWindowReadyToShow) {
    if (opts.skipAutoUpdateCheck) {
      suppressAutoCheckWindows.add(win);
    }
    return;
  }
  const wasHiddenOrMinimized = !win.isVisible() || win.isMinimized();
  if (opts.skipAutoUpdateCheck) {
    suppressAutoCheckWindows.add(win);
  }
  try {
    if (win.isMinimized()) {
      win.restore();
    }
    win.show();
    win.focus();
  } finally {
    suppressAutoCheckWindows.delete(win);
  }
  if (!wasHiddenOrMinimized && !opts.skipAutoUpdateCheck) {
    void updaterService?.notifyWindowShown();
  }
}

function sendOpenUpdateModalWhenReady(win: BrowserWindow, confirmClaude: boolean): void {
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

function openUpdateModalInMainWindow(
  confirmClaude = false,
  skipAutoUpdateCheck = false
): void {
  if (!isBootstrapped) return;
  clearMainDestroyTimer();
  if (!mainWindow || mainWindow.isDestroyed()) {
    createMainWindow(
      true,
      confirmClaude ? 'update-confirm' : 'update-modal',
      skipAutoUpdateCheck
    );
    return;
  }
  const win = mainWindow;
  if (!mainWindowReadyToShow) {
    if (skipAutoUpdateCheck) {
      suppressAutoCheckWindows.add(win);
    }
    sendOpenUpdateModalWhenReady(win, confirmClaude);
    return;
  }
  if (skipAutoUpdateCheck) {
    suppressAutoCheckWindows.add(win);
  }
  try {
    if (win.isMinimized()) {
      win.restore();
    }
    win.show();
    win.focus();
  } finally {
    suppressAutoCheckWindows.delete(win);
  }
  sendOpenUpdateModalWhenReady(win, confirmClaude);
}

function hideAlertWindow(): void {
  alertUserDragged = false;
  if (alertWindow && !alertWindow.isDestroyed()) {
    alertWindow.hide();
    clearAlertDestroyTimer();
    alertDestroyTimer = setTimeout(() => {
      alertDestroyTimer = null;
      if (alertWindow && !alertWindow.isDestroyed() && !alertWindow.isVisible()) {
        alertWindow.destroy();
        alertWindow = null;
      }
    }, ALERT_HIDDEN_DESTROY_DELAY_MS);
    alertDestroyTimer.unref?.();
  }
}

function resizeAlertWindow(win: BrowserWindow, width: number, height: number): void {
  const [curW, curH] = win.getSize();
  if (curW === width && curH === height) return;
  suppressAlertMoveTrack = true;
  win.setResizable(true);
  win.setSize(width, height, false);
  win.setResizable(false);
  suppressAlertMoveTrack = false;
}

function estimateTextLines(text: string | undefined | null, cjkPerLine: number): number {
  if (!text) return 0;
  let units = 0;
  for (const ch of text) {
    units += ch.charCodeAt(0) > 255 ? 1 : 0.55;
  }
  return Math.max(1, Math.ceil(units / cjkPerLine));
}

function computeAlertWindowHeight(payload: AlertPayload): number {
  if (payload.source === 'system') return Math.min(420, 170 + estimateTextLines(payload.errorDetail, 24) * 22);
  const hasKilled = Boolean(payload.killedProcesses && payload.killedProcesses.length > 0);
  const hasErr = Boolean(payload.killError);
  const hasIp = Boolean(payload.actualIp || (payload.alertType === 'ip-change' && payload.expectedIp));
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
  const reasonText = `${payload.activeNode ? `[${payload.activeNode}] · ` : ''}${payload.triggerReason || ''}`;
  const extraReasonLines = Math.max(0, estimateTextLines(reasonText, 24) - 1);
  const extraKilledLines = hasKilled
    ? Math.max(0, estimateTextLines(`已强杀进程树：${payload.killedProcesses!.join(', ')}`, 25) - 1)
    : 0;
  const extraErrLines = hasErr
    ? Math.max(0, estimateTextLines(payload.killError, 27) - 1)
    : 0;

  const extraHeight = (extraIpLines + extraReasonLines + extraKilledLines + extraErrLines) * 17;
  return Math.min(420, height + extraHeight);
}

function ensureAlertWindow(): BrowserWindow {
  clearAlertDestroyTimer();
  if (alertWindow && !alertWindow.isDestroyed()) {
    return alertWindow;
  }

  alertLoadHooked = false;
  alertUserDragged = false;

  alertWindow = new BrowserWindow({
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

  alertWindow.setAlwaysOnTop(true, 'screen-saver');
  positionAlertWindow(alertWindow);
  loadRendererRoute(alertWindow, 'alert');

  alertWindow.on('move', () => {
    if (!suppressAlertMoveTrack && alertWindow?.isVisible()) {
      alertUserDragged = true;
    }
  });

  alertWindow.on('closed', () => {
    clearAlertDestroyTimer();
    alertWindow = null;
    alertLoadHooked = false;
    alertUserDragged = false;
  });

  return alertWindow;
}

function positionAlertWindow(win: BrowserWindow): void {
  const primary = screen.getPrimaryDisplay();
  const workArea = primary.workArea;
  const [w, h] = win.getSize();
  const margin = 18;
  const x = Math.round(workArea.x + workArea.width - w - margin);
  const y = Math.round(workArea.y + workArea.height - h - margin);
  suppressAlertMoveTrack = true;
  win.setPosition(x, y, false);
  suppressAlertMoveTrack = false;
}

function showCustomAlertPopup(payload: AlertPayload): void {
  clearAlertDestroyTimer();
  if (alertAutoCloseTimer) {
    clearTimeout(alertAutoCloseTimer);
    alertAutoCloseTimer = null;
  }

  latestAlertPayload = payload;
  const win = ensureAlertWindow();

  const flushLatestAlert = () => {
    alertLoadHooked = false;
    if (win.isDestroyed() || !latestAlertPayload) return;

    const currentPayload = latestAlertPayload;
    const wasVisible = win.isVisible();
    resizeAlertWindow(win, 420, computeAlertWindowHeight(currentPayload));
    if (!wasVisible || !alertUserDragged) {
      positionAlertWindow(win);
    }
    win.setAlwaysOnTop(true, 'screen-saver');
    win.webContents.send('guard:alert-data', currentPayload);
    if (!wasVisible) {
      win.showInactive();
    }
  };

  if (win.webContents.isLoading()) {
    if (!alertLoadHooked) {
      alertLoadHooked = true;
      win.webContents.once('did-finish-load', flushLatestAlert);
    }
  } else {
    flushLatestAlert();
  }
}

function notifyAlertRecovered(payload: AlertPayload): void {
  if (
    !alertWindow ||
    alertWindow.isDestroyed() ||
    !alertWindow.isVisible() ||
    latestAlertPayload?.source !== payload.source
  ) {
    return;
  }
  latestAlertPayload = payload;
  resizeAlertWindow(alertWindow, 420, 276);
  if (!alertUserDragged) {
    positionAlertWindow(alertWindow);
  }
  alertWindow.webContents.send('guard:alert-data', payload);

  if (alertAutoCloseTimer) {
    clearTimeout(alertAutoCloseTimer);
  }
  alertAutoCloseTimer = setTimeout(() => {
    hideAlertWindow();
  }, 2200);
}

function setupTray(): void {
  const initialIcon = createStatusTrayIcon('checking');
  tray = new Tray(initialIcon);
  latestTrayTooltip = '代理地区卫士 · 正在初始化...';
  tray.setToolTip(latestTrayTooltip);

  tray.on('click', () => {
    if (mainWindow && !mainWindow.isDestroyed() && mainWindow.isVisible() && mainWindow.isFocused()) {
      hideMainWindowToTray();
    } else {
      showMainWindow();
    }
  });

  tray.on('double-click', () => {
    showMainWindow();
  });

  refreshTrayFromState(probeEngine.getSnapshot());

  trayHealth?.stop();
  trayHealth = new TrayHealthManager({
    isAutoStart: isLaunchedFromAutoStart(process.argv),
    getTooltip: () => latestTrayTooltip,
    onSyncTray: (healed) => {
      if (!tray || isQuitting) return;
      if (healed) {
        lastTrayMenuSignature = '';
        refreshTrayFromState(probeEngine.getSnapshot());
      } else {
        tray.setToolTip(latestTrayTooltip);
      }
    },
    onHealed: () => {
      probeEngine?.recordExternalLog(
        'info',
        '检测到系统托盘延迟就绪或资源管理器重启，已自动恢复任务栏托盘图标'
      );
    },
    onStartupRetriesExhausted: (lastRes) => {
      if (
        isQuitting ||
        !shouldStartSilentlyInTray(process.argv) ||
        !lastRes.probeOk ||
        lastRes.iconAlive ||
        !lastRes.desktopInteractive
      ) {
        return;
      }
      if (!mainWindow || mainWindow.isDestroyed()) {
        probeEngine?.recordExternalLog(
          'warn',
          '系统托盘长时间未就绪，已自动打开主控制面板以防后台不可达'
        );
        showMainWindow();
      }
    },
  });
  trayHealth.start();
}

function refreshTrayFromState(state: AppStateSnapshot): void {
  if (!tray) return;

  const icon = createStatusTrayIcon(state.status);
  tray.setImage(icon);
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.setIcon(createWindowAppIcon(state.status));
  }

  const curText = state.lastProbe
    ? `${state.lastProbe.countryName} (${state.lastProbe.countryCode}) · ${state.lastProbe.ip}`
    : state.lastError || '检测中...';

  const clashChannelText = state.clashInfo.connected
    ? `Clash选中: ${
        state.clashInfo.activeProfileName
          ? `${state.clashInfo.activeProfileName} / `
          : ''
      }${state.clashInfo.activeNode || state.clashInfo.mode}`
    : 'Clash: 未连接';

  const profilePrefix =
    state.config.selectedClashProfileName || state.privateChannels.claude.profileName;
  const effectiveClaudeIp =
    state.claudeState.lockedSessionIp ||
    state.claudeState.nodeProbe?.claudeTraceIp ||
    state.claudeState.nodeProbe?.ip;
  const claudeProbeSuffix = state.claudeState.nodeProbe
    ? ` (${state.claudeState.nodeProbe.countryCode} · ${
        state.claudeState.lockedSessionIp ? `🔒${effectiveClaudeIp}` : effectiveClaudeIp
      })`
    : state.claudeState.lockedSessionIp
    ? ` (🔒${state.claudeState.lockedSessionIp})`
    : '';
  const nodeText = state.config.selectedClashNode
    ? `Claude节点: ${profilePrefix ? `${profilePrefix} / ` : ''}${state.config.selectedClashNode}${claudeProbeSuffix}`
    : '';

  const agProfilePrefix =
    state.config.antigravityClashProfileName || state.privateChannels.antigravity.profileName;
  const agNodeText = state.config.antigravityClashNode
    ? `Antigravity节点: ${agProfilePrefix ? `${agProfilePrefix} / ` : ''}${state.config.antigravityClashNode}`
    : '';

  const claudeText = state.claudeState.running
    ? 'Claude: 🟢 受控运行中'
    : state.claudeState.canLaunch
    ? 'Claude: 就绪可启动'
    : 'Claude: 待校验';

  const agText = state.antigravityState.running
    ? state.antigravityState.proxiedSession
      ? 'Antigravity: 🟢 代理运行中'
      : 'Antigravity: 🟡 外部运行中'
    : state.antigravityState.canLaunch
    ? 'Antigravity: 就绪可启动'
    : 'Antigravity: 待选择节点';

  const isMonitorLocaleMatched = state.lastProbe
    ? isWindowsLocaleMatchingCountry(
        state.winLocale.timeZoneId,
        state.winLocale.regionCode,
        state.lastProbe.countryCode
      )
    : false;

  const statusLabelMap: Record<AppStateSnapshot['status'], string> = {
    ok: isMonitorLocaleMatched
      ? '🟢 代理与时区一致 (正常)'
      : '🟢 代理通道正常 (未锁定保护地区)',
    mismatch: '🔴 代理或时区不一致！',
    error: '🔴 代理连接异常！',
    unset: '🔵 待选择节点或保护地区',
    checking: '⏳ 正在检测...',
  };

  const updateTooltipText =
    state.updateState.hasUpdate && state.updateState.latestVersion
      ? state.updateState.status === 'downloaded'
        ? `✨ 新版 v${state.updateState.latestVersion} 已就绪 (可重启更新)`
        : `⬇️ 发现新版本 v${state.updateState.latestVersion}`
      : '';

  const tooltip = [
    `代理地区卫士 · ${statusLabelMap[state.status]}`,
    updateTooltipText,
    clashChannelText,
    `当前出口: ${curText}`,
    nodeText,
    agNodeText,
    `系统区域: ${state.winLocale.regionName} (${state.winLocale.regionCode})`,
    agText,
    claudeText,
  ]
    .filter(Boolean)
    .join('\n');

  latestTrayTooltip = tooltip;
  tray.setToolTip(tooltip);

  const probeValid = Boolean(
    state.lastProbe && isValidIsoCountryCode(state.lastProbe.countryCode)
  );
  const claudeValid = Boolean(
    state.claudeState.proxyCountryCode &&
      isValidIsoCountryCode(state.claudeState.proxyCountryCode)
  );
  const canSyncLocale = Boolean(
    state.config.defaultCountryCode || probeValid || claudeValid
  );
  const syncTargetName =
    state.config.defaultCountryName ||
    (probeValid ? state.lastProbe?.countryName : '') ||
    (claudeValid ? state.claudeState.proxyCountryName : '') ||
    '';

  const claudeActiveForUpdate =
    state.claudeState.running || state.claudeState.authorizedSession;
  const dlProgressBucket =
    state.updateState.status === 'downloading'
      ? String(Math.floor((state.updateState.progressPercent ?? 0) / 10))
      : '';

  const menuSig = [
    state.status,
    clashChannelText,
    curText,
    nodeText,
    agNodeText,
    state.winLocale.regionName,
    claudeText,
    agText,
    state.claudeState.canLaunch ? '1' : '0',
    state.claudeState.running ? '1' : '0',
    claudeActiveForUpdate ? '1' : '0',
    state.antigravityState.canLaunch ? '1' : '0',
    state.antigravityState.running ? '1' : '0',
    state.antigravityState.proxiedSession ? '1' : '0',
    canSyncLocale ? syncTargetName : '',
    state.isSyncingLocale ? '1' : '0',
    state.config.autoLaunch ? '1' : '0',
    state.updateState.status,
    state.updateState.hasUpdate ? '1' : '0',
    state.updateState.latestVersion || '',
    dlProgressBucket,
  ].join('|');

  if (menuSig === lastTrayMenuSignature) {
    return;
  }
  lastTrayMenuSignature = menuSig;

  const menu = Menu.buildFromTemplate([
    {
      label: statusLabelMap[state.status],
      enabled: false,
    },
    {
      label: clashChannelText,
      enabled: false,
    },
    ...(nodeText
      ? [
          {
            label: nodeText,
            enabled: false,
          },
        ]
      : []),
    ...(agNodeText
      ? [
          {
            label: agNodeText,
            enabled: false,
          },
        ]
      : []),
    {
      label: `当前: ${curText}`,
      enabled: false,
    },
    {
      label: `系统区域: ${state.winLocale.regionName} (${state.winLocale.regionCode})`,
      enabled: false,
    },
    { type: 'separator' },
    {
      label: state.antigravityState.running
        ? state.antigravityState.proxiedSession
          ? '🟢 Antigravity 代理运行中 (点击重启)'
          : '🔄 重启 Antigravity 以注入专属代理'
        : state.antigravityState.canLaunch
        ? `🚀 启动 Antigravity (${state.config.antigravityClashNode})`
        : `🚀 启动 Antigravity (${state.antigravityState.launchHint || '待配置节点'})`,
      enabled: state.antigravityState.canLaunch,
      click: () => {
        void probeEngine.launchAntigravityFromGuard();
      },
    },
    ...(state.antigravityState.running
      ? [
          {
            label: '🛑 关闭 Antigravity 进程',
            click: () => {
              void probeEngine.terminateAntigravityManually();
            },
          },
        ]
      : []),
    { type: 'separator' },
    {
      label: state.claudeState.running
        ? '🟢 Claude 正在受控运行 (点击重新激活)'
        : state.claudeState.canLaunch
        ? '🤖 安全启动 Claude Desktop'
        : `🔒 启动 Claude (${state.claudeState.launchBlockReason || '条件未满足'})`,
      enabled: state.claudeState.canLaunch,
      click: () => {
        void probeEngine.launchClaudeFromGuard();
      },
    },
    ...(state.claudeState.running
      ? [
          {
            label: '🛑 立即终止 Claude 进程',
            click: () => {
              void probeEngine.terminateClaudeManually();
            },
          },
        ]
      : []),
    { type: 'separator' },
    {
      label: '立即重新检测',
      click: () => {
        void probeEngine.checkNow('托盘菜单手动检测');
      },
    },
    {
      label: syncTargetName
        ? `一键同步系统时区与区域 (${syncTargetName})`
        : '一键同步系统时区与区域',
      enabled: canSyncLocale && !state.isSyncingLocale,
      click: () => {
        void probeEngine.syncSystemLocaleToDefault();
      },
    },
    {
      label: '还原默认中国时区与区域',
      enabled: !state.isSyncingLocale,
      click: () => {
        void probeEngine.restoreDefaultChinaLocale();
      },
    },
    { type: 'separator' },
    {
      label: '开机自动启动',
      type: 'checkbox',
      checked: state.config.autoLaunch,
      click: (menuItem) => {
        const actual = applyAutoLaunchSetting(menuItem.checked);
        configStore.update({ autoLaunch: actual });
        probeEngine.evaluateStatusOnly(
          actual ? '已开启开机自动启动' : '已关闭开机自动启动'
        );
      },
    },
    {
      label:
        state.updateState.status === 'applying'
          ? '🚀 正在重启并应用更新...'
          : state.updateState.status === 'downloading'
          ? `⏳ 正在下载新版本${
              state.updateState.latestVersion ? ` v${state.updateState.latestVersion}` : ''
            } (${state.updateState.progressPercent ?? 0}%)`
          : state.updateState.status === 'checking'
          ? '🔄 正在检查版本更新...'
          : state.updateState.status === 'downloaded' && state.updateState.latestVersion
          ? claudeActiveForUpdate
            ? `✨ 新版本 v${state.updateState.latestVersion} 已就绪 (点击确认更新)`
            : `✨ 立即重启更新至 v${state.updateState.latestVersion}`
          : state.updateState.hasUpdate && state.updateState.latestVersion
          ? `⬇️ 发现新版本 v${state.updateState.latestVersion} (点击查看)`
          : `检查版本更新 (v${state.updateState.currentVersion})`,
      enabled:
        state.updateState.status !== 'checking' &&
        state.updateState.status !== 'downloading' &&
        state.updateState.status !== 'applying',
      click: () => {
        if (state.updateState.status === 'downloaded') {
          if (claudeActiveForUpdate) {
            openUpdateModalInMainWindow(true, true);
            return;
          }
          void updaterService.applyDownloadedUpdate(false).then((res) => {
            if (!res.ok) {
              const needClaudeConfirm =
                res.state.claudeState.running || res.state.claudeState.authorizedSession;
              openUpdateModalInMainWindow(needClaudeConfirm, true);
            }
          });
          return;
        }
        if (state.updateState.hasUpdate) {
          openUpdateModalInMainWindow(false);
          return;
        }
        openUpdateModalInMainWindow(false, true);
        void updaterService.checkForUpdates({ silent: false });
      },
    },
    {
      label: '打开主控制面板',
      click: () => showMainWindow(),
    },
    {
      label: '关闭管理界面（后台继续运行）',
      click: () => {
        mainWindow?.destroy();
        mainWindow = null;
      },
    },
  ]);

  tray.setContextMenu(menu);
}

function broadcastState(state: AppStateSnapshot): void {
  trayHealth?.checkContinuityFast();
  refreshTrayFromState(state);
  if (mainWindow && !mainWindow.isDestroyed() && mainWindow.isVisible()) {
    mainWindow.webContents.send('guard:state-changed', state);
  }
}

function registerIpcHandlers(): void {
  const privateChannel = (value: unknown): 'claude' | 'antigravity' => {
    if (value !== 'claude' && value !== 'antigravity') throw new Error('私有代理通道无效');
    return value;
  };
  ipcMain.handle('guard:apply-node-update', (_event, channel: unknown) => probeEngine.applyNodeUpdate(privateChannel(channel)));
  ipcMain.handle('guard:restart-private-kernel', (_event, channel: unknown) => probeEngine.restartPrivateKernel(privateChannel(channel)));
  ipcMain.handle('guard:get-state', () => probeEngine.getSnapshot());

  ipcMain.handle('guard:check-now', (_e, reason?: string) =>
    probeEngine.checkNow(reason || '手动点击刷新检测')
  );

  ipcMain.handle('guard:set-default-current', () => {
    const snap = probeEngine.getSnapshot();
    if (snap.lastProbe && isValidIsoCountryCode(snap.lastProbe.countryCode)) {
      configStore.update({
        defaultCountryCode: snap.lastProbe.countryCode,
        defaultCountryName: snap.lastProbe.countryName,
      });
      return probeEngine.evaluateStatusOnly(
        `已将 [${snap.lastProbe.countryName}] 设为默认保护地区`
      );
    }
    return snap;
  });

  ipcMain.handle('guard:set-default-region', (_e, code: string | null) => {
    configStore.update({ defaultCountryCode: code });
    return probeEngine.evaluateStatusOnly(
      code ? `手动修改默认地区为 ${code}` : '已清除默认地区限制'
    );
  });

  ipcMain.handle(
    'guard:select-clash-node',
    (_e, nodeName: string | null, profileUid?: string | null) =>
      probeEngine.selectClashNode(nodeName, profileUid)
  );

  ipcMain.handle('guard:probe-claude-node', (_e, reason?: string) =>
    probeEngine.probeClaudeNodeNow(reason || 'Claude 专栏手动重测')
  );

  ipcMain.handle('guard:launch-claude', () => probeEngine.launchClaudeFromGuard());

  ipcMain.handle('guard:terminate-claude', () => probeEngine.terminateClaudeManually());

  ipcMain.handle('guard:browse-claude-exe', async () => {
    const win = mainWindow && !mainWindow.isDestroyed() ? mainWindow : undefined;
    const options: Electron.OpenDialogOptions = {
      title: '选择 Claude Desktop 可执行文件 (Claude.exe)',
      filters: [{ name: '可执行文件 (*.exe)', extensions: ['exe'] }],
      properties: ['openFile'],
    };
    const res = win ? await dialog.showOpenDialog(win, options) : await dialog.showOpenDialog(options);
    if (!res.canceled && res.filePaths.length > 0) {
      configStore.update({ claudeExePath: res.filePaths[0] });
      await probeEngine.refreshClaudeInstallDetection();
    }
    return probeEngine.getSnapshot();
  });

  // Antigravity 启动器专栏 IPC
  ipcMain.handle(
    'guard:select-antigravity-node',
    (_e, nodeName: string | null, profileUid?: string | null) =>
      probeEngine.selectAntigravityClashNode(nodeName, profileUid)
  );

  ipcMain.handle('guard:probe-antigravity-node', () =>
    probeEngine.probeAntigravityNodeNow()
  );

  ipcMain.handle('guard:launch-antigravity', () =>
    probeEngine.launchAntigravityFromGuard()
  );

  ipcMain.handle('guard:terminate-antigravity', () =>
    probeEngine.terminateAntigravityManually()
  );

  ipcMain.handle('guard:browse-antigravity-exe', async () => {
    const win = mainWindow && !mainWindow.isDestroyed() ? mainWindow : undefined;
    const options: Electron.OpenDialogOptions = {
      title: '选择 Antigravity 可执行文件 (Antigravity.exe)',
      filters: [{ name: '可执行文件 (*.exe)', extensions: ['exe'] }],
      properties: ['openFile'],
    };
    const res = win ? await dialog.showOpenDialog(win, options) : await dialog.showOpenDialog(options);
    if (!res.canceled && res.filePaths.length > 0) {
      configStore.update({ antigravityExePath: res.filePaths[0] });
      await probeEngine.refreshAntigravityInstallDetection();
    }
    return probeEngine.getSnapshot();
  });

  ipcMain.handle('guard:check-for-updates', () =>
    updaterService.checkForUpdates({ silent: false })
  );

  ipcMain.handle('guard:download-update', () => updaterService.downloadUpdate());

  ipcMain.handle('guard:apply-update', (_e, allowTerminateClaude?: boolean) =>
    updaterService.applyDownloadedUpdate(Boolean(allowTerminateClaude))
  );

  ipcMain.handle('guard:open-release-page', () =>
    updaterService.openReleasePageInBrowser()
  );

  ipcMain.handle('guard:update-config', async (_e, partial: Partial<AppConfig>) => {
    const prevCfg = configStore.get();
    let nextCfg = await probeEngine.updateConfig(partial);

    if (!nextCfg.monitorAlertEnabled && latestAlertPayload?.source === 'monitor') {
      hideAlertWindow();
    }

    if (prevCfg.autoLaunch !== nextCfg.autoLaunch) {
      const actualAutoLaunch = applyAutoLaunchSetting(nextCfg.autoLaunch);
      if (actualAutoLaunch !== nextCfg.autoLaunch) {
        nextCfg = configStore.update({ autoLaunch: actualAutoLaunch });
      }
    }

    if (prevCfg.claudeExePath !== nextCfg.claudeExePath) {
      await probeEngine.refreshClaudeInstallDetection();
    }

    if (prevCfg.antigravityExePath !== nextCfg.antigravityExePath) {
      await probeEngine.refreshAntigravityInstallDetection();
    }

    if (prevCfg.heartbeatIntervalSec !== nextCfg.heartbeatIntervalSec) {
      probeEngine.restartHeartbeatTimer();
    }

    if (prevCfg.autoCheckUpdates !== nextCfg.autoCheckUpdates) {
      updaterService?.handleAutoCheckConfigChanged(nextCfg.autoCheckUpdates);
    }

    const agChanged =
      prevCfg.antigravityClashNode !== nextCfg.antigravityClashNode ||
      prevCfg.antigravityClashProfileUid !== nextCfg.antigravityClashProfileUid ||
      prevCfg.antigravityDedicatedPort !== nextCfg.antigravityDedicatedPort;

    const claudeChanged =
      prevCfg.selectedClashNode !== nextCfg.selectedClashNode ||
      prevCfg.selectedClashProfileUid !== nextCfg.selectedClashProfileUid ||
      prevCfg.dedicatedProxyPort !== nextCfg.dedicatedProxyPort;

    if (agChanged || claudeChanged) {
      return probeEngine.getSnapshot();
    }

    const proxyCfgChanged =
      prevCfg.proxyMode !== nextCfg.proxyMode ||
      prevCfg.manualProxy.protocol !== nextCfg.manualProxy.protocol ||
      prevCfg.manualProxy.host !== nextCfg.manualProxy.host ||
      prevCfg.manualProxy.port !== nextCfg.manualProxy.port ||
      prevCfg.customProbeUrl !== nextCfg.customProbeUrl;

    if (proxyCfgChanged) {
      return probeEngine.checkNow('代理连接配置已更改');
    }

    return probeEngine.evaluateStatusOnly();
  });

  ipcMain.handle('guard:clear-logs', () => probeEngine.clearLogs());

  ipcMain.handle(
    'guard:sync-locale',
    (_e, targetSource?: 'monitor' | 'claude') =>
      probeEngine.syncSystemLocaleToDefault(targetSource)
  );

  ipcMain.handle('guard:restore-locale', () => probeEngine.restoreDefaultChinaLocale());

  ipcMain.handle('guard:get-alert-data', () => latestAlertPayload);

  ipcMain.handle('guard:accept-current-from-alert', () => {
    if (latestAlertPayload?.source !== 'claude') {
      const snap = probeEngine.getSnapshot();
      if (snap.lastProbe && isValidIsoCountryCode(snap.lastProbe.countryCode)) {
        configStore.update({
          defaultCountryCode: snap.lastProbe.countryCode,
          defaultCountryName: snap.lastProbe.countryName,
        });
        probeEngine.evaluateStatusOnly(
          `已在警告窗确认将 [${snap.lastProbe.countryName}] 设为新默认地区`
        );
      }
    }
    hideAlertWindow();
  });

  ipcMain.on('window:minimize-main', () => {
    mainWindow?.minimize();
  });

  ipcMain.on('window:close-main', () => {
    if (configStore.get().closeToTray) {
      hideMainWindowToTray();
    } else {
      mainWindow?.destroy();
      mainWindow = null;
    }
  });

  ipcMain.on('window:open-main-from-alert', () => {
    hideAlertWindow();
    showMainWindow();
  });

  ipcMain.on('window:dismiss-alert', () => {
    hideAlertWindow();
  });
}

if (tryRelaunchAsWindowsAdmin()) {
  app.exit(0);
} else {
  const gotTheLock = app.requestSingleInstanceLock();
  if (!gotTheLock) {
    app.quit();
  } else {
    app.on('second-instance', () => {
      showMainWindow();
    });

    app.whenReady().then(async () => {
      const appRoot = app.getAppPath();

      configStore = new ConfigStore();

      geoIpService = new GeoIpService();
      await geoIpService.init(appRoot);

      clashMonitor = new ClashMonitor();
      privateProxies = new PrivateProxyService(path.join(app.getPath('userData'), 'private-proxies'),
        path.join(app.isPackaged ? process.resourcesPath : path.join(appRoot, 'resources'), 'mihomo'));
      probeEngine = new ProbeEngine(configStore, geoIpService, clashMonitor, privateProxies);
      updaterService = new UpdaterService({
        configStore,
        probeEngine,
        onQuitForUpdate: () => {
          isQuitting = true;
          trayHealth?.stop();
          updaterService?.stop();
          probeEngine?.stop();
          app.quit();
        },
      });

      let wasClashProxyChannelReady = false;
      probeEngine.on('state-changed', (state: AppStateSnapshot) => {
        broadcastState(state);
        const isClashProxyChannelReady = Boolean(
          (state.clashInfo.connected && state.clashInfo.mixedPort && state.clashInfo.mode !== 'direct') ||
            state.privateChannels.antigravity.phase === 'ready' || state.privateChannels.claude.phase === 'ready'
        );
        if (!wasClashProxyChannelReady && isClashProxyChannelReady) {
          updaterService?.notifyNetworkReady(Date.now());
        }
        wasClashProxyChannelReady = isClashProxyChannelReady;

        if (state.status !== 'error' && state.lastProbe) {
          updaterService?.notifyNetworkReady(state.lastProbe.checkedAt);
        }
      });

      probeEngine.on('trigger-alert', (payload: AlertPayload) => {
        showCustomAlertPopup(payload);
      });

      probeEngine.on('alert-recovered', (payload: AlertPayload) => {
        notifyAlertRecovered(payload);
      });

      registerIpcHandlers();
      isBootstrapped = true;

      if (!shouldStartSilentlyInTray(process.argv)) {
        createMainWindow(true);
      }
      setupTray();

      // 更新重启启动时，在主进程核心服务、离线库、托盘与本地主界面加载就绪后立即写出握手标记，
      // 避免被后续首次外网代理探测的慢网/断网超时（>12s）阻塞而误触发回滚
      if (IS_POST_UPDATE_BOOT && mainWindow && !mainWindow.isDestroyed()) {
        await waitForPostUpdateRendererReady(mainWindow);
      }
      updaterService.initialize(process.argv);
      if (IS_POST_UPDATE_BOOT) {
        postUpdateHandshakeDone = true;
        process.removeListener('uncaughtException', handlePostUpdateBootFatal);
        process.removeListener('unhandledRejection', handlePostUpdateBootFatal);
      }

      try {
        await probeEngine.start();
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error('[ProbeEngine Start Error]', err);
        probeEngine.recordExternalLog('danger', `启动初期代理探测异常：${msg}`);
      }

      // 延迟执行计划任务/注册表自启状态校验，避免同步子进程阻塞主窗口首屏渲染
      setTimeout(() => {
        if (isQuitting) return;
        const curCfg = configStore.get();
        const effectiveAutoLaunch = reconcileAutoLaunchOnStartup(curCfg.autoLaunch);
        if (effectiveAutoLaunch !== curCfg.autoLaunch) {
          configStore.update({ autoLaunch: effectiveAutoLaunch });
          broadcastState(probeEngine.getSnapshot());
        }
      }, 1500).unref?.();
    }).catch((err) => {
      console.error('[App Startup Fatal]', err);
      handlePostUpdateBootFatal(err);
    });
  }
}

app.on('before-quit', () => {
  isQuitting = true;
  trayHealth?.stop();
  updaterService?.stop();
  probeEngine?.stop();
});

app.on('will-quit', () => {
  trayHealth?.stop();
  updaterService?.stop();
  probeEngine?.stop();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin' && isQuitting) {
    app.quit();
  }
});
