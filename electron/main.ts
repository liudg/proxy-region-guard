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
import { createStatusTrayIcon, createWindowAppIcon } from './trayIcon';
import {
  applyAutoLaunchSetting,
  reconcileAutoLaunchOnStartup,
} from './autoLaunch';

const ELEVATED_RELAUNCH_FLAG = '--elevated-relaunch';

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
      '$ErrorActionPreference = "Stop"',
      '$exe = $env:GUARD_ELEVATE_EXE',
      '$cwd = $env:GUARD_ELEVATE_CWD',
      '$argList = @(ConvertFrom-Json $env:GUARD_ELEVATE_ARGS)',
      'Start-Process -FilePath $exe -WorkingDirectory $cwd -ArgumentList $argList -Verb RunAs',
    ].join('; ');

    execFileSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', psScript],
      {
        stdio: 'ignore',
        windowsHide: true,
        timeout: 15000,
        env: {
          ...process.env,
          GUARD_ELEVATE_EXE: process.execPath,
          GUARD_ELEVATE_CWD: process.cwd(),
          GUARD_ELEVATE_ARGS: JSON.stringify(userArgs),
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
let isQuitting = false;
let isBootstrapped = false;

let configStore!: ConfigStore;
let geoIpService!: GeoIpService;
let clashMonitor!: ClashMonitor;
let probeEngine!: ProbeEngine;

let latestAlertPayload: AlertPayload | null = null;
let mainDestroyTimer: NodeJS.Timeout | null = null;
let alertAutoCloseTimer: NodeJS.Timeout | null = null;
let alertDestroyTimer: NodeJS.Timeout | null = null;
let alertLoadHooked = false;
let alertUserDragged = false;
let suppressAlertMoveTrack = false;
let lastTrayMenuSignature = '';

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
  const devUrl = process.env.VITE_DEV_SERVER_URL;
  if (devUrl) {
    const fullUrl = hash ? `${devUrl}#${hash}` : devUrl;
    void win.loadURL(fullUrl);
  } else {
    const htmlPath = path.join(__dirname, '../dist/index.html');
    void win.loadFile(htmlPath, hash ? { hash } : undefined);
  }
}

function createMainWindow(revealOnReady = true): void {
  clearMainDestroyTimer();
  const curStatus = probeEngine ? probeEngine.getSnapshot().status : 'unset';
  const icon = createWindowAppIcon(curStatus);

  mainWindow = new BrowserWindow({
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

  loadRendererRoute(mainWindow);

  if (revealOnReady) {
    let revealed = false;
    let fallbackTimer: NodeJS.Timeout | null = null;

    const reveal = () => {
      if (revealed) return;
      revealed = true;
      if (fallbackTimer) {
        clearTimeout(fallbackTimer);
        fallbackTimer = null;
      }
      if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.isVisible()) {
        mainWindow.show();
        mainWindow.focus();
      }
    };

    mainWindow.once('ready-to-show', reveal);
    fallbackTimer = setTimeout(reveal, 600);
  }

  mainWindow.on('show', () => {
    clearMainDestroyTimer();
    if (probeEngine && mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('guard:state-changed', probeEngine.getSnapshot());
    }
  });

  mainWindow.on('close', (e) => {
    if (!isQuitting && configStore?.get().closeToTray) {
      e.preventDefault();
      hideMainWindowToTray();
    }
  });

  mainWindow.on('closed', () => {
    clearMainDestroyTimer();
    mainWindow = null;
  });
}

function showMainWindow(): void {
  if (!isBootstrapped) return;
  clearMainDestroyTimer();
  if (!mainWindow || mainWindow.isDestroyed()) {
    createMainWindow(true);
    return;
  }
  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }
  mainWindow.show();
  mainWindow.focus();
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
    latestAlertPayload?.source === 'claude'
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
  tray.setToolTip('代理地区卫士 · 正在初始化...');

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
    state.config.selectedClashProfileName || state.clashInfo.boundProfileName;
  const effectiveClaudeIp =
    state.claudeState.lockedSessionIp ||
    state.claudeState.nodeProbe?.claudeTraceIp ||
    state.claudeState.nodeProbe?.ip;
  const claudeProbeSuffix = state.claudeState.nodeProbe
    ? ` (${state.claudeState.nodeProbe.countryCode} · ${
        state.claudeState.lockedSessionIp ? `🔒${effectiveClaudeIp}` : effectiveClaudeIp
      })`
    : '';
  const nodeText = state.config.selectedClashNode
    ? `Claude节点: ${profilePrefix ? `${profilePrefix} / ` : ''}${state.config.selectedClashNode}${claudeProbeSuffix}`
    : '';

  const agProfilePrefix =
    state.config.antigravityClashProfileName || state.clashInfo.antigravityBoundProfileName;
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

  const tooltip = [
    `代理地区卫士 · ${statusLabelMap[state.status]}`,
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
    state.antigravityState.canLaunch ? '1' : '0',
    state.antigravityState.running ? '1' : '0',
    state.antigravityState.proxiedSession ? '1' : '0',
    canSyncLocale ? syncTargetName : '',
    state.isSyncingLocale ? '1' : '0',
    state.config.autoLaunch ? '1' : '0',
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
      label: '打开主控制面板',
      click: () => showMainWindow(),
    },
    {
      label: state.claudeState.running
        ? '完全退出程序 (将终止 Claude，保持 Antigravity 运行)'
        : '完全退出程序 (保持 Antigravity 运行)',
      click: () => {
        isQuitting = true;
        probeEngine?.stop();
        app.quit();
      },
    },
  ]);

  tray.setContextMenu(menu);
}

function broadcastState(state: AppStateSnapshot): void {
  refreshTrayFromState(state);
  if (mainWindow && !mainWindow.isDestroyed() && mainWindow.isVisible()) {
    mainWindow.webContents.send('guard:state-changed', state);
  }
}

function registerIpcHandlers(): void {
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

  ipcMain.handle('guard:update-config', async (_e, partial: Partial<AppConfig>) => {
    const prevCfg = configStore.get();
    let nextCfg = await probeEngine.updateConfig(partial);

    if (!nextCfg.monitorAlertEnabled && latestAlertPayload?.source !== 'claude') {
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
      isQuitting = true;
      probeEngine?.stop();
      app.quit();
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
      probeEngine = new ProbeEngine(configStore, geoIpService, clashMonitor);

      probeEngine.on('state-changed', (state: AppStateSnapshot) => {
        broadcastState(state);
      });

      probeEngine.on('trigger-alert', (payload: AlertPayload) => {
        showCustomAlertPopup(payload);
      });

      probeEngine.on('alert-recovered', (payload: AlertPayload) => {
        notifyAlertRecovered(payload);
      });

      registerIpcHandlers();
      isBootstrapped = true;

      createMainWindow(true);
      setupTray();

      await probeEngine.start();

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
    });
  }
}

app.on('before-quit', () => {
  isQuitting = true;
  probeEngine?.stop();
});

app.on('will-quit', () => {
  probeEngine?.stop();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin' && isQuitting) {
    app.quit();
  }
});
