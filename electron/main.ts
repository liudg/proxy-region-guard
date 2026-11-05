import {
  app,
  BrowserWindow,
  ipcMain,
  Menu,
  screen,
  Tray,
} from 'electron';
import * as path from 'node:path';
import { AlertPayload, AppConfig, AppStateSnapshot } from '../src/shared/types';
import { ConfigStore } from './configStore';
import { GeoIpService } from './geoipService';
import { ClashMonitor } from './clashMonitor';
import { ProbeEngine } from './probeEngine';
import { createStatusTrayIcon, createWindowAppIcon } from './trayIcon';
import {
  applyAutoLaunchSetting,
  isLaunchedFromAutoStart,
  reconcileAutoLaunchOnStartup,
} from './autoLaunch';

if (process.platform === 'win32') {
  app.setAppUserModelId('com.antigravity.proxy-region-guard');
}

let mainWindow: BrowserWindow | null = null;
let alertWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let isQuitting = false;

let configStore!: ConfigStore;
let geoIpService!: GeoIpService;
let clashMonitor!: ClashMonitor;
let probeEngine!: ProbeEngine;

let latestAlertPayload: AlertPayload | null = null;
let alertAutoCloseTimer: NodeJS.Timeout | null = null;

const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    showMainWindow();
  });
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
  const icon = createWindowAppIcon('unset');

  mainWindow = new BrowserWindow({
    width: 510,
    height: 750,
    minWidth: 460,
    minHeight: 640,
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
      sandbox: false,
    },
  });

  loadRendererRoute(mainWindow);

  if (revealOnReady) {
    const reveal = () => {
      if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.isVisible()) {
        mainWindow.show();
        mainWindow.focus();
      }
    };

    mainWindow.once('ready-to-show', reveal);
    setTimeout(reveal, 600);
  }

  mainWindow.on('close', (e) => {
    if (!isQuitting && configStore.get().closeToTray) {
      e.preventDefault();
      mainWindow?.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function showMainWindow(): void {
  if (!mainWindow || mainWindow.isDestroyed()) {
    createMainWindow();
    return;
  }
  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }
  mainWindow.show();
  mainWindow.focus();
}

function ensureAlertWindow(): BrowserWindow {
  if (alertWindow && !alertWindow.isDestroyed()) {
    positionAlertWindow(alertWindow);
    return alertWindow;
  }

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
      sandbox: false,
    },
  });

  alertWindow.setAlwaysOnTop(true, 'screen-saver');
  positionAlertWindow(alertWindow);
  loadRendererRoute(alertWindow, 'alert');

  alertWindow.on('closed', () => {
    alertWindow = null;
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
  win.setPosition(x, y, false);
}

function showCustomAlertPopup(payload: AlertPayload): void {
  if (alertAutoCloseTimer) {
    clearTimeout(alertAutoCloseTimer);
    alertAutoCloseTimer = null;
  }

  latestAlertPayload = payload;
  const win = ensureAlertWindow();

  const hasKilledInfo =
    Boolean(payload.killedProcesses && payload.killedProcesses.length > 0) ||
    Boolean(payload.killError);
  const targetHeight = hasKilledInfo ? 318 : 276;

  const sendAndShow = () => {
    if (win.isDestroyed()) return;
    win.setSize(420, targetHeight, false);
    positionAlertWindow(win);
    win.setAlwaysOnTop(true, 'screen-saver');
    win.webContents.send('guard:alert-data', payload);
    if (!win.isVisible()) {
      // showInactive 既能强置顶浮现，又不会抢夺用户正在输入的键盘焦点
      win.showInactive();
    }
  };

  if (win.webContents.isLoading()) {
    win.webContents.once('did-finish-load', sendAndShow);
  } else {
    sendAndShow();
  }
}

function notifyAlertRecovered(payload: AlertPayload): void {
  if (!alertWindow || alertWindow.isDestroyed() || !alertWindow.isVisible()) {
    return;
  }
  latestAlertPayload = payload;
  alertWindow.setSize(420, 276, false);
  positionAlertWindow(alertWindow);
  alertWindow.webContents.send('guard:alert-data', payload);

  if (alertAutoCloseTimer) {
    clearTimeout(alertAutoCloseTimer);
  }
  alertAutoCloseTimer = setTimeout(() => {
    if (alertWindow && !alertWindow.isDestroyed()) {
      alertWindow.hide();
    }
  }, 2200);
}

function setupTray(): void {
  const initialIcon = createStatusTrayIcon('checking', 32);
  tray = new Tray(initialIcon);
  tray.setToolTip('代理地区卫士 · 正在初始化...');

  tray.on('click', () => {
    if (mainWindow && mainWindow.isVisible() && mainWindow.isFocused()) {
      mainWindow.hide();
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

  const icon = createStatusTrayIcon(state.status, 32);
  tray.setImage(icon);
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.setIcon(createWindowAppIcon(state.status));
  }

  const curText = state.lastProbe
    ? `${state.lastProbe.countryName} (${state.lastProbe.countryCode}) · ${state.lastProbe.ip}`
    : state.lastError || '检测中...';

  const defText = state.config.defaultCountryCode
    ? `${state.config.defaultCountryName} (${state.config.defaultCountryCode})`
    : '未设置';

  const statusLabelMap: Record<AppStateSnapshot['status'], string> = {
    ok: '🟢 地区一致 (正常)',
    mismatch: '🔴 地区异常变更！',
    error: '🔴 代理连接异常！',
    unset: '🔵 未设默认地区',
    checking: '⏳ 正在检测...',
  };

  const tooltip = [
    `代理地区卫士 · ${statusLabelMap[state.status]}`,
    `当前出口: ${curText}`,
    `默认地区: ${defText}`,
    `系统区域: ${state.winLocale.regionName} (${state.winLocale.regionCode})`,
    state.clashInfo.connected ? `Clash节点: ${state.clashInfo.activeNode || state.clashInfo.mode}` : '',
  ]
    .filter(Boolean)
    .join('\n');

  tray.setToolTip(tooltip);

  const menu = Menu.buildFromTemplate([
    {
      label: statusLabelMap[state.status],
      enabled: false,
    },
    {
      label: `当前: ${curText}`,
      enabled: false,
    },
    {
      label: `默认: ${defText}`,
      enabled: false,
    },
    {
      label: `系统区域: ${state.winLocale.regionName}`,
      enabled: false,
    },
    { type: 'separator' },
    {
      label: '立即重新检测',
      click: () => {
        void probeEngine.checkNow('托盘菜单手动检测');
      },
    },
    {
      label: state.lastProbe
        ? `将当前 [${state.lastProbe.countryName}] 设为默认`
        : '将当前地区设为默认',
      enabled: Boolean(state.lastProbe),
      click: () => {
        if (state.lastProbe) {
          configStore.update({
            defaultCountryCode: state.lastProbe.countryCode,
            defaultCountryName: state.lastProbe.countryName,
          });
          probeEngine.evaluateStatusOnly('通过托盘将当前地区设为默认');
        }
      },
    },
    {
      label: state.config.defaultCountryName
        ? `一键同步系统时区与区域 (${state.config.defaultCountryName})`
        : '一键同步系统时区与区域 (需先设默认)',
      enabled: Boolean(state.config.defaultCountryCode) && !state.isSyncingLocale,
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
      label: '完全退出程序',
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);

  tray.setContextMenu(menu);
}

function broadcastState(state: AppStateSnapshot): void {
  refreshTrayFromState(state);
  if (mainWindow && !mainWindow.isDestroyed()) {
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
    if (snap.lastProbe && snap.lastProbe.countryCode !== 'UNKNOWN') {
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

  ipcMain.handle('guard:update-config', async (_e, partial: Partial<AppConfig>) => {
    const prevCfg = configStore.get();
    let nextCfg = configStore.update(partial);

    if (prevCfg.autoLaunch !== nextCfg.autoLaunch) {
      const actualAutoLaunch = applyAutoLaunchSetting(nextCfg.autoLaunch);
      if (actualAutoLaunch !== nextCfg.autoLaunch) {
        nextCfg = configStore.update({ autoLaunch: actualAutoLaunch });
      }
    }

    if (prevCfg.heartbeatIntervalSec !== nextCfg.heartbeatIntervalSec) {
      probeEngine.restartHeartbeatTimer();
    }

    const clashCfgChanged =
      prevCfg.clashAutoDetect !== nextCfg.clashAutoDetect ||
      prevCfg.clashCustomController.host !== nextCfg.clashCustomController.host ||
      prevCfg.clashCustomController.port !== nextCfg.clashCustomController.port ||
      prevCfg.clashCustomController.secret !== nextCfg.clashCustomController.secret;

    if (clashCfgChanged) {
      await clashMonitor.forceReconnect();
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

  ipcMain.handle('guard:sync-locale', () => probeEngine.syncSystemLocaleToDefault());

  ipcMain.handle('guard:restore-locale', () => probeEngine.restoreDefaultChinaLocale());

  ipcMain.handle('guard:get-alert-data', () => latestAlertPayload);

  ipcMain.handle('guard:accept-current-from-alert', () => {
    const snap = probeEngine.getSnapshot();
    if (snap.lastProbe && snap.lastProbe.countryCode !== 'UNKNOWN') {
      configStore.update({
        defaultCountryCode: snap.lastProbe.countryCode,
        defaultCountryName: snap.lastProbe.countryName,
      });
      probeEngine.evaluateStatusOnly(
        `已在警告窗确认将 [${snap.lastProbe.countryName}] 设为新默认地区`
      );
    }
    if (alertWindow && !alertWindow.isDestroyed()) {
      alertWindow.hide();
    }
  });

  ipcMain.on('window:minimize-main', () => {
    mainWindow?.minimize();
  });

  ipcMain.on('window:close-main', () => {
    if (configStore.get().closeToTray) {
      mainWindow?.hide();
    } else {
      isQuitting = true;
      app.quit();
    }
  });

  ipcMain.on('window:open-main-from-alert', () => {
    if (alertWindow && !alertWindow.isDestroyed()) {
      alertWindow.hide();
    }
    showMainWindow();
  });

  ipcMain.on('window:dismiss-alert', () => {
    if (alertWindow && !alertWindow.isDestroyed()) {
      alertWindow.hide();
    }
  });
}

app.whenReady().then(async () => {
  const appRoot = app.getAppPath();

  configStore = new ConfigStore();
  const initialCfg = configStore.get();
  const effectiveAutoLaunch = reconcileAutoLaunchOnStartup(initialCfg.autoLaunch);
  if (effectiveAutoLaunch !== initialCfg.autoLaunch) {
    configStore.update({ autoLaunch: effectiveAutoLaunch });
  }

  geoIpService = new GeoIpService();
  await geoIpService.init(appRoot);

  clashMonitor = new ClashMonitor(() => configStore.get());
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
  const startHiddenInTray = isLaunchedFromAutoStart() && configStore.get().closeToTray;
  createMainWindow(!startHiddenInTray);
  setupTray();

  // 预先后台初始化隐藏警告窗，使首次告警实现 0ms 瞬时弹出
  ensureAlertWindow();

  await probeEngine.start();
});

app.on('before-quit', () => {
  isQuitting = true;
  probeEngine?.stop();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin' && isQuitting) {
    app.quit();
  }
});
