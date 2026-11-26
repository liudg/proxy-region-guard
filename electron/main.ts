import { app } from 'electron';
import * as path from 'node:path';
import { AlertPayload, AppStateSnapshot } from '../src/shared/types';
import { ClashMonitor } from './clash';
import { GuardCoordinator } from './guard';
import { PrivateProxyService } from './kernel';
import {
  configureAppUserData,
  ConfigStore,
  GeoIpService,
  reconcileAutoLaunchOnStartup,
  shouldStartSilentlyInTray,
  tryRelaunchAsWindowsAdmin,
} from './system';
import {
  AlertWindowManager,
  MainWindowManager,
  registerGuardIpcHandlers,
  TrayController,
} from './ui';
import { recordUpdateBootEvent, UpdaterService } from './updater';

configureAppUserData();
const IS_POST_UPDATE_BOOT = process.argv.some((a) => a.startsWith('--updated-from='));

let postUpdateHandshakeDone = false;
const handlePostUpdateBootFatal = (err: unknown) => {
  if (postUpdateHandshakeDone) return;
  console.error('[Updater Boot Fatal]', err);
  try {
    recordUpdateBootEvent(
      'boot-failed',
      err instanceof Error ? err.stack || err.message : String(err)
    );
  } finally {
    app.exit(1);
  }
};
if (IS_POST_UPDATE_BOOT) {
  process.on('uncaughtException', handlePostUpdateBootFatal);
  process.on('unhandledRejection', handlePostUpdateBootFatal);
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

let isQuitting = false;
let isBootstrapped = false;

let configStore: ConfigStore | undefined;
let geoIpService: GeoIpService | undefined;
let clashMonitor: ClashMonitor | undefined;
let coordinator: GuardCoordinator | undefined;
let privateProxies: PrivateProxyService | undefined;
let updaterService: UpdaterService | undefined;
let trayController: TrayController | undefined;

const alertWindows = new AlertWindowManager();
const mainWindows = new MainWindowManager({
  getConfigStore: () => configStore,
  getSnapshot: () => coordinator?.getSnapshot(),
  isBootstrapped: () => isBootstrapped,
  isQuitting: () => isQuitting,
  onWindowShownForUpdater: () => {
    void updaterService?.notifyWindowShown();
  },
  onEnsureTrayHealthyOnHide: () => {
    trayController?.ensureHealthyOnHideToTray();
  },
});

function broadcastState(state: AppStateSnapshot): void {
  trayController?.checkContinuityFast();
  trayController?.refreshFromState(state);
  mainWindows.broadcastState(state);
}

if (tryRelaunchAsWindowsAdmin()) {
  app.exit(0);
} else {
  const gotTheLock = app.requestSingleInstanceLock();
  if (!gotTheLock) {
    app.quit();
  } else {
    app.on('second-instance', () => {
      mainWindows.showMainWindow();
    });

    app
      .whenReady()
      .then(async () => {
        if (IS_POST_UPDATE_BOOT) {
          recordUpdateBootEvent('boot-start', '开始初始化主进程服务');
        }
        const appRoot = app.getAppPath();

        configStore = new ConfigStore();
        geoIpService = new GeoIpService();
        await geoIpService.init(appRoot);

        clashMonitor = new ClashMonitor();
        privateProxies = new PrivateProxyService(
          path.join(app.getPath('userData'), 'private-proxies'),
          path.join(
            app.isPackaged ? process.resourcesPath : path.join(appRoot, 'resources'),
            'mihomo'
          )
        );
        coordinator = new GuardCoordinator(
          configStore,
          geoIpService,
          clashMonitor,
          privateProxies
        );
        updaterService = new UpdaterService({
          configStore,
          probeEngine: coordinator,
          onQuitForUpdate: () => {
            isQuitting = true;
            trayController?.stopHealth();
            updaterService?.stop();
            coordinator?.stop();
            app.quit();
          },
        });
        trayController = new TrayController({
          configStore,
          coordinator,
          updaterService,
          mainWindows,
          isQuitting: () => isQuitting,
        });

        let wasClashProxyChannelReady = false;
        coordinator.on('state-changed', (state: AppStateSnapshot) => {
          broadcastState(state);
          const isClashProxyChannelReady = Boolean(
            (state.clashInfo.connected &&
              state.clashInfo.mixedPort &&
              state.clashInfo.mode !== 'direct') ||
              state.privateChannels.antigravity.phase === 'ready' ||
              state.privateChannels.claude.phase === 'ready'
          );
          if (!wasClashProxyChannelReady && isClashProxyChannelReady) {
            updaterService?.notifyNetworkReady(Date.now());
          }
          wasClashProxyChannelReady = isClashProxyChannelReady;

          if (state.status !== 'error' && state.lastProbe) {
            updaterService?.notifyNetworkReady(state.lastProbe.checkedAt);
          }
        });

        coordinator.on('trigger-alert', (payload: AlertPayload) => {
          alertWindows.showAlertPopup(payload);
        });

        coordinator.on('alert-recovered', (payload: AlertPayload) => {
          alertWindows.notifyAlertRecovered(payload);
        });

        registerGuardIpcHandlers({
          configStore,
          coordinator,
          updaterService,
          mainWindows,
          alertWindows,
        });
        isBootstrapped = true;

        if (!shouldStartSilentlyInTray(process.argv)) {
          mainWindows.createMainWindow(true);
        }
        trayController.setup();

        // 更新重启启动时，在主进程核心服务、离线库、托盘与本地主界面加载就绪后立即写出握手标记，
        // 避免被后续首次外网代理探测的慢网/断网超时（>12s）阻塞而误触发回滚
        if (IS_POST_UPDATE_BOOT && mainWindows.getWindow()) {
          recordUpdateBootEvent('renderer-wait', '等待主窗口加载');
          await mainWindows.waitForPostUpdateReady();
        }
        updaterService.initialize(process.argv);
        if (IS_POST_UPDATE_BOOT) {
          postUpdateHandshakeDone = true;
          process.removeListener('uncaughtException', handlePostUpdateBootFatal);
          process.removeListener('unhandledRejection', handlePostUpdateBootFatal);
        }

        try {
          await coordinator.start();
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error('[GuardCoordinator Start Error]', err);
          coordinator.recordExternalLog('danger', `启动初期代理探测异常：${msg}`);
        }

        // 延迟执行计划任务/注册表自启状态校验，避免同步子进程阻塞主窗口首屏渲染
        setTimeout(() => {
          if (isQuitting || !configStore || !coordinator) return;
          const curCfg = configStore.get();
          const effectiveAutoLaunch = reconcileAutoLaunchOnStartup(curCfg.autoLaunch);
          if (effectiveAutoLaunch !== curCfg.autoLaunch) {
            configStore.update({ autoLaunch: effectiveAutoLaunch });
            broadcastState(coordinator.getSnapshot());
          }
        }, 1500).unref?.();
      })
      .catch((err) => {
        console.error('[App Startup Fatal]', err);
        handlePostUpdateBootFatal(err);
      });
  }
}

app.on('before-quit', () => {
  isQuitting = true;
  trayController?.stopHealth();
  updaterService?.stop();
  coordinator?.stop();
  privateProxies?.stopMonitoring();
});

app.on('will-quit', () => {
  trayController?.destroy();
  trayController = undefined;
  updaterService?.stop();
  coordinator?.stop();
  privateProxies?.stopMonitoring();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin' && isQuitting) {
    app.quit();
  }
});
