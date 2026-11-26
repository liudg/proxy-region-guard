import { dialog, ipcMain } from 'electron';
import { AppConfig } from '../../src/shared/types';
import { isValidIsoCountryCode } from '../../src/shared/countries';
import { GuardCoordinator } from '../guard';
import { applyAutoLaunchSetting, ConfigStore } from '../system';
import { UpdaterService } from '../updater';
import { AlertWindowManager } from './alertWindowManager';
import { MainWindowManager } from './mainWindowManager';

export interface IpcHandlersDeps {
  configStore: ConfigStore;
  coordinator: GuardCoordinator;
  updaterService: UpdaterService;
  mainWindows: MainWindowManager;
  alertWindows: AlertWindowManager;
}

export function registerGuardIpcHandlers(deps: IpcHandlersDeps): void {
  const { configStore, coordinator, updaterService, mainWindows, alertWindows } = deps;

  const privateChannel = (value: unknown): 'claude' | 'antigravity' => {
    if (value !== 'claude' && value !== 'antigravity') {
      throw new Error('私有代理通道无效');
    }
    return value;
  };

  ipcMain.handle('guard:apply-node-update', (_event, channel: unknown) =>
    coordinator.applyNodeUpdate(privateChannel(channel))
  );
  ipcMain.handle('guard:restart-private-kernel', (_event, channel: unknown) =>
    coordinator.restartPrivateKernel(privateChannel(channel))
  );
  ipcMain.handle('guard:get-state', () => coordinator.getSnapshot());

  ipcMain.handle('guard:check-now', (_e, reason?: string) =>
    coordinator.checkNow(reason || '手动点击刷新检测')
  );

  ipcMain.handle('guard:set-default-current', () => {
    const snap = coordinator.getSnapshot();
    if (snap.lastProbe && isValidIsoCountryCode(snap.lastProbe.countryCode)) {
      configStore.update({
        defaultCountryCode: snap.lastProbe.countryCode,
        defaultCountryName: snap.lastProbe.countryName,
      });
      return coordinator.evaluateStatusOnly(
        `已将 [${snap.lastProbe.countryName}] 设为默认保护地区`
      );
    }
    return snap;
  });

  ipcMain.handle('guard:set-default-region', (_e, code: string | null) => {
    configStore.update({ defaultCountryCode: code });
    return coordinator.evaluateStatusOnly(
      code ? `手动修改默认地区为 ${code}` : '已清除默认地区限制'
    );
  });

  ipcMain.handle(
    'guard:select-clash-node',
    (_e, nodeName: string | null, profileUid?: string | null) =>
      coordinator.selectClashNode(nodeName, profileUid)
  );

  ipcMain.handle('guard:probe-claude-node', (_e, reason?: string) =>
    coordinator.probeClaudeNodeNow(reason || 'Claude 专栏手动重测')
  );

  ipcMain.handle('guard:launch-claude', () => coordinator.launchClaudeFromGuard());

  ipcMain.handle('guard:terminate-claude', () => coordinator.terminateClaudeManually());

  ipcMain.handle('guard:browse-claude-exe', async () => {
    const win = mainWindows.getWindow() ?? undefined;
    const options: Electron.OpenDialogOptions = {
      title: '选择 Claude Desktop 可执行文件 (Claude.exe)',
      filters: [{ name: '可执行文件 (*.exe)', extensions: ['exe'] }],
      properties: ['openFile'],
    };
    const res = win
      ? await dialog.showOpenDialog(win, options)
      : await dialog.showOpenDialog(options);
    if (!res.canceled && res.filePaths.length > 0) {
      configStore.update({ claudeExePath: res.filePaths[0] });
      await coordinator.refreshClaudeInstallDetection();
    }
    return coordinator.getSnapshot();
  });

  // Antigravity 启动器专栏 IPC
  ipcMain.handle(
    'guard:select-antigravity-node',
    (_e, nodeName: string | null, profileUid?: string | null) =>
      coordinator.selectAntigravityClashNode(nodeName, profileUid)
  );

  ipcMain.handle('guard:probe-antigravity-node', () =>
    coordinator.probeAntigravityNodeNow()
  );

  ipcMain.handle('guard:launch-antigravity', () =>
    coordinator.launchAntigravityFromGuard()
  );

  ipcMain.handle('guard:terminate-antigravity', () =>
    coordinator.terminateAntigravityManually()
  );

  ipcMain.handle('guard:browse-antigravity-exe', async () => {
    const win = mainWindows.getWindow() ?? undefined;
    const options: Electron.OpenDialogOptions = {
      title: '选择 Antigravity 可执行文件 (Antigravity.exe)',
      filters: [{ name: '可执行文件 (*.exe)', extensions: ['exe'] }],
      properties: ['openFile'],
    };
    const res = win
      ? await dialog.showOpenDialog(win, options)
      : await dialog.showOpenDialog(options);
    if (!res.canceled && res.filePaths.length > 0) {
      configStore.update({ antigravityExePath: res.filePaths[0] });
      await coordinator.refreshAntigravityInstallDetection();
    }
    return coordinator.getSnapshot();
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

  ipcMain.handle(
    'guard:update-config',
    async (
      _e,
      partial: Partial<AppConfig>,
      options?: { confirmTerminateClaude?: boolean }
    ) => {
      const prevCfg = configStore.get();
      let nextCfg = await coordinator.updateConfig(partial, options);

      if (
        !nextCfg.monitorAlertEnabled &&
        alertWindows.getLatestPayload()?.source === 'monitor'
      ) {
        alertWindows.hideAlertWindow();
      }

      if (prevCfg.autoLaunch !== nextCfg.autoLaunch) {
        const actualAutoLaunch = applyAutoLaunchSetting(nextCfg.autoLaunch);
        if (actualAutoLaunch !== nextCfg.autoLaunch) {
          nextCfg = configStore.update({ autoLaunch: actualAutoLaunch });
        }
      }

      if (prevCfg.claudeExePath !== nextCfg.claudeExePath) {
        await coordinator.refreshClaudeInstallDetection();
      }

      if (prevCfg.antigravityExePath !== nextCfg.antigravityExePath) {
        await coordinator.refreshAntigravityInstallDetection();
      }

      if (prevCfg.heartbeatIntervalSec !== nextCfg.heartbeatIntervalSec) {
        coordinator.restartHeartbeatTimer();
      }

      if (prevCfg.autoCheckUpdates !== nextCfg.autoCheckUpdates) {
        updaterService.handleAutoCheckConfigChanged(nextCfg.autoCheckUpdates);
      }

      const agChanged =
        prevCfg.antigravityClashNode !== nextCfg.antigravityClashNode ||
        prevCfg.antigravityClashProfileUid !== nextCfg.antigravityClashProfileUid ||
        prevCfg.antigravityDedicatedPort !== nextCfg.antigravityDedicatedPort;

      const claudeChanged =
        prevCfg.selectedClashNode !== nextCfg.selectedClashNode ||
        prevCfg.selectedClashProfileUid !== nextCfg.selectedClashProfileUid ||
        prevCfg.dedicatedProxyPort !== nextCfg.dedicatedProxyPort ||
        prevCfg.claudeForceIpv4 !== nextCfg.claudeForceIpv4;

      if (agChanged || claudeChanged) {
        return coordinator.getSnapshot();
      }

      const proxyCfgChanged =
        prevCfg.proxyMode !== nextCfg.proxyMode ||
        prevCfg.manualProxy.protocol !== nextCfg.manualProxy.protocol ||
        prevCfg.manualProxy.host !== nextCfg.manualProxy.host ||
        prevCfg.manualProxy.port !== nextCfg.manualProxy.port ||
        prevCfg.customProbeUrl !== nextCfg.customProbeUrl;

      if (proxyCfgChanged) {
        return coordinator.checkNow('代理连接配置已更改');
      }

      return coordinator.evaluateStatusOnly();
    }
  );

  ipcMain.handle('guard:clear-logs', () => coordinator.clearLogs());

  ipcMain.handle('guard:sync-locale', (_e, targetSource?: 'monitor' | 'claude') =>
    coordinator.syncSystemLocaleToDefault(targetSource)
  );

  ipcMain.handle('guard:restore-locale', () => coordinator.restoreDefaultChinaLocale());

  ipcMain.handle('guard:get-alert-data', () => alertWindows.getLatestPayload());

  ipcMain.handle('guard:accept-current-from-alert', () => {
    if (alertWindows.getLatestPayload()?.source !== 'claude') {
      const snap = coordinator.getSnapshot();
      if (snap.lastProbe && isValidIsoCountryCode(snap.lastProbe.countryCode)) {
        configStore.update({
          defaultCountryCode: snap.lastProbe.countryCode,
          defaultCountryName: snap.lastProbe.countryName,
        });
        coordinator.evaluateStatusOnly(
          `已在警告窗确认将 [${snap.lastProbe.countryName}] 设为新默认地区`
        );
      }
    }
    alertWindows.hideAlertWindow();
  });

  ipcMain.on('window:minimize-main', () => {
    mainWindows.minimize();
  });

  ipcMain.on('window:close-main', () => {
    mainWindows.closeFromTitlebar();
  });

  ipcMain.on('window:open-main-from-alert', () => {
    alertWindows.hideAlertWindow();
    mainWindows.showMainWindow();
  });

  ipcMain.on('window:dismiss-alert', () => {
    alertWindows.hideAlertWindow();
  });
}
