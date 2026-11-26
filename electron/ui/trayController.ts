import { app, Menu, Tray } from 'electron';
import { AppStateSnapshot } from '../../src/shared/types';
import { isValidIsoCountryCode } from '../../src/shared/countries';
import { isWindowsLocaleMatchingCountry } from '../../src/shared/timezones';
import { GuardCoordinator } from '../guard';
import {
  applyAutoLaunchSetting,
  ConfigStore,
  isLaunchedFromAutoStart,
  shouldStartSilentlyInTray,
} from '../system';
import { UpdaterService } from '../updater';
import { MainWindowManager } from './mainWindowManager';
import { TrayHealthManager } from './trayHealth';
import { createStatusTrayIcon } from './trayIcon';

export interface TrayControllerDeps {
  configStore: ConfigStore;
  coordinator: GuardCoordinator;
  updaterService: UpdaterService;
  mainWindows: MainWindowManager;
  isQuitting: () => boolean;
}

export class TrayController {
  private tray: Tray | null = null;
  private trayHealth: TrayHealthManager | null = null;
  private lastTrayMenuSignature = '';
  private latestTrayTooltip = '代理地区卫士 · 正在初始化...';

  constructor(private readonly deps: TrayControllerDeps) {}

  public setup(): void {
    const initialIcon = createStatusTrayIcon('checking');
    this.tray = new Tray(initialIcon);
    this.latestTrayTooltip = '代理地区卫士 · 正在初始化...';
    this.tray.setToolTip(this.latestTrayTooltip);

    this.tray.on('click', () => {
      if (this.deps.mainWindows.isFocusedVisible()) {
        this.deps.mainWindows.hideToTray();
      } else {
        this.deps.mainWindows.showMainWindow();
      }
    });

    this.tray.on('double-click', () => {
      this.deps.mainWindows.showMainWindow();
    });

    this.refreshFromState(this.deps.coordinator.getSnapshot());

    this.trayHealth?.stop();
    this.trayHealth = new TrayHealthManager({
      isAutoStart: isLaunchedFromAutoStart(process.argv),
      getTooltip: () => this.latestTrayTooltip,
      onSyncTray: (healed) => {
        if (!this.tray || this.deps.isQuitting()) return;
        if (healed) {
          this.lastTrayMenuSignature = '';
          this.refreshFromState(this.deps.coordinator.getSnapshot());
        } else {
          this.tray.setToolTip(this.latestTrayTooltip);
        }
      },
      onHealed: () => {
        this.deps.coordinator.recordExternalLog(
          'info',
          '检测到系统托盘延迟就绪或资源管理器重启，已自动恢复任务栏托盘图标'
        );
      },
      onStartupRetriesExhausted: (lastRes) => {
        if (
          this.deps.isQuitting() ||
          !shouldStartSilentlyInTray(process.argv) ||
          !lastRes.probeOk ||
          lastRes.iconAlive ||
          !lastRes.desktopInteractive
        ) {
          return;
        }
        if (!this.deps.mainWindows.getWindow()) {
          this.deps.coordinator.recordExternalLog(
            'warn',
            '系统托盘长时间未就绪，已自动打开主控制面板以防后台不可达'
          );
          this.deps.mainWindows.showMainWindow();
        }
      },
    });
    this.trayHealth.start();
  }

  public checkContinuityFast(): void {
    this.trayHealth?.checkContinuityFast();
  }

  public ensureHealthyOnHideToTray(): void {
    this.trayHealth?.ensureHealthyOnHideToTray();
  }

  public stopHealth(): void {
    this.trayHealth?.stop();
  }

  public destroy(): void {
    this.trayHealth?.stop();
    this.tray?.destroy();
    this.tray = null;
  }

  public refreshFromState(state: AppStateSnapshot): void {
    if (!this.tray) return;

    const icon = createStatusTrayIcon(state.status);
    this.tray.setImage(icon);
    this.deps.mainWindows.updateIcon(state.status);

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
      state.config.antigravityClashProfileName ||
      state.privateChannels.antigravity.profileName;
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

    this.latestTrayTooltip = tooltip;
    this.tray.setToolTip(tooltip);

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

    if (menuSig === this.lastTrayMenuSignature) {
      return;
    }
    this.lastTrayMenuSignature = menuSig;

    const { coordinator, configStore, updaterService, mainWindows } = this.deps;

    const menu = Menu.buildFromTemplate([
      {
        label: statusLabelMap[state.status],
        enabled: false,
      },
      {
        label: clashChannelText,
        enabled: false,
      },
      ...(nodeText ? [{ label: nodeText, enabled: false }] : []),
      ...(agNodeText ? [{ label: agNodeText, enabled: false }] : []),
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
          void coordinator.launchAntigravityFromGuard();
        },
      },
      ...(state.antigravityState.running
        ? [
            {
              label: '🛑 关闭 Antigravity 进程',
              click: () => {
                void coordinator.terminateAntigravityManually();
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
          void coordinator.launchClaudeFromGuard();
        },
      },
      ...(state.claudeState.running
        ? [
            {
              label: '🛑 立即终止 Claude 进程',
              click: () => {
                void coordinator.terminateClaudeManually();
              },
            },
          ]
        : []),
      { type: 'separator' },
      {
        label: '立即重新检测',
        click: () => {
          void coordinator.checkNow('托盘菜单手动检测');
        },
      },
      {
        label: syncTargetName
          ? `一键同步系统时区与区域 (${syncTargetName})`
          : '一键同步系统时区与区域',
        enabled: canSyncLocale && !state.isSyncingLocale,
        click: () => {
          void coordinator.syncSystemLocaleToDefault();
        },
      },
      {
        label: '还原默认中国时区与区域',
        enabled: !state.isSyncingLocale,
        click: () => {
          void coordinator.restoreDefaultChinaLocale();
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
          coordinator.evaluateStatusOnly(
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
              mainWindows.openUpdateModal(true, true);
              return;
            }
            void updaterService.applyDownloadedUpdate(false).then((res) => {
              if (!res.ok) {
                const needClaudeConfirm =
                  res.state.claudeState.running || res.state.claudeState.authorizedSession;
                mainWindows.openUpdateModal(needClaudeConfirm, true);
              }
            });
            return;
          }
          if (state.updateState.hasUpdate) {
            mainWindows.openUpdateModal(false);
            return;
          }
          mainWindows.openUpdateModal(false, true);
          void updaterService.checkForUpdates({ silent: false });
        },
      },
      {
        label: '打开主控制面板',
        click: () => mainWindows.showMainWindow(),
      },
      { type: 'separator' },
      {
        label: '退出代理地区卫士',
        click: () => app.quit(),
      },
    ]);

    this.tray.setContextMenu(menu);
  }
}
