import { app } from 'electron';
import * as path from 'node:path';

export const AUTOSTART_ARG = '--autostart';
const REGISTRY_VALUE_NAME = 'ProxyRegionGuard';

interface LaunchTarget {
  execPath: string;
  args: string[];
}

function getLaunchTarget(): LaunchTarget {
  const execPath = process.execPath;

  if (app.isPackaged) {
    return {
      execPath,
      args: [AUTOSTART_ARG],
    };
  }

  const appDir = path.resolve(app.getAppPath());
  const formattedDir = appDir.includes(' ') ? `"${appDir}"` : appDir;
  return {
    execPath,
    args: [formattedDir, AUTOSTART_ARG],
  };
}

export function isLaunchedFromAutoStart(argv: string[] = process.argv): boolean {
  return argv.includes(AUTOSTART_ARG);
}

export function applyAutoLaunchSetting(enable: boolean): boolean {
  if (process.platform !== 'win32' && process.platform !== 'darwin') {
    return false;
  }

  try {
    if (process.platform === 'win32') {
      if (enable) {
        const target = getLaunchTarget();
        app.setLoginItemSettings({
          openAtLogin: true,
          enabled: true,
          name: REGISTRY_VALUE_NAME,
          path: target.execPath,
          args: target.args,
        });
      } else {
        // 不传 path，确保即使便携版目录移动过也能按注册表键名彻底清除
        app.setLoginItemSettings({
          openAtLogin: false,
          name: REGISTRY_VALUE_NAME,
        });
      }
      return readSystemAutoLaunchEnabled();
    }

    app.setLoginItemSettings({ openAtLogin: enable });
    return Boolean(app.getLoginItemSettings().openAtLogin);
  } catch (err) {
    console.error('[AutoLaunch] Failed to apply login item settings:', err);
    return readSystemAutoLaunchEnabled();
  }
}

export function readSystemAutoLaunchEnabled(): boolean {
  if (process.platform !== 'win32' && process.platform !== 'darwin') {
    return false;
  }

  try {
    if (process.platform === 'win32') {
      const target = getLaunchTarget();
      const info = app.getLoginItemSettings({
        path: target.execPath,
        args: target.args,
      });
      const byName = info.launchItems?.find((item) => item.name === REGISTRY_VALUE_NAME);
      if (byName) {
        return Boolean(byName.enabled);
      }
      return Boolean(info.openAtLogin);
    }

    return Boolean(app.getLoginItemSettings().openAtLogin);
  } catch (err) {
    console.error('[AutoLaunch] Failed to read login item settings:', err);
    return false;
  }
}

export function reconcileAutoLaunchOnStartup(configuredAutoLaunch: boolean): boolean {
  if (process.platform !== 'win32' && process.platform !== 'darwin') {
    return false;
  }

  try {
    if (process.platform === 'win32') {
      const target = getLaunchTarget();
      const info = app.getLoginItemSettings({
        path: target.execPath,
        args: target.args,
      });
      const byName = info.launchItems?.find((item) => item.name === REGISTRY_VALUE_NAME);

      // 若用户在 Windows 任务管理器「启动应用」中手动禁用了本程序，尊重系统状态
      if (byName && !byName.enabled) {
        return false;
      }

      if (configuredAutoLaunch || (byName && byName.enabled)) {
        // 重新写入一次以同步便携版移动目录后的最新可执行文件路径
        return applyAutoLaunchSetting(true);
      }

      return false;
    }

    if (configuredAutoLaunch) {
      return applyAutoLaunchSetting(true);
    }
    return Boolean(app.getLoginItemSettings().openAtLogin);
  } catch (err) {
    console.error('[AutoLaunch] Failed to reconcile auto launch:', err);
    return false;
  }
}
