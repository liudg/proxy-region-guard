import { app } from 'electron';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export const AUTOSTART_ARG = '--autostart';
const REGISTRY_VALUE_NAME = 'ProxyRegionGuard';
const SCHEDULED_TASK_NAME = 'ProxyRegionGuard';
const RUN_REG_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';

interface LaunchTarget {
  execPath: string;
  args: string[];
  workingDir: string;
}

function escapeXml(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function getLaunchTarget(): LaunchTarget {
  const execPath = process.execPath;

  if (app.isPackaged) {
    return {
      execPath,
      args: [AUTOSTART_ARG],
      workingDir: path.dirname(execPath),
    };
  }

  const appDir = path.resolve(app.getAppPath());
  const formattedDir = appDir.includes(' ') ? `"${appDir}"` : appDir;
  return {
    execPath,
    args: [formattedDir, AUTOSTART_ARG],
    workingDir: appDir,
  };
}

function getCurrentWindowsUserPrincipal(): string {
  const domain = (process.env.USERDOMAIN || '').trim();
  const username = (process.env.USERNAME || os.userInfo().username || '').trim();
  if (domain && username) {
    return `${domain}\\${username}`;
  }
  return username;
}

function buildScheduledTaskXml(target: LaunchTarget): string {
  const userPrincipal = getCurrentWindowsUserPrincipal();
  const quotedCommand = `"${target.execPath}"`;
  const argsText = target.args.join(' ');

  const userIdNode = userPrincipal
    ? `<UserId>${escapeXml(userPrincipal)}</UserId>`
    : '';

  return [
    '<?xml version="1.0" encoding="UTF-16"?>',
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
    '  <Triggers>',
    '    <LogonTrigger>',
    '      <Enabled>true</Enabled>',
    userIdNode ? `      ${userIdNode}` : '',
    '    </LogonTrigger>',
    '  </Triggers>',
    '  <Principals>',
    '    <Principal id="Author">',
    userIdNode ? `      ${userIdNode}` : '',
    '      <LogonType>InteractiveToken</LogonType>',
    '      <RunLevel>HighestAvailable</RunLevel>',
    '    </Principal>',
    '  </Principals>',
    '  <Settings>',
    '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>',
    '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>',
    '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>',
    '    <AllowHardTerminate>true</AllowHardTerminate>',
    '    <StartWhenAvailable>true</StartWhenAvailable>',
    '    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>',
    '    <AllowStartOnDemand>true</AllowStartOnDemand>',
    '    <Enabled>true</Enabled>',
    '    <Hidden>false</Hidden>',
    '    <RunOnlyIfIdle>false</RunOnlyIfIdle>',
    '    <WakeToRun>false</WakeToRun>',
    '    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>',
    '    <Priority>7</Priority>',
    '  </Settings>',
    '  <Actions Context="Author">',
    '    <Exec>',
    `      <Command>${escapeXml(quotedCommand)}</Command>`,
    `      <Arguments>${escapeXml(argsText)}</Arguments>`,
    `      <WorkingDirectory>${escapeXml(target.workingDir)}</WorkingDirectory>`,
    '    </Exec>',
    '  </Actions>',
    '</Task>',
  ]
    .filter(Boolean)
    .join('\r\n');
}

function registerWindowsScheduledTask(target: LaunchTarget): boolean {
  const tmpXmlPath = path.join(
    os.tmpdir(),
    `proxy-region-guard-task-${process.pid}-${Date.now()}.xml`
  );
  try {
    const xmlContent = buildScheduledTaskXml(target);
    const utf16Buffer = Buffer.from('\uFEFF' + xmlContent, 'utf16le');
    fs.writeFileSync(tmpXmlPath, utf16Buffer);

    execFileSync(
      'schtasks.exe',
      ['/Create', '/TN', SCHEDULED_TASK_NAME, '/XML', tmpXmlPath, '/F'],
      {
        windowsHide: true,
        stdio: 'ignore',
        timeout: 6000,
      }
    );
    return true;
  } catch (err) {
    console.error('[AutoLaunch] Failed to register scheduled task:', err);
    return false;
  } finally {
    try {
      if (fs.existsSync(tmpXmlPath)) {
        fs.unlinkSync(tmpXmlPath);
      }
    } catch {
      // ignore temp cleanup failure
    }
  }
}

function deleteWindowsScheduledTask(): void {
  try {
    execFileSync('schtasks.exe', ['/Delete', '/TN', SCHEDULED_TASK_NAME, '/F'], {
      windowsHide: true,
      stdio: 'ignore',
      timeout: 5000,
    });
  } catch {
    // Task may not exist
  }
}

function getScheduledTaskState(): 'enabled' | 'disabled' | 'missing' {
  try {
    const stdout = execFileSync(
      'schtasks.exe',
      ['/Query', '/TN', SCHEDULED_TASK_NAME, '/XML'],
      {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 4000,
      }
    );
    const asciiXml = stdout.toString('latin1').replace(/\0/g, '');
    if (/<Settings>[\s\S]*?<Enabled>\s*false\s*<\/Enabled>[\s\S]*?<\/Settings>/i.test(asciiXml)) {
      return 'disabled';
    }
    return 'enabled';
  } catch {
    return 'missing';
  }
}

function removeRegistryRunValue(): void {
  try {
    app.setLoginItemSettings({
      openAtLogin: false,
      name: REGISTRY_VALUE_NAME,
    });
  } catch {
    // ignore
  }
  try {
    execFileSync('reg.exe', ['delete', RUN_REG_KEY, '/v', REGISTRY_VALUE_NAME, '/f'], {
      windowsHide: true,
      stdio: 'ignore',
      timeout: 3000,
    });
  } catch {
    // Value may not exist
  }
}

function setRegistryRunValueFallback(target: LaunchTarget): boolean {
  try {
    const cmdLine = `"${target.execPath}" ${target.args.join(' ')}`.trim();
    execFileSync(
      'reg.exe',
      ['add', RUN_REG_KEY, '/v', REGISTRY_VALUE_NAME, '/t', 'REG_SZ', '/d', cmdLine, '/f'],
      {
        windowsHide: true,
        stdio: 'ignore',
        timeout: 3000,
      }
    );
    return true;
  } catch {
    return false;
  }
}

function hasRegistryRunValue(): boolean {
  try {
    execFileSync('reg.exe', ['query', RUN_REG_KEY, '/v', REGISTRY_VALUE_NAME], {
      windowsHide: true,
      stdio: 'ignore',
      timeout: 2500,
    });
    return true;
  } catch {
    return false;
  }
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
        // Windows 下本程序包含管理员权限清单 (requireAdministrator)，
        // 注册表 HKCU\...\Run 会在登录时被系统拦截，必须通过最高权限计划任务实现开机自启
        const taskOk = registerWindowsScheduledTask(target);
        if (taskOk) {
          removeRegistryRunValue();
          return true;
        }
        // 非管理员环境降级回退至注册表 Run 键
        return setRegistryRunValueFallback(target);
      } else {
        deleteWindowsScheduledTask();
        removeRegistryRunValue();
        return false;
      }
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
      const taskState = getScheduledTaskState();
      if (taskState === 'enabled') return true;
      if (taskState === 'disabled') return false;
      return hasRegistryRunValue();
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
      const taskState = getScheduledTaskState();

      // 若用户在系统计划任务中手动禁用了本任务，尊重系统状态
      if (taskState === 'disabled') {
        return false;
      }

      if (configuredAutoLaunch || taskState === 'enabled' || hasRegistryRunValue()) {
        // 同步最新可执行文件路径并自动将旧版失效的注册表 Run 键升级为最高权限计划任务
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
