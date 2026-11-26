import { app } from 'electron';
import { execFileSync } from 'node:child_process';
import * as path from 'node:path';
import { quoteWindowsCommandLine, resolveWindowsPowerShellExe } from './winShell';

export const ELEVATED_RELAUNCH_FLAG = '--elevated-relaunch';

export function isRunningAsWindowsAdmin(): boolean {
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

export function tryRelaunchAsWindowsAdmin(): boolean {
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
