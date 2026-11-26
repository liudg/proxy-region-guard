export {
  resolveWindowsPowerShellExe,
  quoteWindowsArg,
  quoteWindowsCommandLine,
} from './winShell';

export { configureAppUserData } from './appIdentity';

export {
  ELEVATED_RELAUNCH_FLAG,
  isRunningAsWindowsAdmin,
  tryRelaunchAsWindowsAdmin,
} from './adminElevation';

export {
  AUTOSTART_ARG,
  SILENT_TRAY_ARG,
  AUTOSTART_LOGON_DELAY,
  type LaunchTarget,
  isLaunchedFromAutoStart,
  shouldStartSilentlyInTray,
  buildScheduledTaskXml,
  applyAutoLaunchSetting,
  readSystemAutoLaunchEnabled,
  reconcileAutoLaunchOnStartup,
} from './autoLaunch';

export { DEFAULT_CONFIG, ConfigStore } from './configStore';
export { GeoIpService } from './geoipService';

export {
  type ProcessKillReport,
  type RunningProcEntry,
  type CachedProcessSnapshot,
  decodeWinConsoleBuffer,
  getCachedRunningProcessesSnapshot,
  parseTasklistCsvOutput,
  listRunningProcesses,
  terminateProtectedProcesses,
  assertProcessesStopped,
  spawnDetachedWithProxyCheck,
} from './processGuard';

export {
  type SystemProxyState,
  readWindowsSystemProxy,
  getNetworkInterfaceFingerprint,
} from './systemProxy';

export {
  readWindowsLocaleState,
  applyWindowsTimeZoneAndRegion,
  queryExactExitIanaTimeZone,
} from './winSystemLocale';

export {
  CLAUDE_DESKTOP_PROCESS_PATTERNS,
  markClaudeLaunchedByGuard,
  getLaunchedClaudePort,
  fileOrReparseExists,
  detectClaudeInstallation,
  isPidAlive,
  areAnyPidsAlive,
  countRunningClaudeProcesses,
  terminateClaudeProcessesSync,
  spawnClaudeWithDedicatedProxy,
} from './claudeController';

export {
  ANTIGRAVITY_PROCESS_PATTERNS,
  markAntigravityLaunchedByGuard,
  detectAntigravityInstallation,
  inspectRunningAntigravityProcesses,
  spawnAntigravityWithDedicatedProxy,
} from './antigravityController';
