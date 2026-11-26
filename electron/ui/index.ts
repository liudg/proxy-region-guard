export { createStatusTrayIcon, createWindowAppIcon } from './trayIcon';

export {
  ELECTRON_FIRST_TRAY_UID,
  type TrayWin32ProbeResult,
  type TrayProbeRunner,
  type TrayHealthManagerOptions,
  isPidAliveFast,
  truncateTrayTooltipSafe,
  parseTrayProbeStdout,
  probeAndHealWindowsTray,
  TrayHealthManager,
} from './trayHealth';

export {
  getPreloadPath,
  loadRendererRoute,
  waitForPostUpdateRendererReady,
} from './rendererLoader';

export {
  type MainWindowManagerDeps,
  MainWindowManager,
} from './mainWindowManager';

export { AlertWindowManager } from './alertWindowManager';

export {
  type TrayControllerDeps,
  TrayController,
} from './trayController';

export {
  type IpcHandlersDeps,
  registerGuardIpcHandlers,
} from './ipcHandlers';
