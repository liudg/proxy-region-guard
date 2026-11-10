import { execFile } from 'node:child_process';
import * as os from 'node:os';
import * as path from 'node:path';
import { AntigravityRuntimeState } from '../src/shared/types';
import { fileOrReparseExists } from './claudeController';
import {
  decodeWinConsoleBuffer,
  listRunningProcesses,
  spawnDetachedWithProxyCheck,
} from './processGuard';

export const ANTIGRAVITY_PROCESS_PATTERNS = [
  'Antigravity.exe',
  'language_server.exe',
  'language_server_windows_x64.exe',
];

const ANTIGRAVITY_UI_PROCESS_NAMES = new Set(['antigravity.exe']);
const ANTIGRAVITY_LS_PROCESS_NAMES = new Set([
  'language_server.exe',
  'language_server_windows_x64.exe',
]);

let launchedByGuardPort: number | null = null;
let launchedByGuardAt = 0;
let cachedUiPidsSignature = '';
let cachedCheckedPort = 0;
let cachedCmdlineProxied = false;

export function markAntigravityLaunchedByGuard(port: number | null): void {
  launchedByGuardPort = port;
  launchedByGuardAt = port !== null ? Date.now() : 0;
  if (port === null) {
    cachedUiPidsSignature = '';
    cachedCheckedPort = 0;
    cachedCmdlineProxied = false;
  }
}

export async function detectAntigravityInstallation(
  customExePath?: string
): Promise<{
  exePath: string | null;
  installType: AntigravityRuntimeState['installType'];
}> {
  const trimmedCustom = (customExePath || '').trim();
  if (trimmedCustom && fileOrReparseExists(trimmedCustom)) {
    return {
      exePath: trimmedCustom,
      installType: 'custom',
    };
  }

  const localAppData =
    process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  const programFiles = process.env['ProgramFiles'] || 'C:\\Program Files';
  const programFilesX86 =
    process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';

  const candidates = [
    path.join(localAppData, 'Programs', 'antigravity', 'Antigravity.exe'),
    path.join(localAppData, 'Programs', 'Antigravity', 'Antigravity.exe'),
    path.join(localAppData, 'antigravity', 'Antigravity.exe'),
    path.join(programFiles, 'Antigravity', 'Antigravity.exe'),
    path.join(programFilesX86, 'Antigravity', 'Antigravity.exe'),
    path.join(localAppData, 'Microsoft', 'WindowsApps', 'Antigravity.exe'),
  ];

  for (const candidate of candidates) {
    if (fileOrReparseExists(candidate)) {
      return {
        exePath: candidate,
        installType: 'standard',
      };
    }
  }

  return {
    exePath: null,
    installType: 'not-found',
  };
}

function checkAntigravityCommandLineProxy(dedicatedPort: number): Promise<boolean> {
  if (process.platform !== 'win32') {
    return Promise.resolve(false);
  }

  return new Promise((resolve) => {
    execFile(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        "Get-CimInstance Win32_Process -Filter \"Name = 'Antigravity.exe'\" | Select-Object -ExpandProperty CommandLine",
      ],
      { encoding: 'buffer', windowsHide: true, timeout: 3500 },
      (err, stdout) => {
        if (err || !stdout) {
          resolve(false);
          return;
        }
        const text = decodeWinConsoleBuffer(stdout).toLowerCase();
        const expectedA = `--proxy-server=http://127.0.0.1:${dedicatedPort}`;
        const expectedB = `--proxy-server=127.0.0.1:${dedicatedPort}`;
        resolve(text.includes(expectedA) || text.includes(expectedB));
      }
    );
  });
}

export async function inspectRunningAntigravityProcesses(
  dedicatedPort: number,
  forceFresh = false
): Promise<{
  running: boolean;
  uiProcessCount: number;
  languageServerCount: number;
  totalProcessCount: number;
  proxiedSession: boolean;
}> {
  const procs = await listRunningProcesses(forceFresh);
  const uiPids: number[] = [];
  const lsPids: number[] = [];

  for (const p of procs) {
    const lower = p.imageName.toLowerCase();
    if (ANTIGRAVITY_UI_PROCESS_NAMES.has(lower)) {
      uiPids.push(p.pid);
    } else if (ANTIGRAVITY_LS_PROCESS_NAMES.has(lower)) {
      lsPids.push(p.pid);
    }
  }

  const uiProcessCount = uiPids.length;
  const languageServerCount = lsPids.length;
  const totalProcessCount = uiProcessCount + languageServerCount;
  const running = totalProcessCount > 0;

  if (!running || uiProcessCount === 0) {
    launchedByGuardPort = null;
    launchedByGuardAt = 0;
    cachedUiPidsSignature = '';
    cachedCheckedPort = 0;
    cachedCmdlineProxied = false;
    return {
      running,
      uiProcessCount,
      languageServerCount,
      totalProcessCount,
      proxiedSession: false,
    };
  }

  uiPids.sort((a, b) => a - b);
  const sig = uiPids.join(',');
  const inLaunchGrace =
    launchedByGuardPort === dedicatedPort && Date.now() - launchedByGuardAt <= 6000;

  if (
    sig !== cachedUiPidsSignature ||
    cachedCheckedPort !== dedicatedPort ||
    (inLaunchGrace && !cachedCmdlineProxied)
  ) {
    cachedCheckedPort = dedicatedPort;
    cachedCmdlineProxied = await checkAntigravityCommandLineProxy(dedicatedPort);
    if (cachedCmdlineProxied) {
      cachedUiPidsSignature = sig;
      launchedByGuardPort = dedicatedPort;
    } else if (inLaunchGrace) {
      // 启动宽限期内若 WMI/CIM 查询因启动负载暂未检出命令行参数，不锁死签名缓存，确保宽限期结束后仍会复核一次
      cachedUiPidsSignature = '';
    } else {
      cachedUiPidsSignature = sig;
      launchedByGuardPort = null;
    }
  }

  return {
    running: true,
    uiProcessCount,
    languageServerCount,
    totalProcessCount,
    proxiedSession: cachedCmdlineProxied,
  };
}

/**
 * 通过指定专属本地代理端口拉起 Antigravity.exe：
 * 1. 向 Antigravity.exe (Electron/Chromium) 注入 --proxy-server 与 WebRTC 防泄漏参数
 * 2. 向进程环境块注入 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / GRPC_PROXY，使子进程 language_server.exe 及衍生工具进程全部自动继承代理
 * 3. 强制注入 NO_PROXY=localhost,127.0.0.1,::1，保护 Antigravity.exe 与 language_server.exe 之间的本地回环 RPC 通信不被代理截断
 */
export async function spawnAntigravityWithDedicatedProxy(
  exePath: string,
  dedicatedPort: number
): Promise<{ ok: boolean; error?: string }> {
  const httpProxy = `http://127.0.0.1:${dedicatedPort}`;
  const socksProxy = `socks5://127.0.0.1:${dedicatedPort}`;
  const noProxy = 'localhost,127.0.0.1,::1';

  const args = [
    `--proxy-server=${httpProxy}`,
    '--proxy-bypass-list=<-loopback>;localhost;127.0.0.1;::1',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
  ];

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HTTP_PROXY: httpProxy,
    HTTPS_PROXY: httpProxy,
    ALL_PROXY: socksProxy,
    GRPC_PROXY: httpProxy,
    http_proxy: httpProxy,
    https_proxy: httpProxy,
    all_proxy: socksProxy,
    grpc_proxy: httpProxy,
    NO_PROXY: noProxy,
    no_proxy: noProxy,
  };

  return spawnDetachedWithProxyCheck(exePath, args, env, path.dirname(exePath));
}
