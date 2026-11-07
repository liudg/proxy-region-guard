import { execFile, execFileSync, spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { ClaudeRuntimeState } from '../src/shared/types';
import {
  decodeWinConsoleBuffer,
  listRunningProcesses,
} from './processGuard';

export const CLAUDE_DESKTOP_PROCESS_PATTERNS = [
  'claude.exe',
  'claude-desktop.exe',
  'claude-ssh-proxy.exe',
  'claude-ssh-broker.exe',
  'claude-ssh-askpass.exe',
  'claude-make-data-folder.exe',
  'cowork-svc.exe',
];

export const CLAUDE_TUN_PROCESS_NAMES = [...CLAUDE_DESKTOP_PROCESS_PATTERNS];

const CLAUDE_UI_PROCESS_NAMES = new Set([
  'claude.exe',
  'claude-desktop.exe',
]);

let cachedMsixDirectExe: string | null = null;

export function fileOrReparseExists(filePath: string | null | undefined): boolean {
  if (!filePath) return false;
  try {
    // Windows MSIX AppExecutionAlias (如 claude-desktop.exe) 是 IO_REPARSE_TAG_APPEXECLINK 重解析点，
    // fs.existsSync (statSync) 会返回 false，必须使用 lstatSync 检测存在性
    return Boolean(fs.lstatSync(filePath, { throwIfNoEntry: false }));
  } catch {
    return false;
  }
}

function queryMsixInstallDirectExe(forceRefresh = false): Promise<string | null> {
  if (!forceRefresh && cachedMsixDirectExe && fileOrReparseExists(cachedMsixDirectExe)) {
    return Promise.resolve(cachedMsixDirectExe);
  }
  if (process.platform !== 'win32') {
    return Promise.resolve(null);
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
        '(Get-AppxPackage -Name "*Claude*" | Select-Object -First 1).InstallLocation',
      ],
      { encoding: 'buffer', windowsHide: true, timeout: 4000 },
      (err, stdout) => {
        if (err || !stdout) {
          resolve(null);
          return;
        }
        const loc = decodeWinConsoleBuffer(stdout).trim().split(/\r?\n/)[0]?.trim();
        if (loc) {
          const directExe = path.join(loc, 'app', 'claude.exe');
          if (fileOrReparseExists(directExe)) {
            cachedMsixDirectExe = directExe;
            resolve(directExe);
            return;
          }
          const rootExe = path.join(loc, 'claude.exe');
          if (fileOrReparseExists(rootExe)) {
            cachedMsixDirectExe = rootExe;
            resolve(rootExe);
            return;
          }
        }
        resolve(null);
      }
    );
  });
}

export async function detectClaudeInstallation(
  customExePath?: string,
  forceRefresh = false
): Promise<{
  exePath: string | null;
  fallbackDirectPath: string | null;
  installType: ClaudeRuntimeState['installType'];
}> {
  if (forceRefresh) {
    cachedMsixDirectExe = null;
  }

  const trimmedCustom = (customExePath || '').trim();
  if (trimmedCustom && fileOrReparseExists(trimmedCustom)) {
    return {
      exePath: trimmedCustom,
      fallbackDirectPath: null,
      installType: 'custom',
    };
  }

  const localAppData =
    process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');

  // 1. 经典 Squirrel / 独立安装包路径
  const squirrelCandidates = [
    path.join(localAppData, 'AnthropicClaude', 'claude.exe'),
    path.join(localAppData, 'AnthropicClaude', 'Claude.exe'),
    path.join(localAppData, 'Programs', 'claude', 'Claude.exe'),
    path.join(localAppData, 'Programs', 'AnthropicClaude', 'Claude.exe'),
  ];

  for (const p of squirrelCandidates) {
    if (fileOrReparseExists(p)) {
      return {
        exePath: p,
        fallbackDirectPath: null,
        installType: 'squirrel',
      };
    }
  }

  // 2. MSIX 官方执行别名 (AppExecutionAlias) —— 支持命令行参数与环境变量透传且跨版本升级路径固定
  const aliasCandidates = [
    path.join(localAppData, 'Microsoft', 'WindowsApps', 'claude-desktop.exe'),
    path.join(
      localAppData,
      'Microsoft',
      'WindowsApps',
      'Claude_pzs8sxrjxfjjc',
      'claude-desktop.exe'
    ),
  ];

  for (const alias of aliasCandidates) {
    if (fileOrReparseExists(alias)) {
      return {
        exePath: alias,
        fallbackDirectPath: cachedMsixDirectExe,
        installType: 'msix-alias',
      };
    }
  }

  // 3. 仅当上述快速路径均不存在时，才调用 PowerShell 查询 MSIX 包目录直连路径
  const msixDirect = await queryMsixInstallDirectExe(forceRefresh);
  if (msixDirect) {
    return {
      exePath: msixDirect,
      fallbackDirectPath: null,
      installType: 'msix-direct',
    };
  }

  return {
    exePath: null,
    fallbackDirectPath: null,
    installType: 'not-found',
  };
}

export async function countRunningClaudeProcesses(): Promise<{
  running: boolean;
  count: number;
  pids: number[];
}> {
  const procs = await listRunningProcesses();
  const matchedPids: number[] = [];
  for (const p of procs) {
    if (CLAUDE_UI_PROCESS_NAMES.has(p.imageName.toLowerCase())) {
      matchedPids.push(p.pid);
    }
  }
  return {
    running: matchedPids.length > 0,
    count: matchedPids.length,
    pids: matchedPids,
  };
}

/**
 * 卫士退出时同步强杀全部 Claude 关联进程树，确保卫士退出后 Claude 绝不单独留存裸奔
 */
export function terminateClaudeProcessesSync(): void {
  if (process.platform !== 'win32') return;
  try {
    const args = ['/F', '/T'];
    for (const procName of CLAUDE_DESKTOP_PROCESS_PATTERNS) {
      args.push('/IM', procName);
    }
    execFileSync('taskkill.exe', args, {
      windowsHide: true,
      stdio: 'ignore',
      timeout: 3000,
    });
  } catch {
    // 若当前没有运行中的 Claude 进程，taskkill 返回非 0 退出码，安全忽略即可
  }
}

/**
 * 通过指定专属本地代理端口拉起 Claude Desktop，强制其主进程及全部衍生子进程 100% 走指定节点
 */
export async function spawnClaudeWithDedicatedProxy(
  exePath: string,
  fallbackDirectPath: string | null,
  proxyUrl: string
): Promise<{ ok: boolean; error?: string }> {
  const cleanProxy = proxyUrl.trim();
  const hostPort = cleanProxy.replace(/^[a-z0-9+.-]+:\/\//i, '');
  const httpProxy = `http://${hostPort}`;
  const socksProxy = `socks5://${hostPort}`;

  const args = [
    `--proxy-server=${httpProxy}`,
    '--proxy-bypass-list=<-loopback>',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
  ];

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HTTP_PROXY: httpProxy,
    HTTPS_PROXY: httpProxy,
    ALL_PROXY: socksProxy,
    http_proxy: httpProxy,
    https_proxy: httpProxy,
    all_proxy: socksProxy,
    NO_PROXY: 'localhost,127.0.0.1,::1',
    no_proxy: 'localhost,127.0.0.1,::1',
  };

  const trySpawn = (targetExe: string): Promise<{ ok: boolean; error?: string }> => {
    return new Promise((resolve) => {
      try {
        const child = spawn(targetExe, args, {
          detached: true,
          stdio: 'ignore',
          windowsHide: false,
          env,
        });

        let settled = false;
        const finish = (res: { ok: boolean; error?: string }) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolve(res);
        };

        child.once('error', (err) => {
          finish({ ok: false, error: err.message });
        });

        child.once('exit', (code) => {
          if (code !== null && code !== 0) {
            finish({ ok: false, error: `进程异常退出 (代码 ${code})` });
          }
        });

        const timer = setTimeout(() => {
          try {
            child.unref();
          } catch {
            // ignore
          }
          finish({ ok: true });
        }, 450);
      } catch (err) {
        resolve({
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    });
  };

  const primaryRes = await trySpawn(exePath);
  if (primaryRes.ok) {
    return primaryRes;
  }

  const resolvedFallback =
    fallbackDirectPath ||
    (exePath.toLowerCase().includes('windowsapps')
      ? await queryMsixInstallDirectExe(true)
      : null);

  if (resolvedFallback && resolvedFallback !== exePath) {
    return trySpawn(resolvedFallback);
  }

  return primaryRes;
}
