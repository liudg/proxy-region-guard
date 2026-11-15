import { ChildProcess, execFile } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  CachedProcessSnapshot,
  getCachedRunningProcessesSnapshot,
  RunningProcEntry,
} from './processGuard';

/**
 * Electron Windows 托盘底层 (shell/browser/ui/win/notify_icon_host.h) 中：
 * kBaseIconId = 2，初始 next_icon_id_ = 1，因此进程内首个 new Tray() 的固定 uID 为 3。
 * 复用同一个 Tray 实例并通过 TaskbarCreated 触发其内部 ResetIcon()，可保持 uID=3 不变，
 * 避免产生新 uID 导致用户在 Windows 11 任务栏固定的托盘图标 (IsPromoted=1) 退回折叠区。
 */
export const ELECTRON_FIRST_TRAY_UID = 3;

const STARTUP_RETRY_DELAYS_MS = [
  800, 1500, 2500, 4000, 6000, 8000, 10000, 15000, 20000, 30000,
] as const;

const CONTINUITY_CHECK_INTERVAL_MS = 5000;
const HIDE_TO_TRAY_VERIFY_COOLDOWN_MS = 15000;
const EXHAUSTED_FALLBACK_POLL_MS = 60000;

export interface TrayWin32ProbeResult {
  probeOk: boolean;
  desktopInteractive: boolean;
  taskbarReady: boolean;
  explorerPid: number;
  shellTrayHwnd: string;
  hostFound: boolean;
  iconAlive: boolean;
  healed: boolean;
}

export type TrayProbeRunner = (
  targetPid: number,
  iconUid: number,
  tooltip: string,
  onSpawn?: (child: ChildProcess) => void
) => Promise<TrayWin32ProbeResult>;

export interface TrayHealthManagerOptions {
  isAutoStart: boolean;
  getTooltip: () => string;
  onSyncTray: (healed: boolean) => void;
  onHealed?: (explorerPid: number) => void;
  onStartupRetriesExhausted?: (lastResult: TrayWin32ProbeResult) => void;
  targetPid?: number;
  iconUid?: number;
  probeRunner?: TrayProbeRunner;
  isPidAlive?: (pid: number) => boolean;
  getCachedProcessSnapshot?: () => CachedProcessSnapshot | null;
  initialDelayMs?: number;
  retryDelaysMs?: readonly number[];
  exhaustedPollIntervalMs?: number;
  continuityIntervalMs?: number;
  hideVerifyCooldownMs?: number;
}

export function isPidAliveFast(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 4) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException)?.code;
    return code === 'EPERM';
  }
}

export function truncateTrayTooltipSafe(raw: string, maxUtf16Units = 127): string {
  if (!raw || maxUtf16Units <= 0) return '';
  const clean = String(raw).replace(/\0/g, '');
  if (!clean) return '';
  if (clean.length <= maxUtf16Units) return clean;
  let end = maxUtf16Units;
  const lastCode = clean.charCodeAt(end - 1);
  // 防止截断落在 UTF-16 高代理项 (0xD800..0xDBFF) 上产生孤立代理半字
  if (lastCode >= 0xd800 && lastCode <= 0xdbff) {
    end--;
  }
  return clean.slice(0, end);
}

let cachedPowerShellExe: string | null = null;
function resolveWindowsPowerShellExe(): string {
  if (cachedPowerShellExe) return cachedPowerShellExe;
  const sysRoot = process.env.SystemRoot || 'C:\\Windows';
  const fullPath = path.join(sysRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  cachedPowerShellExe = fs.existsSync(fullPath) ? fullPath : 'powershell.exe';
  return cachedPowerShellExe;
}

const POWERSHELL_TRAY_PROBE_SCRIPT = [
  '$ErrorActionPreference = "Stop"',
  'Add-Type -TypeDefinition @"',
  'using System;',
  'using System.Runtime.InteropServices;',
  'using System.Text;',
  'public static class GuardTrayBridge {',
  '  private const uint NIM_MODIFY = 0x00000001;',
  '  private const uint NIF_TIP = 0x00000004;',
  '  private const uint SMTO_ABORTIFHUNG = 0x0002;',
  '  private const uint DESKTOP_READOBJECTS = 0x0001;',
  '  private const int UOI_NAME = 2;',
  '  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]',
  '  public struct NOTIFYICONDATAW {',
  '    public uint cbSize;',
  '    public IntPtr hWnd;',
  '    public uint uID;',
  '    public uint uFlags;',
  '    public uint uCallbackMessage;',
  '    public IntPtr hIcon;',
  '    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;',
  '    public uint dwState;',
  '    public uint dwStateMask;',
  '    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;',
  '    public uint uTimeoutOrVersion;',
  '    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;',
  '    public uint dwInfoFlags;',
  '    public Guid guidItem;',
  '    public IntPtr hBalloonIcon;',
  '  }',
  '  [DllImport("user32.dll", CharSet = CharSet.Unicode)]',
  '  private static extern IntPtr FindWindowW(string lpClassName, IntPtr lpWindowName);',
  '  [DllImport("user32.dll", CharSet = CharSet.Unicode)]',
  '  private static extern IntPtr FindWindowExW(IntPtr hWndParent, IntPtr hWndChildAfter, string lpszClass, IntPtr lpszWindow);',
  '  [DllImport("user32.dll")]',
  '  private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);',
  '  [DllImport("user32.dll", CharSet = CharSet.Unicode)]',
  '  private static extern uint RegisterWindowMessageW(string lpString);',
  '  [DllImport("user32.dll")]',
  '  private static extern IntPtr SendMessageTimeoutW(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam, uint fuFlags, uint uTimeout, out IntPtr lpdwResult);',
  '  [DllImport("user32.dll")]',
  '  private static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);',
  '  [DllImport("user32.dll")]',
  '  private static extern bool CloseDesktop(IntPtr hDesktop);',
  '  [DllImport("user32.dll")]',
  '  private static extern IntPtr GetThreadDesktop(uint dwThreadId);',
  '  [DllImport("kernel32.dll")]',
  '  private static extern uint GetCurrentThreadId();',
  '  [DllImport("user32.dll", CharSet = CharSet.Unicode)]',
  '  private static extern bool GetUserObjectInformationW(IntPtr hObj, int nIndex, StringBuilder pvInfo, uint nLength, out uint lpnLengthNeeded);',
  '  [DllImport("shell32.dll", CharSet = CharSet.Unicode)]',
  '  private static extern bool Shell_NotifyIconW(uint dwMessage, ref NOTIFYICONDATAW lpData);',
  '  private static string ReadDesktopName(IntPtr hDesk) {',
  '    if (hDesk == IntPtr.Zero) return string.Empty;',
  '    var sb = new StringBuilder(128);',
  '    uint needed = 0;',
  '    if (!GetUserObjectInformationW(hDesk, UOI_NAME, sb, (uint)(sb.Capacity * 2), out needed)) return string.Empty;',
  '    return sb.ToString();',
  '  }',
  '  private static bool IsActiveInteractiveDesktop() {',
  '    IntPtr hThreadDesk = GetThreadDesktop(GetCurrentThreadId());',
  '    string threadName = ReadDesktopName(hThreadDesk);',
  '    if (!string.Equals(threadName, "Default", StringComparison.OrdinalIgnoreCase)) return false;',
  '    IntPtr hInput = OpenInputDesktop(0, false, DESKTOP_READOBJECTS);',
  '    if (hInput == IntPtr.Zero) return false;',
  '    try {',
  '      string inputName = ReadDesktopName(hInput);',
  '      return string.Equals(inputName, "Default", StringComparison.OrdinalIgnoreCase);',
  '    } finally {',
  '      CloseDesktop(hInput);',
  '    }',
  '  }',
  '  private static IntPtr FindHostWindow(uint targetPid) {',
  '    IntPtr cur = IntPtr.Zero;',
  '    for (int i = 0; i < 4096; i++) {',
  '      cur = FindWindowExW(IntPtr.Zero, cur, "Electron_NotifyIconHostWindow", IntPtr.Zero);',
  '      if (cur == IntPtr.Zero) return IntPtr.Zero;',
  '      uint pid = 0;',
  '      GetWindowThreadProcessId(cur, out pid);',
  '      if (pid == targetPid) return cur;',
  '    }',
  '    return IntPtr.Zero;',
  '  }',
  '  private static bool TryModifyTip(IntPtr hostHwnd, uint iconUid, string tip) {',
  '    var nid = new NOTIFYICONDATAW();',
  '    nid.cbSize = (uint)Marshal.SizeOf(typeof(NOTIFYICONDATAW));',
  '    nid.hWnd = hostHwnd;',
  '    nid.uID = iconUid;',
  '    nid.uFlags = NIF_TIP;',
  '    nid.szTip = tip ?? string.Empty;',
  '    return Shell_NotifyIconW(NIM_MODIFY, ref nid);',
  '  }',
  '  public static string ProbeAndHeal(uint targetPid, uint iconUid, string rawTip) {',
  '    string tip = rawTip ?? string.Empty;',
  '    if (tip.Length > 127) {',
  '      int len = 127;',
  '      if (char.IsHighSurrogate(tip[len - 1])) len--;',
  '      tip = tip.Substring(0, len);',
  '    }',
  '    string deskFlag = IsActiveInteractiveDesktop() ? "1" : "0";',
  '    IntPtr hostHwnd = FindHostWindow(targetPid);',
  '    bool hostFound = hostHwnd != IntPtr.Zero;',
  '    IntPtr shellTrayHwnd = FindWindowW("Shell_TrayWnd", IntPtr.Zero);',
  '    if (shellTrayHwnd == IntPtr.Zero) {',
  '      return deskFlag + "|0|0|0|" + (hostFound ? "1" : "0") + "|0|0";',
  '    }',
  '    uint explorerPid = 0;',
  '    GetWindowThreadProcessId(shellTrayHwnd, out explorerPid);',
  '    if (!hostFound) {',
  '      return deskFlag + "|1|" + explorerPid + "|" + shellTrayHwnd.ToInt64() + "|0|0|0";',
  '    }',
  '    if (TryModifyTip(hostHwnd, iconUid, tip)) {',
  '      return deskFlag + "|1|" + explorerPid + "|" + shellTrayHwnd.ToInt64() + "|1|1|0";',
  '    }',
  '    uint wm = RegisterWindowMessageW("TaskbarCreated");',
  '    if (wm != 0) {',
  '      IntPtr unused = IntPtr.Zero;',
  '      SendMessageTimeoutW(hostHwnd, wm, IntPtr.Zero, IntPtr.Zero, SMTO_ABORTIFHUNG, 3000, out unused);',
  '    }',
  '    bool aliveAfter = TryModifyTip(hostHwnd, iconUid, tip);',
  '    return deskFlag + "|1|" + explorerPid + "|" + shellTrayHwnd.ToInt64() + "|1|" + (aliveAfter ? "1|1" : "0|0");',
  '  }',
  '}',
  '"@',
  '$res = [GuardTrayBridge]::ProbeAndHeal([uint32]$env:GUARD_TRAY_PID, [uint32]$env:GUARD_TRAY_UID, [string]$env:GUARD_TRAY_TIP)',
  'Write-Output ("GUARD_TRAY_RESULT:" + $res)',
].join('\r\n');

export function parseTrayProbeStdout(stdout: string): TrayWin32ProbeResult | null {
  if (!stdout) return null;
  const m =
    /GUARD_TRAY_RESULT:(0|1)\|(0|1)\|(\d+)\|(-?\d+)\|(0|1)\|(0|1)\|(0|1)/.exec(stdout);
  if (!m) return null;
  return {
    probeOk: true,
    desktopInteractive: m[1] === '1',
    taskbarReady: m[2] === '1',
    explorerPid: Number(m[3]) || 0,
    shellTrayHwnd: m[4],
    hostFound: m[5] === '1',
    iconAlive: m[6] === '1',
    healed: m[7] === '1',
  };
}

export const probeAndHealWindowsTray: TrayProbeRunner = (
  targetPid,
  iconUid,
  tooltip,
  onSpawn
) => {
  if (process.platform !== 'win32') {
    return Promise.resolve({
      probeOk: true,
      desktopInteractive: true,
      taskbarReady: true,
      explorerPid: 1,
      shellTrayHwnd: '1',
      hostFound: true,
      iconAlive: true,
      healed: false,
    });
  }

  return new Promise<TrayWin32ProbeResult>((resolve) => {
    const fallback: TrayWin32ProbeResult = {
      probeOk: false,
      desktopInteractive: false,
      taskbarReady: false,
      explorerPid: 0,
      shellTrayHwnd: '0',
      hostFound: false,
      iconAlive: false,
      healed: false,
    };

    try {
      const safeTip = truncateTrayTooltipSafe(tooltip);
      const child = execFile(
        resolveWindowsPowerShellExe(),
        [
          '-NoProfile',
          '-NonInteractive',
          '-ExecutionPolicy',
          'Bypass',
          '-WindowStyle',
          'Hidden',
          '-Command',
          POWERSHELL_TRAY_PROBE_SCRIPT,
        ],
        {
          cwd: os.tmpdir(),
          windowsHide: true,
          timeout: 15000,
          env: {
            ...process.env,
            GUARD_TRAY_PID: String(targetPid),
            GUARD_TRAY_UID: String(iconUid),
            GUARD_TRAY_TIP: safeTip,
          },
        },
        (err, stdout) => {
          if (err || !stdout) {
            resolve(fallback);
            return;
          }
          resolve(parseTrayProbeStdout(String(stdout)) ?? fallback);
        }
      );

      onSpawn?.(child);
    } catch {
      resolve(fallback);
    }
  });
};

export class TrayHealthManager {
  private readonly isAutoStart: boolean;
  private readonly getTooltip: () => string;
  private readonly onSyncTray: (healed: boolean) => void;
  private readonly onHealed?: (explorerPid: number) => void;
  private readonly onStartupRetriesExhausted?: (lastResult: TrayWin32ProbeResult) => void;
  private readonly targetPid: number;
  private readonly iconUid: number;
  private readonly probeRunner: TrayProbeRunner;
  private readonly isPidAlive: (pid: number) => boolean;
  private readonly getCachedProcessSnapshot: () => CachedProcessSnapshot | null;
  private readonly initialDelayMs: number;
  private readonly retryDelaysMs: readonly number[];
  private readonly exhaustedPollIntervalMs: number;
  private readonly continuityIntervalMs: number;
  private readonly hideVerifyCooldownMs: number;

  private verifiedExplorerPid: number | null = null;
  private verifiedAtLeastSnapshotTime = 0;
  private lastVerifiedAt = 0;
  private hasEverVerified = false;
  private startupExhaustedNotified = false;
  private recoveringFromFailure = false;
  private inExhaustedSlowPoll = false;
  private lastSeenExplorerSignature = '';
  private retryAttempt = 0;
  private retryTimer: NodeJS.Timeout | null = null;
  private continuityTimer: NodeJS.Timeout | null = null;
  private checkInFlight: Promise<TrayWin32ProbeResult> | null = null;
  private pendingRecheck = false;
  private activeChild: ChildProcess | null = null;
  private stopped = false;

  constructor(opts: TrayHealthManagerOptions) {
    this.isAutoStart = opts.isAutoStart;
    this.getTooltip = opts.getTooltip;
    this.onSyncTray = opts.onSyncTray;
    this.onHealed = opts.onHealed;
    this.onStartupRetriesExhausted = opts.onStartupRetriesExhausted;
    this.targetPid = opts.targetPid ?? process.pid;
    this.iconUid = opts.iconUid ?? ELECTRON_FIRST_TRAY_UID;
    this.probeRunner = opts.probeRunner ?? probeAndHealWindowsTray;
    this.isPidAlive = opts.isPidAlive ?? isPidAliveFast;
    this.getCachedProcessSnapshot =
      opts.getCachedProcessSnapshot ?? getCachedRunningProcessesSnapshot;
    this.initialDelayMs = opts.initialDelayMs ?? (this.isAutoStart ? 600 : 1200);
    this.retryDelaysMs = opts.retryDelaysMs ?? STARTUP_RETRY_DELAYS_MS;
    this.exhaustedPollIntervalMs = opts.exhaustedPollIntervalMs ?? EXHAUSTED_FALLBACK_POLL_MS;
    this.continuityIntervalMs = opts.continuityIntervalMs ?? CONTINUITY_CHECK_INTERVAL_MS;
    this.hideVerifyCooldownMs = opts.hideVerifyCooldownMs ?? HIDE_TO_TRAY_VERIFY_COOLDOWN_MS;
  }

  public start(): void {
    if (process.platform !== 'win32') return;
    this.stopped = false;
    this.retryAttempt = 0;
    this.inExhaustedSlowPoll = false;
    this.pendingRecheck = false;
    this.scheduleRetry(this.initialDelayMs);

    if (!this.continuityTimer && this.continuityIntervalMs > 0) {
      this.continuityTimer = setInterval(() => {
        this.checkContinuityFast();
      }, this.continuityIntervalMs);
      this.continuityTimer.unref?.();
    }
  }

  public stop(): void {
    this.stopped = true;
    this.pendingRecheck = false;
    this.inExhaustedSlowPoll = false;
    this.clearRetryTimer();
    if (this.continuityTimer) {
      clearInterval(this.continuityTimer);
      this.continuityTimer = null;
    }
    if (this.activeChild) {
      try {
        this.activeChild.kill();
      } catch {
        // ignore child cleanup failure
      }
      this.activeChild = null;
    }
  }

  public getVerifiedExplorerPid(): number | null {
    return this.verifiedExplorerPid;
  }

  /**
   * 零子进程开销的快速连续性检查：
   * 1. 已验证状态下，通过进程存活检测 + 新鲜度受控的缓存进程表识别 explorer.exe 退出/重启或 PID 复用；
   * 2. 未验证或已降级慢轮询状态下，若缓存进程表出现新的 explorer.exe 进程，立即唤醒快检。
   */
  public checkContinuityFast(): void {
    if (this.stopped || process.platform !== 'win32') return;

    const snapshot = this.getCachedProcessSnapshot();

    if (this.verifiedExplorerPid !== null) {
      // 在途探测回调栈帧（如 onHealed -> broadcastState）内不重复触发已验证态失效，僅在真实进程已死时标记补检
      const pid = this.verifiedExplorerPid;
      let explorerGone = !this.isPidAlive(pid);

      if (
        !explorerGone &&
        snapshot &&
        snapshot.entries.length > 0 &&
        snapshot.readAt >= this.verifiedAtLeastSnapshotTime
      ) {
        const matchedExplorer = snapshot.entries.some(
          (p) => p.pid === pid && p.imageName.toLowerCase() === 'explorer.exe'
        );
        if (!matchedExplorer) {
          explorerGone = true;
        }
      }

      if (explorerGone) {
        this.verifiedExplorerPid = null;
        this.recoveringFromFailure = true;
        this.retryAttempt = 0;
        this.inExhaustedSlowPoll = false;
        void this.triggerCheckNow();
      }
      return;
    }

    if (snapshot) {
      const sig = this.computeExplorerSignature(snapshot.entries);
      const prevSig = this.lastSeenExplorerSignature;
      this.lastSeenExplorerSignature = sig;

      if (sig && sig !== prevSig && (this.inExhaustedSlowPoll || (!this.retryTimer && !this.checkInFlight))) {
        this.retryAttempt = 0;
        this.inExhaustedSlowPoll = false;
        void this.triggerCheckNow();
      }
    }
  }

  /**
   * 用户关闭主窗口隐藏到托盘时的兜底校验：
   * - 未处于已验证状态时立即触发挂载修复（若已有在途探测则置 pendingRecheck 确保最新复核）；
   * - 已验证但距离上次实测超过冷却期时，后台静默复核一次以防第三方工具移除托盘图标。
   */
  public ensureHealthyOnHideToTray(): void {
    if (this.stopped || process.platform !== 'win32') return;
    this.checkContinuityFast();
    if (this.verifiedExplorerPid === null) {
      this.retryAttempt = 0;
      this.inExhaustedSlowPoll = false;
      void this.triggerCheckNow();
      return;
    }
    if (Date.now() - this.lastVerifiedAt >= this.hideVerifyCooldownMs) {
      void this.triggerCheckNow();
    }
  }

  public triggerCheckNow(): Promise<TrayWin32ProbeResult> {
    if (this.checkInFlight) {
      this.pendingRecheck = true;
      return this.checkInFlight;
    }
    this.clearRetryTimer();
    this.inExhaustedSlowPoll = false;

    const runLoop = async (): Promise<TrayWin32ProbeResult> => {
      let lastRes: TrayWin32ProbeResult = {
        probeOk: false,
        desktopInteractive: false,
        taskbarReady: false,
        explorerPid: 0,
        shellTrayHwnd: '0',
        hostFound: false,
        iconAlive: false,
        healed: false,
      };
      do {
        this.pendingRecheck = false;
        lastRes = await this.executeSingleCheckOnce();
      } while (!this.stopped && this.pendingRecheck);
      return lastRes;
    };

    const runPromise = runLoop().finally(() => {
      if (this.checkInFlight === runPromise) {
        this.checkInFlight = null;
      }
    });

    this.checkInFlight = runPromise;
    return runPromise;
  }

  private async executeSingleCheckOnce(): Promise<TrayWin32ProbeResult> {
    const probeStartedAt = Date.now();
    let res: TrayWin32ProbeResult;
    try {
      res = await this.probeRunner(
        this.targetPid,
        this.iconUid,
        this.getTooltip(),
        (child) => {
          this.activeChild = child;
        }
      );
    } catch {
      res = {
        probeOk: false,
        desktopInteractive: false,
        taskbarReady: false,
        explorerPid: 0,
        shellTrayHwnd: '0',
        hostFound: false,
        iconAlive: false,
        healed: false,
      };
    } finally {
      this.activeChild = null;
    }

    if (this.stopped) {
      return res;
    }

    const snapNow = this.getCachedProcessSnapshot();
    if (snapNow) {
      this.lastSeenExplorerSignature = this.computeExplorerSignature(snapNow.entries);
    }

    // 若本轮在途期间收到了新的重检请求，不在旧结果上触发状态回调或推进重试计数，直接交由外层循环立即重测
    if (this.pendingRecheck) {
      if (res.healed || (!res.iconAlive && res.probeOk)) {
        this.recoveringFromFailure = true;
      }
      return res;
    }

    if (res.iconAlive && res.explorerPid > 0) {
      const effectiveHealed = res.healed || this.recoveringFromFailure;
      this.verifiedExplorerPid = res.explorerPid;
      this.verifiedAtLeastSnapshotTime = probeStartedAt;
      this.lastVerifiedAt = Date.now();
      this.hasEverVerified = true;
      this.recoveringFromFailure = false;
      this.inExhaustedSlowPoll = false;
      this.retryAttempt = 0;
      this.clearRetryTimer();

      try {
        this.onSyncTray(effectiveHealed);
        if (effectiveHealed) {
          this.onHealed?.(res.explorerPid);
        }
      } catch (err) {
        console.warn('[TrayHealth] onSyncTray/onHealed callback error:', err);
      }
      return res;
    }

    this.verifiedExplorerPid = null;
    if (res.probeOk) {
      this.recoveringFromFailure = true;
    }

    if (this.retryAttempt < this.retryDelaysMs.length) {
      const delayMs = this.retryDelaysMs[this.retryAttempt++];
      this.scheduleRetry(delayMs);
      return res;
    }

    if (!this.hasEverVerified && !this.startupExhaustedNotified) {
      this.startupExhaustedNotified = true;
      try {
        this.onStartupRetriesExhausted?.(res);
      } catch (err) {
        console.warn('[TrayHealth] onStartupRetriesExhausted callback error:', err);
      }
    }

    // 快速退避重试耗尽后，若 Win32 探测通道可用则转入低频慢轮询兜底（应对同 PID 慢启动任务栏），避免永久休眠
    if (this.exhaustedPollIntervalMs > 0 && res.probeOk) {
      this.inExhaustedSlowPoll = true;
      this.scheduleRetry(this.exhaustedPollIntervalMs);
    }

    return res;
  }

  private computeExplorerSignature(procs: RunningProcEntry[]): string {
    return procs
      .filter((p) => p.imageName.toLowerCase() === 'explorer.exe')
      .map((p) => p.pid)
      .sort((a, b) => a - b)
      .join(',');
  }

  private scheduleRetry(delayMs: number): void {
    if (this.stopped) return;
    this.clearRetryTimer();
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      if (!this.stopped) {
        void this.triggerCheckNow();
      }
    }, delayMs);
    this.retryTimer.unref?.();
  }

  private clearRetryTimer(): void {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }
}
