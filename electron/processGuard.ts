import { execFile } from 'node:child_process';
import * as path from 'node:path';
import { compileValidPatterns } from '../src/shared/processPattern';

export interface ProcessKillReport {
  matchedSummary: string[];   // 如 ["Claude.exe (×8)", "claude-native.exe"]
  matchedRawNames: string[];  // 去重进程名列表，如 ["Claude.exe", "claude-native.exe"]
  totalMatchedPids: number;
  accessDenied: boolean;
  errorDetail?: string;
}

interface RunningProcEntry {
  imageName: string;
  pid: number;
}

export function decodeWinConsoleBuffer(buf: Buffer | string | null | undefined): string {
  if (!buf) return '';
  if (typeof buf === 'string') return buf;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    try {
      return new TextDecoder('gbk').decode(buf);
    } catch {
      return buf.toString('utf-8');
    }
  }
}

function listRunningProcesses(): Promise<RunningProcEntry[]> {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') {
      resolve([]);
      return;
    }

    execFile(
      'tasklist.exe',
      ['/FO', 'CSV', '/NH'],
      { encoding: 'buffer', windowsHide: true, timeout: 3500, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout) => {
        if (err && (!stdout || stdout.length === 0)) {
          resolve([]);
          return;
        }

        const text = decodeWinConsoleBuffer(stdout);
        const list: RunningProcEntry[] = [];

        for (const rawLine of text.split(/\r?\n/)) {
          const line = rawLine.trim();
          if (!line.startsWith('"')) continue;
          // 格式: "Image Name","PID","Session Name","Session#","Mem Usage"
          const match = line.match(/^"([^"]+)","(\d+)"/);
          if (!match) continue;
          const imageName = match[1].trim();
          const pid = Number(match[2]);
          if (imageName && Number.isInteger(pid) && pid > 4) {
            list.push({ imageName, pid });
          }
        }

        resolve(list);
      }
    );
  });
}

function runTaskkillTreeBatch(pids: number[]): Promise<{ accessDenied: boolean; rawError?: string }> {
  return new Promise((resolve) => {
    if (pids.length === 0) {
      resolve({ accessDenied: false });
      return;
    }

    const args = ['/F', '/T'];
    for (const pid of pids) {
      args.push('/PID', String(pid));
    }

    execFile(
      'taskkill.exe',
      args,
      { encoding: 'buffer', windowsHide: true, timeout: 5000, maxBuffer: 1024 * 1024 },
      (err, stdout, stderr) => {
        if (!err) {
          resolve({ accessDenied: false });
          return;
        }
        const combined = `${decodeWinConsoleBuffer(stdout)}\n${decodeWinConsoleBuffer(stderr)}`;
        const denied = /拒绝访问|Access is denied/i.test(combined);
        resolve({
          accessDenied: denied,
          rawError: denied ? '部分目标进程以管理员权限运行，当前权限无法终止（请以管理员身份运行本卫士）' : undefined,
        });
      }
    );
  });
}

/**
 * 扫描当前所有运行进程，使用通配符/正则规则匹配，并按进程树 (/F /T) 连带全部子进程一次性强杀
 */
export async function terminateProtectedProcesses(patterns: string[]): Promise<ProcessKillReport> {
  const emptyReport: ProcessKillReport = {
    matchedSummary: [],
    matchedRawNames: [],
    totalMatchedPids: 0,
    accessDenied: false,
  };

  if (process.platform !== 'win32' || !patterns || patterns.length === 0) {
    return emptyReport;
  }

  const compiled = compileValidPatterns(patterns);
  if (compiled.length === 0) {
    return emptyReport;
  }

  const running = await listRunningProcesses();
  if (running.length === 0) {
    return emptyReport;
  }

  const selfExeLower = path.basename(process.execPath).toLowerCase();
  const isDevElectron = selfExeLower === 'electron.exe';
  const selfPid = process.pid;
  const selfPpid = process.ppid;

  const targetPids: number[] = [];
  const countByName = new Map<string, number>();

  for (const proc of running) {
    if (proc.pid === selfPid || proc.pid === selfPpid) continue;

    const lowerName = proc.imageName.toLowerCase();
    // 绝对保护卫士自身进程不被误杀
    if (lowerName === '代理地区卫士.exe' || lowerName === 'proxy-region-guard.exe') {
      continue;
    }
    if (isDevElectron && lowerName === 'electron.exe') {
      continue;
    }

    const hit = compiled.some((item) => item.regex.test(proc.imageName));
    if (hit) {
      targetPids.push(proc.pid);
      countByName.set(proc.imageName, (countByName.get(proc.imageName) || 0) + 1);
    }
  }

  if (targetPids.length === 0) {
    return emptyReport;
  }

  // 分批执行 taskkill /F /T /PID ... 连同所有派生子进程（如 node.exe / crashpad_handler.exe 等）一起强杀
  let anyAccessDenied = false;
  let errorDetail: string | undefined;
  const chunkSize = 40;

  for (let i = 0; i < targetPids.length; i += chunkSize) {
    const batch = targetPids.slice(i, i + chunkSize);
    const res = await runTaskkillTreeBatch(batch);
    if (res.accessDenied) {
      anyAccessDenied = true;
      errorDetail = res.rawError;
    }
  }

  const matchedRawNames = Array.from(countByName.keys());
  const matchedSummary = Array.from(countByName.entries()).map(([name, cnt]) =>
    cnt > 1 ? `${name} (×${cnt})` : name
  );

  return {
    matchedSummary,
    matchedRawNames,
    totalMatchedPids: targetPids.length,
    accessDenied: anyAccessDenied,
    errorDetail,
  };
}
