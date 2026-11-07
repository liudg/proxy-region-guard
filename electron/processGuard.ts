import { execFile } from 'node:child_process';
import * as path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  compileValidPatterns,
  CRITICAL_SYSTEM_PROCESSES,
} from '../src/shared/processPattern';

export interface ProcessKillReport {
  killedSummary: string[];   // 实际已被成功终止的进程汇总，如 ["Claude.exe (×8)"]
  killedCount: number;       // 实际终止的 PID 数量
  failedSummary: string[];   // 因权限不足等原因仍存活的进程汇总
  failedPids: number[];      // 未能终止的存活 PID 列表（已排序，用于去重抑制）
  accessDenied: boolean;
  errorDetail?: string;
}

export interface RunningProcEntry {
  imageName: string;
  pid: number;
}

const CRITICAL_SYSTEM_SET = new Set<string>(CRITICAL_SYSTEM_PROCESSES);

// 保护常见代理客户端与内核进程不被误配规则强杀（否则会导致网络彻底断联死循环）
const PROTECTED_PROXY_INFRA_SET = new Set<string>([
  'verge-mihomo.exe',
  'verge-mihomo-alpha.exe',
  'clash-verge-service.exe',
  'mihomo.exe',
  'mihomo-party.exe',
  'clash.exe',
  'clash-verge.exe',
  'clash-nyanpasu.exe',
  'flclash.exe',
  'clash for windows.exe',
  'v2ray.exe',
  'v2rayn.exe',
  'xray.exe',
  'sing-box.exe',
  'nekoray.exe',
  'nekobox.exe',
]);

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

export function listRunningProcesses(): Promise<RunningProcEntry[]> {
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

function runTaskkillTreeBatch(
  pids: number[]
): Promise<{ hadError: boolean; accessDenied: boolean }> {
  return new Promise((resolve) => {
    if (pids.length === 0) {
      resolve({ hadError: false, accessDenied: false });
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
          resolve({ hadError: false, accessDenied: false });
          return;
        }
        const combined = `${decodeWinConsoleBuffer(stdout)}\n${decodeWinConsoleBuffer(stderr)}`;
        const denied = /拒绝访问|Access is denied/i.test(combined);
        resolve({
          hadError: true,
          accessDenied: denied,
        });
      }
    );
  });
}

function formatCountMap(countByName: Map<string, number>): string[] {
  return Array.from(countByName.entries()).map(([name, cnt]) =>
    cnt > 1 ? `${name} (×${cnt})` : name
  );
}

/**
 * 扫描当前所有运行进程，使用通配符/正则规则匹配，按进程树 (/F /T) 强杀并二次核验实际终止结果
 */
export async function terminateProtectedProcesses(patterns: string[]): Promise<ProcessKillReport> {
  const emptyReport: ProcessKillReport = {
    killedSummary: [],
    killedCount: 0,
    failedSummary: [],
    failedPids: [],
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
  const selfPid = process.pid;
  const selfPpid = process.ppid;

  const matchedEntries: RunningProcEntry[] = [];

  for (const proc of running) {
    if (proc.pid === selfPid || proc.pid === selfPpid) continue;

    const lowerName = proc.imageName.toLowerCase();
    // 保护卫士自身（含重命名后的 exe）、系统关键进程与代理内核进程不被误杀
    if (
      lowerName === selfExeLower ||
      lowerName === '代理地区卫士.exe' ||
      lowerName === 'proxy-region-guard.exe' ||
      CRITICAL_SYSTEM_SET.has(lowerName) ||
      PROTECTED_PROXY_INFRA_SET.has(lowerName)
    ) {
      continue;
    }

    const hit = compiled.some((item) => item.regex.test(proc.imageName));
    if (hit) {
      matchedEntries.push(proc);
    }
  }

  if (matchedEntries.length === 0) {
    return emptyReport;
  }

  const targetPids = matchedEntries.map((p) => p.pid);
  let anyError = false;
  let anyAccessDenied = false;
  const chunkSize = 40;

  for (let i = 0; i < targetPids.length; i += chunkSize) {
    const batch = targetPids.slice(i, i + chunkSize);
    const res = await runTaskkillTreeBatch(batch);
    if (res.hadError) anyError = true;
    if (res.accessDenied) anyAccessDenied = true;
  }

  // 若 taskkill 报错（特别是权限拒绝），二次扫描存活进程以区分“真正已杀”与“因权限存活”
  let survivingPidSet = new Set<number>();
  if (anyError) {
    await sleep(60);
    const afterRunning = await listRunningProcesses();
    survivingPidSet = new Set(afterRunning.map((p) => p.pid));
  }

  const killedByName = new Map<string, number>();
  const failedByName = new Map<string, number>();
  const failedPids: number[] = [];

  for (const entry of matchedEntries) {
    if (survivingPidSet.has(entry.pid)) {
      failedPids.push(entry.pid);
      failedByName.set(entry.imageName, (failedByName.get(entry.imageName) || 0) + 1);
    } else {
      killedByName.set(entry.imageName, (killedByName.get(entry.imageName) || 0) + 1);
    }
  }

  failedPids.sort((a, b) => a - b);
  const killedSummary = formatCountMap(killedByName);
  const failedSummary = formatCountMap(failedByName);
  const stillAlive = failedPids.length > 0;

  let errorDetail: string | undefined;
  if (stillAlive) {
    errorDetail = anyAccessDenied
      ? `无法终止高权限进程 [${failedSummary.join(', ')}]，请以管理员身份运行本卫士`
      : `部分目标进程未能成功终止：[${failedSummary.join(', ')}]`;
  }

  return {
    killedSummary,
    killedCount: matchedEntries.length - failedPids.length,
    failedSummary,
    failedPids,
    accessDenied: anyAccessDenied && stillAlive,
    errorDetail,
  };
}
