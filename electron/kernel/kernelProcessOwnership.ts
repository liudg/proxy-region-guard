import { execFile } from 'node:child_process';
import * as path from 'node:path';
import { promisify } from 'node:util';
import { KernelLease } from './kernelTypes';

const execute = promisify(execFile);

export async function verifyKernelProcessIdentity(
  directory: string,
  executable: string,
  lease: Pick<KernelLease, 'pid' | 'revision'>
): Promise<void> {
  const result = await execute(
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $ErrorActionPreference = "Stop"; Get-CimInstance Win32_Process -Filter ("ProcessId=" + $env:GUARD_KERNEL_PID) | Select-Object ExecutablePath,CommandLine | ConvertTo-Json -Compress',
    ],
    {
      windowsHide: true,
      env: { ...process.env, GUARD_KERNEL_PID: String(lease.pid) },
      timeout: 5000,
    }
  );
  const identity = result.stdout.trim() ? JSON.parse(result.stdout) : null;
  if (!identity) throw new Error('私有内核进程已退出');
  if (!identity.ExecutablePath || !identity.CommandLine) {
    throw new Error('无法读取私有内核进程身份，请检查进程访问权限');
  }
  const configuration = path.join(directory, lease.revision, 'config.yaml');
  if (
    String(identity.ExecutablePath).toLowerCase() !== executable.toLowerCase() ||
    !String(identity.CommandLine).toLowerCase().includes(configuration.toLowerCase())
  ) {
    throw new Error('私有内核进程身份不匹配');
  }
}

export async function getLocalPortOwnerPids(
  port: number,
  signal?: AbortSignal
): Promise<number[]> {
  const result = await execute(
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $ErrorActionPreference = "Stop"; @(Get-NetTCPConnection -State Listen -LocalPort $env:GUARD_KERNEL_PORT -ErrorAction SilentlyContinue | Select-Object LocalAddress,OwningProcess) | ConvertTo-Json -Compress',
    ],
    {
      windowsHide: true,
      env: { ...process.env, GUARD_KERNEL_PORT: String(port) },
      timeout: 10000,
      signal,
    }
  );
  const raw: unknown = result.stdout.trim() ? JSON.parse(result.stdout) : [];
  const rows = (Array.isArray(raw) ? raw : [raw]).filter(
    (item): item is { LocalAddress?: unknown; OwningProcess?: unknown } =>
      Boolean(item && typeof item === 'object')
  );
  const uniqueValidPids = (items: Array<{ OwningProcess?: unknown }>): number[] => [
    ...new Set(
      items
        .map((r) => r.OwningProcess)
        .filter((pid): pid is number => Number.isInteger(pid) && (pid as number) > 0)
    ),
  ];
  // 127.0.0.1 精确绑定优先级最高；无精确绑定时纳入可接受 127.0.0.1 连接的 0.0.0.0 与双栈 :: 监听
  const exactLoopback = uniqueValidPids(
    rows.filter((r) => String(r.LocalAddress || '').trim() === '127.0.0.1')
  );
  if (exactLoopback.length > 0) return exactLoopback;
  return uniqueValidPids(
    rows.filter((r) => {
      const addr = String(r.LocalAddress || '').trim();
      return addr === '0.0.0.0' || addr === '::';
    })
  );
}
