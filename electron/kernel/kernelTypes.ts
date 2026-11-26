import { createHash, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { MihomoEndpoint, NodeSnapshot } from '../clash';

export interface SavedChannel {
  schema: 1;
  snapshot: NodeSnapshot;
  port: number;
  internalPort?: number;
  revision: string;
  ipv4Only?: boolean;
}

export interface KernelLease {
  pid: number;
  executable: string;
  revision: string;
  endpoint: MihomoEndpoint;
}

export class PortOwnershipError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PortOwnershipError';
  }
}

export class PortOwnershipLookupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PortOwnershipLookupError';
  }
}

export function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function atomicWriteJsonSync(file: string, value: unknown): void {
  const temporary = `${file}.${randomUUID()}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(value), { mode: 0o600 });
  fs.renameSync(temporary, file);
}

export function verifyCore(directory: string): string {
  const manifest = JSON.parse(
    fs.readFileSync(path.join(directory, 'manifest.json'), 'utf8')
  ) as { version: string; sha256: string };
  const executable = path.join(directory, 'guard-mihomo.exe');
  if (createHash('sha256').update(fs.readFileSync(executable)).digest('hex') !== manifest.sha256) {
    throw new Error('私有 Mihomo 文件完整性校验失败');
  }
  return executable;
}

export function isKernelPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false;
    throw error;
  }
}

export async function allocateFreeLoopbackPort(excludePorts: Set<number>): Promise<number> {
  for (let attempt = 0; attempt < 16; attempt++) {
    const port = await new Promise<number>((resolve, reject) => {
      const srv = net.createServer();
      srv.unref();
      srv.once('error', reject);
      srv.listen(0, '127.0.0.1', () => {
        const addr = srv.address();
        const bound = addr && typeof addr !== 'string' ? addr.port : 0;
        srv.close(() => {
          if (bound > 0) resolve(bound);
          else reject(new Error('无法分配私有内核内部回环端口'));
        });
      });
    });
    if (!excludePorts.has(port)) return port;
  }
  throw new Error('无法为私有内核分配可用的内部回环端口');
}
