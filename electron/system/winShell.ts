import * as path from 'node:path';
import { getRawFs } from '../utils/rawFs';

export function resolveWindowsPowerShellExe(): string {
  const rawFs = getRawFs();
  const sysRoot = process.env.SystemRoot || process.env.WINDIR;
  if (sysRoot) {
    const candidate = path.join(
      sysRoot,
      'System32',
      'WindowsPowerShell',
      'v1.0',
      'powershell.exe'
    );
    if (rawFs.existsSync(candidate)) {
      return candidate;
    }
  }
  return 'powershell.exe';
}

export function quoteWindowsArg(value: string): string {
  if (value.length === 0) return '""';
  if (!/[\s"]/.test(value)) return value;
  const escaped = value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/g, '$1$1');
  return `"${escaped}"`;
}

export function quoteWindowsCommandLine(args: readonly string[]): string {
  return args.map(quoteWindowsArg).join(' ');
}
