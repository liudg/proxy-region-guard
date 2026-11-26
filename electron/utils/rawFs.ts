import * as fs from 'node:fs';

export function getRawFs(): typeof fs {
  if (process.versions && process.versions.electron) {
    try {
      // Electron 主进程中 node:fs 会将 *.asar 拦截为虚拟目录，必须使用 original-fs 读写归档原始字节
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      return require('original-fs') as typeof fs;
    } catch {
      return fs;
    }
  }
  return fs;
}
