import { build } from 'esbuild';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import electron from 'electron';

const directory = await mkdtemp(path.join(tmpdir(), 'guard-regression-'));
try {
  const output = path.join(directory, 'regression.cjs');
  await build({
    entryPoints: ['tests/regression.ts'],
    outfile: output,
    bundle: true,
    platform: 'node',
    format: 'cjs',
    external: ['electron'],
  });
  const env = {
    ...process.env,
    GUARD_TEST_NODE: process.execPath,
    GUARD_TEST_DATA: path.join(directory, 'user-data'),
  };
  delete env.ELECTRON_RUN_AS_NODE;
  const child = spawn(electron, [output], { stdio: 'inherit', env, windowsHide: true });
  process.exitCode = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code) => resolve(code ?? 1));
  });
} finally {
  if (path.dirname(path.resolve(directory)) !== path.resolve(tmpdir())) {
    throw new Error('测试临时目录超出预期范围');
  }
  await rm(directory, { recursive: true });
}
