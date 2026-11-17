import { build } from 'esbuild';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import electron from 'electron';

const directory = await mkdtemp(path.join(tmpdir(), 'guard-regression-'));
try {
  const entries = process.argv[2] ? [process.argv[2]] : ['tests/regression.ts', 'tests/appIdentity.ts', 'tests/claudeVerificationRecovery.ts'];
  for (const [index, entry] of entries.entries()) {
    const output = path.join(directory, `test-${index}.cjs`);
    await build({
      entryPoints: [entry],
      outfile: output,
      bundle: true,
      platform: 'node',
      target: 'node20',
      format: 'cjs',
      external: ['electron', 'original-fs'],
    });
    const env = {
      ...process.env,
      GUARD_TEST_NODE: process.execPath,
      GUARD_TEST_DATA: path.join(directory, `user-data-${index}`),
    };
    delete env.ELECTRON_RUN_AS_NODE;
    const child = spawn(electron, [output], { stdio: 'inherit', env, windowsHide: true });
    process.exitCode = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', (code) => resolve(code ?? 1));
    });
    if (process.exitCode !== 0) break;
  }
} finally {
  if (path.dirname(path.resolve(directory)) !== path.resolve(tmpdir())) {
    throw new Error('测试临时目录超出预期范围');
  }
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
