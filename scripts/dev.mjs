import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';
import { createServer } from 'vite';
import { getElectronEsbuildOptions, syncBundledMmdb } from './build-electron.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const require = createRequire(import.meta.url);
const electronExePath = require('electron');

async function startDev() {
  const viteServer = await createServer({
    root: rootDir,
    configFile: path.join(rootDir, 'vite.config.ts'),
  });

  await viteServer.listen();
  const address = viteServer.httpServer?.address();
  const port = typeof address === 'object' && address ? address.port : 5179;
  const devUrl = `http://localhost:${port}`;
  console.log(`[Dev] Vite renderer ready at ${devUrl}`);

  syncBundledMmdb();
  const esbuildCtx = await esbuild.context(getElectronEsbuildOptions());
  await esbuildCtx.watch();

  const env = { ...process.env, VITE_DEV_SERVER_URL: devUrl };
  delete env.ELECTRON_RUN_AS_NODE;

  const child = spawn(electronExePath, ['.'], {
    cwd: rootDir,
    env,
    stdio: 'inherit',
    shell: false,
  });

  child.on('exit', async (code) => {
    await esbuildCtx.dispose();
    await viteServer.close();
    process.exit(code ?? 0);
  });
}

startDev().catch((err) => {
  console.error(err);
  process.exit(1);
});
