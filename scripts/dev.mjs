import { spawn } from 'node:child_process';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import { buildElectronMain } from './build-electron.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

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

  await buildElectronMain();

  const electronBin = path.join(
    rootDir,
    'node_modules',
    '.bin',
    process.platform === 'win32' ? 'electron.cmd' : 'electron'
  );

  const env = { ...process.env, VITE_DEV_SERVER_URL: devUrl };
  delete env.ELECTRON_RUN_AS_NODE;

  const child = spawn(electronBin, ['.'], {
    cwd: rootDir,
    env,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });

  child.on('exit', async (code) => {
    await viteServer.close();
    process.exit(code ?? 0);
  });
}

startDev().catch((err) => {
  console.error(err);
  process.exit(1);
});
