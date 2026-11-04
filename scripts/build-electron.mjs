import * as esbuild from 'esbuild';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

export async function buildElectronMain() {
  const outDir = path.join(rootDir, 'dist-electron');
  fs.mkdirSync(outDir, { recursive: true });

  await esbuild.build({
    entryPoints: [
      path.join(rootDir, 'electron', 'main.ts'),
      path.join(rootDir, 'electron', 'preload.ts'),
    ],
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    outdir: outDir,
    external: ['electron'],
    sourcemap: true,
    logLevel: 'info',
  });

  // 确保离线 mmdb 文件同步到 resources/ 目录，方便后续打包或独立分发
  const srcMmdbDir = path.join(
    rootDir,
    'node_modules',
    '@ip-location-db',
    'geolite2-country-mmdb'
  );
  const destResDir = path.join(rootDir, 'resources');
  if (fs.existsSync(srcMmdbDir)) {
    fs.mkdirSync(destResDir, { recursive: true });
    for (const file of fs.readdirSync(srcMmdbDir)) {
      if (file.endsWith('.mmdb')) {
        const destFile = path.join(destResDir, file);
        if (!fs.existsSync(destFile)) {
          fs.copyFileSync(path.join(srcMmdbDir, file), destFile);
        }
      }
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildElectronMain().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
