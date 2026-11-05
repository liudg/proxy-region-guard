import * as esbuild from 'esbuild';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

export function getElectronEsbuildOptions() {
  const outDir = path.join(rootDir, 'dist-electron');
  fs.mkdirSync(outDir, { recursive: true });

  return {
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
  };
}

export function syncBundledMmdb() {
  const srcMmdbFile = path.join(
    rootDir,
    'node_modules',
    '@ip-location-db',
    'geolite2-country-mmdb',
    'geolite2-country.mmdb'
  );
  const destResDir = path.join(rootDir, 'resources');
  if (!fs.existsSync(srcMmdbFile)) return;

  fs.mkdirSync(destResDir, { recursive: true });

  // 清理多余的拆分版 mmdb，仅保留统一双栈 geolite2-country.mmdb
  for (const obsolete of ['geolite2-country-ipv4.mmdb', 'geolite2-country-ipv6.mmdb']) {
    const obsoletePath = path.join(destResDir, obsolete);
    if (fs.existsSync(obsoletePath)) {
      fs.rmSync(obsoletePath, { force: true });
    }
  }

  const destFile = path.join(destResDir, 'geolite2-country.mmdb');
  const srcStat = fs.statSync(srcMmdbFile);
  let needCopy = !fs.existsSync(destFile);
  if (!needCopy) {
    const destStat = fs.statSync(destFile);
    needCopy = srcStat.size !== destStat.size || srcStat.mtimeMs > destStat.mtimeMs;
  }

  if (needCopy) {
    fs.copyFileSync(srcMmdbFile, destFile);
  }
}

export async function buildElectronMain() {
  await esbuild.build(getElectronEsbuildOptions());
  syncBundledMmdb();
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildElectronMain().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
