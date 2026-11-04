import * as fs from 'node:fs';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { build as viteBuild } from 'vite';
import { buildElectronMain } from './build-electron.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

async function main() {
  console.log('1/5 正在编译前后端生产代码...');
  await buildElectronMain();
  await viteBuild({
    root: rootDir,
    configFile: path.join(rootDir, 'vite.config.ts'),
  });

  console.log('2/5 正在生成高清多尺寸应用图标 (.ico)...');
  const buildAssetsDir = path.join(rootDir, 'build');
  fs.mkdirSync(buildAssetsDir, { recursive: true });
  const icoPath = path.join(buildAssetsDir, 'icon.ico');
  fs.writeFileSync(icoPath, generateAppIcoBuffer());

  console.log('3/5 正在组装 Windows x64 正式发布目录...');
  const releaseRoot = path.join(rootDir, 'release');
  const appOutDir = path.join(releaseRoot, '代理地区卫士-win32-x64');

  if (fs.existsSync(appOutDir)) {
    fs.rmSync(appOutDir, { recursive: true, force: true });
  }
  fs.mkdirSync(appOutDir, { recursive: true });

  const electronDistDir = path.join(rootDir, 'node_modules', 'electron', 'dist');
  copyDirFiltered(electronDistDir, appOutDir);

  // 移除默认占位应用包
  const defaultAsar = path.join(appOutDir, 'resources', 'default_app.asar');
  if (fs.existsSync(defaultAsar)) {
    fs.rmSync(defaultAsar, { force: true });
  }

  // 精简多语言包，仅保留简体中文与美式英语，减小约 35MB 体积
  const localesDir = path.join(appOutDir, 'locales');
  if (fs.existsSync(localesDir)) {
    const keepLocales = new Set(['zh-CN.pak', 'en-US.pak']);
    for (const f of fs.readdirSync(localesDir)) {
      if (!keepLocales.has(f)) {
        fs.rmSync(path.join(localesDir, f), { force: true });
      }
    }
  }

  console.log('4/5 正在打包应用核心代码 (app.asar) 与离线 GeoIP 数据库...');
  const stageDir = path.join(releaseRoot, '.stage-app');
  if (fs.existsSync(stageDir)) {
    fs.rmSync(stageDir, { recursive: true, force: true });
  }
  fs.mkdirSync(path.join(stageDir, 'dist-electron'), { recursive: true });

  // 写入精简生产 package.json
  const prodPkg = {
    name: 'proxy-region-guard',
    productName: '代理地区卫士',
    version: '1.0.0',
    description: 'Windows 代理 IP 地区变更实时检测与强提醒工具',
    main: 'dist-electron/main.js',
  };
  fs.writeFileSync(path.join(stageDir, 'package.json'), JSON.stringify(prodPkg, null, 2), 'utf-8');

  // 拷贝编译产物（不含 sourcemap）
  fs.copyFileSync(
    path.join(rootDir, 'dist-electron', 'main.js'),
    path.join(stageDir, 'dist-electron', 'main.js')
  );
  fs.copyFileSync(
    path.join(rootDir, 'dist-electron', 'preload.js'),
    path.join(stageDir, 'dist-electron', 'preload.js')
  );
  copyDirFiltered(path.join(rootDir, 'dist'), path.join(stageDir, 'dist'));

  const targetResourcesDir = path.join(appOutDir, 'resources');
  try {
    const asar = await import('@electron/asar');
    await asar.createPackage(stageDir, path.join(targetResourcesDir, 'app.asar'));
  } catch {
    copyDirFiltered(stageDir, path.join(targetResourcesDir, 'app'));
  }
  fs.rmSync(stageDir, { recursive: true, force: true });

  // 放置内置离线 GeoIP 数据库到 resources/ 根目录
  const mmdbSrc = path.join(rootDir, 'resources', 'geolite2-country.mmdb');
  if (fs.existsSync(mmdbSrc)) {
    fs.copyFileSync(mmdbSrc, path.join(targetResourcesDir, 'geolite2-country.mmdb'));
  }

  console.log('5/5 正在写入可执行文件名称与图标资源...');
  const srcExe = path.join(appOutDir, 'electron.exe');
  const destExe = path.join(appOutDir, '代理地区卫士.exe');
  fs.renameSync(srcExe, destExe);

  try {
    const rceditMod = await import('rcedit');
    const rcedit = rceditMod.rcedit || rceditMod.default;
    if (typeof rcedit === 'function') {
      await rcedit(destExe, {
        icon: icoPath,
        'version-string': {
          ProductName: '代理地区卫士',
          FileDescription: '代理地区卫士 - 代理 IP 地区变更检测工具',
          CompanyName: 'Proxy Region Guard',
          InternalName: 'ProxyRegionGuard',
          OriginalFilename: '代理地区卫士.exe',
        },
        'file-version': '1.0.0',
        'product-version': '1.0.0',
      });
    }
  } catch (err) {
    console.warn('[Package] rcedit metadata stamp skipped:', err?.message || err);
  }

  console.log(`\n✅ 正式包构建成功！输出路径：\n${destExe}`);
}

function copyDirFiltered(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (entry.name.endsWith('.pdb') || entry.name === 'LICENSES.chromium.html') {
      continue;
    }
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDirFiltered(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// 生成包含 16/32/48/256 四档高清 PNG 帧的标准 Windows .ico
function generateAppIcoBuffer() {
  const sizes = [16, 32, 48, 256];
  const pngBuffers = sizes.map((s) => renderAppIconPng(s));

  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // type 1 = ICO
  header.writeUInt16LE(sizes.length, 4);

  const dirEntries = [];
  let offset = 6 + sizes.length * 16;

  for (let i = 0; i < sizes.length; i++) {
    const s = sizes[i];
    const png = pngBuffers[i];
    const entry = Buffer.alloc(16);
    entry[0] = s >= 256 ? 0 : s;
    entry[1] = s >= 256 ? 0 : s;
    entry[2] = 0;
    entry[3] = 0;
    entry.writeUInt16LE(1, 4);  // color planes
    entry.writeUInt16LE(32, 6); // bits per pixel
    entry.writeUInt32LE(png.length, 8);
    entry.writeUInt32LE(offset, 12);
    dirEntries.push(entry);
    offset += png.length;
  }

  return Buffer.concat([header, ...dirEntries, ...pngBuffers]);
}

function renderAppIconPng(size) {
  const rgba = new Uint8Array(size * size * 4);
  const cx = (size - 1) / 2;
  const cy = (size - 1) / 2;
  const maxR = size * 0.46;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const idx = (y * size + x) * 4;
      const dx = x - cx;
      const dy = y - cy;
      const dist = Math.hypot(dx, dy);
      if (dist > maxR + 0.8) continue;

      const alpha = dist > maxR - 0.8 ? Math.max(0, Math.min(1, (maxR + 0.8 - dist) / 1.6)) : 1;
      const t = Math.min(1, (x + y) / (size * 1.8));
      // 深邃蓝绿渐变圆标 + 白色对勾盾心
      let r = Math.round(37 * (1 - t) + 16 * t);
      let g = Math.round(99 * (1 - t) + 185 * t);
      let b = Math.round(235 * (1 - t) + 129 * t);

      const nx = (x - cx) / (size * 0.5);
      const ny = (y - cy) / (size * 0.5);
      const d1 = segDist(nx, ny, -0.32, 0.04, -0.06, 0.28);
      const d2 = segDist(nx, ny, -0.06, 0.28, 0.36, -0.22);
      const d = Math.min(d1, d2);
      const stroke = 0.13;
      const feather = Math.max(0.03, 1.5 / size);
      const cov = d <= stroke - feather ? 1 : d >= stroke + feather ? 0 : (stroke + feather - d) / (2 * feather);

      if (cov > 0) {
        r = Math.round(r * (1 - cov) + 255 * cov);
        g = Math.round(g * (1 - cov) + 255 * cov);
        b = Math.round(b * (1 - cov) + 255 * cov);
      }

      rgba[idx] = r;
      rgba[idx + 1] = g;
      rgba[idx + 2] = b;
      rgba[idx + 3] = Math.round(alpha * 255);
    }
  }

  return encodePng(size, size, rgba);
}

function segDist(px, py, x1, y1, x2, y2) {
  const l2 = (x2 - x1) ** 2 + (y2 - y1) ** 2;
  let t = ((px - x1) * (x2 - x1) + (py - y1) * (y2 - y1)) / l2;
  t = Math.max(0, Math.min(1, t));
  return Math.hypot(px - (x1 + t * (x2 - x1)), py - (y1 + t * (y2 - y1)));
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const t = Buffer.from(type, 'ascii');
  const l = Buffer.alloc(4);
  l.writeUInt32BE(data.length, 0);
  const crcIn = Buffer.concat([t, data]);
  const c = Buffer.alloc(4);
  c.writeUInt32BE(crc32(crcIn), 0);
  return Buffer.concat([l, t, data, c]);
}

function encodePng(w, h, rgba) {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const stride = w * 4 + 1;
  const raw = Buffer.alloc(stride * h);
  for (let y = 0; y < h; y++) {
    raw[y * stride] = 0;
    Buffer.from(rgba.buffer, rgba.byteOffset + y * w * 4, w * 4).copy(raw, y * stride + 1);
  }
  return Buffer.concat([
    sig,
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
