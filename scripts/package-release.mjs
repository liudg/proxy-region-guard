import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build as viteBuild } from 'vite';
import { buildElectronMain } from './build-electron.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function stampExeResourcesWithRetry(destExe, icoPath, maxAttempts = 3) {
  const rceditMod = await import('rcedit');
  const rcedit = rceditMod.rcedit || rceditMod.default;
  if (typeof rcedit !== 'function') {
    throw new Error('rcedit 模块未正确导出可执行函数');
  }

  let lastErr = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await rcedit(destExe, {
        icon: icoPath,
        'requested-execution-level': 'requireAdministrator',
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
      return;
    } catch (err) {
      lastErr = err;
      if (attempt < maxAttempts) {
        // 等待杀毒软件实时文件扫描释放句柄后重试
        await sleep(350 * attempt);
      }
    }
  }
  throw lastErr;
}

async function main() {
  const icoPath = path.join(rootDir, 'build', 'icon.ico');
  if (!fs.existsSync(icoPath)) {
    throw new Error(`未找到应用图标资源: ${icoPath}`);
  }

  console.log('1/5 正在编译前后端生产代码...');
  await buildElectronMain();
  await viteBuild({
    root: rootDir,
    configFile: path.join(rootDir, 'vite.config.ts'),
  });

  console.log('2/5 正在组装 Windows x64 正式发布目录...');
  const releaseRoot = path.join(rootDir, 'release');
  const appOutDir = path.join(releaseRoot, '代理地区卫士-win32-x64');

  try {
    execFileSync('taskkill.exe', ['/F', '/IM', '代理地区卫士.exe'], {
      stdio: 'ignore',
      windowsHide: true,
    });
    await sleep(350);
  } catch {
    // 忽略未运行时的返回码
  }

  const srcExe = path.join(appOutDir, 'electron.exe');
  const destExe = path.join(appOutDir, '代理地区卫士.exe');

  if (fs.existsSync(destExe)) {
    try {
      const fd = fs.openSync(destExe, 'r+');
      fs.closeSync(fd);
    } catch {
      throw new Error(
        '检测到「代理地区卫士.exe」正在以管理员权限运行且无法从当前非管理员终端自动关闭。请先手动退出运行中的「代理地区卫士」，或以管理员身份运行 npm run package。'
      );
    }
  }

  if (fs.existsSync(appOutDir)) {
    fs.rmSync(appOutDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 150 });
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

  console.log('3/5 正在打包应用核心代码 (app.asar) 与离线 GeoIP 数据库...');
  const stageDir = path.join(releaseRoot, '.stage-app');
  if (fs.existsSync(stageDir)) {
    fs.rmSync(stageDir, { recursive: true, force: true });
  }
  fs.mkdirSync(path.join(stageDir, 'dist-electron'), { recursive: true });

  const prodPkg = {
    name: 'proxy-region-guard',
    productName: '代理地区卫士',
    version: '1.0.0',
    description: 'Windows 代理 IP 地区变更实时检测与强提醒工具',
    main: 'dist-electron/main.js',
  };
  fs.writeFileSync(path.join(stageDir, 'package.json'), JSON.stringify(prodPkg, null, 2), 'utf-8');

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
  const asar = await import('@electron/asar');
  await asar.createPackage(stageDir, path.join(targetResourcesDir, 'app.asar'));
  fs.rmSync(stageDir, { recursive: true, force: true });

  const mmdbSrc = path.join(rootDir, 'resources', 'geolite2-country.mmdb');
  if (!fs.existsSync(mmdbSrc)) {
    throw new Error(`未找到离线 GeoIP 数据库: ${mmdbSrc}`);
  }
  fs.copyFileSync(mmdbSrc, path.join(targetResourcesDir, 'geolite2-country.mmdb'));

  console.log('4/5 正在写入可执行文件名称与图标元数据...');
  fs.renameSync(srcExe, destExe);
  await stampExeResourcesWithRetry(destExe, icoPath);

  const zipName = `代理地区卫士-v${prodPkg.version}-win32-x64.zip`;
  const zipPath = path.join(releaseRoot, zipName);
  console.log(`5/5 正在压缩生成分发压缩包 (${zipName})...`);
  try {
    if (fs.existsSync(zipPath)) {
      fs.rmSync(zipPath, { force: true });
    }
    execFileSync('tar.exe', ['-a', '-cf', zipName, path.basename(appOutDir)], {
      cwd: releaseRoot,
      stdio: 'inherit',
      windowsHide: true,
    });
    console.log(`📦 压缩分发包已输出: ${zipPath}`);
  } catch (e) {
    console.warn(`⚠️ 自动压缩分发包失败 (可手动压缩): ${e.message}`);
  }

  console.log(`\n✅ 正式发布包打包完成！\n程序目录: ${appOutDir}\n可执行文件: ${destExe}\n发布压缩包: ${zipPath}`);
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

main().catch((err) => {
  console.error('\n❌ 打包失败:', err);
  process.exit(1);
});
