import * as crypto from 'node:crypto';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { UpdateDeliveryMode } from '../../src/shared/types';
import {
  compareSemver,
  DEFAULT_GITHUB_MIRROR_PREFIXES,
  normalizeSemverString,
  UpdateReleaseManifest,
} from '../../src/shared/updateManifest';
import { computeFileSha256, getRawFs, validateAsarArchiveHeader } from './updateCrypto';

export interface StagedReadyMetadata {
  version: string;
  deliveryMode: UpdateDeliveryMode;
  includeMmdbUpdate: boolean;
  asarSha256?: string;
  mmdbSha256?: string;
  zipSha256?: string;
  verifiedAt: number;
}

export interface UpdateDownloadAttempt {
  url: string;
  proxyUrl: string | null;
  label: string;
  isMirror: boolean;
}

export async function gunzipFileWithVerification(
  gzFilePath: string,
  destFilePath: string,
  expectedUncompressedSize: number,
  expectedUncompressedSha256: string
): Promise<void> {
  const rawFs = getRawFs();
  await rawFs.promises.mkdir(path.dirname(destFilePath), { recursive: true });

  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const hash = crypto.createHash('sha256');
    let writtenBytes = 0;
    const maxAllowedBytes = expectedUncompressedSize + 1024;

    const rs = rawFs.createReadStream(gzFilePath);
    const gunzip = zlib.createGunzip();
    const ws = rawFs.createWriteStream(destFilePath, { flags: 'w' });

    const removeDestBestEffort = () => {
      try {
        if (rawFs.existsSync(destFilePath)) {
          rawFs.rmSync(destFilePath, { force: true });
        }
      } catch {
        // ignore
      }
    };

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      rs.destroy();
      gunzip.destroy();
      ws.once('close', removeDestBestEffort);
      ws.destroy();
      reject(err);
    };

    gunzip.on('data', (chunk: Buffer) => {
      writtenBytes += chunk.length;
      if (writtenBytes > maxAllowedBytes) {
        fail(new Error('解压数据超出签名声明体积，已终止解压'));
        return;
      }
      hash.update(chunk);
    });

    rs.on('error', fail);
    gunzip.on('error', (err) => fail(new Error(`解压更新包失败: ${err.message}`)));
    ws.on('error', fail);

    ws.on('close', () => {
      if (settled) return;
      settled = true;
      if (writtenBytes !== expectedUncompressedSize) {
        removeDestBestEffort();
        reject(
          new Error(
            `解压后体积不匹配 (实际 ${writtenBytes} 字节，预期 ${expectedUncompressedSize} 字节)`
          )
        );
        return;
      }
      const actualSha = hash.digest('hex').toLowerCase();
      if (actualSha !== expectedUncompressedSha256.toLowerCase()) {
        removeDestBestEffort();
        reject(new Error('解压后文件 SHA-256 校验不一致，已拦截损坏文件'));
        return;
      }
      resolve();
    });

    rs.pipe(gunzip).pipe(ws);
  });
}

export function buildUpdateDownloadAttempts(
  rawUrl: string,
  proxies: ReadonlyArray<{ proxyUrl: string | null; label: string }>,
  useMirror: boolean,
  appendCacheBuster = false
): UpdateDownloadAttempt[] {
  const withCacheBust = (u: string): string => {
    if (!appendCacheBuster) return u;
    const sep = u.includes('?') ? '&' : '?';
    return `${u}${sep}_t=${Math.floor(Date.now() / 30000)}`;
  };

  const attempts: UpdateDownloadAttempt[] = [];

  // 1. 优先通过已识别代理或直连访问原始 GitHub 地址
  for (const p of proxies) {
    attempts.push({
      url: withCacheBust(rawUrl),
      proxyUrl: p.proxyUrl,
      label: p.label,
      isMirror: false,
    });
  }

  // 2. 开启镜像兜底且目标是 GitHub 官方地址时，追加镜像通道（全程受 Ed25519 公钥签名保护）
  if (useMirror && rawUrl.startsWith('https://github.com/')) {
    const firstLocalProxy = proxies.find((p) => p.proxyUrl !== null) || null;
    for (const prefix of DEFAULT_GITHUB_MIRROR_PREFIXES) {
      const mirroredUrl = withCacheBust(`${prefix}${rawUrl}`);
      attempts.push({
        url: mirroredUrl,
        proxyUrl: null,
        label: `GitHub 加速镜像 (${new URL(prefix).host})`,
        isMirror: true,
      });
      if (firstLocalProxy) {
        attempts.push({
          url: mirroredUrl,
          proxyUrl: firstLocalProxy.proxyUrl,
          label: `GitHub 加速镜像经代理 (${new URL(prefix).host})`,
          isMirror: true,
        });
      }
    }
  }

  return attempts;
}

export async function decideDeliveryAndMmdb(options: {
  manifest: UpdateReleaseManifest;
  isPackaged: boolean;
  electronVersion: string;
  nativeShellVersion: string;
  resourcesDir: string;
}): Promise<{
  deliveryMode: UpdateDeliveryMode;
  includeMmdbUpdate: boolean;
  expectedBytes: number;
}> {
  const { manifest, isPackaged, electronVersion, nativeShellVersion, resourcesDir } = options;
  const rawFs = getRawFs();
  let localAsarExists = false;
  try {
    const st = rawFs.statSync(path.join(resourcesDir, 'app.asar'));
    localAsarExists = st.isFile();
  } catch {
    localAsarExists = false;
  }
  const canUseAsarHotUpdate =
    isPackaged &&
    localAsarExists &&
    manifest.electronVersion === electronVersion &&
    compareSemver(nativeShellVersion, manifest.minNativeShellVersion) >= 0 &&
    rawFs.existsSync(path.join(resourcesDir, 'mihomo', 'guard-mihomo.exe')) &&
    (await computeFileSha256(path.join(resourcesDir, 'mihomo', 'guard-mihomo.exe'))).sha256 ===
      manifest.mihomo.sha256;

  if (!canUseAsarHotUpdate && isPackaged) {
    return {
      deliveryMode: 'full-zip',
      includeMmdbUpdate: false,
      expectedBytes: manifest.fullZip.size,
    };
  }

  // 开发模式下展示增量包信息供预览（不会覆盖本地源码）
  if (!isPackaged) {
    const mode: UpdateDeliveryMode =
      manifest.electronVersion === electronVersion ? 'asar' : 'full-zip';
    return {
      deliveryMode: mode,
      includeMmdbUpdate: false,
      expectedBytes: mode === 'asar' ? manifest.asar.size : manifest.fullZip.size,
    };
  }

  let needMmdb = false;
  if (manifest.mmdb) {
    const localMmdbPath = path.join(resourcesDir, 'geolite2-country.mmdb');
    if (!rawFs.existsSync(localMmdbPath)) {
      needMmdb = true;
    } else {
      try {
        const { sha256 } = await computeFileSha256(localMmdbPath);
        needMmdb = sha256 !== manifest.mmdb.uncompressedSha256.toLowerCase();
      } catch {
        needMmdb = true;
      }
    }
  }

  const totalBytes = manifest.asar.size + (needMmdb && manifest.mmdb ? manifest.mmdb.size : 0);

  return {
    deliveryMode: 'asar',
    includeMmdbUpdate: needMmdb,
    expectedBytes: totalBytes,
  };
}

export async function isStagedUpdateAlreadyVerified(
  stageDir: string,
  manifest: UpdateReleaseManifest,
  deliveryMode: UpdateDeliveryMode,
  includeMmdbUpdate: boolean
): Promise<boolean> {
  const rawFs = getRawFs();
  const readyFile = path.join(stageDir, 'ready.json');
  if (!rawFs.existsSync(readyFile)) return false;

  try {
    const meta = JSON.parse(
      await rawFs.promises.readFile(readyFile, 'utf-8')
    ) as StagedReadyMetadata;
    if (meta.version !== manifest.version || meta.deliveryMode !== deliveryMode) {
      return false;
    }

    if (deliveryMode === 'asar') {
      const stagedAsar = path.join(stageDir, 'app-payload.bin');
      if (!rawFs.existsSync(stagedAsar)) return false;
      const asarHash = await computeFileSha256(stagedAsar);
      if (
        asarHash.size !== manifest.asar.uncompressedSize ||
        asarHash.sha256 !== manifest.asar.uncompressedSha256.toLowerCase()
      ) {
        return false;
      }
      await validateAsarArchiveHeader(stagedAsar);

      if (includeMmdbUpdate && manifest.mmdb) {
        const stagedMmdb = path.join(stageDir, 'geolite2-country.mmdb.staged');
        if (!rawFs.existsSync(stagedMmdb)) return false;
        const mmdbHash = await computeFileSha256(stagedMmdb);
        if (
          mmdbHash.size !== manifest.mmdb.uncompressedSize ||
          mmdbHash.sha256 !== manifest.mmdb.uncompressedSha256.toLowerCase()
        ) {
          return false;
        }
      }
      return true;
    }

    const stagedZip = path.join(stageDir, 'release.zip.staged');
    if (!rawFs.existsSync(stagedZip)) return false;
    const zipHash = await computeFileSha256(stagedZip);
    return (
      zipHash.size === manifest.fullZip.size &&
      zipHash.sha256 === manifest.fullZip.sha256.toLowerCase()
    );
  } catch {
    return false;
  }
}

export async function cleanupObsoleteStagingDirs(
  stagingRootDir: string,
  currentVersion: string
): Promise<void> {
  const rawFs = getRawFs();
  try {
    if (!rawFs.existsSync(stagingRootDir)) return;
    const entries = await rawFs.promises.readdir(stagingRootDir, {
      withFileTypes: true,
    });
    const now = Date.now();
    for (const entry of entries) {
      const fullEntryPath = path.join(stagingRootDir, entry.name);
      if (entry.isDirectory() && entry.name.startsWith('v-')) {
        const ver = normalizeSemverString(entry.name.slice(2));
        if (!ver || compareSemver(ver, currentVersion) <= 0) {
          await rawFs.promises.rm(fullEntryPath, {
            recursive: true,
            force: true,
          });
        }
      } else if (
        entry.isFile() &&
        entry.name.startsWith('boot-ready-') &&
        entry.name.endsWith('.ok')
      ) {
        try {
          const stat = await rawFs.promises.stat(fullEntryPath);
          if (now - stat.mtimeMs > 60_000) {
            await rawFs.promises.rm(fullEntryPath, { force: true });
          }
        } catch {
          // ignore
        }
      }
    }
  } catch {
    // ignore cleanup error
  }
}
