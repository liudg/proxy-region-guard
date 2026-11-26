import * as crypto from 'node:crypto';
import * as path from 'node:path';
import { GuardEventLog, UpdateDeliveryMode } from '../../src/shared/types';
import {
  compareSemver,
  UpdateReleaseManifest,
  validateUpdateManifestStructure,
} from '../../src/shared/updateManifest';
import { downloadFileViaProxy, requestTextViaProxy } from '../net';
import {
  getRawFs,
  validateAsarArchiveHeader,
  verifyUpdateManifestSignature,
} from './updateCrypto';
import {
  gunzipFileWithVerification,
  StagedReadyMetadata,
  UpdateDownloadAttempt,
} from './updateStagingVerifier';
import {
  buildEncodedPowerShellLaunch,
  launchDetachedWindowsUpdater,
} from './windowsPowerShellUpdater';

const rawFs = getRawFs();

const MANIFEST_FETCH_TIMEOUT_MS = 12000;
const ASAR_DOWNLOAD_TIMEOUT_MS = 180000;
const FULL_ZIP_DOWNLOAD_TIMEOUT_MS = 15 * 60 * 1000;

export interface ManifestFetchOutcome {
  manifest: UpdateReleaseManifest | null;
  usedChannel: string;
  sawSecurityRejection: boolean;
  securityRejectionText: string;
  sawStaleMirrorOnly: boolean;
  lastErrText: string;
}

export async function fetchVerifiedUpdateManifest(params: {
  attempts: UpdateDownloadAttempt[];
  publicKey: string;
  allowLocalhostForTest: boolean;
  prevVerifiedManifest: UpdateReleaseManifest | null;
  recordLog: (level: GuardEventLog['level'], message: string, emitImmediately?: boolean) => void;
}): Promise<ManifestFetchOutcome> {
  const { attempts, publicKey, allowLocalhostForTest, prevVerifiedManifest, recordLog } = params;

  let verifiedManifest: UpdateReleaseManifest | null = null;
  let usedChannel = '';
  let sawSecurityRejection = false;
  let securityRejectionText = '';
  let sawStaleMirrorOnly = false;
  let lastErrText = '无法连接更新服务器';

  for (let idx = 0; idx < attempts.length; idx++) {
    const attempt = attempts[idx];
    try {
      const rawText = await requestTextViaProxy(
        attempt.url,
        attempt.proxyUrl,
        MANIFEST_FETCH_TIMEOUT_MS,
        'application/json, text/plain, */*',
        5,
        allowLocalhostForTest
      );
      const parsedJson = JSON.parse(rawText) as unknown;
      const looksLikeManifestObject =
        Boolean(parsedJson) &&
        typeof parsedJson === 'object' &&
        !Array.isArray(parsedJson) &&
        ('schemaVersion' in (parsedJson as Record<string, unknown>) ||
          'asar' in (parsedJson as Record<string, unknown>) ||
          'fullZip' in (parsedJson as Record<string, unknown>) ||
          'signature' in (parsedJson as Record<string, unknown>));

      let manifest: UpdateReleaseManifest;
      try {
        manifest = validateUpdateManifestStructure(parsedJson, allowLocalhostForTest);
      } catch (structErr) {
        const structMsg = structErr instanceof Error ? structErr.message : String(structErr);
        const rawSchemaVer = looksLikeManifestObject
          ? (parsedJson as Record<string, unknown>).schemaVersion
          : undefined;
        const isUnsupportedFutureSchema = typeof rawSchemaVer === 'number' && rawSchemaVer > 1;
        if (looksLikeManifestObject && !isUnsupportedFutureSchema) {
          sawSecurityRejection = true;
          securityRejectionText = `更新清单安全校验未通过，已拦截可疑数据（${structMsg}）`;
          lastErrText = securityRejectionText;
          if (idx < attempts.length - 1) {
            recordLog(
              'warn',
              `通道 [${attempt.label}] 返回异常更新清单已被安全拦截（${structMsg}），正在切换备用通道`,
              false
            );
          }
          continue;
        }
        throw structErr;
      }

      if (!verifyUpdateManifestSignature(manifest, publicKey)) {
        sawSecurityRejection = true;
        securityRejectionText = '更新清单 Ed25519 数字签名校验失败，已拒绝加载以防篡改';
        lastErrText = securityRejectionText;
        if (idx < attempts.length - 1) {
          recordLog(
            'warn',
            `通道 [${attempt.label}] 更新清单 Ed25519 签名校验失败，已拦截并切换备用通道`,
            false
          );
        }
        continue;
      }

      // 防镜像陈旧缓存回退：若本地已持有更高版本验签清单，拒绝被滞后的镜像清单降级覆盖
      if (
        attempt.isMirror &&
        prevVerifiedManifest &&
        compareSemver(manifest.version, prevVerifiedManifest.version) < 0
      ) {
        sawStaleMirrorOnly = true;
        lastErrText = `镜像节点缓存尚未刷新 (镜像返回 v${manifest.version} < 已发现 v${prevVerifiedManifest.version})`;
        continue;
      }

      verifiedManifest = manifest;
      usedChannel = attempt.label;
      break;
    } catch (err) {
      lastErrText = err instanceof Error ? err.message : String(err);
    }
  }

  return {
    manifest: verifiedManifest,
    usedChannel,
    sawSecurityRejection,
    securityRejectionText,
    sawStaleMirrorOnly,
    lastErrText,
  };
}

async function downloadSingleVerifiedFile(params: {
  attempts: UpdateDownloadAttempt[];
  destPath: string;
  expectedSize: number;
  expectedSha256: string;
  timeoutMs: number;
  progressOffsetBytes: number;
  overallTotalBytes: number;
  allowLocalhostForTest: boolean;
  onProgress: (downloadedBytes: number, progressPercent: number | null) => void;
}): Promise<string> {
  const {
    attempts,
    destPath,
    expectedSize,
    expectedSha256,
    timeoutMs,
    progressOffsetBytes,
    overallTotalBytes,
    allowLocalhostForTest,
    onProgress,
  } = params;

  let lastErr = '下载连接失败';

  for (let idx = 0; idx < attempts.length; idx++) {
    const attempt = attempts[idx];
    const attemptTmpPath = `${destPath}.attempt-${idx}-${Date.now()}.tmp`;
    try {
      const res = await downloadFileViaProxy({
        targetUrl: attempt.url,
        proxyUrl: attempt.proxyUrl,
        destFilePath: attemptTmpPath,
        timeoutMs,
        maxBytes: expectedSize + 4096,
        allowLocalhost: allowLocalhostForTest,
        onProgress: (curBytes) => {
          const downloadedBytes = Math.min(overallTotalBytes, progressOffsetBytes + curBytes);
          const progressPercent =
            overallTotalBytes > 0
              ? Math.min(99, Math.round((downloadedBytes / overallTotalBytes) * 100))
              : null;
          onProgress(downloadedBytes, progressPercent);
        },
      });

      if (res.size !== expectedSize) {
        throw new Error(`文件字节数不匹配 (${res.size} != ${expectedSize})`);
      }
      if (res.sha256 !== expectedSha256.toLowerCase()) {
        throw new Error('下载文件 SHA-256 哈希与签名清单不一致');
      }
      if (rawFs.existsSync(destPath)) {
        await rawFs.promises.rm(destPath, { force: true });
      }
      await rawFs.promises.rename(attemptTmpPath, destPath);
      return attempt.label;
    } catch (err) {
      lastErr = err instanceof Error ? err.message : String(err);
      try {
        if (rawFs.existsSync(attemptTmpPath)) {
          await rawFs.promises.rm(attemptTmpPath, { force: true });
        }
      } catch {
        // ignore
      }
    }
  }

  throw new Error(lastErr);
}

export async function downloadAndStageVerifiedUpdate(params: {
  manifest: UpdateReleaseManifest;
  deliveryMode: UpdateDeliveryMode;
  includeMmdbUpdate: boolean;
  expectedBytes: number;
  stageDir: string;
  initialChannel: string;
  allowLocalhostForTest: boolean;
  buildDownloadAttempts: (rawUrl: string) => Promise<UpdateDownloadAttempt[]>;
  onProgress: (downloadedBytes: number, progressPercent: number | null) => void;
}): Promise<{ channelUsed: string }> {
  const {
    manifest,
    deliveryMode,
    includeMmdbUpdate,
    expectedBytes,
    stageDir,
    initialChannel,
    allowLocalhostForTest,
    buildDownloadAttempts,
    onProgress,
  } = params;

  await rawFs.promises.rm(stageDir, { recursive: true, force: true });
  await rawFs.promises.mkdir(stageDir, { recursive: true });

  let channelUsed = initialChannel;

  if (deliveryMode === 'asar') {
    const asarGzPath = path.join(stageDir, 'app-payload.gz.part');
    const stagedAsarPath = path.join(stageDir, 'app-payload.bin');

    channelUsed = await downloadSingleVerifiedFile({
      attempts: await buildDownloadAttempts(manifest.asar.url),
      destPath: asarGzPath,
      expectedSize: manifest.asar.size,
      expectedSha256: manifest.asar.sha256,
      timeoutMs: ASAR_DOWNLOAD_TIMEOUT_MS,
      progressOffsetBytes: 0,
      overallTotalBytes: expectedBytes,
      allowLocalhostForTest,
      onProgress,
    });

    await gunzipFileWithVerification(
      asarGzPath,
      stagedAsarPath,
      manifest.asar.uncompressedSize,
      manifest.asar.uncompressedSha256
    );
    await rawFs.promises.rm(asarGzPath, { force: true });
    await validateAsarArchiveHeader(stagedAsarPath);

    if (includeMmdbUpdate && manifest.mmdb) {
      const mmdbGzPath = path.join(stageDir, 'mmdb.gz.part');
      const stagedMmdbPath = path.join(stageDir, 'geolite2-country.mmdb.staged');

      channelUsed = await downloadSingleVerifiedFile({
        attempts: await buildDownloadAttempts(manifest.mmdb.url),
        destPath: mmdbGzPath,
        expectedSize: manifest.mmdb.size,
        expectedSha256: manifest.mmdb.sha256,
        timeoutMs: ASAR_DOWNLOAD_TIMEOUT_MS,
        progressOffsetBytes: manifest.asar.size,
        overallTotalBytes: expectedBytes,
        allowLocalhostForTest,
        onProgress,
      });

      await gunzipFileWithVerification(
        mmdbGzPath,
        stagedMmdbPath,
        manifest.mmdb.uncompressedSize,
        manifest.mmdb.uncompressedSha256
      );
      await rawFs.promises.rm(mmdbGzPath, { force: true });
    }

    const readyMeta: StagedReadyMetadata = {
      version: manifest.version,
      deliveryMode: 'asar',
      includeMmdbUpdate,
      asarSha256: manifest.asar.uncompressedSha256,
      mmdbSha256:
        includeMmdbUpdate && manifest.mmdb ? manifest.mmdb.uncompressedSha256 : undefined,
      verifiedAt: Date.now(),
    };
    await rawFs.promises.writeFile(
      path.join(stageDir, 'ready.json'),
      JSON.stringify(readyMeta, null, 2),
      'utf-8'
    );
  } else {
    const stagedZipPath = path.join(stageDir, 'release.zip.staged');
    channelUsed = await downloadSingleVerifiedFile({
      attempts: await buildDownloadAttempts(manifest.fullZip.url),
      destPath: stagedZipPath,
      expectedSize: manifest.fullZip.size,
      expectedSha256: manifest.fullZip.sha256,
      timeoutMs: FULL_ZIP_DOWNLOAD_TIMEOUT_MS,
      progressOffsetBytes: 0,
      overallTotalBytes: expectedBytes,
      allowLocalhostForTest,
      onProgress,
    });

    const readyMeta: StagedReadyMetadata = {
      version: manifest.version,
      deliveryMode: 'full-zip',
      includeMmdbUpdate: false,
      zipSha256: manifest.fullZip.sha256,
      verifiedAt: Date.now(),
    };
    await rawFs.promises.writeFile(
      path.join(stageDir, 'ready.json'),
      JSON.stringify(readyMeta, null, 2),
      'utf-8'
    );
  }

  return { channelUsed };
}

export async function launchStagedWindowsUpdater(params: {
  manifest: UpdateReleaseManifest;
  mode: UpdateDeliveryMode;
  includeMmdb: boolean;
  stageDir: string;
  stagingRootDir: string;
  appDir: string;
  resourcesDir: string;
  exePath: string;
  currentVersion: string;
  targetPid: number;
  bootHandshakeTimeoutMs: number;
  waitExitAttemptsOverride?: number;
  prepareForUpdate: () => Promise<void>;
  resumeAfterUpdateFailure: () => Promise<void>;
}): Promise<void> {
  const {
    manifest,
    mode,
    includeMmdb,
    stageDir,
    stagingRootDir,
    appDir,
    resourcesDir,
    exePath,
    currentVersion,
    targetPid,
    bootHandshakeTimeoutMs,
    waitExitAttemptsOverride,
    prepareForUpdate,
    resumeAfterUpdateFailure,
  } = params;

  const stagedAsar = path.join(stageDir, 'app-payload.bin');
  const stagedMmdb =
    includeMmdb && manifest.mmdb
      ? path.join(stageDir, 'geolite2-country.mmdb.staged')
      : '';
  const stagedZip = path.join(stageDir, 'release.zip.staged');

  // 将就绪握手标记置于 stageDir 之外，防止任何暂存目录清理操作误删握手文件导致误判超时回滚
  const readyHandshakeFile = path.join(
    stagingRootDir,
    `boot-ready-${manifest.version}-${targetPid}.ok`
  );
  const diagnosticFile = path.join(
    stagingRootDir,
    `update-${manifest.version}-${crypto.randomUUID()}.jsonl`
  );
  rawFs.writeFileSync(diagnosticFile, '', { encoding: 'utf8', flag: 'wx' });

  const { encodedCommand, scriptGzB64 } = buildEncodedPowerShellLaunch();

  const updaterEnv: Record<string, string> = {
    GUARD_UPD_SCRIPT_GZ: scriptGzB64,
    GUARD_UPD_PID: String(targetPid),
    GUARD_UPD_MODE: mode,
    GUARD_UPD_APP_DIR: appDir,
    GUARD_UPD_RES_DIR: resourcesDir,
    GUARD_UPD_EXE_PATH: exePath,
    GUARD_UPD_FROM_VER: currentVersion,
    GUARD_UPD_TO_VER: manifest.version,
    GUARD_UPD_STAGED_ASAR: stagedAsar,
    GUARD_UPD_STAGED_MMDB: stagedMmdb,
    GUARD_UPD_STAGED_ZIP: stagedZip,
    GUARD_UPD_ASAR_SHA256:
      mode === 'asar' ? manifest.asar.uncompressedSha256.toLowerCase() : '',
    GUARD_UPD_MMDB_SHA256:
      mode === 'asar' && includeMmdb && manifest.mmdb
        ? manifest.mmdb.uncompressedSha256.toLowerCase()
        : '',
    GUARD_UPD_ZIP_SHA256:
      mode === 'full-zip' ? manifest.fullZip.sha256.toLowerCase() : '',
    GUARD_UPD_STAGE_DIR: stageDir,
    GUARD_UPD_READY_FILE: readyHandshakeFile,
    GUARD_UPD_DIAGNOSTIC_FILE: diagnosticFile,
    GUARD_UPD_BOOT_CHECK_MS: String(bootHandshakeTimeoutMs),
  };
  if (waitExitAttemptsOverride !== undefined) {
    updaterEnv.GUARD_UPD_WAIT_EXIT_ATTEMPTS = String(waitExitAttemptsOverride);
  }

  try {
    await prepareForUpdate();
    await launchDetachedWindowsUpdater(encodedCommand, updaterEnv);
  } catch (error) {
    await resumeAfterUpdateFailure();
    throw error;
  }
}
