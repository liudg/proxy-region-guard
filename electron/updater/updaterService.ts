import { app, shell } from 'electron';
import * as path from 'node:path';
import {
  AppStateSnapshot,
  ClaudeLaunchResult,
  GuardEventLog,
  UpdateActionResult,
  UpdateDeliveryMode,
  UpdateStateSnapshot,
  UpdateStatus,
} from '../../src/shared/types';
import {
  BUILTIN_UPDATE_PUBLIC_KEY_SPKI_B64,
  compareSemver,
  DEFAULT_GITHUB_RELEASE_LATEST_JSON_URL,
  DEFAULT_GITHUB_RELEASES_PAGE_URL,
  normalizeSemverString,
  UpdateReleaseManifest,
} from '../../src/shared/updateManifest';
import { ConfigStore } from '../system/configStore';
import { readUpdateFailureReason, recordUpdateBootEvent, writeUpdateReadyFile } from './updateBoot';
import { getRawFs } from './updateCrypto';
import {
  downloadAndStageVerifiedUpdate,
  fetchVerifiedUpdateManifest,
  launchStagedWindowsUpdater,
} from './updateDownloadManager';
import {
  buildUpdateDownloadAttempts,
  cleanupObsoleteStagingDirs,
  decideDeliveryAndMmdb,
  isStagedUpdateAlreadyVerified,
  UpdateDownloadAttempt,
} from './updateStagingVerifier';

const rawFs = getRawFs();

const DEFAULT_STARTUP_CHECK_DELAY_MS = 4000;
const DEFAULT_STARTUP_RETRY_DELAY_MS = 20000;
const DEFAULT_WINDOW_SHOW_COOLDOWN_MS = 30 * 60 * 1000; // 唤起窗口按需检查 30 分钟冷却
const DEFAULT_ERROR_RETRY_COOLDOWN_MS = 2 * 60 * 1000;  // 失败态唤起窗口 2 分钟冷却重试
const POST_UPDATE_BAK_CLEANUP_DELAY_MS = 15000;
const DEFAULT_BOOT_HANDSHAKE_TIMEOUT_MS = 12000;

export interface UpdaterHostAdapter {
  setUpdateStateProvider(provider: () => UpdateStateSnapshot): void;
  getSnapshot(): AppStateSnapshot;
  recordExternalLog(
    level: GuardEventLog['level'],
    message: string,
    emitImmediately?: boolean
  ): void;
  notifyExternalStateChanged(): void;
  resolveUpdateDownloadProxies(
    targetUrl: string
  ): Promise<Array<{ proxyUrl: string | null; label: string }>>;
  isClaudeActiveForUpdateInterlock(): Promise<boolean>;
  terminateClaudeManually(): Promise<ClaudeLaunchResult>;
  prepareForUpdate(): Promise<void>;
  resumeAfterUpdateFailure(): Promise<void>;
  stop(): void;
}

export interface UpdaterServiceOptions {
  configStore: ConfigStore;
  probeEngine: UpdaterHostAdapter;
  onQuitForUpdate?: () => void;
  manifestUrlOverride?: string;
  releasePageUrlOverride?: string;
  publicKeyOverride?: string;
  isPackagedOverride?: boolean;
  currentVersionOverride?: string;
  electronVersionOverride?: string;
  nativeShellVersionOverride?: string;
  appDirOverride?: string;
  resourcesDirOverride?: string;
  exePathOverride?: string;
  stagingRootDirOverride?: string;
  allowLocalhostForTest?: boolean;
  targetPidOverride?: number;
  bootHandshakeTimeoutMsOverride?: number;
  waitExitAttemptsOverride?: number;
  startupCheckDelayMsOverride?: number;
  startupRetryDelayMsOverride?: number;
  windowShowCooldownMsOverride?: number;
  errorRetryCooldownMsOverride?: number;
}

export class UpdaterService {
  private readonly configStore: ConfigStore;
  private readonly host: UpdaterHostAdapter;
  private readonly onQuitForUpdate?: () => void;

  private readonly manifestUrl: string;
  private readonly releasePageUrl: string;
  private readonly publicKey: string;
  private readonly isPackaged: boolean;
  private readonly currentVersion: string;
  private readonly electronVersion: string;
  private readonly nativeShellVersion: string;
  private readonly appDir: string;
  private readonly resourcesDir: string;
  private readonly exePath: string;
  private readonly stagingRootDir: string;
  private readonly allowLocalhostForTest: boolean;
  private readonly targetPidOverride?: number;
  private readonly bootHandshakeTimeoutMs: number;
  private readonly waitExitAttemptsOverride?: number;
  private readonly startupCheckDelayMs: number;
  private readonly startupRetryDelayMs: number;
  private readonly windowShowCooldownMs: number;
  private readonly errorRetryCooldownMs: number;

  private status: UpdateStatus = 'idle';
  private cachedManifest: UpdateReleaseManifest | null = null;
  private deliveryMode: UpdateDeliveryMode | null = null;
  private includeMmdbUpdate = false;
  private downloadTotalBytes: number | null = null;
  private downloadedBytes = 0;
  private progressPercent: number | null = null;
  private signatureVerified = false;
  private lastCheckedAt: number | null = null;
  private lastSuccessfulCheckAt: number | null = null;
  private lastAttemptAt: number | null = null;
  private lastAttemptSucceeded = false;
  private viaChannel: string | null = null;
  private lastError: string | null = null;

  private startupTimer: NodeJS.Timeout | null = null;
  private startupRetryTimer: NodeJS.Timeout | null = null;
  private initialized = false;
  private startupCheckFailedAt: number | null = null;
  private startupRetryUsed = false;
  private bakCleanupTimer: NodeJS.Timeout | null = null;
  private quitTimer: NodeJS.Timeout | null = null;
  private checkPromise: Promise<UpdateActionResult> | null = null;
  private downloadPromise: Promise<UpdateActionResult> | null = null;
  private applyingInProgress = false;
  private lastProgressEmitAt = 0;

  constructor(options: UpdaterServiceOptions) {
    this.configStore = options.configStore;
    this.host = options.probeEngine;
    this.onQuitForUpdate = options.onQuitForUpdate;

    this.manifestUrl = options.manifestUrlOverride || DEFAULT_GITHUB_RELEASE_LATEST_JSON_URL;
    this.releasePageUrl = options.releasePageUrlOverride || DEFAULT_GITHUB_RELEASES_PAGE_URL;
    this.publicKey = options.publicKeyOverride || BUILTIN_UPDATE_PUBLIC_KEY_SPKI_B64;
    this.isPackaged = options.isPackagedOverride ?? app.isPackaged;
    this.currentVersion =
      normalizeSemverString(options.currentVersionOverride || app.getVersion()) || '1.0.0';
    this.electronVersion =
      normalizeSemverString(options.electronVersionOverride || process.versions.electron) ||
      '0.0.0';

    this.exePath = options.exePathOverride || process.execPath;
    this.appDir = options.appDirOverride || path.dirname(this.exePath);
    this.resourcesDir =
      options.resourcesDirOverride || process.resourcesPath || path.join(this.appDir, 'resources');
    this.stagingRootDir =
      options.stagingRootDirOverride || path.join(app.getPath('userData'), 'updates');
    this.allowLocalhostForTest = Boolean(options.allowLocalhostForTest);
    this.targetPidOverride = options.targetPidOverride;
    this.bootHandshakeTimeoutMs =
      options.bootHandshakeTimeoutMsOverride ?? DEFAULT_BOOT_HANDSHAKE_TIMEOUT_MS;
    this.waitExitAttemptsOverride = options.waitExitAttemptsOverride;
    this.startupCheckDelayMs =
      options.startupCheckDelayMsOverride ?? DEFAULT_STARTUP_CHECK_DELAY_MS;
    this.startupRetryDelayMs =
      options.startupRetryDelayMsOverride ?? DEFAULT_STARTUP_RETRY_DELAY_MS;
    this.windowShowCooldownMs =
      options.windowShowCooldownMsOverride ?? DEFAULT_WINDOW_SHOW_COOLDOWN_MS;
    this.errorRetryCooldownMs =
      options.errorRetryCooldownMsOverride ?? DEFAULT_ERROR_RETRY_COOLDOWN_MS;
    this.nativeShellVersion =
      normalizeSemverString(options.nativeShellVersionOverride) || this.readNativeShellVersion();

    this.host.setUpdateStateProvider(() => this.getSnapshot());
  }

  private readNativeShellVersion(): string {
    try {
      const shellMetaPath = path.join(this.resourcesDir, 'shell-meta.json');
      if (rawFs.existsSync(shellMetaPath)) {
        const parsed = JSON.parse(rawFs.readFileSync(shellMetaPath, 'utf-8')) as {
          shellVersion?: unknown;
        };
        if (typeof parsed.shellVersion === 'string') {
          const norm = normalizeSemverString(parsed.shellVersion);
          if (norm) return norm;
        }
      }
    } catch {
      // fallback to 1.0.0
    }
    return '1.0.0';
  }

  private hasVerifiedUpdate(): boolean {
    if (!this.cachedManifest || !this.signatureVerified) {
      return false;
    }
    try {
      return compareSemver(this.cachedManifest.version, this.currentVersion) > 0;
    } catch {
      return false;
    }
  }

  public getSnapshot(): UpdateStateSnapshot {
    const hasUpdate = this.hasVerifiedUpdate();
    return {
      currentVersion: this.currentVersion,
      electronVersion: this.electronVersion,
      isPackaged: this.isPackaged,
      status: this.status,
      hasUpdate,
      latestVersion: this.cachedManifest?.version || null,
      publishedAt: this.cachedManifest?.publishedAt || null,
      releaseNotes: this.cachedManifest?.notes || null,
      deliveryMode: this.deliveryMode,
      includeMmdbUpdate: this.includeMmdbUpdate,
      downloadTotalBytes: this.downloadTotalBytes,
      downloadedBytes: this.downloadedBytes,
      progressPercent: this.progressPercent,
      signatureVerified: this.signatureVerified,
      lastCheckedAt: this.lastCheckedAt,
      lastSuccessfulCheckAt: this.lastSuccessfulCheckAt,
      viaChannel: this.viaChannel,
      error: this.lastError,
      releasePageUrl: this.releasePageUrl,
    };
  }

  private clearStartupTimer(): void {
    if (this.startupTimer) {
      clearTimeout(this.startupTimer);
      this.startupTimer = null;
    }
  }

  private clearStartupRetryTimer(): void {
    if (this.startupRetryTimer) {
      clearTimeout(this.startupRetryTimer);
      this.startupRetryTimer = null;
    }
  }

  public initialize(argv: string[] = process.argv): void {
    this.initialized = true;
    this.handlePostUpdateStartupFlags(argv);
    this.clearStartupTimer();
    this.clearStartupRetryTimer();
    this.startupCheckFailedAt = null;
    this.startupRetryUsed = false;

    if (this.configStore.get().autoCheckUpdates) {
      this.startupTimer = setTimeout(() => {
        void this.runStartupAutoCheck();
      }, this.startupCheckDelayMs);
      this.startupTimer.unref?.();
    }
    if (argv.some((arg) => arg.startsWith('--updated-from='))) {
      recordUpdateBootEvent('boot-check-complete', '启动检查完成，准备发布就绪标记', argv);
    }
    writeUpdateReadyFile(argv);
  }

  private async runStartupAutoCheck(): Promise<void> {
    this.startupTimer = null;
    if (!this.configStore.get().autoCheckUpdates) {
      return;
    }
    const res = await this.checkForUpdates({ silent: true });
    if (!res.ok && this.lastSuccessfulCheckAt === null && !this.startupRetryUsed) {
      this.startupCheckFailedAt = Date.now();
      this.clearStartupRetryTimer();
      this.startupRetryTimer = setTimeout(() => {
        this.startupRetryTimer = null;
        if (
          this.startupRetryUsed ||
          this.lastSuccessfulCheckAt !== null ||
          !this.configStore.get().autoCheckUpdates
        ) {
          return;
        }
        this.startupRetryUsed = true;
        void this.checkForUpdates({ silent: true });
      }, this.startupRetryDelayMs);
      this.startupRetryTimer.unref?.();
    }
  }

  public notifyNetworkReady(readyTimestamp?: number): void {
    if (
      this.startupCheckFailedAt === null ||
      this.startupRetryUsed ||
      this.lastSuccessfulCheckAt !== null
    ) {
      return;
    }
    if (readyTimestamp !== undefined && readyTimestamp <= this.startupCheckFailedAt) {
      return;
    }
    if (!this.configStore.get().autoCheckUpdates) {
      return;
    }
    this.clearStartupRetryTimer();
    this.startupRetryUsed = true;
    void this.checkForUpdates({ silent: true });
  }

  public async notifyWindowShown(): Promise<UpdateActionResult | null> {
    if (!this.initialized || !this.configStore.get().autoCheckUpdates) {
      return null;
    }
    // 启动初期定时器尚未触发时交由启动检查统一执行，避免在代理探测初始化前抢跑
    if (this.startupTimer !== null) {
      return null;
    }
    if (
      this.applyingInProgress ||
      this.status === 'applying' ||
      this.checkPromise ||
      this.downloadPromise
    ) {
      return null;
    }

    const now = Date.now();

    // 最近一次检查或预下载尝试失败：统一遵守 errorRetryCooldownMs（默认 2 分钟）短冷却节流，
    // 防止满 30 分钟后处于离线/超时环境时每次切换窗口都触发无节流请求风暴
    if (!this.lastAttemptSucceeded) {
      if (this.lastAttemptAt !== null && now - this.lastAttemptAt < this.errorRetryCooldownMs) {
        return null;
      }
      return this.checkForUpdates({ silent: true });
    }

    // 最近一次尝试已成功：严格遵循 windowShowCooldownMs（默认 30 分钟）长冷却节流
    if (
      this.lastSuccessfulCheckAt !== null &&
      now - this.lastSuccessfulCheckAt < this.windowShowCooldownMs
    ) {
      return null;
    }

    return this.checkForUpdates({ silent: true });
  }

  public handleAutoCheckConfigChanged(enabled: boolean): void {
    if (!enabled) {
      this.clearStartupTimer();
      this.clearStartupRetryTimer();
      return;
    }
    void this.notifyWindowShown();
  }

  public stop(): void {
    this.clearStartupTimer();
    this.clearStartupRetryTimer();
    if (this.bakCleanupTimer) {
      clearTimeout(this.bakCleanupTimer);
      this.bakCleanupTimer = null;
    }
    if (this.quitTimer) {
      clearTimeout(this.quitTimer);
      this.quitTimer = null;
    }
  }

  private handlePostUpdateStartupFlags(argv: string[]): void {
    for (const arg of argv) {
      if (arg.startsWith('--updated-from=')) {
        const fromVer = arg.slice('--updated-from='.length).trim();
        if (fromVer && fromVer !== this.currentVersion) {
          this.host.recordExternalLog(
            'success',
            `🎉 已成功完成版本更新：v${fromVer} → v${this.currentVersion}`
          );
        }
      } else if (arg.startsWith('--update-rolled-back=')) {
        const failedVer = arg.slice('--update-rolled-back='.length).trim();
        this.host.recordExternalLog(
          'danger',
          `⚠️ 更新至 v${failedVer || '新版本'} 未完成，已回滚至 v${this.currentVersion}${readUpdateFailureReason(argv)}`
        );
      }
    }

    // 推迟兜底清理残留 .bak 与历史暂存目录，避免在后台更新脚本观察/收尾窗口内抢删握手或回滚备份
    if (this.bakCleanupTimer) {
      clearTimeout(this.bakCleanupTimer);
    }
    this.bakCleanupTimer = setTimeout(() => {
      this.bakCleanupTimer = null;
      for (const bakPath of [
        path.join(this.resourcesDir, 'app.asar.bak'),
        path.join(this.resourcesDir, 'geolite2-country.mmdb.bak'),
        `${this.exePath}.bak`,
      ]) {
        try {
          if (rawFs.existsSync(bakPath)) {
            rawFs.rmSync(bakPath, { force: true });
          }
        } catch {
          // ignore
        }
      }
      void cleanupObsoleteStagingDirs(this.stagingRootDir, this.currentVersion);
    }, POST_UPDATE_BAK_CLEANUP_DELAY_MS);
    this.bakCleanupTimer.unref?.();
  }

  private emitUpdateState(): void {
    this.host.notifyExternalStateChanged();
  }

  private async buildDownloadAttempts(
    rawUrl: string,
    appendCacheBuster = false
  ): Promise<UpdateDownloadAttempt[]> {
    const proxies = await this.host.resolveUpdateDownloadProxies(rawUrl);
    const useMirror = this.configStore.get().useUpdateMirrorFallback;
    return buildUpdateDownloadAttempts(rawUrl, proxies, useMirror, appendCacheBuster);
  }

  private getVersionStageDir(version: string): string {
    return path.join(this.stagingRootDir, `v-${version}`);
  }

  private decideDelivery(manifest: UpdateReleaseManifest): Promise<{
    deliveryMode: UpdateDeliveryMode;
    includeMmdbUpdate: boolean;
    expectedBytes: number;
  }> {
    return decideDeliveryAndMmdb({
      manifest,
      isPackaged: this.isPackaged,
      electronVersion: this.electronVersion,
      nativeShellVersion: this.nativeShellVersion,
      resourcesDir: this.resourcesDir,
    });
  }

  private isStagedVerified(
    manifest: UpdateReleaseManifest,
    deliveryMode: UpdateDeliveryMode,
    includeMmdbUpdate: boolean
  ): Promise<boolean> {
    return isStagedUpdateAlreadyVerified(
      this.getVersionStageDir(manifest.version),
      manifest,
      deliveryMode,
      includeMmdbUpdate
    );
  }

  private resetCachedUpdateState(): void {
    this.cachedManifest = null;
    this.signatureVerified = false;
    this.deliveryMode = null;
    this.includeMmdbUpdate = false;
    this.downloadTotalBytes = null;
    this.downloadedBytes = 0;
    this.progressPercent = null;
  }

  public async checkForUpdates(opts: { silent?: boolean } = {}): Promise<UpdateActionResult> {
    if (this.applyingInProgress || (this.status as UpdateStatus) === 'applying') {
      return {
        ok: false,
        message: '正在准备重启应用更新...',
        state: this.host.getSnapshot(),
      };
    }
    if (this.downloadPromise) return this.downloadPromise;
    if (this.checkPromise) return this.checkPromise;

    const task = this.executeCheckForUpdates(Boolean(opts.silent));
    this.checkPromise = task;
    try {
      return await task;
    } finally {
      if (this.checkPromise === task) {
        this.checkPromise = null;
      }
    }
  }

  private async executeCheckForUpdates(silent: boolean): Promise<UpdateActionResult> {
    if (this.applyingInProgress || (this.status as UpdateStatus) === 'applying') {
      return {
        ok: false,
        message: '正在准备重启应用更新...',
        state: this.host.getSnapshot(),
      };
    }

    const prevStatus = this.status;
    const prevManifest = this.cachedManifest;
    const prevSigVerified = this.signatureVerified;
    const prevDeliveryMode = this.deliveryMode;
    const prevIncludeMmdb = this.includeMmdbUpdate;
    const prevTotalBytes = this.downloadTotalBytes;
    const prevProgressPercent = this.progressPercent;
    const prevChannel = this.viaChannel;
    const prevLastError = this.lastError;
    const prevHadVerifiedUpdate =
      Boolean(prevManifest && prevSigVerified) &&
      compareSemver(prevManifest!.version, this.currentVersion) > 0;

    // 当已有验签就绪/可用的新版本且本次仅为后台静默复查时，保持原视觉状态不降级为 checking，
    // 消除右上角标志闪烁并确保用户在静默复查期间随时可点击「立即重启并更新」
    const preserveVisualStatusDuringSilentCheck =
      silent &&
      prevHadVerifiedUpdate &&
      (prevStatus === 'downloaded' || prevStatus === 'available');
    if (!preserveVisualStatusDuringSilentCheck) {
      this.status = 'checking';
      this.lastError = null;
      this.emitUpdateState();
    }

    const attempts = await this.buildDownloadAttempts(this.manifestUrl, true);
    const outcome = await fetchVerifiedUpdateManifest({
      attempts,
      publicKey: this.publicKey,
      allowLocalhostForTest: this.allowLocalhostForTest,
      prevVerifiedManifest: prevManifest && prevSigVerified ? prevManifest : null,
      recordLog: (level, message, emitImmediately) =>
        this.host.recordExternalLog(level, message, emitImmediately),
    });

    if (this.applyingInProgress || (this.status as UpdateStatus) === 'applying') {
      return {
        ok: false,
        message: '正在准备重启应用更新...',
        state: this.host.getSnapshot(),
      };
    }

    const checkedNow = Date.now();
    this.lastCheckedAt = checkedNow;
    this.lastAttemptAt = checkedNow;

    if (!outcome.manifest) {
      this.lastAttemptSucceeded = false;

      // 1) 签名伪造或清单资产地址篡改属于最高优先级安全异常：无条件清空缓存并告警（绝不被陈旧镜像覆盖）
      if (outcome.sawSecurityRejection) {
        this.resetCachedUpdateState();
        this.status = 'error';
        this.lastError =
          outcome.securityRejectionText ||
          '更新清单 Ed25519 数字签名校验失败，已拒绝加载以防篡改';
        this.host.recordExternalLog('danger', this.lastError, false);
        this.emitUpdateState();
        return {
          ok: false,
          message: this.lastError,
          state: this.host.getSnapshot(),
        };
      }

      // 2) 纯网络故障或镜像缓存滞后（sawStaleMirrorOnly）时，若此前已验签发现新版本，保持状态粘性
      if (
        (prevHadVerifiedUpdate || outcome.sawStaleMirrorOnly) &&
        prevManifest &&
        prevSigVerified
      ) {
        if (compareSemver(prevManifest.version, this.currentVersion) <= 0) {
          this.cachedManifest = prevManifest;
          this.signatureVerified = true;
          this.status = 'up-to-date';
          this.lastError = silent ? null : `检查更新失败：${outcome.lastErrText}`;
          this.emitUpdateState();
          return {
            ok: false,
            message: `检查更新失败：${outcome.lastErrText}`,
            state: this.host.getSnapshot(),
          };
        }

        const stagedPrevValid =
          this.isPackaged && prevDeliveryMode
            ? await this.isStagedVerified(prevManifest, prevDeliveryMode, prevIncludeMmdb)
            : false;
        if (this.applyingInProgress || (this.status as UpdateStatus) === 'applying') {
          return {
            ok: false,
            message: '正在准备重启应用更新...',
            state: this.host.getSnapshot(),
          };
        }
        if (stagedPrevValid) {
          this.cachedManifest = prevManifest;
          this.signatureVerified = true;
          this.deliveryMode = prevDeliveryMode;
          this.includeMmdbUpdate = prevIncludeMmdb;
          this.downloadTotalBytes = prevTotalBytes;
          this.downloadedBytes = prevTotalBytes ?? 0;
          this.progressPercent = 100;
          this.viaChannel = prevChannel;
          this.status = 'downloaded';
          this.lastError = silent
            ? null
            : `联网刷新失败（${outcome.lastErrText}），本地已验签就绪的 v${prevManifest.version} 仍可直接重启更新`;
          this.emitUpdateState();
          return {
            ok: false,
            message: `联网刷新失败（${outcome.lastErrText}），本地已验签就绪的 v${prevManifest.version} 仍可直接重启更新`,
            state: this.host.getSnapshot(),
          };
        }

        this.cachedManifest = prevManifest;
        this.signatureVerified = true;
        this.deliveryMode = prevDeliveryMode;
        this.includeMmdbUpdate = prevIncludeMmdb;
        this.downloadTotalBytes = prevTotalBytes;
        this.downloadedBytes = 0;
        this.progressPercent = prevStatus === 'available' ? prevProgressPercent : 0;
        this.viaChannel = prevChannel;
        this.status = prevStatus === 'error' ? 'error' : 'available';
        this.lastError = silent
          ? prevStatus === 'error'
            ? prevLastError
            : null
          : `联网刷新失败（${outcome.lastErrText}），已保留新版本 v${prevManifest.version} 更新提示`;
        if (!silent && this.lastError) {
          this.host.recordExternalLog('warn', this.lastError, false);
        }
        this.emitUpdateState();
        return {
          ok: false,
          message: `联网刷新失败（${outcome.lastErrText}），已保留新版本 v${prevManifest.version} 更新提示`,
          state: this.host.getSnapshot(),
        };
      }

      this.resetCachedUpdateState();
      this.status = 'error';
      this.lastError = `检查更新失败：${outcome.lastErrText}`;
      if (!silent) {
        this.host.recordExternalLog('warn', this.lastError, false);
      }
      this.emitUpdateState();
      return {
        ok: false,
        message: this.lastError,
        state: this.host.getSnapshot(),
      };
    }

    const verifiedManifest = outcome.manifest;
    this.lastAttemptSucceeded = true;
    this.lastSuccessfulCheckAt = checkedNow;
    this.startupCheckFailedAt = null;
    this.startupRetryUsed = true;
    this.clearStartupRetryTimer();

    this.cachedManifest = verifiedManifest;
    this.signatureVerified = true;
    this.viaChannel = outcome.usedChannel;

    const cmp = compareSemver(verifiedManifest.version, this.currentVersion);
    if (cmp <= 0) {
      this.status = 'up-to-date';
      this.deliveryMode = null;
      this.includeMmdbUpdate = false;
      this.downloadTotalBytes = null;
      this.downloadedBytes = 0;
      this.progressPercent = null;
      this.lastError = null;
      this.emitUpdateState();
      return {
        ok: true,
        message: `当前已是最新版本 (v${this.currentVersion})`,
        state: this.host.getSnapshot(),
      };
    }

    const decision = await this.decideDelivery(verifiedManifest);
    const stagedAlreadyValid = this.isPackaged
      ? await this.isStagedVerified(
          verifiedManifest,
          decision.deliveryMode,
          decision.includeMmdbUpdate
        )
      : false;
    if (this.applyingInProgress || (this.status as UpdateStatus) === 'applying') {
      return {
        ok: false,
        message: '正在准备重启应用更新...',
        state: this.host.getSnapshot(),
      };
    }

    this.deliveryMode = decision.deliveryMode;
    this.includeMmdbUpdate = decision.includeMmdbUpdate;
    this.downloadTotalBytes = decision.expectedBytes;

    if (stagedAlreadyValid) {
      this.status = 'downloaded';
      this.downloadedBytes = decision.expectedBytes;
      this.progressPercent = 100;
      this.lastError = null;
      this.emitUpdateState();
      return {
        ok: true,
        message: `新版本 v${verifiedManifest.version} 已验签就绪，可随时重启生效`,
        state: this.host.getSnapshot(),
      };
    }

    this.status = 'available';
    this.downloadedBytes = 0;
    this.progressPercent = this.isPackaged ? 0 : null;
    this.lastError = null;
    this.emitUpdateState();

    // 正式打包环境下，发现轻量 ASAR 增量更新包时自动在后台静默下载并完成验签
    if (this.isPackaged && decision.deliveryMode === 'asar') {
      return this.runTrackedDownload(silent);
    }

    if (!silent || prevManifest?.version !== verifiedManifest.version) {
      this.host.recordExternalLog(
        'info',
        this.isPackaged
          ? `发现新版本 v${verifiedManifest.version}（完整更新包），可点击右上角更新标志下载升级`
          : `发现新版本 v${verifiedManifest.version}（源码运行模式），可点击右上角更新标志查看详情`,
        false
      );
      this.emitUpdateState();
    }

    return {
      ok: true,
      message: this.isPackaged
        ? `发现新版本 v${verifiedManifest.version}，请点击下载完整更新包`
        : `发现新版本 v${verifiedManifest.version}（当前为源码运行模式，仅正式打包版执行原地替换）`,
      state: this.host.getSnapshot(),
    };
  }

  private async runTrackedDownload(silent: boolean): Promise<UpdateActionResult> {
    if (this.downloadPromise) {
      return this.downloadPromise;
    }
    const task = this.executeDownloadUpdate(silent);
    this.downloadPromise = task;
    try {
      return await task;
    } finally {
      if (this.downloadPromise === task) {
        this.downloadPromise = null;
      }
    }
  }

  public async downloadUpdate(): Promise<UpdateActionResult> {
    if (this.applyingInProgress || (this.status as UpdateStatus) === 'applying') {
      return {
        ok: false,
        message: '正在准备重启应用更新...',
        state: this.host.getSnapshot(),
      };
    }
    if (this.downloadPromise) {
      return this.downloadPromise;
    }
    if (this.checkPromise) {
      const checkRes = await this.checkPromise;
      if (this.downloadPromise) {
        return this.downloadPromise;
      }
      if (
        !this.cachedManifest ||
        !this.signatureVerified ||
        this.status === 'up-to-date' ||
        this.status === 'downloaded'
      ) {
        return checkRes;
      }
    }

    return this.runTrackedDownload(false);
  }

  private async executeDownloadUpdate(silent: boolean): Promise<UpdateActionResult> {
    if (!this.cachedManifest || !this.signatureVerified) {
      const checkRes = await this.executeCheckForUpdates(silent);
      if (!checkRes.ok || this.status === 'up-to-date' || this.status === 'downloaded') {
        return checkRes;
      }
    }

    const manifest = this.cachedManifest!;
    if (compareSemver(manifest.version, this.currentVersion) <= 0) {
      return {
        ok: true,
        message: `当前已是最新版本 (v${this.currentVersion})`,
        state: this.host.getSnapshot(),
      };
    }
    if (!this.isPackaged) {
      return {
        ok: false,
        message: '当前处于源码开发模式，为保护工作区文件不执行原地覆盖，请前往 Release 页面查看',
        state: this.host.getSnapshot(),
      };
    }

    const decision = await this.decideDelivery(manifest);
    this.deliveryMode = decision.deliveryMode;
    this.includeMmdbUpdate = decision.includeMmdbUpdate;
    this.downloadTotalBytes = decision.expectedBytes;

    if (
      await this.isStagedVerified(manifest, decision.deliveryMode, decision.includeMmdbUpdate)
    ) {
      this.status = 'downloaded';
      this.downloadedBytes = decision.expectedBytes;
      this.progressPercent = 100;
      this.lastError = null;
      this.emitUpdateState();
      return {
        ok: true,
        message: `新版本 v${manifest.version} 已就绪，点击重启即可完成更新`,
        state: this.host.getSnapshot(),
      };
    }

    this.status = 'downloading';
    this.downloadedBytes = 0;
    this.progressPercent = 0;
    this.lastError = null;
    this.emitUpdateState();

    const stageDir = this.getVersionStageDir(manifest.version);
    try {
      const { channelUsed } = await downloadAndStageVerifiedUpdate({
        manifest,
        deliveryMode: decision.deliveryMode,
        includeMmdbUpdate: decision.includeMmdbUpdate,
        expectedBytes: decision.expectedBytes,
        stageDir,
        initialChannel: this.viaChannel || '',
        allowLocalhostForTest: this.allowLocalhostForTest,
        buildDownloadAttempts: (rawUrl) => this.buildDownloadAttempts(rawUrl, false),
        onProgress: (downloadedBytes, progressPercent) => {
          const now = Date.now();
          this.downloadedBytes = downloadedBytes;
          this.progressPercent = progressPercent;
          if (now - this.lastProgressEmitAt >= 90) {
            this.lastProgressEmitAt = now;
            this.emitUpdateState();
          }
        },
      });

      this.viaChannel = channelUsed;
      this.status = 'downloaded';
      this.downloadedBytes = decision.expectedBytes;
      this.progressPercent = 100;
      this.lastError = null;
      this.lastAttemptAt = Date.now();
      this.lastAttemptSucceeded = true;
      this.host.recordExternalLog(
        'success',
        `✨ 新版本 v${manifest.version} 更新包已下载并通过 Ed25519 + SHA-256 验签，可点击右上角更新标志立即重启生效`,
        false
      );
      this.emitUpdateState();

      return {
        ok: true,
        message: `新版本 v${manifest.version} 已验签就绪，点击「立即重启并更新」即可生效`,
        state: this.host.getSnapshot(),
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.status = 'error';
      this.downloadedBytes = 0;
      this.progressPercent = 0;
      this.lastAttemptAt = Date.now();
      this.lastAttemptSucceeded = false;
      this.lastError = `更新包下载或验签失败：${msg}`;
      await rawFs.promises.rm(stageDir, { recursive: true, force: true }).catch(() => {});
      if (!silent) {
        this.host.recordExternalLog('warn', this.lastError, false);
      }
      this.emitUpdateState();
      return {
        ok: false,
        message: this.lastError,
        state: this.host.getSnapshot(),
      };
    }
  }

  public async applyDownloadedUpdate(allowTerminateClaude = false): Promise<UpdateActionResult> {
    if (this.applyingInProgress || this.status === 'applying') {
      return {
        ok: false,
        message: '正在启动更新助手，请勿重复点击',
        state: this.host.getSnapshot(),
      };
    }

    if (!this.isPackaged) {
      return {
        ok: false,
        message: '开发调试环境不支持执行原地热替换',
        state: this.host.getSnapshot(),
      };
    }

    if (
      this.status !== 'downloaded' ||
      !this.cachedManifest ||
      !this.deliveryMode ||
      !this.signatureVerified
    ) {
      return {
        ok: false,
        message: '更新包尚未准备就绪，请先下载并完成签名校验',
        state: this.host.getSnapshot(),
      };
    }

    // 同步加锁并立即广播 applying 状态，彻底阻断双击或面板/托盘并发拉起多个更新脚本
    this.applyingInProgress = true;
    const manifest = this.cachedManifest;
    const mode = this.deliveryMode;
    const includeMmdb = this.includeMmdbUpdate;
    this.status = 'applying';
    this.lastError = null;
    this.emitUpdateState();

    try {
      const claudeActive = await this.host.isClaudeActiveForUpdateInterlock();
      if (claudeActive && !allowTerminateClaude) {
        this.applyingInProgress = false;
        this.status = 'downloaded';
        this.emitUpdateState();
        return {
          ok: false,
          message: 'Claude 正在受控守护运行中，请先确认终止 Claude 会话后再执行重启更新',
          state: this.host.getSnapshot(),
        };
      }

      const stillValid = await this.isStagedVerified(manifest, mode, includeMmdb);
      if (!stillValid) {
        this.applyingInProgress = false;
        this.status = 'error';
        this.lastError = '本地暂存更新包完整性复核未通过，请重新下载更新';
        this.emitUpdateState();
        return {
          ok: false,
          message: this.lastError,
          state: this.host.getSnapshot(),
        };
      }

      if (claudeActive && allowTerminateClaude) {
        const termRes = await this.host.terminateClaudeManually();
        if (!termRes.ok) {
          this.applyingInProgress = false;
          this.status = 'downloaded';
          this.lastError = `安全终止 Claude 进程未完成，已取消本次重启更新：${termRes.message}`;
          this.emitUpdateState();
          return {
            ok: false,
            message: this.lastError,
            state: this.host.getSnapshot(),
          };
        }
      }

      await launchStagedWindowsUpdater({
        manifest,
        mode,
        includeMmdb,
        stageDir: this.getVersionStageDir(manifest.version),
        stagingRootDir: this.stagingRootDir,
        appDir: this.appDir,
        resourcesDir: this.resourcesDir,
        exePath: this.exePath,
        currentVersion: this.currentVersion,
        targetPid: this.targetPidOverride ?? process.pid,
        bootHandshakeTimeoutMs: this.bootHandshakeTimeoutMs,
        waitExitAttemptsOverride: this.waitExitAttemptsOverride,
        prepareForUpdate: () => this.host.prepareForUpdate(),
        resumeAfterUpdateFailure: () => this.host.resumeAfterUpdateFailure(),
      });

      const finalState = this.host.getSnapshot();
      if (this.quitTimer) {
        clearTimeout(this.quitTimer);
      }
      this.quitTimer = setTimeout(() => {
        this.quitTimer = null;
        if (this.onQuitForUpdate) {
          this.onQuitForUpdate();
        } else {
          this.host.stop();
          app.quit();
        }
      }, 120);

      return {
        ok: true,
        message: `正在重启并应用 v${manifest.version} 更新...`,
        state: finalState,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.applyingInProgress = false;
      this.status = 'downloaded';
      this.lastError = `启动更新助手脚本失败：${msg}`;
      this.emitUpdateState();
      return {
        ok: false,
        message: this.lastError,
        state: this.host.getSnapshot(),
      };
    }
  }

  public async openReleasePageInBrowser(): Promise<void> {
    const url = this.releasePageUrl;
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.hostname !== 'github.com') {
      throw new Error('不受信任的外部链接');
    }
    await shell.openExternal(url);
  }
}
