export {
  getRawFs,
  parseEd25519PrivateKey,
  parseEd25519PublicKey,
  signUpdateManifest,
  verifyUpdateManifestSignature,
  computeFileSha256,
  validateAsarArchiveHeader,
} from './updateCrypto';

export {
  recordUpdateBootEvent,
  writeUpdateReadyFile,
  readUpdateFailureReason,
} from './updateBoot';

export {
  resolveWindowsPowerShellExe,
  quoteWindowsArg,
  quoteWindowsCommandLine,
  launchDetachedWindowsUpdater,
  buildEncodedPowerShellLaunch,
  buildWindowsUpdatePowerShellScript,
} from './windowsPowerShellUpdater';

export {
  type StagedReadyMetadata,
  type UpdateDownloadAttempt,
  gunzipFileWithVerification,
  buildUpdateDownloadAttempts,
  decideDeliveryAndMmdb,
  isStagedUpdateAlreadyVerified,
  cleanupObsoleteStagingDirs,
} from './updateStagingVerifier';

export {
  type UpdaterHostAdapter,
  type UpdaterServiceOptions,
  UpdaterService,
} from './updaterService';
