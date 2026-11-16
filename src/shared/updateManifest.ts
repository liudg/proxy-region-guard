export const UPDATE_REPO_SLUG = 'liudg/proxy-region-guard';

export const DEFAULT_GITHUB_RELEASE_LATEST_JSON_URL = `https://github.com/${UPDATE_REPO_SLUG}/releases/latest/download/latest.json`;

export const DEFAULT_GITHUB_RELEASES_PAGE_URL = `https://github.com/${UPDATE_REPO_SLUG}/releases`;

export const DEFAULT_GITHUB_MIRROR_PREFIXES: readonly string[] = [
  'https://gh-proxy.com/',
  'https://ghfast.top/',
];

// Ed25519 SPKI DER Base64 公钥（由 npm run keygen 生成并自动同步，用于离线校验 latest.json 数字签名）
export const BUILTIN_UPDATE_PUBLIC_KEY_SPKI_B64 =
  'MCowBQYDK2VwAyEAnMyl197782r0IMN76gX6zYuNsLuczhfKtMyfFjBM2U8=';

export interface SignedAssetEntry {
  name: string;
  url: string;
  size: number;
  sha256: string;
  uncompressedSize?: number;
  uncompressedSha256?: string;
}

export interface SignedExtractedAssetEntry extends SignedAssetEntry {
  uncompressedSize: number;
  uncompressedSha256: string;
}

export interface UpdateReleaseManifest {
  schemaVersion: 2;
  version: string;
  publishedAt: string;
  electronVersion: string;
  minNativeShellVersion: string;
  mihomo: { version: string; sha256: string };
  notes: string;
  asar: SignedExtractedAssetEntry;
  mmdb?: SignedExtractedAssetEntry;
  fullZip: SignedAssetEntry;
  signature: string;
}

export interface ParsedSemver {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
}

export function parseSemver(raw: string | null | undefined): ParsedSemver | null {
  if (typeof raw !== 'string') return null;
  const cleaned = raw.trim().replace(/^v/i, '');
  const match =
    /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/.exec(cleaned);
  if (!match) return null;

  if (
    !/^(0|[1-9]\d*)$/.test(match[1]) ||
    !/^(0|[1-9]\d*)$/.test(match[2]) ||
    !/^(0|[1-9]\d*)$/.test(match[3])
  ) {
    return null;
  }

  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (
    !Number.isSafeInteger(major) ||
    !Number.isSafeInteger(minor) ||
    !Number.isSafeInteger(patch)
  ) {
    return null;
  }

  let prerelease: string[] = [];
  if (match[4] !== undefined) {
    const rawParts = match[4].split('.');
    for (const part of rawParts) {
      if (!part || !/^[0-9A-Za-z-]+$/.test(part)) {
        return null;
      }
      if (/^\d+$/.test(part) && part.length > 1 && part.startsWith('0')) {
        return null;
      }
    }
    prerelease = rawParts;
  }

  if (match[5] !== undefined) {
    const buildParts = match[5].split('.');
    if (buildParts.some((part) => !part || !/^[0-9A-Za-z-]+$/.test(part))) {
      return null;
    }
  }

  return { major, minor, patch, prerelease };
}

export function normalizeSemverString(raw: string | null | undefined): string | null {
  const parsed = parseSemver(raw);
  if (!parsed) return null;
  const base = `${parsed.major}.${parsed.minor}.${parsed.patch}`;
  return parsed.prerelease.length > 0 ? `${base}-${parsed.prerelease.join('.')}` : base;
}

export function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) {
    throw new Error(`无效的语义化版本号: "${a}" vs "${b}"`);
  }

  if (pa.major !== pb.major) return pa.major > pb.major ? 1 : -1;
  if (pa.minor !== pb.minor) return pa.minor > pb.minor ? 1 : -1;
  if (pa.patch !== pb.patch) return pa.patch > pb.patch ? 1 : -1;

  if (pa.prerelease.length === 0 && pb.prerelease.length === 0) return 0;
  if (pa.prerelease.length === 0) return 1;
  if (pb.prerelease.length === 0) return -1;

  const len = Math.max(pa.prerelease.length, pb.prerelease.length);
  for (let i = 0; i < len; i++) {
    const idA = pa.prerelease[i];
    const idB = pb.prerelease[i];
    if (idA === undefined) return -1;
    if (idB === undefined) return 1;
    if (idA === idB) continue;

    const numA = /^\d+$/.test(idA) ? Number(idA) : null;
    const numB = /^\d+$/.test(idB) ? Number(idB) : null;
    if (numA !== null && numB !== null) {
      return numA > numB ? 1 : -1;
    }
    if (numA !== null) return -1;
    if (numB !== null) return 1;
    return idA > idB ? 1 : -1;
  }
  return 0;
}

export function normalizeManifestNotes(notes: string | undefined | null): string {
  return String(notes ?? '').replace(/\r\n/g, '\n').trim();
}

export function buildUpdateSignaturePayload(
  manifest: Omit<UpdateReleaseManifest, 'signature'>
): string {
  const mmdbPart = manifest.mmdb
    ? [
        manifest.mmdb.name,
        manifest.mmdb.url,
        manifest.mmdb.size,
        manifest.mmdb.sha256.toLowerCase(),
        manifest.mmdb.uncompressedSize,
        manifest.mmdb.uncompressedSha256.toLowerCase(),
      ].join('|')
    : 'none';

  return [
    'proxy-region-guard-update-v2',
    `schemaVersion=${manifest.schemaVersion}`,
    `version=${manifest.version.trim()}`,
    `publishedAt=${manifest.publishedAt.trim()}`,
    `electronVersion=${manifest.electronVersion.trim()}`,
    `minNativeShellVersion=${manifest.minNativeShellVersion.trim()}`,
    `mihomo=${manifest.mihomo.version}|${manifest.mihomo.sha256.toLowerCase()}`,
    `asar=${[
      manifest.asar.name,
      manifest.asar.url,
      manifest.asar.size,
      manifest.asar.sha256.toLowerCase(),
      manifest.asar.uncompressedSize,
      manifest.asar.uncompressedSha256.toLowerCase(),
    ].join('|')}`,
    `mmdb=${mmdbPart}`,
    `fullZip=${[
      manifest.fullZip.name,
      manifest.fullZip.url,
      manifest.fullZip.size,
      manifest.fullZip.sha256.toLowerCase(),
    ].join('|')}`,
    `notes=${normalizeManifestNotes(manifest.notes)}`,
  ].join('\n');
}

export function isValidSha256Hex(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value.trim());
}

export function isSafeAssetDownloadUrl(
  rawUrl: unknown,
  allowLocalhostForTest = false
): rawUrl is string {
  if (typeof rawUrl !== 'string') return false;
  const trimmed = rawUrl.trim();
  if (!trimmed || /[\x00-\x20\x7f|]/.test(trimmed)) return false;
  try {
    const parsed = new URL(trimmed);
    if (parsed.username || parsed.password) return false;
    if (allowLocalhostForTest && parsed.protocol === 'http:') {
      return parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost';
    }
    if (parsed.protocol !== 'https:') return false;
    return parsed.hostname === 'github.com' || parsed.hostname.endsWith('.githubusercontent.com');
  } catch {
    return false;
  }
}

export function validateUpdateManifestStructure(
  raw: unknown,
  allowLocalhostForTest = false
): UpdateReleaseManifest {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('更新清单格式无效：根节点不是对象');
  }
  const obj = raw as Record<string, unknown>;
  if (obj.schemaVersion !== 2) {
    throw new Error(`不支持的更新清单版本 (schemaVersion=${String(obj.schemaVersion)})，请手动下载最新版`);
  }

  const version = normalizeSemverString(typeof obj.version === 'string' ? obj.version : '');
  if (!version) {
    throw new Error('更新清单缺少合法的版本号 (version)');
  }

  const electronVersion = normalizeSemverString(
    typeof obj.electronVersion === 'string' ? obj.electronVersion : ''
  );
  if (!electronVersion) {
    throw new Error('更新清单缺少合法的 Electron 基座版本 (electronVersion)');
  }

  const minNativeShellVersion = normalizeSemverString(
    typeof obj.minNativeShellVersion === 'string' ? obj.minNativeShellVersion : '1.0.0'
  );
  if (!minNativeShellVersion) {
    throw new Error('更新清单缺少合法的壳版本要求 (minNativeShellVersion)');
  }

  const publishedAt =
    typeof obj.publishedAt === 'string' && obj.publishedAt.trim()
      ? obj.publishedAt.trim()
      : new Date(0).toISOString();
  if (/[\x00-\x20\x7f|]/.test(publishedAt)) {
    throw new Error('更新清单发布时间格式非法 (publishedAt)');
  }

  const notes = normalizeManifestNotes(typeof obj.notes === 'string' ? obj.notes : '');
  const signature = typeof obj.signature === 'string' ? obj.signature.trim() : '';

  const validateBaseAsset = (
    entry: unknown,
    fieldName: string
  ): SignedAssetEntry => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`更新清单缺少资产字段 ${fieldName}`);
    }
    const e = entry as Record<string, unknown>;
    const name = typeof e.name === 'string' ? e.name.trim() : '';
    if (!name || !/^[A-Za-z0-9._-]+$/.test(name) || name.includes('..')) {
      throw new Error(`更新清单资产文件名非法 (${fieldName}.name)`);
    }
    if (!isSafeAssetDownloadUrl(e.url, allowLocalhostForTest)) {
      throw new Error(`更新清单下载地址不受信任 (${fieldName}.url)`);
    }
    const size = Number(e.size);
    if (!Number.isSafeInteger(size) || size <= 0) {
      throw new Error(`更新清单文件大小无效 (${fieldName}.size)`);
    }
    if (!isValidSha256Hex(e.sha256)) {
      throw new Error(`更新清单 SHA-256 摘要无效 (${fieldName}.sha256)`);
    }
    return {
      name,
      url: e.url.trim(),
      size,
      sha256: e.sha256.trim().toLowerCase(),
    };
  };

  const validateExtractedAsset = (
    entry: unknown,
    fieldName: string
  ): SignedExtractedAssetEntry => {
    const base = validateBaseAsset(entry, fieldName);
    const e = entry as Record<string, unknown>;
    const uncompressedSize = Number(e.uncompressedSize);
    if (!Number.isSafeInteger(uncompressedSize) || uncompressedSize <= 0) {
      throw new Error(`更新清单解压体积无效 (${fieldName}.uncompressedSize)`);
    }
    if (!isValidSha256Hex(e.uncompressedSha256)) {
      throw new Error(`更新清单解压摘要无效 (${fieldName}.uncompressedSha256)`);
    }
    return {
      ...base,
      uncompressedSize,
      uncompressedSha256: e.uncompressedSha256.trim().toLowerCase(),
    };
  };

  const asar = validateExtractedAsset(obj.asar, 'asar');
  const core = obj.mihomo as { version?: unknown; sha256?: unknown } | undefined;
  const coreVersion = typeof core?.version === 'string' ? normalizeSemverString(core.version) : null;
  if (!coreVersion || !isValidSha256Hex(core?.sha256)) throw new Error('更新清单缺少合法的私有 Mihomo 版本和文件摘要');
  const mmdb = obj.mmdb ? validateExtractedAsset(obj.mmdb, 'mmdb') : undefined;
  const fullZip = validateBaseAsset(obj.fullZip, 'fullZip');

  return {
    schemaVersion: 2,
    version,
    publishedAt,
    electronVersion,
    minNativeShellVersion,
    mihomo: { version: coreVersion, sha256: core!.sha256!.toString().toLowerCase() },
    notes,
    asar,
    ...(mmdb ? { mmdb } : {}),
    fullZip,
    signature,
  };
}
