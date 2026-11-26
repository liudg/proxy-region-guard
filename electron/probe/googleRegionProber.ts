import { BinaryReader, WireType } from '@bufbuild/protobuf/wire';
import * as net from 'node:net';
import { ProbeResult } from '../../src/shared/types';
import {
  getCountryNameZh,
  isValidIsoCountryCode,
  normalizeIsoCountryCode,
} from '../../src/shared/countries';
import { normalizeIpAddress } from '../../src/shared/probeValidation';
import {
  ProxyHttpResponse,
  requestHttpViaProxy,
  requestTextViaProxy,
} from '../net';

const GOOGLE_REGION_PROBE_TIMEOUT_MS = 8500;
const GOOGLE_AI_CHECK_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36';

function isAsciiAlphaByte(byte: number): boolean {
  return (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a);
}

/**
 * 使用 @bufbuild/protobuf/wire 解析 YouTube sw.js_data 内嵌的 visitorData Protobuf（field 6 -> field 1），
 * 提取 Google 内部 GeoIP 真实国家码（解决 CN 送中节点在 inner[1] 被静默回退为 US 的盲区）。
 */
export function extractYoutubeVisitorCountryCode(rawToken: string): string | null {
  const trimmed = rawToken.trim();
  if (!trimmed || trimmed.length < 16 || trimmed.length > 2048) return null;

  let decodedText = trimmed;
  if (decodedText.includes('%')) {
    try {
      decodedText = decodeURIComponent(decodedText);
    } catch {
      return null;
    }
  }
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(decodedText)) return null;

  const normalized = decodedText.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const buf = Buffer.from(padded, 'base64');
  if (buf.length < 12) return null;

  let visitorId: Uint8Array | null = null;
  let timestamp: bigint | null = null;
  let geoContainer: Uint8Array | null = null;

  try {
    const reader = new BinaryReader(buf);
    while (reader.pos < reader.len) {
      const [fieldNo, wireType] = reader.tag();
      if (fieldNo <= 0) return null;
      if (fieldNo === 1 && wireType === WireType.LengthDelimited && visitorId === null) {
        visitorId = reader.bytes();
      } else if (fieldNo === 5 && wireType === WireType.Varint && timestamp === null) {
        timestamp = BigInt(reader.uint64());
      } else if (fieldNo === 6 && wireType === WireType.LengthDelimited && geoContainer === null) {
        geoContainer = reader.bytes();
      } else {
        reader.skip(wireType, fieldNo);
      }
    }
  } catch {
    return null;
  }

  if (
    !visitorId ||
    visitorId.length < 6 ||
    visitorId.length > 32 ||
    timestamp === null ||
    timestamp < 1_000_000_000n ||
    !geoContainer ||
    geoContainer.length < 4
  ) {
    return null;
  }

  let countryBytes: Uint8Array | null = null;
  try {
    const geoReader = new BinaryReader(geoContainer);
    while (geoReader.pos < geoReader.len) {
      const [fieldNo, wireType] = geoReader.tag();
      if (fieldNo <= 0) return null;
      if (fieldNo === 1 && wireType === WireType.LengthDelimited && countryBytes === null) {
        countryBytes = geoReader.bytes();
      } else {
        geoReader.skip(wireType, fieldNo);
      }
    }
  } catch {
    return null;
  }

  // 严格校验原始字节为纯 ASCII 字母，禁止使用 Buffer.toString('ascii') 剥离最高位导致非法字节误判
  if (
    !countryBytes ||
    countryBytes.length !== 2 ||
    !isAsciiAlphaByte(countryBytes[0]) ||
    !isAsciiAlphaByte(countryBytes[1])
  ) {
    return null;
  }

  return normalizeIsoCountryCode(String.fromCharCode(countryBytes[0], countryBytes[1]));
}

export interface YoutubeSwJsDataResult {
  countryCode: string;
  ip?: string;
  glCountryCode?: string;
  visitorCountryCode?: string;
}

export function parseYoutubeSwJsData(raw: string): YoutubeSwJsDataResult | null {
  let glCountryCode: string | undefined;
  let visitorCountryCode: string | undefined;
  let ip: string | undefined;

  try {
    const cleaned = raw.replace(/^\)\]\}'\s*/, '');
    const parsed = JSON.parse(cleaned) as unknown;
    let entry: unknown[] | null = null;
    if (Array.isArray(parsed)) {
      if (parsed[0] === 'yt.sw.adr') {
        entry = parsed;
      } else {
        const found = parsed.find((item) => Array.isArray(item) && item[0] === 'yt.sw.adr');
        if (Array.isArray(found)) entry = found;
      }
    }
    const inner = ((entry?.[2] as unknown[])?.[0] as unknown[])?.[0];
    if (Array.isArray(inner)) {
      glCountryCode = normalizeIsoCountryCode(String(inner[1] || '')) || undefined;
      const ipCandidate = String(inner[3] || '').trim();
      if (net.isIP(ipCandidate)) {
        ip = normalizeIpAddress(ipCandidate) || ipCandidate;
      }
      const candidateTokens: string[] = [];
      if (typeof inner[13] === 'string') {
        candidateTokens.push(inner[13]);
      }
      for (let i = 4; i < inner.length; i++) {
        if (i !== 13 && typeof inner[i] === 'string' && inner[i].length >= 16) {
          candidateTokens.push(inner[i]);
        }
      }
      for (const token of candidateTokens) {
        const extracted = extractYoutubeVisitorCountryCode(token);
        if (extracted) {
          visitorCountryCode = extracted;
          break;
        }
      }
    }
  } catch {
    // ignore JSON parse failure, fall back to regex below
  }

  if (!glCountryCode && !visitorCountryCode) {
    const m = raw.match(
      /\["yt\.sw\.adr"\s*,\s*null\s*,\s*\[\[\[\s*"[^"]*"\s*,\s*"([A-Za-z]{2,3})"\s*,\s*null\s*,\s*"([^"]*)"/
    );
    if (m) {
      glCountryCode = normalizeIsoCountryCode(m[1]) || undefined;
      const ipStr = m[2].trim();
      if (net.isIP(ipStr)) {
        ip = normalizeIpAddress(ipStr) || ipStr;
      }
    }
  }

  const countryCode = visitorCountryCode || glCountryCode;
  if (!countryCode) return null;
  return {
    countryCode,
    ip,
    glCountryCode,
    visitorCountryCode,
  };
}

export function extractGoogleRedirectCountry(
  rawLocation: string,
  baseUrl = 'https://www.google.com/'
): string | null {
  try {
    const parsed = new URL(rawLocation, baseUrl);
    const host = parsed.hostname.toLowerCase();
    if (parsed.searchParams.get('pref')?.toLowerCase() === 'hkredirect') {
      return 'CN';
    }
    if (host === 'google.cn' || host.endsWith('.google.cn')) {
      return 'CN';
    }
    if (host === 'consent.google.com') {
      const gl = normalizeIsoCountryCode(parsed.searchParams.get('gl'));
      if (gl) return gl;
    }
  } catch {
    // ignore malformed redirect URL
  }
  return null;
}

export function parseGoogleSearchHtml(raw: string): { countryCode: string } | null {
  const patterns = [
    /"MgUcDb"\s*:\s*"([A-Za-z]{2,3})"/,
    /,\d+,\d+,200,"([A-Za-z]{2,3})",null/,
  ];
  for (const pat of patterns) {
    const m = raw.match(pat);
    if (m) {
      const code = normalizeIsoCountryCode(m[1]);
      if (code) {
        return { countryCode: code };
      }
    }
  }
  return null;
}

function isNotebookLmDomainMigrationRedirect(
  rawLocation: string,
  fromUrl = 'https://notebooklm.google.com/'
): boolean {
  try {
    const parsed = new URL(rawLocation, fromUrl);
    if (parsed.protocol !== 'https:') return false;
    if (parsed.searchParams.get('location')?.toLowerCase() === 'unsupported') {
      return false;
    }
    const host = parsed.hostname.toLowerCase();
    return host === 'notebook.google.com' || host === 'notebooklm.google.com';
  } catch {
    return false;
  }
}

export function classifyNotebookLmResponse(
  res: Pick<ProxyHttpResponse, 'statusCode' | 'location'> & { finalUrl?: string }
): boolean | undefined {
  if (res.location && res.statusCode >= 300 && res.statusCode < 400) {
    try {
      const parsed = new URL(res.location, res.finalUrl || 'https://notebooklm.google.com/');
      if (parsed.searchParams.get('location')?.toLowerCase() === 'unsupported') {
        return false;
      }
      const host = parsed.hostname.toLowerCase();
      if (
        host === 'accounts.google.com' ||
        host === 'notebooklm.google' ||
        host === 'notebook.google'
      ) {
        return true;
      }
    } catch {
      return undefined;
    }
    return undefined;
  }
  if (res.statusCode >= 200 && res.statusCode < 300) {
    return true;
  }
  return undefined;
}

export interface GoogleRegionProbeResult {
  countryCode?: string;
  countryCodeAuthoritative?: boolean;
  ip?: string;
  altCountryCode?: string;
  aiSupported?: boolean;
}

export async function probeGoogleRegionViaProxy(
  proxyUrl: string | null,
  signal?: AbortSignal
): Promise<GoogleRegionProbeResult | null> {
  const [ytSettled, gSearchSettled, notebookLmSettled] = await Promise.allSettled([
    requestTextViaProxy(
      'https://www.youtube.com/sw.js_data',
      proxyUrl,
      GOOGLE_REGION_PROBE_TIMEOUT_MS,
      undefined,
      2,
      false,
      signal
    ),
    requestHttpViaProxy(
      'https://www.google.com/?hl=en',
      proxyUrl,
      GOOGLE_REGION_PROBE_TIMEOUT_MS,
      {
        acceptHeader: 'text/html, */*',
        redirectsLeft: 2,
        allowLocalhost: false,
        signal,
        allowRedirectStatus: true,
        onRedirect: ({ location, fromUrl }) =>
          extractGoogleRedirectCountry(location, fromUrl.toString()) ? 'stop' : 'follow',
      }
    ),
    requestHttpViaProxy(
      'https://notebooklm.google.com/',
      proxyUrl,
      GOOGLE_REGION_PROBE_TIMEOUT_MS,
      {
        acceptHeader: 'text/html, */*',
        redirectsLeft: 2,
        allowLocalhost: false,
        signal,
        userAgent: GOOGLE_AI_CHECK_USER_AGENT,
        headers: { 'Accept-Language': 'en-US,en;q=0.9' },
        allowRedirectStatus: true,
        onRedirect: ({ location, fromUrl }) =>
          isNotebookLmDomainMigrationRedirect(location, fromUrl.toString()) ? 'follow' : 'stop',
        discardBody: true,
      }
    ),
  ]);

  const ytRes =
    ytSettled.status === 'fulfilled' ? parseYoutubeSwJsData(ytSettled.value) : null;

  let gSearchRes: { countryCode: string; authoritative: boolean } | null = null;
  if (gSearchSettled.status === 'fulfilled') {
    const resp = gSearchSettled.value;
    const redirectCode = resp.location
      ? extractGoogleRedirectCountry(resp.location, resp.finalUrl)
      : null;
    if (redirectCode) {
      gSearchRes = { countryCode: redirectCode, authoritative: true };
    } else if (resp.statusCode >= 200 && resp.statusCode < 300 && resp.body) {
      const htmlRes = parseGoogleSearchHtml(resp.body);
      if (htmlRes) {
        gSearchRes = { countryCode: htmlRes.countryCode, authoritative: false };
      }
    }
  }

  const aiSupported =
    notebookLmSettled.status === 'fulfilled'
      ? classifyNotebookLmResponse(notebookLmSettled.value)
      : undefined;

  if (ytRes && gSearchRes && ytRes.countryCode !== gSearchRes.countryCode) {
    // 若 Google 搜索通过明确重定向（如 pref=hkredirect -> CN）得出结论，
    // 不允许缺少 visitorData 的 YouTube 默认 GL（常将 CN 回退为 US）作为备选值覆盖该结论。
    const altCountryCode =
      gSearchRes.authoritative && !ytRes.visitorCountryCode
        ? undefined
        : ytRes.countryCode;
    return {
      countryCode: gSearchRes.countryCode,
      countryCodeAuthoritative: gSearchRes.authoritative,
      ip: ytRes.ip,
      altCountryCode,
      aiSupported,
    };
  }

  if (gSearchRes) {
    return {
      countryCode: gSearchRes.countryCode,
      countryCodeAuthoritative: gSearchRes.authoritative,
      ip: ytRes?.ip,
      aiSupported,
    };
  }

  if (ytRes) {
    return {
      countryCode: ytRes.countryCode,
      countryCodeAuthoritative: Boolean(ytRes.visitorCountryCode),
      ip: ytRes.ip,
      aiSupported,
    };
  }

  if (aiSupported !== undefined) {
    return { aiSupported };
  }

  return null;
}

/**
 * 校验 Antigravity 的 Google 识别地区与 NotebookLM 地区可用性。
 */
export async function verifyAntigravityGoogleRegion(
  proxyUrl: string | null,
  probe: ProbeResult,
  signal?: AbortSignal
): Promise<void> {
  if (signal?.aborted) return;
  const baseCode = probe.countryCode.toUpperCase();
  if (!isValidIsoCountryCode(baseCode)) return;

  probe.googleCountryCode = undefined;
  probe.googleCountryName = undefined;
  probe.googleAiSupported = undefined;
  probe.regionMismatchDetail = null;

  const googleRes = await probeGoogleRegionViaProxy(proxyUrl, signal);
  if (signal?.aborted) return;

  let googleCode: string | undefined;
  if (googleRes) {
    if (googleRes.countryCode && googleRes.countryCode !== baseCode) {
      googleCode = googleRes.countryCode;
    } else if (googleRes.altCountryCode && googleRes.altCountryCode !== baseCode) {
      googleCode = googleRes.altCountryCode;
    } else {
      googleCode = googleRes.countryCode ?? googleRes.altCountryCode;
    }
    probe.googleAiSupported = googleRes.aiSupported;
  }

  if (googleCode && isValidIsoCountryCode(googleCode)) {
    probe.googleCountryCode = googleCode;
    probe.googleCountryName = getCountryNameZh(googleCode);
  }

  const googleMismatch = Boolean(
    probe.googleCountryCode && probe.googleCountryCode !== baseCode
  );
  const aiUnsupported = probe.googleAiSupported === false;

  if (googleMismatch && probe.googleCountryCode) {
    probe.regionMismatchDetail = aiUnsupported
      ? `离线库为 ${probe.countryName} (${baseCode})，但 Google 实际识别为 ${probe.googleCountryName} (${probe.googleCountryCode})，且 NotebookLM 判定该地区不受支持（疑似假${probe.countryName}/送中节点）`
      : `离线库为 ${probe.countryName} (${baseCode})，但 Google 实际识别为 ${probe.googleCountryName} (${probe.googleCountryCode})（疑似假${probe.countryName}/送中节点）`;
  } else if (aiUnsupported) {
    probe.regionMismatchDetail = probe.googleCountryCode
      ? `Google 识别地区为 ${probe.googleCountryName} (${probe.googleCountryCode})，但 NotebookLM 判定当前节点地区不受支持`
      : `离线库为 ${probe.countryName} (${baseCode})，但 NotebookLM 判定当前节点地区不受支持（疑似送中或受限地区节点）`;
  } else {
    probe.regionMismatchDetail = null;
  }
}
