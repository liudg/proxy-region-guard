import { execFile } from 'node:child_process';
import { WindowsLocaleState } from '../src/shared/types';
import { isValidIsoCountryCode } from '../src/shared/countries';
import {
  DEFAULT_CHINA_REGION_CODE,
  DEFAULT_CHINA_TIMEZONE_ID,
  getWindowsRegionDisplayNameZh,
  mapIanaToWindowsTimeZone,
} from '../src/shared/timezones';
import { decodeWinConsoleBuffer } from './processGuard';
import { requestJsonViaProxy } from './netClient';

const tzDisplayCache = new Map<string, string>();

function execRegQuery(keyPath: string, valueName?: string): Promise<string> {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') {
      resolve('');
      return;
    }
    const args = valueName ? ['query', keyPath, '/v', valueName] : ['query', keyPath];
    execFile(
      'reg.exe',
      args,
      { encoding: 'buffer', windowsHide: true, timeout: 2500 },
      (err, stdout) => {
        if (err || !stdout) {
          resolve('');
          return;
        }
        resolve(decodeWinConsoleBuffer(stdout));
      }
    );
  });
}

function parseRegSzValue(output: string, valueName: string): string | null {
  const escaped = valueName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`^\\s*${escaped}\\s+REG_[A-Z0-9_]+\\s+(.+)$`, 'im');
  const m = output.match(re);
  return m && m[1] ? m[1].trim() : null;
}

async function getTimeZoneDisplayName(tzId: string): Promise<string> {
  if (!tzId) return '未知时区';
  const cached = tzDisplayCache.get(tzId);
  if (cached) return cached;

  const out = await execRegQuery(
    `HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\${tzId}`,
    'Display'
  );
  const display = parseRegSzValue(out, 'Display') || tzId;
  tzDisplayCache.set(tzId, display);
  return display;
}

export async function readWindowsLocaleState(): Promise<WindowsLocaleState> {
  if (process.platform !== 'win32') {
    return {
      timeZoneId: DEFAULT_CHINA_TIMEZONE_ID,
      timeZoneDisplayName: '(UTC+08:00) 北京，重庆，香港特别行政区，乌鲁木齐',
      regionCode: DEFAULT_CHINA_REGION_CODE,
      regionName: '中国',
    };
  }

  const [tzOut, geoOut] = await Promise.all([
    execRegQuery('HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation', 'TimeZoneKeyName'),
    execRegQuery('HKCU\\Control Panel\\International\\Geo', 'Name'),
  ]);

  const timeZoneId = parseRegSzValue(tzOut, 'TimeZoneKeyName') || DEFAULT_CHINA_TIMEZONE_ID;
  const regionCode = (parseRegSzValue(geoOut, 'Name') || DEFAULT_CHINA_REGION_CODE).toUpperCase();
  const timeZoneDisplayName = await getTimeZoneDisplayName(timeZoneId);

  return {
    timeZoneId,
    timeZoneDisplayName,
    regionCode,
    regionName: getWindowsRegionDisplayNameZh(regionCode),
  };
}

function runTzUtilSet(windowsTimeZoneId: string): Promise<{ ok: boolean; errText?: string }> {
  return new Promise((resolve) => {
    execFile(
      'tzutil.exe',
      ['/s', windowsTimeZoneId],
      { encoding: 'buffer', windowsHide: true, timeout: 5000 },
      (err, stdout, stderr) => {
        if (!err) {
          resolve({ ok: true });
          return;
        }
        const msg = `${decodeWinConsoleBuffer(stdout)} ${decodeWinConsoleBuffer(stderr)}`.trim();
        resolve({ ok: false, errText: msg || err.message });
      }
    );
  });
}

function runSetWinHomeLocation(isoCountryCode: string): Promise<{ ok: boolean; errText?: string }> {
  return new Promise((resolve) => {
    const upper = isoCountryCode.trim().toUpperCase();
    if (!isValidIsoCountryCode(upper)) {
      resolve({ ok: false, errText: `无效的国家/地区代码: ${isoCountryCode}` });
      return;
    }

    const psScript = [
      '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
      `$ErrorActionPreference = 'Stop'`,
      `$r = New-Object System.Globalization.RegionInfo('${upper}')`,
      `Set-WinHomeLocation -GeoId $r.GeoId`,
    ].join('; ');

    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', psScript],
      { encoding: 'buffer', windowsHide: true, timeout: 8000 },
      (err, stdout, stderr) => {
        if (!err) {
          resolve({ ok: true });
          return;
        }
        const msg = `${decodeWinConsoleBuffer(stdout)} ${decodeWinConsoleBuffer(stderr)}`.trim();
        resolve({ ok: false, errText: msg || err.message });
      }
    );
  });
}

async function isAutoTimeZoneServiceEnabled(): Promise<boolean> {
  const out = await execRegQuery('HKLM\\SYSTEM\\CurrentControlSet\\Services\\tzautoupdate', 'Start');
  const startVal = parseRegSzValue(out, 'Start');
  return startVal === '0x3' || startVal === '3' || startVal === '0x2' || startVal === '2';
}

export async function applyWindowsTimeZoneAndRegion(
  windowsTimeZoneId: string,
  isoCountryCode: string
): Promise<{ ok: boolean; error?: string; updated: WindowsLocaleState }> {
  const upperCountry = isoCountryCode.trim().toUpperCase();
  const previous = await readWindowsLocaleState();

  if (!isValidIsoCountryCode(upperCountry)) {
    return {
      ok: false,
      error: `不支持将该地区代码 (${isoCountryCode}) 设置为系统区域`,
      updated: previous,
    };
  }

  // 第一步：先设置系统时区并确认生效，避免出现“时区失败但区域已改”的半残状态
  const tzChanged = previous.timeZoneId.toLowerCase() !== windowsTimeZoneId.toLowerCase();
  if (tzChanged) {
    const tzRes = await runTzUtilSet(windowsTimeZoneId);
    const afterTz = await readWindowsLocaleState();
    const tzMatched = afterTz.timeZoneId.toLowerCase() === windowsTimeZoneId.toLowerCase();

    if (!tzRes.ok || !tzMatched) {
      const autoTzOn = await isAutoTimeZoneServiceEnabled();
      if (autoTzOn) {
        return {
          ok: false,
          error:
            '系统开启了“自动设置时区”，请先在 Windows 设置 -> 时间和语言 -> 日期和时间 中关闭「自动设置时区」后再试',
          updated: afterTz,
        };
      }
      return {
        ok: false,
        error: `设置系统时区失败 (${tzRes.errText || '未生效'})`,
        updated: afterTz,
      };
    }
  }

  // 第二步：设置系统国家/区域；若失败则回滚第一步修改过的时区
  const regionChanged = previous.regionCode.toUpperCase() !== upperCountry;
  if (regionChanged) {
    const regionRes = await runSetWinHomeLocation(upperCountry);
    const updated = await readWindowsLocaleState();
    const regionMatched = updated.regionCode.toUpperCase() === upperCountry;

    if (!regionRes.ok || !regionMatched) {
      if (tzChanged) {
        await runTzUtilSet(previous.timeZoneId);
      }
      const rolledBack = await readWindowsLocaleState();
      return {
        ok: false,
        error: `设置系统区域失败 (${regionRes.errText || '未生效'})`,
        updated: rolledBack,
      };
    }

    return { ok: true, updated };
  }

  const updated = await readWindowsLocaleState();
  return { ok: true, updated };
}

interface OnlineTzApiSpec {
  buildUrl: (ip?: string) => string;
  extract: (data: Record<string, unknown>) => { country?: string; ianaTz?: string };
}

const ONLINE_TZ_APIS: OnlineTzApiSpec[] = [
  {
    buildUrl: (ip) => (ip ? `https://ipwho.is/${encodeURIComponent(ip)}` : 'https://ipwho.is/'),
    extract: (d) => {
      if (d['success'] === false) return {};
      const tzObj = d['timezone'] as Record<string, unknown> | undefined;
      return {
        country: typeof d['country_code'] === 'string' ? d['country_code'] : undefined,
        ianaTz: tzObj && typeof tzObj['id'] === 'string' ? tzObj['id'] : undefined,
      };
    },
  },
  {
    buildUrl: (ip) =>
      ip
        ? `https://freeipapi.com/api/json/${encodeURIComponent(ip)}`
        : 'https://freeipapi.com/api/json',
    extract: (d) => {
      const tzs = d['timeZones'];
      const firstTz =
        Array.isArray(tzs) && typeof tzs[0] === 'string'
          ? tzs[0]
          : typeof d['timeZone'] === 'string'
          ? d['timeZone']
          : undefined;
      return {
        country: typeof d['countryCode'] === 'string' ? d['countryCode'] : undefined,
        ianaTz: firstTz,
      };
    },
  },
  {
    buildUrl: (ip) =>
      ip ? `https://ipapi.co/${encodeURIComponent(ip)}/json/` : 'https://ipapi.co/json/',
    extract: (d) => ({
      country: typeof d['country_code'] === 'string' ? d['country_code'] : undefined,
      ianaTz: typeof d['timezone'] === 'string' ? d['timezone'] : undefined,
    }),
  },
];

/**
 * 仅针对多时区大国（美/加/澳/俄等），经由当前代理隧道探测出口 IP 所在的精确城市级 IANA 时区
 */
export async function queryExactExitIanaTimeZone(
  proxyUrl: string | null,
  expectedCountryCode: string,
  knownExitIp?: string | null
): Promise<string | null> {
  const expected = expectedCountryCode.trim().toUpperCase();
  const cleanIp =
    knownExitIp && !knownExitIp.includes(':') ? knownExitIp.trim() : undefined;

  for (const spec of ONLINE_TZ_APIS) {
    try {
      const url = spec.buildUrl(cleanIp);
      const json = await requestJsonViaProxy<Record<string, unknown>>(url, proxyUrl, 3200);
      const { country, ianaTz } = spec.extract(json);
      // 必须明确返回国家代码且与期望国家一致，防止无国家字段或跨国脏数据污染
      if (!country || country.trim().toUpperCase() !== expected) {
        continue;
      }
      if (ianaTz && mapIanaToWindowsTimeZone(ianaTz)) {
        return ianaTz.trim();
      }
    } catch {
      // 自动尝试下一个互备源
    }
  }

  return null;
}
