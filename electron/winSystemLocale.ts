import { execFile } from 'node:child_process';
import * as http from 'node:http';
import * as https from 'node:https';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { WindowsLocaleState } from '../src/shared/types';
import {
  DEFAULT_CHINA_REGION_CODE,
  DEFAULT_CHINA_TIMEZONE_ID,
  getWindowsRegionDisplayNameZh,
  mapIanaToWindowsTimeZone,
} from '../src/shared/timezones';
import { decodeWinConsoleBuffer } from './processGuard';

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
      geoId: '45',
    };
  }

  const [tzOut, geoOut] = await Promise.all([
    execRegQuery('HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation', 'TimeZoneKeyName'),
    execRegQuery('HKCU\\Control Panel\\International\\Geo'),
  ]);

  const timeZoneId = parseRegSzValue(tzOut, 'TimeZoneKeyName') || DEFAULT_CHINA_TIMEZONE_ID;
  const regionCode = (parseRegSzValue(geoOut, 'Name') || DEFAULT_CHINA_REGION_CODE).toUpperCase();
  const geoId = parseRegSzValue(geoOut, 'Nation') || '';
  const timeZoneDisplayName = await getTimeZoneDisplayName(timeZoneId);

  return {
    timeZoneId,
    timeZoneDisplayName,
    regionCode,
    regionName: getWindowsRegionDisplayNameZh(regionCode),
    geoId,
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
    if (!/^[A-Z]{2}$/.test(upper)) {
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

  const [tzRes, regionRes] = await Promise.all([
    runTzUtilSet(windowsTimeZoneId),
    runSetWinHomeLocation(upperCountry),
  ]);

  const updated = await readWindowsLocaleState();

  const tzMatched = updated.timeZoneId.toLowerCase() === windowsTimeZoneId.toLowerCase();
  const regionMatched = updated.regionCode.toUpperCase() === upperCountry;

  if (!tzRes.ok || !tzMatched) {
    const autoTzOn = await isAutoTimeZoneServiceEnabled();
    if (autoTzOn) {
      return {
        ok: false,
        error: '系统开启了“自动设置时区”，请先在 Windows 设置 -> 时间和语言 -> 日期和时间 中关闭「自动设置时区」后再试',
        updated,
      };
    }
    return {
      ok: false,
      error: `设置系统时区失败 (${tzRes.errText || '未生效'})`,
      updated,
    };
  }

  if (!regionRes.ok || !regionMatched) {
    return {
      ok: false,
      error: `设置系统区域失败 (${regionRes.errText || '未生效'})`,
      updated,
    };
  }

  return { ok: true, updated };
}

interface OnlineTzApiSpec {
  url: string;
  extract: (data: Record<string, unknown>) => { country?: string; ianaTz?: string };
}

const ONLINE_TZ_APIS: OnlineTzApiSpec[] = [
  {
    url: 'https://ipwho.is/',
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
    url: 'https://freeipapi.com/api/json',
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
    url: 'https://ipapi.co/json/',
    extract: (d) => ({
      country: typeof d['country_code'] === 'string' ? d['country_code'] : undefined,
      ianaTz: typeof d['timezone'] === 'string' ? d['timezone'] : undefined,
    }),
  },
];

function fetchJsonViaProxy(
  targetUrl: string,
  proxyUrl: string | null,
  timeoutMs: number
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(targetUrl);
    const isHttps = parsedUrl.protocol === 'https:';

    let agent: http.Agent | undefined;
    if (proxyUrl) {
      agent = proxyUrl.startsWith('socks')
        ? new SocksProxyAgent(proxyUrl, { keepAlive: false, timeout: timeoutMs })
        : new HttpsProxyAgent(proxyUrl, { keepAlive: false, timeout: timeoutMs });
    } else {
      agent = isHttps
        ? new https.Agent({ keepAlive: false, timeout: timeoutMs })
        : new http.Agent({ keepAlive: false, timeout: timeoutMs });
    }

    const transport = isHttps ? https : http;
    const req = transport.request(
      parsedUrl,
      {
        method: 'GET',
        agent,
        timeout: timeoutMs,
        headers: {
          'User-Agent': 'curl/8.7.1',
          Accept: 'application/json',
          'Cache-Control': 'no-cache',
          Connection: 'close',
        },
      },
      (res) => {
        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.from(c)));
        res.on('end', () => {
          try {
            const parsed = JSON.parse(Buffer.concat(chunks).toString('utf-8')) as Record<
              string,
              unknown
            >;
            resolve(parsed);
          } catch (e) {
            reject(e);
          }
        });
      }
    );

    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (err) => reject(err));
    req.end();
  });
}

/**
 * 经由当前代理隧道探测出口 IP 所在的精确城市级 IANA 时区（如区分美国洛杉矶与纽约）
 */
export async function queryExactExitIanaTimeZone(
  proxyUrl: string | null,
  expectedCountryCode: string
): Promise<string | null> {
  const expected = expectedCountryCode.trim().toUpperCase();

  for (const spec of ONLINE_TZ_APIS) {
    try {
      const json = await fetchJsonViaProxy(spec.url, proxyUrl, 3500);
      const { country, ianaTz } = spec.extract(json);
      if (country && country.trim().toUpperCase() !== expected) {
        // 如果在线接口看到的国家与期望国家不一致，跳过以防误配跨国时区
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
