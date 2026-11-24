import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { CountryResponse, Reader } from 'maxmind';
import { getCountryNameZh, isValidIsoCountryCode } from '../src/shared/countries';

type AnyGeoRecord = CountryResponse & {
  country_code?: string;
};

const READER_IDLE_RELEASE_MS = 5000;
const MAX_IP_CACHE_ENTRIES = 128;

export class GeoIpService {
  private mmdbFilePath: string | null = null;
  private reader: Reader<AnyGeoRecord> | null = null;
  private releaseTimer: NodeJS.Timeout | null = null;
  private mmdbIpCache = new Map<string, string | null>();
  private dbSourceDescription = '未加载离线库';

  public async init(appRootPath: string): Promise<void> {
    this.mmdbFilePath = null;
    this.reader = null;
    this.mmdbIpCache.clear();
    if (this.releaseTimer) {
      clearTimeout(this.releaseTimer);
      this.releaseTimer = null;
    }
    const resPath = process.resourcesPath || '';

    const candidateFiles = [
      resPath ? path.join(resPath, 'geolite2-country.mmdb') : '',
      path.join(appRootPath, 'resources', 'geolite2-country.mmdb'),
      path.join(
        appRootPath,
        'node_modules',
        '@ip-location-db',
        'geolite2-country-mmdb',
        'geolite2-country.mmdb'
      ),
    ].filter(Boolean);

    for (const mmdbFile of candidateFiles) {
      try {
        const stat = await fs.promises.stat(mmdbFile);
        if (stat.isFile() && stat.size > 1024) {
          this.mmdbFilePath = mmdbFile;
          this.dbSourceDescription = '内置离线库 (GeoLite2-Country.mmdb)';
          return;
        }
      } catch {
        // try next candidate
      }
    }

    this.dbSourceDescription = '离线库未就绪 (仅使用边缘节点回退)';
  }

  public getSourceDescription(): string {
    return this.dbSourceDescription;
  }

  private getOrLoadReader(): Reader<AnyGeoRecord> | null {
    if (!this.mmdbFilePath) return null;
    if (!this.reader) {
      try {
        const buf = fs.readFileSync(this.mmdbFilePath);
        this.reader = new Reader<AnyGeoRecord>(buf);
      } catch (err) {
        console.warn('[GeoIpService] Failed to load mmdb:', this.mmdbFilePath, err);
        return null;
      }
    }
    this.scheduleReaderRelease();
    return this.reader;
  }

  private scheduleReaderRelease(): void {
    if (this.releaseTimer) {
      clearTimeout(this.releaseTimer);
    }
    this.releaseTimer = setTimeout(() => {
      this.releaseTimer = null;
      this.reader = null;
    }, READER_IDLE_RELEASE_MS);
    this.releaseTimer.unref?.();
  }

  private lookupMmdbCountryCode(cleanIp: string, strict: boolean): string | null {
    if (this.mmdbIpCache.has(cleanIp)) {
      return this.mmdbIpCache.get(cleanIp) ?? null;
    }
    const reader = this.getOrLoadReader();
    if (!reader) {
      if (strict) throw new Error('离线 GeoIP 数据库未就绪');
      return null;
    }
    let code: string | null = null;
    try {
      const record = reader.get(cleanIp);
      if (record) {
        const candidate =
          record.country?.iso_code ||
          record.country_code ||
          record.registered_country?.iso_code;
        if (isValidIsoCountryCode(candidate)) {
          code = candidate.trim().toUpperCase();
        }
      }
    } catch (err) {
      if (strict) {
        throw new Error(
          `读取离线 GeoIP 数据库失败 (${cleanIp})：${err instanceof Error ? err.message : String(err)}`
        );
      }
      console.warn('[GeoIpService] Lookup failed for IP:', cleanIp, err);
      return null;
    }
    if (this.mmdbIpCache.size >= MAX_IP_CACHE_ENTRIES) {
      const oldestKey = this.mmdbIpCache.keys().next().value;
      if (oldestKey !== undefined) {
        this.mmdbIpCache.delete(oldestKey);
      }
    }
    this.mmdbIpCache.set(cleanIp, code);
    return code;
  }

  public lookupOfflineStrict(ip: string): { countryCode: string; countryName: string } {
    const cleanIp = ip.trim();
    if (!net.isIP(cleanIp)) {
      throw new Error(`无效的出口 IP：${ip}`);
    }
    if (!this.mmdbFilePath) {
      throw new Error('离线 GeoIP 数据库未就绪');
    }
    const code = this.lookupMmdbCountryCode(cleanIp, true);
    if (!code) {
      throw new Error(`离线 GeoIP 数据库无法确定出口 ${cleanIp} 的国家`);
    }
    return {
      countryCode: code,
      countryName: getCountryNameZh(code),
    };
  }

  public lookup(ip: string, fallbackLoc?: string): { countryCode: string; countryName: string } {
    const cleanIp = ip.trim();
    let code: string | null = net.isIP(cleanIp) ? this.lookupMmdbCountryCode(cleanIp, false) : null;

    if (!code && isValidIsoCountryCode(fallbackLoc)) {
      code = fallbackLoc.trim().toUpperCase();
    }

    const finalCode = code || 'UNKNOWN';
    return {
      countryCode: finalCode,
      countryName: getCountryNameZh(finalCode),
    };
  }
}
