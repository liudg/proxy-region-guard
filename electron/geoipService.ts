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

  public lookup(ip: string, fallbackLoc?: string): { countryCode: string; countryName: string } {
    const cleanIp = ip.trim();
    let code: string | undefined;

    if (net.isIP(cleanIp)) {
      if (this.mmdbIpCache.has(cleanIp)) {
        code = this.mmdbIpCache.get(cleanIp) || undefined;
      } else {
        const reader = this.getOrLoadReader();
        if (reader) {
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
            if (this.mmdbIpCache.size >= MAX_IP_CACHE_ENTRIES) {
              const oldestKey = this.mmdbIpCache.keys().next().value;
              if (oldestKey !== undefined) {
                this.mmdbIpCache.delete(oldestKey);
              }
            }
            this.mmdbIpCache.set(cleanIp, code || null);
          } catch (err) {
            console.warn('[GeoIpService] Lookup failed for IP:', cleanIp, err);
          }
        }
      }
    }

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
