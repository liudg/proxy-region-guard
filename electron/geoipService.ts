import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { CountryResponse, Reader } from 'maxmind';
import { getCountryNameZh, isValidIsoCountryCode } from '../src/shared/countries';

type AnyGeoRecord = CountryResponse & {
  country_code?: string;
};

export class GeoIpService {
  private reader: Reader<AnyGeoRecord> | null = null;
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
      if (!fs.existsSync(mmdbFile)) continue;
      try {
        const buf = await fs.promises.readFile(mmdbFile);
        this.reader = new Reader<AnyGeoRecord>(buf);
        this.dbSourceDescription = '内置离线库 (GeoLite2-Country.mmdb)';
        return;
      } catch (err) {
        console.warn('[GeoIpService] Failed to load mmdb:', mmdbFile, err);
      }
    }

    this.dbSourceDescription = '离线库未就绪 (仅使用边缘节点回退)';
  }

  public getSourceDescription(): string {
    return this.dbSourceDescription;
  }

  public lookup(ip: string, fallbackLoc?: string): { countryCode: string; countryName: string } {
    const cleanIp = ip.trim();
    let code: string | undefined;

    if (this.reader && net.isIP(cleanIp)) {
      try {
        const record = this.reader.get(cleanIp);
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
        console.warn('[GeoIpService] Lookup failed for IP:', cleanIp, err);
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
