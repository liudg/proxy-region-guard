import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import * as os from 'node:os';
import { CountryResponse, Reader } from 'maxmind';
import { getCountryNameZh } from '../src/shared/countries';

type AnyGeoRecord = CountryResponse & {
  country_code?: string;
};

export class GeoIpService {
  private unifiedReader: Reader<AnyGeoRecord> | null = null;
  private v4Reader: Reader<AnyGeoRecord> | null = null;
  private v6Reader: Reader<AnyGeoRecord> | null = null;
  private dbSourceDescription = '未加载离线库';

  public async init(appRootPath: string): Promise<void> {
    const resPath = process.resourcesPath || '';

    // 1. 优先尝试打包后 resources 目录及开发环境内置目录
    const bundledDirs = [
      resPath,
      path.join(resPath, 'resources'),
      path.join(appRootPath, 'resources'),
      path.join(appRootPath, 'node_modules', '@ip-location-db', 'geolite2-country-mmdb'),
    ];

    for (const dir of bundledDirs) {
      if (!dir || !fs.existsSync(dir)) continue;

      const unifiedCandidate = path.join(dir, 'geolite2-country.mmdb');
      const countryCandidate = path.join(dir, 'Country.mmdb');
      const v4Candidate = path.join(dir, 'geolite2-country-ipv4.mmdb');
      const v6Candidate = path.join(dir, 'geolite2-country-ipv6.mmdb');

      if (fs.existsSync(unifiedCandidate)) {
        this.unifiedReader = new Reader<AnyGeoRecord>(fs.readFileSync(unifiedCandidate));
        this.dbSourceDescription = '内置离线库 (GeoLite2-Country.mmdb)';
        return;
      }

      if (fs.existsSync(countryCandidate)) {
        this.unifiedReader = new Reader<AnyGeoRecord>(fs.readFileSync(countryCandidate));
        this.dbSourceDescription = '内置离线库 (Country.mmdb)';
        return;
      }

      if (fs.existsSync(v4Candidate)) {
        this.v4Reader = new Reader<AnyGeoRecord>(fs.readFileSync(v4Candidate));
        if (fs.existsSync(v6Candidate)) {
          this.v6Reader = new Reader<AnyGeoRecord>(fs.readFileSync(v6Candidate));
        }
        this.dbSourceDescription = '内置离线库 (GeoLite2 IPv4/IPv6 mmdb)';
        return;
      }
    }

    // 2. 备选：扫描本机 Clash 系列目录自带的 Country.mmdb
    const appData = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    const clashMmdbPaths = [
      path.join(appData, 'io.github.clash-verge-rev.clash-verge-rev', 'Country.mmdb'),
      path.join(appData, 'clash-verge', 'Country.mmdb'),
      path.join(appData, 'mihomo-party', 'Country.mmdb'),
      path.join(os.homedir(), '.config', 'clash', 'Country.mmdb'),
      path.join(os.homedir(), '.config', 'mihomo', 'Country.mmdb'),
    ];

    for (const mmdbPath of clashMmdbPaths) {
      if (fs.existsSync(mmdbPath)) {
        try {
          this.unifiedReader = new Reader<AnyGeoRecord>(fs.readFileSync(mmdbPath));
          this.dbSourceDescription = `本机 Clash 离线库 (${path.basename(path.dirname(mmdbPath))})`;
          return;
        } catch {
          // try next
        }
      }
    }

    this.dbSourceDescription = '离线库未就绪 (仅使用边缘节点回退)';
  }

  public getSourceDescription(): string {
    return this.dbSourceDescription;
  }

  public lookup(ip: string, fallbackLoc?: string): { countryCode: string; countryName: string } {
    const cleanIp = ip.trim();
    const ipVersion = net.isIP(cleanIp);

    let code: string | undefined;

    try {
      let record: AnyGeoRecord | null = null;
      if (this.unifiedReader) {
        record = this.unifiedReader.get(cleanIp);
      } else if (ipVersion === 4 && this.v4Reader) {
        record = this.v4Reader.get(cleanIp);
      } else if (ipVersion === 6 && this.v6Reader) {
        record = this.v6Reader.get(cleanIp);
      }

      if (record) {
        code =
          record.country?.iso_code ||
          record.country_code ||
          record.registered_country?.iso_code;
      }
    } catch (err) {
      console.warn('[GeoIpService] Lookup failed for IP:', cleanIp, err);
    }

    if (!code && fallbackLoc && fallbackLoc !== 'XX' && fallbackLoc !== 'T1') {
      code = fallbackLoc.trim().toUpperCase();
    }

    const finalCode = (code || 'UNKNOWN').toUpperCase();
    return {
      countryCode: finalCode,
      countryName: getCountryNameZh(finalCode),
    };
  }
}
