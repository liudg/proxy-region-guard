import { app } from 'electron';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { AppConfig } from '../src/shared/types';
import { getCountryNameZh } from '../src/shared/countries';

export const DEFAULT_CONFIG: AppConfig = {
  defaultCountryCode: null,
  defaultCountryName: null,
  proxyMode: 'auto',
  manualProxy: {
    protocol: 'http',
    host: '127.0.0.1',
    port: 7890,
  },
  clashAutoDetect: true,
  clashCustomController: {
    host: '127.0.0.1',
    port: 9090,
    secret: '',
  },
  heartbeatIntervalSec: 15,
  customProbeUrl: '',
  alertPopupEnabled: true,
  alertSoundEnabled: true,
  alertOnDisconnect: true,
  closeToTray: true,
  autoLaunch: false,
  killProcessesEnabled: true,
  killOnDisconnect: true,
  killOnLocaleMismatch: true,
  protectedProcessPatterns: [],
};

function sanitizePatternList(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item !== 'string') continue;
    const trimmed = item.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      out.push(trimmed);
    }
  }
  return out;
}

export class ConfigStore {
  private filePath: string;
  private config: AppConfig;

  constructor() {
    const userDataDir = app.getPath('userData');
    this.filePath = path.join(userDataDir, 'guard-config.json');
    this.config = this.load();
  }

  private load(): AppConfig {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        const parsed = JSON.parse(raw);
        const merged: AppConfig = {
          ...DEFAULT_CONFIG,
          ...parsed,
          manualProxy: {
            ...DEFAULT_CONFIG.manualProxy,
            ...(parsed.manualProxy || {}),
          },
          clashCustomController: {
            ...DEFAULT_CONFIG.clashCustomController,
            ...(parsed.clashCustomController || {}),
          },
          protectedProcessPatterns: sanitizePatternList(parsed.protectedProcessPatterns),
        };
        if (merged.defaultCountryCode && !merged.defaultCountryName) {
          merged.defaultCountryName = getCountryNameZh(merged.defaultCountryCode);
        }
        return merged;
      }
    } catch (err) {
      console.error('[ConfigStore] Failed to load config, using defaults:', err);
    }
    return structuredClone(DEFAULT_CONFIG);
  }

  public get(): AppConfig {
    return structuredClone(this.config);
  }

  public update(partial: Partial<AppConfig>): AppConfig {
    this.config = {
      ...this.config,
      ...partial,
      manualProxy: {
        ...this.config.manualProxy,
        ...(partial.manualProxy || {}),
      },
      clashCustomController: {
        ...this.config.clashCustomController,
        ...(partial.clashCustomController || {}),
      },
      protectedProcessPatterns:
        partial.protectedProcessPatterns !== undefined
          ? sanitizePatternList(partial.protectedProcessPatterns)
          : this.config.protectedProcessPatterns,
    };

    if (this.config.defaultCountryCode) {
      this.config.defaultCountryCode = this.config.defaultCountryCode.toUpperCase();
      this.config.defaultCountryName = getCountryNameZh(this.config.defaultCountryCode);
    } else {
      this.config.defaultCountryName = null;
    }

    this.save();
    return this.get();
  }

  private save(): void {
    try {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(this.filePath, JSON.stringify(this.config, null, 2), 'utf-8');
    } catch (err) {
      console.error('[ConfigStore] Failed to save config:', err);
    }
  }
}
