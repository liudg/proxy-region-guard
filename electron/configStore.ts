import { app } from 'electron';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { AppConfig, ManualProxyProtocol, ProxyMode } from '../src/shared/types';
import { getCountryNameZh, isValidIsoCountryCode } from '../src/shared/countries';

export const DEFAULT_CONFIG: AppConfig = {
  defaultCountryCode: null,
  defaultCountryName: null,
  proxyMode: 'auto',
  manualProxy: {
    protocol: 'http',
    host: '127.0.0.1',
    port: 7890,
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
  selectedClashNode: null,
  dedicatedProxyPort: 27897,
  claudeExePath: '',
  claudeExclusiveGuard: true,
  antigravityClashNode: null,
  antigravityDedicatedPort: 27898,
  antigravityExePath: '',
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

function normalizeConfig(raw: Partial<AppConfig>): AppConfig {
  const proxyMode: ProxyMode =
    raw.proxyMode === 'manual' || raw.proxyMode === 'direct' ? raw.proxyMode : 'auto';

  const rawManual: Partial<AppConfig['manualProxy']> =
    raw.manualProxy && typeof raw.manualProxy === 'object' ? raw.manualProxy : {};
  const protocol: ManualProxyProtocol = rawManual.protocol === 'socks5' ? 'socks5' : 'http';
  const host =
    typeof rawManual.host === 'string' && rawManual.host.trim()
      ? rawManual.host.trim()
      : DEFAULT_CONFIG.manualProxy.host;
  const portNum = Number(rawManual.port);
  const port =
    Number.isFinite(portNum) && portNum >= 1 && portNum <= 65535
      ? Math.round(portNum)
      : DEFAULT_CONFIG.manualProxy.port;

  const hbNum = Number(raw.heartbeatIntervalSec);
  const heartbeatIntervalSec =
    Number.isFinite(hbNum) && hbNum >= 0
      ? Math.round(hbNum)
      : DEFAULT_CONFIG.heartbeatIntervalSec;

  const normalizedCode = isValidIsoCountryCode(raw.defaultCountryCode)
    ? raw.defaultCountryCode.trim().toUpperCase()
    : null;

  const selectedClashNode =
    typeof raw.selectedClashNode === 'string' && raw.selectedClashNode.trim()
      ? raw.selectedClashNode.trim()
      : null;

  const dedPortNum = Number(raw.dedicatedProxyPort);
  const dedicatedProxyPort =
    Number.isFinite(dedPortNum) && dedPortNum >= 1024 && dedPortNum <= 65535
      ? Math.round(dedPortNum)
      : DEFAULT_CONFIG.dedicatedProxyPort;

  const claudeExePath =
    typeof raw.claudeExePath === 'string' ? raw.claudeExePath.trim() : '';

  const claudeExclusiveGuard =
    typeof raw.claudeExclusiveGuard === 'boolean'
      ? raw.claudeExclusiveGuard
      : DEFAULT_CONFIG.claudeExclusiveGuard;

  const antigravityClashNode =
    typeof raw.antigravityClashNode === 'string' && raw.antigravityClashNode.trim()
      ? raw.antigravityClashNode.trim()
      : null;

  const agPortNum = Number(raw.antigravityDedicatedPort);
  let antigravityDedicatedPort =
    Number.isFinite(agPortNum) && agPortNum >= 1024 && agPortNum <= 65535
      ? Math.round(agPortNum)
      : DEFAULT_CONFIG.antigravityDedicatedPort;

  if (antigravityDedicatedPort === dedicatedProxyPort) {
    antigravityDedicatedPort = dedicatedProxyPort === 27898 ? 27899 : 27898;
  }

  const antigravityExePath =
    typeof raw.antigravityExePath === 'string' ? raw.antigravityExePath.trim() : '';

  return {
    defaultCountryCode: normalizedCode,
    defaultCountryName: normalizedCode ? getCountryNameZh(normalizedCode) : null,
    proxyMode,
    manualProxy: { protocol, host, port },
    heartbeatIntervalSec,
    customProbeUrl: typeof raw.customProbeUrl === 'string' ? raw.customProbeUrl.trim() : '',
    alertPopupEnabled:
      typeof raw.alertPopupEnabled === 'boolean'
        ? raw.alertPopupEnabled
        : DEFAULT_CONFIG.alertPopupEnabled,
    alertSoundEnabled:
      typeof raw.alertSoundEnabled === 'boolean'
        ? raw.alertSoundEnabled
        : DEFAULT_CONFIG.alertSoundEnabled,
    alertOnDisconnect:
      typeof raw.alertOnDisconnect === 'boolean'
        ? raw.alertOnDisconnect
        : DEFAULT_CONFIG.alertOnDisconnect,
    closeToTray:
      typeof raw.closeToTray === 'boolean' ? raw.closeToTray : DEFAULT_CONFIG.closeToTray,
    autoLaunch:
      typeof raw.autoLaunch === 'boolean' ? raw.autoLaunch : DEFAULT_CONFIG.autoLaunch,
    killProcessesEnabled:
      typeof raw.killProcessesEnabled === 'boolean'
        ? raw.killProcessesEnabled
        : DEFAULT_CONFIG.killProcessesEnabled,
    killOnDisconnect:
      typeof raw.killOnDisconnect === 'boolean'
        ? raw.killOnDisconnect
        : DEFAULT_CONFIG.killOnDisconnect,
    killOnLocaleMismatch:
      typeof raw.killOnLocaleMismatch === 'boolean'
        ? raw.killOnLocaleMismatch
        : DEFAULT_CONFIG.killOnLocaleMismatch,
    protectedProcessPatterns: sanitizePatternList(raw.protectedProcessPatterns),
    selectedClashNode,
    dedicatedProxyPort,
    claudeExePath,
    claudeExclusiveGuard,
    antigravityClashNode,
    antigravityDedicatedPort,
    antigravityExePath,
  };
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
        const parsed = JSON.parse(raw) as Partial<AppConfig>;
        if (parsed && typeof parsed === 'object') {
          return normalizeConfig(parsed);
        }
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
    this.config = normalizeConfig({
      ...this.config,
      ...partial,
      manualProxy: {
        ...this.config.manualProxy,
        ...(partial.manualProxy || {}),
      },
      protectedProcessPatterns:
        partial.protectedProcessPatterns !== undefined
          ? partial.protectedProcessPatterns
          : this.config.protectedProcessPatterns,
    });

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
