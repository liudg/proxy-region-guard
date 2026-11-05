export type ProxyMode = 'auto' | 'manual' | 'direct';
export type ManualProxyProtocol = 'http' | 'socks5';

export type GuardStatus =
  | 'checking'   // 正在检测中
  | 'unset'      // 已获取当前地区，尚未设置默认地区
  | 'ok'         // 当前地区与默认地区一致（正常 🟢）
  | 'mismatch'   // 当前地区与默认地区不一致（异常 🔴）
  | 'error';     // 代理连接失败 / 超时（异常 🔴）

export interface AppConfig {
  defaultCountryCode: string | null;
  defaultCountryName: string | null;
  proxyMode: ProxyMode;
  manualProxy: {
    protocol: ManualProxyProtocol;
    host: string;
    port: number;
  };
  heartbeatIntervalSec: number; // 0 = 仅事件触发, >0 = 心跳秒数
  customProbeUrl: string;
  alertPopupEnabled: boolean;
  alertSoundEnabled: boolean;
  alertOnDisconnect: boolean;
  closeToTray: boolean;
  autoLaunch: boolean;

  // 进程守护配置
  killProcessesEnabled: boolean;       // 总开关：异常时自动强杀配置的进程
  killOnDisconnect: boolean;           // 代理断连/超时同样强杀进程
  killOnLocaleMismatch: boolean;       // 系统时区/区域与默认保护地区不一致时同样强杀进程
  protectedProcessPatterns: string[];  // 手动输入的进程匹配规则列表（支持通配符如 claude*.exe 与正则）
}

export interface WindowsLocaleState {
  timeZoneId: string;           // 例如 "China Standard Time"
  timeZoneDisplayName: string;  // 例如 "(UTC+08:00) 北京，重庆，香港特别行政区，乌鲁木齐"
  regionCode: string;           // 例如 "CN", "US"
  regionName: string;           // 例如 "中国", "美国"
}

export interface ClashRuntimeInfo {
  connected: boolean;
  source: string;         // 例如: "Clash Verge (Pipe)" 或 "Clash (127.0.0.1:9097)"
  mode: string;           // rule / global / direct
  mixedPort: number | null;
  activeNode: string | null;
  nodeChain: string[];    // 完整节点选择链，如 ["节点选择", "自动选择", "🇺🇸 美国 01"]
}

export interface ProbeResult {
  ip: string;
  countryCode: string;    // 离线 GeoIP mmdb 解析出的权威 ISO 国家代码，如 "US"
  countryName: string;    // 中文名称，如 "美国"
  edgeLoc?: string;       // Cloudflare Trace 边缘路由位置（用于辅助识别广播 IP）
  viaChannel: string;     // 本次检测实际使用的通道说明
  latencyMs: number;
  checkedAt: number;
}

export interface GuardEventLog {
  id: string;
  timestamp: number;
  level: 'info' | 'success' | 'warn' | 'danger';
  message: string;
}

export interface AlertPayload {
  alertType: 'mismatch' | 'disconnect' | 'locale-mismatch' | 'recovered';
  expectedCode: string | null;
  expectedName: string | null;
  actualCode: string | null;
  actualName: string | null;
  actualIp: string | null;
  edgeLoc?: string;
  viaChannel?: string;
  activeNode?: string | null;
  triggerReason: string;
  errorDetail?: string;
  killedProcesses?: string[];
  killError?: string;
  sysRegionCode?: string;
  sysRegionName?: string;
  sysTimeZoneDisplay?: string;
  soundEnabled: boolean;
  timestamp: number;
}

export interface AppStateSnapshot {
  status: GuardStatus;
  isChecking: boolean;
  isSyncingLocale: boolean;
  config: AppConfig;
  winLocale: WindowsLocaleState;
  lastProbe: ProbeResult | null;
  lastError: string | null;
  clashInfo: ClashRuntimeInfo;
  geoDbSource: string;
  logs: GuardEventLog[];
}

export interface LocaleSyncResult {
  ok: boolean;
  message: string;
  killedProcesses: string[];
  state: AppStateSnapshot;
}

export interface GuardBridgeAPI {
  getState: () => Promise<AppStateSnapshot>;
  checkNow: (reason?: string) => Promise<AppStateSnapshot>;
  setDefaultCurrent: () => Promise<AppStateSnapshot>;
  setDefaultRegion: (code: string | null) => Promise<AppStateSnapshot>;
  updateConfig: (partial: Partial<AppConfig>) => Promise<AppStateSnapshot>;
  clearLogs: () => Promise<AppStateSnapshot>;
  syncSystemLocaleToDefault: () => Promise<LocaleSyncResult>;
  restoreDefaultChinaLocale: () => Promise<LocaleSyncResult>;
  // 窗口控制（主面板与自绘警告窗通用）
  minimizeMain: () => void;
  closeMain: () => void;
  openMainFromAlert: () => void;
  dismissAlert: () => void;
  acceptCurrentAsDefaultFromAlert: () => Promise<void>;
  getAlertData: () => Promise<AlertPayload | null>;
  // 事件订阅
  onStateChanged: (cb: (state: AppStateSnapshot) => void) => () => void;
  onAlertData: (cb: (payload: AlertPayload) => void) => () => void;
}

declare global {
  interface Window {
    guardAPI: GuardBridgeAPI;
  }
}
