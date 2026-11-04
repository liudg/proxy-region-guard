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
  clashAutoDetect: boolean;
  clashCustomController: {
    host: string;
    port: number;
    secret: string;
  };
  heartbeatIntervalSec: number; // 0 = 仅事件触发, >0 = 心跳秒数
  customProbeUrl: string;
  alertPopupEnabled: boolean;
  alertSoundEnabled: boolean;
  alertOnDisconnect: boolean;
  closeToTray: boolean;
  autoLaunch: boolean;
}

export interface ClashRuntimeInfo {
  connected: boolean;
  source: string;         // 例如: "Clash Verge (Named Pipe)" 或 "127.0.0.1:9097"
  mode: string;           // rule / global / direct
  mixedPort: number | null;
  activeGroup: string | null;
  activeNode: string | null;
  nodeChain: string[];    // 完整节点选择链，如 ["节点选择", "自动选择", "🇺🇸 美国 01"]
}

export interface ProbeResult {
  ip: string;
  countryCode: string;    // 离线 GeoIP mmdb 解析出的权威 ISO 国家代码，如 "US"
  countryName: string;    // 中文名称，如 "美国"
  edgeLoc?: string;       // Cloudflare Trace 边缘路由位置（用于辅助识别广播 IP）
  viaChannel: string;     // 本次检测实际使用的通道说明
  probeSource: string;    // 命中的基础设施回显源，如 "Cloudflare Trace"
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
  alertType: 'mismatch' | 'disconnect' | 'recovered';
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
  soundEnabled: boolean;
  timestamp: number;
}

export interface AppStateSnapshot {
  status: GuardStatus;
  isChecking: boolean;
  config: AppConfig;
  lastProbe: ProbeResult | null;
  lastError: string | null;
  lastTriggerReason: string;
  clashInfo: ClashRuntimeInfo;
  systemProxyUrl: string | null;
  geoDbSource: string;
  logs: GuardEventLog[];
}

export interface GuardBridgeAPI {
  getState: () => Promise<AppStateSnapshot>;
  checkNow: (reason?: string) => Promise<AppStateSnapshot>;
  setDefaultCurrent: () => Promise<AppStateSnapshot>;
  setDefaultRegion: (code: string | null) => Promise<AppStateSnapshot>;
  updateConfig: (partial: Partial<AppConfig>) => Promise<AppStateSnapshot>;
  clearLogs: () => Promise<AppStateSnapshot>;
  testAlertPopup: () => Promise<void>;
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
