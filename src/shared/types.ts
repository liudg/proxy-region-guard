export type ProxyMode = 'auto' | 'manual' | 'direct';
export type ManualProxyProtocol = 'http' | 'socks5';

export type GuardStatus =
  | 'checking'   // 正在检测中
  | 'unset'      // 已获取当前地区，尚未设置默认地区
  | 'ok'         // 当前地区与默认地区、系统时区/区域一致（正常 🟢）
  | 'mismatch'   // 当前地区与默认地区或系统时区/区域不一致（异常 🔴）
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
  killOnLocaleMismatch: boolean;       // 系统时区/区域与代理保护地区不一致时同样强杀进程
  protectedProcessPatterns: string[];  // 手动输入的进程匹配规则列表（支持通配符如 claude*.exe 与正则）

  // Clash 指定代理节点与 Claude 专栏配置
  selectedClashNode: string | null;    // 下拉选择的指定 Clash 节点名称
  dedicatedProxyPort: number;          // 为所选节点分配的本地独立专属代理端口（默认 27897）
  claudeExePath: string;               // 自定义 Claude Desktop 启动路径（留空则自动探测）
  claudeExclusiveGuard: boolean;       // 唯一入口守护：禁止任何外部途径启动 Claude，不一致立杀

  // Antigravity 启动器专栏配置（纯代理绑定，无监控/预警/强杀）
  antigravityClashNode: string | null; // Antigravity 独立指定的 Clash 节点名称
  antigravityDedicatedPort: number;    // Antigravity 独立专属本地代理端口（默认 27898）
  antigravityExePath: string;          // 自定义 Antigravity.exe 启动路径（留空则自动探测）
}

export interface WindowsLocaleState {
  timeZoneId: string;           // 例如 "China Standard Time"
  timeZoneDisplayName: string;  // 例如 "(UTC+08:00) 北京，重庆，香港特别行政区，乌鲁木齐"
  regionCode: string;           // 例如 "CN", "US"
  regionName: string;           // 例如 "中国", "美国"
}

export interface ClashProxyNodeOption {
  name: string;
  type: string;
  isGroup: boolean;
  now?: string;
  delay?: number;
  alive?: boolean;
}

export interface ClashRuntimeInfo {
  connected: boolean;
  source: string;         // 例如: "Clash Verge (Pipe)" 或 "Clash (127.0.0.1:9097)"
  mode: string;           // rule / global / direct
  mixedPort: number | null;
  activeNode: string | null;
  nodeChain: string[];    // 完整节点选择链，如 ["节点选择", "自动选择", "🇺🇸 美国 01"]
  availableNodes: ClashProxyNodeOption[]; // 从 Clash 读取的可选节点与策略组列表
  boundNode: string | null;               // 当前 Claude 独立专属端口实际绑定的节点名
  dedicatedPort: number | null;           // 当前 Claude 独立专属端口（如 27897）
  dedicatedPortListening: boolean;        // Claude 独立专属端口是否已就绪监听
  antigravityBoundNode: string | null;    // 当前 Antigravity 独立专属端口实际绑定的节点名
  antigravityDedicatedPort: number | null;// 当前 Antigravity 独立专属端口（如 27898）
  antigravityPortListening: boolean;      // Antigravity 独立专属端口是否已就绪监听
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

export interface ClaudeRuntimeState {
  detectedExePath: string | null;
  installType: 'msix-alias' | 'msix-direct' | 'squirrel' | 'custom' | 'not-found';
  running: boolean;
  processCount: number;
  authorizedSession: boolean;     // 是否通过本程序 Claude 专栏验证并授权启动
  canLaunch: boolean;             // 当前是否满足启动前全部校验条件
  launchBlockReason: string | null;
  threeWayMatched: boolean;       // 指定代理地区 == 系统区域 == 系统时区
  proxyCountryCode: string | null;
  proxyCountryName: string | null;
  winRegionMatched: boolean;
  winTimeZoneMatched: boolean;
}

export interface AntigravityRuntimeState {
  detectedExePath: string | null;
  installType: 'standard' | 'custom' | 'not-found';
  running: boolean;
  uiProcessCount: number;         // Antigravity.exe 进程数量
  languageServerCount: number;    // language_server*.exe 进程数量
  totalProcessCount: number;      // 关联进程总数
  proxiedSession: boolean;        // 当前运行的实例是否已注入专属代理参数
  canLaunch: boolean;             // 是否满足启动条件（存在可执行文件 + 已选节点 + 专属端口就绪）
  launchHint: string | null;      // 未满足启动条件时的操作指引（非告警）
  isProbingNode: boolean;         // 是否正在探测所选节点的出口信息
  nodeProbe: ProbeResult | null;  // 所选节点的出口 IP 与国家（纯展示，不触发任何报警或拦截）
  nodeProbeError: string | null;  // 节点探测失败提示（纯展示）
}

export interface GuardEventLog {
  id: string;
  timestamp: number;
  level: 'info' | 'success' | 'warn' | 'danger';
  message: string;
}

export interface AlertPayload {
  alertType: 'mismatch' | 'disconnect' | 'locale-mismatch' | 'unauthorized-launch' | 'recovered';
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
  claudeState: ClaudeRuntimeState;
  antigravityState: AntigravityRuntimeState;
  geoDbSource: string;
  logs: GuardEventLog[];
}

export interface LocaleSyncResult {
  ok: boolean;
  message: string;
  killedProcesses: string[];
  state: AppStateSnapshot;
}

export interface ClaudeLaunchResult {
  ok: boolean;
  message: string;
  state: AppStateSnapshot;
}

export interface AntigravityLaunchResult {
  ok: boolean;
  message: string;
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
  // Clash 指定节点 & Claude 专栏控制
  selectClashNode: (nodeName: string | null) => Promise<AppStateSnapshot>;
  launchClaude: () => Promise<ClaudeLaunchResult>;
  terminateClaudeNow: () => Promise<ClaudeLaunchResult>;
  browseClaudeExe: () => Promise<AppStateSnapshot>;
  // Antigravity 启动器专栏控制
  selectAntigravityClashNode: (nodeName: string | null) => Promise<AppStateSnapshot>;
  probeAntigravityNode: () => Promise<AppStateSnapshot>;
  launchAntigravity: () => Promise<AntigravityLaunchResult>;
  terminateAntigravityNow: () => Promise<AntigravityLaunchResult>;
  browseAntigravityExe: () => Promise<AppStateSnapshot>;
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
