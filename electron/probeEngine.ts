import { EventEmitter } from 'node:events';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
import {
  AlertPayload,
  AppConfig,
  AppStateSnapshot,
  GuardEventLog,
  GuardStatus,
  ProbeResult,
} from '../src/shared/types';
import { ConfigStore } from './configStore';
import { GeoIpService } from './geoipService';
import { ClashMonitor } from './clashMonitor';
import { getNetworkInterfaceFingerprint, readWindowsSystemProxy } from './systemProxy';

interface TraceEndpoint {
  name: string;
  url: string;
  format: 'cf-trace' | 'plain-ip';
}

const BUILTIN_TRACE_ENDPOINTS: TraceEndpoint[] = [
  {
    name: 'Cloudflare Connectivity Trace',
    url: 'https://cp.cloudflare.com/cdn-cgi/trace',
    format: 'cf-trace',
  },
  {
    name: 'Cloudflare Global Trace',
    url: 'https://www.cloudflare.com/cdn-cgi/trace',
    format: 'cf-trace',
  },
  {
    name: 'AWS CheckIP',
    url: 'https://checkip.amazonaws.com',
    format: 'plain-ip',
  },
  {
    name: 'Cloudflare ICanHazIP',
    url: 'https://icanhazip.com',
    format: 'plain-ip',
  },
];

export class ProbeEngine extends EventEmitter {
  private configStore: ConfigStore;
  private geoIp: GeoIpService;
  private clashMonitor: ClashMonitor;

  private status: GuardStatus = 'checking';
  private isChecking = false;
  private pendingReason: string | null = null;
  private lastProbe: ProbeResult | null = null;
  private lastError: string | null = null;
  private lastTriggerReason = '初始化启动检测';
  private systemProxyUrl: string | null = null;
  private logs: GuardEventLog[] = [];

  private heartbeatTimer: NodeJS.Timeout | null = null;
  private localEnvTimer: NodeJS.Timeout | null = null;
  private lastSysProxySnapshot = '';
  private lastNetFingerprint = '';
  private lastAlertSignature: string | null = null;

  constructor(configStore: ConfigStore, geoIp: GeoIpService, clashMonitor: ClashMonitor) {
    super();
    this.configStore = configStore;
    this.geoIp = geoIp;
    this.clashMonitor = clashMonitor;

    this.clashMonitor.on('clash-change', (reason: string) => {
      this.addLog('info', `实时捕获事件：${reason}`);
      // 给 Clash 节点切换留出 250ms 内部路由生效时间后立即校验出口
      setTimeout(() => {
        void this.checkNow(reason);
      }, 250);
    });

    this.clashMonitor.on('clash-status-updated', () => {
      const info = this.clashMonitor.getRuntimeInfo();
      this.addLog(
        'info',
        `已连接 Clash 控制接口 (${info.source})，当前节点: ${info.activeNode || '未知'}`
      );
      this.emitState();
    });
  }

  public async start(): Promise<void> {
    const sys = await readWindowsSystemProxy();
    this.systemProxyUrl = sys.proxyUrl;
    this.lastSysProxySnapshot = `${sys.enabled}|${sys.proxyUrl || ''}`;
    this.lastNetFingerprint = getNetworkInterfaceFingerprint();

    this.clashMonitor.start();
    this.startLocalEnvironmentWatcher();
    this.restartHeartbeatTimer();

    await this.checkNow('应用启动首次检测');
  }

  public stop(): void {
    this.clashMonitor.stop();
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    if (this.localEnvTimer) {
      clearInterval(this.localEnvTimer);
      this.localEnvTimer = null;
    }
  }

  public restartHeartbeatTimer(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    const sec = this.configStore.get().heartbeatIntervalSec;
    if (sec > 0) {
      this.heartbeatTimer = setInterval(() => {
        void this.checkNow('轻量心跳巡检');
      }, sec * 1000);
    }
  }

  private startLocalEnvironmentWatcher(): void {
    // 纯本机轻量环境监测（注册表系统代理 & 网卡/TUN 变动，0 外部网络流量）
    this.localEnvTimer = setInterval(async () => {
      try {
        const sys = await readWindowsSystemProxy();
        this.systemProxyUrl = sys.proxyUrl;
        const sysSnap = `${sys.enabled}|${sys.proxyUrl || ''}`;
        if (this.lastSysProxySnapshot && sysSnap !== this.lastSysProxySnapshot) {
          this.lastSysProxySnapshot = sysSnap;
          const desc = sys.enabled ? `开启 (${sys.proxyUrl})` : '已关闭';
          this.addLog('info', `系统代理设置变更：${desc}`);
          void this.checkNow(`系统代理变更: ${desc}`);
          return;
        }
        this.lastSysProxySnapshot = sysSnap;

        const netFp = getNetworkInterfaceFingerprint();
        if (this.lastNetFingerprint && netFp !== this.lastNetFingerprint) {
          this.lastNetFingerprint = netFp;
          this.addLog('info', '检测到本机网络接口 / TUN 虚拟网卡变动');
          setTimeout(() => {
            void this.checkNow('本机网卡 / TUN 路由变动');
          }, 400);
        }
      } catch {
        // ignore
      }
    }, 2000);
  }

  public getSnapshot(): AppStateSnapshot {
    return {
      status: this.status,
      isChecking: this.isChecking,
      config: this.configStore.get(),
      lastProbe: this.lastProbe ? structuredClone(this.lastProbe) : null,
      lastError: this.lastError,
      lastTriggerReason: this.lastTriggerReason,
      clashInfo: this.clashMonitor.getRuntimeInfo(),
      systemProxyUrl: this.systemProxyUrl,
      geoDbSource: this.geoIp.getSourceDescription(),
      logs: [...this.logs],
    };
  }

  public clearLogs(): AppStateSnapshot {
    this.logs = [];
    this.emitState();
    return this.getSnapshot();
  }

  public evaluateStatusOnly(reason?: string): AppStateSnapshot {
    const cfg = this.configStore.get();
    if (reason) {
      this.lastTriggerReason = reason;
    }

    if (this.lastError && !this.lastProbe) {
      this.status = 'error';
    } else if (this.lastProbe) {
      if (!cfg.defaultCountryCode) {
        this.status = 'unset';
        this.lastAlertSignature = null;
      } else if (this.lastProbe.countryCode === cfg.defaultCountryCode) {
        this.status = 'ok';
        if (this.lastAlertSignature !== null) {
          this.lastAlertSignature = null;
          this.emitRecoveredAlert();
        }
      } else {
        this.status = 'mismatch';
        this.maybeTriggerMismatchAlert(reason || '默认地区配置更新');
      }
    }

    this.emitState();
    return this.getSnapshot();
  }

  public async checkNow(reason = '手动立即检测'): Promise<AppStateSnapshot> {
    if (this.isChecking) {
      // 如果不是普通心跳，记录待补测原因，确保节点切换绝不漏检
      if (reason !== '轻量心跳巡检') {
        this.pendingReason = reason;
      }
      return this.getSnapshot();
    }

    this.isChecking = true;
    this.lastTriggerReason = reason;
    this.emitState();

    try {
      const channel = await this.resolveProxyChannel();
      const endpoints = this.buildEndpointsList();

      let probeSuccess: ProbeResult | null = null;
      let lastErrMsg = '所有回显探测源均不可达';

      for (const ep of endpoints) {
        try {
          const startedAt = Date.now();
          const rawBody = await fetchViaProxy(ep.url, channel.proxyUrl, 6000);
          const latencyMs = Date.now() - startedAt;

          const parsed = parseTraceResponse(rawBody, ep.format);
          if (!parsed.ip) {
            throw new Error('响应中未解析到有效公网 IP');
          }

          const geo = this.geoIp.lookup(parsed.ip, parsed.loc);
          probeSuccess = {
            ip: parsed.ip,
            countryCode: geo.countryCode,
            countryName: geo.countryName,
            edgeLoc: parsed.loc,
            viaChannel: channel.description,
            probeSource: ep.name,
            latencyMs,
            checkedAt: Date.now(),
          };
          break;
        } catch (err) {
          lastErrMsg = err instanceof Error ? err.message : String(err);
        }
      }

      const cfg = this.configStore.get();

      if (probeSuccess) {
        const prevIp = this.lastProbe?.ip;
        const prevCountry = this.lastProbe?.countryCode;

        this.lastProbe = probeSuccess;
        this.lastError = null;

        if (!cfg.defaultCountryCode) {
          this.status = 'unset';
          this.lastAlertSignature = null;
          if (prevIp !== probeSuccess.ip || prevCountry !== probeSuccess.countryCode) {
            this.addLog(
              'info',
              `当前出口: ${probeSuccess.countryName} (${probeSuccess.countryCode}) · ${probeSuccess.ip}`
            );
          }
        } else if (probeSuccess.countryCode === cfg.defaultCountryCode) {
          const wasAbnormal = this.status === 'mismatch' || this.status === 'error';
          this.status = 'ok';
          if (
            wasAbnormal ||
            prevIp !== probeSuccess.ip ||
            prevCountry !== probeSuccess.countryCode
          ) {
            this.addLog(
              'success',
              `地区正常 [${probeSuccess.countryName}] · IP: ${probeSuccess.ip} (${probeSuccess.latencyMs}ms)`
            );
          }
          if (this.lastAlertSignature !== null) {
            this.lastAlertSignature = null;
            this.emitRecoveredAlert();
          }
        } else {
          this.status = 'mismatch';
          if (
            prevIp !== probeSuccess.ip ||
            prevCountry !== probeSuccess.countryCode ||
            reason !== '轻量心跳巡检'
          ) {
            this.addLog(
              'danger',
              `地区不匹配！期望 [${cfg.defaultCountryName}]，实际为 [${probeSuccess.countryName} (${probeSuccess.countryCode})] · IP: ${probeSuccess.ip}`
            );
          }
          this.maybeTriggerMismatchAlert(reason);
        }
      } else {
        this.lastError = simplifyNetworkError(lastErrMsg, channel.description);
        this.status = 'error';
        this.addLog('warn', `代理检测失败：${this.lastError}`);
        this.maybeTriggerDisconnectAlert(reason, this.lastError);
      }
    } finally {
      this.isChecking = false;
      this.emitState();

      if (this.pendingReason) {
        const nextReason = this.pendingReason;
        this.pendingReason = null;
        setTimeout(() => {
          void this.checkNow(nextReason);
        }, 150);
      }
    }

    return this.getSnapshot();
  }

  private maybeTriggerMismatchAlert(reason: string): void {
    const cfg = this.configStore.get();
    if (!cfg.defaultCountryCode || !this.lastProbe) return;

    const sig = `mismatch:${cfg.defaultCountryCode}->${this.lastProbe.countryCode}`;
    if (this.lastAlertSignature === sig) return;
    this.lastAlertSignature = sig;

    if (!cfg.alertPopupEnabled) return;

    const clash = this.clashMonitor.getRuntimeInfo();
    const payload: AlertPayload = {
      alertType: 'mismatch',
      expectedCode: cfg.defaultCountryCode,
      expectedName: cfg.defaultCountryName,
      actualCode: this.lastProbe.countryCode,
      actualName: this.lastProbe.countryName,
      actualIp: this.lastProbe.ip,
      edgeLoc: this.lastProbe.edgeLoc,
      viaChannel: this.lastProbe.viaChannel,
      activeNode: clash.connected ? clash.activeNode : null,
      triggerReason: reason,
      soundEnabled: cfg.alertSoundEnabled,
      timestamp: Date.now(),
    };

    this.emit('trigger-alert', payload);
  }

  private maybeTriggerDisconnectAlert(reason: string, errDetail: string): void {
    const cfg = this.configStore.get();
    if (!cfg.defaultCountryCode || !cfg.alertOnDisconnect) return;

    const sig = `disconnect:${cfg.defaultCountryCode}`;
    if (this.lastAlertSignature === sig) return;
    this.lastAlertSignature = sig;

    if (!cfg.alertPopupEnabled) return;

    const clash = this.clashMonitor.getRuntimeInfo();
    const payload: AlertPayload = {
      alertType: 'disconnect',
      expectedCode: cfg.defaultCountryCode,
      expectedName: cfg.defaultCountryName,
      actualCode: null,
      actualName: '连接断开',
      actualIp: null,
      viaChannel: undefined,
      activeNode: clash.connected ? clash.activeNode : null,
      triggerReason: reason,
      errorDetail: errDetail,
      soundEnabled: cfg.alertSoundEnabled,
      timestamp: Date.now(),
    };

    this.emit('trigger-alert', payload);
  }

  private emitRecoveredAlert(): void {
    const cfg = this.configStore.get();
    if (!this.lastProbe) return;
    const payload: AlertPayload = {
      alertType: 'recovered',
      expectedCode: cfg.defaultCountryCode,
      expectedName: cfg.defaultCountryName,
      actualCode: this.lastProbe.countryCode,
      actualName: this.lastProbe.countryName,
      actualIp: this.lastProbe.ip,
      viaChannel: this.lastProbe.viaChannel,
      triggerReason: '已恢复至默认地区',
      soundEnabled: false,
      timestamp: Date.now(),
    };
    this.emit('alert-recovered', payload);
  }

  public buildTestAlertPayload(): AlertPayload {
    const cfg = this.configStore.get();
    const clash = this.clashMonitor.getRuntimeInfo();
    const expectedCode = cfg.defaultCountryCode || 'US';
    const expectedName = cfg.defaultCountryName || '美国';
    const actualCode = expectedCode === 'HK' ? 'JP' : 'HK';
    const actualName = expectedCode === 'HK' ? '日本' : '中国香港';

    return {
      alertType: 'mismatch',
      expectedCode,
      expectedName,
      actualCode,
      actualName,
      actualIp: this.lastProbe?.ip || '203.0.113.88',
      edgeLoc: actualCode,
      viaChannel: this.lastProbe?.viaChannel || 'Clash 混合端口 (127.0.0.1:7897)',
      activeNode: clash.activeNode || '示例节点 (测试预览)',
      triggerReason: '手动触发警告弹窗预览',
      soundEnabled: cfg.alertSoundEnabled,
      timestamp: Date.now(),
    };
  }

  private buildEndpointsList(): TraceEndpoint[] {
    const custom = this.configStore.get().customProbeUrl.trim();
    const list: TraceEndpoint[] = [];
    if (custom) {
      list.push({
        name: '自定义探测源',
        url: custom,
        format: custom.includes('cdn-cgi/trace') ? 'cf-trace' : 'plain-ip',
      });
    }
    list.push(...BUILTIN_TRACE_ENDPOINTS);
    return list;
  }

  private async resolveProxyChannel(): Promise<{ proxyUrl: string | null; description: string }> {
    const cfg = this.configStore.get();

    if (cfg.proxyMode === 'direct') {
      return {
        proxyUrl: null,
        description: '网卡直连 / TUN 模式',
      };
    }

    if (cfg.proxyMode === 'manual') {
      const scheme = cfg.manualProxy.protocol === 'socks5' ? 'socks5h' : 'http';
      const proxyUrl = `${scheme}://${cfg.manualProxy.host}:${cfg.manualProxy.port}`;
      return {
        proxyUrl,
        description: `手动端口 (${cfg.manualProxy.protocol.toUpperCase()} ${cfg.manualProxy.host}:${cfg.manualProxy.port})`,
      };
    }

    // auto 模式：1) 优先读取系统代理 -> 2) 其次读取本机运行中的 Clash mixed-port -> 3) 回退到 TUN / 网卡直连
    const sys = await readWindowsSystemProxy();
    this.systemProxyUrl = sys.proxyUrl;
    if (sys.enabled && sys.proxyUrl) {
      const cleanAddr = sys.proxyUrl.replace(/^[a-z0-9+.-]+:\/\//i, '');
      return {
        proxyUrl: sys.proxyUrl,
        description: `系统代理 (${cleanAddr})`,
      };
    }

    const clash = this.clashMonitor.getRuntimeInfo();
    if (clash.connected && clash.mixedPort) {
      const alive = await canConnectLocalPort('127.0.0.1', clash.mixedPort, 400);
      if (alive) {
        return {
          proxyUrl: `http://127.0.0.1:${clash.mixedPort}`,
          description: `Clash 端口 (127.0.0.1:${clash.mixedPort})`,
        };
      }
    }

    // 兜底探测常见本机代理监听端口（例如仅开本地端口或 TUN 混合运行的 Clash / v2rayN）
    for (const candidatePort of [7897, 7890, 10809]) {
      const alive = await canConnectLocalPort('127.0.0.1', candidatePort, 250);
      if (alive) {
        return {
          proxyUrl: `http://127.0.0.1:${candidatePort}`,
          description: `自动发现本地端口 (127.0.0.1:${candidatePort})`,
        };
      }
    }

    return {
      proxyUrl: null,
      description: '自动 (TUN 虚拟网卡 / 本机直连)',
    };
  }

  private addLog(level: GuardEventLog['level'], message: string): void {
    const entry: GuardEventLog = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: Date.now(),
      level,
      message,
    };
    this.logs.unshift(entry);
    if (this.logs.length > 60) {
      this.logs.length = 60;
    }
  }

  private emitState(): void {
    this.emit('state-changed', this.getSnapshot());
  }
}

function parseTraceResponse(
  raw: string,
  format: 'cf-trace' | 'plain-ip'
): { ip: string | null; loc?: string } {
  const text = raw.trim();
  if (format === 'cf-trace' || text.includes('ip=')) {
    let ip: string | null = null;
    let loc: string | undefined;
    for (const line of text.split(/\r?\n/)) {
      const idx = line.indexOf('=');
      if (idx <= 0) continue;
      const k = line.slice(0, idx).trim();
      const v = line.slice(idx + 1).trim();
      if (k === 'ip' && net.isIP(v)) {
        ip = v;
      } else if (k === 'loc' && v) {
        loc = v.toUpperCase();
      }
    }
    return { ip, loc };
  }

  // 纯文本 IP 回显（或简单 JSON 包含 ip 字段）
  if (net.isIP(text)) {
    return { ip: text };
  }
  try {
    const obj = JSON.parse(text) as Record<string, unknown>;
    const candidate = String(obj['ip'] || obj['query'] || '').trim();
    if (net.isIP(candidate)) {
      return { ip: candidate };
    }
  } catch {
    // try first line
    const firstLine = text.split(/\r?\n/)[0]?.trim() || '';
    if (net.isIP(firstLine)) {
      return { ip: firstLine };
    }
  }
  return { ip: null };
}

function fetchViaProxy(
  targetUrl: string,
  proxyUrl: string | null,
  timeoutMs: number
): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(targetUrl);
    const isHttps = parsedUrl.protocol === 'https:';

    let agent: http.Agent | undefined;
    if (proxyUrl) {
      if (proxyUrl.startsWith('socks')) {
        agent = new SocksProxyAgent(proxyUrl, { keepAlive: false, timeout: timeoutMs });
      } else {
        agent = new HttpsProxyAgent(proxyUrl, { keepAlive: false, timeout: timeoutMs });
      }
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
          Accept: 'text/plain, */*',
          'Cache-Control': 'no-cache',
          Connection: 'close',
        },
      },
      (res) => {
        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          reject(new Error(`HTTP 状态码 ${res.statusCode}`));
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => {
          resolve(Buffer.concat(chunks).toString('utf-8'));
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error('连接超时'));
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.end();
  });
}

function canConnectLocalPort(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => finish(true));
    socket.on('timeout', () => finish(false));
    socket.on('error', () => finish(false));
  });
}

function simplifyNetworkError(errMsg: string, channelDesc: string): string {
  if (errMsg.includes('ECONNREFUSED')) {
    return `代理端口拒绝连接 (${channelDesc})，请检查 VPN/Clash 是否已启动`;
  }
  if (errMsg.includes('超时') || errMsg.includes('ETIMEDOUT') || errMsg.includes('Timeout')) {
    return `经由 [${channelDesc}] 访问超时，当前代理节点可能已失效`;
  }
  if (errMsg.includes('ENOTFOUND')) {
    return `DNS 解析失败 (${channelDesc})，网络连接异常`;
  }
  return `${errMsg} (${channelDesc})`;
}
