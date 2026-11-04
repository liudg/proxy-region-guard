import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import yaml from 'js-yaml';
import WebSocket from 'ws';
import { AppConfig, ClashRuntimeInfo } from '../src/shared/types';

interface ControllerEndpoint {
  label: string;
  pipePath?: string;
  host?: string;
  port?: number;
  secret?: string;
}

export class ClashMonitor extends EventEmitter {
  private currentEndpoint: ControllerEndpoint | null = null;
  private ws: WebSocket | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private stopped = false;

  private info: ClashRuntimeInfo = {
    connected: false,
    source: '未连接',
    mode: 'unknown',
    mixedPort: null,
    activeGroup: null,
    activeNode: null,
    nodeChain: [],
  };

  private getConfig: () => AppConfig;

  constructor(getConfig: () => AppConfig) {
    super();
    this.getConfig = getConfig;
  }

  public getRuntimeInfo(): ClashRuntimeInfo {
    return structuredClone(this.info);
  }

  public start(): void {
    this.stopped = false;
    void this.tick();
    this.pollTimer = setInterval(() => {
      void this.tick();
    }, 1800);
  }

  public stop(): void {
    this.stopped = true;
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    this.closeWs();
  }

  public async forceReconnect(): Promise<void> {
    this.closeWs();
    this.currentEndpoint = null;
    await this.tick();
  }

  private closeWs(): void {
    if (this.ws) {
      try {
        this.ws.removeAllListeners();
        this.ws.terminate();
      } catch {
        // ignore
      }
      this.ws = null;
    }
  }

  private async tick(): Promise<void> {
    if (this.stopped) return;

    if (!this.currentEndpoint) {
      const found = await this.findWorkingEndpoint();
      if (!found) {
        if (this.info.connected) {
          this.info = {
            connected: false,
            source: '未连接',
            mode: 'unknown',
            mixedPort: null,
            activeGroup: null,
            activeNode: null,
            nodeChain: [],
          };
          this.emit('clash-change', 'Clash 控制接口断开连接');
        }
        return;
      }
      this.currentEndpoint = found;
      this.connectWebSocket(found);
    }

    try {
      const [configs, proxiesData] = await Promise.all([
        this.requestJson<Record<string, unknown>>(this.currentEndpoint, '/configs'),
        this.requestJson<{ proxies?: Record<string, ClashProxyItem> }>(this.currentEndpoint, '/proxies'),
      ]);

      const mode = String(configs['mode'] || 'rule').toLowerCase();
      const mixedPortRaw = Number(configs['mixed-port'] || configs['port'] || configs['socks-port'] || 0);
      const mixedPort = mixedPortRaw > 0 ? mixedPortRaw : null;

      const resolved = resolveActiveProxyChain(mode, proxiesData?.proxies || {});

      const prevConnected = this.info.connected;
      const prevMode = this.info.mode;
      const prevNode = this.info.activeNode;
      const prevChainKey = this.info.nodeChain.join(' > ');
      const nextChainKey = resolved.chain.join(' > ');

      this.info = {
        connected: true,
        source: this.currentEndpoint.label,
        mode,
        mixedPort,
        activeGroup: resolved.group,
        activeNode: resolved.leafNode,
        nodeChain: resolved.chain,
      };

      if (!prevConnected) {
        this.emit('clash-status-updated');
      } else if (prevMode !== mode) {
        this.emit('clash-change', `Clash 代理模式变更: ${prevMode} → ${mode}`);
      } else if (prevNode !== resolved.leafNode || prevChainKey !== nextChainKey) {
        this.emit(
          'clash-change',
          `Clash 节点变更: ${prevNode || '无'} → ${resolved.leafNode || '直连'}`
        );
      }
    } catch {
      // 当前控制端点失效，关闭并在下一拍重连或告警
      this.closeWs();
      this.currentEndpoint = null;
      if (this.info.connected) {
        this.info = {
          connected: false,
          source: '未连接',
          mode: 'unknown',
          mixedPort: null,
          activeGroup: null,
          activeNode: null,
          nodeChain: [],
        };
        this.emit('clash-change', 'Clash 内核已关闭或重启');
      }
    }
  }

  private connectWebSocket(endpoint: ControllerEndpoint): void {
    this.closeWs();
    if (this.stopped) return;

    try {
      const headers: Record<string, string> = {};
      let query = '';
      if (endpoint.secret) {
        headers['Authorization'] = `Bearer ${endpoint.secret}`;
        query = `?token=${encodeURIComponent(endpoint.secret)}`;
      }

      let ws: WebSocket;
      if (endpoint.pipePath) {
        const pipePath = endpoint.pipePath;
        ws = new WebSocket(`ws://localhost/connections${query}`, {
          headers,
          createConnection: () => net.connect(pipePath),
        });
      } else {
        ws = new WebSocket(`ws://${endpoint.host}:${endpoint.port}/connections${query}`, {
          headers,
        });
      }

      let lastActiveConnLeaf: string | null = null;

      ws.on('message', (raw) => {
        try {
          const data = JSON.parse(raw.toString()) as {
            connections?: Array<{ chains?: string[]; metadata?: { host?: string } }>;
          };
          const conns = data.connections;
          if (!Array.isArray(conns) || conns.length === 0) return;

          // 检查最新活跃非直连连接的实际落地节点（chain[0] 在 Clash 中通常是最终落地节点）
          for (let i = conns.length - 1; i >= 0; i--) {
            const chains = conns[i].chains;
            if (Array.isArray(chains) && chains.length > 0) {
              const leaf = chains[0];
              if (leaf && leaf !== 'DIRECT' && leaf !== 'REJECT') {
                if (lastActiveConnLeaf && lastActiveConnLeaf !== leaf) {
                  lastActiveConnLeaf = leaf;
                  void this.tick();
                } else {
                  lastActiveConnLeaf = leaf;
                }
                break;
              }
            }
          }
        } catch {
          // ignore malformed ws frame
        }
      });

      ws.on('error', () => {
        // handled by periodic tick fallback
      });

      ws.on('close', () => {
        if (this.ws === ws) {
          this.ws = null;
        }
      });

      this.ws = ws;
    } catch {
      // fallback to fast local polling in tick()
    }
  }

  private async findWorkingEndpoint(): Promise<ControllerEndpoint | null> {
    const cfg = this.getConfig();
    const candidates: ControllerEndpoint[] = [];

    if (!cfg.clashAutoDetect) {
      candidates.push({
        label: `手动 (${cfg.clashCustomController.host}:${cfg.clashCustomController.port})`,
        host: cfg.clashCustomController.host,
        port: cfg.clashCustomController.port,
        secret: cfg.clashCustomController.secret || undefined,
      });
    } else {
      // 1. 先扫描本机常见 Clash 配置文件提取 external-controller、pipe 与 secret
      const { endpoints: yamlEndpoints, secrets: knownSecrets } = this.scanClashConfigFiles();

      // 2. 动态枚举 Windows Named Pipes（兼容 Clash Verge Rev 带哈希后缀的 verge-mihomo-production-xxx 管道）
      if (process.platform === 'win32') {
        const pipeNames = this.discoverWindowsClashPipes();
        for (const pipeName of pipeNames) {
          const fullPipe = `\\\\.\\pipe\\${pipeName}`;
          const friendly = pipeName.startsWith('verge-mihomo')
            ? 'Clash Verge (Pipe)'
            : pipeName.startsWith('mihomo-party')
            ? 'Mihomo Party (Pipe)'
            : `Clash (${pipeName.slice(0, 18)})`;

          candidates.push({ label: friendly, pipePath: fullPipe });
          for (const sec of knownSecrets) {
            candidates.push({ label: friendly, pipePath: fullPipe, secret: sec });
          }
        }
      }

      // 3. 加入配置文件中明确解析出的端点
      candidates.push(...yamlEndpoints);

      // 4. 标准本地默认端口兜底
      for (const port of [9097, 9090, 9099]) {
        candidates.push({ label: `Clash (127.0.0.1:${port})`, host: '127.0.0.1', port });
        for (const sec of knownSecrets) {
          candidates.push({
            label: `Clash (127.0.0.1:${port})`,
            host: '127.0.0.1',
            port,
            secret: sec,
          });
        }
      }
    }

    for (const candidate of candidates) {
      try {
        const res = await this.requestJson<Record<string, unknown>>(candidate, '/version', 800);
        if (res && (typeof res['version'] === 'string' || typeof res['meta'] !== 'undefined' || typeof res['premium'] !== 'undefined')) {
          return candidate;
        }
      } catch {
        // try next candidate
      }
    }
    return null;
  }

  private discoverWindowsClashPipes(): string[] {
    try {
      const allPipes = fs.readdirSync('\\\\.\\pipe\\');
      return allPipes.filter((name) => {
        const lower = name.toLowerCase();
        if (lower.includes('service') || lower.includes('helper') || lower.includes('ipc')) {
          return false;
        }
        return (
          lower.startsWith('verge-mihomo') ||
          lower.startsWith('mihomo-party') ||
          lower.startsWith('mihomo') ||
          lower.startsWith('clash-verge') ||
          lower.startsWith('nyanpasu')
        );
      });
    } catch {
      return ['verge-mihomo', 'mihomo-party', 'clash-verge'];
    }
  }

  private scanClashConfigFiles(): { endpoints: ControllerEndpoint[]; secrets: string[] } {
    const results: ControllerEndpoint[] = [];
    const secretSet = new Set<string>();
    const appData = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    const home = os.homedir();

    const filesToCheck: Array<{ name: string; file: string }> = [
      {
        name: 'Clash Verge Rev',
        file: path.join(appData, 'io.github.clash-verge-rev.clash-verge-rev', 'clash-verge.yaml'),
      },
      {
        name: 'Clash Verge Rev (Verge)',
        file: path.join(appData, 'io.github.clash-verge-rev.clash-verge-rev', 'verge.yaml'),
      },
      {
        name: 'Clash Verge',
        file: path.join(appData, 'clash-verge', 'clash-verge.yaml'),
      },
      {
        name: 'Mihomo Party',
        file: path.join(appData, 'mihomo-party', 'mihomo.yaml'),
      },
      {
        name: 'Clash Nyanpasu',
        file: path.join(appData, 'moe.elaina.clash.nyanpasu', 'clash-nyanpasu.yaml'),
      },
      {
        name: 'Clash for Windows',
        file: path.join(home, '.config', 'clash', 'config.yaml'),
      },
      {
        name: 'Mihomo',
        file: path.join(home, '.config', 'mihomo', 'config.yaml'),
      },
      {
        name: 'FlClash',
        file: path.join(appData, 'com.follow.clash', 'config.yaml'),
      },
    ];

    for (const item of filesToCheck) {
      try {
        if (!fs.existsSync(item.file)) continue;
        const content = fs.readFileSync(item.file, 'utf-8');
        const parsed = yaml.load(content) as Record<string, unknown> | null;
        if (!parsed || typeof parsed !== 'object') continue;

        const pipeVal = parsed['external-controller-pipe'];
        const rawSecret =
          typeof parsed['secret'] === 'string'
            ? parsed['secret']
            : typeof parsed['verge_clash_core_secret'] === 'string'
            ? parsed['verge_clash_core_secret']
            : undefined;
        const secret = rawSecret ? rawSecret.trim() : undefined;
        if (secret) {
          secretSet.add(secret);
        }

        if (typeof pipeVal === 'string' && pipeVal.trim()) {
          results.push({
            label: `${item.name} (Pipe)`,
            pipePath: pipeVal.trim(),
            secret,
          });
        }

        const ctrl = parsed['external-controller'];
        if (typeof ctrl === 'string' && ctrl.includes(':')) {
          const [rawHost, rawPort] = ctrl.trim().split(':');
          const host = !rawHost || rawHost === '0.0.0.0' ? '127.0.0.1' : rawHost;
          const port = Number(rawPort);
          if (port > 0 && port < 65536) {
            results.push({
              label: `${item.name} (${host}:${port})`,
              host,
              port,
              secret,
            });
          }
        }
      } catch {
        // ignore unreadable yaml
      }
    }

    return { endpoints: results, secrets: Array.from(secretSet) };
  }

  private requestJson<T>(
    endpoint: ControllerEndpoint,
    urlPath: string,
    timeoutMs = 1200
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = {
        Accept: 'application/json',
      };
      if (endpoint.secret) {
        headers['Authorization'] = `Bearer ${endpoint.secret}`;
      }

      const options: http.RequestOptions = endpoint.pipePath
        ? {
            socketPath: endpoint.pipePath,
            path: urlPath,
            method: 'GET',
            headers,
            timeout: timeoutMs,
          }
        : {
            host: endpoint.host,
            port: endpoint.port,
            path: urlPath,
            method: 'GET',
            headers,
            timeout: timeoutMs,
          };

      const req = http.request(options, (res) => {
        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => {
          try {
            const text = Buffer.concat(chunks).toString('utf-8');
            resolve(JSON.parse(text) as T);
          } catch (e) {
            reject(e);
          }
        });
      });

      req.on('timeout', () => {
        req.destroy(new Error('Timeout'));
      });
      req.on('error', (err) => {
        reject(err);
      });
      req.end();
    });
  }
}

interface ClashProxyItem {
  name: string;
  type: string;
  now?: string;
  all?: string[];
}

const GROUP_TYPES = new Set([
  'Selector',
  'URLTest',
  'Fallback',
  'LoadBalance',
  'Relay',
]);

function resolveActiveProxyChain(
  mode: string,
  proxies: Record<string, ClashProxyItem>
): { group: string | null; leafNode: string | null; chain: string[] } {
  if (mode === 'direct') {
    return { group: 'DIRECT', leafNode: 'DIRECT', chain: ['DIRECT'] };
  }

  let entryGroup: ClashProxyItem | undefined;

  if (mode === 'global' && proxies['GLOBAL']) {
    entryGroup = proxies['GLOBAL'];
  } else {
    // 在 Rule 模式下定位主策略组（优先寻找常见主选择组名称，否则选第一个 Selector）
    const preferredNames = [
      'Proxy',
      'PROXY',
      '节点选择',
      '代理模式',
      '默认代理',
      '选择节点',
      '🚀 节点选择',
      '🔰 节点选择',
      '🌍 选择节点',
    ];
    for (const name of preferredNames) {
      if (proxies[name] && proxies[name].now) {
        entryGroup = proxies[name];
        break;
      }
    }
    if (!entryGroup) {
      // 检查 GLOBAL.all 列表里的第一个非内置 Selector 组
      const globalAll = proxies['GLOBAL']?.all || [];
      for (const candidateName of globalAll) {
        if (candidateName === 'DIRECT' || candidateName === 'REJECT') continue;
        const item = proxies[candidateName];
        if (item && item.type === 'Selector' && item.now) {
          entryGroup = item;
          break;
        }
      }
    }
    if (!entryGroup) {
      entryGroup = Object.values(proxies).find(
        (p) => p.type === 'Selector' && p.name !== 'GLOBAL' && Boolean(p.now)
      );
    }
  }

  if (!entryGroup) {
    return { group: null, leafNode: null, chain: [] };
  }

  const chain: string[] = [entryGroup.name];
  let current: ClashProxyItem | undefined = entryGroup;
  const visited = new Set<string>([entryGroup.name]);

  while (current && current.now && !visited.has(current.now)) {
    visited.add(current.now);
    chain.push(current.now);
    const nextItem: ClashProxyItem | undefined = proxies[current.now];
    if (!nextItem || !GROUP_TYPES.has(nextItem.type)) {
      break;
    }
    current = nextItem;
  }

  const leafNode = chain[chain.length - 1] || null;
  return {
    group: entryGroup.name,
    leafNode,
    chain,
  };
}
