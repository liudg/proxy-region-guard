import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { ClashRuntimeInfo } from '../src/shared/types';

interface ControllerEndpoint {
  label: string;
  pipePath?: string;
  host?: string;
  port?: number;
  secret?: string;
}

interface CachedYamlMeta {
  mtimeMs: number;
  size: number;
  pipePath?: string;
  host?: string;
  port?: number;
  secret?: string;
}

const CONNECTED_POLL_MS = 1500;
const DISCONNECTED_POLL_MS = 4500;
const YAML_HEADER_READ_BYTES = 16 * 1024;

export class ClashMonitor extends EventEmitter {
  private currentEndpoint: ControllerEndpoint | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private isTicking = false;
  private stopped = false;
  private lastGroupsSignature = '';
  private yamlCache = new Map<string, CachedYamlMeta>();

  private info: ClashRuntimeInfo = {
    connected: false,
    source: '未连接',
    mode: 'unknown',
    mixedPort: null,
    activeNode: null,
    nodeChain: [],
  };

  public getRuntimeInfo(): ClashRuntimeInfo {
    return structuredClone(this.info);
  }

  public start(): void {
    this.stopped = false;
    this.scheduleNextTick(0);
  }

  public stop(): void {
    this.stopped = true;
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private scheduleNextTick(delayMs: number): void {
    if (this.stopped) return;
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
    }
    this.pollTimer = setTimeout(() => {
      this.pollTimer = null;
      void this.tick();
    }, delayMs);
  }

  private async tick(): Promise<void> {
    if (this.stopped || this.isTicking) return;
    this.isTicking = true;

    try {
      if (!this.currentEndpoint) {
        const found = await this.findWorkingEndpoint();
        if (!found) {
          if (this.info.connected) {
            this.resetDisconnectedState();
            this.emit('clash-change', 'Clash 控制接口断开连接');
          }
          return;
        }
        this.currentEndpoint = found;
      }

      try {
        const [configs, proxiesData] = await Promise.all([
          this.requestJson<Record<string, unknown>>(this.currentEndpoint, '/configs'),
          this.requestJson<{ proxies?: Record<string, ClashProxyItem> }>(
            this.currentEndpoint,
            '/proxies'
          ),
        ]);

        const mode = String(configs['mode'] || 'rule').toLowerCase();
        const mixedPortRaw = Number(
          configs['mixed-port'] || configs['port'] || configs['socks-port'] || 0
        );
        const mixedPort = mixedPortRaw > 0 ? mixedPortRaw : null;

        const proxiesMap = proxiesData?.proxies || {};
        const resolved = resolveActiveProxyChain(mode, proxiesMap);
        const nextGroupsSig = buildAllGroupsSignature(proxiesMap);

        const prevConnected = this.info.connected;
        const prevMode = this.info.mode;
        const prevNode = this.info.activeNode;
        const prevChainKey = this.info.nodeChain.join(' > ');
        const nextChainKey = resolved.chain.join(' > ');
        const prevGroupsSig = this.lastGroupsSignature;

        this.lastGroupsSignature = nextGroupsSig;
        this.info = {
          connected: true,
          source: this.currentEndpoint.label,
          mode,
          mixedPort,
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
        } else if (prevGroupsSig && prevGroupsSig !== nextGroupsSig) {
          this.emit('clash-change', 'Clash 分流策略组节点切换');
        }
      } catch {
        this.currentEndpoint = null;
        if (this.info.connected) {
          this.resetDisconnectedState();
          this.emit('clash-change', 'Clash 内核已关闭或重启');
        }
      }
    } finally {
      this.isTicking = false;
      const nextDelay = this.currentEndpoint ? CONNECTED_POLL_MS : DISCONNECTED_POLL_MS;
      this.scheduleNextTick(nextDelay);
    }
  }

  private resetDisconnectedState(): void {
    this.lastGroupsSignature = '';
    this.info = {
      connected: false,
      source: '未连接',
      mode: 'unknown',
      mixedPort: null,
      activeNode: null,
      nodeChain: [],
    };
  }

  private async findWorkingEndpoint(): Promise<ControllerEndpoint | null> {
    const rawCandidates: ControllerEndpoint[] = [];
    const { endpoints: yamlEndpoints, secrets: knownSecrets } = this.scanClashConfigFiles();

    // 1. 优先尝试从配置文件中精准提取的带密钥端点
    rawCandidates.push(...yamlEndpoints);

    // 2. 动态枚举 Windows Named Pipes（兼容 Clash Verge Rev 带哈希后缀的管道）
    if (process.platform === 'win32') {
      const pipeNames = this.discoverWindowsClashPipes();
      for (const pipeName of pipeNames) {
        const fullPipe = `\\\\.\\pipe\\${pipeName}`;
        const friendly = pipeName.startsWith('verge-mihomo')
          ? 'Clash Verge (Pipe)'
          : pipeName.startsWith('mihomo-party')
          ? 'Mihomo Party (Pipe)'
          : `Clash (${pipeName.slice(0, 18)})`;

        for (const sec of knownSecrets) {
          rawCandidates.push({ label: friendly, pipePath: fullPipe, secret: sec });
        }
        rawCandidates.push({ label: friendly, pipePath: fullPipe });
      }
    }

    // 3. 标准本地默认端口兜底
    for (const port of [9097, 9090, 9099]) {
      for (const sec of knownSecrets) {
        rawCandidates.push({
          label: `Clash (127.0.0.1:${port})`,
          host: '127.0.0.1',
          port,
          secret: sec,
        });
      }
      rawCandidates.push({ label: `Clash (127.0.0.1:${port})`, host: '127.0.0.1', port });
    }

    // 严格去重，避免同一失效端点重复发起超时请求
    const seenKeys = new Set<string>();
    const candidates: ControllerEndpoint[] = [];
    for (const c of rawCandidates) {
      const key = `${c.pipePath || `${c.host}:${c.port}`}|${c.secret || ''}`;
      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        candidates.push(c);
      }
    }

    for (const candidate of candidates) {
      if (this.stopped) return null;
      try {
        const res = await this.requestJson<Record<string, unknown>>(candidate, '/version', 600);
        if (
          res &&
          (typeof res['version'] === 'string' ||
            typeof res['meta'] !== 'undefined' ||
            typeof res['premium'] !== 'undefined')
        ) {
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
        name: 'Clash Verge Rev',
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
      const meta = this.readYamlHeaderCached(item.file);
      if (!meta) continue;

      if (meta.secret) {
        secretSet.add(meta.secret);
      }

      if (meta.pipePath) {
        results.push({
          label: `${item.name} (Pipe)`,
          pipePath: meta.pipePath,
          secret: meta.secret,
        });
      }

      if (meta.host && meta.port) {
        results.push({
          label: `${item.name} (${meta.host}:${meta.port})`,
          host: meta.host,
          port: meta.port,
          secret: meta.secret,
        });
      }
    }

    return { endpoints: results, secrets: Array.from(secretSet) };
  }

  /**
   * 按 mtime 增量缓存并仅读取 YAML 头部前 16KB，避免同步解析数兆分流规则阻塞主线程
   */
  private readYamlHeaderCached(filePath: string): CachedYamlMeta | null {
    try {
      if (!fs.existsSync(filePath)) return null;
      const stat = fs.statSync(filePath);
      const cached = this.yamlCache.get(filePath);
      if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
        return cached;
      }

      const bytesToRead = Math.min(stat.size, YAML_HEADER_READ_BYTES);
      if (bytesToRead <= 0) return null;

      const buf = Buffer.alloc(bytesToRead);
      const fd = fs.openSync(filePath, 'r');
      let bytesRead = 0;
      try {
        bytesRead = fs.readSync(fd, buf, 0, bytesToRead, 0);
      } finally {
        fs.closeSync(fd);
      }

      const headerText = buf.subarray(0, bytesRead).toString('utf-8');
      const pipeVal = extractYamlTopScalar(headerText, 'external-controller-pipe');
      const ctrlVal = extractYamlTopScalar(headerText, 'external-controller');
      const secretVal =
        extractYamlTopScalar(headerText, 'secret') ||
        extractYamlTopScalar(headerText, 'verge_clash_core_secret');

      const parsedCtrl = ctrlVal ? parseControllerAddress(ctrlVal) : null;

      const entry: CachedYamlMeta = {
        mtimeMs: stat.mtimeMs,
        size: stat.size,
        pipePath: pipeVal || undefined,
        host: parsedCtrl?.host,
        port: parsedCtrl?.port,
        secret: secretVal || undefined,
      };
      this.yamlCache.set(filePath, entry);
      return entry;
    } catch {
      return null;
    }
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

function extractYamlTopScalar(text: string, key: string): string | null {
  const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`^${escapedKey}\\s*:\\s*(.+)$`, 'm');
  const match = text.match(re);
  if (!match || !match[1]) return null;

  const raw = match[1].trim();
  if (!raw || raw.startsWith('#')) return null;

  let val: string;
  if (raw.startsWith('"')) {
    const dqMatch = raw.match(/^"((?:[^"\\]|\\.)*)"(?:\s+#.*|\s*)$/);
    if (!dqMatch) return null;
    val = dqMatch[1].replace(/\\(["\\/bfnrt])/g, (_m, ch: string) => {
      if (ch === 'n') return '\n';
      if (ch === 'r') return '\r';
      if (ch === 't') return '\t';
      return ch;
    });
  } else if (raw.startsWith("'")) {
    const sqMatch = raw.match(/^'((?:[^']|'')*)'(?:\s+#.*|\s*)$/);
    if (!sqMatch) return null;
    val = sqMatch[1].replace(/''/g, "'");
  } else {
    val = raw.replace(/\s+#.*$/, '').trim();
    if (val === 'null' || val === '~') return null;
  }

  val = val.trim();
  return val || null;
}

function parseControllerAddress(raw: string): { host: string; port: number } | null {
  const cleaned = raw.trim().replace(/^https?:\/\//i, '');
  const lastColon = cleaned.lastIndexOf(':');
  if (lastColon < 0) return null;

  const rawHost = cleaned.slice(0, lastColon).trim().replace(/^\[|\]$/g, '');
  const port = Number(cleaned.slice(lastColon + 1).trim());
  if (!Number.isInteger(port) || port <= 0 || port >= 65536) {
    return null;
  }

  const isWildcard = !rawHost || rawHost === '0.0.0.0' || rawHost === '::';
  const host = isWildcard ? '127.0.0.1' : rawHost === '::1' ? '127.0.0.1' : rawHost;
  return { host, port };
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

function buildAllGroupsSignature(proxies: Record<string, ClashProxyItem>): string {
  const parts: string[] = [];
  for (const name of Object.keys(proxies).sort()) {
    const item = proxies[name];
    if (item && GROUP_TYPES.has(item.type) && item.now) {
      parts.push(`${name}=${item.now}`);
    }
  }
  return parts.join('|');
}

function resolveActiveProxyChain(
  mode: string,
  proxies: Record<string, ClashProxyItem>
): { leafNode: string | null; chain: string[] } {
  if (mode === 'direct') {
    return { leafNode: 'DIRECT', chain: ['DIRECT'] };
  }

  let entryGroup: ClashProxyItem | undefined;

  if (mode === 'global' && proxies['GLOBAL']) {
    entryGroup = proxies['GLOBAL'];
  } else {
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
    return { leafNode: null, chain: [] };
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
    leafNode,
    chain,
  };
}
