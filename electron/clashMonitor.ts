import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { ClashProxyNodeOption, ClashRuntimeInfo } from '../src/shared/types';
import { ANTIGRAVITY_TUN_PROCESS_NAMES } from './antigravityController';
import { CLAUDE_TUN_PROCESS_NAMES } from './claudeController';

interface JsYamlModule {
  load: (str: string) => unknown;
  dump: (obj: unknown, opts?: { lineWidth?: number; noRefs?: boolean }) => string;
}

// eslint-disable-next-line @typescript-eslint/no-require-imports
const yaml = require('js-yaml') as JsYamlModule;

interface ControllerEndpoint {
  label: string;
  pipePath?: string;
  host?: string;
  port?: number;
  secret?: string;
  yamlFile?: string;
}

interface CandidateConfigEntry {
  name: string;
  file: string;
  runtimeYaml: string;
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
const MAX_CONTROLLER_RESPONSE_BYTES = 16 * 1024 * 1024;
const CLAUDE_LISTENER_NAME = 'proxy-region-guard-claude-in';
const ANTIGRAVITY_LISTENER_NAME = 'proxy-region-guard-antigravity-in';
const AUTO_REBIND_RETRY_COOLDOWN_MS = 8000;

const MANAGED_PROCESS_RULE_PREFIXES = Array.from(
  new Set([
    ...CLAUDE_TUN_PROCESS_NAMES.map((p) => `process-name,${p.toLowerCase()},`),
    ...ANTIGRAVITY_TUN_PROCESS_NAMES.map((p) => `process-name,${p.toLowerCase()},`),
  ])
);

function isVergeUiSettingsYaml(filePath: string): boolean {
  return path.basename(filePath).toLowerCase() === 'verge.yaml';
}

const EXCLUDED_NODE_NAMES = new Set([
  'DIRECT',
  'REJECT',
  'REJECT-DROP',
  'PASS',
  'PASS-RULE',
  'COMPATIBLE',
  'GLOBAL',
]);

const GROUP_TYPES = new Set([
  'Selector',
  'URLTest',
  'Fallback',
  'LoadBalance',
  'Relay',
]);

export class ClashMonitor extends EventEmitter {
  private currentEndpoint: ControllerEndpoint | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private isTicking = false;
  private listenerApplyQueue: Promise<void> = Promise.resolve();
  private stopped = false;
  private lastGroupsSignature = '';
  private yamlCache = new Map<string, CachedYamlMeta>();

  // Claude 专属节点与端口状态
  private desiredNodeName: string | null = null;
  private desiredDedicatedPort = 27897;
  private boundNodeName: string | null = null;
  private boundPort: number | null = null;

  // Antigravity 专属节点与端口状态
  private desiredAntigravityNode: string | null = null;
  private desiredAntigravityPort = 27898;
  private boundAntigravityNode: string | null = null;
  private boundAntigravityPort: number | null = null;

  private lastAutoBindFailAt = 0;
  private lastAutoBindFailKey = '';

  private info: ClashRuntimeInfo = {
    connected: false,
    source: '未连接',
    mode: 'unknown',
    mixedPort: null,
    activeNode: null,
    nodeChain: [],
    availableNodes: [],
    boundNode: null,
    dedicatedPort: null,
    dedicatedPortListening: false,
    antigravityBoundNode: null,
    antigravityDedicatedPort: null,
    antigravityPortListening: false,
  };

  public getRuntimeInfo(): ClashRuntimeInfo {
    return structuredClone(this.info);
  }

  public start(
    initialClaudeNode: string | null = null,
    claudePort = 27897,
    initialAntigravityNode: string | null = null,
    antigravityPort = 27898
  ): void {
    this.desiredNodeName = initialClaudeNode;
    this.desiredDedicatedPort = claudePort;
    this.desiredAntigravityNode = initialAntigravityNode;
    this.desiredAntigravityPort = antigravityPort;
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

  /**
   * 设置或切换 Claude 指定的 Clash 节点，并在 Mihomo 内核中建立/更新独立专属入站端口
   */
  public async configureDedicatedNode(
    nodeName: string | null,
    dedicatedPort: number
  ): Promise<{ ok: boolean; listening: boolean; error?: string }> {
    this.desiredNodeName = nodeName ? nodeName.trim() : null;
    this.desiredDedicatedPort = dedicatedPort;

    if (!this.currentEndpoint) {
      const found = await this.findWorkingEndpoint();
      if (found) {
        this.currentEndpoint = found;
      }
    }

    if (!this.currentEndpoint) {
      this.boundNodeName = null;
      this.boundPort = null;
      this.info.boundNode = null;
      this.info.dedicatedPort = dedicatedPort;
      this.info.dedicatedPortListening = false;
      return {
        ok: false,
        listening: false,
        error: '未检测到运行中的 Clash Verge / Mihomo 控制接口',
      };
    }

    const res = await this.queueSyncDedicatedListeners(true);
    this.emit('clash-status-updated');

    if (!this.desiredNodeName) {
      return { ok: true, listening: false };
    }
    return {
      ok: res.claudeListening,
      listening: res.claudeListening,
      error: res.claudeError || res.generalError,
    };
  }

  /**
   * 设置或切换 Antigravity 指定的 Clash 节点，并在 Mihomo 内核中建立/更新独立专属入站端口及进程规则
   */
  public async configureAntigravityNode(
    nodeName: string | null,
    dedicatedPort: number
  ): Promise<{ ok: boolean; listening: boolean; error?: string }> {
    this.desiredAntigravityNode = nodeName ? nodeName.trim() : null;
    this.desiredAntigravityPort = dedicatedPort;

    if (!this.currentEndpoint) {
      const found = await this.findWorkingEndpoint();
      if (found) {
        this.currentEndpoint = found;
      }
    }

    if (!this.currentEndpoint) {
      this.boundAntigravityNode = null;
      this.boundAntigravityPort = null;
      this.info.antigravityBoundNode = null;
      this.info.antigravityDedicatedPort = dedicatedPort;
      this.info.antigravityPortListening = false;
      return {
        ok: false,
        listening: false,
        error: '未检测到运行中的 Clash Verge / Mihomo 控制接口',
      };
    }

    const res = await this.queueSyncDedicatedListeners(true);
    this.emit('clash-status-updated');

    if (!this.desiredAntigravityNode) {
      return { ok: true, listening: false };
    }
    return {
      ok: res.antigravityListening,
      listening: res.antigravityListening,
      error: res.antigravityError || res.generalError,
    };
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
        const availableNodes = extractAvailableNodes(proxiesMap);
        const nextGroupsSig = buildAllGroupsSignature(proxiesMap);

        const prevBoundClaudeNode = this.boundNodeName;
        const prevBoundClaudePort = this.boundPort;
        const prevBoundAgNode = this.boundAntigravityNode;
        const prevBoundAgPort = this.boundAntigravityPort;

        let claudeListening = false;
        let antigravityListening = false;
        let needsSync = false;

        if (this.desiredNodeName && proxiesMap[this.desiredNodeName]) {
          const alive = await isLocalPortListening(this.desiredDedicatedPort);
          if (
            !alive ||
            this.boundNodeName !== this.desiredNodeName ||
            this.boundPort !== this.desiredDedicatedPort
          ) {
            needsSync = true;
          } else {
            claudeListening = true;
          }
        }

        if (this.desiredAntigravityNode && proxiesMap[this.desiredAntigravityNode]) {
          const alive = await isLocalPortListening(this.desiredAntigravityPort);
          if (
            !alive ||
            this.boundAntigravityNode !== this.desiredAntigravityNode ||
            this.boundAntigravityPort !== this.desiredAntigravityPort
          ) {
            needsSync = true;
          } else {
            antigravityListening = true;
          }
        }

        let claudeBoundChanged = false;
        let agBoundChanged = false;

        if (needsSync) {
          const targetKey = `${this.desiredNodeName || ''}:${this.desiredDedicatedPort}|${
            this.desiredAntigravityNode || ''
          }:${this.desiredAntigravityPort}`;
          const now = Date.now();
          const inCooldown =
            this.lastAutoBindFailKey === targetKey &&
            now - this.lastAutoBindFailAt < AUTO_REBIND_RETRY_COOLDOWN_MS;

          if (!inCooldown) {
            const syncRes = await this.queueSyncDedicatedListeners(false);
            claudeListening = syncRes.claudeListening;
            antigravityListening = syncRes.antigravityListening;

            const allDesiredOk =
              (!this.desiredNodeName ||
                !proxiesMap[this.desiredNodeName] ||
                claudeListening) &&
              (!this.desiredAntigravityNode ||
                !proxiesMap[this.desiredAntigravityNode] ||
                antigravityListening);

            if (allDesiredOk) {
              this.lastAutoBindFailAt = 0;
              this.lastAutoBindFailKey = '';
            } else {
              this.lastAutoBindFailAt = Date.now();
              this.lastAutoBindFailKey = targetKey;
            }

            if (
              prevBoundClaudeNode !== this.boundNodeName ||
              prevBoundClaudePort !== this.boundPort ||
              this.info.dedicatedPortListening !== claudeListening
            ) {
              claudeBoundChanged = true;
            }
            if (
              prevBoundAgNode !== this.boundAntigravityNode ||
              prevBoundAgPort !== this.boundAntigravityPort ||
              this.info.antigravityPortListening !== antigravityListening
            ) {
              agBoundChanged = true;
            }
          }
        }

        const prevConnected = this.info.connected;
        const prevMode = this.info.mode;
        const prevNode = this.info.activeNode;
        const prevChainKey = this.info.nodeChain.join(' > ');
        const nextChainKey = resolved.chain.join(' > ');
        const prevGroupsSig = this.lastGroupsSignature;
        const prevClaudeListening = this.info.dedicatedPortListening;
        const prevAgListening = this.info.antigravityPortListening;
        const prevAvailCount = this.info.availableNodes.length;

        this.lastGroupsSignature = nextGroupsSig;
        this.info = {
          connected: true,
          source: this.currentEndpoint.label,
          mode,
          mixedPort,
          activeNode: resolved.leafNode,
          nodeChain: resolved.chain,
          availableNodes,
          boundNode: this.desiredNodeName,
          dedicatedPort: this.desiredNodeName ? this.desiredDedicatedPort : null,
          dedicatedPortListening: claudeListening,
          antigravityBoundNode: this.desiredAntigravityNode,
          antigravityDedicatedPort: this.desiredAntigravityNode
            ? this.desiredAntigravityPort
            : null,
          antigravityPortListening: antigravityListening,
        };

        if (agBoundChanged || prevAgListening !== antigravityListening) {
          this.emit('antigravity-clash-ready');
        }

        if (!prevConnected) {
          if (claudeBoundChanged) {
            this.emit(
              'clash-change',
              claudeListening
                ? `Clash 已连接并绑定专属节点: ${this.desiredNodeName} (127.0.0.1:${this.desiredDedicatedPort})`
                : `Clash 已连接，但指定节点通道未就绪: ${this.desiredNodeName}`
            );
          } else {
            this.emit('clash-status-updated');
          }
        } else if (claudeBoundChanged || prevClaudeListening !== claudeListening) {
          this.emit(
            'clash-change',
            claudeListening
              ? `已绑定专属节点通道: ${this.desiredNodeName} (127.0.0.1:${this.desiredDedicatedPort})`
              : `指定节点通道异常: ${this.desiredNodeName}`
          );
        } else if (!this.desiredNodeName && prevMode !== mode) {
          this.emit('clash-change', `Clash 代理模式变更: ${prevMode} → ${mode}`);
        } else if (
          !this.desiredNodeName &&
          (prevNode !== resolved.leafNode || prevChainKey !== nextChainKey)
        ) {
          this.emit(
            'clash-change',
            `Clash 节点变更: ${prevNode || '无'} → ${resolved.leafNode || '直连'}`
          );
        } else if (prevGroupsSig && prevGroupsSig !== nextGroupsSig) {
          const selectedClaudeItem = this.desiredNodeName
            ? proxiesMap[this.desiredNodeName]
            : null;
          const selectedAgItem = this.desiredAntigravityNode
            ? proxiesMap[this.desiredAntigravityNode]
            : null;
          if (selectedAgItem && GROUP_TYPES.has(selectedAgItem.type)) {
            this.emit('antigravity-clash-ready');
          }
          if (
            !this.desiredNodeName ||
            (selectedClaudeItem && GROUP_TYPES.has(selectedClaudeItem.type))
          ) {
            this.emit('clash-change', 'Clash 策略组节点切换');
          } else {
            this.emit('clash-status-updated');
          }
        } else if (
          prevAvailCount !== availableNodes.length ||
          agBoundChanged ||
          prevAgListening !== antigravityListening
        ) {
          this.emit('clash-status-updated');
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

  private async queueSyncDedicatedListeners(forceRebind: boolean): Promise<{
    claudeListening: boolean;
    antigravityListening: boolean;
    claudeError?: string;
    antigravityError?: string;
    generalError?: string;
  }> {
    const operation = this.listenerApplyQueue.then(() =>
      this.applySyncDedicatedListeners(forceRebind)
    );
    this.listenerApplyQueue = operation.then(
      () => undefined,
      () => undefined
    );
    return operation;
  }

  private async applySyncDedicatedListeners(forceRebind: boolean): Promise<{
    claudeListening: boolean;
    antigravityListening: boolean;
    claudeError?: string;
    antigravityError?: string;
    generalError?: string;
  }> {
    if (!this.currentEndpoint) {
      const claudeAlive = this.desiredNodeName
        ? await isLocalPortListening(this.desiredDedicatedPort)
        : false;
      const agAlive = this.desiredAntigravityNode
        ? await isLocalPortListening(this.desiredAntigravityPort)
        : false;
      return {
        claudeListening: claudeAlive,
        antigravityListening: agAlive,
        generalError: '尚未连接到 Clash 控制接口，无法确认专属节点绑定状态',
      };
    }

    const claudeAlreadyOk = !this.desiredNodeName
      ? !this.boundNodeName
      : !forceRebind &&
        this.boundNodeName === this.desiredNodeName &&
        this.boundPort === this.desiredDedicatedPort &&
        (await isLocalPortListening(this.desiredDedicatedPort));

    const agAlreadyOk = !this.desiredAntigravityNode
      ? !this.boundAntigravityNode
      : !forceRebind &&
        this.boundAntigravityNode === this.desiredAntigravityNode &&
        this.boundAntigravityPort === this.desiredAntigravityPort &&
        (await isLocalPortListening(this.desiredAntigravityPort));

    if (claudeAlreadyOk && agAlreadyOk) {
      const claudeListening = Boolean(this.desiredNodeName);
      const antigravityListening = Boolean(this.desiredAntigravityNode);
      this.info.boundNode = this.desiredNodeName;
      this.info.dedicatedPort = this.desiredNodeName ? this.desiredDedicatedPort : null;
      this.info.dedicatedPortListening = claudeListening;
      this.info.antigravityBoundNode = this.desiredAntigravityNode;
      this.info.antigravityDedicatedPort = this.desiredAntigravityNode
        ? this.desiredAntigravityPort
        : null;
      this.info.antigravityPortListening = antigravityListening;
      return { claudeListening, antigravityListening };
    }

    try {
      const yamlPath = this.findActiveClashYamlFile();
      if (!yamlPath) {
        return {
          claudeListening: false,
          antigravityListening: false,
          generalError: '未找到 Clash / Mihomo 运行时配置文件',
        };
      }

      const proxiesRes = await this.requestJson<{ proxies?: Record<string, ClashProxyItem> }>(
        this.currentEndpoint,
        '/proxies'
      );
      const proxiesMap = proxiesRes?.proxies || {};
      const savedSelections = extractSelectorSelections(proxiesMap);

      const portsToStrip = [
        this.desiredDedicatedPort,
        this.boundPort,
        this.desiredAntigravityPort,
        this.boundAntigravityPort,
      ].filter((p): p is number => typeof p === 'number' && p > 0);

      const doc = this.loadAndPrepareCoreYaml(yamlPath, portsToStrip);
      if (!doc) {
        return {
          claudeListening: false,
          antigravityListening: false,
          generalError: `配置文件无效或非内核配置: ${path.basename(yamlPath)}`,
        };
      }

      const existingListeners = Array.isArray(doc['listeners'])
        ? (doc['listeners'] as Array<Record<string, unknown>>)
        : [];
      const prependedRules: string[] = [];

      let claudeError: string | undefined;
      let antigravityError: string | undefined;
      let shouldBindClaude = false;
      let shouldBindAg = false;

      if (this.desiredNodeName) {
        if (!proxiesMap[this.desiredNodeName]) {
          claudeError = `当前 Clash 配置中不存在节点 "${this.desiredNodeName}"，请重新选择`;
        } else {
          shouldBindClaude = true;
          existingListeners.push({
            name: CLAUDE_LISTENER_NAME,
            type: 'mixed',
            port: this.desiredDedicatedPort,
            listen: '127.0.0.1',
            proxy: this.desiredNodeName,
            udp: true,
          });
          for (const proc of CLAUDE_TUN_PROCESS_NAMES) {
            prependedRules.push(`PROCESS-NAME,${proc},${this.desiredNodeName}`);
          }
        }
      }

      if (this.desiredAntigravityNode) {
        if (!proxiesMap[this.desiredAntigravityNode]) {
          antigravityError = `当前 Clash 配置中不存在节点 "${this.desiredAntigravityNode}"，请重新选择`;
        } else {
          shouldBindAg = true;
          existingListeners.push({
            name: ANTIGRAVITY_LISTENER_NAME,
            type: 'mixed',
            port: this.desiredAntigravityPort,
            listen: '127.0.0.1',
            proxy: this.desiredAntigravityNode,
            udp: true,
          });
          for (const proc of ANTIGRAVITY_TUN_PROCESS_NAMES) {
            prependedRules.push(`PROCESS-NAME,${proc},${this.desiredAntigravityNode}`);
          }
        }
      }

      doc['listeners'] = existingListeners;

      if (prependedRules.length > 0 && doc['find-process-mode'] === 'off') {
        doc['find-process-mode'] = 'strict';
      }

      const existingRules = Array.isArray(doc['rules']) ? (doc['rules'] as string[]) : [];
      doc['rules'] = [...prependedRules, ...existingRules];

      await this.reloadClashDocAndRestoreSelections(doc, savedSelections);

      const [claudeListening, antigravityListening] = await Promise.all([
        shouldBindClaude ? waitPortListening(this.desiredDedicatedPort, 1200) : Promise.resolve(false),
        shouldBindAg
          ? waitPortListening(this.desiredAntigravityPort, 1200)
          : Promise.resolve(false),
      ]);

      this.boundNodeName = claudeListening ? this.desiredNodeName : null;
      this.boundPort = claudeListening ? this.desiredDedicatedPort : null;
      this.info.boundNode = this.boundNodeName;
      this.info.dedicatedPort = this.desiredNodeName ? this.desiredDedicatedPort : null;
      this.info.dedicatedPortListening = claudeListening;

      this.boundAntigravityNode = antigravityListening ? this.desiredAntigravityNode : null;
      this.boundAntigravityPort = antigravityListening ? this.desiredAntigravityPort : null;
      this.info.antigravityBoundNode = this.boundAntigravityNode;
      this.info.antigravityDedicatedPort = this.desiredAntigravityNode
        ? this.desiredAntigravityPort
        : null;
      this.info.antigravityPortListening = antigravityListening;

      if (shouldBindClaude && !claudeListening && !claudeError) {
        claudeError = `专属代理端口 127.0.0.1:${this.desiredDedicatedPort} 未能成功启动监听`;
      }
      if (shouldBindAg && !antigravityListening && !antigravityError) {
        antigravityError = `Antigravity 专属代理端口 127.0.0.1:${this.desiredAntigravityPort} 未能成功启动监听`;
      }

      return {
        claudeListening,
        antigravityListening,
        claudeError,
        antigravityError,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        claudeListening: false,
        antigravityListening: false,
        generalError: `绑定 Clash 专属节点失败: ${msg}`,
      };
    }
  }

  private loadAndPrepareCoreYaml(
    yamlPath: string,
    portsToStrip: number[]
  ): Record<string, unknown> | null {
    if (!fs.existsSync(yamlPath) || isVergeUiSettingsYaml(yamlPath)) {
      return null;
    }
    const rawYaml = fs.readFileSync(yamlPath, 'utf-8');
    const parsed = yaml.load(rawYaml);
    if (!parsed || typeof parsed !== 'object') {
      return null;
    }
    const doc = parsed as Record<string, unknown>;
    const hasCoreFields =
      Array.isArray(doc['proxies']) ||
      Array.isArray(doc['proxy-groups']) ||
      Boolean(doc['proxy-providers']) ||
      Array.isArray(doc['rules']) ||
      typeof doc['mixed-port'] === 'number' ||
      typeof doc['port'] === 'number';
    if (!hasCoreFields) {
      return null;
    }

    if (this.currentEndpoint?.pipePath) {
      doc['external-controller-pipe'] = this.currentEndpoint.pipePath;
    }
    if (this.currentEndpoint?.host && this.currentEndpoint?.port) {
      doc['external-controller'] = `${this.currentEndpoint.host}:${this.currentEndpoint.port}`;
    }
    if (this.currentEndpoint?.secret) {
      doc['secret'] = this.currentEndpoint.secret;
    }

    const stripPortSet = new Set(portsToStrip);
    if (Array.isArray(doc['listeners'])) {
      doc['listeners'] = (doc['listeners'] as Array<Record<string, unknown>>).filter(
        (l) =>
          l &&
          l['name'] !== CLAUDE_LISTENER_NAME &&
          l['name'] !== ANTIGRAVITY_LISTENER_NAME &&
          !stripPortSet.has(Number(l['port']))
      );
    }

    if (Array.isArray(doc['rules'])) {
      doc['rules'] = (doc['rules'] as unknown[]).filter((r) => {
        if (typeof r !== 'string') return false;
        const lower = r.toLowerCase();
        return !MANAGED_PROCESS_RULE_PREFIXES.some((prefix) => lower.startsWith(prefix));
      });
    }

    return doc;
  }

  private async reloadClashDocAndRestoreSelections(
    doc: Record<string, unknown>,
    savedSelections: Array<{ group: string; now: string }>
  ): Promise<void> {
    if (!this.currentEndpoint) return;
    const dumpedYaml = yaml.dump(doc, { lineWidth: -1, noRefs: true });
    await this.requestRaw(
      this.currentEndpoint,
      'PUT',
      '/configs?force=true',
      JSON.stringify({ payload: dumpedYaml }),
      3500
    );

    if (savedSelections.length === 0) return;

    try {
      const afterProxiesRes = await this.requestJson<{ proxies?: Record<string, ClashProxyItem> }>(
        this.currentEndpoint,
        '/proxies'
      );
      const afterMap = afterProxiesRes?.proxies || {};
      for (const sel of savedSelections) {
        if (afterMap[sel.group] && afterMap[sel.group].now !== sel.now) {
          try {
            await this.requestRaw(
              this.currentEndpoint,
              'PUT',
              `/proxies/${encodeURIComponent(sel.group)}`,
              JSON.stringify({ name: sel.now }),
              1200
            );
          } catch {
            // ignore individual group restore error
          }
        }
      }
    } catch {
      // ignore transient post-reload proxies query error
    }
  }

  private findActiveClashYamlFile(): string | null {
    if (
      this.currentEndpoint?.yamlFile &&
      !isVergeUiSettingsYaml(this.currentEndpoint.yamlFile) &&
      fs.existsSync(this.currentEndpoint.yamlFile)
    ) {
      return this.currentEndpoint.yamlFile;
    }
    for (const item of this.getCandidateConfigFiles()) {
      if (fs.existsSync(item.runtimeYaml)) {
        return item.runtimeYaml;
      }
    }
    return null;
  }

  private resetDisconnectedState(): void {
    this.lastGroupsSignature = '';
    this.boundNodeName = null;
    this.boundPort = null;
    this.boundAntigravityNode = null;
    this.boundAntigravityPort = null;
    this.info = {
      connected: false,
      source: '未连接',
      mode: 'unknown',
      mixedPort: null,
      activeNode: null,
      nodeChain: [],
      availableNodes: [],
      boundNode: this.desiredNodeName,
      dedicatedPort: this.desiredNodeName ? this.desiredDedicatedPort : null,
      dedicatedPortListening: false,
      antigravityBoundNode: this.desiredAntigravityNode,
      antigravityDedicatedPort: this.desiredAntigravityNode
        ? this.desiredAntigravityPort
        : null,
      antigravityPortListening: false,
    };
  }

  private async findWorkingEndpoint(): Promise<ControllerEndpoint | null> {
    const rawCandidates: ControllerEndpoint[] = [];
    const { endpoints: yamlEndpoints, secrets: knownSecrets, primaryYamlFile } =
      this.scanClashConfigFiles();

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
          rawCandidates.push({
            label: friendly,
            pipePath: fullPipe,
            secret: sec,
            yamlFile: primaryYamlFile,
          });
        }
        rawCandidates.push({
          label: friendly,
          pipePath: fullPipe,
          yamlFile: primaryYamlFile,
        });
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
          yamlFile: primaryYamlFile,
        });
      }
      rawCandidates.push({
        label: `Clash (127.0.0.1:${port})`,
        host: '127.0.0.1',
        port,
        yamlFile: primaryYamlFile,
      });
    }

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

  private getCandidateConfigFiles(): CandidateConfigEntry[] {
    const appData = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    const home = os.homedir();
    const vergeRevRuntime = path.join(
      appData,
      'io.github.clash-verge-rev.clash-verge-rev',
      'clash-verge.yaml'
    );

    return [
      {
        name: 'Clash Verge Rev',
        file: vergeRevRuntime,
        runtimeYaml: vergeRevRuntime,
      },
      {
        name: 'Clash Verge Rev',
        file: path.join(appData, 'io.github.clash-verge-rev.clash-verge-rev', 'verge.yaml'),
        runtimeYaml: vergeRevRuntime,
      },
      {
        name: 'Clash Verge',
        file: path.join(appData, 'clash-verge', 'clash-verge.yaml'),
        runtimeYaml: path.join(appData, 'clash-verge', 'clash-verge.yaml'),
      },
      {
        name: 'Mihomo Party',
        file: path.join(appData, 'mihomo-party', 'mihomo.yaml'),
        runtimeYaml: path.join(appData, 'mihomo-party', 'mihomo.yaml'),
      },
      {
        name: 'Clash Nyanpasu',
        file: path.join(appData, 'moe.elaina.clash.nyanpasu', 'clash-nyanpasu.yaml'),
        runtimeYaml: path.join(appData, 'moe.elaina.clash.nyanpasu', 'clash-nyanpasu.yaml'),
      },
      {
        name: 'Clash for Windows',
        file: path.join(home, '.config', 'clash', 'config.yaml'),
        runtimeYaml: path.join(home, '.config', 'clash', 'config.yaml'),
      },
      {
        name: 'Mihomo',
        file: path.join(home, '.config', 'mihomo', 'config.yaml'),
        runtimeYaml: path.join(home, '.config', 'mihomo', 'config.yaml'),
      },
      {
        name: 'FlClash',
        file: path.join(appData, 'com.follow.clash', 'config.yaml'),
        runtimeYaml: path.join(appData, 'com.follow.clash', 'config.yaml'),
      },
    ];
  }

  private scanClashConfigFiles(): {
    endpoints: ControllerEndpoint[];
    secrets: string[];
    primaryYamlFile?: string;
  } {
    const results: ControllerEndpoint[] = [];
    const secretSet = new Set<string>();
    const filesToCheck = this.getCandidateConfigFiles();
    let primaryYamlFile: string | undefined;

    for (const item of filesToCheck) {
      if (!primaryYamlFile && fs.existsSync(item.runtimeYaml)) {
        primaryYamlFile = item.runtimeYaml;
      }

      const meta = this.readYamlHeaderCached(item.file);
      if (!meta) continue;

      if (meta.secret) {
        secretSet.add(meta.secret);
      }

      const targetYaml = fs.existsSync(item.runtimeYaml) ? item.runtimeYaml : primaryYamlFile;

      if (meta.pipePath) {
        results.push({
          label: `${item.name} (Pipe)`,
          pipePath: meta.pipePath,
          secret: meta.secret,
          yamlFile: targetYaml,
        });
      }

      if (meta.host && meta.port) {
        results.push({
          label: `${item.name} (${meta.host}:${meta.port})`,
          host: meta.host,
          port: meta.port,
          secret: meta.secret,
          yamlFile: targetYaml,
        });
      }
    }

    return { endpoints: results, secrets: Array.from(secretSet), primaryYamlFile };
  }

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
    return this.requestRaw(endpoint, 'GET', urlPath, undefined, timeoutMs).then((text) =>
      JSON.parse(text || '{}') as T
    );
  }

  private requestRaw(
    endpoint: ControllerEndpoint,
    method: 'GET' | 'PUT' | 'PATCH' | 'POST',
    urlPath: string,
    body?: string,
    timeoutMs = 1500
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      const payloadBuf = body ? Buffer.from(body, 'utf-8') : null;
      const headers: Record<string, string> = {
        Accept: 'application/json',
      };
      if (payloadBuf) {
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = String(payloadBuf.length);
      }
      if (endpoint.secret) {
        headers['Authorization'] = `Bearer ${endpoint.secret}`;
      }

      const options: http.RequestOptions = endpoint.pipePath
        ? {
            socketPath: endpoint.pipePath,
            path: urlPath,
            method,
            headers,
            timeout: timeoutMs,
          }
        : {
            host: endpoint.host,
            port: endpoint.port,
            path: urlPath,
            method,
            headers,
            timeout: timeoutMs,
          };

      const req = http.request(options, (res) => {
        const chunks: Buffer[] = [];
        let capturedBytes = 0;
        res.on('data', (chunk) => {
          if (capturedBytes >= MAX_CONTROLLER_RESPONSE_BYTES) return;
          const bytes = Buffer.from(chunk);
          const remaining = MAX_CONTROLLER_RESPONSE_BYTES - capturedBytes;
          const captured = bytes.length > remaining ? bytes.subarray(0, remaining) : bytes;
          chunks.push(captured);
          capturedBytes += captured.length;
        });
        res.on('end', () => {
          const responseBody = Buffer.concat(chunks).toString('utf-8').trim();
          if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
            const detail = formatControllerErrorBody(responseBody);
            reject(new Error(`HTTP ${res.statusCode}${detail}`));
            return;
          }
          resolve(responseBody);
        });
      });

      req.on('timeout', () => {
        req.destroy(new Error('Timeout'));
      });
      req.on('error', (err) => {
        reject(err);
      });
      if (payloadBuf) {
        req.write(payloadBuf);
      }
      req.end();
    });
  }
}

function formatControllerErrorBody(body: string): string {
  if (!body) return '';

  let detail = body;
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    const message = parsed.message || parsed.error || parsed.detail;
    if (typeof message === 'string') {
      detail = message;
    }
  } catch {
    // Keep non-JSON controller responses as-is.
  }

  return `: ${detail.replace(/\s+/g, ' ').slice(0, 512)}`;
}

function isLocalPortListening(port: number, timeoutMs = 220): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.connect(port, '127.0.0.1');
  });
}

async function waitPortListening(port: number, maxWaitMs: number): Promise<boolean> {
  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    if (await isLocalPortListening(port, 180)) {
      return true;
    }
    await new Promise((r) => setTimeout(r, 80));
  }
  return isLocalPortListening(port, 200);
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
  alive?: boolean;
  history?: Array<{ time?: string; delay?: number }>;
}

function extractSelectorSelections(
  proxies: Record<string, ClashProxyItem>
): Array<{ group: string; now: string }> {
  const saved: Array<{ group: string; now: string }> = [];
  for (const [k, item] of Object.entries(proxies)) {
    if (item && item.type === 'Selector' && item.now && k !== 'GLOBAL') {
      saved.push({ group: k, now: item.now });
    }
  }
  return saved;
}

function extractAvailableNodes(proxies: Record<string, ClashProxyItem>): ClashProxyNodeOption[] {
  const concreteNodes: ClashProxyNodeOption[] = [];
  const groupNodes: ClashProxyNodeOption[] = [];

  // 优先按照 GLOBAL.all 的原始配置顺序提取，保证与 Clash Verge 界面顺序一致
  const globalOrder = proxies['GLOBAL']?.all || Object.keys(proxies);
  const visited = new Set<string>();

  const processName = (name: string) => {
    if (!name || visited.has(name) || EXCLUDED_NODE_NAMES.has(name.toUpperCase())) {
      return;
    }
    const item = proxies[name];
    if (!item || !item.type) return;
    if (EXCLUDED_NODE_NAMES.has(item.type.toUpperCase())) return;
    visited.add(name);

    const isGroup = GROUP_TYPES.has(item.type);
    const lastHist =
      Array.isArray(item.history) && item.history.length > 0
        ? item.history[item.history.length - 1]
        : undefined;
    const delay =
      lastHist && typeof lastHist.delay === 'number' && lastHist.delay > 0
        ? lastHist.delay
        : undefined;

    const option: ClashProxyNodeOption = {
      name: item.name,
      type: item.type,
      isGroup,
      now: item.now,
      delay,
      alive: item.alive !== false,
    };

    if (isGroup) {
      groupNodes.push(option);
    } else {
      concreteNodes.push(option);
    }
  };

  for (const name of globalOrder) {
    processName(name);
  }
  for (const name of Object.keys(proxies)) {
    processName(name);
  }

  // 具体落地节点排在前面，策略组排在后面
  return [...concreteNodes, ...groupNodes];
}

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
