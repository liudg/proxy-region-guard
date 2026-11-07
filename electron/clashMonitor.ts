import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  ClashProfileGroupOption,
  ClashProxyNodeOption,
  ClashRuntimeInfo,
} from '../src/shared/types';
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

interface CachedProfileNodesEntry {
  mtimeMs: number;
  size: number;
  nodes: ClashProxyNodeOption[];
  rawMap: Map<string, Record<string, unknown>>;
}

interface CachedProfilesIndexEntry {
  mtimeMs: number;
  size: number;
  parsed: Record<string, unknown>;
}

interface ResolvedProfileData {
  uid: string;
  name: string;
  type: string;
  isActive: boolean;
  updatedAt?: number;
  nodes: ClashProxyNodeOption[];
  rawMap: Map<string, Record<string, unknown>>;
}

const CONNECTED_POLL_MS = 3000;
const DISCONNECTED_POLL_MS = 6000;
const YAML_HEADER_READ_BYTES = 16 * 1024;
const MAX_CONTROLLER_RESPONSE_BYTES = 4 * 1024 * 1024;
const CLAUDE_LISTENER_NAME = 'proxy-region-guard-claude-in';
const ANTIGRAVITY_LISTENER_NAME = 'proxy-region-guard-antigravity-in';
const DEDICATED_PROXY_INTERNAL_NAME = '__guard_claude_dedicated_proxy__';
const DEDICATED_DIALER_PREFIX = '__guard_claude_dialer_';
const ANTIGRAVITY_PROXY_INTERNAL_NAME = '__guard_ag_dedicated_proxy__';
const ANTIGRAVITY_DIALER_PREFIX = '__guard_ag_dialer_';
const GUARD_INTERNAL_PROXY_PREFIX = '__guard_';
const AUTO_REBIND_RETRY_COOLDOWN_MS = 2500;
const RELOAD_GRACE_WINDOW_MS = 6500;

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

const GROUP_TYPES_LOWER = new Set([
  'selector',
  'select',
  'urltest',
  'url-test',
  'fallback',
  'loadbalance',
  'load-balance',
  'relay',
  'direct',
  'reject',
  'reject-drop',
  'pass',
  'compatible',
]);

export type DedicatedChannelId = 'claude' | 'antigravity';

export interface DedicatedNodeBindResult {
  ok: boolean;
  listening: boolean;
  profileUid?: string | null;
  profileName?: string | null;
  nodeRaw?: Record<string, unknown> | null;
  dialerRaw?: Array<Record<string, unknown>> | null;
  error?: string;
}

interface DedicatedChannelSlot {
  id: DedicatedChannelId;
  label: string;
  listenerName: string;
  internalProxyName: string;
  dialerPrefix: string;
  processNames: readonly string[];
  desiredNodeName: string | null;
  desiredProfileUid: string | null;
  desiredProfileName: string | null;
  desiredNodeRaw: Record<string, unknown> | null;
  desiredDialerRaw: Array<Record<string, unknown>> | null;
  desiredPort: number;
  boundNodeName: string | null;
  boundProfileUid: string | null;
  boundProfileName: string | null;
  boundInternalProxyName: string | null;
  boundPort: number | null;
}

export class ClashMonitor extends EventEmitter {
  private currentEndpoint: ControllerEndpoint | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private configWatchDebounceTimer: NodeJS.Timeout | null = null;
  private configWatcher: fs.FSWatcher | null = null;
  private watchedDir: string | null = null;

  private isTicking = false;
  private listenerApplyQueue: Promise<void> = Promise.resolve();
  private stopped = false;
  private lastGroupsSignature = '';
  private lastProfilesSignature = '';

  private yamlCache = new Map<string, CachedYamlMeta>();
  private profileNodesCache = new Map<string, CachedProfileNodesEntry>();
  private profilesIndexCache = new Map<string, CachedProfilesIndexEntry>();
  private profileRawLookup = new Map<string, ResolvedProfileData>();
  private activeProfileSavedSelections: Array<{ group: string; now: string }> = [];

  // 通用双通道（Claude & Antigravity）专属节点与端口槽位
  private slots: Record<DedicatedChannelId, DedicatedChannelSlot> = {
    claude: {
      id: 'claude',
      label: 'Claude',
      listenerName: CLAUDE_LISTENER_NAME,
      internalProxyName: DEDICATED_PROXY_INTERNAL_NAME,
      dialerPrefix: DEDICATED_DIALER_PREFIX,
      processNames: CLAUDE_TUN_PROCESS_NAMES,
      desiredNodeName: null,
      desiredProfileUid: null,
      desiredProfileName: null,
      desiredNodeRaw: null,
      desiredDialerRaw: null,
      desiredPort: 27897,
      boundNodeName: null,
      boundProfileUid: null,
      boundProfileName: null,
      boundInternalProxyName: null,
      boundPort: null,
    },
    antigravity: {
      id: 'antigravity',
      label: 'Antigravity',
      listenerName: ANTIGRAVITY_LISTENER_NAME,
      internalProxyName: ANTIGRAVITY_PROXY_INTERNAL_NAME,
      dialerPrefix: ANTIGRAVITY_DIALER_PREFIX,
      processNames: ANTIGRAVITY_TUN_PROCESS_NAMES,
      desiredNodeName: null,
      desiredProfileUid: null,
      desiredProfileName: null,
      desiredNodeRaw: null,
      desiredDialerRaw: null,
      desiredPort: 27898,
      boundNodeName: null,
      boundProfileUid: null,
      boundProfileName: null,
      boundInternalProxyName: null,
      boundPort: null,
    },
  };

  private rebindGraceUntil = 0;
  private lastAutoBindFailAt = 0;
  private lastAutoBindFailKey = '';

  private info: ClashRuntimeInfo = {
    connected: false,
    source: '未连接',
    mode: 'unknown',
    mixedPort: null,
    activeNode: null,
    activeProfileUid: null,
    activeProfileName: null,
    nodeChain: [],
    availableNodes: [],
    profileGroups: [],
    boundNode: null,
    boundProfileUid: null,
    boundProfileName: null,
    dedicatedPort: null,
    dedicatedPortListening: false,
    antigravityBoundNode: null,
    antigravityBoundProfileUid: null,
    antigravityBoundProfileName: null,
    antigravityDedicatedPort: null,
    antigravityPortListening: false,
  };

  public getRuntimeInfo(): ClashRuntimeInfo {
    return {
      ...this.info,
      nodeChain: [...this.info.nodeChain],
      availableNodes: this.info.availableNodes,
    };
  }

  public start(
    initialClaudeNode: string | null = null,
    claudePort = 27897,
    initialAntigravityNode: string | null = null,
    antigravityPort = 27898,
    initialProfileUid: string | null = null,
    initialProfileName: string | null = null,
    initialNodeRaw: Record<string, unknown> | null = null,
    initialDialerRaw: Array<Record<string, unknown>> | null = null,
    initialAgProfileUid: string | null = null,
    initialAgProfileName: string | null = null,
    initialAgNodeRaw: Record<string, unknown> | null = null,
    initialAgDialerRaw: Array<Record<string, unknown>> | null = null
  ): void {
    const claudeSlot = this.slots.claude;
    claudeSlot.desiredNodeName = initialClaudeNode ? initialClaudeNode.trim() : null;
    claudeSlot.desiredPort = claudePort;
    claudeSlot.desiredProfileUid = initialProfileUid ? initialProfileUid.trim() : null;
    claudeSlot.desiredProfileName = initialProfileName ? initialProfileName.trim() : null;
    claudeSlot.desiredNodeRaw = initialNodeRaw ? structuredClone(initialNodeRaw) : null;
    claudeSlot.desiredDialerRaw = initialDialerRaw ? structuredClone(initialDialerRaw) : null;

    const agSlot = this.slots.antigravity;
    agSlot.desiredNodeName = initialAntigravityNode ? initialAntigravityNode.trim() : null;
    agSlot.desiredPort = antigravityPort;
    agSlot.desiredProfileUid = initialAgProfileUid ? initialAgProfileUid.trim() : null;
    agSlot.desiredProfileName = initialAgProfileName ? initialAgProfileName.trim() : null;
    agSlot.desiredNodeRaw = initialAgNodeRaw ? structuredClone(initialAgNodeRaw) : null;
    agSlot.desiredDialerRaw = initialAgDialerRaw ? structuredClone(initialAgDialerRaw) : null;

    this.stopped = false;

    // 启动时先扫描一次本地 Clash Verge Rev 订阅库，确保即使内核未连接也能立即展示全部订阅组
    this.refreshOfflineProfilesState({});
    this.ensureConfigDirWatcher();
    this.scheduleNextTick(0);
  }

  public stop(): void {
    this.stopped = true;
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
    if (this.configWatchDebounceTimer) {
      clearTimeout(this.configWatchDebounceTimer);
      this.configWatchDebounceTimer = null;
    }
    this.closeConfigWatcher();
  }

  /**
   * 通用跨订阅节点与专属入站端口配置引擎（Claude 与 Antigravity 共用同一套底层逻辑）
   */
  public async configureChannelNode(
    channelId: DedicatedChannelId,
    nodeName: string | null,
    dedicatedPort: number,
    profileUid?: string | null,
    forceRebind = true
  ): Promise<DedicatedNodeBindResult> {
    const slot = this.slots[channelId];
    const cleanNode = nodeName ? nodeName.trim() : null;
    const cleanProfileUid =
      profileUid !== undefined
        ? profileUid && profileUid.trim()
          ? profileUid.trim()
          : null
        : slot.desiredProfileUid;

    const isSameSelection =
      slot.desiredNodeName === cleanNode && slot.desiredProfileUid === cleanProfileUid;

    slot.desiredNodeName = cleanNode;
    slot.desiredProfileUid = cleanNode ? cleanProfileUid : null;
    if (!cleanNode) {
      slot.desiredProfileName = null;
      slot.desiredNodeRaw = null;
      slot.desiredDialerRaw = null;
    } else if (!isSameSelection) {
      slot.desiredNodeRaw = null;
      slot.desiredDialerRaw = null;
    }
    slot.desiredPort = dedicatedPort;

    if (!this.currentEndpoint) {
      const found = await this.findWorkingEndpoint();
      if (found) {
        this.currentEndpoint = found;
        this.ensureConfigDirWatcher();
      }
    }

    if (slot.desiredNodeName) {
      this.refreshOfflineProfilesState({});
      const resolvedMeta = this.resolveSlotTargetNodeDefinition(slot);
      if (resolvedMeta) {
        slot.desiredProfileUid = resolvedMeta.profileUid;
        slot.desiredProfileName = resolvedMeta.profileName;
        slot.desiredNodeRaw = structuredClone(resolvedMeta.rawProxy);
        slot.desiredDialerRaw = structuredClone(resolvedMeta.dialerChain);
      }
    }

    if (!this.currentEndpoint) {
      slot.boundNodeName = null;
      slot.boundProfileUid = null;
      slot.boundProfileName = null;
      slot.boundInternalProxyName = null;
      slot.boundPort = null;
      if (channelId === 'claude') {
        this.rebindGraceUntil = 0;
      }
      this.syncSlotInfoFields(false, false);
      this.emit('clash-status-updated');
      if (!slot.desiredNodeName) {
        return { ok: true, listening: false };
      }
      return {
        ok: false,
        listening: false,
        profileUid: slot.desiredProfileUid,
        profileName: slot.desiredProfileName,
        nodeRaw: slot.desiredNodeRaw,
        dialerRaw: slot.desiredDialerRaw,
        error: '未检测到运行中的 Clash Verge / Mihomo 控制接口',
      };
    }

    const res = await this.queueSyncDedicatedListeners(forceRebind);
    this.emit('clash-status-updated');

    if (!slot.desiredNodeName) {
      if (channelId === 'claude') {
        this.rebindGraceUntil = 0;
      }
      return { ok: true, listening: false };
    }

    const listening = channelId === 'claude' ? res.claudeListening : res.antigravityListening;
    const channelErr = channelId === 'claude' ? res.claudeError : res.antigravityError;

    return {
      ok: listening,
      listening,
      profileUid: slot.desiredProfileUid,
      profileName: slot.desiredProfileName,
      nodeRaw: slot.desiredNodeRaw,
      dialerRaw: slot.desiredDialerRaw,
      error: channelErr || res.generalError,
    };
  }

  /**
   * 设置或切换 Claude 指定的 Clash 节点（支持任意未激活订阅组的节点）
   */
  public async configureDedicatedNode(
    nodeName: string | null,
    dedicatedPort: number,
    profileUid?: string | null,
    forceRebind = true
  ): Promise<DedicatedNodeBindResult> {
    return this.configureChannelNode('claude', nodeName, dedicatedPort, profileUid, forceRebind);
  }

  /**
   * 设置或切换 Antigravity 指定的 Clash 节点（同样支持任意未激活订阅组的节点）
   */
  public async configureAntigravityNode(
    nodeName: string | null,
    dedicatedPort: number,
    profileUid?: string | null,
    forceRebind = true
  ): Promise<DedicatedNodeBindResult> {
    return this.configureChannelNode(
      'antigravity',
      nodeName,
      dedicatedPort,
      profileUid,
      forceRebind
    );
  }

  private syncSlotInfoFields(claudeListening: boolean, antigravityListening: boolean): void {
    const claude = this.slots.claude;
    const ag = this.slots.antigravity;

    this.info.boundNode = claude.desiredNodeName;
    this.info.boundProfileUid = claude.desiredNodeName
      ? claude.boundProfileUid || claude.desiredProfileUid
      : null;
    this.info.boundProfileName = claude.desiredNodeName
      ? claude.boundProfileName || claude.desiredProfileName
      : null;
    this.info.dedicatedPort = claude.desiredNodeName ? claude.desiredPort : null;
    this.info.dedicatedPortListening = claudeListening;

    this.info.antigravityBoundNode = ag.desiredNodeName;
    this.info.antigravityBoundProfileUid = ag.desiredNodeName
      ? ag.boundProfileUid || ag.desiredProfileUid
      : null;
    this.info.antigravityBoundProfileName = ag.desiredNodeName
      ? ag.boundProfileName || ag.desiredProfileName
      : null;
    this.info.antigravityDedicatedPort = ag.desiredNodeName ? ag.desiredPort : null;
    this.info.antigravityPortListening = antigravityListening;
  }

  private ensureConfigDirWatcher(): void {
    const vergeDir = this.findClashVergeConfigDir();
    if (!vergeDir || !fs.existsSync(vergeDir)) return;
    if (this.watchedDir === vergeDir && this.configWatcher) return;

    this.closeConfigWatcher();
    try {
      this.watchedDir = vergeDir;
      this.configWatcher = fs.watch(vergeDir, { persistent: false }, (_event, filename) => {
        if (this.stopped || !filename) return;
        const lower = filename.toLowerCase();
        if (
          lower === 'clash-verge.yaml' ||
          lower === 'profiles.yaml' ||
          lower === 'config.yaml'
        ) {
          // 当用户在 Clash Verge Rev 中切换订阅组或重载配置时，留出 360ms 让 Clash Verge 完成自身重载后立即无缝补回专属节点
          if (this.slots.claude.boundNodeName && this.info.dedicatedPortListening) {
            this.rebindGraceUntil = Date.now() + RELOAD_GRACE_WINDOW_MS;
          }
          if (this.configWatchDebounceTimer) {
            clearTimeout(this.configWatchDebounceTimer);
          }
          this.configWatchDebounceTimer = setTimeout(() => {
            this.configWatchDebounceTimer = null;
            this.scheduleNextTick(0);
          }, 360);
        }
      });
    } catch {
      this.closeConfigWatcher();
    }
  }

  private closeConfigWatcher(): void {
    if (this.configWatcher) {
      try {
        this.configWatcher.close();
      } catch {
        // ignore
      }
      this.configWatcher = null;
    }
    this.watchedDir = null;
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
    let fastRetryMs: number | null = null;

    try {
      this.ensureConfigDirWatcher();

      if (!this.currentEndpoint) {
        const found = await this.findWorkingEndpoint();
        if (!found) {
          this.refreshOfflineProfilesState({});
          if (this.info.connected) {
            this.resetDisconnectedState();
            this.emit('clash-change', 'Clash 控制接口断开连接');
          }
          return;
        }
        this.currentEndpoint = found;
        this.ensureConfigDirWatcher();
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

        // 扫描全部订阅组及节点，并结合当前运行态 proxiesMap 填充延迟数据
        const profilesScan = this.scanAllClashVergeProfiles(proxiesMap);
        const nextGroupsSig = buildAllGroupsSignature(proxiesMap);
        const nextProfilesSig = buildProfilesSignature(profilesScan.profileGroups);

        const claudeSlot = this.slots.claude;
        const agSlot = this.slots.antigravity;

        const prevBoundClaudeNode = claudeSlot.boundNodeName;
        const prevBoundProfile = claudeSlot.boundProfileUid;
        const prevBoundClaudePort = claudeSlot.boundPort;
        const prevBoundAgNode = agSlot.boundNodeName;
        const prevBoundAgProfile = agSlot.boundProfileUid;
        const prevBoundAgPort = agSlot.boundPort;

        let claudeListening = false;
        let antigravityListening = false;
        let needsSync = false;

        for (const slot of [claudeSlot, agSlot]) {
          if (!slot.desiredNodeName) continue;
          const expectedInternal = slot.boundInternalProxyName || slot.internalProxyName;
          const nodeAliveInKernel = Boolean(
            proxiesMap[expectedInternal] || proxiesMap[slot.desiredNodeName]
          );
          const portAlive = nodeAliveInKernel
            ? await isLocalPortListening(slot.desiredPort)
            : false;
          const desiredProfileMatches =
            !slot.desiredProfileUid ||
            !slot.boundProfileUid ||
            slot.desiredProfileUid === slot.boundProfileUid;

          if (
            !nodeAliveInKernel ||
            !portAlive ||
            slot.boundNodeName !== slot.desiredNodeName ||
            !desiredProfileMatches ||
            slot.boundPort !== slot.desiredPort
          ) {
            needsSync = true;
          } else if (slot.id === 'claude') {
            claudeListening = true;
            this.rebindGraceUntil = 0;
          } else {
            antigravityListening = true;
          }
        }

        let claudeBoundChanged = false;
        let agBoundChanged = false;

        if (needsSync) {
          const targetKey = `${claudeSlot.desiredProfileUid || ''}:::${
            claudeSlot.desiredNodeName || ''
          }:${claudeSlot.desiredPort}|${agSlot.desiredProfileUid || ''}:::${
            agSlot.desiredNodeName || ''
          }:${agSlot.desiredPort}`;
          const now = Date.now();
          const inCooldown =
            this.lastAutoBindFailKey === targetKey &&
            now - this.lastAutoBindFailAt < AUTO_REBIND_RETRY_COOLDOWN_MS &&
            now >= this.rebindGraceUntil;

          if (!inCooldown) {
            if (this.info.dedicatedPortListening) {
              this.rebindGraceUntil = Math.max(
                this.rebindGraceUntil,
                Date.now() + RELOAD_GRACE_WINDOW_MS
              );
            }
            const syncRes = await this.queueSyncDedicatedListeners(true);
            claudeListening = syncRes.claudeListening;
            antigravityListening = syncRes.antigravityListening;

            const allDesiredOk =
              (!claudeSlot.desiredNodeName || claudeListening) &&
              (!agSlot.desiredNodeName || antigravityListening);

            if (allDesiredOk) {
              this.lastAutoBindFailAt = 0;
              this.lastAutoBindFailKey = '';
              this.rebindGraceUntil = 0;
            } else {
              this.lastAutoBindFailAt = Date.now();
              this.lastAutoBindFailKey = targetKey;
              if (
                claudeSlot.desiredNodeName &&
                !claudeListening &&
                Date.now() < this.rebindGraceUntil &&
                prevBoundClaudeNode === claudeSlot.desiredNodeName
              ) {
                claudeListening = true;
                fastRetryMs = 400;
              }
            }

            if (
              prevBoundClaudeNode !== claudeSlot.boundNodeName ||
              prevBoundProfile !== claudeSlot.boundProfileUid ||
              prevBoundClaudePort !== claudeSlot.boundPort ||
              this.info.dedicatedPortListening !== claudeListening
            ) {
              claudeBoundChanged = true;
            }
            if (
              prevBoundAgNode !== agSlot.boundNodeName ||
              prevBoundAgProfile !== agSlot.boundProfileUid ||
              prevBoundAgPort !== agSlot.boundPort ||
              this.info.antigravityPortListening !== antigravityListening
            ) {
              agBoundChanged = true;
            }
          } else if (
            claudeSlot.desiredNodeName &&
            Date.now() < this.rebindGraceUntil &&
            prevBoundClaudeNode === claudeSlot.desiredNodeName
          ) {
            claudeListening = true;
            fastRetryMs = 450;
          }
        }

        const prevConnected = this.info.connected;
        const prevMode = this.info.mode;
        const prevNode = this.info.activeNode;
        const prevChainKey = this.info.nodeChain.join(' > ');
        const nextChainKey = resolved.chain.join(' > ');
        const prevGroupsSig = this.lastGroupsSignature;
        const prevProfilesSig = this.lastProfilesSignature;
        const prevClaudeListening = this.info.dedicatedPortListening;
        const prevAgListening = this.info.antigravityPortListening;
        const prevAvailCount = this.info.availableNodes.length;
        const prevActiveProfileUid = this.info.activeProfileUid;

        this.lastGroupsSignature = nextGroupsSig;
        this.lastProfilesSignature = nextProfilesSig;
        this.info = {
          connected: true,
          source: this.currentEndpoint.label,
          mode,
          mixedPort,
          activeNode: resolved.leafNode,
          activeProfileUid: profilesScan.activeProfileUid,
          activeProfileName: profilesScan.activeProfileName,
          nodeChain: resolved.chain,
          availableNodes: profilesScan.availableNodes,
          profileGroups: profilesScan.profileGroups,
          boundNode: claudeSlot.desiredNodeName,
          boundProfileUid: claudeSlot.desiredNodeName
            ? claudeSlot.boundProfileUid || claudeSlot.desiredProfileUid
            : null,
          boundProfileName: claudeSlot.desiredNodeName
            ? claudeSlot.boundProfileName || claudeSlot.desiredProfileName
            : null,
          dedicatedPort: claudeSlot.desiredNodeName ? claudeSlot.desiredPort : null,
          dedicatedPortListening: claudeListening,
          antigravityBoundNode: agSlot.desiredNodeName,
          antigravityBoundProfileUid: agSlot.desiredNodeName
            ? agSlot.boundProfileUid || agSlot.desiredProfileUid
            : null,
          antigravityBoundProfileName: agSlot.desiredNodeName
            ? agSlot.boundProfileName || agSlot.desiredProfileName
            : null,
          antigravityDedicatedPort: agSlot.desiredNodeName ? agSlot.desiredPort : null,
          antigravityPortListening: antigravityListening,
        };

        if (agBoundChanged || prevAgListening !== antigravityListening) {
          this.emit('antigravity-clash-ready');
        }

        const displayBoundLabel = this.formatBoundDisplayLabel(claudeSlot);

        if (!prevConnected) {
          if (claudeBoundChanged) {
            this.emit(
              'clash-change',
              claudeListening
                ? `Clash 已连接并锁定专属节点: ${displayBoundLabel} (127.0.0.1:${claudeSlot.desiredPort})`
                : `Clash 已连接，但指定节点通道未就绪: ${displayBoundLabel}`
            );
          } else {
            this.emit('clash-status-updated');
          }
        } else if (claudeBoundChanged || prevClaudeListening !== claudeListening) {
          this.emit(
            'clash-change',
            claudeListening
              ? `已绑定专属节点通道: ${displayBoundLabel} (127.0.0.1:${claudeSlot.desiredPort})`
              : `指定节点通道异常: ${displayBoundLabel}`
          );
        } else if (!claudeSlot.desiredNodeName && prevMode !== mode) {
          this.emit('clash-change', `Clash 代理模式变更: ${prevMode} → ${mode}`);
        } else if (
          !claudeSlot.desiredNodeName &&
          (prevNode !== resolved.leafNode || prevChainKey !== nextChainKey)
        ) {
          this.emit(
            'clash-change',
            `Clash 节点变更: ${prevNode || '无'} → ${resolved.leafNode || '直连'}`
          );
        } else if (prevGroupsSig && prevGroupsSig !== nextGroupsSig) {
          const selectedAgItem = agSlot.desiredNodeName
            ? proxiesMap[agSlot.desiredNodeName]
            : null;
          if (selectedAgItem && GROUP_TYPES.has(selectedAgItem.type)) {
            this.emit('antigravity-clash-ready');
          }
          if (!claudeSlot.desiredNodeName) {
            this.emit('clash-change', 'Clash 策略组节点切换');
          } else {
            this.emit('clash-status-updated');
          }
        } else if (
          prevAvailCount !== profilesScan.availableNodes.length ||
          prevProfilesSig !== nextProfilesSig ||
          prevActiveProfileUid !== profilesScan.activeProfileUid ||
          agBoundChanged ||
          prevAgListening !== antigravityListening
        ) {
          this.emit('clash-status-updated');
        }
      } catch {
        this.currentEndpoint = null;
        this.refreshOfflineProfilesState({});
        if (this.info.connected) {
          // 若处于 Clash 切换订阅或 TUN 重启瞬间的宽限期内，先快速重连而不立即触发断连告警
          if (
            this.slots.claude.desiredNodeName &&
            this.slots.claude.boundNodeName &&
            Date.now() < this.rebindGraceUntil
          ) {
            fastRetryMs = 400;
            return;
          }
          this.resetDisconnectedState();
          this.emit('clash-change', 'Clash 内核已关闭或重启');
        }
      }
    } finally {
      this.isTicking = false;
      const nextDelay =
        fastRetryMs !== null
          ? fastRetryMs
          : this.currentEndpoint
          ? CONNECTED_POLL_MS
          : DISCONNECTED_POLL_MS;
      this.scheduleNextTick(nextDelay);
    }
  }

  private formatBoundDisplayLabel(slot: DedicatedChannelSlot): string {
    const pName = slot.boundProfileName || slot.desiredProfileName;
    const nName = slot.desiredNodeName || '';
    return pName ? `${pName} / ${nName}` : nName;
  }

  private refreshOfflineProfilesState(activeProxiesMap: Record<string, ClashProxyItem>): void {
    try {
      const scan = this.scanAllClashVergeProfiles(activeProxiesMap);
      this.info.activeProfileUid = scan.activeProfileUid;
      this.info.activeProfileName = scan.activeProfileName;
      this.info.availableNodes = scan.availableNodes;
      this.info.profileGroups = scan.profileGroups;
    } catch {
      // ignore offline scan errors
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
    const claudeSlot = this.slots.claude;
    const agSlot = this.slots.antigravity;

    if (!this.currentEndpoint) {
      const claudeAlive = claudeSlot.desiredNodeName
        ? await isLocalPortListening(claudeSlot.desiredPort)
        : false;
      const agAlive = agSlot.desiredNodeName
        ? await isLocalPortListening(agSlot.desiredPort)
        : false;
      return {
        claudeListening: claudeAlive,
        antigravityListening: agAlive,
        generalError: '尚未连接到 Clash Verge Rev 控制接口，无法确认专属节点绑定状态',
      };
    }

    const isSlotAlreadyOk = async (slot: DedicatedChannelSlot): Promise<boolean> => {
      if (!slot.desiredNodeName) {
        return !slot.boundNodeName;
      }
      if (forceRebind) return false;
      return (
        slot.boundNodeName === slot.desiredNodeName &&
        (!slot.desiredProfileUid || slot.boundProfileUid === slot.desiredProfileUid) &&
        slot.boundPort === slot.desiredPort &&
        (await isLocalPortListening(slot.desiredPort))
      );
    };

    const [claudeAlreadyOk, agAlreadyOk] = await Promise.all([
      isSlotAlreadyOk(claudeSlot),
      isSlotAlreadyOk(agSlot),
    ]);

    if (claudeAlreadyOk && agAlreadyOk) {
      const claudeListening = Boolean(claudeSlot.desiredNodeName);
      const antigravityListening = Boolean(agSlot.desiredNodeName);
      this.syncSlotInfoFields(claudeListening, antigravityListening);
      return { claudeListening, antigravityListening };
    }

    try {
      const yamlPath = this.findActiveClashYamlFile();
      if (!yamlPath) {
        return {
          claudeListening: false,
          antigravityListening: false,
          generalError: '未找到 Clash Verge Rev 运行时配置文件 (clash-verge.yaml)',
        };
      }

      const proxiesRes = await this.requestJson<{ proxies?: Record<string, ClashProxyItem> }>(
        this.currentEndpoint,
        '/proxies'
      );
      const proxiesMap = proxiesRes?.proxies || {};

      this.scanAllClashVergeProfiles(proxiesMap);

      const savedSelections = this.mergeSelectorSelections(
        extractSelectorSelections(proxiesMap),
        this.activeProfileSavedSelections
      );

      const portsToStrip = [
        claudeSlot.desiredPort,
        claudeSlot.boundPort,
        agSlot.desiredPort,
        agSlot.boundPort,
      ].filter((p): p is number => typeof p === 'number' && p > 0);

      const doc = this.loadAndPrepareCoreYaml(yamlPath, portsToStrip);
      if (!doc) {
        return {
          claudeListening: false,
          antigravityListening: false,
          generalError: `配置文件无效或非内核配置: ${path.basename(yamlPath)}`,
        };
      }

      const existingProxies = Array.isArray(doc['proxies'])
        ? (doc['proxies'] as Array<Record<string, unknown>>)
        : [];
      const existingListeners = Array.isArray(doc['listeners'])
        ? (doc['listeners'] as Array<Record<string, unknown>>)
        : [];
      const prependedRules: string[] = [];

      const slotOutcome: Record<
        DedicatedChannelId,
        { shouldBind: boolean; targetProxy: string; error?: string }
      > = {
        claude: { shouldBind: false, targetProxy: '' },
        antigravity: { shouldBind: false, targetProxy: '' },
      };

      // 统一遍历所有专属通道槽位，执行跨订阅节点提取、链式前置节点注入、独立入站监听及进程规则绑定
      for (const slot of [claudeSlot, agSlot]) {
        if (!slot.desiredNodeName) continue;

        const resolved = this.resolveSlotTargetNodeDefinition(slot);
        if (resolved) {
          slot.desiredProfileUid = resolved.profileUid;
          slot.desiredProfileName = resolved.profileName;
          slot.desiredNodeRaw = structuredClone(resolved.rawProxy);
          slot.desiredDialerRaw = structuredClone(resolved.dialerChain);
        }

        let shouldBind = false;
        let targetProxy = slot.desiredNodeName;

        if (slot.desiredNodeRaw) {
          shouldBind = true;
          const dialerChain = slot.desiredDialerRaw || [];
          for (let i = 0; i < dialerChain.length; i++) {
            const hopClone = structuredClone(dialerChain[i]);
            hopClone['name'] = `${slot.dialerPrefix}${i}__`;
            if (i + 1 < dialerChain.length) {
              hopClone['dialer-proxy'] = `${slot.dialerPrefix}${i + 1}__`;
            }
            existingProxies.push(hopClone);
          }

          const injectedNode = structuredClone(slot.desiredNodeRaw);
          injectedNode['name'] = slot.internalProxyName;
          if (dialerChain.length > 0) {
            injectedNode['dialer-proxy'] = `${slot.dialerPrefix}0__`;
          }
          existingProxies.push(injectedNode);
          targetProxy = slot.internalProxyName;
        } else if (proxiesMap[slot.desiredNodeName]) {
          shouldBind = true;
          targetProxy = slot.desiredNodeName;
        } else {
          slotOutcome[slot.id].error = `在所有 Clash 订阅组中均未找到节点 "${slot.desiredNodeName}"，请重新选择`;
        }

        if (shouldBind) {
          slotOutcome[slot.id].shouldBind = true;
          slotOutcome[slot.id].targetProxy = targetProxy;
          existingListeners.push({
            name: slot.listenerName,
            type: 'mixed',
            port: slot.desiredPort,
            listen: '127.0.0.1',
            proxy: targetProxy,
            udp: true,
          });
          for (const proc of slot.processNames) {
            prependedRules.push(`PROCESS-NAME,${proc},${targetProxy}`);
          }
        }
      }

      doc['proxies'] = existingProxies;
      doc['listeners'] = existingListeners;

      if (prependedRules.length > 0 && doc['find-process-mode'] === 'off') {
        doc['find-process-mode'] = 'strict';
      }

      const existingRules = Array.isArray(doc['rules']) ? (doc['rules'] as string[]) : [];
      doc['rules'] = [...prependedRules, ...existingRules];

      await this.reloadClashDocAndRestoreSelections(doc, savedSelections);

      const [claudeListening, antigravityListening] = await Promise.all([
        slotOutcome.claude.shouldBind
          ? waitPortListening(claudeSlot.desiredPort, 1500)
          : Promise.resolve(false),
        slotOutcome.antigravity.shouldBind
          ? waitPortListening(agSlot.desiredPort, 1500)
          : Promise.resolve(false),
      ]);

      const updateSlotBoundState = (slot: DedicatedChannelSlot, listening: boolean) => {
        slot.boundNodeName = listening ? slot.desiredNodeName : null;
        slot.boundProfileUid = listening ? slot.desiredProfileUid : null;
        slot.boundProfileName = listening ? slot.desiredProfileName : null;
        slot.boundInternalProxyName = listening ? slotOutcome[slot.id].targetProxy : null;
        slot.boundPort = listening ? slot.desiredPort : null;
        if (slotOutcome[slot.id].shouldBind && !listening && !slotOutcome[slot.id].error) {
          slotOutcome[slot.id].error = `${slot.label} 专属代理端口 127.0.0.1:${slot.desiredPort} 未能成功启动监听`;
        }
      };

      updateSlotBoundState(claudeSlot, claudeListening);
      updateSlotBoundState(agSlot, antigravityListening);
      this.syncSlotInfoFields(claudeListening, antigravityListening);

      if (claudeListening) {
        this.lastAutoBindFailAt = 0;
        this.lastAutoBindFailKey = '';
        this.rebindGraceUntil = 0;
      }

      return {
        claudeListening,
        antigravityListening,
        claudeError: slotOutcome.claude.error,
        antigravityError: slotOutcome.antigravity.error,
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

  private mergeSelectorSelections(
    liveSelections: Array<{ group: string; now: string }>,
    profileSaved: Array<{ group: string; now: string }>
  ): Array<{ group: string; now: string }> {
    const map = new Map<string, string>();
    for (const item of profileSaved) {
      if (item.group && item.now) {
        map.set(item.group, item.now);
      }
    }
    for (const item of liveSelections) {
      if (item.group && item.now) {
        map.set(item.group, item.now);
      }
    }
    const out: Array<{ group: string; now: string }> = [];
    for (const [group, now] of map.entries()) {
      out.push({ group, now });
    }
    return out;
  }

  private resolveSlotTargetNodeDefinition(slot: DedicatedChannelSlot): {
    profileUid: string | null;
    profileName: string | null;
    rawProxy: Record<string, unknown>;
    dialerChain: Array<Record<string, unknown>>;
  } | null {
    const nodeName = slot.desiredNodeName;
    if (!nodeName) return null;
    const preferredProfileUid = slot.desiredProfileUid;

    // 1. 优先从用户指定的订阅组 UID 中精确匹配
    if (preferredProfileUid && this.profileRawLookup.has(preferredProfileUid)) {
      const targetProf = this.profileRawLookup.get(preferredProfileUid)!;
      const raw = targetProf.rawMap.get(nodeName);
      if (raw) {
        return {
          profileUid: targetProf.uid,
          profileName: targetProf.name,
          rawProxy: structuredClone(raw),
          dialerChain: extractDialerChain(raw, targetProf.rawMap),
        };
      }
    }

    // 2. 其次在当前激活的订阅组中查找同名节点
    for (const prof of this.profileRawLookup.values()) {
      if (prof.isActive && prof.rawMap.has(nodeName)) {
        const raw = prof.rawMap.get(nodeName)!;
        return {
          profileUid: prof.uid,
          profileName: prof.name,
          rawProxy: structuredClone(raw),
          dialerChain: extractDialerChain(raw, prof.rawMap),
        };
      }
    }

    // 3. 遍历其余所有未激活订阅组查找
    for (const prof of this.profileRawLookup.values()) {
      if (prof.rawMap.has(nodeName)) {
        const raw = prof.rawMap.get(nodeName)!;
        return {
          profileUid: prof.uid,
          profileName: prof.name,
          rawProxy: structuredClone(raw),
          dialerChain: extractDialerChain(raw, prof.rawMap),
        };
      }
    }

    // 4. 兜底使用该通道槽位已持久化的缓存节点定义
    if (slot.desiredNodeRaw) {
      return {
        profileUid: slot.desiredProfileUid,
        profileName: slot.desiredProfileName,
        rawProxy: structuredClone(slot.desiredNodeRaw),
        dialerChain: slot.desiredDialerRaw ? structuredClone(slot.desiredDialerRaw) : [],
      };
    }

    return null;
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

    // 清理之前注入的内部专属节点定义
    if (Array.isArray(doc['proxies'])) {
      doc['proxies'] = (doc['proxies'] as Array<Record<string, unknown>>).filter(
        (p) =>
          p &&
          typeof p['name'] === 'string' &&
          !p['name'].startsWith(GUARD_INTERNAL_PROXY_PREFIX)
      );
    }
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
        if (
          afterMap[sel.group] &&
          afterMap[sel.group].now !== sel.now &&
          (!Array.isArray(afterMap[sel.group].all) || afterMap[sel.group].all!.includes(sel.now))
        ) {
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

  /**
   * 扫描 Clash Verge Rev 的 profiles.yaml 及 profiles/*.yaml，
   * 提取所有订阅组（含未激活订阅）下的全部具体落地节点及其底层配置对象
   */
  private scanAllClashVergeProfiles(activeProxiesMap: Record<string, ClashProxyItem>): {
    activeProfileUid: string | null;
    activeProfileName: string | null;
    profileGroups: ClashProfileGroupOption[];
    availableNodes: ClashProxyNodeOption[];
  } {
    const resolvedProfiles: ResolvedProfileData[] = [];
    const nextLookup = new Map<string, ResolvedProfileData>();
    const nextActiveSelections: Array<{ group: string; now: string }> = [];

    let activeProfileUid: string | null = null;
    let activeProfileName: string | null = null;

    const vergeDir = this.findClashVergeConfigDir();
    if (vergeDir) {
      const profilesYamlPath = path.join(vergeDir, 'profiles.yaml');
      const profilesDoc = this.readProfilesIndexCached(profilesYamlPath);

      if (profilesDoc) {
        const currentRaw = profilesDoc['current'];
        const activeUids = new Set<string>(
          Array.isArray(currentRaw)
            ? currentRaw.map((x) => String(x || '').trim()).filter(Boolean)
            : typeof currentRaw === 'string' && currentRaw.trim()
            ? [currentRaw.trim()]
            : []
        );

        const items = Array.isArray(profilesDoc['items'])
          ? (profilesDoc['items'] as Array<Record<string, unknown>>)
          : [];

        const itemsByUid = new Map<string, Record<string, unknown>>();
        const baseNameCounts = new Map<string, number>();

        for (const item of items) {
          if (!item || typeof item !== 'object') continue;
          const uid = String(item['uid'] || '').trim();
          if (!uid) continue;
          itemsByUid.set(uid, item);

          const rawType = String(item['type'] || 'remote').toLowerCase();
          if (rawType !== 'remote' && rawType !== 'local') continue;

          const fileField = String(item['file'] || '').trim();
          const fallbackBaseName = fileField
            ? path.basename(fileField, path.extname(fileField))
            : uid;
          const baseName =
            String(item['name'] || item['desc'] || fallbackBaseName || uid).trim() || uid;
          baseNameCounts.set(baseName, (baseNameCounts.get(baseName) || 0) + 1);
        }

        for (const item of items) {
          if (!item || typeof item !== 'object') continue;
          const uid = String(item['uid'] || '').trim();
          if (!uid) continue;

          const rawType = String(item['type'] || 'remote').toLowerCase();
          const fileField = String(item['file'] || '').trim();
          if (rawType !== 'remote' && rawType !== 'local') {
            continue;
          }

          const isActive = activeUids.has(uid);

          // 收集当前激活订阅在 profiles.yaml 中持久化的策略组选择记录
          if (isActive && Array.isArray(item['selected'])) {
            for (const sel of item['selected'] as Array<Record<string, unknown>>) {
              if (
                sel &&
                typeof sel['name'] === 'string' &&
                typeof sel['now'] === 'string' &&
                sel['name'].trim() &&
                sel['now'].trim()
              ) {
                nextActiveSelections.push({
                  group: sel['name'].trim(),
                  now: sel['now'].trim(),
                });
              }
            }
          }

          const profileYamlPath = this.resolveProfileItemYamlPath(vergeDir, fileField, uid);
          if (!profileYamlPath) continue;

          const parsedNodes = this.readProfileNodesCached(profileYamlPath, vergeDir);
          if (!parsedNodes) continue;

          const rawMap = new Map<string, Record<string, unknown>>(parsedNodes.rawMap);
          const mergedNodeList: ClashProxyNodeOption[] = [...parsedNodes.nodes];

          // 合并该订阅关联的自定义节点增强配置 (option.proxies / option.merge)
          const optionObj =
            item['option'] && typeof item['option'] === 'object'
              ? (item['option'] as Record<string, unknown>)
              : null;
          if (optionObj) {
            for (const optKey of ['proxies', 'merge']) {
              const companionUid =
                typeof optionObj[optKey] === 'string' ? optionObj[optKey].trim() : '';
              if (!companionUid) continue;
              const companionItem = itemsByUid.get(companionUid);
              const companionFile = companionItem
                ? String(companionItem['file'] || '').trim()
                : `${companionUid}.yaml`;
              const companionPath = this.resolveProfileItemYamlPath(
                vergeDir,
                companionFile,
                companionUid
              );
              if (!companionPath) continue;
              const companionParsed = this.readProfileNodesCached(companionPath, vergeDir);
              if (!companionParsed) continue;
              for (const cn of companionParsed.nodes) {
                if (!rawMap.has(cn.name)) {
                  const rawObj = companionParsed.rawMap.get(cn.name);
                  if (rawObj) {
                    rawMap.set(cn.name, rawObj);
                    mergedNodeList.push(cn);
                  }
                }
              }
            }
          }

          if (mergedNodeList.length === 0 && !isActive) {
            continue;
          }

          const fallbackBaseName = fileField
            ? path.basename(fileField, path.extname(fileField))
            : uid;
          const baseName =
            String(item['name'] || item['desc'] || fallbackBaseName || uid).trim() || uid;
          const isDuplicateName = (baseNameCounts.get(baseName) || 0) > 1;
          const profileName = isDuplicateName
            ? `${baseName} (${uid.slice(0, 4)})`
            : baseName;

          const updatedAt =
            typeof item['updated'] === 'number' && item['updated'] > 0
              ? item['updated']
              : undefined;

          const nodes: ClashProxyNodeOption[] = mergedNodeList.map((n) => {
            const liveItem = isActive ? activeProxiesMap[n.name] : undefined;
            const delay = extractProxyDelay(liveItem);
            return {
              ...n,
              profileUid: uid,
              profileName,
              delay,
              alive: liveItem ? liveItem.alive !== false : true,
            };
          });

          const profData: ResolvedProfileData = {
            uid,
            name: profileName,
            type: rawType || 'remote',
            isActive,
            updatedAt,
            nodes,
            rawMap,
          };

          if (isActive && !activeProfileUid) {
            activeProfileUid = uid;
            activeProfileName = profileName;
          }

          resolvedProfiles.push(profData);
          nextLookup.set(uid, profData);
        }
      }
    }

    // 补充检查当前运行时 clash-verge.yaml（兼容通过 Merge/Script 动态追加的落地节点，或无 profiles.yaml 时的兜底）
    const activeRuntimeYaml = this.findActiveClashYamlFile();
    if (activeRuntimeYaml && fs.existsSync(activeRuntimeYaml)) {
      const runtimeDir = vergeDir || path.dirname(activeRuntimeYaml);
      const runtimeParsed = this.readProfileNodesCached(activeRuntimeYaml, runtimeDir);
      if (runtimeParsed && runtimeParsed.nodes.length > 0) {
        const activeProf = resolvedProfiles.find((p) => p.isActive);
        if (activeProf) {
          for (const rtNode of runtimeParsed.nodes) {
            if (!activeProf.rawMap.has(rtNode.name)) {
              const rawObj = runtimeParsed.rawMap.get(rtNode.name);
              if (rawObj) {
                activeProf.rawMap.set(rtNode.name, rawObj);
                const liveItem = activeProxiesMap[rtNode.name];
                activeProf.nodes.push({
                  ...rtNode,
                  profileUid: activeProf.uid,
                  profileName: activeProf.name,
                  delay: extractProxyDelay(liveItem),
                  alive: liveItem ? liveItem.alive !== false : true,
                });
              }
            }
          }
        } else if (resolvedProfiles.length === 0) {
          const fallbackUid = '__runtime_active__';
          const fallbackName = '当前激活订阅';
          const nodes = runtimeParsed.nodes.map((n) => {
            const liveItem = activeProxiesMap[n.name];
            return {
              ...n,
              profileUid: fallbackUid,
              profileName: fallbackName,
              delay: extractProxyDelay(liveItem),
              alive: liveItem ? liveItem.alive !== false : true,
            };
          });
          const fallbackProf: ResolvedProfileData = {
            uid: fallbackUid,
            name: fallbackName,
            type: 'runtime',
            isActive: true,
            nodes,
            rawMap: new Map(runtimeParsed.rawMap),
          };
          activeProfileUid = fallbackUid;
          activeProfileName = fallbackName;
          resolvedProfiles.push(fallbackProf);
          nextLookup.set(fallbackUid, fallbackProf);
        }
      }
    }

    // 如果连运行时 YAML 都没有解析到节点，但已连接 Mihomo API，则从 activeProxiesMap 兜底提取具体落地节点
    if (resolvedProfiles.length === 0 && Object.keys(activeProxiesMap).length > 0) {
      const apiNodes = extractConcreteNodesFromApi(activeProxiesMap);
      if (apiNodes.length > 0) {
        const fallbackUid = '__api_active__';
        const fallbackName = '当前 Clash 活动节点';
        const taggedNodes = apiNodes.map((n) => ({
          ...n,
          profileUid: fallbackUid,
          profileName: fallbackName,
        }));
        const fallbackProf: ResolvedProfileData = {
          uid: fallbackUid,
          name: fallbackName,
          type: 'runtime',
          isActive: true,
          nodes: taggedNodes,
          rawMap: new Map(),
        };
        activeProfileUid = fallbackUid;
        activeProfileName = fallbackName;
        resolvedProfiles.push(fallbackProf);
        nextLookup.set(fallbackUid, fallbackProf);
      }
    }

    // 若已绑定专属节点且 Mihomo 内核中存在注入的专属代理，同步其最新测速延迟到对应节点
    for (const slot of [this.slots.claude, this.slots.antigravity]) {
      const dedicatedLive = activeProxiesMap[slot.internalProxyName];
      const dedicatedDelay = extractProxyDelay(dedicatedLive);
      if (dedicatedDelay && slot.desiredNodeName) {
        for (const prof of resolvedProfiles) {
          if (!slot.desiredProfileUid || prof.uid === slot.desiredProfileUid) {
            for (const n of prof.nodes) {
              if (n.name === slot.desiredNodeName && !n.delay) {
                n.delay = dedicatedDelay;
              }
            }
          }
        }
      }
    }

    this.profileRawLookup = nextLookup;
    this.activeProfileSavedSelections = nextActiveSelections;

    const profileGroups: ClashProfileGroupOption[] = resolvedProfiles.map((p) => ({
      uid: p.uid,
      name: p.name,
      type: p.type,
      isActive: p.isActive,
      nodeCount: p.nodes.length,
      updatedAt: p.updatedAt,
      nodes: p.nodes,
    }));

    const availableNodes: ClashProxyNodeOption[] = [];
    for (const group of profileGroups) {
      for (const node of group.nodes) {
        availableNodes.push(node);
      }
    }

    return {
      activeProfileUid,
      activeProfileName,
      profileGroups,
      availableNodes,
    };
  }

  private findClashVergeConfigDir(): string | null {
    if (
      this.currentEndpoint?.yamlFile &&
      fs.existsSync(this.currentEndpoint.yamlFile)
    ) {
      const dir = path.dirname(this.currentEndpoint.yamlFile);
      if (fs.existsSync(path.join(dir, 'profiles.yaml'))) {
        return dir;
      }
    }

    const appData = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    const candidateDirs = [
      path.join(appData, 'io.github.clash-verge-rev.clash-verge-rev'),
      path.join(appData, 'clash-verge'),
      path.join(localAppData, 'io.github.clash-verge-rev.clash-verge-rev'),
    ];

    for (const dir of candidateDirs) {
      if (fs.existsSync(path.join(dir, 'profiles.yaml'))) {
        return dir;
      }
    }
    for (const dir of candidateDirs) {
      if (fs.existsSync(dir)) {
        return dir;
      }
    }
    return null;
  }

  private resolveProfileItemYamlPath(
    vergeDir: string,
    fileField: string,
    uid: string
  ): string | null {
    const candidates: string[] = [];
    if (fileField) {
      if (path.isAbsolute(fileField)) {
        candidates.push(fileField);
      } else {
        candidates.push(path.join(vergeDir, 'profiles', fileField));
        candidates.push(path.join(vergeDir, fileField));
      }
    }
    candidates.push(path.join(vergeDir, 'profiles', `${uid}.yaml`));
    candidates.push(path.join(vergeDir, 'profiles', `${uid}.yml`));

    for (const c of candidates) {
      if (fs.existsSync(c)) {
        return c;
      }
    }
    return null;
  }

  private readProfilesIndexCached(filePath: string): Record<string, unknown> | null {
    try {
      if (!fs.existsSync(filePath)) return null;
      const stat = fs.statSync(filePath);
      const cached = this.profilesIndexCache.get(filePath);
      if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
        return cached.parsed;
      }
      const raw = fs.readFileSync(filePath, 'utf-8');
      const loaded = yaml.load(raw);
      if (!loaded || typeof loaded !== 'object') return null;
      const parsed = loaded as Record<string, unknown>;
      this.profilesIndexCache.set(filePath, {
        mtimeMs: stat.mtimeMs,
        size: stat.size,
        parsed,
      });
      return parsed;
    } catch {
      return null;
    }
  }

  private readProfileNodesCached(
    filePath: string,
    vergeDir: string
  ): CachedProfileNodesEntry | null {
    try {
      if (!fs.existsSync(filePath)) return null;
      const stat = fs.statSync(filePath);
      const cached = this.profileNodesCache.get(filePath);
      if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
        return cached;
      }

      const rawYaml = fs.readFileSync(filePath, 'utf-8');
      const loaded = yaml.load(rawYaml);
      if (!loaded || typeof loaded !== 'object') return null;
      const doc = loaded as Record<string, unknown>;

      const nodes: ClashProxyNodeOption[] = [];
      const rawMap = new Map<string, Record<string, unknown>>();

      const addRawProxyList = (list: unknown) => {
        if (!Array.isArray(list)) return;
        for (const item of list) {
          if (!item || typeof item !== 'object') continue;
          const p = item as Record<string, unknown>;
          const name = typeof p['name'] === 'string' ? p['name'].trim() : '';
          const type = typeof p['type'] === 'string' ? p['type'].trim() : '';
          if (!name || !type) continue;
          if (name.startsWith(GUARD_INTERNAL_PROXY_PREFIX)) continue;
          if (EXCLUDED_NODE_NAMES.has(name.toUpperCase())) continue;
          if (GROUP_TYPES_LOWER.has(type.toLowerCase())) continue;
          if (rawMap.has(name)) continue;

          rawMap.set(name, structuredClone(p));
          nodes.push({
            name,
            type,
            isGroup: false,
            server: typeof p['server'] === 'string' ? p['server'] : undefined,
            port: typeof p['port'] === 'number' ? p['port'] : undefined,
            alive: true,
          });
        }
      };

      // 1. 直接提取 proxies 列表（兼容 prepend / append 扩展字段）
      addRawProxyList(doc['prepend']);
      addRawProxyList(doc['prepend-proxies']);
      addRawProxyList(doc['proxies']);
      addRawProxyList(doc['append']);
      addRawProxyList(doc['append-proxies']);

      // 2. 兼容使用 proxy-providers 的订阅配置（读取本地已缓存的 provider 节点文件）
      const providers = doc['proxy-providers'];
      if (providers && typeof providers === 'object' && !Array.isArray(providers)) {
        for (const provVal of Object.values(providers as Record<string, unknown>)) {
          if (!provVal || typeof provVal !== 'object') continue;
          const prov = provVal as Record<string, unknown>;
          if (Array.isArray(prov['payload'])) {
            addRawProxyList(prov['payload']);
          }
          const relPath = typeof prov['path'] === 'string' ? prov['path'].trim() : '';
          if (relPath) {
            const providerCandidates = [
              path.resolve(vergeDir, relPath),
              path.resolve(path.dirname(filePath), relPath),
              path.join(vergeDir, 'proxies', path.basename(relPath)),
              path.join(vergeDir, 'providers', path.basename(relPath)),
            ];
            for (const cand of providerCandidates) {
              if (fs.existsSync(cand)) {
                try {
                  const provRaw = fs.readFileSync(cand, 'utf-8');
                  const provDoc = yaml.load(provRaw) as Record<string, unknown> | null;
                  if (provDoc && typeof provDoc === 'object') {
                    addRawProxyList(provDoc['proxies']);
                    addRawProxyList(provDoc['payload']);
                  }
                } catch {
                  // ignore broken provider file
                }
                break;
              }
            }
          }
        }
      }

      const entry: CachedProfileNodesEntry = {
        mtimeMs: stat.mtimeMs,
        size: stat.size,
        nodes,
        rawMap,
      };
      this.profileNodesCache.set(filePath, entry);
      return entry;
    } catch {
      return null;
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
    for (const slot of [this.slots.claude, this.slots.antigravity]) {
      slot.boundNodeName = null;
      slot.boundInternalProxyName = null;
      slot.boundPort = null;
    }
    this.info = {
      connected: false,
      source: '未连接',
      mode: 'unknown',
      mixedPort: null,
      activeNode: null,
      activeProfileUid: this.info.activeProfileUid,
      activeProfileName: this.info.activeProfileName,
      nodeChain: [],
      availableNodes: this.info.availableNodes,
      profileGroups: this.info.profileGroups,
      boundNode: this.slots.claude.desiredNodeName,
      boundProfileUid: this.slots.claude.desiredProfileUid,
      boundProfileName: this.slots.claude.desiredProfileName,
      dedicatedPort: this.slots.claude.desiredNodeName ? this.slots.claude.desiredPort : null,
      dedicatedPortListening: false,
      antigravityBoundNode: this.slots.antigravity.desiredNodeName,
      antigravityBoundProfileUid: this.slots.antigravity.desiredProfileUid,
      antigravityBoundProfileName: this.slots.antigravity.desiredProfileName,
      antigravityDedicatedPort: this.slots.antigravity.desiredNodeName
        ? this.slots.antigravity.desiredPort
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

function extractDialerChain(
  leafProxy: Record<string, unknown>,
  rawMap: Map<string, Record<string, unknown>>
): Array<Record<string, unknown>> {
  const chain: Array<Record<string, unknown>> = [];
  const visited = new Set<string>();
  if (typeof leafProxy['name'] === 'string') {
    visited.add(leafProxy['name']);
  }

  let current = leafProxy;
  while (typeof current['dialer-proxy'] === 'string') {
    const nextName = current['dialer-proxy'].trim();
    if (!nextName || visited.has(nextName)) break;
    const nextRaw = rawMap.get(nextName);
    if (!nextRaw) break;
    visited.add(nextName);
    chain.push(structuredClone(nextRaw));
    current = nextRaw;
  }
  return chain;
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

function extractProxyDelay(item: ClashProxyItem | undefined): number | undefined {
  if (!item || !Array.isArray(item.history) || item.history.length === 0) {
    return undefined;
  }
  const lastHist = item.history[item.history.length - 1];
  return lastHist && typeof lastHist.delay === 'number' && lastHist.delay > 0
    ? lastHist.delay
    : undefined;
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

function extractConcreteNodesFromApi(
  proxies: Record<string, ClashProxyItem>
): ClashProxyNodeOption[] {
  const concreteNodes: ClashProxyNodeOption[] = [];
  const globalOrder = proxies['GLOBAL']?.all || Object.keys(proxies);
  const visited = new Set<string>();

  const processName = (name: string) => {
    if (
      !name ||
      visited.has(name) ||
      name.startsWith(GUARD_INTERNAL_PROXY_PREFIX) ||
      EXCLUDED_NODE_NAMES.has(name.toUpperCase())
    ) {
      return;
    }
    const item = proxies[name];
    if (!item || !item.type) return;
    if (
      EXCLUDED_NODE_NAMES.has(item.type.toUpperCase()) ||
      GROUP_TYPES.has(item.type) ||
      GROUP_TYPES_LOWER.has(item.type.toLowerCase())
    ) {
      return;
    }
    visited.add(name);

    concreteNodes.push({
      name: item.name,
      type: item.type,
      isGroup: false,
      delay: extractProxyDelay(item),
      alive: item.alive !== false,
    });
  };

  for (const name of globalOrder) {
    processName(name);
  }
  for (const name of Object.keys(proxies)) {
    processName(name);
  }

  return concreteNodes;
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

function buildProfilesSignature(groups: ClashProfileGroupOption[]): string {
  return groups
    .map((g) => `${g.uid}:${g.isActive ? 1 : 0}:${g.nodeCount}`)
    .join('|');
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
