import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';
import { ClashRuntimeInfo } from '../../src/shared/types';
import { MihomoEndpoint, mihomoRequest } from './mihomoClient';
import { SubscriptionCatalog } from './subscriptionCatalog';

/**
 * 严格只读的外部 Clash Verge 状态与订阅监控器：
 * 仅通过只读文件解析订阅快照，并经 GET 请求读取运行模式、混合端口、TUN 状态与选中节点链，
 * 绝不向外部 Clash 文件或控制接口发起任何写操作。
 */
export class ClashMonitor extends EventEmitter {
  public readonly catalog: SubscriptionCatalog;
  private timer: NodeJS.Timeout | null = null;
  private polling: Promise<void> | null = null;
  private stopped = true;
  private previousTun: boolean | null = null;
  private info: ClashRuntimeInfo = {
    connected: false,
    error: null,
    tunEnabled: null,
    catalogErrors: [],
    source: 'Clash Verge',
    mode: 'unknown',
    mixedPort: null,
    activeNode: null,
    activeProfileUid: null,
    activeProfileName: null,
    nodeChain: [],
    availableNodes: [],
    profileGroups: [],
  };

  constructor(directory?: string | null) {
    super();
    this.catalog = new SubscriptionCatalog(directory);
  }

  public getRuntimeInfo(): ClashRuntimeInfo {
    return structuredClone(this.info);
  }

  public start(): void {
    this.stopped = false;
    void this.refresh();
  }

  public stop(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  public refresh(): Promise<void> {
    if (this.polling) return this.polling;
    if (this.timer) clearTimeout(this.timer);
    this.polling = this.poll().finally(() => {
      this.polling = null;
      if (!this.stopped) {
        this.timer = setTimeout(() => void this.refresh(), 3000);
      }
    });
    return this.polling;
  }

  public readEndpoint(): MihomoEndpoint {
    if (!this.catalog.directory) throw new Error('未找到 Clash Verge 配置目录');
    const file = path.join(this.catalog.directory, 'clash-verge.yaml');
    // 控制密码保持 YAML 标量文本，包含前导零的密码也必须完整保留。
    const document = yaml.load(fs.readFileSync(file, 'utf8'), {
      schema: yaml.FAILSAFE_SCHEMA,
    }) as Record<string, unknown>;
    if (!document || typeof document !== 'object') throw new Error('Clash Verge 运行配置无效');
    const secret = String(document.secret || '');
    const pipe = document['external-controller-pipe'];
    if (typeof pipe === 'string' && pipe) return { pipePath: pipe, secret };
    const address = document['external-controller'];
    if (typeof address !== 'string' || !address) throw new Error('Clash Verge 未启用本地控制接口');
    const url = new URL(`http://${address}`);
    if (!['127.0.0.1', 'localhost', '[::1]', '0.0.0.0', '[::]'].includes(url.hostname)) {
      throw new Error('Clash Verge 控制接口必须位于本机');
    }
    return { host: url.hostname === '[::1]' ? '::1' : '127.0.0.1', port: Number(url.port), secret };
  }

  private async poll(): Promise<void> {
    const previous = JSON.stringify([
      this.info.connected,
      this.info.mode,
      this.info.activeNode,
      this.info.activeProfileUid,
    ]);
    try {
      this.catalog.refresh();
      this.info.catalogErrors = [...this.catalog.errors];
    } catch (error) {
      this.info.catalogErrors = [error instanceof Error ? error.message : String(error)];
      this.catalog.errors = [...this.info.catalogErrors];
    }
    this.info.profileGroups = structuredClone(this.catalog.groups);
    this.info.availableNodes = this.info.profileGroups.flatMap((group) => group.nodes);
    const active = this.info.profileGroups.find((group) => group.isActive);
    this.info.activeProfileUid = active?.uid || null;
    this.info.activeProfileName = active?.name || null;
    try {
      const endpoint = this.readEndpoint();
      const [config, response] = await Promise.all([
        mihomoRequest<Record<string, unknown>>(endpoint, '/configs'),
        mihomoRequest<{ proxies: Record<string, { now?: string; type: string }> }>(
          endpoint,
          '/proxies'
        ),
      ]);
      this.info.connected = true;
      this.info.error = null;
      this.info.mode = String(config.mode);
      this.info.mixedPort = Number(config['mixed-port'] || config.port) || null;
      const tun = config.tun as { enable?: unknown } | undefined;
      this.info.tunEnabled = typeof tun?.enable === 'boolean' ? tun.enable : null;
      const chain: string[] = [];
      let next =
        this.info.mode === 'global'
          ? 'GLOBAL'
          : Object.keys(response.proxies).find(
              (key) => key !== 'GLOBAL' && response.proxies[key].now
            );
      while (next && !chain.includes(next)) {
        chain.push(next);
        next = response.proxies[next]?.now;
      }
      this.info.nodeChain = chain;
      this.info.activeNode = chain.at(-1) || null;
      if (this.info.tunEnabled === true && this.previousTun !== true) this.emit('tun-enabled');
      if (this.info.tunEnabled !== null) this.previousTun = this.info.tunEnabled;
    } catch (error) {
      this.info.connected = false;
      this.info.error = error instanceof Error ? error.message : String(error);
      this.info.tunEnabled = null;
      this.info.mixedPort = null;
      this.info.activeNode = null;
      this.info.nodeChain = [];
      this.info.mode = 'unknown';
    }
    this.emit('catalog-updated');
    this.emit('clash-status-updated');
    if (
      previous !==
      JSON.stringify([
        this.info.connected,
        this.info.mode,
        this.info.activeNode,
        this.info.activeProfileUid,
      ])
    ) {
      this.emit('clash-change', 'Clash Verge 运行状态变化');
    }
  }
}
