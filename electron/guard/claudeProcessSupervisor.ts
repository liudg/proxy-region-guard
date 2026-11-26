import { setTimeout as sleep } from 'node:timers/promises';
import {
  AppConfig,
  AppStateSnapshot,
  ClaudeLaunchResult,
  ClaudeRuntimeState,
  ProbeResult,
} from '../../src/shared/types';
import { getCountryNameZh } from '../../src/shared/countries';
import { normalizeIpAddress } from '../../src/shared/probeValidation';
import {
  areAnyPidsAlive,
  assertProcessesStopped,
  CLAUDE_DESKTOP_PROCESS_PATTERNS,
  countRunningClaudeProcesses,
  detectClaudeInstallation,
  markClaudeLaunchedByGuard,
  ProcessKillReport,
  readWindowsLocaleState,
  spawnClaudeWithDedicatedProxy,
} from '../system';
import { GuardRuntimeContext } from './guardTypes';
import { PrivateChannelCoordinator } from './privateChannelCoordinator';

export interface ClaudeSessionSupervisorHost {
  readonly ctx: GuardRuntimeContext;
  readonly channels: PrivateChannelCoordinator;
  detectedExe: string | null;
  installType: ClaudeRuntimeState['installType'];
  running: boolean;
  processCount: number;
  runningPids: number[];
  authorizedSession: boolean;
  sessionInitialIp: string | null;
  fastCheckTicks: number;
  externalBaselinePending: boolean;
  externalBaselineMinSeq: number;
  seenRunningSinceAuth: boolean;
  launchGraceUntil: number;
  getNodeProbe(): ProbeResult | null;
  clearVerificationRecovery(): void;
  unsetAuthLock(): void;
  syncHeartbeatSchedule(): void;
  buildRuntimeState(): ClaudeRuntimeState;
  probeNodeNow(reason?: string, skipSafetyEnforcement?: boolean): Promise<AppStateSnapshot>;
  stopBeforeRoutingChange(forceTerminate?: boolean): Promise<ProcessKillReport>;
  ensureExternalBaselineProbe(cfg?: AppConfig): void;
  enforceRunningSafety(triggerContext: string): Promise<boolean>;
  migrateDeferredIpv4IfIdle(): Promise<void>;
}

export async function executeAuthorizedClaudeLaunch(
  host: ClaudeSessionSupervisorHost
): Promise<ClaudeLaunchResult> {
  const cfg = host.ctx.configStore.get();

  // 1. 确认 Claude Desktop 安装路径
  const install = await detectClaudeInstallation(cfg.claudeExePath);
  host.detectedExe = install.exePath;
  host.installType = install.installType;

  if (!install.exePath) {
    return {
      ok: false,
      message: '未检测到 Claude Desktop 安装路径',
      state: host.ctx.getSnapshot(),
    };
  }
  const killReport = await host.stopBeforeRoutingChange(true);

  // 2. 若已选择节点，确保专属端口绑定就绪
  if (cfg.selectedClashNode) {
    const bindRes = await host.channels.ensurePrivateChannelReadyForLaunch('claude');
    if (!bindRes.ok) {
      const msg = `启动被拦截：无法建立节点 [${cfg.selectedClashNode}] 的专属代理端口 (${
        bindRes.error || '端口未监听'
      })`;
      host.ctx.logs.add('danger', msg);
      host.ctx.emitState();
      return { ok: false, message: msg, state: host.ctx.getSnapshot() };
    }
  }

  // 3. 实时刷新读取本机最新 Windows 时区/区域，并对 Claude 选定节点发起一次独立真实出口探测
  host.ctx.setWinLocale(await readWindowsLocaleState());
  await host.probeNodeNow('Claude 启动前三重安全校验', true);

  // 4. 统一复用 buildRuntimeState 校验结果
  const prelaunchState = host.buildRuntimeState();
  const initialClaudeIp = normalizeIpAddress(host.getNodeProbe()?.claudeTraceIp);
  if (
    !prelaunchState.canLaunch ||
    !install.exePath ||
    !prelaunchState.proxyCountryCode ||
    !initialClaudeIp
  ) {
    const msg = `启动被拦截：${prelaunchState.launchBlockReason || '未获取到有效 Claude 出口 IP'}`;
    host.ctx.logs.add('danger', msg);
    host.ctx.emitState();
    return { ok: false, message: msg, state: host.ctx.getSnapshot() };
  }

  const proxyCountry = prelaunchState.proxyCountryCode;
  const proxyCountryName = prelaunchState.proxyCountryName || getCountryNameZh(proxyCountry);

  // 5. 授权前再次检查全部关联进程
  await assertProcessesStopped(CLAUDE_DESKTOP_PROCESS_PATTERNS, killReport);

  // 6. 授予唯一入口会话锁、锁定初始会话出口 IP 并注入专属代理参数拉起 Claude
  host.authorizedSession = true;
  host.sessionInitialIp = initialClaudeIp;
  host.externalBaselinePending = false;
  host.externalBaselineMinSeq = 0;
  host.seenRunningSinceAuth = false;
  host.launchGraceUntil = Date.now() + 12000;
  markClaudeLaunchedByGuard(cfg.dedicatedProxyPort);

  const dedicatedProxyUrl = `http://127.0.0.1:${cfg.dedicatedProxyPort}`;
  const spawnRes = await spawnClaudeWithDedicatedProxy(
    install.exePath,
    install.fallbackDirectPath,
    dedicatedProxyUrl
  );

  if (!spawnRes.ok) {
    host.unsetAuthLock();
    const errMsg = `拉起 Claude 进程失败：${spawnRes.error || '未知错误'}`;
    host.ctx.logs.add('danger', errMsg);
    host.ctx.emitState();
    return { ok: false, message: errMsg, state: host.ctx.getSnapshot() };
  }

  let afterProc = { running: false, count: 0, pids: [] as number[] };
  while (Date.now() < host.launchGraceUntil) {
    await sleep(250);
    afterProc = await countRunningClaudeProcesses(true);
    if (afterProc.running) break;
  }

  host.running = afterProc.running;
  host.processCount = afterProc.count;
  host.runningPids = afterProc.pids;
  host.fastCheckTicks = 0;
  if (!afterProc.running) {
    host.unsetAuthLock();
    const message = '启动 Claude 失败：未检测到主进程运行';
    host.ctx.logs.add('danger', message);
    host.ctx.emitState();
    return { ok: false, message, state: host.ctx.getSnapshot() };
  }
  host.seenRunningSinceAuth = true;
  host.syncHeartbeatSchedule();

  const fullNodeLabel = cfg.selectedClashProfileName
    ? `${cfg.selectedClashProfileName} / ${cfg.selectedClashNode}`
    : cfg.selectedClashNode;
  const ipLockTag = cfg.claudeLockExitIp
    ? `锁定出口 IP ${initialClaudeIp}`
    : `初始出口 IP ${initialClaudeIp}`;
  const ipv4Tag = cfg.claudeForceIpv4 ? ' · 仅IPv4' : '';
  const okMsg = `三重校验通过！已通过专属节点 [${fullNodeLabel}] (127.0.0.1:${cfg.dedicatedProxyPort}${ipv4Tag} · ${proxyCountryName} · ${ipLockTag}) 安全启动 Claude`;
  host.ctx.logs.add('success', okMsg);
  host.ctx.emitState();
  return {
    ok: true,
    message: okMsg,
    state: host.ctx.getSnapshot(),
  };
}

export async function runClaudeExclusiveWatchTick(
  host: ClaudeSessionSupervisorHost
): Promise<number> {
  if (host.ctx.isStopped()) return 2000;
  let nextDelay = 2000;

  if (host.ctx.killQueue.isBusy) {
    return nextDelay;
  }

  try {
    let proc: { running: boolean; count: number; pids: number[] };

    if (
      host.authorizedSession &&
      host.seenRunningSinceAuth &&
      host.runningPids.length > 0 &&
      host.fastCheckTicks < 4
    ) {
      host.fastCheckTicks++;
      const fast = areAnyPidsAlive(host.runningPids);
      if (fast.aliveCount > 0) {
        proc = {
          running: true,
          count: host.processCount,
          pids: fast.alivePids,
        };
      } else {
        host.fastCheckTicks = 0;
        proc = await countRunningClaudeProcesses();
      }
    } else {
      host.fastCheckTicks = 0;
      proc = await countRunningClaudeProcesses();
    }
    const prevRunning = host.running;
    const prevCount = host.processCount;
    host.running = proc.running;
    host.processCount = proc.count;
    host.runningPids = proc.pids;
    if (!proc.running) host.clearVerificationRecovery();

    if (proc.running) {
      if (host.authorizedSession) {
        host.seenRunningSinceAuth = true;
      }
    } else if (
      host.authorizedSession &&
      (host.seenRunningSinceAuth || Date.now() > host.launchGraceUntil)
    ) {
      // 用户已关闭 Claude，立即回收唯一入口会话授权锁，并连带清理残留的 cowork-svc.exe 等后台进程
      host.unsetAuthLock();
      await host.ctx.killQueue.executeSafely(CLAUDE_DESKTOP_PROCESS_PATTERNS);
      host.ctx.logs.add(
        'info',
        '检测到 Claude 已退出，已自动清理关联后台进程并回收启动授权锁（下次需从专栏启动）'
      );
      host.ctx.emitState();
      return 2000;
    } else if (
      !host.authorizedSession &&
      Date.now() > host.launchGraceUntil &&
      (host.sessionInitialIp !== null || host.externalBaselinePending)
    ) {
      host.sessionInitialIp = null;
      host.externalBaselinePending = false;
      host.externalBaselineMinSeq = 0;
      host.ctx.emitState();
    }

    const cfg = host.ctx.configStore.get();

    // 拦截 1：开启唯一启动入口拦截时，未通过卫士专栏授权启动的外部 Claude -> 立即无条件强杀！
    if (proc.running && !host.authorizedSession && cfg.claudeExclusiveGuard) {
      const report = await host.ctx.killQueue.executeSafely(
        CLAUDE_DESKTOP_PROCESS_PATTERNS
      );
      if (!host.running) {
        host.unsetAuthLock();
      }
      const reason =
        '拦截到从外部直接启动 Claude！本卫士【Claude 专栏】是唯一允许的启动入口';
      if (report.killedCount > 0) {
        host.ctx.logs.add(
          'danger',
          `${reason}，已立即强杀：${report.killedSummary.join(', ')}`
        );
      } else if (report.errorDetail) {
        host.ctx.logs.add('warn', `${reason}，但终止受阻：${report.errorDetail}`);
      }
      host.ctx.emitState();

      if (report.killedCount > 0 || report.errorDetail) {
        const nodeProbe = host.getNodeProbe();
        host.ctx.emitGuardAlert({
          source: 'claude',
          alertType: 'unauthorized-launch',
          expectedCode: nodeProbe?.countryCode || cfg.defaultCountryCode,
          expectedName: nodeProbe?.countryName || cfg.defaultCountryName,
          triggerReason: reason,
          killedProcesses: report.killedCount > 0 ? report.killedSummary : undefined,
          killError: report.errorDetail,
        });
      }
      return 1500;
    }

    // 若关闭了唯一入口拦截且检测到外部拉起的 Claude 尚未建立会话出口 IP 基线，立即发起实时重测
    host.ensureExternalBaselineProbe(cfg);

    // 运行期安全检查独立于唯一启动入口设置。
    if (proc.running) {
      const killedOrBlocked = await host.enforceRunningSafety('Claude 运行期实时监控');
      if (killedOrBlocked) {
        return 1500;
      }
    } else if (
      cfg.selectedClashNode &&
      host.ctx.privateProxies.channels.claude.getSnapshot() &&
      host.ctx.privateProxies.channels.claude.getIpv4Only() !== cfg.claudeForceIpv4 &&
      !host.ctx.hasActiveApplicationChanges()
    ) {
      void host.migrateDeferredIpv4IfIdle();
    }

    if (prevRunning !== host.running || prevCount !== host.processCount) {
      if (prevRunning !== host.running) {
        host.syncHeartbeatSchedule();
      }
      host.ctx.emitState();
    }

    if (host.running || Date.now() < host.launchGraceUntil) {
      nextDelay = 1200;
    } else if (cfg.claudeExclusiveGuard && host.installType !== 'not-found') {
      nextDelay = 2000;
    } else {
      nextDelay = 5000;
    }
  } catch {
    // ignore transient watcher error
  }

  return nextDelay;
}
