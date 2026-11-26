import * as net from 'node:net';
import { AppConfig, AppStateSnapshot, ProbeResult } from '../../src/shared/types';
import { isValidIsoCountryCode } from '../../src/shared/countries';
import {
  getTargetServiceVerificationError,
  isValidIpAddress,
  normalizeIpAddress,
} from '../../src/shared/probeValidation';
import { isWindowsLocaleMatchingCountry } from '../../src/shared/timezones';
import {
  BUILTIN_TRACE_ENDPOINTS,
  probeAndVerifyClaudeExitConsensus,
  selectProbeEndpointsForTransportHosts,
} from '../probe';
import { ClaudeSafetyCheck } from './alertBuilder';
import {
  ClaudePolicySnapshotInput,
  hasConfirmedClaudeProbeViolation,
  VerifiedRegionSnapshot,
} from './claudeSafetyPolicy';
import { GuardRuntimeContext, MAX_IN_FLIGHT_REBOUND_CONTINUES } from './guardTypes';
import { PrivateChannelCoordinator } from './privateChannelCoordinator';

export interface ClaudeProbeRunnerCallbacks {
  ctx: GuardRuntimeContext;
  channels: PrivateChannelCoordinator;
  isRunning: () => boolean;
  isAuthorizedSession: () => boolean;
  getSessionInitialIp: () => string | null;
  recordSessionBaselineIp: (ip: string, countryName: string, countryCode: string) => void;
  isExternalBaselinePending: () => boolean;
  getExternalBaselineMinSeq: () => number;
  getSwitchingCount: () => number;
  hasSafetyKillInFlight: () => boolean;
  isEffectiveForceIpv4: (cfg: AppConfig) => boolean;
  getPolicySnapshotInput: (cfg?: AppConfig) => ClaudePolicySnapshotInput;
  evaluateSafety: (requireDedicatedNode: boolean) => ClaudeSafetyCheck;
  clearVerificationFailureIfRecovered: () => boolean;
  recordVerificationFailure: (reason: string) => void;
  enforceRunningSafety: (triggerContext: string) => Promise<boolean>;
  clearHeartbeatTimer: () => void;
  syncHeartbeatSchedule: () => void;
}

export class ClaudeNodeProbeRunner {
  public isProbing = false;
  public activeProbeSkipSafety = false;
  public probePromise: Promise<AppStateSnapshot> | null = null;
  public probeSeq = 0;
  public pendingProbe: { reason: string; skipSafetyEnforcement: boolean } | null = null;
  public nodeProbe: ProbeResult | null = null;
  public nodeProbeError: string | null = null;
  public lastVerificationSuccessAt: number | null = null;
  public lastVerifiedRegion: VerifiedRegionSnapshot | null = null;
  public lastClaudeProbeCompletedAt = 0;
  public reboundDuringProbe = false;

  private probeAbortController: AbortController | null = null;

  constructor(private readonly cb: ClaudeProbeRunnerCallbacks) {}

  public abortActiveProbe(reason = 'Claude 探测已取消'): void {
    const controller = this.probeAbortController;
    if (controller && !controller.signal.aborted) {
      controller.abort(Object.assign(new Error(reason), { name: 'AbortError' }));
    }
  }

  public needsRecoveryProbe(): boolean {
    if (!this.nodeProbe || Boolean(this.nodeProbeError)) {
      return true;
    }
    return Boolean(getTargetServiceVerificationError(this.nodeProbe, 'claude'));
  }

  private isCurrentProbe(sequence: number, config: AppConfig): boolean {
    const current = this.cb.ctx.configStore.get();
    return (
      this.cb.getSwitchingCount() === 0 &&
      this.probeSeq === sequence &&
      current.selectedClashNode === config.selectedClashNode &&
      current.selectedClashProfileUid === config.selectedClashProfileUid &&
      current.dedicatedProxyPort === config.dedicatedProxyPort &&
      current.claudeForceIpv4 === config.claudeForceIpv4
    );
  }

  private async tryRecoverBindingAfterFailure(
    curCfg: AppConfig,
    seqAtStart: number,
    localProxyRefused: boolean,
    signal: AbortSignal
  ): Promise<boolean> {
    if (this.cb.ctx.isStopped() || signal.aborted || !this.isCurrentProbe(seqAtStart, curCfg)) {
      return false;
    }
    const kernel = this.cb.ctx.privateProxies.channels.claude;
    const kernelState = kernel.getState();
    const canAttemptPortRecovery =
      kernelState.phase === 'ready' ||
      (kernelState.phase === 'error' && kernelState.pid !== null);
    if (
      !canAttemptPortRecovery ||
      kernelState.nodeName !== curCfg.selectedClashNode ||
      kernelState.port !== curCfg.dedicatedProxyPort ||
      kernelState.profileUid !== curCfg.selectedClashProfileUid
    ) {
      return false;
    }

    if (!localProxyRefused) {
      const ready = await this.cb.channels.checkPrivateReady('claude', signal);
      if (ready.ok) return false;
      if (
        this.cb.ctx.isStopped() ||
        signal.aborted ||
        !this.isCurrentProbe(seqAtStart, curCfg)
      ) {
        return false;
      }
    }
    const outcome = await kernel.recoverListenerIfNeeded(signal);
    if (outcome === 'failed') {
      return false;
    }
    return (
      !this.cb.ctx.isStopped() &&
      !signal.aborted &&
      this.isCurrentProbe(seqAtStart, curCfg)
    );
  }

  public async probeNodeNow(
    reason = '检测 Claude 专属节点',
    skipSafetyEnforcement = false
  ): Promise<AppStateSnapshot> {
    const { ctx, channels } = this.cb;
    if (ctx.isStopped() || this.cb.getSwitchingCount() > 0) return ctx.getSnapshot();
    const cfg = ctx.configStore.get();
    if (!cfg.selectedClashNode) {
      this.probeSeq++;
      this.abortActiveProbe('未选择 Claude 节点');
      this.lastClaudeProbeCompletedAt = 0;
      this.pendingProbe = null;
      this.reboundDuringProbe = false;
      this.nodeProbe = null;
      this.nodeProbeError = null;
      this.cb.clearHeartbeatTimer();
      ctx.emitState();
      return ctx.getSnapshot();
    }

    if (this.probePromise) {
      if (!skipSafetyEnforcement) {
        this.activeProbeSkipSafety = false;
      }
      if (!reason.includes('心跳')) {
        this.pendingProbe = {
          reason,
          skipSafetyEnforcement:
            (this.pendingProbe?.skipSafetyEnforcement ?? true) && skipSafetyEnforcement,
        };
      } else if (!skipSafetyEnforcement && this.pendingProbe) {
        this.pendingProbe.skipSafetyEnforcement = false;
      }
      return this.probePromise;
    }

    let activeReason = reason;
    this.activeProbeSkipSafety = skipSafetyEnforcement;

    let p: Promise<AppStateSnapshot> | null = null;
    const runProbe = async (): Promise<AppStateSnapshot> => {
      try {
        this.isProbing = true;
        ctx.emitState();

        let claudeReboundContinueCount = 0;
        let retriedBinding = false;
        while (!ctx.isStopped()) {
          if (this.cb.getSwitchingCount() > 0) break;
          const seqAtStart = ++this.probeSeq;
          const curCfg = ctx.configStore.get();
          const targetNode = curCfg.selectedClashNode;
          if (!targetNode) {
            this.nodeProbe = null;
            this.nodeProbeError = null;
            break;
          }

          const tryContinueNextClaudeProbe = (includeSupersededNode: boolean): boolean => {
            if (ctx.isStopped()) return false;
            const latestSelectedNode = ctx.configStore.get().selectedClashNode;
            if (this.pendingProbe && latestSelectedNode) {
              const next = this.pendingProbe;
              this.pendingProbe = null;
              activeReason = next.reason;
              this.activeProbeSkipSafety =
                this.activeProbeSkipSafety && next.skipSafetyEnforcement;
              retriedBinding = false;
              claudeReboundContinueCount = 0;
              return true;
            }
            if (this.pendingProbe && !latestSelectedNode) {
              this.pendingProbe = null;
            }
            if (includeSupersededNode) {
              if (latestSelectedNode) {
                if (ctx.privateProxies.channels.claude.getState().phase !== 'ready') {
                  return false;
                }
                retriedBinding = false;
                claudeReboundContinueCount = 0;
                return true;
              }
              this.nodeProbe = null;
              this.nodeProbeError = null;
            }
            return false;
          };

          const settleIterationSafetyBeforeLoopControl = (): 'must-break' | 'ok' => {
            if (
              this.activeProbeSkipSafety ||
              !this.cb.isRunning() ||
              this.cb.hasSafetyKillInFlight() ||
              ctx.isStopped() ||
              !this.isCurrentProbe(seqAtStart, curCfg)
            ) {
              return 'ok';
            }
            const requireDedicated =
              this.cb.isAuthorizedSession() || ctx.configStore.get().claudeExclusiveGuard;
            const check = this.cb.evaluateSafety(requireDedicated);
            if (check.safe) {
              this.cb.clearVerificationFailureIfRecovered();
              return 'ok';
            }
            if (check.alertType === 'verification-unavailable') {
              this.cb.recordVerificationFailure(check.reason);
              return 'ok';
            }
            this.pendingProbe = null;
            return 'must-break';
          };

          const controller = new AbortController();
          this.probeAbortController = controller;
          let probeSuccess: ProbeResult | null = null;
          let lastErrMsg = '探测超时';
          let localProxyRefused = false;
          let effectiveProfileUid: string | null = null;
          let label = targetNode;
          let channelDesc = '';
          let bindFailed = false;
          let bindError: string | undefined;

          try {
            const bindRes = await channels.checkPrivateReady('claude', controller.signal);
            if (ctx.isStopped() || controller.signal.aborted) {
              if (tryContinueNextClaudeProbe(!this.isCurrentProbe(seqAtStart, curCfg))) {
                continue;
              }
              break;
            }
            if (!bindRes.ok) {
              if (
                !retriedBinding &&
                (await this.tryRecoverBindingAfterFailure(
                  curCfg,
                  seqAtStart,
                  true,
                  controller.signal
                ))
              ) {
                retriedBinding = true;
                continue;
              }
              if (ctx.isStopped() || controller.signal.aborted) {
                if (tryContinueNextClaudeProbe(!this.isCurrentProbe(seqAtStart, curCfg))) {
                  continue;
                }
                break;
              }
              bindFailed = true;
              bindError =
                ctx.privateProxies.channels.claude.getState().error || bindRes.error;
            } else {
              if (!this.isCurrentProbe(seqAtStart, curCfg)) {
                if (tryContinueNextClaudeProbe(true)) continue;
                break;
              }

              this.reboundDuringProbe = false;
              effectiveProfileUid = curCfg.selectedClashProfileUid;
              label = curCfg.selectedClashProfileName
                ? `${curCfg.selectedClashProfileName} / ${targetNode}`
                : targetNode;
              const proxyUrl = `http://127.0.0.1:${curCfg.dedicatedProxyPort}`;
              channelDesc = `Claude 专属节点 [${label}] (127.0.0.1:${curCfg.dedicatedProxyPort}${
                ctx.privateProxies.channels.claude.getIpv4Only() ? ' · 仅IPv4' : ''
              })`;

              const activeEndpoints = selectProbeEndpointsForTransportHosts(
                BUILTIN_TRACE_ENDPOINTS,
                ctx.privateProxies.channels.claude.getBoundTransportHosts()
              );
              const consensus = await probeAndVerifyClaudeExitConsensus({
                proxyUrl,
                viaChannel: channelDesc,
                endpoints: activeEndpoints,
                geoIp: ctx.geoIp,
                getSession: () => {
                  const latestCfg = ctx.configStore.get();
                  return {
                    hasSessionBaseline:
                      this.cb.isRunning() ||
                      this.cb.isAuthorizedSession() ||
                      this.cb.getSessionInitialIp() !== null,
                    claudeExternalBaselinePending: this.cb.isExternalBaselinePending(),
                    claudeLockExitIp: latestCfg.claudeLockExitIp,
                    effectiveForceIpv4: this.cb.isEffectiveForceIpv4(latestCfg),
                    sessionInitialIp: this.cb.getSessionInitialIp(),
                    winLocale: ctx.getWinLocale(),
                  };
                },
                signal: controller.signal,
              });
              if (ctx.isStopped() || controller.signal.aborted) {
                if (tryContinueNextClaudeProbe(!this.isCurrentProbe(seqAtStart, curCfg))) {
                  continue;
                }
                break;
              }
              probeSuccess = consensus.result;
              lastErrMsg = consensus.errMsg;
              localProxyRefused = consensus.localProxyRefused;

              const hasConfirmedViolationEarly = hasConfirmedClaudeProbeViolation(
                probeSuccess,
                this.cb.getPolicySnapshotInput(curCfg)
              );
              if (
                !hasConfirmedViolationEarly &&
                !retriedBinding &&
                (!probeSuccess || probeSuccess.claudeTraceError || localProxyRefused) &&
                (await this.tryRecoverBindingAfterFailure(
                  curCfg,
                  seqAtStart,
                  localProxyRefused,
                  controller.signal
                ))
              ) {
                retriedBinding = true;
                continue;
              }
              if (ctx.isStopped() || controller.signal.aborted) {
                if (tryContinueNextClaudeProbe(!this.isCurrentProbe(seqAtStart, curCfg))) {
                  continue;
                }
                break;
              }
            }
          } finally {
            if (this.probeAbortController === controller) {
              this.probeAbortController = null;
            }
            controller.abort();
          }

          if (ctx.isStopped()) break;

          if (bindFailed) {
            if (!this.isCurrentProbe(seqAtStart, curCfg)) {
              if (tryContinueNextClaudeProbe(true)) continue;
              break;
            }
            this.lastClaudeProbeCompletedAt = Date.now();
            this.nodeProbe = null;
            this.nodeProbeError =
              bindError || `Claude 专属端口 127.0.0.1:${curCfg.dedicatedProxyPort} 未就绪`;
            if (settleIterationSafetyBeforeLoopControl() === 'must-break') {
              break;
            }
            if (tryContinueNextClaudeProbe(false)) continue;
            break;
          }

          const hasConfirmedViolation = hasConfirmedClaudeProbeViolation(
            probeSuccess,
            this.cb.getPolicySnapshotInput(curCfg)
          );
          const isHeartbeat = activeReason.includes('心跳');
          const isSilentPoll = isHeartbeat || activeReason.includes('后台复核');

          if (!this.isCurrentProbe(seqAtStart, curCfg)) {
            if (tryContinueNextClaudeProbe(true)) continue;
            break;
          }

          if (
            !hasConfirmedViolation &&
            this.reboundDuringProbe &&
            claudeReboundContinueCount < MAX_IN_FLIGHT_REBOUND_CONTINUES &&
            (!probeSuccess ||
              !isValidIsoCountryCode(probeSuccess.claudeTraceLoc) ||
              !isValidIpAddress(probeSuccess.claudeTraceIp) ||
              Boolean(probeSuccess.claudeTraceError))
          ) {
            claudeReboundContinueCount++;
            if (
              claudeReboundContinueCount >= 2 &&
              !this.activeProbeSkipSafety &&
              this.cb.isRunning() &&
              !this.cb.hasSafetyKillInFlight() &&
              !ctx.isStopped() &&
              this.isCurrentProbe(seqAtStart, curCfg)
            ) {
              const reboundErrDetail = probeSuccess
                ? getTargetServiceVerificationError(probeSuccess, 'claude') ||
                  '目标服务校验未完成'
                : lastErrMsg;
              this.cb.recordVerificationFailure(`${channelDesc}：${reboundErrDetail}`);
            }
            activeReason = 'Claude 专属代理端口恢复重测';
            continue;
          }

          this.lastClaudeProbeCompletedAt = Date.now();
          const runningNow = this.cb.isRunning();
          if (probeSuccess) {
            const prevIp =
              normalizeIpAddress(this.nodeProbe?.claudeTraceIp) || this.nodeProbe?.ip;
            const prevCountry = this.nodeProbe?.countryCode;
            const previousVerificationError = getTargetServiceVerificationError(
              this.nodeProbe,
              'claude'
            );
            const verificationError = getTargetServiceVerificationError(probeSuccess, 'claude');
            const normalizedTraceIp = normalizeIpAddress(probeSuccess.claudeTraceIp);
            if (normalizedTraceIp) {
              probeSuccess.claudeTraceIp = normalizedTraceIp;
            }
            this.nodeProbe = probeSuccess;
            this.nodeProbeError = null;
            if (!verificationError) {
              ctx.privateProxies.channels.claude.clearForwardingError();
            }
            const unexpectedIpv6Violation = Boolean(
              this.cb.isEffectiveForceIpv4(curCfg) &&
                normalizedTraceIp &&
                net.isIPv6(normalizedTraceIp)
            );
            const winLocale = ctx.getWinLocale();
            if (
              !verificationError &&
              !unexpectedIpv6Violation &&
              !ctx.privateProxies.channels.claude.getState().verificationError
            ) {
              this.lastVerificationSuccessAt =
                probeSuccess.claudeTraceCheckedAt || probeSuccess.checkedAt;
              this.lastVerifiedRegion = {
                node: targetNode,
                profileUid: effectiveProfileUid,
                port: curCfg.dedicatedProxyPort,
                countryCode: probeSuccess.countryCode,
                countryName: probeSuccess.countryName,
              };
              const canRecordSessionBaseline = this.cb.isAuthorizedSession()
                ? true
                : !curCfg.claudeExclusiveGuard &&
                  this.cb.isExternalBaselinePending() &&
                  seqAtStart >= this.cb.getExternalBaselineMinSeq();
              if (
                runningNow &&
                this.cb.getSessionInitialIp() === null &&
                canRecordSessionBaseline &&
                normalizedTraceIp &&
                isWindowsLocaleMatchingCountry(
                  winLocale.timeZoneId,
                  winLocale.regionCode,
                  probeSuccess.countryCode
                )
              ) {
                this.cb.recordSessionBaselineIp(
                  normalizedTraceIp,
                  probeSuccess.countryName,
                  probeSuccess.countryCode
                );
              }
            }

            const normalizedLockedIp = normalizeIpAddress(this.cb.getSessionInitialIp());
            const effectiveTraceIp = normalizedTraceIp || probeSuccess.ip;
            const willTriggerIpDriftKill = Boolean(
              !this.activeProbeSkipSafety &&
                runningNow &&
                (unexpectedIpv6Violation ||
                  (!this.cb.isExternalBaselinePending() &&
                    curCfg.claudeLockExitIp &&
                    normalizedLockedIp &&
                    normalizedTraceIp &&
                    normalizedTraceIp !== normalizedLockedIp))
            );

            if (verificationError) {
              if (
                !runningNow &&
                (previousVerificationError !== verificationError || !isSilentPoll)
              ) {
                ctx.logs.add(
                  'danger',
                  `Claude 目标服务地区校验未通过 [${label}]：${verificationError}`
                );
              }
            } else if (
              !willTriggerIpDriftKill &&
              (prevIp !== effectiveTraceIp ||
                prevCountry !== probeSuccess.countryCode ||
                !isSilentPoll)
            ) {
              const verifiedTag = probeSuccess.claudeTraceLoc ? ' · 目标服务地区校验通过' : '';
              const splitExitTag =
                probeSuccess.claudeTraceIp && probeSuccess.claudeTraceIp !== probeSuccess.ip
                  ? ` (常规回显: ${probeSuccess.ip})`
                  : '';
              ctx.logs.add(
                'info',
                `Claude 节点检测 [${label}]：${probeSuccess.countryName} (${probeSuccess.countryCode})${verifiedTag} · Claude 出口 IP: ${effectiveTraceIp}${splitExitTag} (${probeSuccess.latencyMs}ms)`
              );
            }
          } else {
            this.nodeProbe = null;
            this.nodeProbeError = `${channelDesc}：${lastErrMsg}`;
            if (!runningNow) {
              ctx.logs.add('warn', `Claude 节点检测失败：${this.nodeProbeError}`);
            }
          }

          if (settleIterationSafetyBeforeLoopControl() === 'must-break') {
            break;
          }

          if (tryContinueNextClaudeProbe(false)) continue;
          break;
        }
      } finally {
        this.isProbing = false;
        if (this.probePromise === p) {
          this.probePromise = null;
        }
        ctx.emitState();
      }

      if (!this.activeProbeSkipSafety && this.cb.isRunning()) {
        await this.cb.enforceRunningSafety(activeReason);
      }
      this.cb.syncHeartbeatSchedule();

      return ctx.getSnapshot();
    };

    p = runProbe();
    this.probePromise = p;
    return p;
  }
}
