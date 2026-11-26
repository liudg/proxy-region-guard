import { LocaleSyncResult } from '../../src/shared/types';
import { getCountryNameZh, isValidIsoCountryCode } from '../../src/shared/countries';
import { getTargetServiceVerificationError } from '../../src/shared/probeValidation';
import {
  DEFAULT_CHINA_REGION_CODE,
  DEFAULT_CHINA_TIMEZONE_ID,
  hasOfflineTimeZoneMapping,
  isMultiTimeZoneCountry,
  isWindowsLocaleMatchingCountry,
  resolveWindowsTimeZoneForCountry,
} from '../../src/shared/timezones';
import {
  applyWindowsTimeZoneAndRegion,
  assertProcessesStopped,
  CLAUDE_DESKTOP_PROCESS_PATTERNS,
  ProcessKillReport,
  queryExactExitIanaTimeZone,
  readWindowsLocaleState,
} from '../system';
import { ClaudeGuardController } from './claudeGuardController';
import { GuardRuntimeContext } from './guardTypes';
import { RealtimeMonitorController } from './realtimeMonitorController';

export class LocaleSyncController {
  constructor(
    private readonly ctx: GuardRuntimeContext,
    private readonly claude: ClaudeGuardController,
    private readonly monitor: RealtimeMonitorController
  ) {}

  private async runLocaleChange(
    operation: () => Promise<Omit<LocaleSyncResult, 'state'>>
  ): Promise<LocaleSyncResult> {
    this.ctx.setSyncingLocale(true);
    this.ctx.emitState();
    let result: Omit<LocaleSyncResult, 'state'>;
    try {
      result = await operation();
    } finally {
      this.ctx.setSyncingLocale(false);
      this.ctx.emitState();
    }
    return { ...result, state: this.ctx.getSnapshot() };
  }

  public resolveLocaleSyncTarget(
    targetSource: 'monitor' | 'claude' = 'monitor'
  ): { ok: true; targetCode: string; claudeCode: string | null } | { ok: false; message: string } {
    const cfg = this.ctx.configStore.get();
    const claudeCode = this.claude.getVerifiedProbeCountryCode();
    const lastProbe = this.monitor.getLastProbe();
    const monitorProbeCode =
      lastProbe && isValidIsoCountryCode(lastProbe.countryCode)
        ? lastProbe.countryCode.toUpperCase()
        : null;
    const defCode =
      cfg.defaultCountryCode && isValidIsoCountryCode(cfg.defaultCountryCode)
        ? cfg.defaultCountryCode.toUpperCase()
        : null;

    const targetCode =
      targetSource === 'claude' ? claudeCode : defCode || monitorProbeCode || claudeCode;

    const claudeProbe = this.claude.getNodeProbe();
    if (!targetCode) {
      const claudeVerifyError =
        targetSource === 'claude' && claudeProbe
          ? getTargetServiceVerificationError(claudeProbe, 'claude')
          : null;
      return {
        ok: false,
        message:
          targetSource === 'claude'
            ? claudeVerifyError
              ? `Claude 节点地区校验未通过，无法同步系统时区与区域：${claudeVerifyError}`
              : '请先在 Claude 专栏选择 Clash 节点并等待检测出有效出口地区'
            : '请先等待检测出有效出口地区，或先设置默认保护地区',
      };
    }

    if (!hasOfflineTimeZoneMapping(targetCode)) {
      return {
        ok: false,
        message: `尚未收录国家 ${targetCode} 的 Windows 时区映射，无法安全同步`,
      };
    }

    return { ok: true, targetCode, claudeCode };
  }

  private async stopProcessesBeforeLocaleChange(
    targetCode: string,
    targetTimeZone: string
  ): Promise<ProcessKillReport> {
    const cfg = this.ctx.configStore.get();
    const stopClaude = this.claude.shouldStopBeforeLocaleChange(targetCode, targetTimeZone);
    const stopProtected =
      cfg.killProcessesEnabled &&
      cfg.killOnLocaleMismatch &&
      !isWindowsLocaleMatchingCountry(
        targetTimeZone,
        targetCode,
        this.monitor.getEffectiveTargetCountryCode()
      );
    const patterns = [
      ...new Set([
        ...(stopClaude ? CLAUDE_DESKTOP_PROCESS_PATTERNS : []),
        ...(stopProtected ? cfg.protectedProcessPatterns : []),
      ]),
    ];
    if (stopClaude) this.claude.clearVerificationRecovery();
    const report = await this.ctx.killQueue.executeSafely(patterns);
    await assertProcessesStopped(patterns, report);
    if (stopClaude) this.claude.unsetAuthLock();
    if (report.killedCount > 0) {
      this.ctx.logs.add(
        'info',
        `修改系统时区与区域前已终止关联进程：${report.killedSummary.join(', ')}`
      );
    }
    return report;
  }

  /**
   * 根据目标通道（Claude 专栏选定节点 或 实时监控通道/默认保护地区）一键同步 Windows 时区与区域
   */
  public async syncSystemLocaleToDefault(
    targetSource: 'monitor' | 'claude' = 'monitor'
  ): Promise<LocaleSyncResult> {
    return this.ctx.runApplicationChange(() =>
      this.runLocaleChange(() => this.syncSystemLocaleInternal(targetSource))
    );
  }

  private async syncSystemLocaleInternal(
    targetSource: 'monitor' | 'claude'
  ): Promise<Omit<LocaleSyncResult, 'state'>> {
    const cfg = this.ctx.configStore.get();
    const resolvedTarget = this.resolveLocaleSyncTarget(targetSource);
    if (!resolvedTarget.ok) {
      return {
        ok: false,
        message: resolvedTarget.message,
        killedProcesses: [],
      };
    }
    const { targetCode, claudeCode } = resolvedTarget;
    const killedProcesses: string[] = [];

    let exactIanaTz: string | null = null;
    const needsCityTzLookup =
      isMultiTimeZoneCountry(targetCode) || !hasOfflineTimeZoneMapping(targetCode);
    const claudeProbe = this.claude.getNodeProbe();
    const lastProbe = this.monitor.getLastProbe();

    if (needsCityTzLookup) {
      if (targetSource === 'claude' && claudeProbe && claudeCode === targetCode) {
        const claudeProxyUrl = `http://127.0.0.1:${cfg.dedicatedProxyPort}`;
        const claudeLookupIp =
          claudeProbe.claudeTraceIp && !claudeProbe.claudeTraceIp.includes(':')
            ? claudeProbe.claudeTraceIp
            : claudeProbe.ip;
        exactIanaTz = await queryExactExitIanaTimeZone(
          claudeProxyUrl,
          targetCode,
          claudeLookupIp
        );
      } else if (lastProbe && lastProbe.countryCode.toUpperCase() === targetCode) {
        const ch = await this.monitor.resolveProxyChannel();
        const freshProbe = this.monitor.getLastProbe();
        if (
          !ch.errorHint &&
          freshProbe &&
          freshProbe.countryCode.toUpperCase() === targetCode
        ) {
          exactIanaTz = await queryExactExitIanaTimeZone(
            ch.proxyUrl,
            targetCode,
            freshProbe.ip
          );
        }
      } else if (claudeProbe && claudeCode === targetCode) {
        const claudeProxyUrl = `http://127.0.0.1:${cfg.dedicatedProxyPort}`;
        const claudeLookupIp =
          claudeProbe.claudeTraceIp && !claudeProbe.claudeTraceIp.includes(':')
            ? claudeProbe.claudeTraceIp
            : claudeProbe.ip;
        exactIanaTz = await queryExactExitIanaTimeZone(
          claudeProxyUrl,
          targetCode,
          claudeLookupIp
        );
      }
    }

    const resolved = resolveWindowsTimeZoneForCountry(targetCode, exactIanaTz);
    const currentLocale = await readWindowsLocaleState();
    if (
      currentLocale.regionCode !== targetCode ||
      currentLocale.timeZoneId !== resolved.windowsTimeZoneId
    ) {
      const report = await this.stopProcessesBeforeLocaleChange(
        targetCode,
        resolved.windowsTimeZoneId
      );
      killedProcesses.push(...report.killedSummary);
    }
    const applyRes = await applyWindowsTimeZoneAndRegion(
      resolved.windowsTimeZoneId,
      targetCode
    );
    this.ctx.setWinLocale(applyRes.updated);

    if (!applyRes.ok) {
      const errMsg = applyRes.error || '修改系统时区或区域失败';
      this.ctx.logs.add('warn', `一键同步时区/区域失败：${errMsg}`);
      return {
        ok: false,
        message: errMsg,
        killedProcesses,
      };
    }

    this.monitor.resetGuardFailSignature();
    this.monitor.evaluateStatusOnly('完成一键同步系统时区与区域');

    const detailNote =
      resolved.fromExactIp && exactIanaTz ? `（精确匹配城市时区 ${exactIanaTz}）` : '';
    const okMsg = `已同步 Windows 区域为 [${applyRes.updated.regionName}]，时区为 [${applyRes.updated.timeZoneDisplayName}]${detailNote}`;
    this.ctx.logs.add('success', okMsg);

    return {
      ok: true,
      message: okMsg,
      killedProcesses,
    };
  }

  /**
   * 还原回默认中国时区与区域（UTC+08:00 北京时间 + 区域“中国”）
   * 若与当前 Claude 节点出口或实时监控地区不一致，严格执行“先强杀 Claude 及受保护进程并确认全部退出后，才允许切换回中国时区”
   */
  public async restoreDefaultChinaLocale(): Promise<LocaleSyncResult> {
    return this.ctx.runApplicationChange(() =>
      this.runLocaleChange(() => this.restoreDefaultChinaLocaleInternal())
    );
  }

  private async restoreDefaultChinaLocaleInternal(): Promise<Omit<LocaleSyncResult, 'state'>> {
    const cfg = this.ctx.configStore.get();
    const killedProcesses: string[] = [];

    const claudeProbe = this.claude.getNodeProbe();
    const lastProbe = this.monitor.getLastProbe();

    const claudeCountry =
      claudeProbe?.countryCode && claudeProbe.countryCode !== 'UNKNOWN'
        ? claudeProbe.countryCode.toUpperCase()
        : null;
    const ipCountry =
      lastProbe?.countryCode && lastProbe.countryCode !== 'UNKNOWN'
        ? lastProbe.countryCode.toUpperCase()
        : null;
    const defCountry = cfg.defaultCountryCode ? cfg.defaultCountryCode.toUpperCase() : null;

    const wasClaudeRunning = this.claude.running;
    const claudeNeedsKill =
      wasClaudeRunning ||
      (claudeCountry !== null && claudeCountry !== DEFAULT_CHINA_REGION_CODE);
    const guardNeedsKill =
      cfg.killProcessesEnabled &&
      cfg.protectedProcessPatterns.length > 0 &&
      ((ipCountry !== null && ipCountry !== DEFAULT_CHINA_REGION_CODE) ||
        (defCountry !== null && defCountry !== DEFAULT_CHINA_REGION_CODE));

    const emitRestoreLocaleAlert = (triggerReason: string, killError?: string) => {
      const involvesClaude =
        wasClaudeRunning ||
        !guardNeedsKill ||
        killedProcesses.some((s) => /claude|cowork/i.test(s));
      const alertSource: 'claude' | 'monitor' =
        claudeNeedsKill && involvesClaude ? 'claude' : 'monitor';
      const expectedCode =
        alertSource === 'claude'
          ? claudeCountry || ipCountry || defCountry || DEFAULT_CHINA_REGION_CODE
          : ipCountry || defCountry || claudeCountry || DEFAULT_CHINA_REGION_CODE;
      const expectedName =
        (alertSource === 'claude' && claudeCountry
          ? claudeProbe?.countryName
          : ipCountry
          ? lastProbe?.countryName
          : defCountry
          ? cfg.defaultCountryName
          : null) || getCountryNameZh(expectedCode);

      this.ctx.emitGuardAlert({
        source: alertSource,
        alertType: 'locale-mismatch',
        expectedCode,
        expectedName,
        triggerReason,
        killedProcesses: killedProcesses.length > 0 ? killedProcesses : undefined,
        killError,
      });
    };

    const combinedPatterns = Array.from(
      new Set([
        ...(claudeNeedsKill ? CLAUDE_DESKTOP_PROCESS_PATTERNS : []),
        ...(guardNeedsKill ? cfg.protectedProcessPatterns : []),
      ])
    );

    if (combinedPatterns.length > 0) {
      this.claude.clearVerificationRecovery();

      const killReport = await this.ctx.killQueue.executeSafely(combinedPatterns);
      if (!this.claude.running) {
        this.claude.unsetAuthLock();
      }

      if (killReport.killedCount > 0) {
        killedProcesses.push(...killReport.killedSummary);
        this.ctx.logs.add(
          'danger',
          `还原中国时区前检测到代理地区非中国，已先行强杀进程：${killReport.killedSummary.join(', ')}`
        );
      }

      if (killReport.failedPids.length > 0) {
        const abortMsg = `${
          killReport.errorDetail || '部分受保护进程无法终止'
        }，已中止还原中国时区以防暴露！`;
        this.ctx.logs.add('danger', abortMsg);

        emitRestoreLocaleAlert(
          '还原中国时区被安全拦截（受保护进程未能终止）',
          killReport.errorDetail
        );

        return {
          ok: false,
          message: abortMsg,
          killedProcesses,
        };
      }

      await assertProcessesStopped(combinedPatterns, killReport);
      if (claudeNeedsKill) {
        this.claude.unsetAuthLock();
      }
    }

    const applyRes = await applyWindowsTimeZoneAndRegion(
      DEFAULT_CHINA_TIMEZONE_ID,
      DEFAULT_CHINA_REGION_CODE
    );
    this.ctx.setWinLocale(applyRes.updated);

    if (!applyRes.ok) {
      const errMsg = applyRes.error || '还原默认时区失败';
      this.ctx.logs.add('warn', `还原默认时区/区域失败：${errMsg}`);
      return {
        ok: false,
        message: errMsg,
        killedProcesses,
      };
    }

    // 若本次还原已先行强杀进程，预先对齐实时监控的 4 段式告警签名，防止 evaluateStatusOnly 异步触发普通时区不一致弹窗覆盖强杀结果
    const latestProbeAfterApply = this.monitor.getLastProbe();
    if (
      killedProcesses.length > 0 &&
      cfg.monitorAlertEnabled &&
      latestProbeAfterApply &&
      isValidIsoCountryCode(latestProbeAfterApply.countryCode)
    ) {
      const probeCode = latestProbeAfterApply.countryCode.toUpperCase();
      this.monitor.setLastAlertSignature(
        `locale-mismatch:${probeCode}:${applyRes.updated.regionCode}:${applyRes.updated.timeZoneId}`
      );
    }

    this.monitor.evaluateStatusOnly('还原默认中国时区');

    const killedSuffix =
      killedProcesses.length > 0 ? `（已先行终止：${killedProcesses.join(', ')}）` : '';
    const okMsg = `已还原为默认时区 [${applyRes.updated.timeZoneDisplayName}] · 区域 [${applyRes.updated.regionName}]${killedSuffix}`;
    this.ctx.logs.add('info', okMsg);

    if (killedProcesses.length > 0) {
      emitRestoreLocaleAlert('手动还原中国时区（与代理地区不一致，已先行强杀进程）');
    }

    return {
      ok: true,
      message: okMsg,
      killedProcesses,
    };
  }
}
