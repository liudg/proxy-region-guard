import React from 'react';
import {
  AlertTriangle,
  Ban,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  FolderOpen,
  Lock,
  Play,
  Radio,
  RefreshCw,
  ShieldCheck,
  Square,
  XCircle,
} from 'lucide-react';
import { AppConfig, AppStateSnapshot } from '../../shared/types';
import { getCountryNameZh } from '../../shared/countries';
import { ClashNodeSelector } from '../ClashNodeSelector';
import { CountryFlag } from '../CountryFlag';
import { PrivateKernelStatus } from '../PrivateKernelStatus';
import { FeedbackMessage, formatTime, PendingClaudeConfirm } from './dashboardTypes';

export interface ClaudeLauncherPaneProps {
  state: AppStateSnapshot;
  clashHeaderBadgeText: string;
  isSwitchingNode: boolean;
  isLaunchingClaude: boolean;
  claudeVerificationError: string | null;
  claudeFallbackDetectedCode: string | null;
  claudeFeedback: FeedbackMessage | null;
  pendingClaudeConfirm: PendingClaudeConfirm;
  isClaudeSettingsExpanded: boolean;
  installTypeLabel: string;
  dedicatedPortInput: string;
  onState: (next: AppStateSnapshot) => void;
  onSelectNode: (node: string | null, profileUid: string | null) => void;
  onProbeNode: () => void;
  onSyncLocaleFromClaude: () => void;
  onConfirmClaudeAction: () => void;
  onCancelClaudeConfirm: () => void;
  onLaunchClaude: () => void;
  onTerminateClaude: () => void;
  onToggleSettings: () => void;
  onUpdateClaudeConfig: (partial: Partial<AppConfig>) => void;
  onToggleForceIpv4: (enabled: boolean) => void;
  onChangeDedicatedPortInput: (val: string) => void;
  onSaveDedicatedPort: () => void;
  onClearExePath: () => void;
  onBrowseExePath: () => void;
}

export const ClaudeLauncherPane: React.FC<ClaudeLauncherPaneProps> = ({
  state,
  clashHeaderBadgeText,
  isSwitchingNode,
  isLaunchingClaude,
  claudeVerificationError,
  claudeFallbackDetectedCode,
  claudeFeedback,
  pendingClaudeConfirm,
  isClaudeSettingsExpanded,
  installTypeLabel,
  dedicatedPortInput,
  onState,
  onSelectNode,
  onProbeNode,
  onSyncLocaleFromClaude,
  onConfirmClaudeAction,
  onCancelClaudeConfirm,
  onLaunchClaude,
  onTerminateClaude,
  onToggleSettings,
  onUpdateClaudeConfig,
  onToggleForceIpv4,
  onChangeDedicatedPortInput,
  onSaveDedicatedPort,
  onClearExePath,
  onBrowseExePath,
}) => {
  const { config, winLocale, isSyncingLocale, clashInfo, claudeState } = state;

  return (
    <>
      {/* 1. Clash Verge Rev 全订阅组专属节点选择卡片 */}
      <section className="panel-card">
        <div className="panel-card-header">
          <div className="panel-title">
            <Radio
              size={15}
              className={
                state.privateChannels.claude.phase === 'ready' ? 'pulse-green' : ''
              }
            />
            <span>1. Claude 私有代理节点</span>
          </div>
          <span
            className={`mini-badge ${
              clashInfo.availableNodes.length ? 'connected' : 'warn-badge'
            }`}
          >
            {clashHeaderBadgeText}
          </span>
        </div>

        <ClashNodeSelector
          appLabel="Claude"
          clashInfo={clashInfo}
          selectedNode={config.selectedClashNode}
          selectedProfileUid={config.selectedClashProfileUid}
          selectedProfileName={config.selectedClashProfileName}
          boundProfileUid={state.privateChannels.claude.profileUid}
          boundProfileName={state.privateChannels.claude.profileName}
          dedicatedPort={config.dedicatedProxyPort}
          portListening={state.privateChannels.claude.phase === 'ready'}
          isSwitching={isSwitchingNode}
          onSelectNode={onSelectNode}
        />
        <PrivateKernelStatus
          channel="claude"
          state={state.privateChannels.claude}
          onState={onState}
        />
        {clashInfo.catalogErrors.map((error) => (
          <p className="private-kernel-error" key={error}>
            订阅读取失败：{error}
          </p>
        ))}
      </section>

      {/* 2. Claude 唯一启动入口 & 三重一致性校验主控卡 */}
      <section
        className={`hero-card claude-hero-card ${
          claudeState.verificationFailure
            ? 'status-checking'
            : claudeState.running || claudeState.canLaunch
            ? 'status-ok'
            : claudeState.isProbingNode &&
              !claudeState.nodeProbe &&
              !claudeState.nodeProbeError
            ? 'status-checking'
            : 'status-mismatch'
        }`}
      >
        <div className="hero-top-row">
          <div
            className={`status-pill ${
              claudeState.verificationFailure
                ? 'status-checking'
                : claudeState.running || claudeState.canLaunch
                ? 'status-ok'
                : claudeState.isProbingNode &&
                  !claudeState.nodeProbe &&
                  !claudeState.nodeProbeError
                ? 'status-checking'
                : 'status-mismatch'
            }`}
          >
            {claudeState.verificationFailure ? (
              <>
                <Clock size={17} />
                <span>地区校验中断 · 后台复核中</span>
              </>
            ) : claudeState.running ? (
              <>
                <ShieldCheck size={17} />
                <span>Claude 受控运行中 ({claudeState.processCount} 个进程)</span>
              </>
            ) : claudeState.canLaunch ? (
              <>
                <CheckCircle2 size={17} />
                <span>三重校验一致 · 允许启动 Claude</span>
              </>
            ) : claudeState.isProbingNode &&
              !claudeState.nodeProbe &&
              !claudeState.nodeProbeError ? (
              <>
                <RefreshCw className="spin" size={17} />
                <span>正在校验节点与环境...</span>
              </>
            ) : (
              <>
                <Lock size={17} />
                <span>未通过校验 · 禁止启动 Claude</span>
              </>
            )}
          </div>

          <button
            className="btn-refresh"
            disabled={claudeState.isProbingNode || isSwitchingNode}
            onClick={onProbeNode}
          >
            <RefreshCw
              className={claudeState.isProbingNode ? 'spin' : ''}
              size={14}
            />
            <span>{claudeState.isProbingNode ? '校验中...' : '重新校验'}</span>
          </button>
        </div>

        {claudeState.verificationFailure && (
          <div className="claude-verification-notice">
            <Clock size={15} className="verification-notice-icon" />
            <div className="verification-notice-body">
              <strong className="verification-notice-reason">
                {claudeState.verificationFailure.reason}
              </strong>
              <p>
                {formatTime(claudeState.verificationFailure.startedAt)} 起异常 ·{' '}
                每隔 5 秒后台复核，恢复后自动清除提示
              </p>
              <small>
                {claudeState.lockedSessionIp
                  ? `🔒 ${claudeState.lockedSessionIp} · `
                  : ''}
                上次通过：
                {claudeState.lastVerificationSuccessAt
                  ? formatTime(claudeState.lastVerificationSuccessAt)
                  : '无'}
              </small>
            </div>
          </div>
        )}

        {/* 三重一致性对比矩阵：指定代理出口 vs 系统区域 vs 系统时区 */}
        <div className="three-way-check-grid">
          <div
            className={`check-step-card ${
              claudeState.proxyCountryCode &&
              config.selectedClashNode &&
              !claudeVerificationError
                ? 'matched'
                : 'unmatched'
            }`}
          >
            <div className="check-step-header">
              <span className="step-num">1. 指定代理出口</span>
              {claudeState.proxyCountryCode &&
              config.selectedClashNode &&
              !claudeVerificationError ? (
                <CheckCircle2 size={14} className="step-icon-ok" />
              ) : (
                <XCircle size={14} className="step-icon-err" />
              )}
            </div>
            <div className="check-step-body">
              {claudeState.proxyCountryCode && claudeState.nodeProbe ? (
                <>
                  <div className="step-main-line">
                    <CountryFlag code={claudeState.proxyCountryCode} size="sm" />
                    <strong>
                      {claudeState.proxyCountryName} ({claudeState.proxyCountryCode})
                    </strong>
                  </div>
                  {claudeState.nodeProbe.regionMismatchDetail ? (
                    <small
                      className="ellipsis text-danger"
                      title={claudeState.nodeProbe.regionMismatchDetail}
                    >
                      ⚠️ Claude 识别: {claudeState.nodeProbe.claudeTraceLoc}
                    </small>
                  ) : claudeVerificationError ? (
                    <small
                      className="ellipsis text-danger"
                      title={claudeVerificationError}
                    >
                      {claudeVerificationError}
                    </small>
                  ) : claudeState.running && claudeState.lockedSessionIp ? (
                    <small
                      className="ellipsis"
                      title={`锁定出口 IP: ${claudeState.lockedSessionIp}${
                        claudeState.nodeProbe.claudeTraceIp &&
                        claudeState.nodeProbe.claudeTraceIp !==
                          claudeState.nodeProbe.ip
                          ? ` · 常规 IP: ${claudeState.nodeProbe.ip}`
                          : ''
                      } (${claudeState.nodeProbe.latencyMs}ms)`}
                    >
                      🔒 {claudeState.lockedSessionIp} ·{' '}
                      {claudeState.nodeProbe.latencyMs}ms
                    </small>
                  ) : (
                    <small
                      className="ellipsis"
                      title={`Claude 出口 IP: ${
                        claudeState.nodeProbe.claudeTraceIp ||
                        claudeState.nodeProbe.ip
                      }${
                        claudeState.nodeProbe.claudeTraceIp &&
                        claudeState.nodeProbe.claudeTraceIp !==
                          claudeState.nodeProbe.ip
                          ? ` · 常规 IP: ${claudeState.nodeProbe.ip} (同国分流)`
                          : ''
                      } (${claudeState.nodeProbe.latencyMs}ms)`}
                    >
                      {claudeState.nodeProbe.claudeTraceIp ||
                        claudeState.nodeProbe.ip}
                      {claudeState.nodeProbe.claudeTraceIp &&
                      claudeState.nodeProbe.claudeTraceIp !== claudeState.nodeProbe.ip
                        ? ' (分流)'
                        : ''}{' '}
                      · {claudeState.nodeProbe.latencyMs}ms
                    </small>
                  )}
                </>
              ) : claudeState.nodeProbe ? (
                <>
                  <div className="step-main-line">
                    {claudeFallbackDetectedCode && (
                      <CountryFlag code={claudeFallbackDetectedCode} size="sm" />
                    )}
                    <strong
                      className="ellipsis"
                      title={
                        claudeState.nodeProbe.claudeTraceIp
                          ? `Claude 出口 IP: ${claudeState.nodeProbe.claudeTraceIp}${
                              claudeFallbackDetectedCode
                                ? ` · ${getCountryNameZh(claudeFallbackDetectedCode)} (${claudeFallbackDetectedCode})`
                                : ''
                            } (${claudeState.nodeProbe.latencyMs}ms)`
                          : `Claude 出口未知${
                              claudeFallbackDetectedCode
                                ? ` · ${getCountryNameZh(claudeFallbackDetectedCode)} (${claudeFallbackDetectedCode})`
                                : ''
                            }${
                              claudeState.nodeProbe.ip
                                ? ` · 常规回显 IP: ${claudeState.nodeProbe.ip}`
                                : ''
                            } (${claudeState.nodeProbe.latencyMs}ms)`
                      }
                    >
                      {claudeState.nodeProbe.claudeTraceIp
                        ? claudeFallbackDetectedCode
                          ? `Claude ${getCountryNameZh(claudeFallbackDetectedCode)} (${claudeFallbackDetectedCode}) · ${claudeState.nodeProbe.claudeTraceIp}`
                          : `Claude 出口 ${claudeState.nodeProbe.claudeTraceIp}`
                        : claudeFallbackDetectedCode
                        ? `Claude ${getCountryNameZh(claudeFallbackDetectedCode)} (${claudeFallbackDetectedCode}) · 出口未知`
                        : 'Claude 出口未知'}
                    </strong>
                  </div>
                  <small
                    className="ellipsis text-danger"
                    title={claudeVerificationError || undefined}
                  >
                    {claudeVerificationError}
                  </small>
                </>
              ) : (
                <>
                  <strong className="text-warn">
                    {!config.selectedClashNode
                      ? '未选节点'
                      : claudeState.isProbingNode
                      ? '探测中...'
                      : '节点未连通'}
                  </strong>
                  <small
                    className="ellipsis"
                    title={claudeState.nodeProbeError || undefined}
                  >
                    {config.selectedClashNode
                      ? claudeState.nodeProbeError || '请检查连通性'
                      : '请先选择节点'}
                  </small>
                </>
              )}
            </div>
          </div>

          <div
            className={`check-step-card ${
              claudeState.winRegionMatched ? 'matched' : 'unmatched'
            }`}
          >
            <div className="check-step-header">
              <span className="step-num">2. 系统国家/区域</span>
              {claudeState.winRegionMatched ? (
                <CheckCircle2 size={14} className="step-icon-ok" />
              ) : (
                <XCircle size={14} className="step-icon-err" />
              )}
            </div>
            <div className="check-step-body">
              <div className="step-main-line">
                <CountryFlag code={winLocale.regionCode} size="sm" />
                <strong>
                  {winLocale.regionName} ({winLocale.regionCode})
                </strong>
              </div>
              <small>
                {claudeState.winRegionMatched ? '与代理一致' : '与代理不符'}
              </small>
            </div>
          </div>

          <div
            className={`check-step-card ${
              claudeState.winTimeZoneMatched ? 'matched' : 'unmatched'
            }`}
          >
            <div className="check-step-header">
              <span className="step-num">3. 系统时区</span>
              {claudeState.winTimeZoneMatched ? (
                <CheckCircle2 size={14} className="step-icon-ok" />
              ) : (
                <XCircle size={14} className="step-icon-err" />
              )}
            </div>
            <div className="check-step-body">
              <strong className="ellipsis" title={winLocale.timeZoneDisplayName}>
                {winLocale.timeZoneDisplayName}
              </strong>
              <small>
                {claudeState.winTimeZoneMatched ? '与代理一致' : '与代理不符'}
              </small>
            </div>
          </div>
        </div>

        {/* 校验未通过原因提示 */}
        {claudeState.launchBlockReason && (
          <div className="claude-block-banner">
            <div className="block-banner-text">
              <AlertTriangle size={15} />
              <span>{claudeState.launchBlockReason}</span>
            </div>
            {claudeState.proxyCountryCode &&
              !claudeVerificationError &&
              (!claudeState.winRegionMatched || !claudeState.winTimeZoneMatched) && (
                <button
                  className="btn-banner-quick-sync"
                  disabled={isSyncingLocale}
                  onClick={onSyncLocaleFromClaude}
                >
                  <RefreshCw
                    className={isSyncingLocale ? 'spin' : ''}
                    size={13}
                  />
                  <span>
                    {isSyncingLocale
                      ? '正在同步...'
                      : `一键同步至 [${claudeState.proxyCountryName}]`}
                  </span>
                </button>
              )}
          </div>
        )}

        {/* 运行中切换节点 / 修改端口 / 强杀二次确认栏 */}
        {pendingClaudeConfirm && (
          <div className="inline-confirm-bar">
            <div className="confirm-bar-text">
              <AlertTriangle size={15} />
              <span>
                {pendingClaudeConfirm.type === 'switch-node'
                  ? `切换至 [${
                      pendingClaudeConfirm.nodeName || '未绑定'
                    }] 将先终止 Claude，新节点校验通过后可重启。`
                  : pendingClaudeConfirm.type === 'change-port'
                  ? `修改端口为 ${pendingClaudeConfirm.port} 将先终止当前 Claude。`
                  : pendingClaudeConfirm.type === 'toggle-ipv4'
                  ? `${
                      pendingClaudeConfirm.enabled
                        ? '开启强制仅走 IPv4 出站'
                        : '关闭强制仅走 IPv4 出站'
                    }将先终止当前 Claude 并重建专属通道。`
                  : '确定立即终止全部 Claude 进程？'}
              </span>
            </div>
            <div className="confirm-bar-actions">
              <button
                type="button"
                className="btn-confirm-danger"
                disabled={isSwitchingNode}
                onClick={onConfirmClaudeAction}
              >
                {pendingClaudeConfirm.type === 'switch-node'
                  ? '确认切换'
                  : pendingClaudeConfirm.type === 'change-port'
                  ? '确认修改'
                  : pendingClaudeConfirm.type === 'toggle-ipv4'
                  ? '确认生效'
                  : '确认终止'}
              </button>
              <button
                type="button"
                className="btn-confirm-cancel"
                onClick={onCancelClaudeConfirm}
              >
                取消
              </button>
            </div>
          </div>
        )}

        {/* 唯一启动入口主按钮与强杀按钮 */}
        <div className="claude-launch-actions">
          <button
            className={`btn-launch-claude ${
              claudeState.canLaunch ? 'ready' : 'disabled'
            }`}
            disabled={
              !claudeState.canLaunch || isLaunchingClaude || isSwitchingNode
            }
            onClick={onLaunchClaude}
          >
            {isLaunchingClaude ? (
              <>
                <RefreshCw className="spin" size={16} />
                <span>正在校验并启动 Claude...</span>
              </>
            ) : (
              <>
                <Play size={16} />
                <span>
                  {claudeState.running
                    ? '重新唤起 Claude Desktop'
                    : '安全启动 Claude Desktop'}
                </span>
              </>
            )}
          </button>

          {claudeState.running && (
            <button
              className="btn-kill-claude"
              onClick={onTerminateClaude}
              title="立即终止全部 Claude 进程"
            >
              <Square size={14} />
              <span>终止 Claude</span>
            </button>
          )}
        </div>

        {claudeState.nodeProbe && (
          <div className="hero-footer-meta">
            <span className="ellipsis" title={claudeState.nodeProbe.viaChannel}>
              专属通道：127.0.0.1:{config.dedicatedProxyPort}
              {config.selectedClashNode ? ` · ${config.selectedClashNode}` : ''}
            </span>
            <span>{formatTime(claudeState.nodeProbe.checkedAt)} 更新</span>
          </div>
        )}

        {claudeFeedback && (
          <div className={`locale-feedback ${claudeFeedback.ok ? 'ok' : 'err'}`}>
            {claudeFeedback.ok ? <Check size={14} /> : <AlertTriangle size={14} />}
            <span>{claudeFeedback.text}</span>
          </div>
        )}
      </section>

      {/* 3. 启动保护与客户端设置（默认折叠） */}
      <section
        className={`panel-card collapsible-card ${
          isClaudeSettingsExpanded ? 'expanded' : 'collapsed'
        }`}
      >
        <div
          className="panel-card-header collapsible-header"
          role="button"
          tabIndex={0}
          onClick={onToggleSettings}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onToggleSettings();
            }
          }}
        >
          <div className="panel-title">
            <Ban size={15} />
            <span>启动保护与客户端设置</span>
          </div>
          <div className="collapsible-header-right">
            <span className="mini-badge neutral">
              {config.claudeExclusiveGuard ? '唯一入口' : '允许外启'} ·{' '}
              {config.claudeLockExitIp ? '锁IP' : '不锁IP'} ·{' '}
              {config.claudeForceIpv4 ? '仅IPv4' : '双栈'} · 127.0.0.1:
              {config.dedicatedProxyPort} · {installTypeLabel}
            </span>
            <span className="collapse-chevron">
              {isClaudeSettingsExpanded ? (
                <ChevronUp size={15} />
              ) : (
                <ChevronDown size={15} />
              )}
            </span>
          </div>
        </div>

        {isClaudeSettingsExpanded && (
          <div className="collapsible-body">
            <div className="setting-row">
              <div>
                <strong>仅允许从本面板启动 Claude</strong>
                <p>拦截外部直接启动，防止绕过环境校验</p>
              </div>
              <input
                type="checkbox"
                className="toggle-switch"
                checked={config.claudeExclusiveGuard}
                onChange={(e) =>
                  onUpdateClaudeConfig({ claudeExclusiveGuard: e.target.checked })
                }
              />
            </div>

            <div className="setting-row">
              <div>
                <strong>锁定会话出口 IP</strong>
                <p>运行期出口 IP 变动立即强杀；动态住宅代理可关闭</p>
              </div>
              <input
                type="checkbox"
                className="toggle-switch"
                checked={config.claudeLockExitIp}
                onChange={(e) =>
                  onUpdateClaudeConfig({ claudeLockExitIp: e.target.checked })
                }
              />
            </div>

            <div className="setting-row">
              <div>
                <strong>强制通道仅走 IPv4 出站</strong>
                <p>
                  经代理内 DoH 锁定 IPv4 并拦截 IPv6，防止双栈节点切栈误杀与风控；纯 IPv6 出口节点可关闭
                </p>
              </div>
              <input
                type="checkbox"
                className="toggle-switch"
                disabled={isSwitchingNode}
                checked={config.claudeForceIpv4}
                onChange={(e) => onToggleForceIpv4(e.target.checked)}
              />
            </div>

            <div className="setting-row">
              <div>
                <strong>Claude 保护终止提醒</strong>
                <p>IP、地区或时区异常立即终止进程并弹窗；校验中断时持续后台复核</p>
              </div>
              <span className="mini-badge connected" style={{ flexShrink: 0 }}>
                始终开启
              </span>
            </div>

            <div className="claude-exe-path-box">
              <div className="exe-path-header">
                <span>专属监听端口：</span>
              </div>
              <div className="exe-path-row">
                <code className="exe-path-code">127.0.0.1 :</code>
                <input
                  type="number"
                  className="dedicated-port-input"
                  min={1024}
                  max={65535}
                  value={dedicatedPortInput}
                  onChange={(e) => onChangeDedicatedPortInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') onSaveDedicatedPort();
                  }}
                />
                <button
                  className="btn-save-inline"
                  disabled={isSwitchingNode}
                  onClick={onSaveDedicatedPort}
                >
                  <span>保存端口</span>
                </button>
              </div>
            </div>

            <div className="claude-exe-path-box">
              <div className="exe-path-header">
                <span>客户端路径：</span>
                {config.claudeExePath && (
                  <button className="btn-link-clear" onClick={onClearExePath}>
                    恢复自动探测
                  </button>
                )}
              </div>
              <div className="exe-path-row">
                <code
                  className="exe-path-code ellipsis"
                  title={claudeState.detectedExePath || '未检测到 Claude.exe'}
                >
                  {claudeState.detectedExePath || '未检测到客户端，请点击右侧选择'}
                </code>
                <button className="btn-save-inline" onClick={onBrowseExePath}>
                  <FolderOpen size={13} />
                  <span>浏览...</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </section>
    </>
  );
};
