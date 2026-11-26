import React from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  Cpu,
  FolderOpen,
  Info,
  Play,
  Radio,
  RefreshCw,
  Rocket,
  Square,
} from 'lucide-react';
import { AppStateSnapshot } from '../../shared/types';
import { ClashNodeSelector } from '../ClashNodeSelector';
import { CountryFlag } from '../CountryFlag';
import { PrivateKernelStatus } from '../PrivateKernelStatus';
import { FeedbackMessage, PendingAgConfirm } from './dashboardTypes';

export interface AntigravityLauncherPaneProps {
  state: AppStateSnapshot;
  clashHeaderBadgeText: string;
  isSwitchingAgNode: boolean;
  isLaunchingAg: boolean;
  copiedAgIp: boolean;
  agFeedback: FeedbackMessage | null;
  pendingAgConfirm: PendingAgConfirm;
  isAgSettingsExpanded: boolean;
  agInstallTypeLabel: string;
  agDedicatedPortInput: string;
  onState: (next: AppStateSnapshot) => void;
  onSelectNode: (node: string | null, profileUid: string | null) => void;
  onProbeNode: () => void;
  onCopyIp: () => void;
  onLaunch: () => void;
  onTerminate: () => void;
  onConfirmAction: () => void;
  onCancelConfirm: () => void;
  onToggleSettings: () => void;
  onChangeDedicatedPortInput: (val: string) => void;
  onSaveDedicatedPort: () => void;
  onClearExePath: () => void;
  onBrowseExePath: () => void;
}

export const AntigravityLauncherPane: React.FC<AntigravityLauncherPaneProps> = ({
  state,
  clashHeaderBadgeText,
  isSwitchingAgNode,
  isLaunchingAg,
  copiedAgIp,
  agFeedback,
  pendingAgConfirm,
  isAgSettingsExpanded,
  agInstallTypeLabel,
  agDedicatedPortInput,
  onState,
  onSelectNode,
  onProbeNode,
  onCopyIp,
  onLaunch,
  onTerminate,
  onConfirmAction,
  onCancelConfirm,
  onToggleSettings,
  onChangeDedicatedPortInput,
  onSaveDedicatedPort,
  onClearExePath,
  onBrowseExePath,
}) => {
  const { config, clashInfo, antigravityState } = state;

  return (
    <>
      {/* 1. Antigravity 专属 Clash 节点选择卡 */}
      <section className="panel-card">
        <div className="panel-card-header">
          <div className="panel-title">
            <Radio
              size={15}
              className={
                state.privateChannels.antigravity.phase === 'ready' ? 'pulse-green' : ''
              }
            />
            <span>1. Antigravity 私有代理节点</span>
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
          appLabel="Antigravity"
          clashInfo={clashInfo}
          selectedNode={config.antigravityClashNode}
          selectedProfileUid={config.antigravityClashProfileUid}
          selectedProfileName={config.antigravityClashProfileName}
          boundProfileUid={state.privateChannels.antigravity.profileUid}
          boundProfileName={state.privateChannels.antigravity.profileName}
          dedicatedPort={config.antigravityDedicatedPort}
          portListening={state.privateChannels.antigravity.phase === 'ready'}
          isSwitching={isSwitchingAgNode}
          onSelectNode={onSelectNode}
        />
        <PrivateKernelStatus
          channel="antigravity"
          state={state.privateChannels.antigravity}
          onState={onState}
        />
        {clashInfo.catalogErrors.map((error) => (
          <p className="private-kernel-error" key={error}>
            订阅读取失败：{error}
          </p>
        ))}
      </section>

      {/* 2. Antigravity 纯代理启动主控卡 */}
      <section
        className={`hero-card ag-hero-card ${
          antigravityState.running && antigravityState.proxiedSession
            ? 'status-ok'
            : antigravityState.canLaunch
            ? 'status-checking'
            : ''
        }`}
      >
        <div className="hero-top-row">
          <div
            className={`status-pill ${
              antigravityState.running && antigravityState.proxiedSession
                ? 'status-ok'
                : antigravityState.running
                ? 'status-error'
                : antigravityState.canLaunch
                ? 'status-checking'
                : 'status-unset'
            }`}
          >
            {antigravityState.running && antigravityState.proxiedSession ? (
              <>
                <CheckCircle2 size={17} />
                <span>
                  Antigravity 代理运行中 ({antigravityState.totalProcessCount} 个进程)
                </span>
              </>
            ) : antigravityState.running ? (
              <>
                <Info size={17} />
                <span>
                  Antigravity 外部运行中 ({antigravityState.totalProcessCount} 个进程)
                </span>
              </>
            ) : antigravityState.canLaunch ? (
              <>
                <Rocket size={17} />
                <span>专属代理已就绪 · 可启动 Antigravity</span>
              </>
            ) : (
              <>
                <Radio size={17} />
                <span>待配置 Antigravity 启动代理节点</span>
              </>
            )}
          </div>

          <button
            className="btn-refresh"
            disabled={
              !config.antigravityClashNode ||
              antigravityState.isProbingNode ||
              isSwitchingAgNode
            }
            onClick={onProbeNode}
            title="仅测试所选节点的出口 IP 与国家，不触发任何报警或拦截"
          >
            <RefreshCw
              className={antigravityState.isProbingNode ? 'spin' : ''}
              size={14}
            />
            <span>
              {antigravityState.isProbingNode ? '测速中...' : '刷新节点出口'}
            </span>
          </button>
        </div>

        {/* 所选节点出口信息展示（纯展示，无任何监控/时区拦截） */}
        <div
          className={`ag-node-exit-card ${
            antigravityState.nodeProbe?.regionMismatchDetail ||
            antigravityState.nodeProbe?.googleAiSupported === false
              ? 'mismatch-card'
              : ''
          }`}
        >
          {config.antigravityClashNode ? (
            antigravityState.nodeProbe ? (
              <div className="ag-exit-main">
                <CountryFlag
                  code={antigravityState.nodeProbe.countryCode}
                  size="md"
                />
                <div className="ag-exit-text">
                  <div className="ag-exit-title-row">
                    <strong>{antigravityState.nodeProbe.countryName}</strong>
                    <span className="iso-pill">
                      {antigravityState.nodeProbe.countryCode}
                    </span>
                    {antigravityState.nodeProbe.regionMismatchDetail &&
                    antigravityState.nodeProbe.googleCountryCode &&
                    antigravityState.nodeProbe.googleCountryCode.toUpperCase() !==
                      antigravityState.nodeProbe.countryCode.toUpperCase() ? (
                      <span
                        className="target-verify-pill mismatch"
                        title={antigravityState.nodeProbe.regionMismatchDetail}
                      >
                        ⚠️ Google识别: {antigravityState.nodeProbe.googleCountryName} (
                        {antigravityState.nodeProbe.googleCountryCode})
                      </span>
                    ) : antigravityState.nodeProbe.googleAiSupported === false ? (
                      <span
                        className="target-verify-pill mismatch"
                        title={
                          antigravityState.nodeProbe.regionMismatchDetail ||
                          'NotebookLM 判定当前节点地区不受支持'
                        }
                      >
                        ⚠️ NotebookLM 不支持
                        {antigravityState.nodeProbe.googleCountryCode
                          ? ` (${antigravityState.nodeProbe.googleCountryCode})`
                          : ''}
                      </span>
                    ) : antigravityState.nodeProbe.regionMismatchDetail ? (
                      <span
                        className="target-verify-pill mismatch"
                        title={antigravityState.nodeProbe.regionMismatchDetail}
                      >
                        ⚠️ Google地区异常
                      </span>
                    ) : antigravityState.nodeProbe.googleCountryCode ? (
                      <span
                        className="target-verify-pill verified"
                        title={
                          antigravityState.nodeProbe.googleAiSupported === true
                            ? '已通过 Google 地区与 NotebookLM 可用性探测（仅供参考，不含 Antigravity 账号归属地校验）'
                            : '已通过 Google 目标服务真实地区校验'
                        }
                      >
                        ✓ Google验证: {antigravityState.nodeProbe.googleCountryCode}
                      </span>
                    ) : null}
                    <span className="ag-node-tag ellipsis">
                      {config.antigravityClashNode}
                    </span>
                  </div>
                  <div className="ag-exit-ip-row">
                    <span className="ip-label">节点出口 IP:</span>
                    <code className="ip-code">{antigravityState.nodeProbe.ip}</code>
                    <button
                      className="btn-icon-tiny"
                      onClick={onCopyIp}
                      title="复制节点出口 IP"
                    >
                      {copiedAgIp ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                    <span className="latency-tag">
                      {antigravityState.nodeProbe.latencyMs} ms
                    </span>
                  </div>
                </div>
              </div>
            ) : antigravityState.isProbingNode ? (
              <div className="ag-exit-placeholder">
                <RefreshCw className="spin" size={15} />
                <span>
                  正在通过专属端口 127.0.0.1:{config.antigravityDedicatedPort}{' '}
                  获取节点 [{config.antigravityClashNode}] 出口信息并校验 Google 真实地区...
                </span>
              </div>
            ) : (
              <div className="ag-exit-placeholder">
                <Info size={15} />
                <span>
                  {antigravityState.nodeProbeError ||
                    `已选定节点 [${config.antigravityClashNode}]，点击右上角「刷新节点出口」可查看出口 IP`}
                </span>
              </div>
            )
          ) : (
            <div className="ag-exit-placeholder">
              <Radio size={15} />
              <span>请先在上方下拉框选择要为 Antigravity 绑定的 Clash 代理节点</span>
            </div>
          )}
        </div>

        {antigravityState.nodeProbe?.regionMismatchDetail && (
          <div className="ag-warn-banner">
            <AlertTriangle size={14} />
            <span>
              <strong>
                {antigravityState.nodeProbe.googleCountryCode &&
                antigravityState.nodeProbe.googleCountryCode.toUpperCase() !==
                  antigravityState.nodeProbe.countryCode.toUpperCase()
                  ? '假地区 / 送中节点预警：'
                  : 'NotebookLM 地区受限预警：'}
              </strong>
              {antigravityState.nodeProbe.regionMismatchDetail}
              ，Antigravity 可能会报错地区不受支持，建议更换其他节点。
            </span>
          </div>
        )}

        {/* 全进程代理覆盖状态明细：Antigravity.exe + language_server.exe */}
        <div className="ag-process-grid">
          <div
            className={`ag-proc-box ${
              antigravityState.uiProcessCount > 0 ? 'active' : ''
            }`}
          >
            <div className="ag-proc-header">
              <code>Antigravity.exe</code>
              <span
                className={`ag-proc-badge ${
                  antigravityState.uiProcessCount > 0 ? 'on' : 'off'
                }`}
              >
                {antigravityState.uiProcessCount > 0
                  ? `运行中 ×${antigravityState.uiProcessCount}`
                  : '未运行'}
              </span>
            </div>
          </div>

          <div
            className={`ag-proc-box ${
              antigravityState.languageServerCount > 0 ? 'active' : ''
            }`}
          >
            <div className="ag-proc-header">
              <code>language_server.exe</code>
              <span
                className={`ag-proc-badge ${
                  antigravityState.languageServerCount > 0 ? 'on' : 'off'
                }`}
              >
                {antigravityState.languageServerCount > 0
                  ? `运行中 ×${antigravityState.languageServerCount}`
                  : '未运行'}
              </span>
            </div>
          </div>
        </div>

        {/* 外部直连运行提示或未就绪指引 */}
        {antigravityState.running && !antigravityState.proxiedSession && (
          <div className="ag-info-banner">
            <Info size={14} />
            <span>
              当前 Antigravity 由外部启动，可点击下方按钮重启以绑定专属代理通道。
            </span>
          </div>
        )}

        {!antigravityState.canLaunch && antigravityState.launchHint && (
          <div className="ag-info-banner">
            <Info size={14} />
            <span>{antigravityState.launchHint}</span>
          </div>
        )}

        {/* 运行中重启/强杀二次确认栏 */}
        {pendingAgConfirm && (
          <div className="inline-confirm-bar">
            <div className="confirm-bar-text">
              <AlertTriangle size={15} />
              <span>
                {pendingAgConfirm === 'restart'
                  ? '重启将强制终止当前 Antigravity.exe 与 language_server.exe 进程树并重新拉起，请确认已保存代码更改。'
                  : '将强制终止全部 Antigravity.exe 与 language_server.exe 进程，请确认已保存工作内容。'}
              </span>
            </div>
            <div className="confirm-bar-actions">
              <button
                type="button"
                className="btn-confirm-danger"
                disabled={isLaunchingAg}
                onClick={onConfirmAction}
              >
                {pendingAgConfirm === 'restart' ? '确认重启' : '确认关闭'}
              </button>
              <button
                type="button"
                className="btn-confirm-cancel"
                onClick={onCancelConfirm}
              >
                取消
              </button>
            </div>
          </div>
        )}

        {/* 启动 / 重启 / 停止按钮行 */}
        <div className="claude-launch-actions">
          <button
            className={`btn-launch-claude ${
              antigravityState.canLaunch ? 'ready' : 'disabled'
            }`}
            disabled={
              !antigravityState.canLaunch || isLaunchingAg || isSwitchingAgNode
            }
            onClick={onLaunch}
          >
            {isLaunchingAg ? (
              <>
                <RefreshCw className="spin" size={16} />
                <span>正在绑定代理并拉起 Antigravity...</span>
              </>
            ) : (
              <>
                <Play size={16} />
                <span>
                  {antigravityState.running && antigravityState.proxiedSession
                    ? '重启 Antigravity（重新拉起）'
                    : antigravityState.running
                    ? '重启 Antigravity 并注入专属代理参数'
                    : '通过指定节点启动 Antigravity'}
                </span>
              </>
            )}
          </button>

          {antigravityState.running && (
            <button
              className="btn-kill-claude"
              onClick={onTerminate}
              title="关闭 Antigravity.exe 及 language_server.exe 进程"
            >
              <Square size={14} />
              <span>关闭进程</span>
            </button>
          )}
        </div>

        {agFeedback && (
          <div className={`locale-feedback ${agFeedback.ok ? 'ok' : 'err'}`}>
            {agFeedback.ok ? <Check size={14} /> : <AlertTriangle size={14} />}
            <span>{agFeedback.text}</span>
          </div>
        )}
      </section>

      {/* 3. Antigravity 客户端路径与专属端口设置卡（默认折叠） */}
      <section
        className={`panel-card collapsible-card ${
          isAgSettingsExpanded ? 'expanded' : 'collapsed'
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
            <Cpu size={15} />
            <span>客户端路径与专属端口设置</span>
          </div>
          <div className="collapsible-header-right">
            <span className="mini-badge neutral">
              127.0.0.1:{config.antigravityDedicatedPort} · {agInstallTypeLabel}
            </span>
            <span className="collapse-chevron">
              {isAgSettingsExpanded ? (
                <ChevronUp size={15} />
              ) : (
                <ChevronDown size={15} />
              )}
            </span>
          </div>
        </div>

        {isAgSettingsExpanded && (
          <div className="collapsible-body">
            <div className="claude-exe-path-box">
              <div className="exe-path-header">
                <span>Antigravity 专属代理监听端口（与 Claude 端口独立）：</span>
              </div>
              <div className="exe-path-row">
                <code className="exe-path-code">127.0.0.1 :</code>
                <input
                  type="number"
                  className="dedicated-port-input"
                  min={1024}
                  max={65535}
                  value={agDedicatedPortInput}
                  onChange={(e) => onChangeDedicatedPortInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') onSaveDedicatedPort();
                  }}
                />
                <button
                  className="btn-save-inline"
                  disabled={isSwitchingAgNode}
                  onClick={onSaveDedicatedPort}
                >
                  <span>保存端口</span>
                </button>
              </div>
            </div>

            <div className="claude-exe-path-box">
              <div className="exe-path-header">
                <span>Antigravity.exe 路径：</span>
                {config.antigravityExePath && (
                  <button className="btn-link-clear" onClick={onClearExePath}>
                    恢复自动探测
                  </button>
                )}
              </div>
              <div className="exe-path-row">
                <code
                  className="exe-path-code ellipsis"
                  title={
                    antigravityState.detectedExePath || '未检测到 Antigravity.exe'
                  }
                >
                  {antigravityState.detectedExePath ||
                    '未检测到 Antigravity.exe，请点击右侧手动浏览选择'}
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
