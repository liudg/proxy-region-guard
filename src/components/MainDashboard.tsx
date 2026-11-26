import React from 'react';
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  RefreshCw,
  Rocket,
  ShieldAlert,
} from 'lucide-react';
import { AntigravityLauncherPane } from './dashboard/AntigravityLauncherPane';
import { ClaudeLauncherPane } from './dashboard/ClaudeLauncherPane';
import { DashboardNavTabs } from './dashboard/DashboardNavTabs';
import { DashboardTitlebar } from './dashboard/DashboardTitlebar';
import { LogsPane } from './dashboard/LogsPane';
import { MonitorStatusPane } from './dashboard/MonitorStatusPane';
import { ProcessGuardPane } from './dashboard/ProcessGuardPane';
import { SettingsPane } from './dashboard/SettingsPane';
import { UpdateModalDialog } from './dashboard/UpdateModalDialog';
import { useDashboardController } from './dashboard/useDashboardController';

export const MainDashboard: React.FC = () => {
  const ctrl = useDashboardController();

  if (!ctrl.ready) {
    return (
      <div className="app-loading">
        <RefreshCw className="spin" size={24} />
        <span>正在初始化代理地区卫士...</span>
      </div>
    );
  }

  const { state } = ctrl;
  const { config, claudeState, antigravityState, updateState, logs } = state;

  return (
    <div className="dashboard-window">
      <DashboardTitlebar
        titlebarDotClass={ctrl.titlebarDotClass}
        hasNewUpdate={ctrl.hasNewUpdate}
        updateState={updateState}
        updateModalOpen={ctrl.updateModalOpen}
        closeButtonTitle={ctrl.closeButtonTitle}
        onToggleUpdateModal={() => {
          if (ctrl.updateModalOpen) {
            ctrl.closeUpdateModal();
          } else {
            ctrl.setPendingUpdateConfirm(false);
            ctrl.setUpdateModalOpen(true);
          }
        }}
        onMinimize={() => window.guardAPI.minimizeMain()}
        onClose={() => window.guardAPI.closeMain()}
      />

      <UpdateModalDialog
        open={ctrl.updateModalOpen}
        hasNewUpdate={ctrl.hasNewUpdate}
        updateState={updateState}
        updateFeedback={ctrl.updateFeedback}
        isApplyingUpdate={ctrl.isApplyingUpdate}
        isUpdateBusy={ctrl.isUpdateBusy}
        pendingUpdateConfirm={ctrl.pendingUpdateConfirm}
        isClaudeActiveForUpdate={ctrl.isClaudeActiveForUpdate}
        onCloseModal={ctrl.closeUpdateModal}
        onOpenReleasePage={ctrl.handleOpenReleasePage}
        onCheckForUpdates={() => void ctrl.handleCheckForUpdates()}
        onDownloadUpdate={() => void ctrl.handleDownloadUpdate()}
        onClickApplyUpdate={ctrl.handleClickApplyUpdate}
        onConfirmApplyUpdate={() => void ctrl.executeApplyUpdate(true)}
        onCancelUpdateConfirm={() => ctrl.setPendingUpdateConfirm(false)}
      />

      <DashboardNavTabs
        activeTab={ctrl.activeTab}
        launcherTabDotClass={ctrl.launcherTabDotClass}
        killProcessesEnabled={config.killProcessesEnabled}
        protectedPatternCount={config.protectedProcessPatterns.length}
        hasNewUpdate={ctrl.hasNewUpdate}
        updateStatus={updateState.status}
        logsCount={logs.length}
        onSelectTab={ctrl.handleSwitchMainTab}
      />

      <main className="dashboard-content">
        {ctrl.globalNotice && ctrl.activeTab !== 'launcher' && (
          <div
            className={`locale-feedback global-top-notice ${
              ctrl.globalNotice.ok ? 'ok' : 'err'
            }`}
          >
            {ctrl.globalNotice.ok ? <Check size={14} /> : <AlertTriangle size={14} />}
            <span>{ctrl.globalNotice.text}</span>
          </div>
        )}

        {ctrl.activeTab === 'launcher' && (
          <div className="tab-pane">
            <div className="launcher-subtabs">
              <button
                className={`launcher-subtab ${
                  ctrl.launcherSubTab === 'antigravity' ? 'active' : ''
                }`}
                onClick={() => ctrl.setLauncherSubTab('antigravity')}
              >
                <Rocket size={14} />
                <span>Antigravity 启动器</span>
                <span className="subtab-mode-badge pure">纯代理</span>
                <span
                  className={`tab-status-dot ${
                    antigravityState.running && antigravityState.proxiedSession
                      ? 'running'
                      : antigravityState.running
                      ? 'external'
                      : antigravityState.canLaunch
                      ? 'ready'
                      : 'Idle'
                  }`}
                />
              </button>

              <button
                className={`launcher-subtab ${
                  ctrl.launcherSubTab === 'claude' ? 'active' : ''
                }`}
                onClick={() => ctrl.setLauncherSubTab('claude')}
              >
                <Bot size={14} />
                <span>Claude 专栏</span>
                <span className="subtab-mode-badge guard">三重守护</span>
                <span
                  className={`tab-status-dot ${
                    claudeState.running
                      ? 'running'
                      : claudeState.canLaunch
                      ? 'ready'
                      : claudeState.isProbingNode &&
                        !claudeState.nodeProbe &&
                        !claudeState.nodeProbeError
                      ? 'checking'
                      : 'locked'
                  }`}
                />
              </button>
            </div>

            {ctrl.launcherSubTab === 'antigravity' ? (
              <AntigravityLauncherPane
                state={state}
                clashHeaderBadgeText={ctrl.clashHeaderBadgeText}
                isSwitchingAgNode={ctrl.isSwitchingAgNode}
                isLaunchingAg={ctrl.isLaunchingAg}
                copiedAgIp={ctrl.copiedAgIp}
                agFeedback={ctrl.agFeedback}
                pendingAgConfirm={ctrl.pendingAgConfirm}
                isAgSettingsExpanded={ctrl.isAgSettingsExpanded}
                agInstallTypeLabel={ctrl.agInstallTypeLabel}
                agDedicatedPortInput={ctrl.agDedicatedPortInput}
                onState={ctrl.setState}
                onSelectNode={(node, profUid) =>
                  void ctrl.handleSelectAntigravityNode(node, profUid)
                }
                onProbeNode={() =>
                  void window.guardAPI
                    .probeAntigravityNode()
                    .then(ctrl.setState)
                    .catch((err) => ctrl.notifyError(err, 'ag'))
                }
                onCopyIp={ctrl.handleCopyAgIp}
                onLaunch={ctrl.handleLaunchAntigravity}
                onTerminate={ctrl.handleTerminateAntigravity}
                onConfirmAction={() =>
                  void (ctrl.pendingAgConfirm === 'restart'
                    ? ctrl.executeLaunchAntigravity()
                    : ctrl.executeTerminateAntigravity())
                }
                onCancelConfirm={() => ctrl.setPendingAgConfirm(null)}
                onToggleSettings={() => ctrl.setAgSettingsOpen((prev) => !prev)}
                onChangeDedicatedPortInput={ctrl.setAgDedicatedPortInput}
                onSaveDedicatedPort={() => void ctrl.handleSaveAgDedicatedPort()}
                onClearExePath={() =>
                  void ctrl.updateConfigSafe({ antigravityExePath: '' }, 'ag')
                }
                onBrowseExePath={() =>
                  void window.guardAPI
                    .browseAntigravityExe()
                    .then(ctrl.setState)
                    .catch((err) => ctrl.notifyError(err, 'ag'))
                }
              />
            ) : (
              <ClaudeLauncherPane
                state={state}
                clashHeaderBadgeText={ctrl.clashHeaderBadgeText}
                isSwitchingNode={ctrl.isSwitchingNode}
                isLaunchingClaude={ctrl.isLaunchingClaude}
                claudeVerificationError={ctrl.claudeVerificationError}
                claudeFallbackDetectedCode={ctrl.claudeFallbackDetectedCode}
                claudeFeedback={ctrl.claudeFeedback}
                pendingClaudeConfirm={ctrl.pendingClaudeConfirm}
                isClaudeSettingsExpanded={ctrl.isClaudeSettingsExpanded}
                installTypeLabel={ctrl.installTypeLabel}
                dedicatedPortInput={ctrl.dedicatedPortInput}
                onState={ctrl.setState}
                onSelectNode={(node, profUid) =>
                  void ctrl.handleSelectClaudeNode(node, profUid)
                }
                onProbeNode={() =>
                  void window.guardAPI
                    .probeClaudeNode('Claude 专栏手动重测')
                    .then(ctrl.setState)
                    .catch((err) => ctrl.notifyError(err, 'claude'))
                }
                onSyncLocaleFromClaude={() => void ctrl.handleSyncLocaleFromClaude()}
                onConfirmClaudeAction={() => {
                  const pending = ctrl.pendingClaudeConfirm;
                  if (!pending) return;
                  if (pending.type === 'switch-node') {
                    void ctrl.executeSelectClaudeNode(
                      pending.nodeName,
                      pending.profileUid
                    );
                  } else if (pending.type === 'change-port') {
                    void ctrl.executeSaveDedicatedPort(pending.port);
                  } else if (pending.type === 'toggle-ipv4') {
                    void ctrl.executeToggleClaudeForceIpv4(pending.enabled, true);
                  } else {
                    void ctrl.executeTerminateClaude();
                  }
                }}
                onCancelClaudeConfirm={() => {
                  if (ctrl.pendingClaudeConfirm?.type === 'change-port') {
                    ctrl.setDedicatedPortInput(String(config.dedicatedProxyPort));
                  }
                  ctrl.setPendingClaudeConfirm(null);
                }}
                onLaunchClaude={() => void ctrl.handleLaunchClaude()}
                onTerminateClaude={ctrl.handleTerminateClaude}
                onToggleSettings={() => ctrl.setClaudeSettingsOpen((prev) => !prev)}
                onUpdateClaudeConfig={(partial) =>
                  void ctrl.updateConfigSafe(partial, 'claude')
                }
                onToggleForceIpv4={ctrl.handleToggleClaudeForceIpv4}
                onChangeDedicatedPortInput={ctrl.setDedicatedPortInput}
                onSaveDedicatedPort={() => void ctrl.handleSaveDedicatedPort()}
                onClearExePath={() =>
                  void ctrl.updateConfigSafe({ claudeExePath: '' }, 'claude')
                }
                onBrowseExePath={() =>
                  void window.guardAPI
                    .browseClaudeExe()
                    .then(ctrl.setState)
                    .catch((err) => ctrl.notifyError(err, 'claude'))
                }
              />
            )}
          </div>
        )}

        {ctrl.activeTab === 'monitor' && (
          <div className="tab-pane">
            <div className="launcher-subtabs">
              <button
                className={`launcher-subtab ${
                  ctrl.monitorSubTab === 'status' ? 'active' : ''
                }`}
                onClick={() => ctrl.setMonitorSubTab('status')}
              >
                <Activity size={14} />
                <span>状态与时区</span>
                <span className={`tab-status-dot ${ctrl.monitorTabDotClass}`} />
              </button>

              <button
                className={`launcher-subtab ${
                  ctrl.monitorSubTab === 'guard' ? 'active' : ''
                }`}
                onClick={() => ctrl.setMonitorSubTab('guard')}
              >
                <ShieldAlert size={14} />
                <span>联动进程强杀</span>
                <span
                  className={`subtab-mode-badge ${
                    config.killProcessesEnabled &&
                    config.protectedProcessPatterns.length > 0
                      ? 'guard'
                      : 'muted'
                  }`}
                >
                  {!config.killProcessesEnabled
                    ? '已关闭'
                    : config.protectedProcessPatterns.length > 0
                    ? `守护 ${config.protectedProcessPatterns.length} 项`
                    : '未配置规则'}
                </span>
              </button>
            </div>

            {ctrl.monitorSubTab === 'status' ? (
              <MonitorStatusPane
                state={state}
                statusMeta={ctrl.statusMeta}
                copiedIp={ctrl.copiedIp}
                effectiveTargetCode={ctrl.effectiveTargetCode}
                effectiveTargetName={ctrl.effectiveTargetName}
                isWinLocaleMatched={ctrl.isWinLocaleMatched}
                isAlreadyChinaDefaultLocale={ctrl.isAlreadyChinaDefaultLocale}
                localeFeedback={ctrl.localeFeedback}
                canLockCurrentProbe={ctrl.canLockCurrentProbe}
                isCurrentAlreadyDefault={ctrl.isCurrentAlreadyDefault}
                isCustomCountryOutsideCommon={ctrl.isCustomCountryOutsideCommon}
                onCheckNow={() =>
                  void window.guardAPI
                    .checkNow('手动立即刷新')
                    .then(ctrl.setState)
                    .catch((err) => ctrl.notifyError(err, 'global'))
                }
                onCopyIp={ctrl.handleCopyIp}
                onSyncLocale={() => void ctrl.handleSyncLocale()}
                onRestoreLocale={() => void ctrl.handleRestoreLocale()}
                onSetDefaultRegion={(code) =>
                  void window.guardAPI
                    .setDefaultRegion(code)
                    .then(ctrl.setState)
                    .catch((err) => ctrl.notifyError(err, 'global'))
                }
                onSetDefaultCurrent={() =>
                  void window.guardAPI
                    .setDefaultCurrent()
                    .then(ctrl.setState)
                    .catch((err) => ctrl.notifyError(err, 'global'))
                }
              />
            ) : (
              <ProcessGuardPane
                config={config}
                patternInput={ctrl.patternInput}
                patternSubmitErr={ctrl.patternSubmitErr}
                livePatternCheck={ctrl.livePatternCheck}
                onUpdateConfig={(partial) =>
                  void ctrl.updateConfigSafe(partial, 'global')
                }
                onChangePatternInput={(val) => {
                  ctrl.setPatternInput(val);
                  if (ctrl.patternSubmitErr) ctrl.setPatternSubmitErr(null);
                }}
                onAddPattern={() => void ctrl.handleAddPattern()}
                onRemovePattern={(pat) => void ctrl.handleRemovePattern(pat)}
              />
            )}
          </div>
        )}

        {ctrl.activeTab === 'settings' && (
          <SettingsPane
            config={config}
            updateState={updateState}
            displayedProxyMode={ctrl.displayedProxyMode}
            manualProto={ctrl.manualProto}
            manualHost={ctrl.manualHost}
            manualPort={ctrl.manualPort}
            customProbe={ctrl.customProbe}
            probeUrlErr={ctrl.probeUrlErr}
            hasNewUpdate={ctrl.hasNewUpdate}
            isUpdateBusy={ctrl.isUpdateBusy}
            isApplyingUpdate={ctrl.isApplyingUpdate}
            pendingUpdateConfirm={ctrl.pendingUpdateConfirm}
            isClaudeActiveForUpdate={ctrl.isClaudeActiveForUpdate}
            updateFeedback={ctrl.updateFeedback}
            onSwitchNonManualMode={(mode) => void ctrl.handleSwitchNonManualMode(mode)}
            onSelectManualMode={() => {
              if (config.proxyMode !== 'manual') {
                ctrl.setPendingManualMode(true);
              }
            }}
            onChangeManualProto={ctrl.setManualProto}
            onChangeManualHost={ctrl.setManualHost}
            onChangeManualPort={ctrl.setManualPort}
            onSaveManualProxy={() => void ctrl.handleSaveManualProxy()}
            onUpdateConfig={(partial) => void ctrl.updateConfigSafe(partial, 'global')}
            onChangeCustomProbe={(url) => {
              ctrl.setCustomProbe(url);
              if (ctrl.probeUrlErr) ctrl.setProbeUrlErr(null);
            }}
            onSaveCustomProbe={() => void ctrl.handleSaveCustomProbe()}
            onOpenReleasePage={ctrl.handleOpenReleasePage}
            onCheckForUpdates={() => void ctrl.handleCheckForUpdates()}
            onDownloadUpdate={() => void ctrl.handleDownloadUpdate()}
            onClickApplyUpdate={ctrl.handleClickApplyUpdate}
            onConfirmApplyUpdate={() => void ctrl.executeApplyUpdate(true)}
            onCancelUpdateConfirm={() => ctrl.setPendingUpdateConfirm(false)}
          />
        )}

        {ctrl.activeTab === 'logs' && (
          <LogsPane
            logs={logs}
            onClearLogs={() =>
              void window.guardAPI
                .clearLogs()
                .then(ctrl.setState)
                .catch((err) => ctrl.notifyError(err, 'global'))
            }
          />
        )}
      </main>
    </div>
  );
};
