import React from 'react';
import {
  Activity,
  AlertTriangle,
  Check,
  ExternalLink,
  RefreshCw,
  Settings,
  Sparkles,
} from 'lucide-react';
import { AppConfig, ProxyMode, UpdateStateSnapshot } from '../../shared/types';
import { FeedbackMessage, formatTime } from './dashboardTypes';
import { UpdateReleaseCard } from './UpdateReleaseCard';

export interface SettingsPaneProps {
  config: AppConfig;
  updateState: UpdateStateSnapshot;
  displayedProxyMode: ProxyMode;
  manualProto: 'http' | 'socks5';
  manualHost: string;
  manualPort: string;
  customProbe: string;
  probeUrlErr: string | null;
  hasNewUpdate: boolean;
  isUpdateBusy: boolean;
  isApplyingUpdate: boolean;
  pendingUpdateConfirm: boolean;
  isClaudeActiveForUpdate: boolean;
  updateFeedback: FeedbackMessage | null;
  onSwitchNonManualMode: (mode: 'auto' | 'direct') => void;
  onSelectManualMode: () => void;
  onChangeManualProto: (proto: 'http' | 'socks5') => void;
  onChangeManualHost: (host: string) => void;
  onChangeManualPort: (port: string) => void;
  onSaveManualProxy: () => void;
  onUpdateConfig: (partial: Partial<AppConfig>) => void;
  onChangeCustomProbe: (url: string) => void;
  onSaveCustomProbe: () => void;
  onOpenReleasePage: () => void;
  onCheckForUpdates: () => void;
  onDownloadUpdate: () => void;
  onClickApplyUpdate: () => void;
  onConfirmApplyUpdate: () => void;
  onCancelUpdateConfirm: () => void;
}

export const SettingsPane: React.FC<SettingsPaneProps> = ({
  config,
  updateState,
  displayedProxyMode,
  manualProto,
  manualHost,
  manualPort,
  customProbe,
  probeUrlErr,
  hasNewUpdate,
  isUpdateBusy,
  isApplyingUpdate,
  pendingUpdateConfirm,
  isClaudeActiveForUpdate,
  updateFeedback,
  onSwitchNonManualMode,
  onSelectManualMode,
  onChangeManualProto,
  onChangeManualHost,
  onChangeManualPort,
  onSaveManualProxy,
  onUpdateConfig,
  onChangeCustomProbe,
  onSaveCustomProbe,
  onOpenReleasePage,
  onCheckForUpdates,
  onDownloadUpdate,
  onClickApplyUpdate,
  onConfirmApplyUpdate,
  onCancelUpdateConfirm,
}) => {
  return (
    <div className="tab-pane">
      {/* 1. 实时监控专属设置（检测通道模式 + 监控异常告警） */}
      <section className="panel-card">
        <div className="panel-card-header">
          <div className="panel-title">
            <Activity size={15} />
            <span>实时监控设置（通道与告警）</span>
          </div>
          <span className="mini-badge neutral">仅作用于实时监控</span>
        </div>

        <div className="radio-group">
          <label
            className={`radio-card ${displayedProxyMode === 'auto' ? 'selected' : ''}`}
          >
            <input
              type="radio"
              name="proxyMode"
              checked={displayedProxyMode === 'auto'}
              onChange={() => onSwitchNonManualMode('auto')}
            />
            <div>
              <strong>自动识别 Clash 选中通道（推荐）</strong>
              <p>优先跟随 Clash Verge，未连接时回退系统代理或直连</p>
            </div>
          </label>

          <label
            className={`radio-card ${
              displayedProxyMode === 'manual' ? 'selected' : ''
            }`}
          >
            <input
              type="radio"
              name="proxyMode"
              checked={displayedProxyMode === 'manual'}
              onChange={onSelectManualMode}
            />
            <div>
              <strong>手动指定本地代理端口</strong>
              <p>固定使用自定义 HTTP / SOCKS5 代理检测</p>
            </div>
          </label>

          {displayedProxyMode === 'manual' && (
            <div className="manual-proxy-form">
              <select
                value={manualProto}
                onChange={(e) =>
                  onChangeManualProto(e.target.value as 'http' | 'socks5')
                }
              >
                <option value="http">HTTP</option>
                <option value="socks5">SOCKS5</option>
              </select>
              <input
                type="text"
                value={manualHost}
                onChange={(e) => onChangeManualHost(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') onSaveManualProxy();
                }}
                placeholder="127.0.0.1"
              />
              <input
                type="number"
                className="port-input"
                value={manualPort}
                onChange={(e) => onChangeManualPort(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') onSaveManualProxy();
                }}
                placeholder="7890"
              />
              <button className="btn-save-inline" onClick={onSaveManualProxy}>
                {config.proxyMode === 'manual' ? '保存重测' : '启用并重测'}
              </button>
            </div>
          )}

          <label
            className={`radio-card ${
              displayedProxyMode === 'direct' ? 'selected' : ''
            }`}
          >
            <input
              type="radio"
              name="proxyMode"
              checked={displayedProxyMode === 'direct'}
              onChange={() => onSwitchNonManualMode('direct')}
            />
            <div>
              <strong>强制纯网卡直连（仅限全局 TUN 模式）</strong>
              <p>忽略系统代理，直接检测默认网卡出口</p>
            </div>
          </label>
        </div>

        <div className="setting-row">
          <div>
            <strong>实时监控异常弹窗告警</strong>
            <p>出口地区/时区不符或触发联动强杀时置顶提醒</p>
          </div>
          <input
            type="checkbox"
            className="toggle-switch"
            checked={config.monitorAlertEnabled}
            onChange={(e) =>
              onUpdateConfig({ monitorAlertEnabled: e.target.checked })
            }
          />
        </div>

        <div className="setting-row no-border-bottom">
          <div>
            <strong>实时监控断连或超时报警</strong>
            <p>代理连接失败或节点超时时弹窗（需开启上方告警）</p>
          </div>
          <input
            type="checkbox"
            className="toggle-switch"
            disabled={!config.monitorAlertEnabled}
            checked={config.alertOnDisconnect}
            onChange={(e) =>
              onUpdateConfig({ alertOnDisconnect: e.target.checked })
            }
          />
        </div>
      </section>

      {/* 2. 软件全局通用设置 */}
      <section className="panel-card">
        <div className="panel-card-header">
          <div className="panel-title">
            <Settings size={15} />
            <span>软件全局通用设置</span>
          </div>
        </div>

        <div className="setting-row">
          <div>
            <strong>运行期后台巡检间隔</strong>
            <p>定时复核出口 IP 漂移（作用于 Claude 与实时监控）</p>
          </div>
          <select
            className="compact-select"
            value={config.heartbeatIntervalSec}
            onChange={(e) =>
              onUpdateConfig({ heartbeatIntervalSec: Number(e.target.value) })
            }
          >
            <option value={0}>仅本地事件触发</option>
            <option value={5}>每 5 秒</option>
            <option value={10}>每 10 秒</option>
            <option value={15}>每 15 秒 (推荐)</option>
            <option value={30}>每 30 秒</option>
            <option value={60}>每 60 秒</option>
          </select>
        </div>

        <div className="setting-row">
          <div>
            <strong>异常警告提示音</strong>
            <p>触发置顶告警弹窗时播放声音提醒</p>
          </div>
          <input
            type="checkbox"
            className="toggle-switch"
            checked={config.alertSoundEnabled}
            onChange={(e) =>
              onUpdateConfig({ alertSoundEnabled: e.target.checked })
            }
          />
        </div>

        <div className="setting-row">
          <div>
            <strong>关闭窗口时最小化到托盘</strong>
            <p>开启时隐藏窗口，关闭时销毁窗口；后台代理和安全检查持续运行</p>
          </div>
          <input
            type="checkbox"
            className="toggle-switch"
            checked={config.closeToTray}
            onChange={(e) => onUpdateConfig({ closeToTray: e.target.checked })}
          />
        </div>

        <div className="setting-row">
          <div>
            <strong>开机自动启动</strong>
            <p>登录 Windows 时静默启动并驻留托盘</p>
          </div>
          <input
            type="checkbox"
            className="toggle-switch"
            checked={config.autoLaunch}
            onChange={(e) => onUpdateConfig({ autoLaunch: e.target.checked })}
          />
        </div>

        <div className="custom-probe-box">
          <label>自定义探测 URL（留空默认 Cloudflare / AWS 探测源）：</label>
          <div className="custom-probe-row">
            <input
              type="text"
              value={customProbe}
              onChange={(e) => onChangeCustomProbe(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') onSaveCustomProbe();
              }}
              placeholder="例如 https://cp.cloudflare.com/cdn-cgi/trace"
            />
            <button className="btn-save-inline" onClick={onSaveCustomProbe}>
              应用
            </button>
          </div>
          {probeUrlErr && (
            <div className="pattern-hint err">
              <AlertTriangle size={12} />
              <span>{probeUrlErr}</span>
            </div>
          )}
        </div>
      </section>

      {/* 3. 版本与自动更新设置 */}
      <section
        className={`panel-card update-card ${
          updateState.status === 'downloaded' || updateState.status === 'applying'
            ? 'has-ready-update'
            : hasNewUpdate
            ? 'has-available-update'
            : ''
        }`}
      >
        <div className="panel-card-header">
          <div className="panel-title">
            <Sparkles size={15} />
            <span>版本与自动更新</span>
            <span className="mini-badge neutral">v{updateState.currentVersion}</span>
          </div>
          <div className="update-header-actions">
            <button
              type="button"
              className="btn-link-clear"
              onClick={onOpenReleasePage}
              title="在浏览器中打开 GitHub Releases 页面"
            >
              <ExternalLink size={12} />
              <span>GitHub</span>
            </button>
            <button
              type="button"
              className="btn-refresh"
              disabled={isUpdateBusy}
              onClick={onCheckForUpdates}
            >
              <RefreshCw
                size={13}
                className={updateState.status === 'checking' ? 'spin' : ''}
              />
              <span>
                {updateState.status === 'checking' ? '正在检查...' : '检查更新'}
              </span>
            </button>
          </div>
        </div>

        <div className="update-meta-summary">
          <span>
            当前版本 <strong>v{updateState.currentVersion}</strong> · Electron{' '}
            {updateState.electronVersion}
            {!updateState.isPackaged && ' · 源码运行模式'}
          </span>
          {updateState.lastCheckedAt && (
            <span className="update-last-checked">
              上次检查 {formatTime(updateState.lastCheckedAt)}
            </span>
          )}
        </div>

        {updateFeedback && (
          <div className={`locale-feedback ${updateFeedback.ok ? 'ok' : 'err'}`}>
            {updateFeedback.ok ? <Check size={14} /> : <AlertTriangle size={14} />}
            <span>{updateFeedback.text}</span>
          </div>
        )}

        {Boolean(updateState.error) && !updateFeedback && (
          <div className="locale-feedback err">
            <AlertTriangle size={14} />
            <span>{updateState.error}</span>
          </div>
        )}

        <UpdateReleaseCard
          inModal={false}
          hasNewUpdate={hasNewUpdate}
          updateState={updateState}
          isApplyingUpdate={isApplyingUpdate}
          isUpdateBusy={isUpdateBusy}
          pendingUpdateConfirm={pendingUpdateConfirm}
          isClaudeActiveForUpdate={isClaudeActiveForUpdate}
          onConfirmApplyUpdate={onConfirmApplyUpdate}
          onCancelUpdateConfirm={onCancelUpdateConfirm}
          onOpenReleasePage={onOpenReleasePage}
          onClickApplyUpdate={onClickApplyUpdate}
          onDownloadUpdate={onDownloadUpdate}
        />

        <div className="setting-row">
          <div>
            <strong>自动检查版本更新</strong>
            <p>启动与打开面板时按需检测（30 分钟冷却），正式版自动预下载增量包</p>
          </div>
          <input
            type="checkbox"
            className="toggle-switch"
            checked={config.autoCheckUpdates}
            onChange={(e) =>
              onUpdateConfig({ autoCheckUpdates: e.target.checked })
            }
          />
        </div>

        <div className="setting-row no-border-bottom">
          <div>
            <strong>GitHub 下载加速镜像兜底</strong>
            <p>连接超时时自动切换公开镜像，全程签名校验防篡改</p>
          </div>
          <input
            type="checkbox"
            className="toggle-switch"
            checked={config.useUpdateMirrorFallback}
            onChange={(e) =>
              onUpdateConfig({ useUpdateMirrorFallback: e.target.checked })
            }
          />
        </div>
      </section>
    </div>
  );
};
