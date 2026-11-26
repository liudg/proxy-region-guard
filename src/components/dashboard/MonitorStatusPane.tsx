import React from 'react';
import {
  AlertTriangle,
  Check,
  Clock,
  Copy,
  Globe,
  Lock,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Unlock,
  WifiOff,
} from 'lucide-react';
import { AppStateSnapshot } from '../../shared/types';
import { COMMON_COUNTRIES, isValidIsoCountryCode } from '../../shared/countries';
import { CountryFlag } from '../CountryFlag';
import {
  FeedbackMessage,
  formatTime,
  StatusDisplayMeta,
  StatusIconKind,
} from './dashboardTypes';

function renderStatusIcon(kind: StatusIconKind): React.ReactNode {
  switch (kind) {
    case 'ok':
      return <ShieldCheck size={18} />;
    case 'locale-warn':
      return <AlertTriangle size={18} />;
    case 'mismatch':
      return <ShieldAlert size={18} />;
    case 'error':
      return <WifiOff size={18} />;
    case 'checking':
      return <RefreshCw className="spin" size={18} />;
    default:
      return <Shield size={18} />;
  }
}

export interface MonitorStatusPaneProps {
  state: AppStateSnapshot;
  statusMeta: StatusDisplayMeta;
  copiedIp: boolean;
  effectiveTargetCode: string | null;
  effectiveTargetName: string | null;
  isWinLocaleMatched: boolean;
  isAlreadyChinaDefaultLocale: boolean;
  localeFeedback: FeedbackMessage | null;
  canLockCurrentProbe: boolean;
  isCurrentAlreadyDefault: boolean;
  isCustomCountryOutsideCommon: boolean;
  onCheckNow: () => void;
  onCopyIp: () => void;
  onSyncLocale: () => void;
  onRestoreLocale: () => void;
  onSetDefaultRegion: (code: string | null) => void;
  onSetDefaultCurrent: () => void;
}

export const MonitorStatusPane: React.FC<MonitorStatusPaneProps> = ({
  state,
  statusMeta,
  copiedIp,
  effectiveTargetCode,
  effectiveTargetName,
  isWinLocaleMatched,
  isAlreadyChinaDefaultLocale,
  localeFeedback,
  canLockCurrentProbe,
  isCurrentAlreadyDefault,
  isCustomCountryOutsideCommon,
  onCheckNow,
  onCopyIp,
  onSyncLocale,
  onRestoreLocale,
  onSetDefaultRegion,
  onSetDefaultCurrent,
}) => {
  const { status, isChecking, isSyncingLocale, config, winLocale, lastProbe, lastError } =
    state;

  return (
    <>
      {/* 1. 当前出口状态主卡片 */}
      <section className={`hero-card ${statusMeta.cls}`}>
        <div className="hero-top-row">
          <div className={`status-pill ${statusMeta.cls}`}>
            {renderStatusIcon(statusMeta.iconKind)}
            <span>{statusMeta.badge}</span>
          </div>
          <button className="btn-refresh" disabled={isChecking} onClick={onCheckNow}>
            <RefreshCw className={isChecking ? 'spin' : ''} size={14} />
            <span>{isChecking ? '检测中...' : '立即检测'}</span>
          </button>
        </div>

        {lastProbe ? (
          <div className="hero-main-info">
            <div className="hero-country-row">
              <CountryFlag code={lastProbe.countryCode} size="lg" />
              <div className="hero-country-titles">
                <div className="country-primary">
                  <h1>{lastProbe.countryName}</h1>
                  <span className="iso-pill">{lastProbe.countryCode}</span>
                  {lastProbe.edgeLoc &&
                    isValidIsoCountryCode(lastProbe.countryCode) &&
                    lastProbe.edgeLoc !== lastProbe.countryCode && (
                      <span
                        className="edge-hint-pill"
                        title="IP 离线库归属地与 CDN 边缘节点物理位置不同（常见于广播 IP 或跨区路由）"
                      >
                        路由点: {lastProbe.edgeLoc}
                      </span>
                    )}
                </div>
                <div className="ip-row">
                  <span className="ip-label">出口 IP:</span>
                  <code className="ip-code">{lastProbe.ip}</code>
                  <button
                    className="btn-icon-tiny"
                    onClick={onCopyIp}
                    title="复制出口 IP"
                  >
                    {copiedIp ? <Check size={13} /> : <Copy size={13} />}
                  </button>
                  <span className="latency-tag">{lastProbe.latencyMs} ms</span>
                </div>
              </div>
            </div>

            {lastError && status === 'error' && (
              <div className="inline-error-banner">
                <WifiOff size={14} />
                <span>最新检测异常：{lastError}</span>
              </div>
            )}

            <div className="hero-footer-meta">
              <span className="ellipsis" title={lastProbe.viaChannel}>
                检测通道：{lastProbe.viaChannel}
              </span>
              <span>更新于 {formatTime(lastProbe.checkedAt)}</span>
            </div>
          </div>
        ) : (
          <div className="hero-empty-state">
            {lastError ? (
              <div className="error-empty-box">
                <WifiOff size={28} />
                <p>{lastError}</p>
                <small>请确认 Clash Verge 已连接并选择有效节点</small>
              </div>
            ) : (
              <p>正在通过代理隧道验证真实出口 IP...</p>
            )}
          </div>
        )}
      </section>

      {/* 2. Windows 时区与区域同步卡片 */}
      <section className="panel-card">
        <div className="panel-card-header">
          <div className="panel-title">
            <Globe size={15} />
            <span>Windows 时区与区域</span>
          </div>
          {effectiveTargetCode && (
            <span
              className={`mini-badge ${
                isWinLocaleMatched
                  ? 'connected'
                  : config.defaultCountryCode
                  ? 'warn-badge'
                  : 'neutral'
              }`}
            >
              {isWinLocaleMatched
                ? '已与目标地区一致'
                : config.defaultCountryCode
                ? '与保护地区不一致'
                : '与当前出口不同 (可选同步)'}
            </span>
          )}
        </div>

        <div className="win-locale-grid">
          <div className="win-locale-box">
            <div className="win-locale-icon">
              <Clock size={16} />
            </div>
            <div className="win-locale-info">
              <span className="win-locale-label">时区</span>
              <strong
                className="win-locale-val ellipsis"
                title={winLocale.timeZoneDisplayName}
              >
                {winLocale.timeZoneDisplayName}
              </strong>
            </div>
          </div>

          <div className="win-locale-box region-box">
            <div className="win-locale-icon">
              <CountryFlag code={winLocale.regionCode} size="sm" />
            </div>
            <div className="win-locale-info">
              <span className="win-locale-label">区域</span>
              <strong className="win-locale-val">{winLocale.regionName}</strong>
            </div>
          </div>
        </div>

        <div className="locale-actions-row">
          <button
            className="btn-sync-locale"
            disabled={!effectiveTargetCode || isSyncingLocale}
            onClick={onSyncLocale}
            title={
              effectiveTargetCode
                ? '将 Windows 时区与区域同步至目标保护地区（多时区大国自动匹配城市时区）'
                : '请先选择代理节点或设置保护地区'
            }
          >
            <RefreshCw className={isSyncingLocale ? 'spin' : ''} size={14} />
            <span>
              {isSyncingLocale
                ? '正在设置系统时区...'
                : effectiveTargetName
                ? `一键同步至 [${effectiveTargetName}]`
                : '请先选择代理节点'}
            </span>
          </button>

          <button
            className="btn-restore-locale"
            disabled={isSyncingLocale || isAlreadyChinaDefaultLocale}
            onClick={onRestoreLocale}
            title={
              isAlreadyChinaDefaultLocale
                ? '当前系统已处于默认中国时区与区域'
                : '若当前代理非中国，将先强杀 Claude 与守护进程后再还原回中国时区与区域'
            }
          >
            <RotateCcw size={14} />
            <span>
              {isAlreadyChinaDefaultLocale ? '已是中国时区' : '还原默认时区'}
            </span>
          </button>
        </div>

        {localeFeedback && (
          <div className={`locale-feedback ${localeFeedback.ok ? 'ok' : 'err'}`}>
            {localeFeedback.ok ? <Check size={14} /> : <AlertTriangle size={14} />}
            <span>{localeFeedback.text}</span>
          </div>
        )}
      </section>

      {/* 3. 默认保护地区卡片 */}
      <section className="panel-card">
        <div className="panel-card-header">
          <div className="panel-title">
            <Lock size={15} />
            <span>默认保护地区设置</span>
          </div>
          {config.defaultCountryCode && (
            <button
              className="btn-link-clear"
              onClick={() => onSetDefaultRegion(null)}
              title="取消固定默认地区限制"
            >
              <Unlock size={13} />
              <span>清除默认</span>
            </button>
          )}
        </div>

        <div className="default-region-body">
          <div className="default-current-display">
            {config.defaultCountryCode ? (
              <>
                <CountryFlag code={config.defaultCountryCode} size="md" />
                <div className="default-text">
                  <strong>
                    {config.defaultCountryName} ({config.defaultCountryCode})
                  </strong>
                  <small>出口偏离该地区时立即告警并拦截受保护进程</small>
                </div>
              </>
            ) : (
              <div className="default-unset-hint">
                <span>未锁定固定地区，仅展示实时出口信息（不触发地区偏离红灯）</span>
              </div>
            )}
          </div>

          <div className="default-actions-row">
            <button
              className={`btn-primary-set ${
                isCurrentAlreadyDefault ? 'btn-already' : ''
              }`}
              disabled={!canLockCurrentProbe || isCurrentAlreadyDefault}
              onClick={onSetDefaultCurrent}
            >
              <Sparkles size={15} />
              <span>
                {isCurrentAlreadyDefault
                  ? `当前 [${lastProbe?.countryName}] 已是默认`
                  : canLockCurrentProbe && lastProbe
                  ? `将当前 [${lastProbe.countryName}] 设为默认`
                  : '等待检测有效地区...'}
              </span>
            </button>

            <select
              className="region-select"
              value={config.defaultCountryCode || ''}
              onChange={(e) => onSetDefaultRegion(e.target.value || null)}
              title="也可直接手动指定期望的国家/地区"
            >
              <option value="">手动指定地区...</option>
              {isCustomCountryOutsideCommon && config.defaultCountryCode && (
                <option value={config.defaultCountryCode}>
                  {config.defaultCountryName} ({config.defaultCountryCode})
                </option>
              )}
              {COMMON_COUNTRIES.map((c) => (
                <option key={c.code} value={c.code}>
                  {c.name} ({c.code})
                </option>
              ))}
            </select>
          </div>
        </div>
      </section>
    </>
  );
};
