import React from 'react';
import { Download, Minus, RefreshCw, Sparkles, X } from 'lucide-react';
import { UpdateStateSnapshot } from '../../shared/types';

export interface DashboardTitlebarProps {
  titlebarDotClass: string;
  hasNewUpdate: boolean;
  updateState: UpdateStateSnapshot;
  updateModalOpen: boolean;
  closeButtonTitle: string;
  onToggleUpdateModal: () => void;
  onMinimize: () => void;
  onClose: () => void;
}

export const DashboardTitlebar: React.FC<DashboardTitlebarProps> = ({
  titlebarDotClass,
  hasNewUpdate,
  updateState,
  updateModalOpen,
  closeButtonTitle,
  onToggleUpdateModal,
  onMinimize,
  onClose,
}) => {
  return (
    <header className="titlebar drag-region">
      <div className="titlebar-brand">
        <span className={`brand-dot ${titlebarDotClass}`} />
        <span className="brand-name">代理地区卫士</span>
        {!hasNewUpdate && <span className="brand-sub">Proxy Region Guard</span>}
        <span className="brand-version">v{updateState.currentVersion}</span>
      </div>
      <div className="titlebar-controls no-drag">
        {hasNewUpdate && updateState.latestVersion && (
          <button
            type="button"
            className={`titlebar-update-pill ${
              updateState.status === 'downloaded' || updateState.status === 'applying'
                ? 'ready'
                : updateState.status === 'downloading'
                ? 'downloading'
                : 'available'
            } ${updateModalOpen ? 'active' : ''}`}
            onClick={onToggleUpdateModal}
            title={
              updateState.status === 'downloaded'
                ? `新版本 v${updateState.latestVersion} 已验签就绪，点击打开更新浮层`
                : updateState.status === 'downloading'
                ? `正在后台下载新版本 v${updateState.latestVersion} (${
                    updateState.progressPercent ?? 0
                  }%)`
                : `发现新版本 v${updateState.latestVersion}，点击查看详情并更新`
            }
          >
            {updateState.status === 'downloaded' || updateState.status === 'applying' ? (
              <>
                <Sparkles size={11} />
                <span className="update-pill-label">
                  新版 v{updateState.latestVersion} 已就绪
                </span>
              </>
            ) : updateState.status === 'downloading' ? (
              <>
                <RefreshCw className="spin" size={11} />
                <span className="update-pill-label">
                  更新下载 {updateState.progressPercent ?? 0}%
                </span>
              </>
            ) : (
              <>
                <span className="update-pill-dot" />
                <Download size={11} />
                <span className="update-pill-label">
                  发现 v{updateState.latestVersion}
                </span>
              </>
            )}
          </button>
        )}
        <button className="win-btn" onClick={onMinimize} title="最小化">
          <Minus size={15} />
        </button>
        <button
          className="win-btn win-close"
          onClick={onClose}
          title={closeButtonTitle}
        >
          <X size={15} />
        </button>
      </div>
    </header>
  );
};
