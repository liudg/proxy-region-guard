import React from 'react';
import {
  AlertTriangle,
  Download,
  ExternalLink,
  RefreshCw,
  Rocket,
  ShieldCheck,
} from 'lucide-react';
import { UpdateStateSnapshot } from '../../shared/types';
import { formatBytes, formatReleaseDate } from './dashboardTypes';

export interface UpdateReleaseCardProps {
  inModal: boolean;
  hasNewUpdate: boolean;
  updateState: UpdateStateSnapshot;
  isApplyingUpdate: boolean;
  isUpdateBusy: boolean;
  pendingUpdateConfirm: boolean;
  isClaudeActiveForUpdate: boolean;
  onConfirmApplyUpdate: () => void;
  onCancelUpdateConfirm: () => void;
  onOpenReleasePage: () => void;
  onClickApplyUpdate: () => void;
  onDownloadUpdate: () => void;
  onCloseModal?: () => void;
}

export const UpdateReleaseCard: React.FC<UpdateReleaseCardProps> = ({
  inModal,
  hasNewUpdate,
  updateState,
  isApplyingUpdate,
  isUpdateBusy,
  pendingUpdateConfirm,
  isClaudeActiveForUpdate,
  onConfirmApplyUpdate,
  onCancelUpdateConfirm,
  onOpenReleasePage,
  onClickApplyUpdate,
  onDownloadUpdate,
  onCloseModal,
}) => {
  if (!hasNewUpdate || !updateState.latestVersion) {
    return null;
  }

  return (
    <div className={`update-release-box ${inModal ? 'in-modal' : ''}`}>
      <div className="update-release-top">
        <div className="update-version-jump">
          <span className="ver-old">v{updateState.currentVersion}</span>
          <span className="ver-arrow">→</span>
          <span className="ver-new">v{updateState.latestVersion}</span>
          {updateState.publishedAt && formatReleaseDate(updateState.publishedAt) && (
            <span className="update-pub-date">
              {formatReleaseDate(updateState.publishedAt)}
            </span>
          )}
        </div>
        <div className="update-badges-row">
          {!updateState.isPackaged ? (
            <span className="update-tag source-mode">🛠️ 源码模式 · 仅提示</span>
          ) : (
            updateState.deliveryMode && (
              <span className="update-tag mode">
                {updateState.deliveryMode === 'asar'
                  ? `⚡ 增量热更 · ${formatBytes(updateState.downloadTotalBytes)}${
                      updateState.includeMmdbUpdate ? ' (含新离线库)' : ''
                    }`
                  : `📦 完整包 · ${formatBytes(updateState.downloadTotalBytes)}`}
              </span>
            )
          )}
          {updateState.signatureVerified && (
            <span className="update-tag verified">
              <ShieldCheck size={11} />
              <span>Ed25519 已验签</span>
            </span>
          )}
        </div>
      </div>

      <div className={`update-notes-box ${inModal ? 'in-modal' : ''}`}>
        {updateState.releaseNotes || '暂无版本更新日志说明'}
      </div>

      {updateState.status === 'downloading' && (
        <div className="update-progress-wrap">
          <div className="update-progress-track">
            <div
              className="update-progress-fill"
              style={{
                width: `${Math.max(2, updateState.progressPercent ?? 0)}%`,
              }}
            />
          </div>
          <div className="update-progress-meta">
            <span>正在下载并校验完整性...</span>
            <span>
              {updateState.progressPercent ?? 0}% (
              {formatBytes(updateState.downloadedBytes)} /{' '}
              {formatBytes(updateState.downloadTotalBytes)})
            </span>
          </div>
        </div>
      )}

      {pendingUpdateConfirm && isClaudeActiveForUpdate && (
        <div className="inline-confirm-bar">
          <div className="confirm-bar-text">
            <AlertTriangle size={15} />
            <span>
              Claude 正在受控守护运行中，重启更新将先安全终止当前 Claude 会话（保持 Antigravity 正常运行），并在完成替换后自动重新启动本程序。
            </span>
          </div>
          <div className="confirm-bar-actions">
            <button
              type="button"
              className="btn-confirm-danger"
              disabled={isApplyingUpdate || updateState.status === 'applying'}
              onClick={onConfirmApplyUpdate}
            >
              确认终止 Claude 并立即更新
            </button>
            <button
              type="button"
              className="btn-confirm-cancel"
              disabled={isApplyingUpdate || updateState.status === 'applying'}
              onClick={onCancelUpdateConfirm}
            >
              取消
            </button>
          </div>
        </div>
      )}

      <div className="update-action-row">
        {!updateState.isPackaged ? (
          <button
            type="button"
            className="btn-update-primary"
            onClick={onOpenReleasePage}
          >
            <ExternalLink size={14} />
            <span>前往 GitHub Release 下载正式包</span>
          </button>
        ) : updateState.status === 'downloaded' || updateState.status === 'applying' ? (
          <button
            type="button"
            className="btn-update-ready"
            disabled={isApplyingUpdate || updateState.status === 'applying'}
            onClick={onClickApplyUpdate}
          >
            <Rocket size={14} />
            <span>
              {isApplyingUpdate || updateState.status === 'applying'
                ? '正在启动更新助手并重启...'
                : `立即重启并更新至 v${updateState.latestVersion}`}
            </span>
          </button>
        ) : updateState.status === 'downloading' ? (
          <button type="button" className="btn-update-primary" disabled>
            <RefreshCw className="spin" size={14} />
            <span>正在后台下载更新包...</span>
          </button>
        ) : updateState.status === 'checking' ? (
          <button type="button" className="btn-update-primary" disabled>
            <RefreshCw className="spin" size={14} />
            <span>正在刷新版本信息...</span>
          </button>
        ) : (
          <button
            type="button"
            className="btn-update-primary"
            disabled={isUpdateBusy}
            onClick={onDownloadUpdate}
          >
            <Download size={14} />
            <span>
              {updateState.status === 'error'
                ? `重试下载更新包 (${formatBytes(updateState.downloadTotalBytes)})`
                : `下载更新包 (${formatBytes(updateState.downloadTotalBytes)})`}
            </span>
          </button>
        )}

        {inModal && onCloseModal && (
          <button
            type="button"
            className="btn-update-secondary"
            disabled={isApplyingUpdate || updateState.status === 'applying'}
            onClick={onCloseModal}
          >
            稍后
          </button>
        )}
      </div>
    </div>
  );
};
