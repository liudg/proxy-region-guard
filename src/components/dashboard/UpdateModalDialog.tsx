import React from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ExternalLink,
  Info,
  RefreshCw,
  Sparkles,
  X,
} from 'lucide-react';
import { UpdateStateSnapshot } from '../../shared/types';
import { FeedbackMessage, formatTime } from './dashboardTypes';
import { UpdateReleaseCard } from './UpdateReleaseCard';

export interface UpdateModalDialogProps {
  open: boolean;
  hasNewUpdate: boolean;
  updateState: UpdateStateSnapshot;
  updateFeedback: FeedbackMessage | null;
  isApplyingUpdate: boolean;
  isUpdateBusy: boolean;
  pendingUpdateConfirm: boolean;
  isClaudeActiveForUpdate: boolean;
  onCloseModal: () => void;
  onOpenReleasePage: () => void;
  onCheckForUpdates: () => void;
  onDownloadUpdate: () => void;
  onClickApplyUpdate: () => void;
  onConfirmApplyUpdate: () => void;
  onCancelUpdateConfirm: () => void;
}

export const UpdateModalDialog: React.FC<UpdateModalDialogProps> = ({
  open,
  hasNewUpdate,
  updateState,
  updateFeedback,
  isApplyingUpdate,
  isUpdateBusy,
  pendingUpdateConfirm,
  isClaudeActiveForUpdate,
  onCloseModal,
  onOpenReleasePage,
  onCheckForUpdates,
  onDownloadUpdate,
  onClickApplyUpdate,
  onConfirmApplyUpdate,
  onCancelUpdateConfirm,
}) => {
  if (!open) {
    return null;
  }

  return (
    <div
      className="update-modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) {
          onCloseModal();
        }
      }}
    >
      <div className="update-modal-dialog" role="dialog" aria-modal="true">
        <div className="update-modal-header">
          <div className="panel-title">
            <Sparkles size={15} />
            <span>
              {hasNewUpdate
                ? updateState.status === 'downloaded' ||
                  updateState.status === 'applying'
                  ? '新版本已验签就绪'
                  : '发现新版本更新'
                : '版本更新检查'}
            </span>
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
              className="update-modal-close"
              disabled={isApplyingUpdate || updateState.status === 'applying'}
              onClick={onCloseModal}
              title="关闭"
            >
              <X size={15} />
            </button>
          </div>
        </div>

        {updateFeedback && (
          <div className={`locale-feedback ${updateFeedback.ok ? 'ok' : 'err'}`}>
            {updateFeedback.ok ? <Check size={14} /> : <AlertTriangle size={14} />}
            <span>{updateFeedback.text}</span>
          </div>
        )}

        {hasNewUpdate && Boolean(updateState.error) && !updateFeedback && (
          <div className="locale-feedback err">
            <AlertTriangle size={14} />
            <span>{updateState.error}</span>
          </div>
        )}

        {hasNewUpdate ? (
          <UpdateReleaseCard
            inModal={true}
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
            onCloseModal={onCloseModal}
          />
        ) : (
          <div className="update-modal-empty">
            {updateState.status === 'checking' ? (
              <div className="update-modal-status-row">
                <RefreshCw className="spin" size={18} />
                <span>正在连接更新源并校验 Ed25519 数字签名...</span>
              </div>
            ) : updateState.status === 'error' ? (
              <div className="update-modal-status-row is-error">
                <AlertTriangle size={18} />
                <div>
                  <strong>版本更新检查未通过</strong>
                  <p>
                    {updateState.error ||
                      '连接更新服务器失败，请检查网络或代理状态后重试'}
                  </p>
                </div>
              </div>
            ) : updateState.lastSuccessfulCheckAt !== null ? (
              <div className="update-modal-status-row">
                <CheckCircle2 size={18} className="pulse-green" />
                <div>
                  <strong>当前已是最新版本 (v{updateState.currentVersion})</strong>
                  {updateState.lastCheckedAt && (
                    <p>上次检查于 {formatTime(updateState.lastCheckedAt)}</p>
                  )}
                </div>
              </div>
            ) : (
              <div className="update-modal-status-row">
                <Info size={18} />
                <div>
                  <strong>当前版本 v{updateState.currentVersion}</strong>
                  <p>尚未执行检查，点击下方按钮可立即检测最新版本</p>
                </div>
              </div>
            )}
            <div className="update-action-row">
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
                  {updateState.status === 'checking'
                    ? '正在检查...'
                    : updateState.lastCheckedAt
                    ? '重新检查'
                    : '立即检查'}
                </span>
              </button>
              <button
                type="button"
                className="btn-update-secondary"
                onClick={onCloseModal}
              >
                关闭
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
