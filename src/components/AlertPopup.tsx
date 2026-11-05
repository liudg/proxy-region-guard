import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  ShieldAlert,
  Skull,
  WifiOff,
  X,
} from 'lucide-react';
import { AlertPayload } from '../shared/types';
import { CountryFlag } from './CountryFlag';

function playAlertChime(type: AlertPayload['alertType']): void {
  if (type === 'recovered') return;
  try {
    const AudioCtx =
      window.AudioContext ||
      (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
    const ctx = new AudioCtx();
    const now = ctx.currentTime;

    const notes =
      type === 'mismatch' || type === 'locale-mismatch' ? [880, 622.25, 880] : [660, 440];
    notes.forEach((freq, idx) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(freq, now + idx * 0.14);

      gain.gain.setValueAtTime(0.001, now + idx * 0.14);
      gain.gain.exponentialRampToValueAtTime(0.18, now + idx * 0.14 + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.14 + 0.12);

      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now + idx * 0.14);
      osc.stop(now + idx * 0.14 + 0.13);
    });
  } catch {
    // ignore audio errors
  }
}

export const AlertPopup: React.FC = () => {
  const [payload, setPayload] = useState<AlertPayload | null>(null);
  const lastSoundTsRef = useRef<number>(0);

  useEffect(() => {
    void window.guardAPI.getAlertData().then((initial) => {
      if (initial) {
        setPayload(initial);
      }
    });

    const unsub = window.guardAPI.onAlertData((nextPayload) => {
      setPayload(nextPayload);
      if (nextPayload.soundEnabled && nextPayload.timestamp !== lastSoundTsRef.current) {
        lastSoundTsRef.current = nextPayload.timestamp;
        playAlertChime(nextPayload.alertType);
      }
    });

    return unsub;
  }, []);

  if (!payload) {
    return <div className="alert-shell-empty" />;
  }

  const isRecovered = payload.alertType === 'recovered';
  const isDisconnect = payload.alertType === 'disconnect';
  const isLocaleMismatch = payload.alertType === 'locale-mismatch';

  const cardClass = isRecovered
    ? 'alert-recovered'
    : isDisconnect
    ? 'alert-disconnect'
    : 'alert-mismatch';

  const titleText = isRecovered
    ? '代理出口已恢复正常'
    : isDisconnect
    ? '代理连接异常断开警告'
    : isLocaleMismatch
    ? '系统时区/区域不符 · 进程已拦截！'
    : '代理 IP 地区变更警告！';

  return (
    <div className={`alert-popup-card ${cardClass}`}>
      {/* 顶部可拖拽标题条 */}
      <div className="alert-header drag-region">
        <div className="alert-title-row">
          <span className="alert-pulse-icon">
            {isRecovered ? (
              <CheckCircle2 size={18} />
            ) : isDisconnect ? (
              <WifiOff size={18} />
            ) : isLocaleMismatch ? (
              <Clock size={18} />
            ) : (
              <ShieldAlert size={18} />
            )}
          </span>
          <span className="alert-title-text">{titleText}</span>
        </div>
        <button
          className="icon-close-btn no-drag"
          onClick={() => window.guardAPI.dismissAlert()}
          title="关闭提醒"
        >
          <X size={16} />
        </button>
      </div>

      {/* 核心地区对比区 */}
      <div className="alert-body">
        {isDisconnect ? (
          <div className="alert-disconnect-box">
            <div className="disconnect-expect-line">
              <span>受保护默认地区：</span>
              <CountryFlag code={payload.expectedCode} size="sm" />
              <strong>
                {payload.expectedName} ({payload.expectedCode})
              </strong>
            </div>
            <div className="disconnect-err-msg">
              <AlertTriangle size={15} />
              <span>{payload.errorDetail || '无法通过代理连接网络，请立即检查 VPN 状态！'}</span>
            </div>
          </div>
        ) : isLocaleMismatch ? (
          <div className="alert-compare-grid">
            <div className="compare-box expected">
              <span className="compare-label">保护/出口地区</span>
              <div className="compare-region-main">
                <CountryFlag code={payload.expectedCode} size="md" />
                <div className="compare-region-text">
                  <strong>{payload.expectedName || '未设'}</strong>
                  <small>{payload.expectedCode}</small>
                </div>
              </div>
            </div>

            <div className="compare-arrow">
              <ArrowRight size={18} />
            </div>

            <div className="compare-box actual danger">
              <span className="compare-label">当前系统区域</span>
              <div className="compare-region-main">
                <CountryFlag code={payload.sysRegionCode || 'CN'} size="md" />
                <div className="compare-region-text">
                  <strong>{payload.sysRegionName || '未知'}</strong>
                  <small title={payload.sysTimeZoneDisplay}>
                    {payload.sysTimeZoneDisplay || payload.sysRegionCode}
                  </small>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="alert-compare-grid">
            <div className="compare-box expected">
              <span className="compare-label">期望默认地区</span>
              <div className="compare-region-main">
                <CountryFlag code={payload.expectedCode} size="md" />
                <div className="compare-region-text">
                  <strong>{payload.expectedName || '未设'}</strong>
                  <small>{payload.expectedCode}</small>
                </div>
              </div>
            </div>

            <div className="compare-arrow">
              <ArrowRight size={18} />
            </div>

            <div className={`compare-box actual ${isRecovered ? 'ok' : 'danger'}`}>
              <span className="compare-label">{isRecovered ? '当前已恢复' : '当前实际出口'}</span>
              <div className="compare-region-main">
                <CountryFlag code={payload.actualCode} size="md" />
                <div className="compare-region-text">
                  <strong>{payload.actualName || '未知'}</strong>
                  <small>{payload.actualCode}</small>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 已强杀进程醒目提示条 */}
        {payload.killedProcesses && payload.killedProcesses.length > 0 && (
          <div className="alert-killed-banner">
            <Skull size={14} />
            <span className="ellipsis" title={payload.killedProcesses.join(', ')}>
              已强杀进程树：{payload.killedProcesses.join(', ')}
            </span>
          </div>
        )}

        {payload.killError && (
          <div className="alert-kill-error">
            <AlertTriangle size={13} />
            <span className="ellipsis" title={payload.killError}>
              {payload.killError}
            </span>
          </div>
        )}

        <div className="alert-meta-lines">
          {payload.actualIp && (
            <div className="alert-meta-item">
              <span className="meta-k">当前出口 IP：</span>
              <code className="meta-v">{payload.actualIp}</code>
              {payload.edgeLoc &&
                payload.actualCode &&
                payload.edgeLoc !== payload.actualCode && (
                  <span className="broadcast-tag">路由点: {payload.edgeLoc}</span>
                )}
            </div>
          )}
          <div className="alert-meta-item">
            <span className="meta-k">触发原因：</span>
            <span className="meta-v ellipsis" title={payload.triggerReason}>
              {payload.activeNode ? `[${payload.activeNode}] · ` : ''}
              {payload.triggerReason}
            </span>
          </div>
        </div>
      </div>

      {/* 底部快捷处置按钮 */}
      <div className="alert-actions no-drag">
        {!isRecovered &&
          !isDisconnect &&
          !isLocaleMismatch &&
          payload.actualCode &&
          payload.actualCode !== 'UNKNOWN' && (
            <button
              className="btn-alert-secondary"
              onClick={() => void window.guardAPI.acceptCurrentAsDefaultFromAlert()}
              title="如果你是主动切换了节点，可一键将当前新地区更新为默认"
            >
              设为新默认 ({payload.actualName})
            </button>
          )}
        <button
          className="btn-alert-ghost"
          onClick={() => window.guardAPI.openMainFromAlert()}
        >
          打开主面板
        </button>
        <button
          className="btn-alert-primary"
          onClick={() => window.guardAPI.dismissAlert()}
        >
          我知道了
        </button>
      </div>
    </div>
  );
};
