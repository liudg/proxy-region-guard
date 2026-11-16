import React, { useState } from 'react';
import { AppStateSnapshot, PrivateChannelId, PrivateChannelState } from '../shared/types';

const phases: Record<PrivateChannelState['phase'], string> = {
  idle: '尚未选择节点', starting: '正在启动', ready: '内核运行中', recovering: '正在恢复', error: '内核故障',
};

export const PrivateKernelStatus: React.FC<{
  channel: PrivateChannelId; state: PrivateChannelState; onState: (snapshot: AppStateSnapshot) => void;
}> = ({ channel, state, onState }) => {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const action = async (update: boolean) => {
    setBusy(true); setError(null);
    try { onState(await (update ? window.guardAPI.applyNodeUpdate(channel) : window.guardAPI.restartPrivateKernel(channel))); }
    catch (failure) { setError(failure instanceof Error ? failure.message : String(failure)); }
    finally { setBusy(false); }
  };
  return <div className="private-kernel-status">
    <div className="private-kernel-status-row">
      <strong>{phases[state.phase]}</strong>
      {state.pid && <span>PID {state.pid} · 127.0.0.1:{state.port}</span>}
      {state.nodeName && <button className="btn-secondary" disabled={busy || state.phase === 'starting' || state.phase === 'recovering'}
        onClick={() => void action(false)}>重新启动内核</button>}
    </div>
    {state.phase === 'recovering' && <p>自动恢复中（{state.restartAttempts}/3）</p>}
    {state.sourceStatus === 'changed' && <div className="private-kernel-status-row">
      <span>订阅节点已更新，当前仍用旧副本</span>
      <button className="btn-secondary" disabled={busy || state.phase === 'starting' || state.phase === 'recovering'} onClick={() => void action(true)}>应用节点更新</button>
    </div>}
    {state.sourceStatus === 'missing' && state.nodeName && <p>原节点已移除，当前仍用旧副本</p>}
    {state.sourceStatus === 'unknown' && state.sourceError && <p>订阅检查失败：{state.sourceError}</p>}
    {(error || state.error || state.verificationError) && <p role="alert" className="private-kernel-error">{error || state.error || state.verificationError}</p>}
  </div>;
};
