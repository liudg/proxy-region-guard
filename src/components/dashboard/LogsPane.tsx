import React from 'react';
import { History, Trash2 } from 'lucide-react';
import { GuardEventLog } from '../../shared/types';
import { formatTime } from './dashboardTypes';

export interface LogsPaneProps {
  logs: GuardEventLog[];
  onClearLogs: () => void;
}

export const LogsPane: React.FC<LogsPaneProps> = ({ logs, onClearLogs }) => {
  return (
    <div className="tab-pane">
      <section className="panel-card logs-card">
        <div className="panel-card-header">
          <div className="panel-title">
            <History size={15} />
            <span>最近状态与变更记录</span>
          </div>
          {logs.length > 0 && (
            <button className="btn-link-clear" onClick={onClearLogs}>
              <Trash2 size={13} />
              <span>清空记录</span>
            </button>
          )}
        </div>

        {logs.length === 0 ? (
          <div className="logs-empty">暂无变更记录</div>
        ) : (
          <div className="logs-list">
            {logs.map((item) => (
              <div key={item.id} className={`log-item log-${item.level}`}>
                <span className="log-time">{formatTime(item.timestamp)}</span>
                <span className="log-msg">{item.message}</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};
