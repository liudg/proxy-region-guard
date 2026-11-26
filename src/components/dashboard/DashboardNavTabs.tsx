import React from 'react';
import { Activity, History, Rocket, Settings } from 'lucide-react';
import { UpdateStatus } from '../../shared/types';
import { ActiveTab } from './dashboardTypes';

export interface DashboardNavTabsProps {
  activeTab: ActiveTab;
  launcherTabDotClass: string;
  killProcessesEnabled: boolean;
  protectedPatternCount: number;
  hasNewUpdate: boolean;
  updateStatus: UpdateStatus;
  logsCount: number;
  onSelectTab: (tab: ActiveTab) => void;
}

export const DashboardNavTabs: React.FC<DashboardNavTabsProps> = ({
  activeTab,
  launcherTabDotClass,
  killProcessesEnabled,
  protectedPatternCount,
  hasNewUpdate,
  updateStatus,
  logsCount,
  onSelectTab,
}) => {
  return (
    <nav className="nav-tabs">
      <button
        className={`nav-tab ${activeTab === 'launcher' ? 'active' : ''}`}
        onClick={() => onSelectTab('launcher')}
      >
        <Rocket size={14} />
        <span>启动器</span>
        <span className={`tab-status-dot ${launcherTabDotClass}`} />
      </button>
      <button
        className={`nav-tab ${activeTab === 'monitor' ? 'active' : ''}`}
        onClick={() => onSelectTab('monitor')}
      >
        <Activity size={14} />
        <span>实时监控</span>
        {killProcessesEnabled && protectedPatternCount > 0 && (
          <span className="tab-count">{protectedPatternCount}</span>
        )}
      </button>
      <button
        className={`nav-tab ${activeTab === 'settings' ? 'active' : ''}`}
        onClick={() => onSelectTab('settings')}
      >
        <Settings size={14} />
        <span>设置</span>
        {hasNewUpdate && (
          <span
            className={`tab-status-dot ${
              updateStatus === 'downloaded' ? 'running' : 'external'
            }`}
          />
        )}
      </button>
      <button
        className={`nav-tab ${activeTab === 'logs' ? 'active' : ''}`}
        onClick={() => onSelectTab('logs')}
      >
        <History size={14} />
        <span>日志</span>
        {logsCount > 0 && <span className="tab-count">{logsCount}</span>}
      </button>
    </nav>
  );
};
