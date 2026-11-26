import React from 'react';
import { Layers } from 'lucide-react';
import { ClashProfileGroupOption } from '../../shared/types';
import { RegionFilterOption } from './nodeSelectorModel';

export interface NodeFilterBarsProps {
  profileGroups: ClashProfileGroupOption[];
  regionOptions: RegionFilterOption[];
  activeFilterUid: string;
  activeRegionFilter: string;
  selectedNode: string | null;
  effectiveProfileUid: string | null;
  isFilteringByQueryOrRegion: boolean;
  totalNodeCount: number;
  totalMatchedCount: number;
  matchedCountByGroupUid: Map<string, number>;
  isDraggingPills: boolean;
  pillsBarRef: React.RefObject<HTMLDivElement>;
  regionBarRef: React.RefObject<HTMLDivElement>;
  onPillsMouseDown: (e: React.MouseEvent<HTMLDivElement>) => void;
  onPillsMouseMove: (e: React.MouseEvent<HTMLDivElement>) => void;
  onPillsMouseUpOrLeave: () => void;
  onPillsClickCapture: (e: React.MouseEvent<HTMLDivElement>) => void;
  onSelectProfilePill: (uid: string, btnEl: HTMLButtonElement) => void;
  onSelectRegionPill: (code: string, btnEl: HTMLButtonElement) => void;
}

export const NodeFilterBars: React.FC<NodeFilterBarsProps> = ({
  profileGroups,
  regionOptions,
  activeFilterUid,
  activeRegionFilter,
  selectedNode,
  effectiveProfileUid,
  isFilteringByQueryOrRegion,
  totalNodeCount,
  totalMatchedCount,
  matchedCountByGroupUid,
  isDraggingPills,
  pillsBarRef,
  regionBarRef,
  onPillsMouseDown,
  onPillsMouseMove,
  onPillsMouseUpOrLeave,
  onPillsClickCapture,
  onSelectProfilePill,
  onSelectRegionPill,
}) => {
  return (
    <>
      {profileGroups.length > 1 && (
        <div
          ref={pillsBarRef}
          className={`profile-pills-bar ${isDraggingPills ? 'dragging' : ''}`}
          onMouseDown={onPillsMouseDown}
          onMouseMove={onPillsMouseMove}
          onMouseUp={onPillsMouseUpOrLeave}
          onMouseLeave={onPillsMouseUpOrLeave}
          onClickCapture={onPillsClickCapture}
        >
          <button
            type="button"
            className={`profile-filter-pill ${
              activeFilterUid === '__all__' ? 'active' : ''
            }`}
            onClick={(e) => onSelectProfilePill('__all__', e.currentTarget)}
          >
            <Layers size={12} />
            <span>
              全部订阅 (
              {isFilteringByQueryOrRegion
                ? `${totalMatchedCount}/${totalNodeCount}`
                : totalNodeCount}
              )
            </span>
          </button>
          {profileGroups.map((g) => {
            const matchedCount = matchedCountByGroupUid.get(g.uid) ?? g.nodeCount;
            const isZeroMatch = isFilteringByQueryOrRegion && matchedCount === 0;
            const isBoundGroup =
              Boolean(selectedNode) && effectiveProfileUid === g.uid;
            return (
              <button
                type="button"
                key={g.uid}
                className={`profile-filter-pill ${
                  activeFilterUid === g.uid ? 'active' : ''
                } ${isZeroMatch ? 'zero-match' : ''} ${
                  isBoundGroup ? 'bound-group' : ''
                }`}
                onClick={(e) => onSelectProfilePill(g.uid, e.currentTarget)}
                title={
                  g.isActive
                    ? `Clash 当前激活订阅: ${g.name}${
                        isBoundGroup ? '（含当前已选节点）' : ''
                      }`
                    : `独立订阅组: ${g.name}${
                        isBoundGroup ? '（含当前已选节点）' : ''
                      }`
                }
              >
                <span className="prof-dot">{g.isActive ? '🟢' : '📦'}</span>
                <span className="ellipsis">{g.name}</span>
                <span className="prof-count">
                  {isFilteringByQueryOrRegion
                    ? `${matchedCount}/${g.nodeCount}`
                    : g.nodeCount}
                </span>
              </button>
            );
          })}
        </div>
      )}

      {regionOptions.length > 0 && (
        <div ref={regionBarRef} className="region-pills-bar">
          <button
            type="button"
            className={`region-filter-pill ${
              activeRegionFilter === '__all__' ? 'active' : ''
            }`}
            onClick={(e) => onSelectRegionPill('__all__', e.currentTarget)}
          >
            <span>全部地区</span>
          </button>
          {regionOptions.map((reg) => (
            <button
              type="button"
              key={reg.code}
              className={`region-filter-pill ${
                activeRegionFilter === reg.code ? 'active' : ''
              }`}
              onClick={(e) => onSelectRegionPill(reg.code, e.currentTarget)}
              title={`仅筛选 ${reg.label} (${reg.code}) 节点 · 共 ${reg.count} 个`}
            >
              <span className="region-pill-code">{reg.code}</span>
              <span>{reg.label}</span>
              <span className="region-pill-count">{reg.count}</span>
            </button>
          ))}
        </div>
      )}
    </>
  );
};
