import React from 'react';
import { Check } from 'lucide-react';
import { getShortCountryNameZh } from '../../shared/countries';
import { FilteredProfileGroup, getDelayBadgeClass } from './nodeSelectorModel';

export interface NodeDropdownListProps {
  visibleGroups: FilteredProfileGroup[];
  selectedNode: string | null;
  effectiveProfileUid: string | null;
  highlightIndex: number;
  sortByDelay: boolean;
  searchQuery: string;
  activeFilterUid: string;
  activeRegionFilter: string;
  totalMatchedCount: number;
  listContainerRef: React.RefObject<HTMLDivElement>;
  onHoverIndex: (idx: number) => void;
  onChooseItem: (nodeName: string, groupUid: string) => void;
  onClearRegionFilter: () => void;
  onClearProfileFilter: () => void;
}

export const NodeDropdownList: React.FC<NodeDropdownListProps> = ({
  visibleGroups,
  selectedNode,
  effectiveProfileUid,
  highlightIndex,
  sortByDelay,
  searchQuery,
  activeFilterUid,
  activeRegionFilter,
  totalMatchedCount,
  listContainerRef,
  onHoverIndex,
  onChooseItem,
  onClearRegionFilter,
  onClearProfileFilter,
}) => {
  let runningFlatIdx = -1;

  return (
    <div className="node-dropdown-list" ref={listContainerRef}>
      {visibleGroups.length === 0 ? (
        <div className="node-dropdown-empty">
          <span>
            未找到匹配
            {searchQuery ? (
              <>
                {' '}
                “<strong>{searchQuery}</strong>”
              </>
            ) : null}
            {activeRegionFilter !== '__all__' ? (
              <>
                {' '}
                [<strong>{getShortCountryNameZh(activeRegionFilter)}</strong>]
              </>
            ) : null}{' '}
            的节点
          </span>
          <div className="empty-filter-actions">
            {activeRegionFilter !== '__all__' && (
              <button
                type="button"
                className="btn-reset-filter"
                onClick={onClearRegionFilter}
              >
                清除地区筛选
              </button>
            )}
            {activeFilterUid !== '__all__' && (
              <button
                type="button"
                className="btn-reset-filter"
                onClick={onClearProfileFilter}
              >
                在全部订阅组中搜索 ({totalMatchedCount})
              </button>
            )}
          </div>
        </div>
      ) : (
        visibleGroups.map((group) => (
          <div key={group.uid} className="node-group-section">
            <div className="node-group-header">
              <span className="group-status-tag">
                {group.isActive ? '🟢 Clash当前激活' : '📦 独立订阅组'}
              </span>
              <span className="group-title-name ellipsis">{group.name}</span>
              <span className="group-node-count">
                {group.filteredNodes.length}
                {group.filteredNodes.length !== group.nodeCount
                  ? ` / ${group.nodeCount}`
                  : ''}{' '}
                个节点
              </span>
            </div>

            {group.filteredNodes.map((item) => {
              const n = item.node;
              runningFlatIdx++;
              const flatIdx = runningFlatIdx;
              const isCurrentSelected =
                selectedNode === n.name &&
                (!effectiveProfileUid || effectiveProfileUid === group.uid);
              const isHighlighted = flatIdx === highlightIndex;
              const isDead = n.alive === false;

              return (
                <div
                  key={`${group.uid}:::${n.name}`}
                  data-flat-idx={flatIdx}
                  className={`node-option-item ${
                    isCurrentSelected ? 'selected' : ''
                  } ${isHighlighted ? 'highlighted' : ''} ${
                    isDead ? 'dead-node' : ''
                  }`}
                  onMouseEnter={() => onHoverIndex(flatIdx)}
                  onClick={() => onChooseItem(n.name, group.uid)}
                >
                  <span className="node-check-col">
                    {isCurrentSelected ? <Check size={13} /> : null}
                  </span>
                  {item.countryCode && (
                    <span
                      className="node-region-tag"
                      title={`识别地区: ${getShortCountryNameZh(item.countryCode)} (${item.countryCode})`}
                    >
                      {item.countryCode}
                    </span>
                  )}
                  <span className="node-option-name ellipsis" title={n.name}>
                    {n.name}
                  </span>
                  <div className="node-option-badges">
                    <span className="node-proto-pill">
                      {n.type.toUpperCase()}
                    </span>
                    {isDead ? (
                      <span
                        className="node-delay-pill delay-timeout"
                        title="最近一次 Clash 测速超时或不可用"
                      >
                        超时
                      </span>
                    ) : n.delay && n.delay > 0 ? (
                      <span
                        className={`node-delay-pill ${getDelayBadgeClass(n.delay)}`}
                      >
                        {n.delay}ms
                      </span>
                    ) : sortByDelay ? (
                      <span
                        className="node-delay-pill delay-untested"
                        title={
                          group.isActive
                            ? '该节点暂无 Clash 测速记录'
                            : '未激活订阅组节点，绑定后将由专属通道自动测速'
                        }
                      >
                        未测速
                      </span>
                    ) : null}
                  </div>
                </div>
              );
            })}
          </div>
        ))
      )}
    </div>
  );
};
