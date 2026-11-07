import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Check,
  ChevronDown,
  ChevronUp,
  Layers,
  Search,
  ShieldCheck,
  X,
} from 'lucide-react';
import {
  ClashProfileGroupOption,
  ClashProxyNodeOption,
  ClashRuntimeInfo,
} from '../shared/types';

export interface ClashNodeSelectorProps {
  appLabel: string;
  clashInfo: ClashRuntimeInfo;
  selectedNode: string | null;
  selectedProfileUid: string | null;
  selectedProfileName: string | null;
  boundProfileUid: string | null;
  boundProfileName: string | null;
  dedicatedPort: number;
  portListening: boolean;
  isSwitching: boolean;
  onSelectNode: (nodeName: string | null, profileUid: string | null) => void;
}

interface FlatNodeItem {
  groupUid: string;
  groupName: string;
  groupIsActive: boolean;
  node: ClashProxyNodeOption;
}

function getDelayBadgeClass(delay?: number): string {
  if (!delay || delay <= 0) return 'delay-none';
  if (delay < 180) return 'delay-fast';
  if (delay < 420) return 'delay-medium';
  return 'delay-slow';
}

export const ClashNodeSelector: React.FC<ClashNodeSelectorProps> = ({
  appLabel,
  clashInfo,
  selectedNode,
  selectedProfileUid,
  selectedProfileName,
  boundProfileUid,
  boundProfileName,
  dedicatedPort,
  portListening,
  isSwitching,
  onSelectNode,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [profileFilter, setProfileFilter] = useState<string>('__all__');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [highlightIndex, setHighlightIndex] = useState<number>(0);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const listContainerRef = useRef<HTMLDivElement | null>(null);

  const profileGroups: ClashProfileGroupOption[] = useMemo(() => {
    if (clashInfo.profileGroups && clashInfo.profileGroups.length > 0) {
      return clashInfo.profileGroups;
    }
    const concrete = clashInfo.availableNodes.filter((n) => !n.isGroup);
    if (concrete.length === 0) return [];
    return [
      {
        uid: '__runtime_active__',
        name: clashInfo.activeProfileName || '当前运行配置',
        type: 'runtime',
        isActive: true,
        nodeCount: concrete.length,
        nodes: concrete,
      },
    ];
  }, [clashInfo.profileGroups, clashInfo.availableNodes, clashInfo.activeProfileName]);

  const matchedNodeObj = useMemo(() => {
    if (!selectedNode) return undefined;
    return (
      clashInfo.availableNodes.find(
        (n) =>
          n.name === selectedNode &&
          (!selectedProfileUid || n.profileUid === selectedProfileUid)
      ) || clashInfo.availableNodes.find((n) => n.name === selectedNode)
    );
  }, [clashInfo.availableNodes, selectedNode, selectedProfileUid]);

  const effectiveProfileUid =
    selectedProfileUid || matchedNodeObj?.profileUid || boundProfileUid || null;

  const effectiveProfileName =
    selectedProfileName || matchedNodeObj?.profileName || boundProfileName || null;

  const isSelectedProfileActive = useMemo(() => {
    if (!effectiveProfileUid) return true;
    const grp = profileGroups.find((g) => g.uid === effectiveProfileUid);
    if (grp) return grp.isActive;
    return !clashInfo.activeProfileUid || effectiveProfileUid === clashInfo.activeProfileUid;
  }, [effectiveProfileUid, profileGroups, clashInfo.activeProfileUid]);

  const isCrossProfileBound = Boolean(
    selectedNode &&
      effectiveProfileUid &&
      clashInfo.activeProfileUid &&
      effectiveProfileUid !== clashInfo.activeProfileUid
  );

  const activeFilterUid =
    profileFilter === '__all__' || profileGroups.some((g) => g.uid === profileFilter)
      ? profileFilter
      : '__all__';

  const searchLower = searchQuery.trim().toLowerCase();

  const visibleGroups = useMemo(() => {
    return profileGroups
      .filter((g) => activeFilterUid === '__all__' || g.uid === activeFilterUid)
      .map((g) => ({
        ...g,
        filteredNodes: g.nodes.filter((n) => {
          if (!searchLower) return true;
          return (
            n.name.toLowerCase().includes(searchLower) ||
            n.type.toLowerCase().includes(searchLower) ||
            g.name.toLowerCase().includes(searchLower)
          );
        }),
      }))
      .filter((g) => g.filteredNodes.length > 0);
  }, [profileGroups, activeFilterUid, searchLower]);

  const flatItems: FlatNodeItem[] = useMemo(() => {
    const out: FlatNodeItem[] = [];
    for (const g of visibleGroups) {
      for (const n of g.filteredNodes) {
        out.push({
          groupUid: g.uid,
          groupName: g.name,
          groupIsActive: g.isActive,
          node: n,
        });
      }
    }
    return out;
  }, [visibleGroups]);

  // 展开下拉面板时自动聚焦搜索输入框
  useEffect(() => {
    if (isOpen) {
      setHighlightIndex(0);
      requestAnimationFrame(() => {
        searchInputRef.current?.focus();
      });
    }
  }, [isOpen]);

  // 搜索词或订阅筛选变化时重置高亮项到第一项
  useEffect(() => {
    setHighlightIndex(0);
  }, [searchLower, activeFilterUid]);

  // 点击组件外部自动收起下拉面板
  useEffect(() => {
    if (!isOpen) return;
    const handleMouseDownOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleMouseDownOutside);
    return () => {
      document.removeEventListener('mousedown', handleMouseDownOutside);
    };
  }, [isOpen]);

  const handleOpenPanel = () => {
    if (isSwitching || (clashInfo.availableNodes.length === 0 && !selectedNode)) {
      return;
    }
    setIsOpen(true);
  };

  const handleChooseItem = (nodeName: string, groupUid: string | null) => {
    setIsOpen(false);
    setSearchQuery('');
    onSelectNode(nodeName, groupUid);
  };

  const handleClearSelection = (e: React.MouseEvent) => {
    e.stopPropagation();
    setIsOpen(false);
    setSearchQuery('');
    onSelectNode(null, null);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      setIsOpen(false);
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (flatItems.length > 0) {
        const nextIdx = (highlightIndex + 1) % flatItems.length;
        setHighlightIndex(nextIdx);
        scrollToHighlightedItem(nextIdx);
      }
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (flatItems.length > 0) {
        const nextIdx = (highlightIndex - 1 + flatItems.length) % flatItems.length;
        setHighlightIndex(nextIdx);
        scrollToHighlightedItem(nextIdx);
      }
      return;
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      const target = flatItems[highlightIndex];
      if (target) {
        handleChooseItem(target.node.name, target.groupUid);
      }
    }
  };

  const scrollToHighlightedItem = (idx: number) => {
    const container = listContainerRef.current;
    if (!container) return;
    const el = container.querySelector(`[data-flat-idx="${idx}"]`) as HTMLElement | null;
    if (el) {
      el.scrollIntoView({ block: 'nearest' });
    }
  };

  const totalNodeCount = clashInfo.availableNodes.length;
  const isDisabled = isSwitching || (totalNodeCount === 0 && !selectedNode);

  let runningFlatIdx = -1;

  return (
    <div className="clash-node-selector-wrap" ref={containerRef}>
      {/* 一体化可搜索节点选择框（点击直接激活搜索并展开实时列表） */}
      <div className={`node-combobox ${isOpen ? 'open' : ''} ${isDisabled ? 'disabled' : ''}`}>
        {!isOpen ? (
          <div
            className="node-combobox-trigger"
            onClick={handleOpenPanel}
            role="button"
            tabIndex={isDisabled ? -1 : 0}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                handleOpenPanel();
              }
            }}
          >
            {selectedNode ? (
              <div className="selected-node-summary">
                {effectiveProfileName && (
                  <span
                    className={`selected-profile-pill ${
                      isSelectedProfileActive ? 'active-prof' : 'cross-prof'
                    }`}
                    title={`归属订阅组: ${effectiveProfileName}`}
                  >
                    {isSelectedProfileActive ? '🟢' : '📦'} {effectiveProfileName}
                  </span>
                )}
                <span className="selected-node-name ellipsis" title={selectedNode}>
                  {selectedNode}
                </span>
                {matchedNodeObj ? (
                  <span className="node-proto-pill">
                    {matchedNodeObj.type.toUpperCase()}
                  </span>
                ) : (
                  <span className="node-proto-pill cached">已缓存定义</span>
                )}
                {matchedNodeObj?.delay && matchedNodeObj.delay > 0 ? (
                  <span className={`node-delay-pill ${getDelayBadgeClass(matchedNodeObj.delay)}`}>
                    {matchedNodeObj.delay}ms
                  </span>
                ) : null}
              </div>
            ) : (
              <div className="unselected-node-placeholder">
                <Search size={14} className="placeholder-search-icon" />
                <span>
                  {totalNodeCount > 0
                    ? `点击搜索或选择任意订阅组的落地节点 (${profileGroups.length} 个订阅 · 共 ${totalNodeCount} 个)...`
                    : clashInfo.connected
                    ? '未扫描到可用具体节点...'
                    : '未连接 Clash Verge Rev 控制接口...'}
                </span>
              </div>
            )}

            <div className="node-combobox-actions">
              {selectedNode && (
                <button
                  type="button"
                  className="btn-inline-clear-node"
                  disabled={isSwitching}
                  onClick={handleClearSelection}
                  title={`取消 ${appLabel} 专属节点绑定`}
                >
                  <X size={13} />
                </button>
              )}
              <span className="combobox-chevron">
                <ChevronDown size={15} />
              </span>
            </div>
          </div>
        ) : (
          <div className="node-combobox-search-header">
            <Search size={14} className="active-search-icon" />
            <input
              ref={searchInputRef}
              type="text"
              className="combobox-live-input"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="输入国家、地区、节点名或协议即时过滤 (↑↓选择 · Enter确认)..."
            />
            {searchQuery && (
              <button
                type="button"
                className="btn-clear-query"
                onClick={() => {
                  setSearchQuery('');
                  searchInputRef.current?.focus();
                }}
                title="清空搜索词"
              >
                <X size={13} />
              </button>
            )}
            <button
              type="button"
              className="btn-collapse-dropdown"
              onClick={() => setIsOpen(false)}
              title="收起列表 (Esc)"
            >
              <ChevronUp size={15} />
            </button>
          </div>
        )}

        {/* 展开态：订阅组筛选胶囊栏 + 实时过滤节点列表 */}
        {isOpen && (
          <div className="node-dropdown-panel">
            {profileGroups.length > 1 && (
              <div className="profile-pills-bar">
                <button
                  type="button"
                  className={`profile-filter-pill ${
                    activeFilterUid === '__all__' ? 'active' : ''
                  }`}
                  onClick={() => {
                    setProfileFilter('__all__');
                    searchInputRef.current?.focus();
                  }}
                >
                  <Layers size={12} />
                  <span>全部订阅 ({totalNodeCount})</span>
                </button>
                {profileGroups.map((g) => (
                  <button
                    type="button"
                    key={g.uid}
                    className={`profile-filter-pill ${
                      activeFilterUid === g.uid ? 'active' : ''
                    }`}
                    onClick={() => {
                      setProfileFilter(g.uid);
                      searchInputRef.current?.focus();
                    }}
                    title={
                      g.isActive
                        ? `Clash 当前激活订阅: ${g.name}`
                        : `独立订阅组: ${g.name}（选择后将自动跨订阅注入内核）`
                    }
                  >
                    <span className="prof-dot">{g.isActive ? '🟢' : '📦'}</span>
                    <span className="ellipsis">{g.name}</span>
                    <span className="prof-count">{g.nodeCount}</span>
                  </button>
                ))}
              </div>
            )}

            <div className="node-dropdown-list" ref={listContainerRef}>
              {visibleGroups.length === 0 ? (
                <div className="node-dropdown-empty">
                  <span>
                    未找到包含 “<strong>{searchQuery}</strong>” 的节点
                  </span>
                  {activeFilterUid !== '__all__' && (
                    <button
                      type="button"
                      className="btn-reset-filter"
                      onClick={() => setProfileFilter('__all__')}
                    >
                      在全部订阅组中搜索
                    </button>
                  )}
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
                        {group.filteredNodes.length} 个节点
                      </span>
                    </div>

                    {group.filteredNodes.map((n) => {
                      runningFlatIdx++;
                      const flatIdx = runningFlatIdx;
                      const isCurrentSelected =
                        selectedNode === n.name &&
                        (!effectiveProfileUid || effectiveProfileUid === group.uid);
                      const isHighlighted = flatIdx === highlightIndex;

                      return (
                        <div
                          key={`${group.uid}:::${n.name}`}
                          data-flat-idx={flatIdx}
                          className={`node-option-item ${
                            isCurrentSelected ? 'selected' : ''
                          } ${isHighlighted ? 'highlighted' : ''}`}
                          onMouseEnter={() => setHighlightIndex(flatIdx)}
                          onClick={() => handleChooseItem(n.name, group.uid)}
                        >
                          <span className="node-check-col">
                            {isCurrentSelected ? <Check size={13} /> : null}
                          </span>
                          <span className="node-option-name ellipsis" title={n.name}>
                            {n.name}
                          </span>
                          <div className="node-option-badges">
                            <span className="node-proto-pill">
                              {n.type.toUpperCase()}
                            </span>
                            {n.delay && n.delay > 0 ? (
                              <span
                                className={`node-delay-pill ${getDelayBadgeClass(n.delay)}`}
                              >
                                {n.delay}ms
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
          </div>
        )}
      </div>

      {/* 专属端口监听状态 & 跨订阅隔离提示 */}
      {selectedNode && (
        <div className="dedicated-port-status-group">
          <div className="dedicated-port-status">
            <span
              className={`port-dot ${portListening ? 'listening' : 'not-listening'}`}
            />
            <span>
              专属端口：<code>127.0.0.1:{dedicatedPort}</code>
            </span>
            <span
              className="port-bind-tag"
              title={
                effectiveProfileName
                  ? `${effectiveProfileName} / ${selectedNode}`
                  : selectedNode
              }
            >
              {isSwitching
                ? '正在注入并绑定节点...'
                : portListening
                ? `已锁定 [${
                    effectiveProfileName ? `${effectiveProfileName} / ` : ''
                  }${selectedNode}]`
                : '端口未就绪'}
            </span>
          </div>

          <div
            className={`cross-profile-isolation-tip ${
              isCrossProfileBound ? 'cross-active' : ''
            }`}
          >
            <ShieldCheck size={13} />
            <span>
              {isCrossProfileBound
                ? `跨订阅独立直通中：Clash 当前激活 [${
                    clashInfo.activeProfileName || '其他订阅'
                  }]，${appLabel} 独立固定走 [${effectiveProfileName}]，切换订阅或节点互不影响`
                : `节点底层定义已独立注入内核：后续在 Clash 切换任意订阅组或节点均不会影响 ${appLabel}`}
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
