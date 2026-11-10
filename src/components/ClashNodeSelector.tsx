import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowUpDown,
  Check,
  ChevronDown,
  ChevronUp,
  Crosshair,
  Layers,
  Search,
  X,
} from 'lucide-react';
import {
  ClashProfileGroupOption,
  ClashProxyNodeOption,
  ClashRuntimeInfo,
} from '../shared/types';
import {
  buildNodeSearchText,
  getShortCountryNameZh,
  inferNodeCountryCode,
  matchesNodeSearchToken,
} from '../shared/countries';

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

interface EnrichedNodeOption {
  node: ClashProxyNodeOption;
  countryCode: string | null;
  searchText: string;
  originalIdx: number;
}

interface EnrichedProfileGroup extends Omit<ClashProfileGroupOption, 'nodes'> {
  nodes: EnrichedNodeOption[];
}

interface FlatNodeItem {
  groupUid: string;
  node: ClashProxyNodeOption;
}

const REGION_PRIORITY_ORDER: Record<string, number> = {
  US: 1,
  JP: 2,
  SG: 3,
  HK: 4,
  TW: 5,
  KR: 6,
  GB: 7,
  DE: 8,
  NL: 9,
  FR: 10,
  CA: 11,
  AU: 12,
};

function getDelayBadgeClass(delay?: number): string {
  if (!delay || delay <= 0) return 'delay-none';
  if (delay < 180) return 'delay-fast';
  if (delay < 420) return 'delay-medium';
  return 'delay-slow';
}

function compareEnrichedNodesByDelay(a: EnrichedNodeOption, b: EnrichedNodeOption): number {
  const aAlive = a.node.alive !== false;
  const bAlive = b.node.alive !== false;
  if (aAlive !== bAlive) {
    return aAlive ? -1 : 1;
  }
  const aHasDelay = Boolean(a.node.delay && a.node.delay > 0);
  const bHasDelay = Boolean(b.node.delay && b.node.delay > 0);
  if (aHasDelay && bHasDelay) {
    return (a.node.delay as number) - (b.node.delay as number) || a.originalIdx - b.originalIdx;
  }
  if (aHasDelay !== bHasDelay) {
    return aHasDelay ? -1 : 1;
  }
  return a.originalIdx - b.originalIdx;
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
  const [regionFilter, setRegionFilter] = useState<string>('__all__');
  const [sortByDelay, setSortByDelay] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [highlightIndex, setHighlightIndex] = useState<number>(0);
  const [isDraggingPills, setIsDraggingPills] = useState(false);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const pillsBarRef = useRef<HTMLDivElement | null>(null);
  const regionBarRef = useRef<HTMLDivElement | null>(null);
  const listContainerRef = useRef<HTMLDivElement | null>(null);
  const pendingLocateRef = useRef<boolean>(false);
  const pillDragStateRef = useRef<{
    isDown: boolean;
    startX: number;
    startScrollLeft: number;
    moved: boolean;
  }>({
    isDown: false,
    startX: 0,
    startScrollLeft: 0,
    moved: false,
  });

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

  // 预构建各订阅组节点的国家/地区识别结果与多维同义词检索索引
  const enrichedGroups: EnrichedProfileGroup[] = useMemo(() => {
    return profileGroups.map((g) => ({
      ...g,
      nodes: g.nodes.map((n, idx) => {
        const countryCode = inferNodeCountryCode(n.name);
        return {
          node: n,
          countryCode,
          searchText: buildNodeSearchText(n.name, n.type, g.name, countryCode),
          originalIdx: idx,
        };
      }),
    }));
  }, [profileGroups]);

  const matchedNodeObj = useMemo(() => {
    if (!selectedNode) return undefined;
    const profileUid = selectedProfileUid || boundProfileUid;
    return clashInfo.availableNodes.find(
      (n) => n.name === selectedNode && (!profileUid || n.profileUid === profileUid)
    );
  }, [clashInfo.availableNodes, selectedNode, selectedProfileUid, boundProfileUid]);

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

  const activeFilterUid =
    profileFilter === '__all__' || profileGroups.some((g) => g.uid === profileFilter)
      ? profileFilter
      : '__all__';

  const searchTokens = useMemo(
    () =>
      searchQuery
        .trim()
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean),
    [searchQuery]
  );

  const queryFilteredGroups = useMemo(
    () => enrichedGroups.map((g) => ({
      ...g,
      filteredNodes: g.nodes.filter((item) =>
        searchTokens.every((token) =>
          matchesNodeSearchToken(item.searchText, item.countryCode, token)
        )
      ),
    })),
    [enrichedGroups, searchTokens]
  );

  // 统计当前订阅范围内（结合搜索词）各国家/地区的节点分布，用于生成地区快捷筛选胶囊
  const regionOptions = useMemo(() => {
    const counts = new Map<string, number>();
    for (const g of queryFilteredGroups) {
      if (activeFilterUid !== '__all__' && g.uid !== activeFilterUid) continue;
      for (const item of g.filteredNodes) {
        if (item.countryCode) {
          counts.set(item.countryCode, (counts.get(item.countryCode) || 0) + 1);
        }
      }
    }
    return Array.from(counts.entries())
      .map(([code, count]) => ({
        code,
        label: getShortCountryNameZh(code),
        count,
      }))
      .sort((a, b) => {
        if (b.count !== a.count) return b.count - a.count;
        const pa = REGION_PRIORITY_ORDER[a.code] ?? 99;
        const pb = REGION_PRIORITY_ORDER[b.code] ?? 99;
        if (pa !== pb) return pa - pb;
        return a.code.localeCompare(b.code);
      });
  }, [queryFilteredGroups, activeFilterUid]);

  const activeRegionFilter =
    regionFilter === '__all__' || regionOptions.some((r) => r.code === regionFilter)
      ? regionFilter
      : '__all__';

  // 当存在搜索词或地区筛选时，计算每个订阅组的匹配节点数，方便用户跨订阅直观查看命中分布
  const isFilteringByQueryOrRegion =
    searchTokens.length > 0 || activeRegionFilter !== '__all__';

  const filteredGroups = useMemo(
    () => queryFilteredGroups.map((g) => ({
      ...g,
      filteredNodes: activeRegionFilter === '__all__'
        ? g.filteredNodes
        : g.filteredNodes.filter((item) => item.countryCode === activeRegionFilter),
    })),
    [queryFilteredGroups, activeRegionFilter]
  );

  const matchedCountByGroupUid = useMemo(() => {
    const map = new Map<string, number>();
    let totalMatched = 0;
    for (const g of filteredGroups) {
      const count = g.filteredNodes.length;
      map.set(g.uid, count);
      totalMatched += count;
    }
    map.set('__all__', totalMatched);
    return map;
  }, [filteredGroups]);

  const visibleGroups = useMemo(() => {
    return filteredGroups
      .filter((g) =>
        (activeFilterUid === '__all__' || g.uid === activeFilterUid) &&
        g.filteredNodes.length > 0
      )
      .map((g) => sortByDelay ? {
        ...g,
        filteredNodes: [...g.filteredNodes].sort(compareEnrichedNodesByDelay),
      } : g);
  }, [filteredGroups, activeFilterUid, sortByDelay]);

  const flatItems: FlatNodeItem[] = useMemo(() => {
    const out: FlatNodeItem[] = [];
    for (const g of visibleGroups) {
      for (const item of g.filteredNodes) {
        out.push({
          groupUid: g.uid,
          node: item.node,
        });
      }
    }
    return out;
  }, [visibleGroups]);

  const findSelectedFlatIndex = (items: FlatNodeItem[]): number => {
    if (!selectedNode) return -1;
    return items.findIndex(
      (item) =>
        item.node.name === selectedNode &&
        (!effectiveProfileUid || item.groupUid === effectiveProfileUid)
    );
  };

  // 展开下拉面板或点击「定位已选」时自动滚动定位到已选节点及对应订阅胶囊
  useEffect(() => {
    if (!isOpen) return;
    const selectedIdx = findSelectedFlatIndex(flatItems);
    const initialIdx = selectedIdx >= 0 ? selectedIdx : 0;
    setHighlightIndex(initialIdx);
    pendingLocateRef.current = false;

    requestAnimationFrame(() => {
      searchInputRef.current?.focus();
      if (pillsBarRef.current) {
        const activePill = pillsBarRef.current.querySelector(
          '.profile-filter-pill.active'
        ) as HTMLElement | null;
        activePill?.scrollIntoView({ block: 'nearest', inline: 'center' });
      }
      if (selectedIdx >= 0 && listContainerRef.current) {
        const el = listContainerRef.current.querySelector(
          `[data-flat-idx="${selectedIdx}"]`
        ) as HTMLElement | null;
        el?.scrollIntoView({ block: 'center' });
      }
    });
  }, [isOpen]);

  // 当通过「定位已选」重置筛选条件后，在新的 flatItems 中完成滚动定位
  useEffect(() => {
    if (!isOpen || !pendingLocateRef.current) return;
    const selectedIdx = findSelectedFlatIndex(flatItems);
    if (selectedIdx >= 0) {
      pendingLocateRef.current = false;
      setHighlightIndex(selectedIdx);
      requestAnimationFrame(() => {
        if (listContainerRef.current) {
          const el = listContainerRef.current.querySelector(
            `[data-flat-idx="${selectedIdx}"]`
          ) as HTMLElement | null;
          el?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      });
    }
  }, [isOpen, flatItems]);

  // 订阅组筛选栏与地区快捷栏支持鼠标滚轮横向滚动
  useEffect(() => {
    if (!isOpen) return;
    const attachHorizontalWheel = (el: HTMLElement | null) => {
      if (!el) return () => {};
      const handleWheel = (e: WheelEvent) => {
        if (el.scrollWidth <= el.clientWidth) return;
        const delta = Math.abs(e.deltaY) >= Math.abs(e.deltaX) ? e.deltaY : e.deltaX;
        if (delta !== 0) {
          e.preventDefault();
          e.stopPropagation();
          el.scrollLeft += delta;
        }
      };
      el.addEventListener('wheel', handleWheel, { passive: false });
      return () => el.removeEventListener('wheel', handleWheel);
    };

    const cleanupPills = attachHorizontalWheel(pillsBarRef.current);
    const cleanupRegions = attachHorizontalWheel(regionBarRef.current);
    return () => {
      cleanupPills();
      cleanupRegions();
    };
  }, [isOpen, profileGroups.length, regionOptions.length]);

  // 搜索词、订阅筛选、地区筛选或排序变化时重置高亮项（除非正在执行定位已选）
  useEffect(() => {
    if (pendingLocateRef.current) return;
    const selectedIdx = findSelectedFlatIndex(flatItems);
    setHighlightIndex(selectedIdx >= 0 && searchTokens.length === 0 ? selectedIdx : 0);
  }, [searchQuery, activeFilterUid, activeRegionFilter, sortByDelay]);

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

  const handlePillsMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.button !== 0 || !pillsBarRef.current) return;
    pillDragStateRef.current = {
      isDown: true,
      startX: e.clientX,
      startScrollLeft: pillsBarRef.current.scrollLeft,
      moved: false,
    };
  };

  const handlePillsMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const st = pillDragStateRef.current;
    if (!st.isDown || !pillsBarRef.current) return;
    const dx = e.clientX - st.startX;
    if (!st.moved && Math.abs(dx) > 4) {
      st.moved = true;
      setIsDraggingPills(true);
    }
    if (st.moved) {
      e.preventDefault();
      pillsBarRef.current.scrollLeft = st.startScrollLeft - dx;
    }
  };

  const handlePillsMouseUpOrLeave = () => {
    if (!pillDragStateRef.current.isDown) return;
    pillDragStateRef.current.isDown = false;
    setIsDraggingPills(false);
  };

  const handlePillsClickCapture = (e: React.MouseEvent<HTMLDivElement>) => {
    if (pillDragStateRef.current.moved) {
      e.preventDefault();
      e.stopPropagation();
      pillDragStateRef.current.moved = false;
    }
  };

  const handleSelectProfilePill = (
    uid: string,
    btnEl: HTMLButtonElement
  ) => {
    setProfileFilter(uid);
    btnEl.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
    searchInputRef.current?.focus();
  };

  const handleSelectRegionPill = (
    code: string,
    btnEl: HTMLButtonElement
  ) => {
    const nextCode = activeRegionFilter === code ? '__all__' : code;
    setRegionFilter(nextCode);
    btnEl.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
    searchInputRef.current?.focus();
  };

  const handleLocateSelected = () => {
    if (!selectedNode) return;
    const currentIdx = findSelectedFlatIndex(flatItems);
    if (currentIdx >= 0) {
      setHighlightIndex(currentIdx);
      if (listContainerRef.current) {
        const el = listContainerRef.current.querySelector(
          `[data-flat-idx="${currentIdx}"]`
        ) as HTMLElement | null;
        el?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
      searchInputRef.current?.focus();
      return;
    }

    // 若当前筛选条件隐藏了已选节点，自动放宽筛选并在渲染后滚动定位
    pendingLocateRef.current = true;
    if (
      activeFilterUid !== '__all__' &&
      effectiveProfileUid &&
      activeFilterUid !== effectiveProfileUid
    ) {
      setProfileFilter(effectiveProfileUid);
    } else if (activeFilterUid !== '__all__' && !effectiveProfileUid) {
      setProfileFilter('__all__');
    }
    if (activeRegionFilter !== '__all__') {
      setRegionFilter('__all__');
    }
    if (searchQuery) {
      setSearchQuery('');
    }
    searchInputRef.current?.focus();
  };

  const handleOpenPanel = () => {
    if (isSwitching || (clashInfo.availableNodes.length === 0 && !selectedNode)) {
      return;
    }
    // 展开时若已有选中节点，确保订阅与地区筛选不会将其遮蔽
    if (selectedNode) {
      if (
        profileFilter !== '__all__' &&
        effectiveProfileUid &&
        profileFilter !== effectiveProfileUid
      ) {
        setProfileFilter(effectiveProfileUid);
      }
      if (regionFilter !== '__all__') {
        setRegionFilter('__all__');
      }
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
  const totalMatchedCount = matchedCountByGroupUid.get('__all__') ?? totalNodeCount;
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
                {matchedNodeObj?.alive === false ? (
                  <span
                    className="node-delay-pill delay-timeout"
                    title="最近一次 Clash 测速超时或不可用"
                  >
                    超时
                  </span>
                ) : matchedNodeObj?.delay && matchedNodeObj.delay > 0 ? (
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
              placeholder="支持中英文国家/缩写/多词组合搜索，如: 美国 vless / jp 01..."
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
            <div className="search-header-tools">
              <button
                type="button"
                className={`btn-header-tool ${sortByDelay ? 'active' : ''}`}
                onClick={() => {
                  setSortByDelay((v) => !v);
                  searchInputRef.current?.focus();
                }}
                title={
                  sortByDelay
                    ? '当前已按延迟从低到高排序（点击恢复订阅默认顺序）'
                    : '按测速延迟从低到高排序（优先排布低延迟可用节点）'
                }
              >
                <ArrowUpDown size={12} />
                <span>延迟排序</span>
              </button>
              {selectedNode && (
                <button
                  type="button"
                  className="btn-header-tool"
                  onClick={handleLocateSelected}
                  title={`快速定位到当前已选节点: ${selectedNode}`}
                >
                  <Crosshair size={12} />
                  <span>定位已选</span>
                </button>
              )}
            </div>
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

        {/* 展开态：订阅组筛选胶囊栏 + 地区快捷筛选栏 + 实时过滤节点列表 */}
        {isOpen && (
          <div className="node-dropdown-panel">
            {profileGroups.length > 1 && (
              <div
                ref={pillsBarRef}
                className={`profile-pills-bar ${isDraggingPills ? 'dragging' : ''}`}
                onMouseDown={handlePillsMouseDown}
                onMouseMove={handlePillsMouseMove}
                onMouseUp={handlePillsMouseUpOrLeave}
                onMouseLeave={handlePillsMouseUpOrLeave}
                onClickCapture={handlePillsClickCapture}
              >
                <button
                  type="button"
                  className={`profile-filter-pill ${
                    activeFilterUid === '__all__' ? 'active' : ''
                  }`}
                  onClick={(e) => handleSelectProfilePill('__all__', e.currentTarget)}
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
                      onClick={(e) => handleSelectProfilePill(g.uid, e.currentTarget)}
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
                  onClick={(e) => handleSelectRegionPill('__all__', e.currentTarget)}
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
                    onClick={(e) => handleSelectRegionPill(reg.code, e.currentTarget)}
                    title={`仅筛选 ${reg.label} (${reg.code}) 节点 · 共 ${reg.count} 个`}
                  >
                    <span className="region-pill-code">{reg.code}</span>
                    <span>{reg.label}</span>
                    <span className="region-pill-count">{reg.count}</span>
                  </button>
                ))}
              </div>
            )}

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
                        onClick={() => setRegionFilter('__all__')}
                      >
                        清除地区筛选
                      </button>
                    )}
                    {activeFilterUid !== '__all__' && (
                      <button
                        type="button"
                        className="btn-reset-filter"
                        onClick={() => setProfileFilter('__all__')}
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
                          onMouseEnter={() => setHighlightIndex(flatIdx)}
                          onClick={() => handleChooseItem(n.name, group.uid)}
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
          </div>
        )}
      </div>

      {/* 专属端口监听状态 */}
      {selectedNode && (
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
              ? '正在绑定节点...'
              : portListening
              ? `已锁定 [${
                  effectiveProfileName ? `${effectiveProfileName} / ` : ''
                }${selectedNode}]`
              : '端口未就绪'}
          </span>
        </div>
      )}
    </div>
  );
};
