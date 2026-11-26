import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  ClashProfileGroupOption,
  ClashProxyNodeOption,
  ClashRuntimeInfo,
} from '../../shared/types';
import {
  buildNodeSearchText,
  getShortCountryNameZh,
  inferNodeCountryCode,
  matchesNodeSearchToken,
} from '../../shared/countries';

export interface EnrichedNodeOption {
  node: ClashProxyNodeOption;
  countryCode: string | null;
  searchText: string;
  originalIdx: number;
}

export interface EnrichedProfileGroup extends Omit<ClashProfileGroupOption, 'nodes'> {
  nodes: EnrichedNodeOption[];
}

export interface FilteredProfileGroup extends EnrichedProfileGroup {
  filteredNodes: EnrichedNodeOption[];
}

export interface FlatNodeItem {
  groupUid: string;
  node: ClashProxyNodeOption;
}

export interface RegionFilterOption {
  code: string;
  label: string;
  count: number;
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

export function getDelayBadgeClass(delay?: number): string {
  if (!delay || delay <= 0) return 'delay-none';
  if (delay < 180) return 'delay-fast';
  if (delay < 420) return 'delay-medium';
  return 'delay-slow';
}

export function compareEnrichedNodesByDelay(a: EnrichedNodeOption, b: EnrichedNodeOption): number {
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

export interface UseNodeSelectorModelParams {
  clashInfo: ClashRuntimeInfo;
  selectedNode: string | null;
  selectedProfileUid: string | null;
  selectedProfileName: string | null;
  boundProfileUid: string | null;
  boundProfileName: string | null;
  isSwitching: boolean;
  onSelectNode: (nodeName: string | null, profileUid: string | null) => void;
}

export function useClashNodeSelectorModel({
  clashInfo,
  selectedNode,
  selectedProfileUid,
  selectedProfileName,
  boundProfileUid,
  boundProfileName,
  isSwitching,
  onSelectNode,
}: UseNodeSelectorModelParams) {
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

  const profileGroups = clashInfo.profileGroups;

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
    () =>
      enrichedGroups.map((g) => ({
        ...g,
        filteredNodes: g.nodes.filter((item) =>
          searchTokens.every((token) =>
            matchesNodeSearchToken(item.searchText, item.countryCode, token)
          )
        ),
      })),
    [enrichedGroups, searchTokens]
  );

  const regionOptions: RegionFilterOption[] = useMemo(() => {
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

  const isFilteringByQueryOrRegion =
    searchTokens.length > 0 || activeRegionFilter !== '__all__';

  const filteredGroups: FilteredProfileGroup[] = useMemo(
    () =>
      queryFilteredGroups.map((g) => ({
        ...g,
        filteredNodes:
          activeRegionFilter === '__all__'
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

  const visibleGroups: FilteredProfileGroup[] = useMemo(() => {
    return filteredGroups
      .filter(
        (g) =>
          (activeFilterUid === '__all__' || g.uid === activeFilterUid) &&
          g.filteredNodes.length > 0
      )
      .map((g) =>
        sortByDelay
          ? {
              ...g,
              filteredNodes: [...g.filteredNodes].sort(compareEnrichedNodesByDelay),
            }
          : g
      );
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

  useEffect(() => {
    if (pendingLocateRef.current) return;
    const selectedIdx = findSelectedFlatIndex(flatItems);
    setHighlightIndex(selectedIdx >= 0 && searchTokens.length === 0 ? selectedIdx : 0);
  }, [searchQuery, activeFilterUid, activeRegionFilter, sortByDelay]);

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

  const handleSelectProfilePill = (uid: string, btnEl: HTMLButtonElement) => {
    setProfileFilter(uid);
    btnEl.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
    searchInputRef.current?.focus();
  };

  const handleSelectRegionPill = (code: string, btnEl: HTMLButtonElement) => {
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

  const scrollToHighlightedItem = (idx: number) => {
    const container = listContainerRef.current;
    if (!container) return;
    const el = container.querySelector(`[data-flat-idx="${idx}"]`) as HTMLElement | null;
    if (el) {
      el.scrollIntoView({ block: 'nearest' });
    }
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

  const totalNodeCount = clashInfo.availableNodes.length;
  const totalMatchedCount = matchedCountByGroupUid.get('__all__') ?? totalNodeCount;
  const isDisabled = isSwitching || (totalNodeCount === 0 && !selectedNode);

  return {
    isOpen,
    setIsOpen,
    sortByDelay,
    setSortByDelay,
    searchQuery,
    setSearchQuery,
    highlightIndex,
    setHighlightIndex,
    isDraggingPills,
    containerRef,
    searchInputRef,
    pillsBarRef,
    regionBarRef,
    listContainerRef,
    profileGroups,
    matchedNodeObj,
    effectiveProfileUid,
    effectiveProfileName,
    isSelectedProfileActive,
    activeFilterUid,
    activeRegionFilter,
    regionOptions,
    isFilteringByQueryOrRegion,
    matchedCountByGroupUid,
    visibleGroups,
    totalNodeCount,
    totalMatchedCount,
    isDisabled,
    setProfileFilter,
    setRegionFilter,
    handlePillsMouseDown,
    handlePillsMouseMove,
    handlePillsMouseUpOrLeave,
    handlePillsClickCapture,
    handleSelectProfilePill,
    handleSelectRegionPill,
    handleLocateSelected,
    handleOpenPanel,
    handleChooseItem,
    handleClearSelection,
    handleKeyDown,
  };
}
