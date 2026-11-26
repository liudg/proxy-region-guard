import React from 'react';
import {
  ArrowUpDown,
  ChevronDown,
  ChevronUp,
  Crosshair,
  Search,
  X,
} from 'lucide-react';
import { ClashRuntimeInfo } from '../shared/types';
import {
  getDelayBadgeClass,
  useClashNodeSelectorModel,
} from './node-selector/nodeSelectorModel';
import { NodeFilterBars } from './node-selector/NodeFilterBars';
import { NodeDropdownList } from './node-selector/NodeDropdownList';

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
  const model = useClashNodeSelectorModel({
    clashInfo,
    selectedNode,
    selectedProfileUid,
    selectedProfileName,
    boundProfileUid,
    boundProfileName,
    isSwitching,
    onSelectNode,
  });

  return (
    <div className="clash-node-selector-wrap" ref={model.containerRef}>
      {/* 一体化可搜索节点选择框（点击直接激活搜索并展开实时列表） */}
      <div
        className={`node-combobox ${model.isOpen ? 'open' : ''} ${
          model.isDisabled ? 'disabled' : ''
        }`}
      >
        {!model.isOpen ? (
          <div
            className="node-combobox-trigger"
            onClick={model.handleOpenPanel}
            role="button"
            tabIndex={model.isDisabled ? -1 : 0}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                model.handleOpenPanel();
              }
            }}
          >
            {selectedNode ? (
              <div className="selected-node-summary">
                {model.effectiveProfileName && (
                  <span
                    className={`selected-profile-pill ${
                      model.isSelectedProfileActive ? 'active-prof' : 'cross-prof'
                    }`}
                    title={`归属订阅组: ${model.effectiveProfileName}`}
                  >
                    {model.isSelectedProfileActive ? '🟢' : '📦'}{' '}
                    {model.effectiveProfileName}
                  </span>
                )}
                <span className="selected-node-name ellipsis" title={selectedNode}>
                  {selectedNode}
                </span>
                {model.matchedNodeObj ? (
                  <span className="node-proto-pill">
                    {model.matchedNodeObj.type.toUpperCase()}
                  </span>
                ) : (
                  <span className="node-proto-pill cached">已缓存定义</span>
                )}
                {model.matchedNodeObj?.alive === false ? (
                  <span
                    className="node-delay-pill delay-timeout"
                    title="最近一次 Clash 测速超时或不可用"
                  >
                    超时
                  </span>
                ) : model.matchedNodeObj?.delay && model.matchedNodeObj.delay > 0 ? (
                  <span
                    className={`node-delay-pill ${getDelayBadgeClass(
                      model.matchedNodeObj.delay
                    )}`}
                  >
                    {model.matchedNodeObj.delay}ms
                  </span>
                ) : null}
              </div>
            ) : (
              <div className="unselected-node-placeholder">
                <Search size={14} className="placeholder-search-icon" />
                <span>
                  {model.totalNodeCount > 0
                    ? '搜索或选择代理节点...'
                    : '未读取到本地订阅节点'}
                </span>
              </div>
            )}

            <div className="node-combobox-actions">
              {selectedNode && (
                <button
                  type="button"
                  className="btn-inline-clear-node"
                  disabled={isSwitching}
                  onClick={model.handleClearSelection}
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
              ref={model.searchInputRef}
              type="text"
              className="combobox-live-input"
              value={model.searchQuery}
              onChange={(e) => model.setSearchQuery(e.target.value)}
              onKeyDown={model.handleKeyDown}
              placeholder="搜索国家、缩写或协议，如 美国 vless / jp 01..."
            />
            {model.searchQuery && (
              <button
                type="button"
                className="btn-clear-query"
                onClick={() => {
                  model.setSearchQuery('');
                  model.searchInputRef.current?.focus();
                }}
                title="清空搜索词"
              >
                <X size={13} />
              </button>
            )}
            <div className="search-header-tools">
              <button
                type="button"
                className={`btn-header-tool ${model.sortByDelay ? 'active' : ''}`}
                onClick={() => {
                  model.setSortByDelay((v) => !v);
                  model.searchInputRef.current?.focus();
                }}
                title={
                  model.sortByDelay
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
                  onClick={model.handleLocateSelected}
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
              onClick={() => model.setIsOpen(false)}
              title="收起列表 (Esc)"
            >
              <ChevronUp size={15} />
            </button>
          </div>
        )}

        {/* 展开态：订阅组筛选胶囊栏 + 地区快捷筛选栏 + 实时过滤节点列表 */}
        {model.isOpen && (
          <div className="node-dropdown-panel">
            <NodeFilterBars
              profileGroups={model.profileGroups}
              regionOptions={model.regionOptions}
              activeFilterUid={model.activeFilterUid}
              activeRegionFilter={model.activeRegionFilter}
              selectedNode={selectedNode}
              effectiveProfileUid={model.effectiveProfileUid}
              isFilteringByQueryOrRegion={model.isFilteringByQueryOrRegion}
              totalNodeCount={model.totalNodeCount}
              totalMatchedCount={model.totalMatchedCount}
              matchedCountByGroupUid={model.matchedCountByGroupUid}
              isDraggingPills={model.isDraggingPills}
              pillsBarRef={model.pillsBarRef}
              regionBarRef={model.regionBarRef}
              onPillsMouseDown={model.handlePillsMouseDown}
              onPillsMouseMove={model.handlePillsMouseMove}
              onPillsMouseUpOrLeave={model.handlePillsMouseUpOrLeave}
              onPillsClickCapture={model.handlePillsClickCapture}
              onSelectProfilePill={model.handleSelectProfilePill}
              onSelectRegionPill={model.handleSelectRegionPill}
            />

            <NodeDropdownList
              visibleGroups={model.visibleGroups}
              selectedNode={selectedNode}
              effectiveProfileUid={model.effectiveProfileUid}
              highlightIndex={model.highlightIndex}
              sortByDelay={model.sortByDelay}
              searchQuery={model.searchQuery}
              activeFilterUid={model.activeFilterUid}
              activeRegionFilter={model.activeRegionFilter}
              totalMatchedCount={model.totalMatchedCount}
              listContainerRef={model.listContainerRef}
              onHoverIndex={model.setHighlightIndex}
              onChooseItem={(name, uid) => model.handleChooseItem(name, uid)}
              onClearRegionFilter={() => model.setRegionFilter('__all__')}
              onClearProfileFilter={() => model.setProfileFilter('__all__')}
            />
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
              model.effectiveProfileName
                ? `${model.effectiveProfileName} / ${selectedNode}`
                : selectedNode
            }
          >
            {isSwitching
              ? '正在绑定节点...'
              : portListening
              ? `已锁定 [${
                  model.effectiveProfileName ? `${model.effectiveProfileName} / ` : ''
                }${selectedNode}]`
              : '端口未就绪'}
          </span>
        </div>
      )}
    </div>
  );
};
