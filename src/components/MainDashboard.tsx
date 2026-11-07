import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Ban,
  BellRing,
  Bot,
  Check,
  CheckCircle2,
  Clock,
  Copy,
  Cpu,
  FolderOpen,
  Globe,
  History,
  Info,
  Lock,
  Minus,
  Play,
  Plus,
  Radio,
  RefreshCw,
  Rocket,
  RotateCcw,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Square,
  Trash2,
  Unlock,
  WifiOff,
  X,
  XCircle,
} from 'lucide-react';
import { AppConfig, AppStateSnapshot } from '../shared/types';
import { COMMON_COUNTRIES, isValidIsoCountryCode } from '../shared/countries';
import { inspectProcessPattern } from '../shared/processPattern';
import {
  DEFAULT_CHINA_REGION_CODE,
  DEFAULT_CHINA_TIMEZONE_ID,
  isWindowsLocaleMatchingCountry,
} from '../shared/timezones';
import { CountryFlag } from './CountryFlag';

type ActiveTab = 'launcher' | 'monitor' | 'guard' | 'settings' | 'logs';
type LauncherSubTab = 'antigravity' | 'claude';

export const MainDashboard: React.FC = () => {
  const [state, setState] = useState<AppStateSnapshot | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>('launcher');
  const [launcherSubTab, setLauncherSubTab] = useState<LauncherSubTab>('antigravity');
  const [copiedIp, setCopiedIp] = useState(false);
  const [copiedAgIp, setCopiedAgIp] = useState(false);

  // 手动代理表单本地编辑态
  const [pendingManualMode, setPendingManualMode] = useState(false);
  const [manualProto, setManualProto] = useState<'http' | 'socks5'>('http');
  const [manualHost, setManualHost] = useState('127.0.0.1');
  const [manualPort, setManualPort] = useState('7890');
  const [dedicatedPortInput, setDedicatedPortInput] = useState('27897');
  const [agDedicatedPortInput, setAgDedicatedPortInput] = useState('27898');

  const [customProbe, setCustomProbe] = useState('');
  const [probeUrlErr, setProbeUrlErr] = useState<string | null>(null);

  // 进程匹配规则输入态
  const [patternInput, setPatternInput] = useState('');
  const [patternSubmitErr, setPatternSubmitErr] = useState<string | null>(null);

  // 时区同步/还原即时反馈提示
  const [localeFeedback, setLocaleFeedback] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  // Claude 启动/终止操作状态与反馈
  const [isLaunchingClaude, setIsLaunchingClaude] = useState(false);
  const [isSwitchingNode, setIsSwitchingNode] = useState(false);
  const [claudeFeedback, setClaudeFeedback] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  // Antigravity 启动/终止操作状态与反馈
  const [isLaunchingAg, setIsLaunchingAg] = useState(false);
  const [isSwitchingAgNode, setIsSwitchingAgNode] = useState(false);
  const [agFeedback, setAgFeedback] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  useEffect(() => {
    void window.guardAPI.getState().then((initial) => {
      setState(initial);
      syncFormFromConfig(initial.config);
    });

    const unsub = window.guardAPI.onStateChanged((next) => {
      setState(next);
    });

    return unsub;
  }, []);

  const syncFormFromConfig = (cfg: AppConfig) => {
    setManualProto(cfg.manualProxy.protocol);
    setManualHost(cfg.manualProxy.host);
    setManualPort(String(cfg.manualProxy.port));
    setDedicatedPortInput(String(cfg.dedicatedProxyPort));
    setAgDedicatedPortInput(String(cfg.antigravityDedicatedPort));
    setCustomProbe(cfg.customProbeUrl);
  };

  if (!state) {
    return (
      <div className="app-loading">
        <RefreshCw className="spin" size={24} />
        <span>正在初始化代理地区卫士...</span>
      </div>
    );
  }

  const {
    status,
    isChecking,
    isSyncingLocale,
    config,
    winLocale,
    lastProbe,
    lastError,
    clashInfo,
    claudeState,
    antigravityState,
    logs,
  } = state;

  const displayedProxyMode = pendingManualMode ? 'manual' : config.proxyMode;

  const handleCopyIp = () => {
    if (!lastProbe?.ip) return;
    void navigator.clipboard.writeText(lastProbe.ip);
    setCopiedIp(true);
    setTimeout(() => setCopiedIp(false), 1600);
  };

  const handleCopyAgIp = () => {
    if (!antigravityState.nodeProbe?.ip) return;
    void navigator.clipboard.writeText(antigravityState.nodeProbe.ip);
    setCopiedAgIp(true);
    setTimeout(() => setCopiedAgIp(false), 1600);
  };

  const handleSelectClashNode = async (nodeName: string) => {
    const val = nodeName.trim() || null;
    setIsSwitchingNode(true);
    try {
      const next = await window.guardAPI.selectClashNode(val);
      setState(next);
    } finally {
      setIsSwitchingNode(false);
    }
  };

  const handleSelectAntigravityNode = async (nodeName: string) => {
    const val = nodeName.trim() || null;
    setIsSwitchingAgNode(true);
    try {
      const next = await window.guardAPI.selectAntigravityClashNode(val);
      setState(next);
    } finally {
      setIsSwitchingAgNode(false);
    }
  };

  const showTimedClaudeFeedback = (ok: boolean, text: string) => {
    setClaudeFeedback({ ok, text });
    setTimeout(() => {
      setClaudeFeedback((prev) => (prev && prev.text === text ? null : prev));
    }, 6000);
  };

  const showTimedAgFeedback = (ok: boolean, text: string) => {
    setAgFeedback({ ok, text });
    setTimeout(() => {
      setAgFeedback((prev) => (prev && prev.text === text ? null : prev));
    }, 6000);
  };

  const handleLaunchClaude = async () => {
    setIsLaunchingClaude(true);
    setClaudeFeedback(null);
    try {
      const res = await window.guardAPI.launchClaude();
      setState(res.state);
      showTimedClaudeFeedback(res.ok, res.message);
    } finally {
      setIsLaunchingClaude(false);
    }
  };

  const handleTerminateClaude = async () => {
    setClaudeFeedback(null);
    const res = await window.guardAPI.terminateClaudeNow();
    setState(res.state);
    showTimedClaudeFeedback(res.ok, res.message);
  };

  const handleSyncLocaleFromClaude = async () => {
    setClaudeFeedback(null);
    const res = await window.guardAPI.syncSystemLocaleToDefault();
    setState(res.state);
    showTimedClaudeFeedback(res.ok, res.message);
  };

  const handleLaunchAntigravity = async () => {
    setIsLaunchingAg(true);
    setAgFeedback(null);
    try {
      const res = await window.guardAPI.launchAntigravity();
      setState(res.state);
      showTimedAgFeedback(res.ok, res.message);
    } finally {
      setIsLaunchingAg(false);
    }
  };

  const handleTerminateAntigravity = async () => {
    setAgFeedback(null);
    const res = await window.guardAPI.terminateAntigravityNow();
    setState(res.state);
    showTimedAgFeedback(res.ok, res.message);
  };

  const handleSaveDedicatedPort = async () => {
    let portNum = Math.max(
      1024,
      Math.min(65535, Math.round(Number(dedicatedPortInput) || 27897))
    );
    if (portNum === config.antigravityDedicatedPort) {
      portNum = portNum === 27897 ? 27896 : 27897;
      showTimedClaudeFeedback(
        false,
        `端口不能与 Antigravity 专属端口 (${config.antigravityDedicatedPort}) 相同，已自动调整为 ${portNum}`
      );
    }
    setDedicatedPortInput(String(portNum));
    if (portNum === config.dedicatedProxyPort) return;
    setIsSwitchingNode(true);
    try {
      const next = await window.guardAPI.updateConfig({
        dedicatedProxyPort: portNum,
      });
      setState(next);
    } finally {
      setIsSwitchingNode(false);
    }
  };

  const handleSaveAgDedicatedPort = async () => {
    let portNum = Math.max(
      1024,
      Math.min(65535, Math.round(Number(agDedicatedPortInput) || 27898))
    );
    if (portNum === config.dedicatedProxyPort) {
      portNum = portNum === 27898 ? 27899 : 27898;
      showTimedAgFeedback(
        false,
        `端口不能与 Claude 专属端口 (${config.dedicatedProxyPort}) 相同，已自动调整为 ${portNum}`
      );
    }
    setAgDedicatedPortInput(String(portNum));
    if (portNum === config.antigravityDedicatedPort) return;
    setIsSwitchingAgNode(true);
    try {
      const next = await window.guardAPI.updateConfig({
        antigravityDedicatedPort: portNum,
      });
      setState(next);
      showTimedAgFeedback(true, `Antigravity 专属代理端口已更新为 127.0.0.1:${portNum}`);
    } finally {
      setIsSwitchingAgNode(false);
    }
  };

  const handleSwitchNonManualMode = async (mode: 'auto' | 'direct') => {
    setPendingManualMode(false);
    if (config.proxyMode === mode) return;
    const next = await window.guardAPI.updateConfig({ proxyMode: mode });
    setState(next);
  };

  const handleSaveManualProxy = async () => {
    const cleanHost = manualHost.trim() || '127.0.0.1';
    const portNum = Math.max(1, Math.min(65535, Math.round(Number(manualPort) || 7890)));
    setManualHost(cleanHost);
    setManualPort(String(portNum));
    setPendingManualMode(false);

    const next = await window.guardAPI.updateConfig({
      proxyMode: 'manual',
      manualProxy: {
        protocol: manualProto,
        host: cleanHost,
        port: portNum,
      },
    });
    setState(next);
  };

  const handleSaveCustomProbe = async () => {
    const trimmed = customProbe.trim();
    if (trimmed) {
      try {
        const parsed = new URL(trimmed);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          setProbeUrlErr('探测地址必须以 https:// 或 http:// 开头');
          return;
        }
      } catch {
        setProbeUrlErr('请输入合法的完整 URL，例如 https://cp.cloudflare.com/cdn-cgi/trace');
        return;
      }
    }
    setProbeUrlErr(null);
    setCustomProbe(trimmed);
    const next = await window.guardAPI.updateConfig({
      customProbeUrl: trimmed,
    });
    setState(next);
  };

  const showTimedLocaleFeedback = (ok: boolean, text: string) => {
    setLocaleFeedback({ ok, text });
    setTimeout(() => {
      setLocaleFeedback((prev) => (prev && prev.text === text ? null : prev));
    }, 5500);
  };

  const handleSyncLocale = async () => {
    setLocaleFeedback(null);
    const res = await window.guardAPI.syncSystemLocaleToDefault();
    setState(res.state);
    showTimedLocaleFeedback(res.ok, res.message);
  };

  const handleRestoreLocale = async () => {
    setLocaleFeedback(null);
    const res = await window.guardAPI.restoreDefaultChinaLocale();
    setState(res.state);
    showTimedLocaleFeedback(res.ok, res.message);
  };

  const handleAddPattern = async () => {
    const check = inspectProcessPattern(patternInput);
    if (!check.valid) {
      setPatternSubmitErr(check.error || '规则格式不正确');
      return;
    }

    const exists = config.protectedProcessPatterns.some(
      (p) => p.toLowerCase() === check.normalized.toLowerCase()
    );
    if (exists) {
      setPatternSubmitErr('该规则已在守护列表中');
      return;
    }

    setPatternSubmitErr(null);
    setPatternInput('');
    const next = await window.guardAPI.updateConfig({
      protectedProcessPatterns: [...config.protectedProcessPatterns, check.normalized],
    });
    setState(next);
  };

  const handleRemovePattern = async (target: string) => {
    const filtered = config.protectedProcessPatterns.filter((p) => p !== target);
    const next = await window.guardAPI.updateConfig({
      protectedProcessPatterns: filtered,
    });
    setState(next);
  };

  const statusMeta = {
    ok: {
      badge: '状态正常 · 代理与时区一致',
      cls: 'status-ok',
      icon: <ShieldCheck size={18} />,
    },
    mismatch: {
      badge: '警告 · 代理与时区/地区不一致！',
      cls: 'status-mismatch',
      icon: <ShieldAlert size={18} />,
    },
    error: {
      badge: '异常 · 代理连接失败',
      cls: 'status-error',
      icon: <WifiOff size={18} />,
    },
    unset: {
      badge: '待选择节点或保护地区',
      cls: 'status-unset',
      icon: <Shield size={18} />,
    },
    checking: {
      badge: '正在检测出口地区...',
      cls: 'status-checking',
      icon: <RefreshCw className="spin" size={18} />,
    },
  }[status];

  const canLockCurrentProbe = Boolean(lastProbe && isValidIsoCountryCode(lastProbe.countryCode));

  const isCurrentAlreadyDefault =
    canLockCurrentProbe &&
    Boolean(config.defaultCountryCode) &&
    lastProbe?.countryCode === config.defaultCountryCode;

  const isCustomCountryOutsideCommon = Boolean(
    config.defaultCountryCode &&
      !COMMON_COUNTRIES.some((c) => c.code === config.defaultCountryCode)
  );

  const probeValid = Boolean(lastProbe && isValidIsoCountryCode(lastProbe.countryCode));

  const effectiveTargetCode =
    config.defaultCountryCode || (probeValid ? lastProbe?.countryCode : null) || null;

  const effectiveTargetName =
    config.defaultCountryName || (probeValid ? lastProbe?.countryName : null) || null;

  const isWinLocaleMatched = effectiveTargetCode
    ? isWindowsLocaleMatchingCountry(
        winLocale.timeZoneId,
        winLocale.regionCode,
        effectiveTargetCode
      )
    : true;

  const isAlreadyChinaDefaultLocale =
    winLocale.regionCode.toUpperCase() === DEFAULT_CHINA_REGION_CODE &&
    winLocale.timeZoneId.toLowerCase() === DEFAULT_CHINA_TIMEZONE_ID.toLowerCase();

  const livePatternCheck = patternInput.trim() ? inspectProcessPattern(patternInput) : null;

  const concreteNodes = clashInfo.availableNodes.filter((n) => !n.isGroup);
  const groupNodes = clashInfo.availableNodes.filter((n) => n.isGroup);

  const isSelectedNodeMissing = Boolean(
    config.selectedClashNode &&
      clashInfo.connected &&
      !clashInfo.availableNodes.some((n) => n.name === config.selectedClashNode)
  );

  const isAgSelectedNodeMissing = Boolean(
    config.antigravityClashNode &&
      clashInfo.connected &&
      !clashInfo.availableNodes.some((n) => n.name === config.antigravityClashNode)
  );

  const installTypeLabel = {
    'msix-alias': 'MSIX 官方执行别名 (推荐)',
    'msix-direct': 'MSIX 应用包直连',
    squirrel: '独立安装包',
    custom: '手动指定路径',
    'not-found': '未找到安装路径',
  }[claudeState.installType];

  const agInstallTypeLabel = {
    standard: '已自动识别安装路径',
    custom: '手动指定路径',
    'not-found': '未找到安装路径',
  }[antigravityState.installType];

  const launcherTabDotClass =
    (antigravityState.running && antigravityState.proxiedSession) || claudeState.running
      ? 'running'
      : antigravityState.canLaunch || claudeState.canLaunch
      ? 'ready'
      : 'locked';

  const renderClashNodeSelector = () => (
    <div className="clash-node-selector-wrap">
      <div className="node-selector-row">
        <select
          className="clash-node-select"
          value={config.selectedClashNode || ''}
          disabled={isSwitchingNode || (!clashInfo.connected && !config.selectedClashNode)}
          onChange={(e) => void handleSelectClashNode(e.target.value)}
        >
          <option value="">
            {clashInfo.connected
              ? '请选择要为 Claude 强制绑定的 Clash 节点...'
              : '未连接 Clash Verge 控制接口...'}
          </option>
          {isSelectedNodeMissing && config.selectedClashNode && (
            <option value={config.selectedClashNode}>
              ⚠️ {config.selectedClashNode} (当前配置中不存在)
            </option>
          )}
          {concreteNodes.length > 0 && (
            <optgroup label={`🚀 具体落地节点 (${concreteNodes.length} 个)`}>
              {concreteNodes.map((n) => (
                <option key={n.name} value={n.name}>
                  {n.name} [{n.type}
                  {n.delay ? ` · ${n.delay}ms` : ''}]
                </option>
              ))}
            </optgroup>
          )}
          {groupNodes.length > 0 && (
            <optgroup label={`📁 策略组 (${groupNodes.length} 个)`}>
              {groupNodes.map((g) => (
                <option key={g.name} value={g.name}>
                  {g.name} ({g.type}
                  {g.now ? ` → ${g.now}` : ''})
                </option>
              ))}
            </optgroup>
          )}
        </select>

        {config.selectedClashNode && (
          <button
            className="btn-clear-node"
            disabled={isSwitchingNode}
            onClick={() => void handleSelectClashNode('')}
            title="取消固定节点绑定，恢复跟随系统代理"
          >
            <X size={14} />
          </button>
        )}
      </div>

      {config.selectedClashNode && (
        <div className="dedicated-port-status">
          <span
            className={`port-dot ${
              clashInfo.dedicatedPortListening ? 'listening' : 'not-listening'
            }`}
          />
          <span>
            专属本地端口：<code>127.0.0.1:{config.dedicatedProxyPort}</code>
          </span>
          <span className="port-bind-tag">
            {isSwitchingNode
              ? '正在绑定节点...'
              : clashInfo.dedicatedPortListening
              ? `已锁定直通 [${config.selectedClashNode}]`
              : '端口未就绪'}
          </span>
        </div>
      )}
    </div>
  );

  const renderAntigravityNodeSelector = () => (
    <div className="clash-node-selector-wrap">
      <div className="node-selector-row">
        <select
          className="clash-node-select"
          value={config.antigravityClashNode || ''}
          disabled={
            isSwitchingAgNode || (!clashInfo.connected && !config.antigravityClashNode)
          }
          onChange={(e) => void handleSelectAntigravityNode(e.target.value)}
        >
          <option value="">
            {clashInfo.connected
              ? '请选择要为 Antigravity 绑定的 Clash 节点...'
              : '未连接 Clash Verge 控制接口...'}
          </option>
          {isAgSelectedNodeMissing && config.antigravityClashNode && (
            <option value={config.antigravityClashNode}>
              ⚠️ {config.antigravityClashNode} (当前配置中不存在)
            </option>
          )}
          {concreteNodes.length > 0 && (
            <optgroup label={`🚀 具体落地节点 (${concreteNodes.length} 个)`}>
              {concreteNodes.map((n) => (
                <option key={n.name} value={n.name}>
                  {n.name} [{n.type}
                  {n.delay ? ` · ${n.delay}ms` : ''}]
                </option>
              ))}
            </optgroup>
          )}
          {groupNodes.length > 0 && (
            <optgroup label={`📁 策略组 (${groupNodes.length} 个)`}>
              {groupNodes.map((g) => (
                <option key={g.name} value={g.name}>
                  {g.name} ({g.type}
                  {g.now ? ` → ${g.now}` : ''})
                </option>
              ))}
            </optgroup>
          )}
        </select>

        {config.antigravityClashNode && (
          <button
            className="btn-clear-node"
            disabled={isSwitchingAgNode}
            onClick={() => void handleSelectAntigravityNode('')}
            title="取消 Antigravity 专属节点绑定"
          >
            <X size={14} />
          </button>
        )}
      </div>

      {config.antigravityClashNode && (
        <div className="dedicated-port-status">
          <span
            className={`port-dot ${
              clashInfo.antigravityPortListening ? 'listening' : 'not-listening'
            }`}
          />
          <span>
            专属本地端口：<code>127.0.0.1:{config.antigravityDedicatedPort}</code>
          </span>
          <span className="port-bind-tag">
            {isSwitchingAgNode
              ? '正在绑定节点...'
              : clashInfo.antigravityPortListening
              ? `已锁定直通 [${config.antigravityClashNode}]`
              : '端口未就绪'}
          </span>
        </div>
      )}

      <p className="ag-hot-swap-tip">
        💡 当 Antigravity 通过本启动器运行时，直接在此切换节点即可<strong>免重启实时生效</strong>。
      </p>
    </div>
  );

  return (
    <div className="dashboard-window">
      {/* 自绘无边框标题栏 */}
      <header className="titlebar drag-region">
        <div className="titlebar-brand">
          <span className={`brand-dot ${statusMeta.cls}`} />
          <span className="brand-name">代理地区卫士</span>
          <span className="brand-sub">Proxy Region Guard</span>
        </div>
        <div className="titlebar-controls no-drag">
          <button
            className="win-btn"
            onClick={() => window.guardAPI.minimizeMain()}
            title="最小化"
          >
            <Minus size={15} />
          </button>
          <button
            className="win-btn win-close"
            onClick={() => window.guardAPI.closeMain()}
            title={config.closeToTray ? '隐藏到系统托盘' : '退出程序'}
          >
            <X size={15} />
          </button>
        </div>
      </header>

      {/* 顶部导航栏（保持 5 个一级 Tab，清爽不拥挤） */}
      <nav className="nav-tabs">
        <button
          className={`nav-tab ${activeTab === 'launcher' ? 'active' : ''}`}
          onClick={() => setActiveTab('launcher')}
        >
          <Rocket size={14} />
          <span>启动器</span>
          <span className={`tab-status-dot ${launcherTabDotClass}`} />
        </button>
        <button
          className={`nav-tab ${activeTab === 'monitor' ? 'active' : ''}`}
          onClick={() => setActiveTab('monitor')}
        >
          <Activity size={14} />
          <span>实时监控</span>
        </button>
        <button
          className={`nav-tab ${activeTab === 'guard' ? 'active' : ''}`}
          onClick={() => setActiveTab('guard')}
        >
          <ShieldAlert size={14} />
          <span>进程守护</span>
          {config.protectedProcessPatterns.length > 0 && (
            <span className="tab-count">{config.protectedProcessPatterns.length}</span>
          )}
        </button>
        <button
          className={`nav-tab ${activeTab === 'settings' ? 'active' : ''}`}
          onClick={() => setActiveTab('settings')}
        >
          <Settings size={14} />
          <span>设置</span>
        </button>
        <button
          className={`nav-tab ${activeTab === 'logs' ? 'active' : ''}`}
          onClick={() => setActiveTab('logs')}
        >
          <History size={14} />
          <span>日志</span>
          {logs.length > 0 && <span className="tab-count">{logs.length}</span>}
        </button>
      </nav>

      {/* 内容主体 */}
      <main className="dashboard-content">
        {activeTab === 'launcher' && (
          <div className="tab-pane">
            {/* 启动器内部二级切换器：Antigravity 启动器 vs Claude 专栏 */}
            <div className="launcher-subtabs">
              <button
                className={`launcher-subtab ${
                  launcherSubTab === 'antigravity' ? 'active' : ''
                }`}
                onClick={() => setLauncherSubTab('antigravity')}
              >
                <Rocket size={14} />
                <span>Antigravity 启动器</span>
                <span className="subtab-mode-badge pure">纯代理</span>
                <span
                  className={`tab-status-dot ${
                    antigravityState.running && antigravityState.proxiedSession
                      ? 'running'
                      : antigravityState.running
                      ? 'external'
                      : antigravityState.canLaunch
                      ? 'ready'
                      : 'Idle'
                  }`}
                />
              </button>

              <button
                className={`launcher-subtab ${launcherSubTab === 'claude' ? 'active' : ''}`}
                onClick={() => setLauncherSubTab('claude')}
              >
                <Bot size={14} />
                <span>Claude 专栏</span>
                <span className="subtab-mode-badge guard">三重守护</span>
                <span
                  className={`tab-status-dot ${
                    claudeState.running
                      ? 'running'
                      : claudeState.canLaunch
                      ? 'ready'
                      : isChecking && !lastProbe && !lastError
                      ? 'checking'
                      : 'locked'
                  }`}
                />
              </button>
            </div>

            {launcherSubTab === 'antigravity' ? (
              <>
                {/* 1. Antigravity 纯代理启动主控卡 */}
                <section
                  className={`hero-card ag-hero-card ${
                    antigravityState.running && antigravityState.proxiedSession
                      ? 'status-ok'
                      : antigravityState.canLaunch
                      ? 'status-checking'
                      : ''
                  }`}
                >
                  <div className="hero-top-row">
                    <div
                      className={`status-pill ${
                        antigravityState.running && antigravityState.proxiedSession
                          ? 'status-ok'
                          : antigravityState.running
                          ? 'status-error'
                          : antigravityState.canLaunch
                          ? 'status-checking'
                          : 'status-unset'
                      }`}
                    >
                      {antigravityState.running && antigravityState.proxiedSession ? (
                        <>
                          <CheckCircle2 size={17} />
                          <span>
                            Antigravity 代理运行中 ({antigravityState.totalProcessCount} 个进程)
                          </span>
                        </>
                      ) : antigravityState.running ? (
                        <>
                          <Info size={17} />
                          <span>
                            Antigravity 外部运行中 ({antigravityState.totalProcessCount} 个进程)
                          </span>
                        </>
                      ) : antigravityState.canLaunch ? (
                        <>
                          <Rocket size={17} />
                          <span>专属代理已就绪 · 可启动 Antigravity</span>
                        </>
                      ) : (
                        <>
                          <Radio size={17} />
                          <span>待配置 Antigravity 启动代理节点</span>
                        </>
                      )}
                    </div>

                    <button
                      className="btn-refresh"
                      disabled={
                        !config.antigravityClashNode ||
                        antigravityState.isProbingNode ||
                        isSwitchingAgNode
                      }
                      onClick={() =>
                        void window.guardAPI.probeAntigravityNode().then(setState)
                      }
                      title="仅测试所选节点的出口 IP 与国家，不触发任何报警或拦截"
                    >
                      <RefreshCw
                        className={antigravityState.isProbingNode ? 'spin' : ''}
                        size={14}
                      />
                      <span>
                        {antigravityState.isProbingNode ? '测速中...' : '刷新节点出口'}
                      </span>
                    </button>
                  </div>

                  {/* 所选节点出口信息展示（纯展示，无任何监控/时区拦截） */}
                  <div className="ag-node-exit-card">
                    {config.antigravityClashNode ? (
                      antigravityState.nodeProbe ? (
                        <div className="ag-exit-main">
                          <CountryFlag
                            code={antigravityState.nodeProbe.countryCode}
                            size="md"
                          />
                          <div className="ag-exit-text">
                            <div className="ag-exit-title-row">
                              <strong>{antigravityState.nodeProbe.countryName}</strong>
                              <span className="iso-pill">
                                {antigravityState.nodeProbe.countryCode}
                              </span>
                              <span className="ag-node-tag ellipsis">
                                {config.antigravityClashNode}
                              </span>
                            </div>
                            <div className="ag-exit-ip-row">
                              <span className="ip-label">节点出口 IP:</span>
                              <code className="ip-code">
                                {antigravityState.nodeProbe.ip}
                              </code>
                              <button
                                className="btn-icon-tiny"
                                onClick={handleCopyAgIp}
                                title="复制节点出口 IP"
                              >
                                {copiedAgIp ? <Check size={12} /> : <Copy size={12} />}
                              </button>
                              <span className="latency-tag">
                                {antigravityState.nodeProbe.latencyMs} ms
                              </span>
                            </div>
                          </div>
                        </div>
                      ) : antigravityState.isProbingNode ? (
                        <div className="ag-exit-placeholder">
                          <RefreshCw className="spin" size={15} />
                          <span>
                            正在通过专属端口 127.0.0.1:{config.antigravityDedicatedPort}{' '}
                            获取节点 [{config.antigravityClashNode}] 出口信息...
                          </span>
                        </div>
                      ) : (
                        <div className="ag-exit-placeholder">
                          <Info size={15} />
                          <span>
                            {antigravityState.nodeProbeError ||
                              `已选定节点 [${config.antigravityClashNode}]，点击右上角「刷新节点出口」可查看出口 IP`}
                          </span>
                        </div>
                      )
                    ) : (
                      <div className="ag-exit-placeholder">
                        <Radio size={15} />
                        <span>
                          请在下方下拉框选择要为 Antigravity 绑定的 Clash 代理节点
                        </span>
                      </div>
                    )}
                  </div>

                  {/* 全进程代理覆盖状态明细：Antigravity.exe + language_server.exe */}
                  <div className="ag-process-grid">
                    <div
                      className={`ag-proc-box ${
                        antigravityState.uiProcessCount > 0 ? 'active' : ''
                      }`}
                    >
                      <div className="ag-proc-header">
                        <code>Antigravity.exe</code>
                        <span
                          className={`ag-proc-badge ${
                            antigravityState.uiProcessCount > 0 ? 'on' : 'off'
                          }`}
                        >
                          {antigravityState.uiProcessCount > 0
                            ? `运行中 ×${antigravityState.uiProcessCount}`
                            : '未运行'}
                        </span>
                      </div>
                      <small>
                        Chromium <code>--proxy-server</code> 参数 + Clash 进程名规则锁定
                      </small>
                    </div>

                    <div
                      className={`ag-proc-box ${
                        antigravityState.languageServerCount > 0 ? 'active' : ''
                      }`}
                    >
                      <div className="ag-proc-header">
                        <code>language_server.exe</code>
                        <span
                          className={`ag-proc-badge ${
                            antigravityState.languageServerCount > 0 ? 'on' : 'off'
                          }`}
                        >
                          {antigravityState.languageServerCount > 0
                            ? `运行中 ×${antigravityState.languageServerCount}`
                            : '未运行'}
                        </span>
                      </div>
                      <small>
                        <code>HTTP/HTTPS/ALL/GRPC_PROXY</code> 环境变量继承 + Clash 规则兜底
                      </small>
                    </div>
                  </div>

                  {/* 外部直连运行提示或未就绪指引 */}
                  {antigravityState.running && !antigravityState.proxiedSession && (
                    <div className="ag-info-banner">
                      <Info size={14} />
                      <span>
                        当前 Antigravity 由外部启动（Clash 进程名规则已生效，但尚未注入启动参数与环境变量）。如需最严格的专属端口直通，可点击下方按钮重启注入。
                      </span>
                    </div>
                  )}

                  {!antigravityState.canLaunch && antigravityState.launchHint && (
                    <div className="ag-info-banner">
                      <Info size={14} />
                      <span>{antigravityState.launchHint}</span>
                    </div>
                  )}

                  {/* 启动 / 重启 / 停止按钮行 */}
                  <div className="claude-launch-actions">
                    <button
                      className={`btn-launch-claude ${
                        antigravityState.canLaunch ? 'ready' : 'disabled'
                      }`}
                      disabled={
                        !antigravityState.canLaunch || isLaunchingAg || isSwitchingAgNode
                      }
                      onClick={() => void handleLaunchAntigravity()}
                    >
                      {isLaunchingAg ? (
                        <>
                          <RefreshCw className="spin" size={16} />
                          <span>正在绑定代理并拉起 Antigravity...</span>
                        </>
                      ) : (
                        <>
                          <Play size={16} />
                          <span>
                            {antigravityState.running && antigravityState.proxiedSession
                              ? '重启 Antigravity（重新拉起）'
                              : antigravityState.running
                              ? '重启 Antigravity 并注入专属代理参数'
                              : '通过指定节点启动 Antigravity'}
                          </span>
                        </>
                      )}
                    </button>

                    {antigravityState.running && (
                      <button
                        className="btn-kill-claude"
                        onClick={() => void handleTerminateAntigravity()}
                        title="关闭 Antigravity.exe 及 language_server.exe 进程"
                      >
                        <Square size={14} />
                        <span>关闭进程</span>
                      </button>
                    )}
                  </div>

                  {agFeedback && (
                    <div className={`locale-feedback ${agFeedback.ok ? 'ok' : 'err'}`}>
                      {agFeedback.ok ? <Check size={14} /> : <AlertTriangle size={14} />}
                      <span>{agFeedback.text}</span>
                    </div>
                  )}
                </section>

                {/* 2. Antigravity 专属 Clash 节点选择卡 */}
                <section className="panel-card">
                  <div className="panel-card-header">
                    <div className="panel-title">
                      <Radio
                        size={15}
                        className={clashInfo.connected ? 'pulse-green' : ''}
                      />
                      <span>指定 Antigravity 专属代理节点</span>
                    </div>
                    <span
                      className={`mini-badge ${
                        clashInfo.connected ? 'connected' : 'warn-badge'
                      }`}
                    >
                      {clashInfo.connected
                        ? `${clashInfo.source} · ${clashInfo.mode.toUpperCase()}`
                        : '未连接 Clash Verge'}
                    </span>
                  </div>

                  {renderAntigravityNodeSelector()}
                </section>

                {/* 3. Antigravity 客户端路径与专属端口设置卡 */}
                <section className="panel-card">
                  <div className="panel-card-header">
                    <div className="panel-title">
                      <Cpu size={15} />
                      <span>客户端路径与专属端口设置</span>
                    </div>
                    <span className="mini-badge neutral">{agInstallTypeLabel}</span>
                  </div>

                  <div className="claude-exe-path-box">
                    <div className="exe-path-header">
                      <span>Antigravity 专属代理监听端口（与 Claude 端口独立）：</span>
                    </div>
                    <div className="exe-path-row">
                      <code className="exe-path-code">127.0.0.1 :</code>
                      <input
                        type="number"
                        className="dedicated-port-input"
                        min={1024}
                        max={65535}
                        value={agDedicatedPortInput}
                        onChange={(e) => setAgDedicatedPortInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') void handleSaveAgDedicatedPort();
                        }}
                      />
                      <button
                        className="btn-save-inline"
                        disabled={isSwitchingAgNode}
                        onClick={() => void handleSaveAgDedicatedPort()}
                      >
                        <span>保存端口</span>
                      </button>
                    </div>
                  </div>

                  <div className="claude-exe-path-box">
                    <div className="exe-path-header">
                      <span>Antigravity.exe 路径：</span>
                      {config.antigravityExePath && (
                        <button
                          className="btn-link-clear"
                          onClick={() =>
                            void window.guardAPI
                              .updateConfig({ antigravityExePath: '' })
                              .then(setState)
                          }
                        >
                          恢复自动探测
                        </button>
                      )}
                    </div>
                    <div className="exe-path-row">
                      <code
                        className="exe-path-code ellipsis"
                        title={
                          antigravityState.detectedExePath || '未检测到 Antigravity.exe'
                        }
                      >
                        {antigravityState.detectedExePath ||
                          '未检测到 Antigravity.exe，请点击右侧手动浏览选择'}
                      </code>
                      <button
                        className="btn-save-inline"
                        onClick={() =>
                          void window.guardAPI.browseAntigravityExe().then(setState)
                        }
                      >
                        <FolderOpen size={13} />
                        <span>浏览...</span>
                      </button>
                    </div>
                  </div>

                  <div className="ag-pure-footer">
                    <span>
                      ✓ 纯粹代理模式：不做时区/区域校验、不弹警告窗、不断连强杀，卫士退出时保持 Antigravity 继续运行
                    </span>
                  </div>
                </section>
              </>
            ) : (
              <>
                {/* 1. Claude 唯一启动入口 & 三重一致性校验主控卡 */}
                <section
                  className={`hero-card claude-hero-card ${
                    claudeState.running || claudeState.canLaunch
                      ? 'status-ok'
                      : isChecking && !lastProbe && !lastError
                      ? 'status-checking'
                      : 'status-mismatch'
                  }`}
                >
                  <div className="hero-top-row">
                    <div
                      className={`status-pill ${
                        claudeState.running || claudeState.canLaunch
                          ? 'status-ok'
                          : isChecking && !lastProbe && !lastError
                          ? 'status-checking'
                          : 'status-mismatch'
                      }`}
                    >
                      {claudeState.running ? (
                        <>
                          <ShieldCheck size={17} />
                          <span>
                            Claude 受控运行中 ({claudeState.processCount} 个进程)
                          </span>
                        </>
                      ) : claudeState.canLaunch ? (
                        <>
                          <CheckCircle2 size={17} />
                          <span>三重校验一致 · 允许启动 Claude</span>
                        </>
                      ) : isChecking && !lastProbe && !lastError ? (
                        <>
                          <RefreshCw className="spin" size={17} />
                          <span>正在验证所选节点出口与环境...</span>
                        </>
                      ) : (
                        <>
                          <Lock size={17} />
                          <span>未通过校验 · 禁止启动 Claude</span>
                        </>
                      )}
                    </div>

                    <button
                      className="btn-refresh"
                      disabled={isChecking || isSwitchingNode}
                      onClick={() => void window.guardAPI.checkNow('Claude 专栏手动重测')}
                    >
                      <RefreshCw className={isChecking ? 'spin' : ''} size={14} />
                      <span>{isChecking ? '校验中...' : '重新校验'}</span>
                    </button>
                  </div>

                  {/* 三重一致性对比矩阵：指定代理出口 vs 系统区域 vs 系统时区 */}
                  <div className="three-way-check-grid">
                    <div
                      className={`check-step-card ${
                        claudeState.proxyCountryCode && config.selectedClashNode
                          ? 'matched'
                          : 'unmatched'
                      }`}
                    >
                      <div className="check-step-header">
                        <span className="step-num">1. 指定代理出口</span>
                        {claudeState.proxyCountryCode && config.selectedClashNode ? (
                          <CheckCircle2 size={14} className="step-icon-ok" />
                        ) : (
                          <XCircle size={14} className="step-icon-err" />
                        )}
                      </div>
                      <div className="check-step-body">
                        {claudeState.proxyCountryCode && lastProbe ? (
                          <>
                            <div className="step-main-line">
                              <CountryFlag code={claudeState.proxyCountryCode} size="sm" />
                              <strong>
                                {claudeState.proxyCountryName} ({claudeState.proxyCountryCode})
                              </strong>
                            </div>
                            <small className="ellipsis" title={lastProbe.ip}>
                              IP: {lastProbe.ip}
                            </small>
                          </>
                        ) : (
                          <>
                            <strong className="text-warn">
                              {config.selectedClashNode ? '节点未连通' : '未选定节点'}
                            </strong>
                            <small>请在下方下拉框选择节点</small>
                          </>
                        )}
                      </div>
                    </div>

                    <div
                      className={`check-step-card ${
                        claudeState.winRegionMatched ? 'matched' : 'unmatched'
                      }`}
                    >
                      <div className="check-step-header">
                        <span className="step-num">2. 系统国家/区域</span>
                        {claudeState.winRegionMatched ? (
                          <CheckCircle2 size={14} className="step-icon-ok" />
                        ) : (
                          <XCircle size={14} className="step-icon-err" />
                        )}
                      </div>
                      <div className="check-step-body">
                        <div className="step-main-line">
                          <CountryFlag code={winLocale.regionCode} size="sm" />
                          <strong>
                            {winLocale.regionName} ({winLocale.regionCode})
                          </strong>
                        </div>
                        <small>
                          {claudeState.winRegionMatched
                            ? '与指定代理一致'
                            : '与代理地区不符！'}
                        </small>
                      </div>
                    </div>

                    <div
                      className={`check-step-card ${
                        claudeState.winTimeZoneMatched ? 'matched' : 'unmatched'
                      }`}
                    >
                      <div className="check-step-header">
                        <span className="step-num">3. 系统时区</span>
                        {claudeState.winTimeZoneMatched ? (
                          <CheckCircle2 size={14} className="step-icon-ok" />
                        ) : (
                          <XCircle size={14} className="step-icon-err" />
                        )}
                      </div>
                      <div className="check-step-body">
                        <strong
                          className="ellipsis"
                          title={winLocale.timeZoneDisplayName}
                        >
                          {winLocale.timeZoneDisplayName}
                        </strong>
                        <small>
                          {claudeState.winTimeZoneMatched
                            ? '与指定代理一致'
                            : '与代理时区不符！'}
                        </small>
                      </div>
                    </div>
                  </div>

                  {/* 校验未通过原因提示 */}
                  {claudeState.launchBlockReason && (
                    <div className="claude-block-banner">
                      <div className="block-banner-text">
                        <AlertTriangle size={15} />
                        <span>{claudeState.launchBlockReason}</span>
                      </div>
                      {claudeState.proxyCountryCode &&
                        config.defaultCountryCode &&
                        config.defaultCountryCode !== claudeState.proxyCountryCode && (
                          <button
                            className="btn-banner-quick-sync"
                            onClick={() =>
                              void window.guardAPI.setDefaultCurrent().then(setState)
                            }
                          >
                            <Sparkles size={13} />
                            <span>
                              将默认保护地区更改为 [{claudeState.proxyCountryName}]
                            </span>
                          </button>
                        )}
                      {claudeState.proxyCountryCode &&
                        (!config.defaultCountryCode ||
                          config.defaultCountryCode === claudeState.proxyCountryCode) &&
                        (!claudeState.winRegionMatched ||
                          !claudeState.winTimeZoneMatched) && (
                          <button
                            className="btn-banner-quick-sync"
                            disabled={isSyncingLocale}
                            onClick={() => void handleSyncLocaleFromClaude()}
                          >
                            <RefreshCw
                              className={isSyncingLocale ? 'spin' : ''}
                              size={13}
                            />
                            <span>
                              {isSyncingLocale
                                ? '正在同步系统时区与区域...'
                                : `一键同步系统时区与区域至 [${claudeState.proxyCountryName}]`}
                            </span>
                          </button>
                        )}
                    </div>
                  )}

                  {/* 唯一启动入口主按钮与强杀按钮 */}
                  <div className="claude-launch-actions">
                    <button
                      className={`btn-launch-claude ${
                        claudeState.canLaunch ? 'ready' : 'disabled'
                      }`}
                      disabled={
                        !claudeState.canLaunch || isLaunchingClaude || isSwitchingNode
                      }
                      onClick={() => void handleLaunchClaude()}
                    >
                      {isLaunchingClaude ? (
                        <>
                          <RefreshCw className="spin" size={16} />
                          <span>正在校验环境并拉起 Claude...</span>
                        </>
                      ) : (
                        <>
                          <Play size={16} />
                          <span>
                            {claudeState.running
                              ? '重新激活 / 唤起 Claude Desktop'
                              : '安全启动 Claude Desktop（唯一入口）'}
                          </span>
                        </>
                      )}
                    </button>

                    {claudeState.running && (
                      <button
                        className="btn-kill-claude"
                        onClick={() => void handleTerminateClaude()}
                        title="立即强杀全部 Claude 关联进程并回收启动锁"
                      >
                        <Square size={14} />
                        <span>终止 Claude</span>
                      </button>
                    )}
                  </div>

                  {claudeFeedback && (
                    <div
                      className={`locale-feedback ${claudeFeedback.ok ? 'ok' : 'err'}`}
                    >
                      {claudeFeedback.ok ? (
                        <Check size={14} />
                      ) : (
                        <AlertTriangle size={14} />
                      )}
                      <span>{claudeFeedback.text}</span>
                    </div>
                  )}
                </section>

                {/* 2. Clash Verge 专属节点选择卡片 */}
                <section className="panel-card">
                  <div className="panel-card-header">
                    <div className="panel-title">
                      <Radio
                        size={15}
                        className={clashInfo.connected ? 'pulse-green' : ''}
                      />
                      <span>指定 Clash Verge 专属代理节点</span>
                    </div>
                    <span
                      className={`mini-badge ${
                        clashInfo.connected ? 'connected' : 'warn-badge'
                      }`}
                    >
                      {clashInfo.connected
                        ? `${clashInfo.source} · ${clashInfo.mode.toUpperCase()}${
                            clashInfo.mixedPort ? ` (${clashInfo.mixedPort})` : ''
                          }`
                        : '未连接 Clash Verge'}
                    </span>
                  </div>

                  {renderClashNodeSelector()}
                </section>

                {/* 3. 启动保护与客户端设置 */}
                <section className="panel-card">
                  <div className="panel-card-header">
                    <div className="panel-title">
                      <Ban size={15} />
                      <span>启动保护与客户端设置</span>
                    </div>
                    <span className="mini-badge neutral">{installTypeLabel}</span>
                  </div>

                  <div className="setting-row">
                    <div>
                      <strong>仅允许从本面板启动 Claude</strong>
                      <p>拦截桌面、开始菜单等外部直接启动，防止未校验环境裸奔</p>
                    </div>
                    <input
                      type="checkbox"
                      className="toggle-switch"
                      checked={config.claudeExclusiveGuard}
                      onChange={(e) =>
                        void window.guardAPI
                          .updateConfig({ claudeExclusiveGuard: e.target.checked })
                          .then(setState)
                      }
                    />
                  </div>

                  <div className="claude-exe-path-box">
                    <div className="exe-path-header">
                      <span>专属代理监听端口：</span>
                    </div>
                    <div className="exe-path-row">
                      <code className="exe-path-code">127.0.0.1 :</code>
                      <input
                        type="number"
                        className="dedicated-port-input"
                        min={1024}
                        max={65535}
                        value={dedicatedPortInput}
                        onChange={(e) => setDedicatedPortInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') void handleSaveDedicatedPort();
                        }}
                      />
                      <button
                        className="btn-save-inline"
                        disabled={isSwitchingNode}
                        onClick={() => void handleSaveDedicatedPort()}
                      >
                        <span>保存端口</span>
                      </button>
                    </div>
                  </div>

                  <div className="claude-exe-path-box">
                    <div className="exe-path-header">
                      <span>客户端路径：</span>
                      {config.claudeExePath && (
                        <button
                          className="btn-link-clear"
                          onClick={() =>
                            void window.guardAPI
                              .updateConfig({ claudeExePath: '' })
                              .then(setState)
                          }
                        >
                          恢复自动探测
                        </button>
                      )}
                    </div>
                    <div className="exe-path-row">
                      <code
                        className="exe-path-code ellipsis"
                        title={claudeState.detectedExePath || '未检测到 Claude.exe'}
                      >
                        {claudeState.detectedExePath ||
                          '未检测到 Claude Desktop，请点击右侧手动选择'}
                      </code>
                      <button
                        className="btn-save-inline"
                        onClick={() =>
                          void window.guardAPI.browseClaudeExe().then(setState)
                        }
                      >
                        <FolderOpen size={13} />
                        <span>浏览...</span>
                      </button>
                    </div>
                  </div>
                </section>
              </>
            )}
          </div>
        )}

        {activeTab === 'monitor' && (
          <div className="tab-pane">
            {/* 1. 当前出口状态主卡片 */}
            <section className={`hero-card ${statusMeta.cls}`}>
              <div className="hero-top-row">
                <div className={`status-pill ${statusMeta.cls}`}>
                  {statusMeta.icon}
                  <span>{statusMeta.badge}</span>
                </div>
                <button
                  className="btn-refresh"
                  disabled={isChecking}
                  onClick={() => void window.guardAPI.checkNow('手动立即刷新')}
                >
                  <RefreshCw className={isChecking ? 'spin' : ''} size={14} />
                  <span>{isChecking ? '检测中...' : '立即检测'}</span>
                </button>
              </div>

              {lastProbe ? (
                <div className="hero-main-info">
                  <div className="hero-country-row">
                    <CountryFlag code={lastProbe.countryCode} size="lg" />
                    <div className="hero-country-titles">
                      <div className="country-primary">
                        <h1>{lastProbe.countryName}</h1>
                        <span className="iso-pill">{lastProbe.countryCode}</span>
                        {lastProbe.edgeLoc &&
                          isValidIsoCountryCode(lastProbe.countryCode) &&
                          lastProbe.edgeLoc !== lastProbe.countryCode && (
                            <span
                              className="edge-hint-pill"
                              title="IP 离线库归属地与 CDN 边缘节点物理位置不同（常见于广播 IP 或跨区路由）"
                            >
                              路由点: {lastProbe.edgeLoc}
                            </span>
                          )}
                      </div>
                      <div className="ip-row">
                        <span className="ip-label">出口 IP:</span>
                        <code className="ip-code">{lastProbe.ip}</code>
                        <button
                          className="btn-icon-tiny"
                          onClick={handleCopyIp}
                          title="复制出口 IP"
                        >
                          {copiedIp ? <Check size={13} /> : <Copy size={13} />}
                        </button>
                        <span className="latency-tag">{lastProbe.latencyMs} ms</span>
                      </div>
                    </div>
                  </div>

                  {lastError && status === 'error' && (
                    <div className="inline-error-banner">
                      <WifiOff size={14} />
                      <span>最新检测异常：{lastError}</span>
                    </div>
                  )}

                  <div className="hero-footer-meta">
                    <span className="ellipsis" title={lastProbe.viaChannel}>
                      检测通道：{lastProbe.viaChannel}
                    </span>
                    <span>更新于 {formatTime(lastProbe.checkedAt)}</span>
                  </div>
                </div>
              ) : (
                <div className="hero-empty-state">
                  {lastError ? (
                    <div className="error-empty-box">
                      <WifiOff size={28} />
                      <p>{lastError}</p>
                      <small>请确认 Clash Verge 已连接并选择有效节点</small>
                    </div>
                  ) : (
                    <p>正在通过代理隧道验证真实出口 IP...</p>
                  )}
                </div>
              )}
            </section>

            {/* 2. Windows 时区与区域同步卡片 */}
            <section className="panel-card">
              <div className="panel-card-header">
                <div className="panel-title">
                  <Globe size={15} />
                  <span>Windows 时区与区域</span>
                </div>
                {effectiveTargetCode && (
                  <span
                    className={`mini-badge ${isWinLocaleMatched ? 'connected' : 'warn-badge'}`}
                  >
                    {isWinLocaleMatched ? '已与保护地区一致' : '与保护地区不一致'}
                  </span>
                )}
              </div>

              <div className="win-locale-grid">
                <div className="win-locale-box">
                  <div className="win-locale-icon">
                    <Clock size={16} />
                  </div>
                  <div className="win-locale-info">
                    <span className="win-locale-label">时区</span>
                    <strong
                      className="win-locale-val ellipsis"
                      title={winLocale.timeZoneDisplayName}
                    >
                      {winLocale.timeZoneDisplayName}
                    </strong>
                  </div>
                </div>

                <div className="win-locale-box region-box">
                  <div className="win-locale-icon">
                    <CountryFlag code={winLocale.regionCode} size="sm" />
                  </div>
                  <div className="win-locale-info">
                    <span className="win-locale-label">区域</span>
                    <strong className="win-locale-val">{winLocale.regionName}</strong>
                  </div>
                </div>
              </div>

              <div className="locale-actions-row">
                <button
                  className="btn-sync-locale"
                  disabled={!effectiveTargetCode || isSyncingLocale}
                  onClick={() => void handleSyncLocale()}
                  title={
                    effectiveTargetCode
                      ? '将 Windows 时区与区域同步至目标保护地区（多时区大国自动匹配城市时区）'
                      : '请先选择代理节点或设置保护地区'
                  }
                >
                  <RefreshCw className={isSyncingLocale ? 'spin' : ''} size={14} />
                  <span>
                    {isSyncingLocale
                      ? '正在设置系统时区...'
                      : effectiveTargetName
                      ? `一键同步至 [${effectiveTargetName}]`
                      : '请先选择代理节点'}
                  </span>
                </button>

                <button
                  className="btn-restore-locale"
                  disabled={isSyncingLocale || isAlreadyChinaDefaultLocale}
                  onClick={() => void handleRestoreLocale()}
                  title={
                    isAlreadyChinaDefaultLocale
                      ? '当前系统已处于默认中国时区与区域'
                      : '若当前代理非中国，将先强杀 Claude 与守护进程后再还原回中国时区与区域'
                  }
                >
                  <RotateCcw size={14} />
                  <span>{isAlreadyChinaDefaultLocale ? '已是中国时区' : '还原默认时区'}</span>
                </button>
              </div>

              {localeFeedback && (
                <div className={`locale-feedback ${localeFeedback.ok ? 'ok' : 'err'}`}>
                  {localeFeedback.ok ? <Check size={14} /> : <AlertTriangle size={14} />}
                  <span>{localeFeedback.text}</span>
                </div>
              )}
            </section>

            {/* 3. 默认保护地区卡片 */}
            <section className="panel-card">
              <div className="panel-card-header">
                <div className="panel-title">
                  <Lock size={15} />
                  <span>默认保护地区设置</span>
                </div>
                {config.defaultCountryCode && (
                  <button
                    className="btn-link-clear"
                    onClick={() => void window.guardAPI.setDefaultRegion(null)}
                    title="取消固定默认地区限制"
                  >
                    <Unlock size={13} />
                    <span>清除默认</span>
                  </button>
                )}
              </div>

              <div className="default-region-body">
                <div className="default-current-display">
                  {config.defaultCountryCode ? (
                    <>
                      <CountryFlag code={config.defaultCountryCode} size="md" />
                      <div className="default-text">
                        <strong>
                          {config.defaultCountryName} ({config.defaultCountryCode})
                        </strong>
                        <small>出口偏离该地区时立即告警并拦截受保护进程</small>
                      </div>
                    </>
                  ) : (
                    <div className="default-unset-hint">
                      <span>未锁定固定地区，首次选定节点后将自动初始化</span>
                    </div>
                  )}
                </div>

                <div className="default-actions-row">
                  <button
                    className={`btn-primary-set ${isCurrentAlreadyDefault ? 'btn-already' : ''}`}
                    disabled={!canLockCurrentProbe || isCurrentAlreadyDefault}
                    onClick={() => void window.guardAPI.setDefaultCurrent()}
                  >
                    <Sparkles size={15} />
                    <span>
                      {isCurrentAlreadyDefault
                        ? `当前 [${lastProbe?.countryName}] 已是默认`
                        : canLockCurrentProbe && lastProbe
                        ? `将当前 [${lastProbe.countryName}] 设为默认`
                        : '等待检测有效地区...'}
                    </span>
                  </button>

                  <select
                    className="region-select"
                    value={config.defaultCountryCode || ''}
                    onChange={(e) => {
                      const val = e.target.value || null;
                      void window.guardAPI.setDefaultRegion(val);
                    }}
                    title="也可直接手动指定期望的国家/地区"
                  >
                    <option value="">手动指定地区...</option>
                    {isCustomCountryOutsideCommon && config.defaultCountryCode && (
                      <option value={config.defaultCountryCode}>
                        {config.defaultCountryName} ({config.defaultCountryCode})
                      </option>
                    )}
                    {COMMON_COUNTRIES.map((c) => (
                      <option key={c.code} value={c.code}>
                        {c.name} ({c.code})
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </section>
          </div>
        )}

        {activeTab === 'guard' && (
          <div className="tab-pane">
            {/* 1. 强杀触发策略卡片 */}
            <section className="panel-card">
              <div className="panel-card-header">
                <div className="panel-title">
                  <ShieldAlert size={15} />
                  <span>触发拦截条件</span>
                </div>
              </div>

              <div className="setting-row">
                <div>
                  <strong>启用额外进程守护</strong>
                  <p>异常时按进程树强杀下方列表应用（Claude 已由专栏内置保护）</p>
                </div>
                <input
                  type="checkbox"
                  className="toggle-switch"
                  checked={config.killProcessesEnabled}
                  onChange={(e) =>
                    void window.guardAPI.updateConfig({ killProcessesEnabled: e.target.checked })
                  }
                />
              </div>

              <div className="setting-row">
                <div>
                  <strong>代理断连或超时时强杀</strong>
                  <p>代理连接断开或探测超时期间禁止运行</p>
                </div>
                <input
                  type="checkbox"
                  className="toggle-switch"
                  disabled={!config.killProcessesEnabled}
                  checked={config.killOnDisconnect}
                  onChange={(e) =>
                    void window.guardAPI.updateConfig({ killOnDisconnect: e.target.checked })
                  }
                />
              </div>

              <div className="setting-row no-border-bottom">
                <div>
                  <strong>系统时区/区域不一致时强杀</strong>
                  <p>系统时区或国家区域与代理出口不符时立即终止</p>
                </div>
                <input
                  type="checkbox"
                  className="toggle-switch"
                  disabled={!config.killProcessesEnabled}
                  checked={config.killOnLocaleMismatch}
                  onChange={(e) =>
                    void window.guardAPI.updateConfig({ killOnLocaleMismatch: e.target.checked })
                  }
                />
              </div>
            </section>

            {/* 2. 进程匹配规则列表卡片 */}
            <section className="panel-card">
              <div className="panel-card-header">
                <div className="panel-title">
                  <Lock size={15} />
                  <span>额外守护进程列表</span>
                </div>
                <span className="mini-badge neutral">
                  共 {config.protectedProcessPatterns.length} 条
                </span>
              </div>

              <div className="pattern-input-group">
                <div className="pattern-input-row">
                  <input
                    type="text"
                    value={patternInput}
                    onChange={(e) => {
                      setPatternInput(e.target.value);
                      if (patternSubmitErr) setPatternSubmitErr(null);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        void handleAddPattern();
                      }
                    }}
                    placeholder="输入进程名、通配符或正则，如 *cursor*"
                  />
                  <button className="btn-save-inline" onClick={() => void handleAddPattern()}>
                    <Plus size={14} />
                    <span>添加</span>
                  </button>
                </div>

                {patternSubmitErr ? (
                  <div className="pattern-hint err">
                    <AlertTriangle size={12} />
                    <span>{patternSubmitErr}</span>
                  </div>
                ) : livePatternCheck ? (
                  livePatternCheck.valid ? (
                    <div className="pattern-hint valid">
                      <Check size={12} />
                      <span>
                        识别为
                        <strong>
                          {livePatternCheck.mode === 'regex' ? ' 正则表达式 ' : ' 通配符 '}
                        </strong>
                        模式（回车添加）
                      </span>
                    </div>
                  ) : (
                    <div className="pattern-hint err">
                      <AlertTriangle size={12} />
                      <span>{livePatternCheck.error}</span>
                    </div>
                  )
                ) : (
                  <p className="pattern-syntax-tip">
                    支持通配符（如 <code>*cursor*</code>）或正则（<code>/pattern/</code>），大小写不敏感。
                  </p>
                )}
              </div>

              {config.protectedProcessPatterns.length === 0 ? (
                <div className="pattern-empty">
                  Claude 已由专栏内置保护。如需联动保护其他应用，可在上方添加规则。
                </div>
              ) : (
                <div className="pattern-list">
                  {config.protectedProcessPatterns.map((pat) => {
                    const info = inspectProcessPattern(pat);
                    return (
                      <div key={pat} className="pattern-item">
                        <div className="pattern-item-left">
                          <code className="pattern-code">{pat}</code>
                          <span
                            className={`pattern-mode-tag ${
                              info.mode === 'regex' ? 'regex' : 'wildcard'
                            }`}
                          >
                            {info.mode === 'regex' ? '正则' : '通配符'}
                          </span>
                        </div>
                        <button
                          className="btn-remove-pattern"
                          onClick={() => void handleRemovePattern(pat)}
                          title="移除该规则"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="tab-pane">
            {/* 代理获取模式 */}
            <section className="panel-card">
              <div className="panel-card-header">
                <div className="panel-title">
                  <Settings size={15} />
                  <span>全局回退检测通道（未指定 Clash 节点时生效）</span>
                </div>
              </div>

              <div className="radio-group">
                <label className={`radio-card ${displayedProxyMode === 'auto' ? 'selected' : ''}`}>
                  <input
                    type="radio"
                    name="proxyMode"
                    checked={displayedProxyMode === 'auto'}
                    onChange={() => void handleSwitchNonManualMode('auto')}
                  />
                  <div>
                    <strong>自动识别全局出口（推荐）</strong>
                    <p>优先走系统代理，未开启系统代理时自动检测默认网卡 / TUN 路由</p>
                  </div>
                </label>

                <label
                  className={`radio-card ${displayedProxyMode === 'manual' ? 'selected' : ''}`}
                >
                  <input
                    type="radio"
                    name="proxyMode"
                    checked={displayedProxyMode === 'manual'}
                    onChange={() => {
                      if (config.proxyMode !== 'manual') {
                        setPendingManualMode(true);
                      }
                    }}
                  />
                  <div>
                    <strong>手动指定本地代理端口</strong>
                    <p>固定通过指定的 HTTP / SOCKS5 本地端口检测</p>
                  </div>
                </label>

                {displayedProxyMode === 'manual' && (
                  <div className="manual-proxy-form">
                    <select
                      value={manualProto}
                      onChange={(e) => setManualProto(e.target.value as 'http' | 'socks5')}
                    >
                      <option value="http">HTTP</option>
                      <option value="socks5">SOCKS5</option>
                    </select>
                    <input
                      type="text"
                      value={manualHost}
                      onChange={(e) => setManualHost(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') void handleSaveManualProxy();
                      }}
                      placeholder="127.0.0.1"
                    />
                    <input
                      type="number"
                      className="port-input"
                      value={manualPort}
                      onChange={(e) => setManualPort(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') void handleSaveManualProxy();
                      }}
                      placeholder="7890"
                    />
                    <button
                      className="btn-save-inline"
                      onClick={() => void handleSaveManualProxy()}
                    >
                      {config.proxyMode === 'manual' ? '保存重测' : '启用并重测'}
                    </button>
                  </div>
                )}

                <label
                  className={`radio-card ${displayedProxyMode === 'direct' ? 'selected' : ''}`}
                >
                  <input
                    type="radio"
                    name="proxyMode"
                    checked={displayedProxyMode === 'direct'}
                    onChange={() => void handleSwitchNonManualMode('direct')}
                  />
                  <div>
                    <strong>强制纯网卡直连（仅限全局 TUN 模式）</strong>
                    <p>忽略系统代理设置，直接检测系统默认网卡路由出口</p>
                  </div>
                </label>
              </div>
            </section>

            {/* 监测频率与提醒开关 */}
            <section className="panel-card">
              <div className="panel-card-header">
                <div className="panel-title">
                  <BellRing size={15} />
                  <span>巡检与提醒设置</span>
                </div>
              </div>

              <div className="setting-row">
                <div>
                  <strong>运行期后台巡检间隔</strong>
                  <p>Claude 或守护进程运行期间，定时静默复核出口 IP 是否漂移</p>
                </div>
                <select
                  className="compact-select"
                  value={config.heartbeatIntervalSec}
                  onChange={(e) =>
                    void window.guardAPI.updateConfig({
                      heartbeatIntervalSec: Number(e.target.value),
                    })
                  }
                >
                  <option value={0}>仅本地事件触发</option>
                  <option value={5}>每 5 秒</option>
                  <option value={10}>每 10 秒</option>
                  <option value={15}>每 15 秒 (推荐)</option>
                  <option value={30}>每 30 秒</option>
                  <option value={60}>每 60 秒</option>
                </select>
              </div>

              <div className="setting-row">
                <div>
                  <strong>置顶警告弹窗</strong>
                  <p>地区异常或拦截进程时在屏幕右下角弹出置顶提醒</p>
                </div>
                <input
                  type="checkbox"
                  className="toggle-switch"
                  checked={config.alertPopupEnabled}
                  onChange={(e) =>
                    void window.guardAPI.updateConfig({ alertPopupEnabled: e.target.checked })
                  }
                />
              </div>

              <div className="setting-row">
                <div>
                  <strong>异常警告提示音</strong>
                  <p>触发弹窗警告时播放短促提示音</p>
                </div>
                <input
                  type="checkbox"
                  className="toggle-switch"
                  checked={config.alertSoundEnabled}
                  onChange={(e) =>
                    void window.guardAPI.updateConfig({ alertSoundEnabled: e.target.checked })
                  }
                />
              </div>

              <div className="setting-row">
                <div>
                  <strong>代理断连或超时报警</strong>
                  <p>代理连接失败或节点超时时弹窗提醒</p>
                </div>
                <input
                  type="checkbox"
                  className="toggle-switch"
                  checked={config.alertOnDisconnect}
                  onChange={(e) =>
                    void window.guardAPI.updateConfig({ alertOnDisconnect: e.target.checked })
                  }
                />
              </div>

              <div className="setting-row">
                <div>
                  <strong>关闭窗口时最小化到托盘</strong>
                  <p>点击右上角关闭按钮后隐藏至系统托盘继续守护</p>
                </div>
                <input
                  type="checkbox"
                  className="toggle-switch"
                  checked={config.closeToTray}
                  onChange={(e) =>
                    void window.guardAPI.updateConfig({ closeToTray: e.target.checked })
                  }
                />
              </div>

              <div className="setting-row">
                <div>
                  <strong>开机自动启动</strong>
                  <p>登录 Windows 时自动运行本程序</p>
                </div>
                <input
                  type="checkbox"
                  className="toggle-switch"
                  checked={config.autoLaunch}
                  onChange={(e) =>
                    void window.guardAPI.updateConfig({ autoLaunch: e.target.checked })
                  }
                />
              </div>

              <div className="custom-probe-box">
                <label>
                  自定义探测 URL（留空默认使用 Cloudflare / AWS 全球探测源）：
                </label>
                <div className="custom-probe-row">
                  <input
                    type="text"
                    value={customProbe}
                    onChange={(e) => {
                      setCustomProbe(e.target.value);
                      if (probeUrlErr) setProbeUrlErr(null);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') void handleSaveCustomProbe();
                    }}
                    placeholder="例如 https://cp.cloudflare.com/cdn-cgi/trace"
                  />
                  <button
                    className="btn-save-inline"
                    onClick={() => void handleSaveCustomProbe()}
                  >
                    应用
                  </button>
                </div>
                {probeUrlErr && (
                  <div className="pattern-hint err">
                    <AlertTriangle size={12} />
                    <span>{probeUrlErr}</span>
                  </div>
                )}
              </div>
            </section>
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="tab-pane">
            <section className="panel-card logs-card">
              <div className="panel-card-header">
                <div className="panel-title">
                  <History size={15} />
                  <span>最近状态与变更记录</span>
                </div>
                {logs.length > 0 && (
                  <button
                    className="btn-link-clear"
                    onClick={() => void window.guardAPI.clearLogs()}
                  >
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
        )}
      </main>
    </div>
  );
};

function formatTime(ts: number): string {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}
