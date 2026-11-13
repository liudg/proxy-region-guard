import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Ban,
  Bot,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
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
import { getTargetServiceVerificationError } from '../shared/probeValidation';
import {
  DEFAULT_CHINA_REGION_CODE,
  DEFAULT_CHINA_TIMEZONE_ID,
  isWindowsLocaleMatchingCountry,
} from '../shared/timezones';
import { CountryFlag } from './CountryFlag';
import { ClashNodeSelector } from './ClashNodeSelector';

type ActiveTab = 'launcher' | 'monitor' | 'settings' | 'logs';
type LauncherSubTab = 'antigravity' | 'claude';
type MonitorSubTab = 'status' | 'guard';

export const MainDashboard: React.FC = () => {
  const [state, setState] = useState<AppStateSnapshot | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>('launcher');
  const [launcherSubTab, setLauncherSubTab] = useState<LauncherSubTab>('antigravity');
  const [monitorSubTab, setMonitorSubTab] = useState<MonitorSubTab>('status');
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

  // 低频路径与端口设置折叠态（未检测到安装路径时自动展开）
  const [agSettingsOpen, setAgSettingsOpen] = useState(false);
  const [claudeSettingsOpen, setClaudeSettingsOpen] = useState(false);

  // 运行中应用破坏性操作（重启/强杀/切换节点/改端口）二次确认态
  const [pendingAgConfirm, setPendingAgConfirm] = useState<'restart' | 'kill' | null>(null);
  const [pendingClaudeConfirm, setPendingClaudeConfirm] = useState<
    | { type: 'kill' }
    | { type: 'switch-node'; nodeName: string | null; profileUid: string | null }
    | { type: 'change-port'; port: number }
    | null
  >(null);

  // 全局非启动器页操作提示/错误反馈
  const [globalNotice, setGlobalNotice] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  useEffect(() => {
    void window.guardAPI
      .getState()
      .then((initial) => {
        setState(initial);
        syncFormFromConfig(initial.config);
      })
      .catch(() => {
        // ignore initial load error
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

  useEffect(() => {
    if (!state) return;
    setDedicatedPortInput(String(state.config.dedicatedProxyPort));
    setAgDedicatedPortInput(String(state.config.antigravityDedicatedPort));
    setCustomProbe(state.config.customProbeUrl);
    if (!pendingManualMode) {
      setManualProto(state.config.manualProxy.protocol);
      setManualHost(state.config.manualProxy.host);
      setManualPort(String(state.config.manualProxy.port));
    }
  }, [
    state?.config.dedicatedProxyPort,
    state?.config.antigravityDedicatedPort,
    state?.config.customProbeUrl,
    state?.config.manualProxy.protocol,
    state?.config.manualProxy.host,
    state?.config.manualProxy.port,
    pendingManualMode,
  ]);

  useEffect(() => {
    if (!state?.antigravityState.running && pendingAgConfirm) {
      setPendingAgConfirm(null);
    }
  }, [state?.antigravityState.running, pendingAgConfirm]);

  useEffect(() => {
    if (!state?.claudeState.running && pendingClaudeConfirm) {
      setPendingClaudeConfirm(null);
    }
  }, [state?.claudeState.running, pendingClaudeConfirm]);

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
  const claudeVerificationError = getTargetServiceVerificationError(claudeState.nodeProbe);

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

  const extractErrorMessage = (err: unknown): string => {
    const raw = err instanceof Error ? err.message : String(err || '操作失败');
    return raw.replace(/^Error invoking remote method '[^']+':\s*(Error:\s*)?/i, '').trim();
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

  const showTimedLocaleFeedback = (ok: boolean, text: string) => {
    setLocaleFeedback({ ok, text });
    setTimeout(() => {
      setLocaleFeedback((prev) => (prev && prev.text === text ? null : prev));
    }, 5500);
  };

  const showTimedGlobalNotice = (ok: boolean, text: string) => {
    setGlobalNotice({ ok, text });
    setTimeout(() => {
      setGlobalNotice((prev) => (prev && prev.text === text ? null : prev));
    }, 5000);
  };

  const notifyError = (
    err: unknown,
    target: 'ag' | 'claude' | 'locale' | 'global' = 'global'
  ) => {
    const msg = extractErrorMessage(err);
    if (target === 'ag') showTimedAgFeedback(false, msg);
    else if (target === 'claude') showTimedClaudeFeedback(false, msg);
    else if (target === 'locale') showTimedLocaleFeedback(false, msg);
    else showTimedGlobalNotice(false, msg);
  };

  const updateConfigSafe = async (
    partial: Partial<AppConfig>,
    target: 'ag' | 'claude' | 'locale' | 'global' = 'global'
  ): Promise<AppStateSnapshot | null> => {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const next = await window.guardAPI.updateConfig(partial);
        setState(next);
        return next;
      } catch (err) {
        const msg = extractErrorMessage(err);
        if (attempt < 2 && msg.includes('正在进行')) {
          await new Promise((r) => setTimeout(r, 320));
          continue;
        }
        notifyError(err, target);
        return null;
      }
    }
    return null;
  };

  const executeSelectClaudeNode = async (
    nodeName: string | null,
    profileUid: string | null
  ) => {
    setPendingClaudeConfirm(null);
    setIsSwitchingNode(true);
    try {
      const next = await window.guardAPI.selectClashNode(nodeName, profileUid);
      setState(next);
    } catch (err) {
      notifyError(err, 'claude');
    } finally {
      setIsSwitchingNode(false);
    }
  };

  const handleSelectClaudeNode = async (
    nodeName: string | null,
    profileUid: string | null
  ) => {
    const isSame =
      nodeName === config.selectedClashNode &&
      (profileUid || null) === (config.selectedClashProfileUid || null);
    if (isSame) return;

    if (claudeState.running) {
      setPendingClaudeConfirm({
        type: 'switch-node',
        nodeName,
        profileUid,
      });
      return;
    }

    await executeSelectClaudeNode(nodeName, profileUid);
  };

  const handleSelectAntigravityNode = async (
    nodeName: string | null,
    profileUid: string | null
  ) => {
    const wasRunning = antigravityState.running && antigravityState.proxiedSession;
    setIsSwitchingAgNode(true);
    setAgFeedback(null);
    try {
      const next = await window.guardAPI.selectAntigravityClashNode(nodeName, profileUid);
      setState(next);
      if (!nodeName) return;

      const selectedNode = nodeName.trim();
      const selectedProfileUid = profileUid?.trim() || next.config.antigravityClashProfileUid;
      const bindingMatched =
        next.clashInfo.connected &&
        next.clashInfo.antigravityPortListening &&
        next.clashInfo.antigravityBoundNode === selectedNode &&
        next.clashInfo.antigravityBoundProfileUid === selectedProfileUid &&
        next.clashInfo.antigravityDedicatedPort === next.config.antigravityDedicatedPort;
      if (!bindingMatched || next.antigravityState.nodeProbeError) {
        showTimedAgFeedback(
          false,
          next.antigravityState.nodeProbeError || `节点 [${selectedNode}] 的专属代理绑定未就绪`
        );
        return;
      }

      if (wasRunning) {
        showTimedAgFeedback(
          true,
          `专属端口已绑定至节点 [${selectedNode}]`
        );
      }
    } catch (err) {
      notifyError(err, 'ag');
    } finally {
      setIsSwitchingAgNode(false);
    }
  };

  const handleLaunchClaude = async () => {
    setPendingClaudeConfirm(null);
    setIsLaunchingClaude(true);
    setClaudeFeedback(null);
    try {
      const res = await window.guardAPI.launchClaude();
      setState(res.state);
      showTimedClaudeFeedback(res.ok, res.message);
    } catch (err) {
      notifyError(err, 'claude');
    } finally {
      setIsLaunchingClaude(false);
    }
  };

  const executeTerminateClaude = async () => {
    setPendingClaudeConfirm(null);
    setClaudeFeedback(null);
    try {
      const res = await window.guardAPI.terminateClaudeNow();
      setState(res.state);
      showTimedClaudeFeedback(res.ok, res.message);
    } catch (err) {
      notifyError(err, 'claude');
    }
  };

  const handleTerminateClaude = () => {
    if (claudeState.running) {
      setPendingClaudeConfirm({ type: 'kill' });
      return;
    }
    void executeTerminateClaude();
  };

  const handleSyncLocaleFromClaude = async () => {
    setClaudeFeedback(null);
    try {
      const res = await window.guardAPI.syncSystemLocaleToDefault('claude');
      setState(res.state);
      showTimedClaudeFeedback(res.ok, res.message);
    } catch (err) {
      notifyError(err, 'claude');
    }
  };

  const executeLaunchAntigravity = async () => {
    setPendingAgConfirm(null);
    setIsLaunchingAg(true);
    setAgFeedback(null);
    try {
      const res = await window.guardAPI.launchAntigravity();
      setState(res.state);
      showTimedAgFeedback(res.ok, res.message);
    } catch (err) {
      notifyError(err, 'ag');
    } finally {
      setIsLaunchingAg(false);
    }
  };

  const handleLaunchAntigravity = () => {
    if (antigravityState.running) {
      setPendingAgConfirm('restart');
      return;
    }
    void executeLaunchAntigravity();
  };

  const executeTerminateAntigravity = async () => {
    setPendingAgConfirm(null);
    setAgFeedback(null);
    try {
      const res = await window.guardAPI.terminateAntigravityNow();
      setState(res.state);
      showTimedAgFeedback(res.ok, res.message);
    } catch (err) {
      notifyError(err, 'ag');
    }
  };

  const handleTerminateAntigravity = () => {
    if (antigravityState.running) {
      setPendingAgConfirm('kill');
      return;
    }
    void executeTerminateAntigravity();
  };

  const executeSaveDedicatedPort = async (portNum: number) => {
    setPendingClaudeConfirm(null);
    setIsSwitchingNode(true);
    try {
      const next = await updateConfigSafe(
        { dedicatedProxyPort: portNum },
        'claude'
      );
      if (next) {
        showTimedClaudeFeedback(
          true,
          `Claude 专属代理端口已更新为 127.0.0.1:${portNum}`
        );
      }
    } finally {
      setIsSwitchingNode(false);
    }
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
    if (claudeState.running) {
      setPendingClaudeConfirm({ type: 'change-port', port: portNum });
      return;
    }
    await executeSaveDedicatedPort(portNum);
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
      const next = await updateConfigSafe(
        { antigravityDedicatedPort: portNum },
        'ag'
      );
      if (next) {
        showTimedAgFeedback(
          true,
          `Antigravity 专属代理端口已更新为 127.0.0.1:${portNum}${
            antigravityState.running
              ? '（运行中的 Antigravity 需重启后才使用新端口）'
              : ''
          }`
        );
      }
    } finally {
      setIsSwitchingAgNode(false);
    }
  };

  const handleSwitchNonManualMode = async (mode: 'auto' | 'direct') => {
    setPendingManualMode(false);
    if (config.proxyMode === mode) return;
    await updateConfigSafe({ proxyMode: mode }, 'global');
  };

  const handleSaveManualProxy = async () => {
    const cleanHost = manualHost.trim() || '127.0.0.1';
    const portNum = Math.max(1, Math.min(65535, Math.round(Number(manualPort) || 7890)));
    setManualHost(cleanHost);
    setManualPort(String(portNum));
    setPendingManualMode(false);

    await updateConfigSafe(
      {
        proxyMode: 'manual',
        manualProxy: {
          protocol: manualProto,
          host: cleanHost,
          port: portNum,
        },
      },
      'global'
    );
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
    const next = await updateConfigSafe({ customProbeUrl: trimmed }, 'global');
    if (next) {
      showTimedGlobalNotice(true, trimmed ? '已更新自定义探测源并重新检测' : '已恢复默认全球探测源');
    }
  };

  const handleSyncLocale = async () => {
    setLocaleFeedback(null);
    try {
      const res = await window.guardAPI.syncSystemLocaleToDefault('monitor');
      setState(res.state);
      showTimedLocaleFeedback(res.ok, res.message);
    } catch (err) {
      notifyError(err, 'locale');
    }
  };

  const handleRestoreLocale = async () => {
    setLocaleFeedback(null);
    try {
      const res = await window.guardAPI.restoreDefaultChinaLocale();
      setState(res.state);
      showTimedLocaleFeedback(res.ok, res.message);
    } catch (err) {
      notifyError(err, 'locale');
    }
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
    await updateConfigSafe(
      {
        protectedProcessPatterns: [...config.protectedProcessPatterns, check.normalized],
      },
      'global'
    );
  };

  const handleRemovePattern = async (target: string) => {
    const filtered = config.protectedProcessPatterns.filter((p) => p !== target);
    await updateConfigSafe({ protectedProcessPatterns: filtered }, 'global');
  };

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

  const isLocaleOnlyMismatch =
    status === 'mismatch' &&
    (!config.defaultCountryCode ||
      lastProbe?.countryCode?.toUpperCase() === config.defaultCountryCode.toUpperCase()) &&
    !isWinLocaleMatched;

  const statusMeta = {
    ok: {
      badge: isWinLocaleMatched
        ? '状态正常 · 代理与时区一致'
        : '代理通道正常 · 未锁定保护地区',
      cls: 'status-ok',
      icon: <ShieldCheck size={18} />,
    },
    mismatch: isLocaleOnlyMismatch
      ? {
          badge: '提醒 · 代理地区正常，系统时区尚未同步',
          cls: 'status-locale-warn',
          icon: <AlertTriangle size={18} />,
        }
      : {
          badge: '警告 · 代理出口偏离默认保护地区！',
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

  const isAlreadyChinaDefaultLocale =
    winLocale.regionCode.toUpperCase() === DEFAULT_CHINA_REGION_CODE &&
    winLocale.timeZoneId.toLowerCase() === DEFAULT_CHINA_TIMEZONE_ID.toLowerCase();

  const livePatternCheck = patternInput.trim() ? inspectProcessPattern(patternInput) : null;

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

  const isAgSettingsExpanded =
    agSettingsOpen || antigravityState.installType === 'not-found';
  const isClaudeSettingsExpanded =
    claudeSettingsOpen || claudeState.installType === 'not-found';

  const launcherTabDotClass =
    (antigravityState.running && antigravityState.proxiedSession) || claudeState.running
      ? 'running'
      : antigravityState.canLaunch || claudeState.canLaunch
      ? 'ready'
      : 'locked';

  const monitorTabDotClass =
    status === 'ok'
      ? 'running'
      : status === 'error' || (status === 'mismatch' && !isLocaleOnlyMismatch)
      ? 'locked'
      : isLocaleOnlyMismatch
      ? 'external'
      : status === 'checking'
      ? 'checking'
      : 'ready';

  const titlebarDotClass =
    activeTab === 'launcher'
      ? launcherSubTab === 'antigravity'
        ? (antigravityState.running && antigravityState.proxiedSession) ||
          antigravityState.canLaunch
          ? 'status-ok'
          : statusMeta.cls
        : claudeState.running || claudeState.canLaunch
        ? 'status-ok'
        : statusMeta.cls
      : statusMeta.cls;

  const clashHeaderBadgeText = clashInfo.connected
    ? `${
        clashInfo.activeProfileName
          ? `当前订阅: ${clashInfo.activeProfileName}`
          : clashInfo.source
      } · ${clashInfo.mode.toUpperCase()}`
    : '未连接 Clash Verge';

  const closeButtonTitle = config.closeToTray
    ? '隐藏到系统托盘'
    : claudeState.running
    ? '退出程序（将同时安全终止受控运行中的 Claude，保持 Antigravity 运行）'
    : '退出程序（保持 Antigravity 运行）';

  return (
    <div className="dashboard-window">
      {/* 自绘无边框标题栏 */}
      <header className="titlebar drag-region">
        <div className="titlebar-brand">
          <span className={`brand-dot ${titlebarDotClass}`} />
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
            title={closeButtonTitle}
          >
            <X size={15} />
          </button>
        </div>
      </header>

      {/* 顶部导航栏（精简为 4 个一级 Tab：启动器 / 实时监控 / 设置 / 日志） */}
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
          {config.killProcessesEnabled && config.protectedProcessPatterns.length > 0 && (
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
        {globalNotice && activeTab !== 'launcher' && (
          <div className={`locale-feedback global-top-notice ${globalNotice.ok ? 'ok' : 'err'}`}>
            {globalNotice.ok ? <Check size={14} /> : <AlertTriangle size={14} />}
            <span>{globalNotice.text}</span>
          </div>
        )}

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
                      : claudeState.isProbingNode &&
                        !claudeState.nodeProbe &&
                        !claudeState.nodeProbeError
                      ? 'checking'
                      : 'locked'
                  }`}
                />
              </button>
            </div>

            {launcherSubTab === 'antigravity' ? (
              <>
                {/* 1. Antigravity 专属 Clash 节点选择卡（置顶首位，展开下拉列表空间充足） */}
                <section className="panel-card">
                  <div className="panel-card-header">
                    <div className="panel-title">
                      <Radio
                        size={15}
                        className={clashInfo.connected ? 'pulse-green' : ''}
                      />
                      <span>1. 指定 Clash 专属代理节点（支持跨订阅组）</span>
                    </div>
                    <span
                      className={`mini-badge ${
                        clashInfo.connected ? 'connected' : 'warn-badge'
                      }`}
                    >
                      {clashHeaderBadgeText}
                    </span>
                  </div>

                  <ClashNodeSelector
                    appLabel="Antigravity"
                    clashInfo={clashInfo}
                    selectedNode={config.antigravityClashNode}
                    selectedProfileUid={config.antigravityClashProfileUid}
                    selectedProfileName={config.antigravityClashProfileName}
                    boundProfileUid={clashInfo.antigravityBoundProfileUid}
                    boundProfileName={clashInfo.antigravityBoundProfileName}
                    dedicatedPort={config.antigravityDedicatedPort}
                    portListening={clashInfo.antigravityPortListening}
                    isSwitching={isSwitchingAgNode}
                    onSelectNode={(node, profUid) =>
                      void handleSelectAntigravityNode(node, profUid)
                    }
                  />
                </section>

                {/* 2. Antigravity 纯代理启动主控卡 */}
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
                        void window.guardAPI
                          .probeAntigravityNode()
                          .then(setState)
                          .catch((err) => notifyError(err, 'ag'))
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
                  <div
                    className={`ag-node-exit-card ${
                      antigravityState.nodeProbe?.regionMismatchDetail ? 'mismatch-card' : ''
                    }`}
                  >
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
                              {antigravityState.nodeProbe.regionMismatchDetail &&
                              antigravityState.nodeProbe.googleCountryCode ? (
                                <span
                                  className="target-verify-pill mismatch"
                                  title={antigravityState.nodeProbe.regionMismatchDetail}
                                >
                                  ⚠️ Google识别: {antigravityState.nodeProbe.googleCountryName} (
                                  {antigravityState.nodeProbe.googleCountryCode})
                                </span>
                              ) : antigravityState.nodeProbe.googleCountryCode ? (
                                <span
                                  className="target-verify-pill verified"
                                  title="已通过 Google 目标服务真实地区校验"
                                >
                                  ✓ Google验证: {antigravityState.nodeProbe.googleCountryCode}
                                </span>
                              ) : null}
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
                            获取节点 [{config.antigravityClashNode}] 出口信息并校验 Google 真实地区...
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
                          请先在上方下拉框选择要为 Antigravity 绑定的 Clash 代理节点
                        </span>
                      </div>
                    )}
                  </div>

                  {antigravityState.nodeProbe?.regionMismatchDetail && (
                    <div className="ag-warn-banner">
                      <AlertTriangle size={14} />
                      <span>
                        <strong>假地区 / 送中节点预警：</strong>
                        {antigravityState.nodeProbe.regionMismatchDetail}
                        ，Antigravity 可能会报错地区不受支持，建议更换其他节点。
                      </span>
                    </div>
                  )}

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
                    </div>
                  </div>

                  {/* 外部直连运行提示或未就绪指引 */}
                  {antigravityState.running && !antigravityState.proxiedSession && (
                    <div className="ag-info-banner">
                      <Info size={14} />
                      <span>
                        当前 Antigravity 由外部启动，可点击下方按钮重启以绑定专属代理通道。
                      </span>
                    </div>
                  )}

                  {!antigravityState.canLaunch && antigravityState.launchHint && (
                    <div className="ag-info-banner">
                      <Info size={14} />
                      <span>{antigravityState.launchHint}</span>
                    </div>
                  )}

                  {/* 运行中重启/强杀二次确认栏 */}
                  {pendingAgConfirm && (
                    <div className="inline-confirm-bar">
                      <div className="confirm-bar-text">
                        <AlertTriangle size={15} />
                        <span>
                          {pendingAgConfirm === 'restart'
                            ? '重启将强制终止当前 Antigravity.exe 与 language_server.exe 进程树并重新拉起，请确认已保存代码更改。'
                            : '将强制终止全部 Antigravity.exe 与 language_server.exe 进程，请确认已保存工作内容。'}
                        </span>
                      </div>
                      <div className="confirm-bar-actions">
                        <button
                          type="button"
                          className="btn-confirm-danger"
                          disabled={isLaunchingAg}
                          onClick={() =>
                            void (pendingAgConfirm === 'restart'
                              ? executeLaunchAntigravity()
                              : executeTerminateAntigravity())
                          }
                        >
                          {pendingAgConfirm === 'restart' ? '确认重启' : '确认关闭'}
                        </button>
                        <button
                          type="button"
                          className="btn-confirm-cancel"
                          onClick={() => setPendingAgConfirm(null)}
                        >
                          取消
                        </button>
                      </div>
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
                      onClick={handleLaunchAntigravity}
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
                        onClick={handleTerminateAntigravity}
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

                {/* 3. Antigravity 客户端路径与专属端口设置卡（默认折叠，节省首屏纵向空间） */}
                <section className={`panel-card collapsible-card ${isAgSettingsExpanded ? 'expanded' : 'collapsed'}`}>
                  <div
                    className="panel-card-header collapsible-header"
                    role="button"
                    tabIndex={0}
                    onClick={() => setAgSettingsOpen((prev) => !prev)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setAgSettingsOpen((prev) => !prev);
                      }
                    }}
                  >
                    <div className="panel-title">
                      <Cpu size={15} />
                      <span>客户端路径与专属端口设置</span>
                    </div>
                    <div className="collapsible-header-right">
                      <span className="mini-badge neutral">
                        127.0.0.1:{config.antigravityDedicatedPort} · {agInstallTypeLabel}
                      </span>
                      <span className="collapse-chevron">
                        {isAgSettingsExpanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
                      </span>
                    </div>
                  </div>

                  {isAgSettingsExpanded && (
                    <div className="collapsible-body">
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
                                void updateConfigSafe({ antigravityExePath: '' }, 'ag')
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
                              void window.guardAPI
                                .browseAntigravityExe()
                                .then(setState)
                                .catch((err) => notifyError(err, 'ag'))
                            }
                          >
                            <FolderOpen size={13} />
                            <span>浏览...</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </section>
              </>
            ) : (
              <>
                {/* 1. Clash Verge Rev 全订阅组专属节点选择卡片（置顶首位，展开下拉列表空间充足） */}
                <section className="panel-card">
                  <div className="panel-card-header">
                    <div className="panel-title">
                      <Radio
                        size={15}
                        className={clashInfo.connected ? 'pulse-green' : ''}
                      />
                      <span>1. 指定 Clash 专属代理节点（支持跨订阅组）</span>
                    </div>
                    <span
                      className={`mini-badge ${
                        clashInfo.connected ? 'connected' : 'warn-badge'
                      }`}
                    >
                      {clashHeaderBadgeText}
                    </span>
                  </div>

                  <ClashNodeSelector
                    appLabel="Claude"
                    clashInfo={clashInfo}
                    selectedNode={config.selectedClashNode}
                    selectedProfileUid={config.selectedClashProfileUid}
                    selectedProfileName={config.selectedClashProfileName}
                    boundProfileUid={clashInfo.boundProfileUid}
                    boundProfileName={clashInfo.boundProfileName}
                    dedicatedPort={config.dedicatedProxyPort}
                    portListening={clashInfo.dedicatedPortListening}
                    isSwitching={isSwitchingNode}
                    onSelectNode={(node, profUid) =>
                      void handleSelectClaudeNode(node, profUid)
                    }
                  />
                </section>

                {/* 2. Claude 唯一启动入口 & 三重一致性校验主控卡 */}
                <section
                  className={`hero-card claude-hero-card ${
                    claudeState.verificationFailure
                      ? 'status-checking'
                      : claudeState.running || claudeState.canLaunch
                      ? 'status-ok'
                      : claudeState.isProbingNode &&
                        !claudeState.nodeProbe &&
                        !claudeState.nodeProbeError
                      ? 'status-checking'
                      : 'status-mismatch'
                  }`}
                >
                  <div className="hero-top-row">
                    <div
                      className={`status-pill ${
                        claudeState.verificationFailure
                          ? 'status-checking'
                          : claudeState.running || claudeState.canLaunch
                          ? 'status-ok'
                          : claudeState.isProbingNode &&
                            !claudeState.nodeProbe &&
                            !claudeState.nodeProbeError
                          ? 'status-checking'
                          : 'status-mismatch'
                      }`}
                    >
                      {claudeState.verificationFailure ? (
                        <>
                          <Clock size={17} />
                          <span>地区校验暂时不可用 · 后台复核中</span>
                        </>
                      ) : claudeState.running ? (
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
                      ) : claudeState.isProbingNode &&
                        !claudeState.nodeProbe &&
                        !claudeState.nodeProbeError ? (
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
                      disabled={claudeState.isProbingNode || isSwitchingNode}
                      onClick={() =>
                        void window.guardAPI
                          .probeClaudeNode('Claude 专栏手动重测')
                          .then(setState)
                          .catch((err) => notifyError(err, 'claude'))
                      }
                    >
                      <RefreshCw
                        className={claudeState.isProbingNode ? 'spin' : ''}
                        size={14}
                      />
                      <span>{claudeState.isProbingNode ? '校验中...' : '重新校验'}</span>
                    </button>
                  </div>

                  {claudeState.verificationFailure && (
                    <div className="claude-verification-notice">
                      <Clock size={15} className="verification-notice-icon" />
                      <div className="verification-notice-body">
                        <strong className="verification-notice-reason">
                          {claudeState.verificationFailure.reason}
                        </strong>
                        <p>
                          首次失败 {formatTime(claudeState.verificationFailure.startedAt)} ·
                          持续至 {formatTime(claudeState.verificationFailure.deadlineAt)} 仍未恢复将终止 Claude 并提醒。
                        </p>
                        <small>
                          {claudeState.lockedSessionIp
                            ? `🔒 锁定会话 IP：${claudeState.lockedSessionIp} · `
                            : ''}
                          最后成功校验：{claudeState.lastVerificationSuccessAt
                            ? formatTime(claudeState.lastVerificationSuccessAt) : '暂无成功记录'}
                        </small>
                      </div>
                    </div>
                  )}

                  {/* 三重一致性对比矩阵：指定代理出口 vs 系统区域 vs 系统时区 */}
                  <div className="three-way-check-grid">
                    <div
                      className={`check-step-card ${
                        claudeState.proxyCountryCode &&
                        config.selectedClashNode &&
                        !claudeVerificationError
                          ? 'matched'
                          : 'unmatched'
                      }`}
                    >
                      <div className="check-step-header">
                        <span className="step-num">1. 指定代理出口</span>
                        {claudeState.proxyCountryCode &&
                        config.selectedClashNode &&
                        !claudeVerificationError ? (
                          <CheckCircle2 size={14} className="step-icon-ok" />
                        ) : (
                          <XCircle size={14} className="step-icon-err" />
                        )}
                      </div>
                      <div className="check-step-body">
                        {claudeState.proxyCountryCode && claudeState.nodeProbe ? (
                          <>
                            <div className="step-main-line">
                              <CountryFlag code={claudeState.proxyCountryCode} size="sm" />
                              <strong>
                                {claudeState.proxyCountryName} ({claudeState.proxyCountryCode})
                              </strong>
                            </div>
                            {claudeState.nodeProbe.regionMismatchDetail ? (
                              <small
                                className="ellipsis text-danger"
                                title={claudeState.nodeProbe.regionMismatchDetail}
                              >
                                ⚠️ 实际识别:{' '}
                                Claude={claudeState.nodeProbe.claudeTraceLoc}
                              </small>
                            ) : claudeVerificationError ? (
                              <small className="text-danger">{claudeVerificationError}</small>
                            ) : claudeState.running && claudeState.lockedSessionIp ? (
                              <small
                                className="ellipsis"
                                title={`已锁定会话出口 IP: ${claudeState.lockedSessionIp}${
                                  claudeState.nodeProbe.claudeTraceIp &&
                                  claudeState.nodeProbe.claudeTraceIp !== claudeState.nodeProbe.ip
                                    ? ` · 常规回显 IP: ${claudeState.nodeProbe.ip}`
                                    : ''
                                } (${claudeState.nodeProbe.latencyMs} ms)`}
                              >
                                🔒 锁定会话 IP: {claudeState.lockedSessionIp} ·{' '}
                                {claudeState.nodeProbe.latencyMs} ms
                              </small>
                            ) : (
                              <small
                                className="ellipsis"
                                title={`Claude 实际出口 IP: ${
                                  claudeState.nodeProbe.claudeTraceIp || claudeState.nodeProbe.ip
                                }${
                                  claudeState.nodeProbe.claudeTraceIp &&
                                  claudeState.nodeProbe.claudeTraceIp !== claudeState.nodeProbe.ip
                                    ? ` · 常规回显 IP: ${claudeState.nodeProbe.ip} (同国 AI 分流)`
                                    : ''
                                } (${claudeState.nodeProbe.latencyMs} ms)`}
                              >
                                Claude IP:{' '}
                                {claudeState.nodeProbe.claudeTraceIp || claudeState.nodeProbe.ip}
                                {claudeState.nodeProbe.claudeTraceIp &&
                                claudeState.nodeProbe.claudeTraceIp !== claudeState.nodeProbe.ip
                                  ? ' (AI分流)'
                                  : ''}{' '}
                                · {claudeState.nodeProbe.latencyMs} ms
                                {' · 目标服务地区校验通过'}
                              </small>
                            )}
                          </>
                        ) : (
                          <>
                            <strong className="text-warn">
                              {!config.selectedClashNode
                                ? '未选定节点'
                                : claudeState.isProbingNode
                                ? '正在探测节点...'
                                : '节点未连通'}
                            </strong>
                            <small>
                              {config.selectedClashNode
                                ? claudeState.nodeProbeError || '请检查节点连通性'
                                : '请先在上方下拉框选择节点'}
                            </small>
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
                        !claudeVerificationError &&
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

                  {/* 运行中切换节点 / 修改端口 / 强杀二次确认栏 */}
                  {pendingClaudeConfirm && (
                    <div className="inline-confirm-bar">
                      <div className="confirm-bar-text">
                        <AlertTriangle size={15} />
                        <span>
                          {pendingClaudeConfirm.type === 'switch-node'
                            ? `Claude 正在运行中，切换节点至 [${
                                pendingClaudeConfirm.nodeName || '未绑定'
                              }] 将先安全终止当前 Claude 会话，待新节点通过三重校验后可重新启动。`
                            : pendingClaudeConfirm.type === 'change-port'
                            ? `Claude 正在运行中，修改专属端口为 ${pendingClaudeConfirm.port} 将先终止当前 Claude 会话。`
                            : '确定要立即终止全部 Claude 关联进程并回收启动授权锁吗？'}
                        </span>
                      </div>
                      <div className="confirm-bar-actions">
                        <button
                          type="button"
                          className="btn-confirm-danger"
                          disabled={isSwitchingNode}
                          onClick={() => {
                            if (pendingClaudeConfirm.type === 'switch-node') {
                              void executeSelectClaudeNode(
                                pendingClaudeConfirm.nodeName,
                                pendingClaudeConfirm.profileUid
                              );
                            } else if (pendingClaudeConfirm.type === 'change-port') {
                              void executeSaveDedicatedPort(pendingClaudeConfirm.port);
                            } else {
                              void executeTerminateClaude();
                            }
                          }}
                        >
                          {pendingClaudeConfirm.type === 'switch-node'
                            ? '确认切换并终止 Claude'
                            : pendingClaudeConfirm.type === 'change-port'
                            ? '确认修改端口'
                            : '确认终止'}
                        </button>
                        <button
                          type="button"
                          className="btn-confirm-cancel"
                          onClick={() => {
                            if (pendingClaudeConfirm.type === 'change-port') {
                              setDedicatedPortInput(String(config.dedicatedProxyPort));
                            }
                            setPendingClaudeConfirm(null);
                          }}
                        >
                          取消
                        </button>
                      </div>
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
                        onClick={handleTerminateClaude}
                        title="立即强杀全部 Claude 关联进程并回收启动锁"
                      >
                        <Square size={14} />
                        <span>终止 Claude</span>
                      </button>
                    )}
                  </div>

                  {claudeState.nodeProbe && (
                    <div className="hero-footer-meta">
                      <span className="ellipsis" title={claudeState.nodeProbe.viaChannel}>
                        独立监控通道：{claudeState.nodeProbe.viaChannel}
                      </span>
                      <span>更新于 {formatTime(claudeState.nodeProbe.checkedAt)}</span>
                    </div>
                  )}

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

                {/* 3. 启动保护与客户端设置（默认折叠，节省首屏纵向空间） */}
                <section className={`panel-card collapsible-card ${isClaudeSettingsExpanded ? 'expanded' : 'collapsed'}`}>
                  <div
                    className="panel-card-header collapsible-header"
                    role="button"
                    tabIndex={0}
                    onClick={() => setClaudeSettingsOpen((prev) => !prev)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setClaudeSettingsOpen((prev) => !prev);
                      }
                    }}
                  >
                    <div className="panel-title">
                      <Ban size={15} />
                      <span>启动保护与客户端设置</span>
                    </div>
                    <div className="collapsible-header-right">
                      <span className="mini-badge neutral">
                        {config.claudeExclusiveGuard ? '唯一入口拦截' : '拦截已关'} ·{' '}
                        {config.claudeLockExitIp ? 'IP锁定开启' : 'IP锁定已关'} · 127.0.0.1:
                        {config.dedicatedProxyPort} · {installTypeLabel}
                      </span>
                      <span className="collapse-chevron">
                        {isClaudeSettingsExpanded ? (
                          <ChevronUp size={15} />
                        ) : (
                          <ChevronDown size={15} />
                        )}
                      </span>
                    </div>
                  </div>

                  {isClaudeSettingsExpanded && (
                    <div className="collapsible-body">
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
                            void updateConfigSafe(
                              { claudeExclusiveGuard: e.target.checked },
                              'claude'
                            )
                          }
                        />
                      </div>

                      <div className="setting-row">
                        <div>
                          <strong>锁定会话出口 IP（变更即强杀）</strong>
                          <p>
                            锁定会话启动时 claude.ai 识别的真实出口 IP；运行期发生任何 IP 漂移（含同国换 IP、IPv4/IPv6 切换）立即 0 秒强杀进程树。动态轮换住宅代理可按需关闭。
                          </p>
                        </div>
                        <input
                          type="checkbox"
                          className="toggle-switch"
                          checked={config.claudeLockExitIp}
                          onChange={(e) =>
                            void updateConfigSafe(
                              { claudeLockExitIp: e.target.checked },
                              'claude'
                            )
                          }
                        />
                      </div>

                      <div className="setting-row">
                        <div>
                          <strong>Claude 保护终止提醒</strong>
                          <p>
                            出口 IP 漂移、地区或时区不一致时立即 0 秒强杀并置顶弹窗提醒；请求暂时失败期间静默复核，持续 30 秒未恢复时终止并提醒。
                          </p>
                        </div>
                        <span className="mini-badge connected" style={{ flexShrink: 0 }}>
                          始终开启
                        </span>
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
                                void updateConfigSafe({ claudeExePath: '' }, 'claude')
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
                              void window.guardAPI
                                .browseClaudeExe()
                                .then(setState)
                                .catch((err) => notifyError(err, 'claude'))
                            }
                          >
                            <FolderOpen size={13} />
                            <span>浏览...</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </section>
              </>
            )}
          </div>
        )}

        {activeTab === 'monitor' && (
          <div className="tab-pane">
            {/* 实时监控内部二级切换器：状态与时区 vs 联动进程强杀 */}
            <div className="launcher-subtabs">
              <button
                className={`launcher-subtab ${monitorSubTab === 'status' ? 'active' : ''}`}
                onClick={() => setMonitorSubTab('status')}
              >
                <Activity size={14} />
                <span>状态与时区</span>
                <span className={`tab-status-dot ${monitorTabDotClass}`} />
              </button>

              <button
                className={`launcher-subtab ${monitorSubTab === 'guard' ? 'active' : ''}`}
                onClick={() => setMonitorSubTab('guard')}
              >
                <ShieldAlert size={14} />
                <span>联动进程强杀</span>
                <span
                  className={`subtab-mode-badge ${
                    config.killProcessesEnabled && config.protectedProcessPatterns.length > 0
                      ? 'guard'
                      : 'muted'
                  }`}
                >
                  {!config.killProcessesEnabled
                    ? '已关闭'
                    : config.protectedProcessPatterns.length > 0
                    ? `守护 ${config.protectedProcessPatterns.length} 项`
                    : '未配置规则'}
                </span>
              </button>
            </div>

            {monitorSubTab === 'status' ? (
              <>
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
                      onClick={() =>
                        void window.guardAPI
                          .checkNow('手动立即刷新')
                          .then(setState)
                          .catch((err) => notifyError(err, 'global'))
                      }
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
                        className={`mini-badge ${
                          isWinLocaleMatched
                            ? 'connected'
                            : config.defaultCountryCode
                            ? 'warn-badge'
                            : 'neutral'
                        }`}
                      >
                        {isWinLocaleMatched
                          ? '已与目标地区一致'
                          : config.defaultCountryCode
                          ? '与保护地区不一致'
                          : '与当前出口不同 (可选同步)'}
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
                      <span>
                        {isAlreadyChinaDefaultLocale ? '已是中国时区' : '还原默认时区'}
                      </span>
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
                        onClick={() =>
                          void window.guardAPI
                            .setDefaultRegion(null)
                            .then(setState)
                            .catch((err) => notifyError(err, 'global'))
                        }
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
                          <span>未锁定固定地区，仅展示实时出口信息（不触发地区偏离红灯）</span>
                        </div>
                      )}
                    </div>

                    <div className="default-actions-row">
                      <button
                        className={`btn-primary-set ${
                          isCurrentAlreadyDefault ? 'btn-already' : ''
                        }`}
                        disabled={!canLockCurrentProbe || isCurrentAlreadyDefault}
                        onClick={() =>
                          void window.guardAPI
                            .setDefaultCurrent()
                            .then(setState)
                            .catch((err) => notifyError(err, 'global'))
                        }
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
                          void window.guardAPI
                            .setDefaultRegion(val)
                            .then(setState)
                            .catch((err) => notifyError(err, 'global'));
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
              </>
            ) : (
              <>
                {/* 1. 强杀触发策略卡片 */}
                <section className="panel-card">
                  <div className="panel-card-header">
                    <div className="panel-title">
                      <ShieldAlert size={15} />
                      <span>实时监控联动拦截条件</span>
                    </div>
                  </div>

                  <div className="setting-row">
                    <div>
                      <strong>启用实时监控联动进程强杀</strong>
                      <p>
                        当实时监控通道异常时按进程树强杀下方列表应用（Claude 已由启动器专栏独立保护）
                      </p>
                    </div>
                    <input
                      type="checkbox"
                      className="toggle-switch"
                      checked={config.killProcessesEnabled}
                      onChange={(e) =>
                        void updateConfigSafe(
                          { killProcessesEnabled: e.target.checked },
                          'global'
                        )
                      }
                    />
                  </div>

                  <div className="setting-row">
                    <div>
                      <strong>代理断连或超时时强杀</strong>
                      <p>实时监控代理连接断开或探测超时期间禁止运行</p>
                    </div>
                    <input
                      type="checkbox"
                      className="toggle-switch"
                      disabled={!config.killProcessesEnabled}
                      checked={config.killOnDisconnect}
                      onChange={(e) =>
                        void updateConfigSafe(
                          { killOnDisconnect: e.target.checked },
                          'global'
                        )
                      }
                    />
                  </div>

                  <div className="setting-row no-border-bottom">
                    <div>
                      <strong>系统时区/区域不一致时强杀</strong>
                      <p>系统时区或国家区域与实时监控保护地区不符时立即终止</p>
                    </div>
                    <input
                      type="checkbox"
                      className="toggle-switch"
                      disabled={!config.killProcessesEnabled}
                      checked={config.killOnLocaleMismatch}
                      onChange={(e) =>
                        void updateConfigSafe(
                          { killOnLocaleMismatch: e.target.checked },
                          'global'
                        )
                      }
                    />
                  </div>
                </section>

                {/* 2. 进程匹配规则列表卡片 */}
                <section className="panel-card">
                  <div className="panel-card-header">
                    <div className="panel-title">
                      <Lock size={15} />
                      <span>联动守护进程列表</span>
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
                      <button
                        className="btn-save-inline"
                        onClick={() => void handleAddPattern()}
                      >
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
                        支持通配符（如 <code>*cursor*</code>）或正则（<code>/pattern/</code>
                        ），大小写不敏感。
                      </p>
                    )}
                  </div>

                  {config.protectedProcessPatterns.length === 0 ? (
                    <div className="pattern-empty">
                      Claude 已由启动器专栏内置保护。如需根据实时监控通道联动保护其他应用，可在上方添加规则。
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
              </>
            )}
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="tab-pane">
            {/* 1. 实时监控专属设置（检测通道模式 + 监控异常告警） */}
            <section className="panel-card">
              <div className="panel-card-header">
                <div className="panel-title">
                  <Activity size={15} />
                  <span>实时监控设置（通道与告警）</span>
                </div>
                <span className="mini-badge neutral">仅作用于实时监控</span>
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
                    <strong>自动识别 Clash 选中通道（推荐）</strong>
                    <p>优先检测 Clash Verge 当前选中的代理通道（混合端口/当前模式），未连接时自动检测系统代理或网卡路由</p>
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

              <div className="setting-row">
                <div>
                  <strong>实时监控异常弹窗告警</strong>
                  <p>开启后，Clash 选中通道与保护地区/系统时区不一致，或触发联动进程强杀时弹出置顶提醒</p>
                </div>
                <input
                  type="checkbox"
                  className="toggle-switch"
                  checked={config.monitorAlertEnabled}
                  onChange={(e) =>
                    void updateConfigSafe(
                      { monitorAlertEnabled: e.target.checked },
                      'global'
                    )
                  }
                />
              </div>

              <div className="setting-row no-border-bottom">
                <div>
                  <strong>实时监控断连或超时报警</strong>
                  <p>实时监控代理连接失败或节点超时时也弹窗提醒（需先开启实时监控异常弹窗）</p>
                </div>
                <input
                  type="checkbox"
                  className="toggle-switch"
                  disabled={!config.monitorAlertEnabled}
                  checked={config.alertOnDisconnect}
                  onChange={(e) =>
                    void updateConfigSafe(
                      { alertOnDisconnect: e.target.checked },
                      'global'
                    )
                  }
                />
              </div>
            </section>

            {/* 2. 软件全局通用设置 */}
            <section className="panel-card">
              <div className="panel-card-header">
                <div className="panel-title">
                  <Settings size={15} />
                  <span>软件全局通用设置</span>
                </div>
              </div>

              <div className="setting-row">
                <div>
                  <strong>运行期后台巡检间隔</strong>
                  <p>后台定时静默复核出口 IP 是否漂移（同时作用于运行中的 Claude 与实时监控）</p>
                </div>
                <select
                  className="compact-select"
                  value={config.heartbeatIntervalSec}
                  onChange={(e) =>
                    void updateConfigSafe(
                      { heartbeatIntervalSec: Number(e.target.value) },
                      'global'
                    )
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
                  <strong>异常警告提示音</strong>
                  <p>任何模块触发右下角置顶警告弹窗时播放短促提示音</p>
                </div>
                <input
                  type="checkbox"
                  className="toggle-switch"
                  checked={config.alertSoundEnabled}
                  onChange={(e) =>
                    void updateConfigSafe(
                      { alertSoundEnabled: e.target.checked },
                      'global'
                    )
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
                    void updateConfigSafe(
                      { closeToTray: e.target.checked },
                      'global'
                    )
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
                    void updateConfigSafe(
                      { autoLaunch: e.target.checked },
                      'global'
                    )
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
                    onClick={() =>
                      void window.guardAPI
                        .clearLogs()
                        .then(setState)
                        .catch((err) => notifyError(err, 'global'))
                    }
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
