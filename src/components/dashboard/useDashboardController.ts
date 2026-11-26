import { useEffect, useState } from 'react';
import { AppConfig, AppStateSnapshot } from '../../shared/types';
import { COMMON_COUNTRIES, isValidIsoCountryCode } from '../../shared/countries';
import { inspectProcessPattern } from '../../shared/processPattern';
import { getTargetServiceVerificationError } from '../../shared/probeValidation';
import {
  DEFAULT_CHINA_REGION_CODE,
  DEFAULT_CHINA_TIMEZONE_ID,
  isWindowsLocaleMatchingCountry,
} from '../../shared/timezones';
import {
  ActiveTab,
  extractErrorMessage,
  FeedbackMessage,
  FeedbackScope,
  LauncherSubTab,
  MonitorSubTab,
  PendingAgConfirm,
  PendingClaudeConfirm,
  StatusDisplayMeta,
} from './dashboardTypes';

export function useDashboardController() {
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
  const [localeFeedback, setLocaleFeedback] = useState<FeedbackMessage | null>(null);

  // Claude 启动/终止操作状态与反馈
  const [isLaunchingClaude, setIsLaunchingClaude] = useState(false);
  const [isSwitchingNode, setIsSwitchingNode] = useState(false);
  const [claudeFeedback, setClaudeFeedback] = useState<FeedbackMessage | null>(null);

  // Antigravity 启动/终止操作状态与反馈
  const [isLaunchingAg, setIsLaunchingAg] = useState(false);
  const [isSwitchingAgNode, setIsSwitchingAgNode] = useState(false);
  const [agFeedback, setAgFeedback] = useState<FeedbackMessage | null>(null);

  // 低频路径与端口设置折叠态（未检测到安装路径时自动展开）
  const [agSettingsOpen, setAgSettingsOpen] = useState(false);
  const [claudeSettingsOpen, setClaudeSettingsOpen] = useState(false);

  // 运行中应用破坏性操作（重启/强杀/切换节点/改端口）二次确认态
  const [pendingAgConfirm, setPendingAgConfirm] = useState<PendingAgConfirm>(null);
  const [pendingClaudeConfirm, setPendingClaudeConfirm] =
    useState<PendingClaudeConfirm>(null);

  // 全局非启动器页操作提示/错误反馈
  const [globalNotice, setGlobalNotice] = useState<FeedbackMessage | null>(null);

  // 版本更新弹窗、二次确认（Claude 运行时）、本地重入锁与内联反馈
  const [updateModalOpen, setUpdateModalOpen] = useState(false);
  const [pendingUpdateConfirm, setPendingUpdateConfirm] = useState(false);
  const [isApplyingUpdate, setIsApplyingUpdate] = useState(false);
  const [updateFeedback, setUpdateFeedback] = useState<FeedbackMessage | null>(null);

  const syncFormFromConfig = (cfg: AppConfig) => {
    setManualProto(cfg.manualProxy.protocol);
    setManualHost(cfg.manualProxy.host);
    setManualPort(String(cfg.manualProxy.port));
    setDedicatedPortInput(String(cfg.dedicatedProxyPort));
    setAgDedicatedPortInput(String(cfg.antigravityDedicatedPort));
    setCustomProbe(cfg.customProbeUrl);
  };

  useEffect(() => {
    const initialHash = window.location.hash.replace(/^#/, '');
    if (initialHash === 'update-modal' || initialHash === 'update-confirm') {
      setUpdateModalOpen(true);
      if (initialHash === 'update-confirm') {
        setPendingUpdateConfirm(true);
      }
      window.history.replaceState(
        null,
        '',
        window.location.pathname + window.location.search
      );
    }

    void window.guardAPI
      .getState()
      .then((initial) => {
        setState(initial);
        syncFormFromConfig(initial.config);
      })
      .catch(() => {
        // ignore initial load error
      });

    const unsubState = window.guardAPI.onStateChanged((next) => {
      setState(next);
      if (next.updateState.status !== 'applying') {
        setIsApplyingUpdate(false);
      }
    });

    const unsubOpenUpdate = window.guardAPI.onOpenUpdateModal(({ confirmClaude }) => {
      setPendingUpdateConfirm(Boolean(confirmClaude));
      setUpdateModalOpen(true);
    });

    return () => {
      unsubState();
      unsubOpenUpdate();
    };
  }, []);

  useEffect(() => {
    if (!updateModalOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isApplyingUpdate && state?.updateState.status !== 'applying') {
        setUpdateModalOpen(false);
        setPendingUpdateConfirm(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [updateModalOpen, isApplyingUpdate, state?.updateState.status]);

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
    if (!state) return;
    const claudeActive = Boolean(
      state.claudeState.running || state.claudeState.authorizedSession
    );
    if (!claudeActive && pendingClaudeConfirm) {
      setPendingClaudeConfirm(null);
    }
    if (!claudeActive && pendingUpdateConfirm) {
      setPendingUpdateConfirm(false);
    }
  }, [state, pendingClaudeConfirm, pendingUpdateConfirm]);

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

  const showTimedUpdateFeedback = (ok: boolean, text: string) => {
    setUpdateFeedback({ ok, text });
    setTimeout(() => {
      setUpdateFeedback((cur) => (cur?.text === text ? null : cur));
    }, 5500);
  };

  const notifyError = (err: unknown, target: FeedbackScope = 'global') => {
    const msg = extractErrorMessage(err);
    if (target === 'ag') showTimedAgFeedback(false, msg);
    else if (target === 'claude') showTimedClaudeFeedback(false, msg);
    else if (target === 'locale') showTimedLocaleFeedback(false, msg);
    else showTimedGlobalNotice(false, msg);
  };

  const updateConfigSafe = async (
    partial: Partial<AppConfig>,
    target: FeedbackScope = 'global',
    options?: { confirmTerminateClaude?: boolean }
  ): Promise<AppStateSnapshot | null> => {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const next = await window.guardAPI.updateConfig(partial, options);
        setState(next);
        return next;
      } catch (err) {
        const msg = extractErrorMessage(err);
        if (attempt < 2 && msg.includes('正在进行')) {
          await new Promise((r) => setTimeout(r, 320));
          continue;
        }
        if (
          msg.includes('CLAUDE_RUNNING_CONFIRM_REQUIRED:') &&
          typeof partial.claudeForceIpv4 === 'boolean'
        ) {
          const fresh = await window.guardAPI.getState().catch(() => null);
          if (fresh) setState(fresh);
          setPendingClaudeConfirm({
            type: 'toggle-ipv4',
            enabled: partial.claudeForceIpv4,
          });
          return null;
        }
        notifyError(err, target);
        return null;
      }
    }
    return null;
  };

  const handleCopyIp = () => {
    if (!state?.lastProbe?.ip) return;
    void navigator.clipboard.writeText(state.lastProbe.ip);
    setCopiedIp(true);
    setTimeout(() => setCopiedIp(false), 1600);
  };

  const handleCopyAgIp = () => {
    if (!state?.antigravityState.nodeProbe?.ip) return;
    void navigator.clipboard.writeText(state.antigravityState.nodeProbe.ip);
    setCopiedAgIp(true);
    setTimeout(() => setCopiedAgIp(false), 1600);
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
    if (!state) return;
    const isSame =
      nodeName === state.config.selectedClashNode &&
      (profileUid || null) === (state.config.selectedClashProfileUid || null);
    if (isSame) return;

    if (state.claudeState.running) {
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
    if (!state) return;
    const wasRunning =
      state.antigravityState.running && state.antigravityState.proxiedSession;
    setIsSwitchingAgNode(true);
    setAgFeedback(null);
    try {
      const next = await window.guardAPI.selectAntigravityClashNode(nodeName, profileUid);
      setState(next);
      if (!nodeName) return;

      const selectedNode = nodeName.trim();
      const selectedProfileUid =
        profileUid?.trim() || next.config.antigravityClashProfileUid;
      const bindingMatched =
        next.privateChannels.antigravity.phase === 'ready' &&
        next.privateChannels.antigravity.nodeName === selectedNode &&
        next.privateChannels.antigravity.profileUid === selectedProfileUid &&
        next.privateChannels.antigravity.port === next.config.antigravityDedicatedPort;
      if (!bindingMatched || next.antigravityState.nodeProbeError) {
        showTimedAgFeedback(
          false,
          next.antigravityState.nodeProbeError ||
            `节点 [${selectedNode}] 的专属代理绑定未就绪`
        );
        return;
      }

      if (wasRunning) {
        showTimedAgFeedback(true, `专属端口已绑定至节点 [${selectedNode}]`);
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
    if (state?.claudeState.running) {
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
    if (state?.antigravityState.running) {
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
    if (state?.antigravityState.running) {
      setPendingAgConfirm('kill');
      return;
    }
    void executeTerminateAntigravity();
  };

  const executeToggleClaudeForceIpv4 = async (
    enabled: boolean,
    confirmTerminateClaude = false
  ) => {
    setPendingClaudeConfirm(null);
    setIsSwitchingNode(true);
    try {
      const next = await updateConfigSafe(
        { claudeForceIpv4: enabled },
        'claude',
        { confirmTerminateClaude }
      );
      if (next) {
        showTimedClaudeFeedback(
          true,
          enabled
            ? '已开启 Claude 通道强制仅走 IPv4 出站'
            : '已关闭强制仅走 IPv4 出站（允许双栈/IPv6 节点）'
        );
      }
    } finally {
      setIsSwitchingNode(false);
    }
  };

  const handleToggleClaudeForceIpv4 = (enabled: boolean) => {
    if (!state || enabled === state.config.claudeForceIpv4) return;
    if (state.claudeState.running && state.config.selectedClashNode) {
      setPendingClaudeConfirm({ type: 'toggle-ipv4', enabled });
      return;
    }
    void executeToggleClaudeForceIpv4(enabled, false);
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
    if (!state) return;
    let portNum = Math.max(
      1024,
      Math.min(65535, Math.round(Number(dedicatedPortInput) || 27897))
    );
    if (portNum === state.config.antigravityDedicatedPort) {
      portNum = portNum === 27897 ? 27896 : 27897;
      showTimedClaudeFeedback(
        false,
        `端口不能与 Antigravity 专属端口 (${state.config.antigravityDedicatedPort}) 相同，已自动调整为 ${portNum}`
      );
    }
    setDedicatedPortInput(String(portNum));
    if (portNum === state.config.dedicatedProxyPort) return;
    if (state.claudeState.running) {
      setPendingClaudeConfirm({ type: 'change-port', port: portNum });
      return;
    }
    await executeSaveDedicatedPort(portNum);
  };

  const handleSaveAgDedicatedPort = async () => {
    if (!state) return;
    let portNum = Math.max(
      1024,
      Math.min(65535, Math.round(Number(agDedicatedPortInput) || 27898))
    );
    if (portNum === state.config.dedicatedProxyPort) {
      portNum = portNum === 27898 ? 27899 : 27898;
      showTimedAgFeedback(
        false,
        `端口不能与 Claude 专属端口 (${state.config.dedicatedProxyPort}) 相同，已自动调整为 ${portNum}`
      );
    }
    setAgDedicatedPortInput(String(portNum));
    if (portNum === state.config.antigravityDedicatedPort) return;
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
            state.antigravityState.running
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
    if (!state) return;
    setPendingManualMode(false);
    if (state.config.proxyMode === mode) return;
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
      showTimedGlobalNotice(
        true,
        trimmed ? '已更新自定义探测源并重新检测' : '已恢复默认全球探测源'
      );
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
    if (!state) return;
    const check = inspectProcessPattern(patternInput);
    if (!check.valid) {
      setPatternSubmitErr(check.error || '规则格式不正确');
      return;
    }

    const exists = state.config.protectedProcessPatterns.some(
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
        protectedProcessPatterns: [
          ...state.config.protectedProcessPatterns,
          check.normalized,
        ],
      },
      'global'
    );
  };

  const handleRemovePattern = async (target: string) => {
    if (!state) return;
    const filtered = state.config.protectedProcessPatterns.filter((p) => p !== target);
    await updateConfigSafe({ protectedProcessPatterns: filtered }, 'global');
  };

  const closeUpdateModal = () => {
    if (isApplyingUpdate || state?.updateState.status === 'applying') {
      return;
    }
    setUpdateModalOpen(false);
    setPendingUpdateConfirm(false);
  };

  const handleOpenReleasePage = () => {
    void window.guardAPI.openReleasePage().catch((err) => {
      showTimedUpdateFeedback(false, extractErrorMessage(err));
    });
  };

  const handleSwitchMainTab = (nextTab: ActiveTab) => {
    if (nextTab !== activeTab) {
      setPendingUpdateConfirm(false);
    }
    setActiveTab(nextTab);
  };

  const handleCheckForUpdates = async () => {
    setUpdateFeedback(null);
    try {
      const res = await window.guardAPI.checkForUpdates();
      setState(res.state);
      showTimedUpdateFeedback(res.ok, res.message);
    } catch (err) {
      showTimedUpdateFeedback(false, extractErrorMessage(err));
    }
  };

  const handleDownloadUpdate = async () => {
    setUpdateFeedback(null);
    try {
      const res = await window.guardAPI.downloadUpdate();
      setState(res.state);
      showTimedUpdateFeedback(res.ok, res.message);
    } catch (err) {
      showTimedUpdateFeedback(false, extractErrorMessage(err));
    }
  };

  const executeApplyUpdate = async (allowTerminateClaude: boolean) => {
    if (isApplyingUpdate || state?.updateState.status === 'applying') {
      return;
    }
    setIsApplyingUpdate(true);
    setPendingUpdateConfirm(false);
    setUpdateFeedback(null);
    try {
      const res = await window.guardAPI.applyUpdateNow(allowTerminateClaude);
      setState(res.state);
      if (!res.ok) {
        setIsApplyingUpdate(false);
      }
      showTimedUpdateFeedback(res.ok, res.message);
    } catch (err) {
      setIsApplyingUpdate(false);
      showTimedUpdateFeedback(false, extractErrorMessage(err));
    }
  };

  const isClaudeActiveForUpdate = Boolean(
    state?.claudeState.running || state?.claudeState.authorizedSession
  );

  const handleClickApplyUpdate = () => {
    if (isApplyingUpdate || state?.updateState.status === 'applying') {
      return;
    }
    if (isClaudeActiveForUpdate) {
      setPendingUpdateConfirm(true);
      return;
    }
    void executeApplyUpdate(false);
  };

  if (!state) {
    return {
      ready: false as const,
      state: null,
    };
  }

  const {
    status,
    config,
    winLocale,
    lastProbe,
    clashInfo,
    claudeState,
    antigravityState,
    updateState,
  } = state;

  const claudeVerificationError = getTargetServiceVerificationError(claudeState.nodeProbe);
  const claudeFallbackDetectedCode = claudeState.nodeProbe
    ? isValidIsoCountryCode(claudeState.nodeProbe.claudeTraceCountryCode)
      ? claudeState.nodeProbe.claudeTraceCountryCode.toUpperCase()
      : isValidIsoCountryCode(claudeState.nodeProbe.claudeTraceLoc)
      ? claudeState.nodeProbe.claudeTraceLoc.toUpperCase()
      : null
    : null;

  const displayedProxyMode = pendingManualMode ? 'manual' : config.proxyMode;

  const isUpdateBusy =
    isApplyingUpdate ||
    updateState.status === 'checking' ||
    updateState.status === 'downloading' ||
    updateState.status === 'applying';

  const hasNewUpdate = updateState.hasUpdate && Boolean(updateState.latestVersion);

  const canLockCurrentProbe = Boolean(
    lastProbe && isValidIsoCountryCode(lastProbe.countryCode)
  );

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

  const statusMeta: StatusDisplayMeta = {
    ok: {
      badge: isWinLocaleMatched
        ? '状态正常 · 代理与时区一致'
        : '代理通道正常 · 未锁定保护地区',
      cls: 'status-ok',
      iconKind: 'ok' as const,
    },
    mismatch: isLocaleOnlyMismatch
      ? {
          badge: '提醒 · 代理地区正常，系统时区尚未同步',
          cls: 'status-locale-warn',
          iconKind: 'locale-warn' as const,
        }
      : {
          badge: '警告 · 代理出口偏离默认保护地区！',
          cls: 'status-mismatch',
          iconKind: 'mismatch' as const,
        },
    error: {
      badge: '异常 · 代理连接失败',
      cls: 'status-error',
      iconKind: 'error' as const,
    },
    unset: {
      badge: '待选择节点或保护地区',
      cls: 'status-unset',
      iconKind: 'unset' as const,
    },
    checking: {
      badge: '正在检测出口地区...',
      cls: 'status-checking',
      iconKind: 'checking' as const,
    },
  }[status];

  const isAlreadyChinaDefaultLocale =
    winLocale.regionCode.toUpperCase() === DEFAULT_CHINA_REGION_CODE &&
    winLocale.timeZoneId.toLowerCase() === DEFAULT_CHINA_TIMEZONE_ID.toLowerCase();

  const livePatternCheck = patternInput.trim() ? inspectProcessPattern(patternInput) : null;

  const installTypeLabel = {
    'msix-alias': 'MSIX 别名',
    'msix-direct': 'MSIX 直连',
    squirrel: '独立版',
    custom: '自定义路径',
    'not-found': '未找到路径',
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

  const clashHeaderBadgeText = `${clashInfo.profileGroups.length} 个本地订阅 · ${clashInfo.availableNodes.length} 个节点`;

  const closeButtonTitle = config.closeToTray
    ? '隐藏到系统托盘'
    : '关闭管理界面（后台、私有代理和安全检查继续运行）';

  return {
    ready: true as const,
    state,
    setState,
    activeTab,
    launcherSubTab,
    setLauncherSubTab,
    monitorSubTab,
    setMonitorSubTab,
    copiedIp,
    copiedAgIp,
    pendingManualMode,
    setPendingManualMode,
    manualProto,
    setManualProto,
    manualHost,
    setManualHost,
    manualPort,
    setManualPort,
    dedicatedPortInput,
    setDedicatedPortInput,
    agDedicatedPortInput,
    setAgDedicatedPortInput,
    customProbe,
    setCustomProbe,
    probeUrlErr,
    setProbeUrlErr,
    patternInput,
    setPatternInput,
    patternSubmitErr,
    setPatternSubmitErr,
    localeFeedback,
    isLaunchingClaude,
    isSwitchingNode,
    claudeFeedback,
    isLaunchingAg,
    isSwitchingAgNode,
    agFeedback,
    setAgSettingsOpen,
    setClaudeSettingsOpen,
    pendingAgConfirm,
    setPendingAgConfirm,
    pendingClaudeConfirm,
    setPendingClaudeConfirm,
    globalNotice,
    updateModalOpen,
    setUpdateModalOpen,
    pendingUpdateConfirm,
    setPendingUpdateConfirm,
    isApplyingUpdate,
    updateFeedback,
    claudeVerificationError,
    claudeFallbackDetectedCode,
    displayedProxyMode,
    isClaudeActiveForUpdate,
    isUpdateBusy,
    hasNewUpdate,
    canLockCurrentProbe,
    isCurrentAlreadyDefault,
    isCustomCountryOutsideCommon,
    effectiveTargetCode,
    effectiveTargetName,
    isWinLocaleMatched,
    statusMeta,
    isAlreadyChinaDefaultLocale,
    livePatternCheck,
    installTypeLabel,
    agInstallTypeLabel,
    isAgSettingsExpanded,
    isClaudeSettingsExpanded,
    launcherTabDotClass,
    monitorTabDotClass,
    titlebarDotClass,
    clashHeaderBadgeText,
    closeButtonTitle,
    notifyError,
    updateConfigSafe,
    handleCopyIp,
    handleCopyAgIp,
    executeSelectClaudeNode,
    handleSelectClaudeNode,
    handleSelectAntigravityNode,
    handleLaunchClaude,
    executeTerminateClaude,
    handleTerminateClaude,
    handleSyncLocaleFromClaude,
    executeLaunchAntigravity,
    handleLaunchAntigravity,
    executeTerminateAntigravity,
    handleTerminateAntigravity,
    executeToggleClaudeForceIpv4,
    handleToggleClaudeForceIpv4,
    executeSaveDedicatedPort,
    handleSaveDedicatedPort,
    handleSaveAgDedicatedPort,
    handleSwitchNonManualMode,
    handleSaveManualProxy,
    handleSaveCustomProbe,
    handleSyncLocale,
    handleRestoreLocale,
    handleAddPattern,
    handleRemovePattern,
    closeUpdateModal,
    handleOpenReleasePage,
    handleSwitchMainTab,
    handleCheckForUpdates,
    handleDownloadUpdate,
    executeApplyUpdate,
    handleClickApplyUpdate,
  };
}
