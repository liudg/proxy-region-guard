import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BellRing,
  Check,
  Clock,
  Copy,
  Globe,
  History,
  Lock,
  Minus,
  Plus,
  Radio,
  RefreshCw,
  RotateCcw,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Sparkles,
  Trash2,
  Unlock,
  WifiOff,
  X,
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

type ActiveTab = 'monitor' | 'guard' | 'settings' | 'logs';

export const MainDashboard: React.FC = () => {
  const [state, setState] = useState<AppStateSnapshot | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>('monitor');
  const [copiedIp, setCopiedIp] = useState(false);

  // 手动代理表单本地编辑态（点击单选框时先展开表单，点“启用并重测”才真正提交，避免用旧端口误触发断连强杀）
  const [pendingManualMode, setPendingManualMode] = useState(false);
  const [manualProto, setManualProto] = useState<'http' | 'socks5'>('http');
  const [manualHost, setManualHost] = useState('127.0.0.1');
  const [manualPort, setManualPort] = useState('7890');

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
    logs,
  } = state;

  const displayedProxyMode = pendingManualMode ? 'manual' : config.proxyMode;

  const handleCopyIp = () => {
    if (!lastProbe?.ip) return;
    void navigator.clipboard.writeText(lastProbe.ip);
    setCopiedIp(true);
    setTimeout(() => setCopiedIp(false), 1600);
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
      badge: '状态正常 · 地区一致',
      cls: 'status-ok',
      icon: <ShieldCheck size={18} />,
    },
    mismatch: {
      badge: '警告 · 出口地区不符！',
      cls: 'status-mismatch',
      icon: <ShieldAlert size={18} />,
    },
    error: {
      badge: '异常 · 代理连接失败',
      cls: 'status-error',
      icon: <WifiOff size={18} />,
    },
    unset: {
      badge: '待设默认保护地区',
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

  // 判断当前 Windows 时区与区域是否与已锁定的默认保护地区一致
  const isWinLocaleMatched = config.defaultCountryCode
    ? isWindowsLocaleMatchingCountry(
        winLocale.timeZoneId,
        winLocale.regionCode,
        config.defaultCountryCode
      )
    : true;

  const isAlreadyChinaDefaultLocale =
    winLocale.regionCode.toUpperCase() === DEFAULT_CHINA_REGION_CODE &&
    winLocale.timeZoneId.toLowerCase() === DEFAULT_CHINA_TIMEZONE_ID.toLowerCase();

  const livePatternCheck = patternInput.trim() ? inspectProcessPattern(patternInput) : null;

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

      {/* 顶部导航栏 */}
      <nav className="nav-tabs">
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
          <span>代理设置</span>
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
                    <span>检测通道：{lastProbe.viaChannel}</span>
                    <span>更新于 {formatTime(lastProbe.checkedAt)}</span>
                  </div>
                </div>
              ) : (
                <div className="hero-empty-state">
                  {lastError ? (
                    <div className="error-empty-box">
                      <WifiOff size={28} />
                      <p>{lastError}</p>
                      <small>请确认 VPN / Clash 已连接，或在设置中调整本地代理端口</small>
                    </div>
                  ) : (
                    <p>正在通过代理隧道验证真实出口 IP...</p>
                  )}
                </div>
              )}
            </section>

            {/* 2. 默认保护地区卡片 */}
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
                    title="取消默认地区锁定并暂停进程强杀守护"
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
                        <small>偏离该国家/地区时立即变红弹窗并按策略终止守护进程</small>
                      </div>
                    </>
                  ) : (
                    <div className="default-unset-hint">
                      <span>尚未锁定默认地区。选好 VPN 代理后，点击下方按钮一键锁定。</span>
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

            {/* 3. Windows 时区与区域同步卡片 */}
            <section className="panel-card">
              <div className="panel-card-header">
                <div className="panel-title">
                  <Globe size={15} />
                  <span>Windows 时区与区域</span>
                </div>
                {config.defaultCountryCode && (
                  <span
                    className={`mini-badge ${isWinLocaleMatched ? 'connected' : 'warn-badge'}`}
                  >
                    {isWinLocaleMatched ? '已与保护地区一致' : '与默认保护地区不一致'}
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
                  disabled={!config.defaultCountryCode || isSyncingLocale}
                  onClick={() => void handleSyncLocale()}
                  title={
                    config.defaultCountryCode
                      ? '将 Windows 时区与区域同步至默认保护地区（多时区大国自动匹配城市时区）'
                      : '请先在上方设置默认保护地区'
                  }
                >
                  <RefreshCw className={isSyncingLocale ? 'spin' : ''} size={14} />
                  <span>
                    {isSyncingLocale
                      ? '正在设置系统时区...'
                      : config.defaultCountryCode
                      ? `一键同步至 [${config.defaultCountryName}]`
                      : '请先设置默认保护地区'}
                  </span>
                </button>

                <button
                  className="btn-restore-locale"
                  disabled={isSyncingLocale || isAlreadyChinaDefaultLocale}
                  onClick={() => void handleRestoreLocale()}
                  title={
                    isAlreadyChinaDefaultLocale
                      ? '当前系统已处于默认中国时区与区域'
                      : '若当前出口非中国且开启了进程守护，将先确认强杀守护进程再还原回中国时区与区域'
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

            {/* 4. Clash 实时引擎与离线库状态卡片 */}
            <section className="panel-card">
              <div className="panel-card-header">
                <div className="panel-title">
                  <Radio size={15} className={clashInfo.connected ? 'pulse-green' : ''} />
                  <span>本地实时监听引擎</span>
                </div>
                <span className={`mini-badge ${clashInfo.connected ? 'connected' : 'neutral'}`}>
                  {clashInfo.connected ? `已接入 ${clashInfo.source}` : '系统代理 / 网卡监听模式'}
                </span>
              </div>

              {clashInfo.connected ? (
                <div className="clash-live-grid">
                  <div className="kv-cell">
                    <span className="kv-k">代理模式</span>
                    <span className="kv-v mode-badge">{clashInfo.mode.toUpperCase()}</span>
                  </div>
                  <div className="kv-cell">
                    <span className="kv-k">本地端口</span>
                    <span className="kv-v">{clashInfo.mixedPort || '-'}</span>
                  </div>
                  <div className="kv-cell full-span">
                    <span className="kv-k">生效节点链</span>
                    <span className="kv-v ellipsis" title={clashInfo.nodeChain.join(' → ')}>
                      {clashInfo.nodeChain.length > 0
                        ? clashInfo.nodeChain.join(' → ')
                        : clashInfo.activeNode || '自动'}
                    </span>
                  </div>
                </div>
              ) : (
                <p className="subtle-desc">
                  未检测到运行中的 Clash 控制接口，当前通过监听 Windows 系统代理注册表、网卡状态及轻量 Trace 心跳实时守护。
                </p>
              )}

              <div className="engine-bottom-bar">
                <span className="db-tag">离线库：{state.geoDbSource}</span>
                <button
                  className={`guard-quick-pill ${
                    config.killProcessesEnabled && config.protectedProcessPatterns.length > 0
                      ? 'active'
                      : ''
                  }`}
                  onClick={() => setActiveTab('guard')}
                >
                  {config.killProcessesEnabled && config.protectedProcessPatterns.length > 0 ? (
                    <>
                      <ShieldCheck size={13} />
                      <span>进程守护：{config.protectedProcessPatterns.length} 条规则生效</span>
                    </>
                  ) : (
                    <>
                      <ShieldOff size={13} />
                      <span>配置进程守护</span>
                    </>
                  )}
                </button>
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
                  <span>异常自动终止进程策略</span>
                </div>
              </div>

              <div className="setting-row">
                <div>
                  <strong>启用异常自动强杀进程（总开关）</strong>
                  <p>
                    已锁定默认地区后，触发异常时按进程树 (<code>taskkill /F /T</code>) 连带派生子进程一并强杀，异常未恢复期间禁止重开
                  </p>
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
                  <strong>代理断连 / 超时同样强杀</strong>
                  <p>当已设置默认保护地区但代理连接失败或节点超时时，立即终止守护进程</p>
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
                  <strong>系统时区 / 区域不一致时同样强杀</strong>
                  <p>
                    还原默认时区若与保护地区不符将「先杀进程确认退出后再还原」；平时若忘改时区误启动受保护应用也会立即拦截
                  </p>
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
                  <span>受保护应用进程规则列表</span>
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
                    placeholder="输入进程名、通配符或正则，如 claude*.exe"
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
                        模式（大小写不敏感，回车即可添加）
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
                    支持通配符（如 <code>claude*.exe</code>、<code>*cursor*</code>）与正则表达式（如{' '}
                    <code>/^(claude|cursor).*\.exe$/</code>），均不区分大小写。
                  </p>
                )}
              </div>

              {config.protectedProcessPatterns.length === 0 ? (
                <div className="pattern-empty">
                  暂无守护进程规则。添加如 <code>claude*.exe</code> 后，一旦 IP 地区跳变或系统时区不符将瞬间强杀该应用全部关联进程。
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
                  <span>代理流量检测通道</span>
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
                    <p>
                      系统代理开启时经系统代理检测；系统代理关闭时走本机默认网卡路由（自动识别 TUN 虚拟网卡或国内直连暴露）
                    </p>
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
                    <p>固定通过指定的 HTTP / SOCKS5 本地端口检测（适合不开系统代理与 TUN 的纯端口分流软件）</p>
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
                    <strong>强制纯网卡直连（仅限全局 TUN 虚拟网卡）</strong>
                    <p>忽略系统代理设置，始终直接检测操作系统默认网卡路由出口</p>
                  </div>
                </label>
              </div>
            </section>

            {/* 监测频率与提醒开关 */}
            <section className="panel-card">
              <div className="panel-card-header">
                <div className="panel-title">
                  <BellRing size={15} />
                  <span>心跳巡检与强提醒设置</span>
                </div>
              </div>

              <div className="setting-row">
                <div>
                  <strong>无感 Trace 心跳间隔</strong>
                  <p>用于捕获“动态住宅代理不换节点但后台静默换出口 IP”（地区解析纯离线零限流）</p>
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
                  <strong>软件自绘置顶警告弹窗</strong>
                  <p>地区变更或进程拦截时在屏幕右下角弹出强置顶卡片（不受系统勿扰模式屏蔽）</p>
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
                  <p>弹出地区变更、断连或进程拦截警告时播放短促提示音</p>
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
                  <strong>代理断连 / 超时同样报警</strong>
                  <p>当已设置默认地区但代理连接失败或节点超时时，变红并弹窗提醒</p>
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
                  <strong>关闭窗口时最小化到系统托盘</strong>
                  <p>点击右上角关闭按钮后继续在后台托盘守护监控</p>
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
                  <p>登录 Windows 系统时自动启动（若开启最小化到托盘则静默驻留后台）</p>
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
                  自定义回显探测 URL（留空默认使用 Cloudflare / AWS 全球基础设施互备）：
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
