import React, { useEffect, useState } from 'react';
import {
  Activity,
  BellRing,
  Check,
  Copy,
  History,
  Lock,
  Minus,
  Radio,
  RefreshCw,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  Unlock,
  WifiOff,
  X,
} from 'lucide-react';
import { AppConfig, AppStateSnapshot } from '../shared/types';
import { COMMON_COUNTRIES } from '../shared/countries';
import { CountryFlag } from './CountryFlag';

type ActiveTab = 'monitor' | 'settings' | 'logs';

export const MainDashboard: React.FC = () => {
  const [state, setState] = useState<AppStateSnapshot | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>('monitor');
  const [copiedIp, setCopiedIp] = useState(false);

  // 手动代理表单本地编辑态
  const [manualProto, setManualProto] = useState<'http' | 'socks5'>('http');
  const [manualHost, setManualHost] = useState('127.0.0.1');
  const [manualPort, setManualPort] = useState('7890');
  const [customProbe, setCustomProbe] = useState('');

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

  const { status, isChecking, config, lastProbe, lastError, clashInfo, logs } = state;

  const handleCopyIp = () => {
    if (!lastProbe?.ip) return;
    void navigator.clipboard.writeText(lastProbe.ip);
    setCopiedIp(true);
    setTimeout(() => setCopiedIp(false), 1600);
  };

  const handleSaveManualProxy = async () => {
    const portNum = Math.max(1, Math.min(65535, Number(manualPort) || 7890));
    setManualPort(String(portNum));
    const next = await window.guardAPI.updateConfig({
      proxyMode: 'manual',
      manualProxy: {
        protocol: manualProto,
        host: manualHost.trim() || '127.0.0.1',
        port: portNum,
      },
    });
    setState(next);
  };

  const handleSaveCustomProbe = async () => {
    const next = await window.guardAPI.updateConfig({
      customProbeUrl: customProbe.trim(),
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

  const isCurrentAlreadyDefault =
    Boolean(lastProbe?.countryCode) &&
    Boolean(config.defaultCountryCode) &&
    lastProbe?.countryCode === config.defaultCountryCode;

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
          <Activity size={15} />
          <span>实时监控</span>
        </button>
        <button
          className={`nav-tab ${activeTab === 'settings' ? 'active' : ''}`}
          onClick={() => setActiveTab('settings')}
        >
          <Settings size={15} />
          <span>代理与提醒设置</span>
        </button>
        <button
          className={`nav-tab ${activeTab === 'logs' ? 'active' : ''}`}
          onClick={() => setActiveTab('logs')}
        >
          <History size={15} />
          <span>变更日志</span>
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
                          lastProbe.countryCode !== 'UNKNOWN' &&
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
                    title="取消默认地区锁定"
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
                        <small>当检测到出口偏离该国家/地区时立即变红并置顶弹窗</small>
                      </div>
                    </>
                  ) : (
                    <div className="default-unset-hint">
                      <span>尚未锁定默认地区。选好 VPN 代理后，点击右侧按钮一键锁定。</span>
                    </div>
                  )}
                </div>

                <div className="default-actions-row">
                  <button
                    className={`btn-primary-set ${isCurrentAlreadyDefault ? 'btn-already' : ''}`}
                    disabled={!lastProbe || lastProbe.countryCode === 'UNKNOWN' || isCurrentAlreadyDefault}
                    onClick={() => void window.guardAPI.setDefaultCurrent()}
                  >
                    <Sparkles size={15} />
                    <span>
                      {isCurrentAlreadyDefault
                        ? `当前 [${lastProbe?.countryName}] 已是默认`
                        : lastProbe
                        ? `将当前 [${lastProbe.countryName}] 设为默认`
                        : '等待检测当前地区...'}
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
                    {COMMON_COUNTRIES.map((c) => (
                      <option key={c.code} value={c.code}>
                        {c.name} ({c.code})
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </section>

            {/* 3. Clash 实时引擎与离线库状态卡片 */}
            <section className="panel-card compact-card">
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
                    <span className="kv-k">混合端口</span>
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
                  className="btn-preview-alert"
                  onClick={() => void window.guardAPI.testAlertPopup()}
                >
                  <BellRing size={13} />
                  <span>预览警告弹窗</span>
                </button>
              </div>
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
                <label className={`radio-card ${config.proxyMode === 'auto' ? 'selected' : ''}`}>
                  <input
                    type="radio"
                    name="proxyMode"
                    checked={config.proxyMode === 'auto'}
                    onChange={() => void window.guardAPI.updateConfig({ proxyMode: 'auto' })}
                  />
                  <div>
                    <strong>自动识别（推荐）</strong>
                    <p>优先读取 Windows 系统代理；若未开系统代理则自动识别 Clash 本地混合端口或 TUN 网卡</p>
                  </div>
                </label>

                <label className={`radio-card ${config.proxyMode === 'manual' ? 'selected' : ''}`}>
                  <input
                    type="radio"
                    name="proxyMode"
                    checked={config.proxyMode === 'manual'}
                    onChange={() => void window.guardAPI.updateConfig({ proxyMode: 'manual' })}
                  />
                  <div>
                    <strong>手动指定本地代理端口</strong>
                    <p>固定通过指定的 HTTP / SOCKS5 本地端口检测（适合仅开本地端口分流模式）</p>
                  </div>
                </label>

                {config.proxyMode === 'manual' && (
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
                      placeholder="127.0.0.1"
                    />
                    <input
                      type="number"
                      className="port-input"
                      value={manualPort}
                      onChange={(e) => setManualPort(e.target.value)}
                      placeholder="7890"
                    />
                    <button className="btn-save-inline" onClick={() => void handleSaveManualProxy()}>
                      保存重测
                    </button>
                  </div>
                )}

                <label className={`radio-card ${config.proxyMode === 'direct' ? 'selected' : ''}`}>
                  <input
                    type="radio"
                    name="proxyMode"
                    checked={config.proxyMode === 'direct'}
                    onChange={() => void window.guardAPI.updateConfig({ proxyMode: 'direct' })}
                  />
                  <div>
                    <strong>纯网卡直连（仅限全局 TUN 虚拟网卡）</strong>
                    <p>不经过本地代理端口，直接检测系统默认网卡路由出口</p>
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
                  <p>地区变更时在屏幕右下角弹出强置顶卡片（不受系统勿扰模式屏蔽）</p>
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
                  <p>弹出地区变更或断连警告时播放短促提示音</p>
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
                <label>自定义回显探测 URL（留空默认使用 Cloudflare / AWS 全球基础设施互备）：</label>
                <div className="custom-probe-row">
                  <input
                    type="text"
                    value={customProbe}
                    onChange={(e) => setCustomProbe(e.target.value)}
                    placeholder="例如 https://cp.cloudflare.com/cdn-cgi/trace"
                  />
                  <button className="btn-save-inline" onClick={() => void handleSaveCustomProbe()}>
                    应用
                  </button>
                </div>
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
