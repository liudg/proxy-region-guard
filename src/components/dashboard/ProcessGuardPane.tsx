import React from 'react';
import { AlertTriangle, Check, Lock, Plus, ShieldAlert, Trash2 } from 'lucide-react';
import { AppConfig } from '../../shared/types';
import { inspectProcessPattern } from '../../shared/processPattern';

export interface ProcessGuardPaneProps {
  config: AppConfig;
  patternInput: string;
  patternSubmitErr: string | null;
  livePatternCheck: ReturnType<typeof inspectProcessPattern> | null;
  onUpdateConfig: (partial: Partial<AppConfig>) => void;
  onChangePatternInput: (val: string) => void;
  onAddPattern: () => void;
  onRemovePattern: (pat: string) => void;
}

export const ProcessGuardPane: React.FC<ProcessGuardPaneProps> = ({
  config,
  patternInput,
  patternSubmitErr,
  livePatternCheck,
  onUpdateConfig,
  onChangePatternInput,
  onAddPattern,
  onRemovePattern,
}) => {
  return (
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
              onUpdateConfig({ killProcessesEnabled: e.target.checked })
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
              onUpdateConfig({ killOnDisconnect: e.target.checked })
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
              onUpdateConfig({ killOnLocaleMismatch: e.target.checked })
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
              onChange={(e) => onChangePatternInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  onAddPattern();
                }
              }}
              placeholder="输入进程名、通配符或正则，如 *cursor*"
            />
            <button className="btn-save-inline" onClick={onAddPattern}>
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
                    onClick={() => onRemovePattern(pat)}
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
  );
};
