export type ActiveTab = 'launcher' | 'monitor' | 'settings' | 'logs';
export type LauncherSubTab = 'antigravity' | 'claude';
export type MonitorSubTab = 'status' | 'guard';

export type FeedbackScope = 'ag' | 'claude' | 'locale' | 'global';

export interface FeedbackMessage {
  ok: boolean;
  text: string;
}

export type PendingAgConfirm = 'restart' | 'kill' | null;

export type PendingClaudeConfirm =
  | { type: 'kill' }
  | { type: 'switch-node'; nodeName: string | null; profileUid: string | null }
  | { type: 'change-port'; port: number }
  | { type: 'toggle-ipv4'; enabled: boolean }
  | null;

export type StatusIconKind =
  | 'ok'
  | 'locale-warn'
  | 'mismatch'
  | 'error'
  | 'unset'
  | 'checking';

export interface StatusDisplayMeta {
  badge: string;
  cls: string;
  iconKind: StatusIconKind;
}

export function extractErrorMessage(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err || '操作失败');
  return raw.replace(/^Error invoking remote method '[^']+':\s*(Error:\s*)?/i, '').trim();
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes) || bytes <= 0) {
    return '未知大小';
  }
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatReleaseDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime()) || d.getUTCFullYear() <= 1970) {
    return '';
  }
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

export function formatTime(ts: number): string {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}
