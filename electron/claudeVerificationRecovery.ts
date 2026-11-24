import { ClaudeVerificationFailure } from '../src/shared/types';

export const CLAUDE_VERIFICATION_RETRY_MS = 5000;

function normalizeSingleErrorDetail(raw: string): string {
  return raw
    .trim()
    .replace(/https?:\/\/(?:[^\s：:)\[]+|\[[^\]]+\]|:\d+)+(?:：|:\s*)/gi, '<probe-url>:')
    .replace(/\s+/g, ' ');
}

export function normalizeVerificationFailureSignature(reason: string): string {
  const trimmed = reason.trim();
  const exitUnreachable = /^(?:Claude\s+)?专属节点出口不可达\s*\((.*)\)$/s.exec(trimmed);
  if (exitUnreachable) {
    const inner = exitUnreachable[1]
      .trim()
      .replace(/^Claude 专属节点 \[[^\]]+\] \([^)]+\)：/, '');
    const details = new Set(
      inner
        .split('；')
        .map((part) => {
          const normalized = normalizeSingleErrorDetail(part);
          const sepIdx = normalized.indexOf('：');
          return sepIdx > 0 ? normalized.slice(sepIdx + 1).trim() : normalized;
        })
        .filter(Boolean)
    );
    return `Claude 专属节点出口不可达:${[...details].sort().join('；')}`;
  }
  return normalizeSingleErrorDetail(trimmed);
}

export interface VerificationFailureRecordResult {
  shouldLog: boolean;
  stateChanged: boolean;
}

export class ClaudeVerificationRecovery {
  private failure: ClaudeVerificationFailure | null = null;
  private loggedSignatures = new Set<string>();
  private retryTimer: NodeJS.Timeout | null = null;
  private retryInProgress = false;
  private epoch = 0;
  private activeAbort: AbortController | null = null;

  constructor(
    private readonly retry: (signal: AbortSignal) => Promise<void>,
    private readonly retryMs = CLAUDE_VERIFICATION_RETRY_MS,
    private readonly onRetryError?: (error: unknown) => void
  ) {}

  private abortActiveAttempt(reason: string): void {
    if (this.activeAbort && !this.activeAbort.signal.aborted) {
      this.activeAbort.abort(Object.assign(new Error(reason), { name: 'AbortError' }));
    }
    this.activeAbort = null;
  }

  get snapshot(): ClaudeVerificationFailure | null {
    return this.failure ? { ...this.failure } : null;
  }

  recordFailure(reason: string): VerificationFailureRecordResult {
    const nextSignature = normalizeVerificationFailureSignature(reason);
    if (this.failure) {
      const reasonChanged = this.failure.reason !== reason;
      const sigIsNew = !this.loggedSignatures.has(nextSignature);
      this.failure.reason = reason;
      this.loggedSignatures.add(nextSignature);
      return {
        shouldLog: sigIsNew,
        stateChanged: reasonChanged,
      };
    }

    const attemptEpoch = ++this.epoch;
    this.retryInProgress = false;
    this.abortActiveAttempt('启动新一轮后台复核');
    const startedAt = Date.now();
    const failure = { startedAt, reason };
    this.failure = failure;
    this.loggedSignatures.clear();
    this.loggedSignatures.add(nextSignature);
    this.retryTimer = setInterval(() => {
      if (this.epoch !== attemptEpoch || this.failure !== failure || this.retryInProgress) return;
      this.retryInProgress = true;
      const ctrl = new AbortController();
      this.activeAbort = ctrl;
      const releaseIfCurrent = () => {
        if (this.activeAbort === ctrl) {
          this.activeAbort = null;
        }
        if (this.epoch === attemptEpoch) {
          this.retryInProgress = false;
        }
      };
      const attempt = this.retry(ctrl.signal);
      if (this.onRetryError) {
        attempt.then(
          () => {
            releaseIfCurrent();
          },
          (error: unknown) => {
            const stillCurrent =
              this.epoch === attemptEpoch && this.failure === failure && !ctrl.signal.aborted;
            releaseIfCurrent();
            if (stillCurrent) {
              this.onRetryError!(error);
            }
          }
        );
        return;
      }
      void attempt
        .catch((error: unknown) => {
          if (ctrl.signal.aborted && error instanceof Error && error.name === 'AbortError') {
            return;
          }
          if (this.retryTimer && this.epoch === attemptEpoch) {
            clearInterval(this.retryTimer);
            this.retryTimer = null;
          }
          throw error;
        })
        .finally(() => {
          releaseIfCurrent();
        });
    }, this.retryMs);
    return {
      shouldLog: true,
      stateChanged: true,
    };
  }

  clear(): ClaudeVerificationFailure | null {
    const previous = this.failure ? { ...this.failure } : null;
    this.epoch++;
    this.retryInProgress = false;
    this.abortActiveAttempt('清除后台复核状态');
    this.failure = null;
    this.loggedSignatures.clear();
    if (this.retryTimer) clearInterval(this.retryTimer);
    this.retryTimer = null;
    return previous;
  }
}
