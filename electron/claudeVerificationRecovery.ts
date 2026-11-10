import { ClaudeVerificationFailure } from '../src/shared/types';

export const CLAUDE_VERIFICATION_RETRY_MS = 5000;
export const CLAUDE_VERIFICATION_DEADLINE_MS = 30000;

export class ClaudeVerificationRecovery {
  private failure: ClaudeVerificationFailure | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private deadlineTimer: NodeJS.Timeout | null = null;
  private retryInProgress = false;

  constructor(
    private readonly retry: () => Promise<void>,
    private readonly expire: (failure: ClaudeVerificationFailure) => Promise<void>
  ) {}

  get snapshot(): ClaudeVerificationFailure | null {
    return this.failure ? { ...this.failure } : null;
  }

  recordFailure(reason: string): boolean {
    if (this.failure) {
      const changed = this.failure.reason !== reason;
      this.failure.reason = reason;
      return changed;
    }

    const startedAt = Date.now();
    const failure = { startedAt, deadlineAt: startedAt + CLAUDE_VERIFICATION_DEADLINE_MS, reason };
    this.failure = failure;
    this.deadlineTimer = setTimeout(() => {
      if (this.failure !== failure) return;
      const expired = { ...failure };
      this.clear();
      void this.expire(expired);
    }, CLAUDE_VERIFICATION_DEADLINE_MS);
    this.retryTimer = setInterval(() => {
      if (this.failure !== failure || this.retryInProgress) return;
      this.retryInProgress = true;
      void this.retry().finally(() => {
        this.retryInProgress = false;
      });
    }, CLAUDE_VERIFICATION_RETRY_MS);
    return true;
  }

  clear(): ClaudeVerificationFailure | null {
    const previous = this.snapshot;
    this.failure = null;
    if (this.retryTimer) clearInterval(this.retryTimer);
    if (this.deadlineTimer) clearTimeout(this.deadlineTimer);
    this.retryTimer = null;
    this.deadlineTimer = null;
    return previous;
  }
}
