import { ClaudeVerificationFailure } from '../src/shared/types';

export const CLAUDE_VERIFICATION_RETRY_MS = 5000;

export function normalizeVerificationFailureSignature(reason: string): string {
  return reason
    .trim()
    .replace(/^Claude 专属节点出口不可达\s*\((.*)\)$/s, '$1')
    .replace(/https?:\/\/[^\s：)]+?(?:：|:\s+)/gi, '<probe-url>:')
    .replace(/\s+/g, ' ');
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

  constructor(
    private readonly retry: () => Promise<void>,
    private readonly retryMs = CLAUDE_VERIFICATION_RETRY_MS
  ) {}

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

    const startedAt = Date.now();
    const failure = { startedAt, reason };
    this.failure = failure;
    this.loggedSignatures.clear();
    this.loggedSignatures.add(nextSignature);
    this.retryTimer = setInterval(() => {
      if (this.failure !== failure || this.retryInProgress) return;
      this.retryInProgress = true;
      void this.retry().finally(() => {
        this.retryInProgress = false;
      });
    }, this.retryMs);
    return {
      shouldLog: true,
      stateChanged: true,
    };
  }

  clear(): ClaudeVerificationFailure | null {
    const previous = this.snapshot;
    this.failure = null;
    this.loggedSignatures.clear();
    if (this.retryTimer) clearInterval(this.retryTimer);
    this.retryTimer = null;
    return previous;
  }
}
