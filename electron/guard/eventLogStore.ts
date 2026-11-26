import { GuardEventLog } from '../../src/shared/types';

const MAX_LOG_ENTRIES = 60;

export class EventLogStore {
  private logs: GuardEventLog[] = [];

  public add(level: GuardEventLog['level'], message: string): void {
    const entry: GuardEventLog = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: Date.now(),
      level,
      message,
    };
    this.logs.unshift(entry);
    if (this.logs.length > MAX_LOG_ENTRIES) {
      this.logs.length = MAX_LOG_ENTRIES;
    }
  }

  public clear(): void {
    this.logs = [];
  }

  public getSnapshot(): GuardEventLog[] {
    return [...this.logs];
  }
}
