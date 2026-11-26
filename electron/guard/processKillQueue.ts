import {
  ProcessKillReport,
  terminateProtectedProcesses,
} from '../system/processGuard';

/**
 * 串行化进程强杀队列：确保并发触发的强杀调用等待真实强杀结果，并在每次强杀后同步执行状态刷新回调
 */
export class ProcessKillQueue {
  private activeCount = 0;
  private queue: Promise<unknown> = Promise.resolve();
  private onAfterKill?: () => Promise<void>;

  public setAfterKillHook(hook: () => Promise<void>): void {
    this.onAfterKill = hook;
  }

  public get isBusy(): boolean {
    return this.activeCount > 0;
  }

  public executeSafely(patterns: string[]): Promise<ProcessKillReport> {
    const run = async (): Promise<ProcessKillReport> => {
      this.activeCount++;
      try {
        const report = await terminateProtectedProcesses(patterns);
        if (this.onAfterKill) {
          await this.onAfterKill();
        }
        return report;
      } finally {
        this.activeCount--;
      }
    };

    const task = this.queue.then(run, run);
    this.queue = task.then(
      () => undefined,
      () => undefined
    );
    return task;
  }
}
