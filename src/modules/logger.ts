import { appendFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

export interface LogEvent {
  timestamp: string;
  run_id: string;
  source: 'cli' | 'claude-code' | 'codex';
  event_type: string;
  stage?: string;
  duration_ms?: number;
  payload: Record<string, unknown>;
}

export interface LoggerOpts {
  verbose: boolean;
  runId?: string;
}

export class Logger {
  readonly verbose: boolean;
  readonly runId: string;
  private logPath: string | null;

  private constructor(logPath: string | null, opts: LoggerOpts) {
    this.logPath = logPath;
    this.verbose = opts.verbose;
    this.runId = opts.runId ?? randomUUID();
  }

  static init(outputDir: string, opts: LoggerOpts): Logger {
    const logPath = join(outputDir, 'run_log.jsonl');
    writeFileSync(logPath, '');
    return new Logger(logPath, opts);
  }

  static noop(): Logger {
    return new Logger(null, { verbose: false });
  }

  log(
    eventType: string,
    opts: { stage?: string; duration_ms?: number; payload?: Record<string, unknown> } = {},
  ): void {
    if (!this.logPath) return;
    const event: LogEvent = {
      timestamp: new Date().toISOString(),
      run_id: this.runId,
      source: 'cli',
      event_type: eventType,
      ...(opts.stage ? { stage: opts.stage } : {}),
      ...(opts.duration_ms !== undefined ? { duration_ms: opts.duration_ms } : {}),
      payload: opts.payload ?? {},
    };
    appendFileSync(this.logPath, JSON.stringify(event) + '\n');
  }

  async time<T>(eventType: string, stage: string, fn: () => Promise<T>): Promise<T> {
    this.log(`${eventType}.start`, { stage });
    const start = performance.now();
    const result = await fn();
    const duration_ms = Math.round(performance.now() - start);
    this.log(`${eventType}.end`, { stage, duration_ms });
    return result;
  }

  close(): void {
    // No-op for sync writes
  }
}
