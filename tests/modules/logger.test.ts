import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Logger } from '../../src/modules/logger.js';

const tmpDirs: string[] = [];

function makeTmpDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'logger-test-'));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tmpDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('Logger', () => {
  it('writes JSONL events to run_log.jsonl', () => {
    const dir = makeTmpDir();
    const logger = Logger.init(dir, { verbose: false });

    logger.log('test.event', { payload: { key: 'value' } });
    logger.log('other.event', { stage: 'fuzz', payload: { count: 42 } });
    logger.close();

    const content = readFileSync(join(dir, 'run_log.jsonl'), 'utf8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(2);

    const first = JSON.parse(lines[0]);
    expect(first.event_type).toBe('test.event');
    expect(first.run_id).toBeTruthy();
    expect(first.source).toBe('cli');
    expect(first.timestamp).toBeTruthy();
    expect(first.payload).toEqual({ key: 'value' });

    const second = JSON.parse(lines[1]);
    expect(second.event_type).toBe('other.event');
    expect(second.stage).toBe('fuzz');
    expect(second.payload).toEqual({ count: 42 });
  });

  it('uses provided run_id', () => {
    const dir = makeTmpDir();
    const logger = Logger.init(dir, { verbose: false, runId: 'test-run-123' });

    logger.log('check.id');
    logger.close();

    const content = readFileSync(join(dir, 'run_log.jsonl'), 'utf8');
    const event = JSON.parse(content.trim());
    expect(event.run_id).toBe('test-run-123');
  });

  it('time() wraps async function with duration', async () => {
    const dir = makeTmpDir();
    const logger = Logger.init(dir, { verbose: false });

    const result = await logger.time('sleep', 'test-stage', async () => {
      await new Promise((r) => setTimeout(r, 50));
      return 'done';
    });

    expect(result).toBe('done');
    logger.close();

    const content = readFileSync(join(dir, 'run_log.jsonl'), 'utf8');
    const lines = content.trim().split('\n').map((l) => JSON.parse(l));
    expect(lines).toHaveLength(2);

    const startEvent = lines[0];
    expect(startEvent.event_type).toBe('sleep.start');
    expect(startEvent.stage).toBe('test-stage');

    const endEvent = lines[1];
    expect(endEvent.event_type).toBe('sleep.end');
    expect(endEvent.stage).toBe('test-stage');
    expect(endEvent.duration_ms).toBeGreaterThanOrEqual(40);
  });

  it('verbose flag is accessible', () => {
    const dir = makeTmpDir();
    const logger = Logger.init(dir, { verbose: true });
    expect(logger.verbose).toBe(true);
  });

  it('noop logger does nothing', async () => {
    const logger = Logger.noop();

    expect(() => logger.log('any.event')).not.toThrow();

    const result = await logger.time('op', 'stage', async () => 42);
    expect(result).toBe(42);

    logger.close();
  });
});
