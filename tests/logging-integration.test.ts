import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Logger } from '../src/modules/logger.js';
import { extractOpenAI, extractMetrics } from '../src/tools/log-extract.js';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('logging integration', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'log-int-'));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('logger writes events that extraction can parse', async () => {
    const logger = Logger.init(dir, { verbose: true, runId: 'integration-test' });

    logger.log('pipeline.start', { payload: { mode: 'pwn', binary_path: './test' } });
    logger.log('llm.request', { payload: { provider: 'claude', model: 'test', system_prompt: 'Analyze', user_content: 'Function code here' } });
    logger.log('llm.response', { payload: { provider: 'claude', usage: { inputTokens: 100, outputTokens: 50 }, parsed_output: { result: 'vuln found' } } });
    logger.log('hypothesis.result', { payload: { function: 'vuln', vuln_class: 'stack_overflow', status: 'confirmed', primitive: 'controlled_rip' } });
    logger.log('exploit.attempt', { payload: { attempt_number: 1, success: true } });
    logger.log('pipeline.end', { payload: { success: true, total_duration_ms: 5000 } });
    logger.close();

    const logPath = join(dir, 'run_log.jsonl');

    // Verify raw log
    const raw = await readFile(logPath, 'utf-8');
    const lines = raw.trim().split('\n');
    expect(lines).toHaveLength(6);

    // Verify extraction works on logger output
    const pairs = await extractOpenAI(logPath);
    expect(pairs).toHaveLength(1);
    expect(pairs[0]!.messages[0]!.content).toBe('Analyze');

    const metrics = await extractMetrics(logPath);
    expect(metrics.total_runs).toBe(1);
    expect(metrics.success_rate).toBe(1);
    expect(metrics.total_tokens.input).toBe(100);
    expect(metrics.vuln_classes['stack_overflow']).toBe(1);
  });
});
