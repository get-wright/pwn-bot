import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { extractOpenAI, extractRAG, extractMetrics } from '../../src/tools/log-extract.js';

const SAMPLE_EVENTS = [
  { timestamp: '2026-04-09T10:00:00Z', run_id: 'r1', source: 'cli', event_type: 'pipeline.start', payload: { mode: 'pwn', binary_path: './vuln' } },
  { timestamp: '2026-04-09T10:00:01Z', run_id: 'r1', source: 'cli', event_type: 'llm.request', payload: { provider: 'claude', model: 'claude-sonnet-4-6', system_prompt: 'You are a vuln researcher', user_content: 'Analyze this function' } },
  { timestamp: '2026-04-09T10:00:05Z', run_id: 'r1', source: 'cli', event_type: 'llm.response', payload: { provider: 'claude', usage: { inputTokens: 500, outputTokens: 200 }, parsed_output: { function: 'vuln', vuln_class: 'stack_overflow' } } },
  { timestamp: '2026-04-09T10:00:06Z', run_id: 'r1', source: 'cli', event_type: 'hypothesis.result', payload: { function: 'vuln', vuln_class: 'stack_overflow', status: 'confirmed', primitive: 'controlled_rip' } },
  { timestamp: '2026-04-09T10:00:10Z', run_id: 'r1', source: 'cli', event_type: 'exploit.attempt', payload: { attempt_number: 1, success: true } },
  { timestamp: '2026-04-09T10:00:10Z', run_id: 'r1', source: 'cli', event_type: 'pipeline.end', payload: { success: true, total_duration_ms: 10000 } },
];

const LOG_PATH = join(tmpdir(), 'test-log-extract.jsonl');

beforeAll(async () => {
  const content = SAMPLE_EVENTS.map((e) => JSON.stringify(e)).join('\n') + '\n';
  await writeFile(LOG_PATH, content);
});

afterAll(async () => {
  await unlink(LOG_PATH).catch(() => undefined);
});

describe('extractOpenAI', () => {
  it('produces fine-tuning pairs', async () => {
    const pairs = await extractOpenAI(LOG_PATH);
    expect(pairs.length).toBeGreaterThanOrEqual(1);
    const [pair] = pairs;
    const roles = pair.messages.map((m) => m.role);
    expect(roles).toContain('system');
    expect(roles).toContain('user');
    expect(roles).toContain('assistant');
  });
});

describe('extractRAG', () => {
  it('produces knowledge chunks', async () => {
    const chunks = await extractRAG(LOG_PATH);
    expect(chunks.length).toBeGreaterThanOrEqual(1);
    const [chunk] = chunks;
    expect(chunk.vuln_class).toBe('stack_overflow');
    expect(chunk.status).toBe('confirmed');
  });
});

describe('extractMetrics', () => {
  it('produces summary', async () => {
    const summary = await extractMetrics(LOG_PATH);
    expect(summary.total_runs).toBe(1);
    expect(summary.success_rate).toBe(1);
    expect(summary.total_tokens.input).toBe(500);
    expect(summary.total_tokens.output).toBe(200);
  });
});
