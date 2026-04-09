import { readFile, writeFile } from 'node:fs/promises';
import type { LogEvent } from '../modules/logger.js';

export interface FineTuningPair {
  messages: Array<{ role: string; content: string }>;
}

export interface RAGChunk {
  run_id: string;
  binary_path?: string;
  function?: string;
  vuln_class?: string;
  primitive?: string;
  status?: string;
  exploit_success?: boolean;
}

export interface MetricsSummary {
  total_runs: number;
  success_rate: number;
  total_tokens: { input: number; output: number };
  avg_duration_ms?: number;
  vuln_classes: Record<string, number>;
}

async function parseLog(logPath: string): Promise<LogEvent[]> {
  const text = await readFile(logPath, 'utf-8');
  return text
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as LogEvent);
}

export async function extractOpenAI(logPath: string): Promise<FineTuningPair[]> {
  const events = await parseLog(logPath);
  const requests = events.filter((e) => e.event_type === 'llm.request');
  const responses = events.filter((e) => e.event_type === 'llm.response');
  const pairs: FineTuningPair[] = [];

  const count = Math.min(requests.length, responses.length);
  for (let i = 0; i < count; i++) {
    const req = requests[i].payload as {
      system_prompt?: string;
      user_content?: string;
    };
    const res = responses[i].payload as {
      parsed_output?: unknown;
    };

    pairs.push({
      messages: [
        { role: 'system', content: req.system_prompt ?? '' },
        { role: 'user', content: req.user_content ?? '' },
        { role: 'assistant', content: JSON.stringify(res.parsed_output ?? null) },
      ],
    });
  }

  return pairs;
}

export async function extractRAG(logPath: string): Promise<RAGChunk[]> {
  const events = await parseLog(logPath);

  const binaryByRunId: Record<string, string> = {};
  for (const e of events) {
    if (e.event_type === 'pipeline.start') {
      const p = e.payload as { binary_path?: string };
      if (p.binary_path) binaryByRunId[e.run_id] = p.binary_path;
    }
  }

  const exploitSuccessByRunId: Record<string, boolean> = {};
  for (const e of events) {
    if (e.event_type === 'exploit.attempt') {
      const p = e.payload as { success?: boolean };
      if (p.success === true) exploitSuccessByRunId[e.run_id] = true;
    }
  }

  const chunks: RAGChunk[] = [];
  for (const e of events) {
    if (e.event_type === 'hypothesis.result') {
      const p = e.payload as {
        function?: string;
        vuln_class?: string;
        primitive?: string;
        status?: string;
      };
      chunks.push({
        run_id: e.run_id,
        binary_path: binaryByRunId[e.run_id],
        function: p.function,
        vuln_class: p.vuln_class,
        primitive: p.primitive,
        status: p.status,
        exploit_success: exploitSuccessByRunId[e.run_id] ?? false,
      });
    }
  }

  return chunks;
}

export async function extractMetrics(logPath: string): Promise<MetricsSummary> {
  const events = await parseLog(logPath);

  const pipelineEnds = events.filter((e) => e.event_type === 'pipeline.end');
  const total_runs = pipelineEnds.length;
  const successCount = pipelineEnds.filter(
    (e) => (e.payload as { success?: boolean }).success === true,
  ).length;

  const llmResponses = events.filter((e) => e.event_type === 'llm.response');
  let inputTokens = 0;
  let outputTokens = 0;
  for (const e of llmResponses) {
    const usage = (e.payload as { usage?: { inputTokens?: number; outputTokens?: number } }).usage;
    inputTokens += usage?.inputTokens ?? 0;
    outputTokens += usage?.outputTokens ?? 0;
  }

  const durations = pipelineEnds
    .map((e) => (e.payload as { total_duration_ms?: number }).total_duration_ms)
    .filter((d): d is number => typeof d === 'number');

  const avg_duration_ms =
    durations.length > 0 ? durations.reduce((a, b) => a + b, 0) / durations.length : undefined;

  const vuln_classes: Record<string, number> = {};
  for (const e of events) {
    if (e.event_type === 'hypothesis.result') {
      const vc = (e.payload as { vuln_class?: string }).vuln_class;
      if (vc) vuln_classes[vc] = (vuln_classes[vc] ?? 0) + 1;
    }
  }

  return {
    total_runs,
    success_rate: total_runs > 0 ? successCount / total_runs : 0,
    total_tokens: { input: inputTokens, output: outputTokens },
    avg_duration_ms,
    vuln_classes,
  };
}

export async function extractToFile(
  logPaths: string[],
  outputPath: string,
  format: 'openai' | 'rag' | 'metrics',
): Promise<void> {
  if (format === 'openai') {
    const allPairs: FineTuningPair[] = [];
    for (const p of logPaths) allPairs.push(...(await extractOpenAI(p)));
    const lines = allPairs.map((pair) => JSON.stringify(pair)).join('\n');
    await writeFile(outputPath, lines + '\n');
  } else if (format === 'rag') {
    const allChunks: RAGChunk[] = [];
    for (const p of logPaths) allChunks.push(...(await extractRAG(p)));
    const lines = allChunks.map((chunk) => JSON.stringify(chunk)).join('\n');
    await writeFile(outputPath, lines + '\n');
  } else {
    const summaries: MetricsSummary[] = [];
    for (const p of logPaths) summaries.push(await extractMetrics(p));
    await writeFile(outputPath, JSON.stringify(summaries, null, 2) + '\n');
  }
}
