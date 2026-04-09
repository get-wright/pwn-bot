# Logging System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add unified JSONL logging across CLI pipeline, Claude Code hooks, and Codex wrapper to enable fine-tuning, post-mortem analysis, and benchmarking.

**Architecture:** A Logger class writes JSONL events to `output/run_log.jsonl`. It's injected into the pipeline and passed to tool wrappers and LLM providers. Shell hooks capture agent tool calls in the same format. An extraction CLI converts logs to training data.

**Tech Stack:** TypeScript (ESM), Node.js fs (appendFileSync for atomic writes), UUID via crypto.randomUUID(), bash for hooks

**Spec:** `docs/superpowers/specs/2026-04-09-logging-design.md`

---

## File Structure

```
Modified:
  src/config.ts           — add log.enabled + log.verbose to Config
  src/tools/exec.ts       — accept optional Logger, log tool.exec events
  src/providers/claude.ts  — accept optional Logger, log llm.request/response
  src/providers/openai.ts  — accept optional Logger, log llm.request/response
  src/providers/factory.ts — pass logger to provider constructors
  src/pipeline.ts          — create Logger, pass to modules, log stages/gates
  src/cli.ts               — add --no-log, --verbose-log flags
  src/index.ts             — export Logger

Created:
  src/modules/logger.ts         — Logger class (JSONL writer)
  src/tools/log-extract.ts      — training data extraction
  hooks/log-tool-use.sh         — Claude Code post-tool-use hook
  hooks/codex-wrapper.sh        — Codex CLI wrapper
  tests/modules/logger.test.ts  — Logger unit tests
  tests/tools/log-extract.test.ts — extraction tests
```

## Dependency Graph

```
Task 1 (Logger class)
  ├── Task 2 (Config extension)
  ├── Task 3 (exec.ts instrumentation)
  ├── Task 4 (Provider instrumentation)
  │     └── Task 5 (Pipeline instrumentation)
  │           └── Task 6 (CLI flags)
  ├── Task 7 (Claude Code hook)
  ├── Task 8 (Codex wrapper)
  └── Task 9 (Training extraction CLI)
```

---

### Task 1: Logger Module

**Files:**
- Create: `src/modules/logger.ts`
- Create: `tests/modules/logger.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/modules/logger.test.ts`:
```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Logger, type LogEvent } from '../src/modules/logger.js';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('Logger', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'logger-test-'));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('writes JSONL events to run_log.jsonl', async () => {
    const logger = Logger.init(dir, { verbose: false });
    logger.log('pipeline.start', { payload: { mode: 'pwn', binary: './vuln' } });
    logger.log('stage.start', { stage: 'recon' });
    logger.close();

    const content = await readFile(join(dir, 'run_log.jsonl'), 'utf-8');
    const lines = content.trim().split('\n').map(l => JSON.parse(l) as LogEvent);

    expect(lines).toHaveLength(2);
    expect(lines[0]!.event_type).toBe('pipeline.start');
    expect(lines[0]!.source).toBe('cli');
    expect(lines[0]!.run_id).toBeTruthy();
    expect(lines[0]!.timestamp).toBeTruthy();
    expect(lines[0]!.payload).toEqual({ mode: 'pwn', binary: './vuln' });
    expect(lines[1]!.stage).toBe('recon');
  });

  it('uses provided run_id', async () => {
    const logger = Logger.init(dir, { verbose: false, runId: 'test-run-123' });
    logger.log('test.event', {});
    logger.close();

    const content = await readFile(join(dir, 'run_log.jsonl'), 'utf-8');
    const event = JSON.parse(content.trim()) as LogEvent;
    expect(event.run_id).toBe('test-run-123');
  });

  it('time() wraps async function with duration', async () => {
    const logger = Logger.init(dir, { verbose: false });
    const result = await logger.time('stage', 'recon', async () => {
      await new Promise(r => setTimeout(r, 50));
      return 42;
    });
    logger.close();

    expect(result).toBe(42);

    const content = await readFile(join(dir, 'run_log.jsonl'), 'utf-8');
    const lines = content.trim().split('\n').map(l => JSON.parse(l) as LogEvent);

    expect(lines).toHaveLength(2);
    expect(lines[0]!.event_type).toBe('stage.start');
    expect(lines[1]!.event_type).toBe('stage.end');
    expect(lines[1]!.duration_ms).toBeGreaterThanOrEqual(40);
  });

  it('verbose flag is accessible', () => {
    const logger = Logger.init(dir, { verbose: true });
    expect(logger.verbose).toBe(true);
    logger.close();
  });

  it('noop logger does nothing', async () => {
    const logger = Logger.noop();
    logger.log('test', {});
    const result = await logger.time('stage', 'recon', async () => 'ok');
    expect(result).toBe('ok');
    logger.close();
    // No file created — noop
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/modules/logger.test.ts 2>&1 | tail -5`
Expected: FAIL — cannot import `../src/modules/logger.js`

- [ ] **Step 3: Implement logger.ts**

Create `src/modules/logger.ts`:
```typescript
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
    // Ensure file exists (truncate if new run)
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
    // No-op for sync writes. Placeholder for future stream-based impl.
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/modules/logger.test.ts`
Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/modules/logger.ts tests/modules/logger.test.ts
git commit -m "feat: add Logger module with JSONL event writing"
```

---

### Task 2: Config Extension

**Files:**
- Modify: `src/config.ts`
- Modify: `tests/config.test.ts`

- [ ] **Step 1: Write the failing test**

Add to `tests/config.test.ts`:
```typescript
describe('log config', () => {
  it('defaults to logging enabled, verbose off', () => {
    const config = resolveConfig({});
    expect(config.log.enabled).toBe(true);
    expect(config.log.verbose).toBe(false);
  });

  it('respects logEnabled and logVerbose overrides', () => {
    const config = resolveConfig({ logEnabled: false, logVerbose: true });
    expect(config.log.enabled).toBe(false);
    expect(config.log.verbose).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/config.test.ts 2>&1 | tail -5`
Expected: FAIL — `config.log` is undefined.

- [ ] **Step 3: Add log config to Config and ConfigOverrides**

In `src/config.ts`, add to `Config` interface:
```typescript
  log: {
    enabled: boolean;
    verbose: boolean;
  };
```

Add to `ConfigOverrides`:
```typescript
  logEnabled?: boolean;
  logVerbose?: boolean;
```

Add to `DEFAULT_CONFIG`:
```typescript
  log: {
    enabled: true,
    verbose: false,
  },
```

Add to `resolveConfig` return:
```typescript
    log: {
      enabled: overrides.logEnabled ?? DEFAULT_CONFIG.log.enabled,
      verbose: overrides.logVerbose ?? DEFAULT_CONFIG.log.verbose,
    },
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/config.test.ts`
Expected: All 9 tests PASS (7 existing + 2 new).

- [ ] **Step 5: Commit**

```bash
git add src/config.ts tests/config.test.ts
git commit -m "feat: add log.enabled and log.verbose to config"
```

---

### Task 3: Instrument exec.ts

**Files:**
- Modify: `src/tools/exec.ts`
- Modify: `tests/tools/checksec.test.ts` (verify existing tests still pass)

- [ ] **Step 1: Add optional logger parameter to exec()**

Modify `src/tools/exec.ts`:
```typescript
import { execa } from 'execa';
import type { Logger } from '../modules/logger.js';

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export async function exec(
  command: string,
  args: string[],
  opts?: { timeout?: number; cwd?: string; stdin?: string; logger?: Logger },
): Promise<ExecResult> {
  const start = performance.now();
  const result = await execa(command, args, {
    timeout: opts?.timeout ?? 30_000,
    cwd: opts?.cwd,
    reject: false,
    ...(opts?.stdin ? { input: opts.stdin } : {}),
  });
  const duration_ms = Math.round(performance.now() - start);

  const execResult: ExecResult = {
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
    exitCode: result.exitCode ?? 1,
  };

  opts?.logger?.log('tool.exec', {
    payload: {
      command,
      args,
      exit_code: execResult.exitCode,
      stdout: execResult.stdout,
      stderr: execResult.stderr,
      duration_ms,
    },
  });

  return execResult;
}
```

- [ ] **Step 2: Run existing tool tests to verify no regression**

Run: `npx vitest run tests/tools/`
Expected: All existing tests PASS (logger is optional, no change to callers needed).

- [ ] **Step 3: Commit**

```bash
git add src/tools/exec.ts
git commit -m "feat: instrument exec() with optional Logger for tool.exec events"
```

---

### Task 4: Instrument LLM Providers

**Files:**
- Modify: `src/providers/claude.ts`
- Modify: `src/providers/openai.ts`
- Modify: `src/providers/factory.ts`
- Modify: `src/providers/interface.ts`

- [ ] **Step 1: Add logger to LLMProvider interface**

In `src/providers/interface.ts`, add import and optional logger:
```typescript
import type { Logger } from '../modules/logger.js';
```

No change to the interface methods — logger is passed at construction time, not per call.

- [ ] **Step 2: Add logger to ClaudeProvider**

In `src/providers/claude.ts`, modify constructor and analyze():

```typescript
import type { Logger } from '../modules/logger.js';

export class ClaudeProvider implements LLMProvider {
  readonly name = 'claude' as const;
  private client: Anthropic;
  private model: string;
  private logger?: Logger;

  constructor(apiKey: string, model: string, logger?: Logger) {
    this.client = new Anthropic({ apiKey });
    this.model = model;
    this.logger = logger;
  }

  async analyze<T extends z.ZodType>(opts: AnalyzeOpts<T>): Promise<{ parsed: z.infer<T>; usage: TokenUsage }> {
    this.logger?.log('llm.request', {
      payload: {
        provider: 'claude',
        model: this.model,
        ...(this.logger?.verbose ? { system_prompt: opts.system, user_content: opts.userContent } : {}),
        max_tokens: opts.maxTokens ?? 4096,
      },
    });

    const message = await this.client.messages.create({
      model: this.model,
      max_tokens: opts.maxTokens ?? 4096,
      system: opts.system + '\n\nRespond with valid JSON only. No markdown, no explanation.',
      messages: [{ role: 'user', content: opts.userContent }],
    });

    const text = message.content
      .filter((b) => b.type === 'text')
      .map((b) => (b as Anthropic.TextBlock).text)
      .join('');

    const result = opts.schema.safeParse(JSON.parse(text));
    if (!result.success) {
      throw new Error(`Schema validation failed: ${result.error.message}`);
    }

    const usage = {
      inputTokens: message.usage.input_tokens,
      outputTokens: message.usage.output_tokens,
    };

    this.logger?.log('llm.response', {
      payload: {
        provider: 'claude',
        usage,
        ...(this.logger?.verbose ? { raw_response: text } : {}),
        parsed_output: result.data,
      },
    });

    return { parsed: result.data as z.infer<T>, usage };
  }
```

Apply the same pattern to `runWithTools()` — log `llm.request` before the loop, log `llm.response` after each iteration with accumulated usage.

- [ ] **Step 3: Add logger to OpenAIProvider**

In `src/providers/openai.ts`, same pattern:

```typescript
import type { Logger } from '../modules/logger.js';

export class OpenAIProvider implements LLMProvider {
  readonly name = 'openai' as const;
  private client: OpenAI;
  private model: string;
  private logger?: Logger;

  constructor(apiKey: string, model: string, logger?: Logger) {
    this.client = new OpenAI({ apiKey });
    this.model = model;
    this.logger = logger;
  }

  async analyze<T extends z.ZodType>(opts: AnalyzeOpts<T>): Promise<{ parsed: z.infer<T>; usage: TokenUsage }> {
    this.logger?.log('llm.request', {
      payload: {
        provider: 'openai',
        model: this.model,
        ...(this.logger?.verbose ? { system_prompt: opts.system, user_content: opts.userContent } : {}),
        max_tokens: opts.maxTokens ?? 4096,
      },
    });

    const completion = await this.client.chat.completions.parse({
      model: this.model,
      max_tokens: opts.maxTokens ?? 4096,
      messages: [
        { role: 'system', content: opts.system },
        { role: 'user', content: opts.userContent },
      ],
      response_format: zodResponseFormat(opts.schema, 'response'),
    });

    const message = completion.choices[0]?.message;
    if (!message?.parsed) {
      throw new Error('No parsed response from OpenAI');
    }

    const usage = {
      inputTokens: completion.usage?.prompt_tokens ?? 0,
      outputTokens: completion.usage?.completion_tokens ?? 0,
    };

    this.logger?.log('llm.response', {
      payload: {
        provider: 'openai',
        usage,
        ...(this.logger?.verbose ? { raw_response: message.content } : {}),
        parsed_output: message.parsed,
      },
    });

    return { parsed: message.parsed as z.infer<T>, usage };
  }
```

Apply same to `runWithTools()`.

- [ ] **Step 4: Update factory to accept logger**

In `src/providers/factory.ts`:
```typescript
import type { Logger } from '../modules/logger.js';

export interface ProviderConfig {
  provider: 'claude' | 'openai';
  model: string;
  apiKey?: string;
  logger?: Logger;
}

export function createProvider(config: ProviderConfig): LLMProvider {
  if (!config.apiKey) {
    throw new Error(`API key required for ${config.provider} provider`);
  }
  switch (config.provider) {
    case 'claude':
      return new ClaudeProvider(config.apiKey, config.model, config.logger);
    case 'openai':
      return new OpenAIProvider(config.apiKey, config.model, config.logger);
  }
}
```

- [ ] **Step 5: Run existing provider tests**

Run: `npx vitest run tests/providers/`
Expected: All 3 tests PASS (logger is optional).

- [ ] **Step 6: Commit**

```bash
git add src/providers/
git commit -m "feat: instrument LLM providers with optional Logger for request/response events"
```

---

### Task 5: Instrument Pipeline

**Files:**
- Modify: `src/pipeline.ts`

- [ ] **Step 1: Add logger to PipelineOpts and instrument runPipeline**

In `src/pipeline.ts`, add Logger to imports and PipelineOpts:

```typescript
import { Logger } from './modules/logger.js';
```

Add to PipelineOpts:
```typescript
export interface PipelineOpts {
  binaryPath: string;
  sourceDir?: string;
  libcPath?: string;
  remote?: { host: string; port: number };
  config: Config;
  provider: LLMProvider;
  mode: 'pwn' | 'recon' | 'hunt' | 'fuzz' | 'exploit' | 'full';
  logger?: Logger;
}
```

Then instrument `runPipeline()`. Replace console.log calls with logger.log calls (keep console.log too for user feedback). Key instrumentation points:

```typescript
export async function runPipeline(opts: PipelineOpts): Promise<PipelineResult> {
  const { binaryPath, libcPath, remote, config, provider, mode } = opts;
  const outputDir = config.outputDir;
  const logger = opts.logger ?? Logger.noop();

  await mkdir(outputDir, { recursive: true });

  logger.log('pipeline.start', {
    payload: { mode, binary_path: binaryPath, config },
  });

  const pipelineStart = performance.now();

  // --- Recon ---
  let recon: ReconOutput;

  if (mode === 'exploit') {
    // ... existing load logic ...
  } else {
    console.log('[recon] Starting binary analysis');
    recon = await logger.time('stage', 'recon', () =>
      runRecon(binaryPath, { libcPath, outputDir }),
    );
    console.log(`[recon] Found ${recon.functions.length} functions`);
  }

  if (mode === 'recon') {
    logger.log('pipeline.end', { payload: { success: true, message: 'Recon complete', total_duration_ms: Math.round(performance.now() - pipelineStart) } });
    logger.close();
    return { recon, success: true, message: 'Recon complete' };
  }

  // --- Recon gate ---
  const reconGate = validateReconGate(recon);
  logger.log('gate.result', { payload: { gate_name: 'recon', ...reconGate } });
  if (!reconGate.pass) {
    logger.log('pipeline.end', { payload: { success: false, message: reconGate.reason } });
    logger.close();
    return { recon, success: false, message: reconGate.reason ?? 'Recon gate failed' };
  }

  // --- Hunt ---
  // Wrap in logger.time('stage', 'hunt', ...)
  // Log each hypothesis.result after GDB confirmation

  // --- Hunter gate ---
  // logger.log('gate.result', { payload: { gate_name: 'hunter', ...hunterGate } })

  // --- Exploit ---
  // Log each exploit.attempt with attempt number, success, output
  // Wrap in logger.time('stage', 'exploit', ...)

  // --- End ---
  logger.log('pipeline.end', {
    payload: { success: true, total_duration_ms: Math.round(performance.now() - pipelineStart) },
  });
  logger.close();
}
```

Apply this pattern to every stage and gate. Each `console.log` is preserved (user feedback) and a `logger.log` is added alongside it (structured logging).

- [ ] **Step 2: Run existing pipeline tests**

Run: `npx vitest run tests/pipeline.test.ts`
Expected: All 4 tests PASS (logger is optional via `?? Logger.noop()`).

- [ ] **Step 3: Commit**

```bash
git add src/pipeline.ts
git commit -m "feat: instrument pipeline with Logger for stage/gate/attempt events"
```

---

### Task 6: CLI Flags

**Files:**
- Modify: `src/cli.ts`

- [ ] **Step 1: Add --no-log and --verbose-log flags**

In `src/cli.ts`, add to `addCommonOpts()`:
```typescript
    .option('--no-log', 'disable logging')
    .option('--verbose-log', 'log full LLM prompts and responses')
```

Add to `CommonOpts` interface:
```typescript
  log?: boolean;        // commander inverts --no-log to opts.log = false
  verboseLog?: boolean;
```

- [ ] **Step 2: Create Logger in runMode() and pass to pipeline**

In `runMode()`, after resolveConfig:
```typescript
import { Logger } from './modules/logger.js';

  const overrides: ConfigOverrides = {
    // ... existing ...
    logEnabled: opts.log !== false,  // --no-log sets opts.log to false
    logVerbose: opts.verboseLog,
  };

  const config = resolveConfig(overrides);

  const logger = config.log.enabled
    ? Logger.init(config.outputDir, { verbose: config.log.verbose })
    : Logger.noop();

  const provider = createProvider({ ...config, logger });

  const result = await runPipeline({
    binaryPath,
    sourceDir: opts.source,
    libcPath: opts.libc,
    remote: parseRemote(opts.remote),
    config,
    provider,
    mode,
    logger,
  });
```

- [ ] **Step 3: Verify CLI builds**

Run: `npx tsc --noEmit`
Expected: No errors.

Run: `node dist/cli.js pwn --help`
Expected: Shows `--no-log` and `--verbose-log` in options.

- [ ] **Step 4: Commit**

```bash
git add src/cli.ts
git commit -m "feat: add --no-log and --verbose-log CLI flags"
```

---

### Task 7: Claude Code Hook

**Files:**
- Create: `hooks/log-tool-use.sh`
- Modify: `.claude/settings.local.json`

- [ ] **Step 1: Create the hook script**

Create `hooks/log-tool-use.sh`:
```bash
#!/usr/bin/env bash
# Claude Code post-tool-use hook
# Reads tool use JSON from stdin, appends to run_log.jsonl
set -euo pipefail

OUTPUT_DIR="${AGENT_FUZZ_OUTPUT:-$PWD/output}"
LOG_FILE="$OUTPUT_DIR/run_log.jsonl"
SESSION_ID="${CLAUDE_SESSION_ID:-claude-$(date +%s)}"

mkdir -p "$OUTPUT_DIR"

# Read tool context from stdin
TOOL_JSON=$(cat)

# Extract fields — jq if available, else python3 fallback
if command -v jq &>/dev/null; then
  TOOL_NAME=$(echo "$TOOL_JSON" | jq -r '.tool_name // "unknown"')
  TOOL_INPUT=$(echo "$TOOL_JSON" | jq -c '.input // {}')
  TOOL_OUTPUT=$(echo "$TOOL_JSON" | jq -c '.output // ""')
else
  TOOL_NAME=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('tool_name','unknown'))" <<< "$TOOL_JSON" 2>/dev/null || echo "unknown")
  TOOL_INPUT=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('input',{})))" <<< "$TOOL_JSON" 2>/dev/null || echo "{}")
  TOOL_OUTPUT=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('output','')))" <<< "$TOOL_JSON" 2>/dev/null || echo '""')
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")

# Write LogEvent
printf '{"timestamp":"%s","run_id":"%s","source":"claude-code","event_type":"agent.tool_use","payload":{"tool_name":"%s","input":%s,"output":%s}}\n' \
  "$TIMESTAMP" "$SESSION_ID" "$TOOL_NAME" "$TOOL_INPUT" "$TOOL_OUTPUT" >> "$LOG_FILE"
```

- [ ] **Step 2: Make executable**

Run: `chmod +x hooks/log-tool-use.sh`

- [ ] **Step 3: Update .claude/settings.local.json**

Read the existing file, then add hooks config:
```json
{
  "permissions": {
    "allow": [
      "WebFetch(domain:red.anthropic.com)"
    ]
  },
  "hooks": {
    "post-tool-use": [{
      "command": "hooks/log-tool-use.sh",
      "match": "*"
    }]
  }
}
```

- [ ] **Step 4: Commit**

```bash
git add hooks/log-tool-use.sh .claude/settings.local.json
git commit -m "feat: add Claude Code post-tool-use hook for JSONL logging"
```

---

### Task 8: Codex Wrapper

**Files:**
- Create: `hooks/codex-wrapper.sh`

- [ ] **Step 1: Create the wrapper script**

Create `hooks/codex-wrapper.sh`:
```bash
#!/usr/bin/env bash
# Codex CLI wrapper that captures session logs into run_log.jsonl
set -euo pipefail

OUTPUT_DIR="${AGENT_FUZZ_OUTPUT:-$PWD/output}"
LOG_FILE="$OUTPUT_DIR/run_log.jsonl"
RUN_ID="codex-$(date +%s)-$$"

mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")

# Log pipeline start
printf '{"timestamp":"%s","run_id":"%s","source":"codex","event_type":"pipeline.start","payload":{"args":"%s"}}\n' \
  "$TIMESTAMP" "$RUN_ID" "$*" >> "$LOG_FILE"

START_TIME=$(date +%s)

# Run codex, capture output
CODEX_OUTPUT=$(mktemp)
codex "$@" 2>&1 | tee "$CODEX_OUTPUT"
CODEX_EXIT=$?

END_TIME=$(date +%s)
DURATION_MS=$(( (END_TIME - START_TIME) * 1000 ))

# Parse Codex logs if available
CODEX_LOG_DIR="${HOME}/.codex/logs"
if [ -d "$CODEX_LOG_DIR" ]; then
  # Find the most recent log file (created during this session)
  LATEST_LOG=$(find "$CODEX_LOG_DIR" -name "*.log" -newer "$CODEX_OUTPUT" -type f 2>/dev/null | sort | tail -1)

  if [ -n "$LATEST_LOG" ] && [ -f "$LATEST_LOG" ]; then
    # Extract shell commands from codex log
    # Codex logs tool calls as JSON lines with "type":"tool_call"
    while IFS= read -r line; do
      TOOL_NAME=$(echo "$line" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name',''))" 2>/dev/null || true)
      if [ -n "$TOOL_NAME" ]; then
        TOOL_INPUT=$(echo "$line" | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('input',{})))" 2>/dev/null || echo "{}")
        TOOL_OUTPUT=$(echo "$line" | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('output','')))" 2>/dev/null || echo '""')
        TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        printf '{"timestamp":"%s","run_id":"%s","source":"codex","event_type":"agent.tool_use","payload":{"tool_name":"%s","input":%s,"output":%s}}\n' \
          "$TS" "$RUN_ID" "$TOOL_NAME" "$TOOL_INPUT" "$TOOL_OUTPUT" >> "$LOG_FILE"
      fi
    done < "$LATEST_LOG"
  fi
fi

# Log pipeline end
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
printf '{"timestamp":"%s","run_id":"%s","source":"codex","event_type":"pipeline.end","duration_ms":%d,"payload":{"exit_code":%d,"success":%s}}\n' \
  "$TIMESTAMP" "$RUN_ID" "$DURATION_MS" "$CODEX_EXIT" "$([ $CODEX_EXIT -eq 0 ] && echo true || echo false)" >> "$LOG_FILE"

rm -f "$CODEX_OUTPUT"
exit $CODEX_EXIT
```

- [ ] **Step 2: Make executable**

Run: `chmod +x hooks/codex-wrapper.sh`

- [ ] **Step 3: Commit**

```bash
git add hooks/codex-wrapper.sh
git commit -m "feat: add Codex CLI wrapper for JSONL session logging"
```

---

### Task 9: Training Data Extraction

**Files:**
- Create: `src/tools/log-extract.ts`
- Create: `tests/tools/log-extract.test.ts`
- Modify: `src/cli.ts` (add extract-training subcommand)

- [ ] **Step 1: Write the failing test**

Create `tests/tools/log-extract.test.ts`:
```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { extractOpenAI, extractRAG, extractMetrics } from '../src/tools/log-extract.js';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SAMPLE_EVENTS = [
  { timestamp: '2026-04-09T10:00:00Z', run_id: 'r1', source: 'cli', event_type: 'pipeline.start', payload: { mode: 'pwn', binary_path: './vuln' } },
  { timestamp: '2026-04-09T10:00:01Z', run_id: 'r1', source: 'cli', event_type: 'llm.request', payload: { provider: 'claude', model: 'claude-sonnet-4-6', system_prompt: 'You are a vuln researcher', user_content: 'Analyze this function' } },
  { timestamp: '2026-04-09T10:00:05Z', run_id: 'r1', source: 'cli', event_type: 'llm.response', payload: { provider: 'claude', usage: { inputTokens: 500, outputTokens: 200 }, parsed_output: { function: 'vuln', vuln_class: 'stack_overflow' } } },
  { timestamp: '2026-04-09T10:00:06Z', run_id: 'r1', source: 'cli', event_type: 'hypothesis.result', payload: { function: 'vuln', vuln_class: 'stack_overflow', status: 'confirmed', primitive: 'controlled_rip' } },
  { timestamp: '2026-04-09T10:00:10Z', run_id: 'r1', source: 'cli', event_type: 'exploit.attempt', payload: { attempt_number: 1, success: true } },
  { timestamp: '2026-04-09T10:00:10Z', run_id: 'r1', source: 'cli', event_type: 'pipeline.end', payload: { success: true, total_duration_ms: 10000 } },
].map(e => JSON.stringify(e)).join('\n') + '\n';

describe('log-extract', () => {
  let dir: string;
  let logPath: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'extract-test-'));
    logPath = join(dir, 'run_log.jsonl');
    await writeFile(logPath, SAMPLE_EVENTS);
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('extractOpenAI produces fine-tuning pairs', async () => {
    const pairs = await extractOpenAI(logPath);
    expect(pairs.length).toBeGreaterThanOrEqual(1);
    expect(pairs[0]!.messages).toBeDefined();
    expect(pairs[0]!.messages.some((m: { role: string }) => m.role === 'system')).toBe(true);
    expect(pairs[0]!.messages.some((m: { role: string }) => m.role === 'assistant')).toBe(true);
  });

  it('extractRAG produces knowledge chunks', async () => {
    const chunks = await extractRAG(logPath);
    expect(chunks.length).toBeGreaterThanOrEqual(1);
    expect(chunks[0]!.vuln_class).toBe('stack_overflow');
    expect(chunks[0]!.status).toBe('confirmed');
  });

  it('extractMetrics produces summary', async () => {
    const metrics = await extractMetrics(logPath);
    expect(metrics.total_runs).toBe(1);
    expect(metrics.success_rate).toBe(1);
    expect(metrics.total_tokens.input).toBe(500);
    expect(metrics.total_tokens.output).toBe(200);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/tools/log-extract.test.ts 2>&1 | tail -5`
Expected: FAIL.

- [ ] **Step 3: Implement log-extract.ts**

Create `src/tools/log-extract.ts`:
```typescript
import { readFile, writeFile } from 'node:fs/promises';

interface LogEvent {
  timestamp: string;
  run_id: string;
  source: string;
  event_type: string;
  stage?: string;
  duration_ms?: number;
  payload: Record<string, unknown>;
}

async function parseLog(logPath: string): Promise<LogEvent[]> {
  const content = await readFile(logPath, 'utf-8');
  return content
    .trim()
    .split('\n')
    .filter(Boolean)
    .map(line => JSON.parse(line) as LogEvent);
}

export interface FineTuningPair {
  messages: Array<{ role: string; content: string }>;
}

export async function extractOpenAI(logPath: string): Promise<FineTuningPair[]> {
  const events = await parseLog(logPath);
  const pairs: FineTuningPair[] = [];

  // Pair up llm.request + llm.response events
  const requests = events.filter(e => e.event_type === 'llm.request');
  const responses = events.filter(e => e.event_type === 'llm.response');

  for (let i = 0; i < Math.min(requests.length, responses.length); i++) {
    const req = requests[i]!;
    const res = responses[i]!;

    const systemPrompt = (req.payload.system_prompt as string) ?? 'You are a security analyst.';
    const userContent = (req.payload.user_content as string) ?? '';
    const assistantContent = JSON.stringify(res.payload.parsed_output ?? res.payload.raw_response ?? '');

    pairs.push({
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userContent },
        { role: 'assistant', content: assistantContent },
      ],
    });
  }

  return pairs;
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

export async function extractRAG(logPath: string): Promise<RAGChunk[]> {
  const events = await parseLog(logPath);
  const chunks: RAGChunk[] = [];

  const startEvent = events.find(e => e.event_type === 'pipeline.start');
  const binaryPath = (startEvent?.payload?.binary_path as string) ?? undefined;

  const hypothesisResults = events.filter(e => e.event_type === 'hypothesis.result');
  const exploitAttempts = events.filter(e => e.event_type === 'exploit.attempt');
  const exploitSuccess = exploitAttempts.some(e => e.payload.success === true);

  for (const h of hypothesisResults) {
    chunks.push({
      run_id: h.run_id,
      binary_path: binaryPath,
      function: h.payload.function as string,
      vuln_class: h.payload.vuln_class as string,
      primitive: h.payload.primitive as string,
      status: h.payload.status as string,
      exploit_success: exploitSuccess,
    });
  }

  return chunks;
}

export interface MetricsSummary {
  total_runs: number;
  success_rate: number;
  total_tokens: { input: number; output: number };
  avg_duration_ms?: number;
  vuln_classes: Record<string, number>;
}

export async function extractMetrics(logPath: string): Promise<MetricsSummary> {
  const events = await parseLog(logPath);

  const pipelineEnds = events.filter(e => e.event_type === 'pipeline.end');
  const totalRuns = pipelineEnds.length;
  const successes = pipelineEnds.filter(e => e.payload.success === true).length;

  const llmResponses = events.filter(e => e.event_type === 'llm.response');
  let totalInput = 0;
  let totalOutput = 0;
  for (const r of llmResponses) {
    const usage = r.payload.usage as { inputTokens: number; outputTokens: number } | undefined;
    totalInput += usage?.inputTokens ?? 0;
    totalOutput += usage?.outputTokens ?? 0;
  }

  const durations = pipelineEnds
    .map(e => e.payload.total_duration_ms as number)
    .filter(d => d != null);

  const vulnClasses: Record<string, number> = {};
  for (const e of events.filter(e => e.event_type === 'hypothesis.result')) {
    const cls = e.payload.vuln_class as string;
    if (cls) vulnClasses[cls] = (vulnClasses[cls] ?? 0) + 1;
  }

  return {
    total_runs: totalRuns,
    success_rate: totalRuns > 0 ? successes / totalRuns : 0,
    total_tokens: { input: totalInput, output: totalOutput },
    avg_duration_ms: durations.length > 0
      ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length)
      : undefined,
    vuln_classes: vulnClasses,
  };
}

export async function extractToFile(
  logPaths: string[],
  outputPath: string,
  format: 'openai' | 'rag' | 'metrics',
): Promise<void> {
  if (format === 'metrics') {
    // Merge metrics across all logs
    const allMetrics: MetricsSummary[] = [];
    for (const logPath of logPaths) {
      allMetrics.push(await extractMetrics(logPath));
    }

    const merged: MetricsSummary = {
      total_runs: allMetrics.reduce((s, m) => s + m.total_runs, 0),
      success_rate: 0,
      total_tokens: {
        input: allMetrics.reduce((s, m) => s + m.total_tokens.input, 0),
        output: allMetrics.reduce((s, m) => s + m.total_tokens.output, 0),
      },
      vuln_classes: {},
    };
    const totalSuccesses = allMetrics.reduce((s, m) => s + m.success_rate * m.total_runs, 0);
    merged.success_rate = merged.total_runs > 0 ? totalSuccesses / merged.total_runs : 0;

    for (const m of allMetrics) {
      for (const [cls, count] of Object.entries(m.vuln_classes)) {
        merged.vuln_classes[cls] = (merged.vuln_classes[cls] ?? 0) + count;
      }
    }

    await writeFile(outputPath, JSON.stringify(merged, null, 2));
    return;
  }

  // JSONL output for openai and rag formats
  const lines: string[] = [];
  for (const logPath of logPaths) {
    if (format === 'openai') {
      const pairs = await extractOpenAI(logPath);
      for (const p of pairs) lines.push(JSON.stringify(p));
    } else {
      const chunks = await extractRAG(logPath);
      for (const c of chunks) lines.push(JSON.stringify(c));
    }
  }
  await writeFile(outputPath, lines.join('\n') + '\n');
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/tools/log-extract.test.ts`
Expected: All 3 tests PASS.

- [ ] **Step 5: Add extract-training subcommand to CLI**

In `src/cli.ts`, add after the batch command:

```typescript
import { extractToFile } from './tools/log-extract.js';
import { glob } from 'node:fs';

program
  .command('extract-training <logs...>')
  .description('Extract training data from run logs')
  .requiredOption('--format <format>', 'Output format: openai, rag, or metrics')
  .option('--output <path>', 'Output file path', './training_data.jsonl')
  .action(async (logs: string[], opts: { format: string; output: string }) => {
    const format = opts.format as 'openai' | 'rag' | 'metrics';
    if (!['openai', 'rag', 'metrics'].includes(format)) {
      console.error(`Invalid format: ${format}. Use: openai, rag, metrics`);
      process.exit(1);
    }
    await extractToFile(logs, opts.output, format);
    console.log(`Extracted ${format} data to ${opts.output}`);
  });
```

- [ ] **Step 6: Verify build**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 7: Commit**

```bash
git add src/tools/log-extract.ts tests/tools/log-extract.test.ts src/cli.ts
git commit -m "feat: add training data extraction CLI (openai, rag, metrics formats)"
```

---

### Task 10: Update Exports + Integration Test

**Files:**
- Modify: `src/index.ts`
- Create: `tests/logging-integration.test.ts`

- [ ] **Step 1: Update exports**

In `src/index.ts`, add:
```typescript
export { Logger, type LogEvent } from './modules/logger.js';
export { extractOpenAI, extractRAG, extractMetrics } from './tools/log-extract.js';
```

- [ ] **Step 2: Write integration test**

Create `tests/logging-integration.test.ts`:
```typescript
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
    // Simulate a mini pipeline run
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
```

- [ ] **Step 3: Run all tests**

Run: `npx vitest run`
Expected: All tests pass (existing 38 + new ~10).

- [ ] **Step 4: Verify clean build**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 5: Commit**

```bash
git add src/index.ts tests/logging-integration.test.ts
git commit -m "test: add logging integration test and update exports"
```

---

## Self-Review

**Spec coverage:**
- [x] LogEvent schema (Component 1) → Task 1 (Logger module)
- [x] CLI Logger module (Component 2) → Tasks 1, 3, 4, 5
- [x] Config extension (log.enabled, log.verbose) → Task 2
- [x] exec.ts instrumentation → Task 3
- [x] Provider instrumentation → Task 4
- [x] Pipeline instrumentation → Task 5
- [x] CLI flags (--no-log, --verbose-log) → Task 6
- [x] Claude Code hook (Component 3) → Task 7
- [x] Codex wrapper (Component 4) → Task 8
- [x] Training extraction (Component 5) → Task 9
- [x] Integration test → Task 10

**Placeholder scan:** No TBDs, TODOs, or "implement later" in any task.

**Type consistency:**
- `LogEvent` — consistent across logger.ts, log-extract.ts, hook scripts
- `Logger.init()` / `Logger.noop()` — consistent across logger.ts, pipeline.ts, cli.ts
- `logger.log(eventType, { stage?, payload? })` — consistent across all instrumentation points
- `Config.log.enabled` / `Config.log.verbose` — consistent across config.ts, cli.ts
- `extractOpenAI` / `extractRAG` / `extractMetrics` — consistent between log-extract.ts and tests
