# agent-fuzz Logging System

**Date:** 2026-04-09
**Status:** Design approved, pending implementation

## Goal

Add unified logging across all execution surfaces (CLI pipeline, Claude Code skills, Codex sessions) to enable fine-tuning, post-mortem analysis, and benchmarking from historical run data.

## Design Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Storage format | JSONL (one event per line) | Simple, grep-able, easy to parse for training data |
| Log location | Per-run: `output/run_log.jsonl` | Logs stay with artifacts, easy to zip and share |
| LLM content logging | Configurable (verbose flag) | Full prompts/responses are large; default logs structured output only |
| Tool output logging | Always raw | Valuable for debugging when parsed results miss something |
| Agent integration | Claude Code hook + Codex wrapper | Captures tool calls from interactive agent sessions |
| Training extraction | Built-in CLI subcommand | No external tooling needed |

---

## Component 1: Unified Event Schema

Every log event uses the same schema regardless of source:

```typescript
interface LogEvent {
  timestamp: string;          // ISO 8601
  run_id: string;             // UUID per pipeline run or agent session
  source: 'cli' | 'claude-code' | 'codex';
  event_type: string;
  stage?: 'recon' | 'hunt' | 'exploit' | 'fuzz' | 'triage';
  duration_ms?: number;
  payload: Record<string, unknown>;
}
```

### Event Type Catalog

| Event Type | Source | Payload |
|-----------|--------|---------|
| `pipeline.start` | cli | config, binary_path, mode |
| `pipeline.end` | cli | success, message, total_duration_ms |
| `gate.result` | cli | gate_name, pass, reason |
| `stage.start` | cli | stage name |
| `stage.end` | cli | stage name, duration_ms |
| `llm.request` | cli | provider, model, system_prompt (verbose only), user_content (verbose only), token_count |
| `llm.response` | cli | parsed_output, raw_response (verbose only), usage (inputTokens, outputTokens) |
| `tool.exec` | cli | command, args, exit_code, stdout, stderr, duration_ms |
| `tool.parsed` | cli | tool_name, parsed_result |
| `hypothesis.result` | cli | hypothesis, status, evidence |
| `exploit.attempt` | cli | attempt_number, success, output |
| `crash.found` | cli | crash_info, exploitability |
| `agent.tool_use` | claude-code / codex | tool_name, input, output |
| `agent.message` | claude-code / codex | role, content (verbose only) |

---

## Component 2: CLI Logger Module

**File:** `src/modules/logger.ts`

### API

```typescript
class Logger {
  static init(outputDir: string, opts: { verbose: boolean; runId?: string }): Logger;
  log(eventType: string, opts?: { stage?: string; payload?: Record<string, unknown> }): void;
  time<T>(eventType: string, stage: string, fn: () => Promise<T>): Promise<T>;
  close(): void;
}
```

- `init()` — creates/opens `run_log.jsonl` in outputDir, generates run_id if not provided
- `log()` — appends one JSONL line with timestamp, run_id, source='cli'
- `time()` — wraps an async function, logs `stage.start` before and `stage.end` after with duration_ms
- `close()` — flushes write stream

### Integration Points

1. **`pipeline.ts`** — `pipeline.start`, `pipeline.end`, `gate.result`, `stage.start/end`
2. **`tools/exec.ts`** — `tool.exec` for every shell command (raw stdout/stderr always included)
3. **`providers/claude.ts` + `openai.ts`** — `llm.request` + `llm.response` (verbose controls prompt/response inclusion)
4. **`modules/crash-triage.ts`** — `crash.found`
5. **`pipeline.ts` exploit section** — `exploit.attempt`, `hypothesis.result`

### Threading

Logger instance is added to `PipelineOpts` and passed down. Tool wrappers get it via an optional parameter on `exec()`. Provider implementations get it via constructor.

### Config Extension

New field in `Config`:

```typescript
log: {
  enabled: boolean;    // default true
  verbose: boolean;    // default false
}
```

CLI flags: `--no-log` to disable, `--verbose-log` for full LLM content.

---

## Component 3: Claude Code Hook

**File:** `hooks/log-tool-use.sh`

A shell script called by Claude Code after every tool use via the hooks system.

### Behavior

1. Reads tool use context from stdin (JSON from Claude Code hook API)
2. Wraps it in LogEvent schema with `source: "claude-code"`, `event_type: "agent.tool_use"`
3. Uses session ID as `run_id`
4. Appends to `$AGENT_FUZZ_OUTPUT/run_log.jsonl` (env var, defaults to `$PWD/output`)

### Configuration

Added to `.claude/settings.local.json`:

```json
{
  "hooks": {
    "post-tool-use": [{
      "command": "hooks/log-tool-use.sh",
      "match": "*"
    }]
  }
}
```

### Captures

- Every Bash command Claude Code runs (checksec, GDB, ROPgadget, etc.)
- Every file read/write
- Tool inputs and outputs

### Does Not Capture

- Claude Code's internal reasoning (not exposed to hooks)
- User messages (not exposed to hooks)

---

## Component 4: Codex Wrapper

**File:** `hooks/codex-wrapper.sh`

A shell wrapper around the Codex CLI that captures its log output.

### Usage

```bash
./hooks/codex-wrapper.sh "exploit this binary"
```

### Behavior

1. Generates a `run_id` (UUID)
2. Logs `pipeline.start` event with `source: "codex"`
3. Runs `codex` with provided arguments, tees stdout
4. Parses Codex's log output from `~/.codex/logs/` (most recent session)
5. Extracts tool calls (shell commands, file writes) and converts to `agent.tool_use` events
6. Appends all events to `output/run_log.jsonl`
7. Logs `pipeline.end` event

### Brittleness Note

Codex's log format is not a stable API. This parser may need updating when Codex updates. The wrapper isolates this risk to one file.

---

## Component 5: Training Data Extraction

**File:** `src/tools/log-extract.ts`
**CLI subcommand:** `agent-fuzz extract-training`

### Usage

```bash
# Fine-tuning pairs
agent-fuzz extract-training output/run_log.jsonl --format openai

# RAG knowledge base
agent-fuzz extract-training output/run_log.jsonl --format rag

# Aggregate metrics
agent-fuzz extract-training output/*/run_log.jsonl --format metrics
```

### Export Formats

1. **`openai`** — JSONL in OpenAI fine-tuning format: `{ messages: [{ role, content }] }` pairs extracted from `llm.request` + `llm.response` events. Includes system prompt, user content, and assistant response.

2. **`rag`** — JSONL chunks for vector store: each confirmed hypothesis becomes a document with binary metadata, vulnerability details, and the exploit that worked. Useful for "given a similar binary, what worked before?"

3. **`metrics`** — Summary JSON: success rate, avg tokens per stage, avg duration per stage, most common vuln classes, exploit success rate by protection profile. For benchmarking.

No new dependencies — reads JSONL, transforms, writes JSONL/JSON.

---

## Assumptions

- Claude Code hook API provides tool_name, input, output as JSON on stdin
- Codex logs to `~/.codex/logs/` with parseable session files
- JSONL files can grow to hundreds of MB for batch runs — no rotation needed (one file per run)

## Non-Goals

- Real-time log streaming or dashboards
- Log rotation or compression
- Remote log shipping
- Capturing full agent conversation/reasoning (hook APIs don't expose this)
