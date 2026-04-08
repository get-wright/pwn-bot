# agent-fuzz: AI-Powered Binary Exploitation Pipeline

**Date:** 2026-04-08
**Status:** Design approved, pending implementation

## Goal

Build a hybrid system of Claude Code skills (interactive) + TypeScript CLI (automated) that hunts vulnerabilities and generates fuzz harnesses for C/C++ binaries, targeting CTF pwn challenges. Outputs working pwntools exploit scripts.

## Context & Inspiration

- **Anthropic Mythos Preview** — agentic scaffold that reads source, hypothesizes vulnerabilities, confirms with debugging, generates exploits. Found zero-days in every major OS/browser.
- **Google OSS-Fuzz-Gen** — LLM-generated fuzz harnesses for C/C++ projects. 30 confirmed CVEs, 29% coverage increase over human-written targets.
- **PwnGPT (ACL 2025)** — three-module pipeline (analysis, generation, verification) boosted exploit generation from 26% to 58%. Structured decomposition is the key insight.
- **Google Big Sleep** — variant analysis with debugger access. Found SQLite zero-day that 150 CPU-hours of AFL missed.

## Design Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Architecture | PwnGPT-style modular pipeline | Only approach proven to beat raw LLMs at pwn |
| LLM coupling | Provider abstraction (Claude + OpenAI) | Works in Claude Code and Codex |
| Inter-stage validation | Verification gates | Prevents hallucinated exploits from cascading |
| Fuzz + hunt relationship | Flexible (user picks mode or full scan) | Different targets need different approaches |
| Target input | Any (binary, source, remote, combo) | CTF challenges come in all forms |
| Output | Working pwntools exploit script | CTF-focused deliverable |
| Tool availability | Full CTF setup assumed (GDB, pwntools, AFL++, etc.) | User's environment |

## Architecture Overview

```
                     User Entry Points
  /pwn <binary>    /fuzz <target>    /pwn-hunter <binary>
                   /pwn-full <any>
                        |
           +------------+------------+
           |            |            |
           v            v            v
    +-----------+ +------------+ +-----------+
    |   Recon   | |   Hunter   | |  Exploit  |
    |   Skill   | |   Skill    | |   Skill   |
    +-----------+ +------------+ +-----------+
           |            |            |
           +-----+------+------+-----+
                 |             |
                 v             v
          +------------+ +-----------+
          | Verification| | Artifacts |
          |   Gates    | |           |
          +------------+ +-----------+
                 |
                 v
          +--------------+
          |    agent-fuzz |
          |  TS CLI Tool  |
          +--------------+
```

Four components:

1. **Three Claude Code skills** (`recon`, `hunter`, `exploit`) — each focused on one pipeline stage. Invoked interactively or chained by the orchestrator.
2. **TS orchestrator CLI** (`agent-fuzz`) — drives the automated pipeline: spawns AFL++, manages crashes, invokes LLM API for analysis, coordinates parallel runs.
3. **Verification gates** — between each stage, output is validated programmatically before proceeding.
4. **Artifact directory** — structured output per target.

---

## Component 1: Recon Skill (`pwn-recon`)

**Trigger:** `/pwn-recon <target>` or invoked by orchestrator
**Input:** Binary path, optionally source dir, libc, remote host:port

### Steps (in order)

1. **Identify target type** — detect what was handed in (ELF, source dir, remote service, combination). If only remote, attempt to download binary if challenge provides one.

2. **Binary analysis:**
   - `file` — arch, linking, stripped?
   - `checksec` — NX, canary, PIE, RELRO, Fortify
   - `readelf -s` / `nm` — exported symbols, interesting functions (`system`, `execve`, `win`, `flag`, custom)
   - `strings` — embedded paths, format strings, flag patterns, libc version hints

3. **Libc identification** (if provided or inferrable):
   - `libc-database` lookup or parse libc version string
   - Key offsets: `system`, `/bin/sh`, `__free_hook`, `__malloc_hook`, `one_gadget` results

4. **Decompilation:**
   - Headless Ghidra decompile of all functions
   - Output as structured pseudo-C per function

5. **Function ranking** (Mythos-style, 1-5):
   - **5:** Direct user input handling (`read`, `gets`, `scanf`, `recv`), custom allocators, parsing logic
   - **4:** Memory management, string operations, format string usage
   - **3:** Control flow logic, authentication, state machines
   - **2:** Initialization, configuration, utility functions
   - **1:** Dead code, unreachable paths, constants

6. **Protection assessment** — based on checksec, determine viable exploit strategies:
   - No NX -> shellcode injection
   - No canary -> direct stack overflow
   - No PIE -> known addresses, no leak needed
   - Partial RELRO -> GOT overwrite
   - Identify what leaks are needed

### Output: `recon.json`

```json
{
  "target": { "path": "", "arch": "", "bits": 0, "endian": "", "stripped": false },
  "protections": { "nx": true, "canary": false, "pie": false, "relro": "partial", "fortify": false },
  "symbols": [],
  "libc": { "version": "", "offsets": {}, "one_gadgets": [] },
  "functions": [{ "name": "", "decompiled": "", "rank": 5, "notes": "" }],
  "viable_strategies": ["ret2libc", "rop"],
  "leaks_needed": ["libc_base"]
}
```

### Verification Gate

Output must contain valid JSON, all required fields populated, at least one function ranked 4-5 (or explicit "no obvious targets found" with reasoning).

---

## Component 2: Hunter Skill (`pwn-hunter`)

**Trigger:** `/pwn-hunter <target>` (runs recon first if no `recon.json`) or invoked by orchestrator
**Input:** `recon.json` + binary + optionally source

Processes functions in rank order (5->1), stops when a confirmed vulnerability is found or budget exhausted.

### Phase A: Hypothesis Generation

For each function ranked 4-5, generate structured vulnerability hypotheses:

- **What class?** — stack overflow, heap corruption, format string, integer overflow, UAF, etc.
- **Where exactly?** — line, variable, buffer
- **What's the trigger?** — what input reaches this path
- **What's the primitive?** — arbitrary write, controlled RIP, info leak
- **What constraints?** — bad bytes, length limits, alignment

### Phase B: Confirmation via Debugging

For each hypothesis:

1. **Craft minimal trigger input**
2. **Run under GDB** with breakpoints at suspected location:
   - Does execution reach the vulnerable code?
   - Does the overflow/format string/UAF actually occur?
   - What registers/memory are controlled?
3. **Run under ASan** (if source available, recompile with `-fsanitize=address`):
   - Confirms memory corruption with exact location and type
4. **Crash triage** — classify exploitability, capture context (registers, backtrace, memory map)

Hypothesis status: `confirmed`, `rejected`, `partial`

### Phase C: Targeted Fuzz Harness Generation

For confirmed or suspected vulns, generate AFL++ harnesses:

1. **AFL++ persistent mode harness** — C file using `__AFL_FUZZ_INIT()`, `__AFL_FUZZ_TESTCASE_BUF`, `__AFL_LOOP()` macros
2. **Dictionary file** — extracted constants, magic values
3. **Seed corpus** — minimal inputs from the GDB confirmation step

Includes fallback macros for compilation without AFL++ (testing without fuzzer).

Compiled via: `afl-clang-fast -fsanitize=address -o fuzz_target harness.c`

### Phase D: Source Audit (if source available)

Pattern-scan for:
- `gets(`, `sprintf(` without bounds, `strcpy(` without length check
- `malloc`/`free` patterns suggesting UAF or double-free
- Integer arithmetic without overflow checks near allocation sizes
- Format strings with user-controlled arguments
- Off-by-one in loop bounds near buffer operations

### Output: `hunter.json`

```json
{
  "hypotheses": [{
    "function": "",
    "vuln_class": "stack_overflow",
    "location": "",
    "trigger": "",
    "primitive": "controlled_rip",
    "constraints": { "bad_bytes": [], "max_length": null, "alignment": null },
    "status": "confirmed",
    "gdb_evidence": { "registers": {}, "backtrace": [], "controlled_bytes": 0 },
    "asan_report": ""
  }],
  "confirmed_vulns": [],
  "harnesses": [{ "path": "", "target_function": "", "strategy": "" }],
  "source_findings": []
}
```

### Verification Gate

At least one hypothesis must be `confirmed` with GDB/ASan evidence to advance to exploit stage. If none confirmed, output is valid but pipeline doesn't proceed.

---

## Component 3: Exploit Skill (`pwn-exploit`)

**Trigger:** `/pwn-exploit <target>` (runs recon+hunter first if needed) or invoked by orchestrator
**Input:** `recon.json` + `hunter.json` + binary + optionally remote host:port

### Phase A: Strategy Selection

Based on confirmed vulnerability primitive + protection profile:

| Primitive | No PIE | PIE | Canary | Full RELRO |
|-----------|--------|-----|--------|------------|
| Stack overflow (controlled RIP) | ret2win / ret2libc / ROP | Leak PIE first, then ROP | Leak canary first | ROP to exec, skip GOT |
| Format string (arb read+write) | Leak + GOT overwrite | Leak PIE + GOT | Leak canary, then overflow | Overwrite return addr |
| Heap UAF/corruption | tcache poison -> `__free_hook` | Leak heap + PIE | N/A (heap-based) | tcache poison -> return addr |
| Info leak only | Chain with another vuln | Enables PIE bypass | Enables canary bypass | Enables further attacks |

Picks the simplest viable strategy.

### Phase B: Exploit Construction

Generates a pwntools script using:

- `context.binary = ELF('./binary')` for binary loading
- `cyclic()` / `cyclic_find()` for offset calculation
- `ROP(binary)` / `ROP([binary, libc])` for chain building
- `rop.call('puts', [elf.got['puts']])` for GOT leaks
- `remote()` / `process()` for target connection
- `gdb.attach()` for debug mode

Script structure:
1. Config (ELF, libc, remote settings)
2. `conn()` helper with LOCAL/REMOTE/GDB modes
3. Stage 1: Leak (if protections require it)
4. Stage 2: Payload (ROP chain or raw)
5. Stage 3: `io.interactive()` for shell

### Phase C: Local Verification

1. Run exploit against local binary — must get shell or read flag
2. If fails: debug loop (GDB attach, compare expected vs actual, adjust offsets/gadgets/alignment, max 5 iterations)
3. If succeeds: capture proof

### Phase D: Remote Adaptation (if remote target)

1. Try local exploit as-is
2. If libc mismatch: fingerprint remote libc (last 3 nibbles), query libc-database, recalculate offsets
3. If environment difference: adjust stack alignment (extra `ret` gadget), try alternative one_gadget constraints
4. Max 3 adaptation iterations

### Output

```
output/
  recon.json
  hunter.json
  harnesses/
    fuzz_vulnerable_func.c
  crashes/            # from AFL++ if fuzzer was used
  exploit.py          # working pwntools script
  proof.txt           # shell output / flag
```

### Verification Gate

`exploit.py` must produce a shell or read a flag against the local binary. Run the exploit, check for `$` prompt or flag pattern in output. No "should work" — concrete test.

---

## Component 4: TS Orchestrator (`agent-fuzz`)

### CLI Interface

```bash
# Full pipeline
agent-fuzz pwn ./binary
agent-fuzz pwn ./binary --libc ./libc.so.6 --remote host:1337

# Individual modes
agent-fuzz recon ./binary
agent-fuzz hunt ./binary --source ./src/
agent-fuzz fuzz ./binary                    # AFL++ only
agent-fuzz exploit ./binary --hunter-output ./hunter.json

# Batch
agent-fuzz batch ./challenges/ --parallel 4

# Full scan — fuzz + hunt in parallel, merge results
agent-fuzz full ./binary --source ./src/ --timeout 30m

# Provider selection
agent-fuzz pwn ./binary --provider openai --model codex-mini-latest
```

### Directory Structure

```
agent-fuzz/
  src/
    cli.ts              # arg parsing, mode routing
    pipeline.ts         # orchestrates recon -> hunt -> exploit
    providers/
      interface.ts      # LLMProvider interface + LLMResponse type
      claude.ts         # Anthropic SDK (@anthropic-ai/sdk)
      openai.ts         # OpenAI SDK (openai)
      factory.ts        # provider factory from config/env
    modules/
      recon.ts          # runs checksec, file, ghidra, builds recon.json
      fuzzer.ts         # AFL++ lifecycle: compile, run, collect crashes
      crash-triage.ts   # dedup, classify, extract backtraces
      llm.ts            # routes through provider interface
      exploit-test.ts   # run exploit.py, check for shell/flag
    tools/
      checksec.ts       # parse checksec output
      ghidra.ts         # headless ghidra decompilation
      gdb.ts            # scripted gdb sessions
      ropgadget.ts      # gadget extraction + parsing
      one-gadget.ts     # one_gadget invocation + constraint parsing
      pwntools.ts       # generate + run pwntools scripts
      angr.ts           # symbolic execution for constraint solving
    types.ts            # Zod schemas (ReconOutput, HunterOutput, etc.)
    config.ts           # provider config, model selection, tool paths
  templates/
    harness.c.hbs       # AFL++ harness (persistent mode with fallback macros)
    exploit.py.hbs      # pwntools exploit
    prompts/
      recon.md          # LLM prompt for recon analysis
      hunter.md         # LLM prompt for vuln hypothesis
      exploit.md        # LLM prompt for exploit generation
      triage.md         # LLM prompt for crash triage
  package.json
  tsconfig.json
  tests/
    fixtures/           # test binaries (stack overflow, format string, heap)
    *.test.ts
```

### LLM Provider Interface

```typescript
interface LLMProvider {
  name: 'claude' | 'openai';

  analyze<T extends z.ZodType>(opts: {
    system: string;
    userContent: string;
    schema: T;
    maxTokens?: number;
  }): Promise<{ parsed: z.infer<T>; usage: TokenUsage }>;

  runWithTools(opts: {
    system: string;
    userContent: string;
    tools: ToolDef[];
    maxIterations?: number;
  }): Promise<{ content: string; toolResults: ToolResult[]; usage: TokenUsage }>;
}
```

**Claude provider:** `messages.parse()` + `zodOutputFormat()` for structured output. `toolRunner()` + `betaZodTool()` for agentic tool loops.

**OpenAI provider:** `chat.completions.parse()` + `zodResponseFormat()` for structured output. `runTools()` + `zodFunction()` for agentic tool loops.

Both use Zod schemas defined in `types.ts` — shared across providers.

### AFL++ Management (`fuzzer.ts`)

- Compile harness with `afl-clang-fast -fsanitize=address`
- Run `afl-fuzz` with configurable timeout (default 10min)
- Monitor `fuzzer_stats` — stop early if no new paths for 2 minutes
- Collect unique crashes from output/crashes/

### Crash Triage (`crash-triage.ts`)

- Dedup by backtrace similarity (stack hash)
- Each unique crash: run under GDB for registers + backtrace
- Classify exploitability: controlled RIP = high, controlled write = high, null deref = low, canary fail = medium
- Feed to LLM with `triage.md` prompt for detailed analysis

### Full Scan Mode (fuzz + hunt in parallel)

```
               +-- fuzzer.ts (AFL++) --> crash-triage.ts --+
target -> recon|                                           |--> merge --> exploit
               +-- LLM (hunter prompt) -------------------+
```

Both paths produce vulnerability candidates. Merge deduplicates by location (function name + offset within function), prefers stronger evidence (ASan crash > hypothesis-only > pattern-match).

### Verification Gates

| Gate | Check | Fail action |
|------|-------|-------------|
| Recon -> Hunt | `recon.json` parses, has `functions[]` with entries | Abort: "no analyzable functions" |
| Hunt -> Exploit | >= 1 `confirmed` hypothesis with evidence | Report findings, skip exploit gen |
| Exploit -> Done | `exploit.py` produces shell/flag in 10s | Debug loop (max 5), then report partial |
| Fuzz -> Triage | >= 1 unique crash | Report "no crashes in {timeout}" |

### Config Resolution

CLI flags -> env vars -> `agent-fuzz.config.json` -> defaults

```typescript
interface Config {
  provider: 'claude' | 'openai';
  model: string;
  apiKey?: string;            // ANTHROPIC_API_KEY or OPENAI_API_KEY
  fuzz: {
    timeout: number;          // AFL++ timeout seconds (default 600)
    stalledTimeout: number;   // no new paths timeout (default 120)
  };
  exploit: {
    maxRetries: number;       // debug loop iterations (default 5)
    testTimeout: number;      // exploit run timeout (default 10s)
  };
  parallel: number;           // batch workers (default 4)
  outputDir: string;          // default: ./output
}
```

---

## Component 5: CLI Agent Integration

### Claude Code Skills

Five skill files installed as a Claude Code plugin:

| Skill | Command | Behavior |
|-------|---------|----------|
| `pwn-recon.md` | `/pwn-recon <binary>` | Interactive recon — Claude Code runs tools, presents findings |
| `pwn-hunter.md` | `/pwn-hunter <binary>` | Interactive hunt — Claude Code hypothesizes, debugs, confirms |
| `pwn-exploit.md` | `/pwn-exploit <binary>` | Interactive exploit gen — Claude Code builds + tests pwntools script |
| `pwn.md` | `/pwn <binary>` | Automated — delegates to `agent-fuzz pwn` subprocess |
| `fuzz.md` | `/fuzz <binary>` | Automated — delegates to `agent-fuzz fuzz` subprocess |

Interactive skills guide Claude Code step-by-step through each tool. Automated skills run the TS orchestrator and stream output.

### Codex — AGENTS.md

For Codex, an `AGENTS.md` in the project root instructs the agent on available `agent-fuzz` commands and how to use the local tools directly. `--provider openai` is the default.

### Installation

```bash
# TS orchestrator
npm install -g agent-fuzz

# Claude Code skills
claude plugins install agent-fuzz-skills

# Codex — just needs agent-fuzz on PATH + AGENTS.md in project
```

---

## Shared Zod Schemas (key types)

```typescript
const ReconOutputSchema = z.object({
  target: z.object({
    path: z.string(),
    arch: z.enum(['amd64', 'i386', 'arm', 'aarch64', 'mips']),
    bits: z.number(),
    endian: z.enum(['little', 'big']),
    stripped: z.boolean(),
  }),
  protections: z.object({
    nx: z.boolean(),
    canary: z.boolean(),
    pie: z.boolean(),
    relro: z.enum(['no', 'partial', 'full']),
    fortify: z.boolean(),
  }),
  functions: z.array(z.object({
    name: z.string(),
    decompiled: z.string(),
    rank: z.number().min(1).max(5),
    notes: z.string(),
  })),
  viable_strategies: z.array(z.string()),
  leaks_needed: z.array(z.string()),
  libc: z.object({
    version: z.string(),
    offsets: z.record(z.number()),
    one_gadgets: z.array(z.object({
      address: z.number(),
      constraints: z.array(z.string()),
    })),
  }).optional(),
});

const HypothesisSchema = z.object({
  function: z.string(),
  vuln_class: z.enum([
    'stack_overflow', 'heap_uaf', 'heap_overflow', 'double_free',
    'format_string', 'integer_overflow', 'type_confusion', 'race_condition',
  ]),
  location: z.string(),
  trigger: z.string(),
  primitive: z.enum([
    'controlled_rip', 'arbitrary_write', 'arbitrary_read',
    'info_leak', 'dos', 'partial_overwrite',
  ]),
  constraints: z.object({
    bad_bytes: z.array(z.string()),
    max_length: z.number().optional(),
    alignment: z.number().optional(),
  }),
  status: z.enum(['confirmed', 'rejected', 'partial', 'pending']),
  gdb_evidence: z.object({
    registers: z.record(z.string()),
    backtrace: z.array(z.string()),
    controlled_bytes: z.number(),
  }).optional(),
  asan_report: z.string().optional(),
});
```

---

## Assumptions

- Full CTF toolchain is installed: GDB + pwndbg/GEF, pwntools, checksec, ROPgadget, one_gadget, Ghidra (headless), AFL++, angr, Docker
- Claude API key or OpenAI API key is available
- Target binaries are Linux ELF (primary focus: x86_64, with i386 support)
- User has basic CTF pwn knowledge (can evaluate exploit output)

## Non-Goals

- Windows PE binary support
- Web application fuzzing
- Mobile binary analysis
- Automated CTF platform integration (flag submission)
- GUI / web dashboard

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| LLM hallucinates exploit that doesn't work | Verification gates — every stage must produce concrete evidence |
| AFL++ runs too long on complex targets | Configurable timeout + stalled-path early termination |
| Ghidra decompilation fails on stripped/obfuscated binaries | Fall back to objdump disassembly + LLM analysis of assembly |
| Remote libc mismatch breaks exploit | Fingerprinting + libc-database lookup + adaptation loop |
| Provider API differences cause subtle bugs | Shared Zod schemas enforce identical input/output contracts |
