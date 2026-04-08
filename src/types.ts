import { z } from 'zod';

// --- Schemas ---

export const TargetInfoSchema = z.object({
  path: z.string(),
  arch: z.enum(['amd64', 'i386', 'arm', 'aarch64', 'mips']),
  bits: z.number(),
  endian: z.enum(['little', 'big']),
  stripped: z.boolean(),
});

export const ProtectionsSchema = z.object({
  nx: z.boolean(),
  canary: z.boolean(),
  pie: z.boolean(),
  relro: z.enum(['no', 'partial', 'full']),
  fortify: z.boolean(),
});

export const FunctionInfoSchema = z.object({
  name: z.string(),
  decompiled: z.string(),
  notes: z.string(),
  rank: z.number().min(1).max(5),
});

export const OneGadgetSchema = z.object({
  address: z.number(),
  constraints: z.array(z.string()),
});

export const LibcInfoSchema = z.object({
  version: z.string(),
  offsets: z.record(z.string(), z.number()),
  one_gadgets: z.array(OneGadgetSchema),
});

export const ReconOutputSchema = z.object({
  target: TargetInfoSchema,
  protections: ProtectionsSchema,
  symbols: z.array(z.string()),
  functions: z.array(FunctionInfoSchema),
  viable_strategies: z.array(z.string()),
  leaks_needed: z.array(z.string()),
  libc: LibcInfoSchema.optional(),
});

export const GdbEvidenceSchema = z.object({
  registers: z.record(z.string(), z.string()),
  backtrace: z.array(z.string()),
  controlled_bytes: z.number(),
});

export const ConstraintsSchema = z.object({
  bad_bytes: z.array(z.string()),
  max_length: z.number().optional(),
  alignment: z.number().optional(),
});

export const HypothesisSchema = z.object({
  function: z.string(),
  location: z.string(),
  trigger: z.string(),
  vuln_class: z.enum([
    'stack_overflow',
    'heap_uaf',
    'heap_overflow',
    'double_free',
    'format_string',
    'integer_overflow',
    'type_confusion',
    'race_condition',
  ]),
  primitive: z.enum([
    'controlled_rip',
    'arbitrary_write',
    'arbitrary_read',
    'info_leak',
    'dos',
    'partial_overwrite',
  ]),
  constraints: ConstraintsSchema,
  status: z.enum(['confirmed', 'rejected', 'partial', 'pending']),
  gdb_evidence: GdbEvidenceSchema.optional(),
  asan_report: z.string().optional(),
});

export const HarnessInfoSchema = z.object({
  path: z.string(),
  target_function: z.string(),
  strategy: z.string(),
});

export const HunterOutputSchema = z.object({
  hypotheses: z.array(HypothesisSchema),
  confirmed_vulns: z.array(HypothesisSchema),
  harnesses: z.array(HarnessInfoSchema),
  source_findings: z.array(z.string()),
});

export const ExploitConfigSchema = z.object({
  binary_path: z.string(),
  recon: ReconOutputSchema,
  hunter: HunterOutputSchema,
  remote: z
    .object({
      host: z.string(),
      port: z.number(),
    })
    .optional(),
  libc_path: z.string().optional(),
});

export const TokenUsageSchema = z.object({
  inputTokens: z.number(),
  outputTokens: z.number(),
});

export const CrashInfoSchema = z.object({
  id: z.string(),
  input_path: z.string(),
  crash_type: z.string(),
  stack_hash: z.string(),
  backtrace: z.array(z.string()),
  registers: z.record(z.string(), z.string()),
  exploitability: z.enum(['high', 'medium', 'low', 'unknown']),
});

export const TriageOutputSchema = z.object({
  unique_crashes: z.array(CrashInfoSchema),
  total_crashes: z.number(),
  deduped_count: z.number(),
});

// --- Inferred types ---

export type TargetInfo = z.infer<typeof TargetInfoSchema>;
export type Protections = z.infer<typeof ProtectionsSchema>;
export type FunctionInfo = z.infer<typeof FunctionInfoSchema>;
export type OneGadget = z.infer<typeof OneGadgetSchema>;
export type LibcInfo = z.infer<typeof LibcInfoSchema>;
export type ReconOutput = z.infer<typeof ReconOutputSchema>;
export type GdbEvidence = z.infer<typeof GdbEvidenceSchema>;
export type Constraints = z.infer<typeof ConstraintsSchema>;
export type Hypothesis = z.infer<typeof HypothesisSchema>;
export type HarnessInfo = z.infer<typeof HarnessInfoSchema>;
export type HunterOutput = z.infer<typeof HunterOutputSchema>;
export type ExploitConfig = z.infer<typeof ExploitConfigSchema>;
export type TokenUsage = z.infer<typeof TokenUsageSchema>;
export type CrashInfo = z.infer<typeof CrashInfoSchema>;
export type TriageOutput = z.infer<typeof TriageOutputSchema>;

// --- Standalone interfaces ---

export interface ToolDef {
  name: string;
  description: string;
  schema: z.ZodType;
  execute: (input: unknown) => Promise<string>;
}

export interface ToolResult {
  name: string;
  input: unknown;
  output: string;
}

export interface LLMResponse<T> {
  parsed: T;
  usage: TokenUsage;
}

export interface LLMToolResponse {
  content: string;
  toolResults: ToolResult[];
  usage: TokenUsage;
}
