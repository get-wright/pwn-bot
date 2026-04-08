import type { z } from 'zod';
import type { TokenUsage, ToolDef, ToolResult } from '../types.js';

export interface AnalyzeOpts<T extends z.ZodType> {
  system: string;
  userContent: string;
  schema: T;
  maxTokens?: number;
}

export interface RunWithToolsOpts {
  system: string;
  userContent: string;
  tools: ToolDef[];
  maxIterations?: number;
  maxTokens?: number;
}

export interface LLMProvider {
  name: 'claude' | 'openai';
  analyze<T extends z.ZodType>(opts: AnalyzeOpts<T>): Promise<{ parsed: z.infer<T>; usage: TokenUsage }>;
  runWithTools(opts: RunWithToolsOpts): Promise<{ content: string; toolResults: ToolResult[]; usage: TokenUsage }>;
}
