import Anthropic from '@anthropic-ai/sdk';
import type { z } from 'zod';
import type { TokenUsage, ToolDef, ToolResult } from '../types.js';
import type { LLMProvider, AnalyzeOpts, RunWithToolsOpts } from './interface.js';
import type { Logger } from '../modules/logger.js';

function zodToInputSchema(schema: z.ZodType): Anthropic.Tool.InputSchema {
  const def = (schema as unknown as { _def: { typeName: string } })._def;
  if (def.typeName === 'ZodObject') {
    const shape = (schema as unknown as { shape: Record<string, z.ZodType> }).shape;
    const properties: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(shape)) {
      properties[key] = zodToInputSchema(val);
    }
    return { type: 'object', properties };
  }
  if (def.typeName === 'ZodString') return { type: 'object' } as unknown as Anthropic.Tool.InputSchema;
  if (def.typeName === 'ZodNumber') return { type: 'object' } as unknown as Anthropic.Tool.InputSchema;
  if (def.typeName === 'ZodBoolean') return { type: 'object' } as unknown as Anthropic.Tool.InputSchema;
  return { type: 'object' };
}

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
        ...(this.logger.verbose ? { system_prompt: opts.system, user_content: opts.userContent } : {}),
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

    const usage = { inputTokens: message.usage.input_tokens, outputTokens: message.usage.output_tokens };

    this.logger?.log('llm.response', {
      payload: {
        provider: 'claude',
        usage,
        ...(this.logger.verbose ? { raw_response: text } : {}),
        parsed_output: result.data,
      },
    });

    return {
      parsed: result.data as z.infer<T>,
      usage,
    };
  }

  async runWithTools(opts: RunWithToolsOpts): Promise<{ content: string; toolResults: ToolResult[]; usage: TokenUsage }> {
    const maxIterations = opts.maxIterations ?? 10;
    const tools: Anthropic.Tool[] = opts.tools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: zodToInputSchema(t.schema),
    }));

    type AnthropicMessage = Anthropic.MessageParam;
    const messages: AnthropicMessage[] = [{ role: 'user', content: opts.userContent }];
    const allToolResults: ToolResult[] = [];
    let totalInput = 0;
    let totalOutput = 0;

    this.logger?.log('llm.request', {
      payload: {
        provider: 'claude',
        model: this.model,
        ...(this.logger.verbose ? { system_prompt: opts.system, user_content: opts.userContent } : {}),
        max_tokens: opts.maxTokens ?? 4096,
      },
    });

    for (let i = 0; i < maxIterations; i++) {
      const response = await this.client.messages.create({
        model: this.model,
        max_tokens: opts.maxTokens ?? 4096,
        system: opts.system,
        tools,
        messages,
      });

      totalInput += response.usage.input_tokens;
      totalOutput += response.usage.output_tokens;

      this.logger?.log('llm.response', {
        payload: {
          provider: 'claude',
          usage: { inputTokens: response.usage.input_tokens, outputTokens: response.usage.output_tokens },
          ...(this.logger.verbose ? { raw_response: response.content } : {}),
        },
      });

      const toolUseBlocks = response.content.filter((b) => b.type === 'tool_use') as Anthropic.ToolUseBlock[];

      if (response.stop_reason !== 'tool_use' || toolUseBlocks.length === 0) {
        const text = response.content
          .filter((b) => b.type === 'text')
          .map((b) => (b as Anthropic.TextBlock).text)
          .join('');
        return {
          content: text,
          toolResults: allToolResults,
          usage: { inputTokens: totalInput, outputTokens: totalOutput },
        };
      }

      messages.push({ role: 'assistant', content: response.content });

      const toolResultContent: Anthropic.ToolResultBlockParam[] = [];
      for (const block of toolUseBlocks) {
        const toolDef = opts.tools.find((t) => t.name === block.name);
        const output = toolDef
          ? await toolDef.execute(block.input)
          : `Unknown tool: ${block.name}`;

        allToolResults.push({ name: block.name, input: block.input, output });
        toolResultContent.push({ type: 'tool_result', tool_use_id: block.id, content: output });
      }

      messages.push({ role: 'user', content: toolResultContent });
    }

    return {
      content: '',
      toolResults: allToolResults,
      usage: { inputTokens: totalInput, outputTokens: totalOutput },
    };
  }
}
