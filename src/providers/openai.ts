import OpenAI from 'openai';
import { zodResponseFormat } from 'openai/helpers/zod';
import type { z } from 'zod';
import type { TokenUsage, ToolDef, ToolResult } from '../types.js';
import type { LLMProvider, AnalyzeOpts, RunWithToolsOpts } from './interface.js';

function zodToFunctionParameters(schema: z.ZodType): Record<string, unknown> {
  const def = (schema as unknown as { _def: { typeName: string } })._def;
  if (def.typeName === 'ZodObject') {
    const shape = (schema as unknown as { shape: Record<string, z.ZodType> }).shape;
    const properties: Record<string, unknown> = {};
    const required: string[] = [];
    for (const [key, val] of Object.entries(shape)) {
      properties[key] = zodToFunctionParameters(val);
      required.push(key);
    }
    return { type: 'object', properties, required };
  }
  if (def.typeName === 'ZodString') return { type: 'string' };
  if (def.typeName === 'ZodNumber') return { type: 'number' };
  if (def.typeName === 'ZodBoolean') return { type: 'boolean' };
  if (def.typeName === 'ZodArray') {
    const itemDef = (def as unknown as { type: z.ZodType }).type;
    return { type: 'array', items: zodToFunctionParameters(itemDef) };
  }
  return { type: 'object' };
}

export class OpenAIProvider implements LLMProvider {
  readonly name = 'openai' as const;
  private client: OpenAI;
  private model: string;

  constructor(apiKey: string, model: string) {
    this.client = new OpenAI({ apiKey });
    this.model = model;
  }

  async analyze<T extends z.ZodType>(opts: AnalyzeOpts<T>): Promise<{ parsed: z.infer<T>; usage: TokenUsage }> {
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

    const usage = completion.usage;
    return {
      parsed: message.parsed as z.infer<T>,
      usage: {
        inputTokens: usage?.prompt_tokens ?? 0,
        outputTokens: usage?.completion_tokens ?? 0,
      },
    };
  }

  async runWithTools(opts: RunWithToolsOpts): Promise<{ content: string; toolResults: ToolResult[]; usage: TokenUsage }> {
    const maxIterations = opts.maxIterations ?? 10;
    const tools: OpenAI.Chat.Completions.ChatCompletionTool[] = opts.tools.map((t) => ({
      type: 'function' as const,
      function: {
        name: t.name,
        description: t.description,
        parameters: zodToFunctionParameters(t.schema),
      },
    }));

    type MessageParam = OpenAI.Chat.Completions.ChatCompletionMessageParam;
    const messages: MessageParam[] = [
      { role: 'system', content: opts.system },
      { role: 'user', content: opts.userContent },
    ];
    const allToolResults: ToolResult[] = [];
    let totalInput = 0;
    let totalOutput = 0;

    for (let i = 0; i < maxIterations; i++) {
      const response = await this.client.chat.completions.create({
        model: this.model,
        max_tokens: opts.maxTokens ?? 4096,
        tools,
        messages,
      });

      totalInput += response.usage?.prompt_tokens ?? 0;
      totalOutput += response.usage?.completion_tokens ?? 0;

      const choice = response.choices[0];
      if (!choice) break;

      if (choice.finish_reason !== 'tool_calls' || !choice.message.tool_calls?.length) {
        return {
          content: choice.message.content ?? '',
          toolResults: allToolResults,
          usage: { inputTokens: totalInput, outputTokens: totalOutput },
        };
      }

      messages.push(choice.message);

      for (const toolCall of choice.message.tool_calls) {
        if (toolCall.type !== 'function') continue;
        const toolDef = opts.tools.find((t) => t.name === toolCall.function.name);
        let input: unknown;
        try {
          input = JSON.parse(toolCall.function.arguments);
        } catch {
          input = {};
        }
        const output = toolDef
          ? await toolDef.execute(input)
          : `Unknown tool: ${toolCall.function.name}`;

        allToolResults.push({ name: toolCall.function.name, input, output });
        messages.push({
          role: 'tool',
          tool_call_id: toolCall.id,
          content: output,
        });
      }
    }

    return {
      content: '',
      toolResults: allToolResults,
      usage: { inputTokens: totalInput, outputTokens: totalOutput },
    };
  }
}
