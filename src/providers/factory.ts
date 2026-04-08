import { ClaudeProvider } from './claude.js';
import { OpenAIProvider } from './openai.js';
import type { LLMProvider } from './interface.js';

export interface ProviderConfig {
  provider: 'claude' | 'openai';
  model: string;
  apiKey?: string;
}

export function createProvider(config: ProviderConfig): LLMProvider {
  if (!config.apiKey) {
    throw new Error(`API key required for ${config.provider} provider`);
  }
  switch (config.provider) {
    case 'claude':
      return new ClaudeProvider(config.apiKey, config.model);
    case 'openai':
      return new OpenAIProvider(config.apiKey, config.model);
  }
}
