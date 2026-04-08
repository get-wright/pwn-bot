import { describe, it, expect } from 'vitest';
import { createProvider } from '../../src/providers/factory.js';

describe('createProvider', () => {
  it('creates a claude provider', () => {
    const provider = createProvider({ provider: 'claude', model: 'claude-3-5-sonnet-20241022', apiKey: 'sk-ant-test' });
    expect(provider.name).toBe('claude');
  });

  it('creates an openai provider', () => {
    const provider = createProvider({ provider: 'openai', model: 'gpt-4o', apiKey: 'sk-openai-test' });
    expect(provider.name).toBe('openai');
  });

  it('throws on missing API key', () => {
    expect(() => createProvider({ provider: 'claude', model: 'claude-3-5-sonnet-20241022' })).toThrow(
      'API key required for claude provider',
    );
  });
});
