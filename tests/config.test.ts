import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolveConfig, DEFAULT_CONFIG } from '../src/config.js';

describe('resolveConfig', () => {
  let savedEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    savedEnv = { ...process.env };
    delete process.env['AGENT_FUZZ_PROVIDER'];
    delete process.env['ANTHROPIC_API_KEY'];
    delete process.env['OPENAI_API_KEY'];
  });

  afterEach(() => {
    process.env = savedEnv;
  });

  it('returns defaults when no overrides', () => {
    const config = resolveConfig();
    expect(config.provider).toBe('claude');
    expect(config.model).toBe('claude-sonnet-4-6');
    expect(config.fuzz.timeout).toBe(600);
    expect(config.fuzz.stalledTimeout).toBe(120);
    expect(config.exploit.maxRetries).toBe(5);
    expect(config.exploit.testTimeout).toBe(10000);
    expect(config.parallel).toBe(4);
    expect(config.outputDir).toBe('./output');
    expect(config.apiKey).toBeUndefined();
  });

  it('CLI flags override defaults', () => {
    const config = resolveConfig({
      provider: 'openai',
      model: 'gpt-4o',
      fuzzTimeout: 300,
      stalledTimeout: 60,
      maxRetries: 3,
      testTimeout: 5000,
      parallel: 8,
      outputDir: '/tmp/out',
    });
    expect(config.provider).toBe('openai');
    expect(config.model).toBe('gpt-4o');
    expect(config.fuzz.timeout).toBe(300);
    expect(config.fuzz.stalledTimeout).toBe(60);
    expect(config.exploit.maxRetries).toBe(3);
    expect(config.exploit.testTimeout).toBe(5000);
    expect(config.parallel).toBe(8);
    expect(config.outputDir).toBe('/tmp/out');
  });

  it('env vars set API keys (ANTHROPIC_API_KEY for claude)', () => {
    process.env['ANTHROPIC_API_KEY'] = 'sk-ant-test';
    const config = resolveConfig({ provider: 'claude' });
    expect(config.apiKey).toBe('sk-ant-test');
  });

  it('env vars set OpenAI key when provider is openai', () => {
    process.env['OPENAI_API_KEY'] = 'sk-openai-test';
    const config = resolveConfig({ provider: 'openai' });
    expect(config.apiKey).toBe('sk-openai-test');
  });

  it('AGENT_FUZZ_PROVIDER env var sets provider', () => {
    process.env['AGENT_FUZZ_PROVIDER'] = 'openai';
    const config = resolveConfig();
    expect(config.provider).toBe('openai');
  });

  it('CLI flag overrides env var', () => {
    process.env['AGENT_FUZZ_PROVIDER'] = 'openai';
    const config = resolveConfig({ provider: 'claude' });
    expect(config.provider).toBe('claude');
  });

  it('default model depends on provider', () => {
    const claudeConfig = resolveConfig({ provider: 'claude' });
    expect(claudeConfig.model).toBe('claude-sonnet-4-6');

    const openaiConfig = resolveConfig({ provider: 'openai' });
    expect(openaiConfig.model).toBe('codex-mini-latest');
  });
});

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
