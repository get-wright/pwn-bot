export interface Config {
  provider: 'claude' | 'openai';
  model: string;
  apiKey?: string;
  fuzz: {
    timeout: number;
    stalledTimeout: number;
  };
  exploit: {
    maxRetries: number;
    testTimeout: number;
  };
  parallel: number;
  outputDir: string;
  log: {
    enabled: boolean;
    verbose: boolean;
  };
}

export interface ConfigOverrides {
  provider?: 'claude' | 'openai';
  model?: string;
  apiKey?: string;
  fuzzTimeout?: number;
  stalledTimeout?: number;
  maxRetries?: number;
  testTimeout?: number;
  parallel?: number;
  outputDir?: string;
  logEnabled?: boolean;
  logVerbose?: boolean;
}

const DEFAULT_MODELS: Record<'claude' | 'openai', string> = {
  claude: 'claude-sonnet-4-6',
  openai: 'codex-mini-latest',
};

export const DEFAULT_CONFIG: Config = {
  provider: 'claude',
  model: DEFAULT_MODELS['claude'],
  fuzz: {
    timeout: 600,
    stalledTimeout: 120,
  },
  exploit: {
    maxRetries: 5,
    testTimeout: 10000,
  },
  parallel: 4,
  outputDir: './output',
  log: {
    enabled: true,
    verbose: false,
  },
};

export function resolveConfig(overrides: ConfigOverrides = {}): Config {
  const provider: 'claude' | 'openai' =
    overrides.provider ??
    (process.env['AGENT_FUZZ_PROVIDER'] as 'claude' | 'openai' | undefined) ??
    DEFAULT_CONFIG.provider;

  const apiKey =
    overrides.apiKey ??
    (provider === 'claude'
      ? process.env['ANTHROPIC_API_KEY']
      : process.env['OPENAI_API_KEY']);

  const model = overrides.model ?? DEFAULT_MODELS[provider];

  return {
    provider,
    model,
    ...(apiKey !== undefined ? { apiKey } : {}),
    fuzz: {
      timeout: overrides.fuzzTimeout ?? DEFAULT_CONFIG.fuzz.timeout,
      stalledTimeout: overrides.stalledTimeout ?? DEFAULT_CONFIG.fuzz.stalledTimeout,
    },
    exploit: {
      maxRetries: overrides.maxRetries ?? DEFAULT_CONFIG.exploit.maxRetries,
      testTimeout: overrides.testTimeout ?? DEFAULT_CONFIG.exploit.testTimeout,
    },
    parallel: overrides.parallel ?? DEFAULT_CONFIG.parallel,
    outputDir: overrides.outputDir ?? DEFAULT_CONFIG.outputDir,
    log: {
      enabled: overrides.logEnabled ?? DEFAULT_CONFIG.log.enabled,
      verbose: overrides.logVerbose ?? DEFAULT_CONFIG.log.verbose,
    },
  };
}
