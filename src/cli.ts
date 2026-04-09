#!/usr/bin/env node
import { Command } from 'commander';
import { readFileSync, mkdirSync } from 'node:fs';
import { readdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveConfig, type ConfigOverrides } from './config.js';
import { createProvider } from './providers/factory.js';
import { runPipeline, type PipelineOpts } from './pipeline.js';
import { Logger } from './modules/logger.js';
import { extractToFile } from './tools/log-extract.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8')) as {
  version: string;
};

const program = new Command();

program
  .name('agent-fuzz')
  .description('AI-powered binary exploitation pipeline for CTF pwn challenges')
  .version(pkg.version);

function addCommonOpts(cmd: Command): Command {
  return cmd
    .option('--provider <provider>', 'LLM provider (claude|openai)')
    .option('--model <model>', 'model name')
    .option('--libc <path>', 'path to libc')
    .option('--source <dir>', 'source directory')
    .option('--remote <host:port>', 'remote target')
    .option('--output <dir>', 'output directory', './output')
    .option('--fuzz-timeout <seconds>', 'fuzzing timeout in seconds', '600')
    .option('--max-retries <n>', 'max exploit retries', '5')
    .option('--no-log', 'disable logging')
    .option('--verbose-log', 'log full LLM prompts and responses');
}

function parseRemote(str?: string): { host: string; port: number } | undefined {
  if (!str) return undefined;
  const idx = str.lastIndexOf(':');
  if (idx === -1) return undefined;
  return {
    host: str.slice(0, idx),
    port: parseInt(str.slice(idx + 1), 10),
  };
}

interface CommonOpts {
  provider?: string;
  model?: string;
  libc?: string;
  source?: string;
  remote?: string;
  output: string;
  fuzzTimeout: string;
  maxRetries: string;
  log?: boolean;        // commander inverts --no-log to opts.log = false
  verboseLog?: boolean;
}

async function runMode(
  mode: PipelineOpts['mode'],
  binaryPath: string,
  opts: CommonOpts,
): Promise<void> {
  const overrides: ConfigOverrides = {
    provider: opts.provider as 'claude' | 'openai' | undefined,
    model: opts.model,
    fuzzTimeout: parseInt(opts.fuzzTimeout, 10),
    maxRetries: parseInt(opts.maxRetries, 10),
    outputDir: opts.output,
    logEnabled: opts.log !== false,
    logVerbose: opts.verboseLog,
  };

  const config = resolveConfig(overrides);

  mkdirSync(config.outputDir, { recursive: true });
  const logger = config.log.enabled
    ? Logger.init(config.outputDir, { verbose: config.log.verbose ?? false })
    : Logger.noop();

  const provider = createProvider({
    provider: config.provider,
    model: config.model,
    apiKey: config.apiKey,
    logger,
  });

  const result = await runPipeline({
    binaryPath,
    sourceDir: opts.source,
    libcPath: opts.libc,
    remote: parseRemote(opts.remote),
    config,
    provider,
    mode,
    logger,
  });

  console.log(result.message);
  process.exit(result.success ? 0 : 1);
}

addCommonOpts(
  program
    .command('pwn <binary>')
    .description('Full exploitation pipeline'),
).action(async (binary: string, opts: CommonOpts) => {
  await runMode('pwn', binary, opts);
});

addCommonOpts(
  program
    .command('recon <binary>')
    .description('Recon only'),
).action(async (binary: string, opts: CommonOpts) => {
  await runMode('recon', binary, opts);
});

addCommonOpts(
  program
    .command('hunt <binary>')
    .description('Hunt only'),
).action(async (binary: string, opts: CommonOpts) => {
  await runMode('hunt', binary, opts);
});

addCommonOpts(
  program
    .command('fuzz <binary>')
    .description('Fuzz only'),
).action(async (binary: string, opts: CommonOpts) => {
  await runMode('fuzz', binary, opts);
});

addCommonOpts(
  program
    .command('exploit <binary>')
    .description('Exploit from existing analysis'),
).action(async (binary: string, opts: CommonOpts) => {
  await runMode('exploit', binary, opts);
});

addCommonOpts(
  program
    .command('full <binary>')
    .description('Fuzz + hunt in parallel'),
).action(async (binary: string, opts: CommonOpts) => {
  await runMode('full', binary, opts);
});

addCommonOpts(
  program
    .command('batch <dir>')
    .description('Batch process all binaries in a directory'),
).action(async (dir: string, opts: CommonOpts) => {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = entries.filter((e) => e.isFile()).map((e) => e.name);

  if (files.length === 0) {
    console.error('No files found in directory');
    process.exit(1);
  }

  let anyFailed = false;
  for (const file of files) {
    const binaryPath = join(dir, file);
    const batchOpts: CommonOpts = {
      ...opts,
      output: join(opts.output, file),
    };
    console.log(`\n[batch] Processing ${file}`);
    const overrides: ConfigOverrides = {
      provider: batchOpts.provider as 'claude' | 'openai' | undefined,
      model: batchOpts.model,
      fuzzTimeout: parseInt(batchOpts.fuzzTimeout, 10),
      maxRetries: parseInt(batchOpts.maxRetries, 10),
      outputDir: batchOpts.output,
      logEnabled: batchOpts.log !== false,
      logVerbose: batchOpts.verboseLog,
    };
    const config = resolveConfig(overrides);
    mkdirSync(config.outputDir, { recursive: true });
    const logger = config.log.enabled
      ? Logger.init(config.outputDir, { verbose: config.log.verbose ?? false })
      : Logger.noop();
    const provider = createProvider({
      provider: config.provider,
      model: config.model,
      apiKey: config.apiKey,
      logger,
    });
    const result = await runPipeline({
      binaryPath,
      sourceDir: batchOpts.source,
      libcPath: batchOpts.libc,
      remote: parseRemote(batchOpts.remote),
      config,
      provider,
      mode: 'pwn',
      logger,
    });
    console.log(`[batch] ${file}: ${result.message}`);
    if (!result.success) anyFailed = true;
  }

  process.exit(anyFailed ? 1 : 0);
});

program
  .command('extract-training <logs...>')
  .description('Extract training data from run logs')
  .requiredOption('--format <format>', 'Output format: openai, rag, or metrics')
  .option('--output <path>', 'Output file path', './training_data.jsonl')
  .action(async (logs: string[], opts: { format: string; output: string }) => {
    const format = opts.format as 'openai' | 'rag' | 'metrics';
    if (!['openai', 'rag', 'metrics'].includes(format)) {
      console.error(`Invalid format: ${format}. Use: openai, rag, metrics`);
      process.exit(1);
    }
    await extractToFile(logs, opts.output, format);
    console.log(`Extracted ${format} data to ${opts.output}`);
  });

program.parse();
