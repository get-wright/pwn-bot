#!/usr/bin/env node
import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { readdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveConfig, type ConfigOverrides } from './config.js';
import { createProvider } from './providers/factory.js';
import { runPipeline, type PipelineOpts } from './pipeline.js';

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
    .option('--max-retries <n>', 'max exploit retries', '5');
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
  };

  const config = resolveConfig(overrides);
  const provider = createProvider(config);
  const result = await runPipeline({
    binaryPath,
    sourceDir: opts.source,
    libcPath: opts.libc,
    remote: parseRemote(opts.remote),
    config,
    provider,
    mode,
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
    };
    const config = resolveConfig(overrides);
    const provider = createProvider(config);
    const result = await runPipeline({
      binaryPath,
      sourceDir: batchOpts.source,
      libcPath: batchOpts.libc,
      remote: parseRemote(batchOpts.remote),
      config,
      provider,
      mode: 'pwn',
    });
    console.log(`[batch] ${file}: ${result.message}`);
    if (!result.success) anyFailed = true;
  }

  process.exit(anyFailed ? 1 : 0);
});

program.parse();
