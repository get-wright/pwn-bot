import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { exec } from '../tools/exec.js';

export interface FuzzerConfig {
  timeoutSecs: number;
  memoryLimitMb?: number;
  extraAflFlags?: string[];
}

export interface FuzzerResult {
  crashDir: string;
  crashCount: number;
  totalPaths: number;
  duration: number;
}

export async function compileHarness(
  harnessPath: string,
  outputPath: string,
  extraFlags: string[] = [],
): Promise<void> {
  const args = [
    '-fsanitize=address',
    '-g',
    '-o', outputPath,
    harnessPath,
    ...extraFlags,
  ];

  const result = await exec('afl-clang-fast', args, { timeout: 120_000 });

  if (result.exitCode !== 0) {
    throw new Error(`afl-clang-fast failed (exit ${result.exitCode}):\n${result.stderr}`);
  }
}

export async function runAflFuzz(
  targetPath: string,
  inputDir: string,
  outputDir: string,
  config: FuzzerConfig,
): Promise<FuzzerResult> {
  const startTime = Date.now();

  // Ensure inputDir exists; if empty create a minimal seed
  await fs.mkdir(inputDir, { recursive: true });
  const inputEntries = await fs.readdir(inputDir);
  if (inputEntries.length === 0) {
    await fs.writeFile(path.join(inputDir, 'seed'), Buffer.from([0x00]));
  }

  await fs.mkdir(outputDir, { recursive: true });

  const args = [
    '-i', inputDir,
    '-o', outputDir,
    '-V', String(config.timeoutSecs),
    ...(config.memoryLimitMb ? ['-m', String(config.memoryLimitMb)] : []),
    ...(config.extraAflFlags ?? []),
    '--',
    targetPath,
    '@@',
  ];

  const result = await exec('afl-fuzz', args, {
    timeout: (config.timeoutSecs + 30) * 1_000,
  });

  if (result.exitCode !== 0 && result.exitCode !== 1) {
    throw new Error(`afl-fuzz failed (exit ${result.exitCode}):\n${result.stderr}`);
  }

  const duration = (Date.now() - startTime) / 1000;

  // Parse fuzzer_stats
  let totalPaths = 0;
  const statsPath = path.join(outputDir, 'default', 'fuzzer_stats');
  try {
    const stats = await fs.readFile(statsPath, 'utf8');
    const match = stats.match(/^paths_total\s*:\s*(\d+)/m);
    if (match) totalPaths = parseInt(match[1], 10);
  } catch {
    // stats not available (dry run, etc.)
  }

  // Count crashes
  const crashDir = path.join(outputDir, 'default', 'crashes');
  let crashCount = 0;
  try {
    const crashes = await fs.readdir(crashDir);
    crashCount = crashes.filter((f) => !f.startsWith('.')).length;
  } catch {
    // no crashes directory
  }

  return { crashDir, crashCount, totalPaths, duration };
}
