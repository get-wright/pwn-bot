import * as fs from 'fs/promises';
import * as path from 'path';
import { runChecksec } from '../tools/checksec.js';
import { decompile } from '../tools/ghidra.js';
import { getElfInfo } from '../tools/pwntools.js';
import { findOneGadgets } from '../tools/one-gadget.js';
import { exec } from '../tools/exec.js';
import { ReconOutput, Protections, FunctionInfo } from '../types.js';

// --- assessProtections ---

export function assessProtections(protections: Protections): {
  viable_strategies: string[];
  leaks_needed: string[];
} {
  const viable_strategies: string[] = [];
  const leaks_needed: string[] = [];

  if (!protections.nx) viable_strategies.push('shellcode');
  viable_strategies.push('ret2libc', 'rop');
  if (protections.relro !== 'full') viable_strategies.push('got_overwrite');

  leaks_needed.push('libc_base');
  if (protections.canary) leaks_needed.push('canary');
  if (protections.pie) leaks_needed.push('pie_base');

  return { viable_strategies, leaks_needed };
}

// --- rankFunctions ---

const INIT_PATTERNS = /_start|__libc_start|_init|_fini|register_tm|deregister_tm|frame_dummy/;
const RANK5_PATTERNS = /\b(gets|read|recv|scanf|fgets|recvfrom|getline)\s*\(/;
const RANK4_PATTERNS =
  /\b(printf|sprintf|snprintf|strlen|strcpy|strcat|memcpy|malloc|free|realloc)\s*\(/;
const RANK3_PATTERNS = /\b(if|switch|while|for|auth|login|check|verify)\b/;
const FORMAT_STRING_PATTERN = /printf\s*\(\s*\w+\s*\)/;

export function rankFunctions(
  functions: Array<{ name: string; decompiled: string; rank: 0; notes: '' }>,
): FunctionInfo[] {
  return functions
    .map((fn) => {
      let rank = 2;
      let notes = '';

      if (INIT_PATTERNS.test(fn.name)) {
        rank = 1;
      } else if (RANK5_PATTERNS.test(fn.decompiled)) {
        const match = fn.decompiled.match(RANK5_PATTERNS);
        const funcName = match ? match[1] : 'input';
        rank = 5;
        notes = `Direct input: ${funcName}`;
      } else if (RANK4_PATTERNS.test(fn.decompiled)) {
        rank = 4;
        notes = 'Memory/string op';
      } else if (RANK3_PATTERNS.test(fn.decompiled)) {
        rank = 3;
      }

      if (FORMAT_STRING_PATTERN.test(fn.decompiled)) {
        if (rank < 4) rank = 4;
        notes = notes ? `${notes}, Possible format string` : 'Possible format string';
      }

      return { name: fn.name, decompiled: fn.decompiled, rank, notes };
    })
    .sort((a, b) => b.rank - a.rank);
}

// --- runRecon ---

const INTERESTING_STRINGS_PATTERNS = [
  '/bin/sh',
  'system',
  'execve',
  'flag',
  'password',
  'secret',
  '%s',
  '%p',
  '%n',
  'AAAA',
];

async function runStrings(binaryPath: string): Promise<string[]> {
  const result = await exec('strings', [binaryPath], { timeout: 15_000 });
  const lines = result.stdout.split('\n');
  return lines.filter((line) =>
    INTERESTING_STRINGS_PATTERNS.some((pat) => line.includes(pat)),
  );
}

export async function runRecon(
  binaryPath: string,
  opts?: { libcPath?: string; outputDir?: string },
): Promise<ReconOutput> {
  const outputDir = opts?.outputDir ?? path.join(path.dirname(binaryPath), 'recon');
  await fs.mkdir(outputDir, { recursive: true });

  const [protections, elfInfo, decompiledFuncs] = await Promise.all([
    runChecksec(binaryPath),
    getElfInfo(binaryPath),
    decompile(binaryPath),
  ]);

  const symbols = Object.keys(elfInfo.symbols);

  const _interestingStrings = await runStrings(binaryPath);

  const inputFuncs = decompiledFuncs.map((fn) => ({
    name: fn.name,
    decompiled: fn.decompiled,
    rank: 0 as const,
    notes: '' as const,
  }));
  const rankedFunctions = rankFunctions(inputFuncs);

  const { viable_strategies, leaks_needed } = assessProtections(protections);

  const arch = elfInfo.arch as 'amd64' | 'i386' | 'arm' | 'aarch64' | 'mips';
  const bits = elfInfo.bits;
  const endian = elfInfo.endian as 'little' | 'big';

  const target = {
    path: binaryPath,
    arch,
    bits,
    endian,
    stripped: !symbols.some((s) => s === 'main'),
  };

  let libcData: ReconOutput['libc'];

  if (opts?.libcPath) {
    const [gadgets, libcElf] = await Promise.all([
      findOneGadgets(opts.libcPath),
      getElfInfo(opts.libcPath),
    ]);

    const version = String(libcElf.symbols['__libc_version'] ?? 'unknown');
    libcData = {
      version,
      offsets: libcElf.symbols,
      one_gadgets: gadgets,
    };
  }

  const output: ReconOutput = {
    target,
    protections,
    symbols,
    functions: rankedFunctions,
    viable_strategies,
    leaks_needed,
    ...(libcData ? { libc: libcData } : {}),
  };

  await fs.writeFile(path.join(outputDir, 'recon.json'), JSON.stringify(output, null, 2));

  return output;
}
