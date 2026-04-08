import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { runGdbScript } from '../tools/gdb.js';
import { CrashInfo, TriageOutput } from '../types.js';

export interface CrashContext {
  registers: Record<string, string>;
  backtrace: string[];
  signal: string;
  faultAddr?: string;
}

// Returns first 16 hex chars of sha256 of joined top-5 frame func names.
export function computeStackHash(backtrace: string[]): string {
  const top5 = backtrace.slice(0, 5);
  const funcNames = top5.map((frame) => {
    const m = frame.match(/\bin\s+(\S+)/);
    return m ? m[1] : '';
  });
  const joined = funcNames.join('|');
  return createHash('sha256').update(joined).digest('hex').slice(0, 16);
}

const NON_CANONICAL_LOW = BigInt('0x7fffffffffff');
const NON_CANONICAL_HIGH = BigInt('0xffff800000000000');

function isNonCanonical(addr: string): boolean {
  try {
    const val = BigInt(addr);
    return val > NON_CANONICAL_LOW && val < NON_CANONICAL_HIGH;
  } catch {
    return false;
  }
}

function hasRepeatingBytePattern(addr: string): boolean {
  // Strip 0x prefix and normalise to 8 bytes (16 hex chars)
  const hex = addr.replace(/^0x/i, '').toLowerCase().padStart(16, '0');
  // Check if all bytes are the same byte value
  const byte = hex.slice(0, 2);
  for (let i = 0; i < hex.length; i += 2) {
    if (hex.slice(i, i + 2) !== byte) return false;
  }
  return true;
}

export function classifyExploitability(ctx: CrashContext): 'high' | 'medium' | 'low' | 'unknown' {
  if (ctx.backtrace.some((f) => f.includes('__stack_chk_fail'))) {
    return 'medium';
  }

  if (ctx.faultAddr === '0x0' || ctx.faultAddr === '(nil)') {
    return 'low';
  }

  const rip = ctx.registers['rip'] ?? ctx.registers['eip'];
  if (rip) {
    if (isNonCanonical(rip)) return 'high';
    if (hasRepeatingBytePattern(rip)) return 'high';
  }

  if (ctx.signal === 'SIGSEGV') {
    return 'medium';
  }

  return 'unknown';
}

export function deduplicateCrashes<T extends { id: string; backtrace: string[] }>(
  crashes: T[],
): Array<T & { stackHash: string }> {
  const seen = new Set<string>();
  const result: Array<T & { stackHash: string }> = [];

  for (const crash of crashes) {
    const hash = computeStackHash(crash.backtrace);
    if (!seen.has(hash)) {
      seen.add(hash);
      result.push({ ...crash, stackHash: hash });
    }
  }

  return result;
}

export async function triageCrashDir(
  binaryPath: string,
  crashDir: string,
): Promise<TriageOutput> {
  const entries = await fs.readdir(crashDir);
  const crashFiles = entries.filter((e) => !e.startsWith('.')).sort();

  const allCrashes: Array<{ id: string; backtrace: string[]; registers: Record<string, string>; exploitability: CrashInfo['exploitability']; input_path: string; crash_type: string; stack_hash: string }> = [];

  for (const file of crashFiles) {
    const inputPath = path.join(crashDir, file);
    const inputData = await fs.readFile(inputPath);

    const gdbResult = await runGdbScript(
      binaryPath,
      ['run', 'info registers', 'backtrace'],
      inputData.toString('binary'),
    );

    // Detect signal from GDB output
    let signal = 'UNKNOWN';
    const sigMatch = gdbResult.output.match(/Program received signal (\w+)/);
    if (sigMatch) signal = sigMatch[1];

    const faultMatch = gdbResult.output.match(/Address\s+(0x[0-9a-fA-F]+|\(nil\))/);
    const faultAddr = faultMatch ? faultMatch[1] : undefined;

    const ctx: CrashContext = {
      registers: gdbResult.registers,
      backtrace: gdbResult.backtrace,
      signal,
      faultAddr,
    };

    const exploitability = classifyExploitability(ctx);
    const stackHash = computeStackHash(gdbResult.backtrace);

    allCrashes.push({
      id: file,
      input_path: inputPath,
      crash_type: signal,
      stack_hash: stackHash,
      backtrace: gdbResult.backtrace,
      registers: gdbResult.registers,
      exploitability,
    });
  }

  const unique = deduplicateCrashes(allCrashes);

  const unique_crashes: CrashInfo[] = unique.map((c) => ({
    id: c.id,
    input_path: c.input_path,
    crash_type: c.crash_type,
    stack_hash: c.stackHash,
    backtrace: c.backtrace,
    registers: c.registers,
    exploitability: c.exploitability,
  }));

  return {
    unique_crashes,
    total_crashes: allCrashes.length,
    deduped_count: unique_crashes.length,
  };
}
