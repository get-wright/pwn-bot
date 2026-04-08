import { exec } from './exec.js';

export interface ElfInfo {
  arch: string;
  bits: number;
  endian: string;
  symbols: Record<string, number>;
  got: Record<string, number>;
}

export async function runPwntoolsScript(
  scriptPath: string,
  args?: string[],
  timeout?: number,
): Promise<string> {
  const result = await exec('python3', [scriptPath, ...(args ?? [])], {
    timeout: timeout ?? 60_000,
  });
  if (result.exitCode !== 0) {
    throw new Error(`pwntools script failed: ${result.stderr}`);
  }
  return result.stdout;
}

export async function getElfInfo(binaryPath: string): Promise<ElfInfo> {
  const script = `
from pwn import *
import json
context.log_level = 'error'
e = ELF('${binaryPath}', checksec=False)
info = {
    'arch': e.arch,
    'bits': e.bits,
    'endian': e.endian,
    'symbols': {k: v for k, v in e.symbols.items()},
    'got': {k: v for k, v in e.got.items()},
}
print(json.dumps(info))
`.trim();

  const result = await exec('python3', ['-c', script], { timeout: 30_000 });
  if (result.exitCode !== 0) {
    throw new Error(`getElfInfo failed: ${result.stderr}`);
  }

  return JSON.parse(result.stdout) as ElfInfo;
}

export async function findCyclicOffset(crashValue: string): Promise<number> {
  const script = `
from pwn import *
import sys
val = ${crashValue}
try:
    off = cyclic_find(val)
except Exception:
    off = cyclic_find(p64(val) if isinstance(val, int) else val)
print(off)
`.trim();

  const result = await exec('python3', ['-c', script], { timeout: 10_000 });
  if (result.exitCode !== 0) {
    throw new Error(`findCyclicOffset failed: ${result.stderr}`);
  }

  const offset = parseInt(result.stdout.trim(), 10);
  if (isNaN(offset)) throw new Error(`Invalid cyclic offset: ${result.stdout}`);
  return offset;
}
