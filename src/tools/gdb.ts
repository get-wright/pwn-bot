import { exec } from './exec.js';

export interface GdbResult {
  registers: Record<string, string>;
  backtrace: string[];
  memory: Record<string, string>;
  output: string;
}

export function parseGdbOutput(raw: string): GdbResult {
  const registers: Record<string, string> = {};
  const backtrace: string[] = [];
  const memory: Record<string, string> = {};

  for (const line of raw.split('\n')) {
    // Register lines: "rax            0x0                 0"
    // or compact info registers output
    const regMatch = line.match(/^\s*(r[a-z0-9]+)\s+(0x[0-9a-fA-F]+)/);
    if (regMatch) {
      registers[regMatch[1]] = regMatch[2];
      continue;
    }

    // Backtrace lines: "#0  0x... in ..." or "#0 0x..."
    const btMatch = line.match(/^#\d+\s+.+/);
    if (btMatch) {
      backtrace.push(line.trim());
      continue;
    }

    // Memory examine: "0xaddr:\t0xval"
    const memMatch = line.match(/^(0x[0-9a-fA-F]+):\s+(0x[0-9a-fA-F]+)/);
    if (memMatch) {
      memory[memMatch[1]] = memMatch[2];
    }
  }

  return { registers, backtrace, memory, output: raw };
}

export async function runGdbScript(
  binaryPath: string,
  commands: string[],
  stdin?: string,
): Promise<GdbResult> {
  const script = commands.join('\n') + '\nquit\n';
  const args = ['-batch', '-ex', 'set pagination off', binaryPath];

  // Inject commands via --command (stdin script)
  const cmdArgs = ['-batch', binaryPath];
  for (const cmd of commands) {
    cmdArgs.splice(cmdArgs.length - 1, 0, '-ex', cmd);
  }
  cmdArgs.push('-ex', 'quit');

  const result = await exec('gdb', cmdArgs, {
    timeout: 30_000,
    stdin,
  });

  void script; // referenced above for documentation
  void args;

  return parseGdbOutput(result.stdout + '\n' + result.stderr);
}

export async function findCrashOffset(
  binaryPath: string,
  patternLength: number,
): Promise<number> {
  // Generate cyclic pattern via python/pwntools
  const genResult = await exec('python3', [
    '-c',
    `from pwn import *; print(cyclic(${patternLength}).decode())`,
  ]);
  const pattern = genResult.stdout.trim();

  const gdbResult = await runGdbScript(
    binaryPath,
    ['run', 'info registers rip'],
    pattern + '\n',
  );

  const rip = gdbResult.registers['rip'];
  if (!rip) throw new Error('Could not read RIP from crash');

  // Find offset using cyclic_find
  const findResult = await exec('python3', [
    '-c',
    `from pwn import *; print(cyclic_find(p64(${rip})))`,
  ]);

  const offset = parseInt(findResult.stdout.trim(), 10);
  if (isNaN(offset)) throw new Error(`Could not find cyclic offset for RIP ${rip}`);

  return offset;
}
