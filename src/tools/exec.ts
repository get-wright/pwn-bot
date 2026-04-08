import { execa } from 'execa';

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export async function exec(
  command: string,
  args: string[],
  opts?: { timeout?: number; cwd?: string; stdin?: string },
): Promise<ExecResult> {
  const result = await execa(command, args, {
    timeout: opts?.timeout ?? 30_000,
    cwd: opts?.cwd,
    reject: false,
    ...(opts?.stdin ? { input: opts.stdin } : {}),
  });
  return {
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
    exitCode: result.exitCode ?? 1,
  };
}
