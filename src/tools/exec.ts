import { execa, type Options as ExecaOptions } from 'execa';

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
  const options: ExecaOptions = {
    timeout: opts?.timeout ?? 30_000,
    cwd: opts?.cwd,
    reject: false,
  };
  if (opts?.stdin) {
    options.input = opts.stdin;
  }
  const result = await execa(command, args, options);
  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    exitCode: result.exitCode ?? 1,
  };
}
