import { execa } from 'execa';
import type { Logger } from '../modules/logger.js';

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export async function exec(
  command: string,
  args: string[],
  opts?: { timeout?: number; cwd?: string; stdin?: string; logger?: Logger },
): Promise<ExecResult> {
  const start = performance.now();
  const result = await execa(command, args, {
    timeout: opts?.timeout ?? 30_000,
    cwd: opts?.cwd,
    reject: false,
    ...(opts?.stdin ? { input: opts.stdin } : {}),
  });
  const duration_ms = Math.round(performance.now() - start);

  const execResult: ExecResult = {
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
    exitCode: result.exitCode ?? 1,
  };

  opts?.logger?.log('tool.exec', {
    payload: {
      command,
      args,
      exit_code: execResult.exitCode,
      stdout: execResult.stdout,
      stderr: execResult.stderr,
      duration_ms,
    },
  });

  return execResult;
}
