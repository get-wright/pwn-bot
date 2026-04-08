import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs/promises';
import { exec } from './exec.js';

export interface AngrResult {
  found: boolean;
  input?: string; // hex encoded
}

function buildAngrScript(
  binaryPath: string,
  targetAddr: number,
  avoidAddrs: number[],
): string {
  const avoidList = JSON.stringify(avoidAddrs);
  return `
import angr
import json
import sys

proj = angr.Project('${binaryPath}', auto_load_libs=False)
state = proj.factory.entry_state(stdin=angr.SimFile)
sm = proj.factory.simulation_manager(state)

target = ${targetAddr}
avoid = ${avoidList}

sm.explore(find=target, avoid=avoid)

if sm.found:
    found_state = sm.found[0]
    inp = found_state.posix.stdin.load(0, found_state.posix.stdin.size)
    solved = found_state.solver.eval(inp, cast_to=bytes)
    print(json.dumps({'found': True, 'input': solved.hex()}))
else:
    print(json.dumps({'found': False}))
`.trim();
}

export async function solveForInput(
  binaryPath: string,
  targetAddr: number,
  avoidAddrs: number[] = [],
  timeout?: number,
): Promise<AngrResult> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'angr-'));
  const scriptFile = path.join(tmpDir, 'solve.py');

  try {
    await fs.writeFile(scriptFile, buildAngrScript(binaryPath, targetAddr, avoidAddrs));

    const result = await exec('python3', [scriptFile], {
      timeout: timeout ?? 300_000,
    });

    if (result.exitCode !== 0) {
      return { found: false };
    }

    const lastLine = result.stdout.trim().split('\n').pop() ?? '';
    return JSON.parse(lastLine) as AngrResult;
  } catch {
    return { found: false };
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
}
