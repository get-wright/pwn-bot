import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs/promises';
import { exec } from './exec.js';

export interface DecompiledFunction {
  name: string;
  decompiled: string;
}

const GHIDRA_SCRIPT = `
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;

DecompInterface decomp = new DecompInterface();
decomp.openProgram(currentProgram);

FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
while (funcs.hasNext()) {
    Function f = funcs.next();
    DecompileResults res = decomp.decompileFunction(f, 30, new ConsoleTaskMonitor());
    if (res.decompileCompleted()) {
        println("FUNC_START:" + f.getName());
        println(res.getDecompiledFunction().getC());
        println("FUNC_END");
    }
}
`.trim();

async function fallbackObjdump(binaryPath: string): Promise<DecompiledFunction[]> {
  const result = await exec('objdump', ['-d', '-M', 'intel', binaryPath], { timeout: 60_000 });
  const lines = result.stdout.split('\n');
  const functions: DecompiledFunction[] = [];

  let currentName: string | null = null;
  let currentLines: string[] = [];

  for (const line of lines) {
    const funcLabel = line.match(/^[0-9a-f]+ <([^>]+)>:$/);
    if (funcLabel) {
      if (currentName !== null) {
        functions.push({ name: currentName, decompiled: currentLines.join('\n') });
      }
      currentName = funcLabel[1];
      currentLines = [line];
    } else if (currentName !== null) {
      currentLines.push(line);
    }
  }
  if (currentName !== null) {
    functions.push({ name: currentName, decompiled: currentLines.join('\n') });
  }

  return functions;
}

export async function decompile(binaryPath: string): Promise<DecompiledFunction[]> {
  const ghidraHome = process.env['GHIDRA_HOME'] ?? '/opt/ghidra';
  const analyzeHeadless = path.join(ghidraHome, 'support', 'analyzeHeadless');

  try {
    await fs.access(analyzeHeadless);
  } catch {
    return fallbackObjdump(binaryPath);
  }

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghidra-'));
  const scriptFile = path.join(tmpDir, 'Decompile.java');
  await fs.writeFile(scriptFile, GHIDRA_SCRIPT);

  try {
    const result = await exec(
      analyzeHeadless,
      [
        tmpDir,
        'TmpProject',
        '-import',
        binaryPath,
        '-postScript',
        scriptFile,
        '-deleteProject',
        '-noanalysis',
      ],
      { timeout: 120_000 },
    );

    return parseGhidraOutput(result.stdout + result.stderr);
  } catch {
    return fallbackObjdump(binaryPath);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
}

function parseGhidraOutput(raw: string): DecompiledFunction[] {
  const functions: DecompiledFunction[] = [];
  const lines = raw.split('\n');

  let currentName: string | null = null;
  let currentLines: string[] = [];

  for (const line of lines) {
    if (line.startsWith('FUNC_START:')) {
      currentName = line.slice('FUNC_START:'.length).trim();
      currentLines = [];
    } else if (line.trim() === 'FUNC_END' && currentName !== null) {
      functions.push({ name: currentName, decompiled: currentLines.join('\n') });
      currentName = null;
      currentLines = [];
    } else if (currentName !== null) {
      currentLines.push(line);
    }
  }

  return functions;
}
