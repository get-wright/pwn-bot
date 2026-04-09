import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Config } from './config.js';
import { LLMProvider } from './providers/interface.js';
import { ReconOutput, HunterOutput, Hypothesis } from './types.js';
import { runRecon } from './modules/recon.js';
import { compileHarness, runAflFuzz } from './modules/fuzzer.js';
import { triageCrashDir } from './modules/crash-triage.js';
import { testExploit, detectExploitSuccess } from './modules/exploit-test.js';
import { analyzeForVulnerabilities, generateExploitCode, triageCrashWithLLM } from './modules/llm.js';
import { runGdbScript, findCrashOffset } from './tools/gdb.js';
import { Logger } from './modules/logger.js';

// Suppress unused import warnings for tools that are part of the API surface
void compileHarness;
void runAflFuzz;
void triageCrashDir;
void triageCrashWithLLM;
void runGdbScript;
void findCrashOffset;

export interface GateResult {
  pass: boolean;
  reason?: string;
}

export interface PipelineOpts {
  binaryPath: string;
  sourceDir?: string;
  libcPath?: string;
  remote?: { host: string; port: number };
  config: Config;
  provider: LLMProvider;
  mode: 'pwn' | 'recon' | 'hunt' | 'fuzz' | 'exploit' | 'full';
  logger?: Logger;
}

export interface PipelineResult {
  recon?: ReconOutput;
  hunter?: HunterOutput;
  exploitPath?: string;
  success: boolean;
  message: string;
}

export function validateReconGate(recon: ReconOutput): GateResult {
  if (recon.functions.length > 0) {
    return { pass: true };
  }
  return { pass: false, reason: 'Recon produced no analyzable functions' };
}

export function validateHunterGate(hunter: HunterOutput): GateResult {
  const hasConfirmed = hunter.hypotheses.some((h) => h.status === 'confirmed');
  if (hasConfirmed || hunter.confirmed_vulns.length > 0) {
    return { pass: true };
  }
  return { pass: false, reason: 'No confirmed vulnerabilities found' };
}

export function validateExploitGate(output: string): GateResult {
  if (detectExploitSuccess(output)) {
    return { pass: true };
  }
  return { pass: false, reason: 'Exploit did not produce success indicators' };
}

export async function runPipeline(opts: PipelineOpts): Promise<PipelineResult> {
  const { binaryPath, libcPath, remote, config, provider, mode } = opts;
  const outputDir = config.outputDir;

  await mkdir(outputDir, { recursive: true });

  const logger = opts.logger ?? Logger.noop();
  logger.log('pipeline.start', {
    payload: { mode, binary_path: binaryPath, config },
  });
  const pipelineStart = performance.now();

  // --- Recon ---
  let recon: ReconOutput;

  if (mode === 'exploit') {
    const reconPath = join(outputDir, 'recon.json');
    if (!existsSync(reconPath)) {
      logger.log('pipeline.end', {
        payload: { success: false, message: `recon.json not found at ${reconPath}`, total_duration_ms: Math.round(performance.now() - pipelineStart) },
      });
      logger.close();
      return { success: false, message: `recon.json not found at ${reconPath}` };
    }
    console.log('[recon] Loading existing recon.json');
    recon = JSON.parse(await readFile(reconPath, 'utf-8')) as ReconOutput;
  } else {
    console.log('[recon] Starting binary analysis');
    recon = await logger.time('stage', 'recon', () =>
      runRecon(binaryPath, { libcPath, outputDir }),
    );
    console.log(`[recon] Found ${recon.functions.length} functions`);
  }

  if (mode === 'recon') {
    logger.log('pipeline.end', {
      payload: { success: true, message: 'Recon complete', total_duration_ms: Math.round(performance.now() - pipelineStart) },
    });
    logger.close();
    return { recon, success: true, message: 'Recon complete' };
  }

  // --- Recon gate ---
  const reconGate = validateReconGate(recon);
  logger.log('gate.result', { payload: { gate_name: 'recon', ...reconGate } });
  if (!reconGate.pass) {
    logger.log('pipeline.end', {
      payload: { success: false, message: reconGate.reason ?? 'Recon gate failed', total_duration_ms: Math.round(performance.now() - pipelineStart) },
    });
    logger.close();
    return { recon, success: false, message: reconGate.reason ?? 'Recon gate failed' };
  }

  // --- Hunt ---
  console.log('[hunt] Analyzing for vulnerabilities');
  const hypotheses = await analyzeForVulnerabilities(provider, recon);
  console.log(`[hunt] Generated ${hypotheses.length} hypotheses`);

  const confirmedVulns: Hypothesis[] = [];

  for (const hypothesis of hypotheses) {
    console.log(`[hunt] Confirming hypothesis: ${hypothesis.function} (${hypothesis.vuln_class})`);
    try {
      const gdbResult = await runGdbScript(
        binaryPath,
        ['run', 'info registers', 'backtrace'],
        hypothesis.trigger,
      );

      const hasEvidence =
        Object.keys(gdbResult.registers).length > 0 || gdbResult.backtrace.length > 0;

      if (hasEvidence) {
        const confirmed: Hypothesis = {
          ...hypothesis,
          status: 'confirmed',
          gdb_evidence: {
            registers: gdbResult.registers,
            backtrace: gdbResult.backtrace,
            controlled_bytes: 0,
          },
        };
        confirmedVulns.push(confirmed);
        console.log(`[hunt] Confirmed: ${hypothesis.function}`);
        logger.log('hypothesis.result', {
          stage: 'hunt',
          payload: { function: hypothesis.function, vuln_class: hypothesis.vuln_class, status: 'confirmed', primitive: hypothesis.primitive },
        });
      }
    } catch {
      // Hypothesis could not be confirmed via GDB
    }
  }

  const hunter: HunterOutput = {
    hypotheses,
    confirmed_vulns: confirmedVulns,
    harnesses: [],
    source_findings: [],
  };

  await writeFile(join(outputDir, 'hunter.json'), JSON.stringify(hunter, null, 2));
  console.log(`[hunt] Wrote hunter.json (${confirmedVulns.length} confirmed vulns)`);

  if (mode === 'hunt' || mode === 'fuzz') {
    logger.log('pipeline.end', {
      payload: { success: true, message: `Hunt complete (${confirmedVulns.length} confirmed)`, total_duration_ms: Math.round(performance.now() - pipelineStart) },
    });
    logger.close();
    return { recon, hunter, success: true, message: `Hunt complete (${confirmedVulns.length} confirmed)` };
  }

  // --- Hunter gate ---
  const hunterGate = validateHunterGate(hunter);
  logger.log('gate.result', { payload: { gate_name: 'hunter', ...hunterGate } });
  if (!hunterGate.pass) {
    logger.log('pipeline.end', {
      payload: { success: false, message: hunterGate.reason ?? 'Hunter gate failed', total_duration_ms: Math.round(performance.now() - pipelineStart) },
    });
    logger.close();
    return { recon, hunter, success: false, message: hunterGate.reason ?? 'Hunter gate failed' };
  }

  // --- Exploit ---
  const targetVuln = hunter.confirmed_vulns[0] ?? hunter.hypotheses.find((h) => h.status === 'confirmed');
  if (!targetVuln) {
    logger.log('pipeline.end', {
      payload: { success: false, message: 'No confirmed vulnerability to exploit', total_duration_ms: Math.round(performance.now() - pipelineStart) },
    });
    logger.close();
    return { recon, hunter, success: false, message: 'No confirmed vulnerability to exploit' };
  }

  console.log(`[exploit] Generating exploit for ${targetVuln.function}`);
  const exploitPath = join(outputDir, 'exploit.py');
  const maxRetries = config.exploit.maxRetries;

  let lastOutput = '';
  let exploitSuccess = false;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    console.log(`[exploit] Attempt ${attempt}/${maxRetries}`);
    const code = await generateExploitCode(provider, recon, targetVuln);
    await writeFile(exploitPath, code);

    const result = await testExploit(exploitPath, config.exploit.testTimeout);
    lastOutput = result.output;

    logger.log('exploit.attempt', {
      stage: 'exploit',
      payload: { attempt_number: attempt, success: result.success, output: result.output },
    });

    if (result.success) {
      exploitSuccess = true;
      console.log('[exploit] Local test succeeded');
      break;
    }

    console.log(`[exploit] Attempt ${attempt} failed`);
  }

  if (!exploitSuccess) {
    logger.log('pipeline.end', {
      payload: { success: false, message: 'Exploit failed after max retries', total_duration_ms: Math.round(performance.now() - pipelineStart) },
    });
    logger.close();
    return { recon, hunter, exploitPath, success: false, message: 'Exploit failed after max retries' };
  }

  if (remote) {
    console.log(`[exploit] Testing remote ${remote.host}:${remote.port}`);
    const remoteResult = await testExploit(exploitPath, config.exploit.testTimeout, 'REMOTE');
    lastOutput = remoteResult.output;
    if (!remoteResult.success) {
      logger.log('pipeline.end', {
        payload: { success: false, message: 'Remote exploit test failed', total_duration_ms: Math.round(performance.now() - pipelineStart) },
      });
      logger.close();
      return { recon, hunter, exploitPath, success: false, message: 'Remote exploit test failed' };
    }
    console.log('[exploit] Remote test succeeded');
  }

  void lastOutput;

  logger.log('pipeline.end', {
    payload: { success: true, message: 'Exploit successful', total_duration_ms: Math.round(performance.now() - pipelineStart) },
  });
  logger.close();
  return { recon, hunter, exploitPath, success: true, message: 'Exploit successful' };
}
