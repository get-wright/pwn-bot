import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { LLMProvider } from '../providers/interface.js';
import { HypothesisSchema, ReconOutput, Hypothesis } from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function loadPrompt(name: string): Promise<string> {
  const promptPath = join(__dirname, '../../templates/prompts', `${name}.md`);
  try {
    return await readFile(promptPath, 'utf-8');
  } catch {
    return `You are a binary exploitation assistant. Analyze the provided data and respond with valid JSON matching the requested schema.`;
  }
}

// --- analyzeForVulnerabilities ---

export async function analyzeForVulnerabilities(
  provider: LLMProvider,
  recon: ReconOutput,
): Promise<Hypothesis[]> {
  const system = await loadPrompt('hunter');

  const highRankFunctions = recon.functions
    .filter((fn) => fn.rank >= 4)
    .map((fn) => `### ${fn.name} (rank ${fn.rank})\n${fn.notes ? `Notes: ${fn.notes}\n` : ''}\`\`\`c\n${fn.decompiled}\n\`\`\``)
    .join('\n\n');

  const userContent = [
    `## Target`,
    `Path: ${recon.target.path}`,
    `Arch: ${recon.target.arch} (${recon.target.bits}-bit, ${recon.target.endian}-endian)`,
    `Stripped: ${recon.target.stripped}`,
    ``,
    `## Protections`,
    `NX: ${recon.protections.nx}`,
    `Canary: ${recon.protections.canary}`,
    `PIE: ${recon.protections.pie}`,
    `RELRO: ${recon.protections.relro}`,
    `Fortify: ${recon.protections.fortify}`,
    ``,
    `## Viable Strategies`,
    recon.viable_strategies.join(', '),
    ``,
    `## Leaks Needed`,
    recon.leaks_needed.join(', '),
    ``,
    `## High-Interest Functions`,
    highRankFunctions,
  ].join('\n');

  const result = await provider.analyze({
    system,
    userContent,
    schema: z.array(HypothesisSchema),
  });

  return result.parsed;
}

// --- generateExploitCode ---

export async function generateExploitCode(
  provider: LLMProvider,
  recon: ReconOutput,
  confirmedVuln: Hypothesis,
): Promise<string> {
  const system = await loadPrompt('exploit');

  const libcLines: string[] = [];
  if (recon.libc) {
    libcLines.push(`## Libc`);
    libcLines.push(`Version: ${recon.libc.version}`);
    const offsets = Object.entries(recon.libc.offsets)
      .map(([sym, off]) => `  ${sym}: 0x${off.toString(16)}`)
      .join('\n');
    libcLines.push(`Offsets:\n${offsets}`);
    if (recon.libc.one_gadgets.length > 0) {
      const gadgets = recon.libc.one_gadgets
        .map((g) => `  0x${g.address.toString(16)} [${g.constraints.join(', ')}]`)
        .join('\n');
      libcLines.push(`One-gadgets:\n${gadgets}`);
    }
  }

  const userContent = [
    `## Target`,
    `Path: ${recon.target.path}`,
    `Arch: ${recon.target.arch} (${recon.target.bits}-bit, ${recon.target.endian}-endian)`,
    `Stripped: ${recon.target.stripped}`,
    ``,
    `## Protections`,
    `NX: ${recon.protections.nx}`,
    `Canary: ${recon.protections.canary}`,
    `PIE: ${recon.protections.pie}`,
    `RELRO: ${recon.protections.relro}`,
    `Fortify: ${recon.protections.fortify}`,
    ``,
    ...(libcLines.length > 0 ? [...libcLines, ''] : []),
    `## Confirmed Vulnerability`,
    `Function: ${confirmedVuln.function}`,
    `Location: ${confirmedVuln.location}`,
    `Trigger: ${confirmedVuln.trigger}`,
    `Class: ${confirmedVuln.vuln_class}`,
    `Primitive: ${confirmedVuln.primitive}`,
    `Bad bytes: ${confirmedVuln.constraints.bad_bytes.join(', ') || 'none'}`,
    ...(confirmedVuln.constraints.max_length !== undefined
      ? [`Max length: ${confirmedVuln.constraints.max_length}`]
      : []),
    ...(confirmedVuln.asan_report ? [`\nASAN Report:\n${confirmedVuln.asan_report}`] : []),
  ].join('\n');

  const result = await provider.analyze({
    system,
    userContent,
    schema: z.object({ code: z.string() }),
  });

  return result.parsed.code;
}

// --- triageCrashWithLLM ---

export async function triageCrashWithLLM(
  provider: LLMProvider,
  crashContext: {
    registers: Record<string, string>;
    backtrace: string[];
    signal: string;
    faultAddr?: string;
    asanReport?: string;
  },
  recon: ReconOutput,
): Promise<{ analysis: string; severity: string }> {
  const system = await loadPrompt('triage');

  const userContent = [
    `## Target`,
    `Arch: ${recon.target.arch} (${recon.target.bits}-bit)`,
    ``,
    `## Crash Info`,
    `Signal: ${crashContext.signal}`,
    ...(crashContext.faultAddr ? [`Fault address: ${crashContext.faultAddr}`] : []),
    ``,
    `## Registers`,
    Object.entries(crashContext.registers)
      .map(([r, v]) => `  ${r}: ${v}`)
      .join('\n'),
    ``,
    `## Backtrace`,
    crashContext.backtrace.map((f) => `  ${f}`).join('\n'),
    ...(crashContext.asanReport ? [`\n## ASAN Report\n${crashContext.asanReport}`] : []),
  ].join('\n');

  const result = await provider.analyze({
    system,
    userContent,
    schema: z.object({
      analysis: z.string(),
      severity: z.enum(['critical', 'high', 'medium', 'low']),
      vuln_class: z.string(),
      exploitable: z.boolean(),
    }),
  });

  return {
    analysis: result.parsed.analysis,
    severity: result.parsed.severity,
  };
}
