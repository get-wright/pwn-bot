import { describe, it, expect } from 'vitest';
import { assessProtections, rankFunctions } from '../src/modules/recon.js';
import { validateReconGate, validateHunterGate } from '../src/pipeline.js';
import { parseChecksecOutput } from '../src/tools/checksec.js';
import { resolveConfig } from '../src/config.js';
import { ReconOutputSchema, HunterOutputSchema } from '../src/types.js';

describe('integration: recon pipeline (no LLM)', () => {
  it('assessProtections + rankFunctions produce valid recon-like output', () => {
    // Simulate what runRecon does without calling external tools
    const protections = parseChecksecOutput(
      JSON.stringify({
        './vuln': {
          relro: 'no', stack_canary: 'no', nx: 'no',
          pie: 'no', fortify_source: 'no', fortified: '0', fortifiable: '0',
        },
      }),
      './vuln',
    );

    const { viable_strategies, leaks_needed } = assessProtections(protections);
    expect(viable_strategies).toContain('shellcode');
    expect(viable_strategies).toContain('ret2libc');

    const functions = rankFunctions([
      { name: 'vuln', decompiled: 'void vuln() { char buf[64]; read(0, buf, 256); }', rank: 0, notes: '' },
      { name: 'win', decompiled: 'void win() { system("/bin/sh"); }', rank: 0, notes: '' },
      { name: 'main', decompiled: 'int main() { vuln(); return 0; }', rank: 0, notes: '' },
    ]);

    expect(functions[0]!.name).toBe('vuln');
    expect(functions[0]!.rank).toBe(5);

    const recon = {
      target: { path: './vuln', arch: 'amd64' as const, bits: 64, endian: 'little' as const, stripped: false },
      protections,
      symbols: ['main', 'vuln', 'win'],
      functions,
      viable_strategies,
      leaks_needed,
    };

    expect(() => ReconOutputSchema.parse(recon)).not.toThrow();
    expect(validateReconGate(recon).pass).toBe(true);
  });
});

describe('integration: config resolution', () => {
  it('full config chain works', () => {
    const config = resolveConfig({
      provider: 'openai',
      model: 'gpt-4.1',
      fuzzTimeout: 300,
      maxRetries: 3,
    });

    expect(config.provider).toBe('openai');
    expect(config.model).toBe('gpt-4.1');
    expect(config.fuzz.timeout).toBe(300);
    expect(config.exploit.maxRetries).toBe(3);
    expect(config.parallel).toBe(4);
  });
});

describe('integration: verification gates', () => {
  it('full gate chain validates correctly', () => {
    const recon = ReconOutputSchema.parse({
      target: { path: './x', arch: 'amd64', bits: 64, endian: 'little', stripped: false },
      protections: { nx: true, canary: false, pie: false, relro: 'partial', fortify: false },
      symbols: ['main'],
      functions: [{ name: 'vuln', decompiled: 'gets(buf)', rank: 5, notes: 'gets' }],
      viable_strategies: ['rop'],
      leaks_needed: ['libc_base'],
    });

    expect(validateReconGate(recon).pass).toBe(true);

    const hunter = HunterOutputSchema.parse({
      hypotheses: [{
        function: 'vuln', vuln_class: 'stack_overflow', location: 'buf',
        trigger: 'cyclic(200)', primitive: 'controlled_rip',
        constraints: { bad_bytes: [] }, status: 'confirmed',
        gdb_evidence: { registers: { rip: '0x41414141' }, backtrace: ['#0 0x41414141'], controlled_bytes: 72 },
      }],
      confirmed_vulns: [{
        function: 'vuln', vuln_class: 'stack_overflow', location: 'buf',
        trigger: 'cyclic(200)', primitive: 'controlled_rip',
        constraints: { bad_bytes: [] }, status: 'confirmed',
        gdb_evidence: { registers: { rip: '0x41414141' }, backtrace: ['#0 0x41414141'], controlled_bytes: 72 },
      }],
      harnesses: [],
      source_findings: [],
    });

    expect(validateHunterGate(hunter).pass).toBe(true);
  });
});
