import { describe, it, expect } from 'vitest';
import { validateReconGate, validateHunterGate } from '../src/pipeline.js';
import { ReconOutput, HunterOutput } from '../src/types.js';

const baseTarget: ReconOutput['target'] = {
  path: '/bin/test',
  arch: 'amd64',
  bits: 64,
  endian: 'little',
  stripped: false,
};

const baseProtections: ReconOutput['protections'] = {
  nx: true,
  canary: false,
  pie: false,
  relro: 'partial',
  fortify: false,
};

describe('verification gates', () => {
  it('recon gate passes with ranked functions', () => {
    const recon: ReconOutput = {
      target: baseTarget,
      protections: baseProtections,
      symbols: [],
      functions: [{ name: 'vuln', decompiled: 'void vuln() {}', notes: '', rank: 5 }],
      viable_strategies: ['ret2libc'],
      leaks_needed: ['libc_base'],
    };

    const result = validateReconGate(recon);

    expect(result.pass).toBe(true);
  });

  it('recon gate fails with no functions', () => {
    const recon: ReconOutput = {
      target: baseTarget,
      protections: baseProtections,
      symbols: [],
      functions: [],
      viable_strategies: [],
      leaks_needed: [],
    };

    const result = validateReconGate(recon);

    expect(result.pass).toBe(false);
    expect(result.reason).toMatch(/no analyzable functions/i);
  });

  it('hunter gate passes with confirmed vuln', () => {
    const hunter: HunterOutput = {
      hypotheses: [
        {
          function: 'vuln',
          location: '0x401234',
          trigger: 'AAAA',
          vuln_class: 'stack_overflow',
          primitive: 'controlled_rip',
          constraints: { bad_bytes: [] },
          status: 'confirmed',
        },
      ],
      confirmed_vulns: [],
      harnesses: [],
      source_findings: [],
    };

    const result = validateHunterGate(hunter);

    expect(result.pass).toBe(true);
  });

  it('hunter gate fails with no confirmed vulns', () => {
    const hunter: HunterOutput = {
      hypotheses: [
        {
          function: 'vuln',
          location: '0x401234',
          trigger: 'AAAA',
          vuln_class: 'stack_overflow',
          primitive: 'controlled_rip',
          constraints: { bad_bytes: [] },
          status: 'rejected',
        },
      ],
      confirmed_vulns: [],
      harnesses: [],
      source_findings: [],
    };

    const result = validateHunterGate(hunter);

    expect(result.pass).toBe(false);
  });
});
