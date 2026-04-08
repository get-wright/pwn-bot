import { describe, it, expect } from 'vitest';
import {
  ReconOutputSchema,
  HypothesisSchema,
  HunterOutputSchema,
} from '../src/types.js';

const validTarget = {
  path: '/bin/vuln',
  arch: 'amd64',
  bits: 64,
  endian: 'little',
  stripped: false,
};

const validProtections = {
  nx: true,
  canary: false,
  pie: false,
  relro: 'partial',
  fortify: false,
};

const validRecon = {
  target: validTarget,
  protections: validProtections,
  symbols: ['main', 'vuln', 'win'],
  functions: [
    {
      name: 'vuln',
      decompiled: 'void vuln() { char buf[64]; gets(buf); }',
      notes: 'classic stack overflow via gets',
      rank: 5,
    },
  ],
  viable_strategies: ['ret2win', 'rop'],
  leaks_needed: [],
};

describe('ReconOutputSchema', () => {
  it('parses a valid full recon output', () => {
    const result = ReconOutputSchema.safeParse(validRecon);
    expect(result.success).toBe(true);
  });

  it('rejects invalid arch', () => {
    const bad = { ...validRecon, target: { ...validTarget, arch: 'sparc' } };
    const result = ReconOutputSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it('accepts optional libc field', () => {
    const withLibc = {
      ...validRecon,
      libc: {
        version: '2.35',
        offsets: { system: 0x50d70, puts: 0x80ed0 },
        one_gadgets: [
          { address: 0xebcf8, constraints: ['[rsp+0x78] == NULL'] },
        ],
      },
    };
    const result = ReconOutputSchema.safeParse(withLibc);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.libc?.version).toBe('2.35');
    }
  });
});

describe('HypothesisSchema', () => {
  it('parses a confirmed hypothesis with GDB evidence', () => {
    const hyp = {
      function: 'vuln',
      location: '0x401234',
      trigger: 'send >64 bytes to stdin',
      vuln_class: 'stack_overflow',
      primitive: 'controlled_rip',
      constraints: { bad_bytes: ['\x00', '\x0a'] },
      status: 'confirmed',
      gdb_evidence: {
        registers: { rip: '0x4141414141414141', rsp: '0x7fffffffe4a0' },
        backtrace: ['#0 0x4141414141414141', '#1 vuln ()'],
        controlled_bytes: 72,
      },
    };
    const result = HypothesisSchema.safeParse(hyp);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status).toBe('confirmed');
      expect(result.data.gdb_evidence?.controlled_bytes).toBe(72);
    }
  });

  it('rejects unknown vuln_class', () => {
    const bad = {
      function: 'login',
      location: '0x402000',
      trigger: "' OR 1=1--",
      vuln_class: 'sql_injection',
      primitive: 'arbitrary_read',
      constraints: { bad_bytes: [] },
      status: 'pending',
    };
    const result = HypothesisSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });
});

describe('HunterOutputSchema', () => {
  it('parses output with harnesses', () => {
    const hyp = {
      function: 'vuln',
      location: '0x401234',
      trigger: 'long input',
      vuln_class: 'stack_overflow',
      primitive: 'controlled_rip',
      constraints: { bad_bytes: [] },
      status: 'confirmed',
    };
    const hunter = {
      hypotheses: [hyp],
      confirmed_vulns: [hyp],
      harnesses: [
        {
          path: 'harnesses/vuln_harness.c',
          target_function: 'vuln',
          strategy: 'afl_persistent',
        },
      ],
      source_findings: ['gets() call at 0x401250'],
    };
    const result = HunterOutputSchema.safeParse(hunter);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.harnesses).toHaveLength(1);
      expect(result.data.harnesses[0].strategy).toBe('afl_persistent');
    }
  });
});
