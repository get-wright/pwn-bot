import { describe, it, expect } from 'vitest';
import { assessProtections, rankFunctions } from '../../src/modules/recon.js';
import { Protections } from '../../src/types.js';

describe('assessProtections', () => {
  it('identifies viable strategies for no-canary no-pie binary', () => {
    const protections: Protections = {
      nx: true,
      canary: false,
      pie: false,
      relro: 'partial',
      fortify: false,
    };

    const result = assessProtections(protections);

    expect(result.viable_strategies).toContain('ret2libc');
    expect(result.viable_strategies).toContain('rop');
    expect(result.viable_strategies).toContain('got_overwrite');
    expect(result.leaks_needed).toContain('libc_base');
    expect(result.leaks_needed).not.toContain('pie_base');
    expect(result.leaks_needed).not.toContain('canary');
  });

  it('identifies all leaks needed for fully protected binary', () => {
    const protections: Protections = {
      nx: true,
      canary: true,
      pie: true,
      relro: 'full',
      fortify: true,
    };

    const result = assessProtections(protections);

    expect(result.leaks_needed).toContain('canary');
    expect(result.leaks_needed).toContain('pie_base');
    expect(result.leaks_needed).toContain('libc_base');
    expect(result.viable_strategies).not.toContain('got_overwrite');
    expect(result.viable_strategies).not.toContain('shellcode');
  });

  it('includes shellcode when NX is disabled', () => {
    const protections: Protections = {
      nx: false,
      canary: false,
      pie: false,
      relro: 'no',
      fortify: false,
    };

    const result = assessProtections(protections);

    expect(result.viable_strategies).toContain('shellcode');
  });
});

describe('rankFunctions', () => {
  it('ranks input-handling functions as 5', () => {
    const functions = [
      {
        name: 'vuln',
        decompiled: 'void vuln() { char buf[64]; gets(buf); }',
        rank: 0 as const,
        notes: '' as const,
      },
      {
        name: '_start',
        decompiled: 'void _start() { __libc_start_main(main, argc, argv); }',
        rank: 0 as const,
        notes: '' as const,
      },
    ];

    const ranked = rankFunctions(functions);

    const vuln = ranked.find((f) => f.name === 'vuln');
    const start = ranked.find((f) => f.name === '_start');

    expect(vuln?.rank).toBe(5);
    expect(start?.rank).toBeLessThanOrEqual(2);
  });

  it('ranks format string usage as 4+', () => {
    const functions = [
      {
        name: 'fmt_vuln',
        decompiled: 'void fmt_vuln(char *msg) { printf(msg); }',
        rank: 0 as const,
        notes: '' as const,
      },
    ];

    const ranked = rankFunctions(functions);

    expect(ranked[0].rank).toBeGreaterThanOrEqual(4);
  });
});
