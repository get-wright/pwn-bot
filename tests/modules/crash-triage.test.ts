import { describe, it, expect } from 'vitest';
import { classifyExploitability, deduplicateCrashes } from '../../src/modules/crash-triage.js';

describe('classifyExploitability', () => {
  it('rates controlled RIP as high', () => {
    const result = classifyExploitability({
      registers: { rip: '0x4141414141414141' },
      backtrace: ['#0  0x4141414141414141 in ??'],
      signal: 'SIGSEGV',
    });
    expect(result).toBe('high');
  });

  it('rates null deref as low', () => {
    const result = classifyExploitability({
      registers: { rip: '0x400f00' },
      backtrace: ['#0  0x400f00 in main'],
      signal: 'SIGSEGV',
      faultAddr: '0x0',
    });
    expect(result).toBe('low');
  });

  it('rates stack canary failure as medium', () => {
    const result = classifyExploitability({
      registers: { rip: '0x7ffff7a3c000' },
      backtrace: [
        '#0  0x7ffff7a3c000 in __stack_chk_fail',
        '#1  0x400abc in vulnerable_func',
      ],
      signal: 'SIGABRT',
    });
    expect(result).toBe('medium');
  });
});

describe('deduplicateCrashes', () => {
  it('deduplicates by stack hash', () => {
    const sharedBacktrace = [
      '#0  0xdeadbeef in foo',
      '#1  0xcafebabe in bar',
    ];

    const crashes = [
      { id: 'crash-1', backtrace: sharedBacktrace },
      { id: 'crash-2', backtrace: sharedBacktrace },
      { id: 'crash-3', backtrace: ['#0  0x11223344 in baz'] },
    ];

    const result = deduplicateCrashes(crashes);
    expect(result).toHaveLength(2);
  });
});
