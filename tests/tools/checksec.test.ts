import { describe, it, expect } from 'vitest';
import { parseChecksecOutput } from '../../src/tools/checksec.js';

describe('parseChecksecOutput', () => {
  it('parses partial relro, no canary, nx yes, no pie', () => {
    const binaryPath = '/bin/vuln';
    const raw = JSON.stringify({
      [binaryPath]: {
        nx: 'yes',
        stack_canary: 'no',
        pie: 'no',
        relro: 'partial',
        fortify_source: 'no',
      },
    });

    const result = parseChecksecOutput(raw, binaryPath);

    expect(result.nx).toBe(true);
    expect(result.canary).toBe(false);
    expect(result.pie).toBe(false);
    expect(result.relro).toBe('partial');
    expect(result.fortify).toBe(false);
  });

  it('parses full relro + pie + canary + fortify', () => {
    const binaryPath = '/bin/hardened';
    const raw = JSON.stringify({
      [binaryPath]: {
        nx: 'yes',
        stack_canary: 'yes',
        pie: 'yes',
        relro: 'full',
        fortify_source: 'yes',
      },
    });

    const result = parseChecksecOutput(raw, binaryPath);

    expect(result.nx).toBe(true);
    expect(result.canary).toBe(true);
    expect(result.pie).toBe(true);
    expect(result.relro).toBe('full');
    expect(result.fortify).toBe(true);
  });
});
