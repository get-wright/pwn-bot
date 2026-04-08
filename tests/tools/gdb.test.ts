import { describe, it, expect } from 'vitest';
import { parseGdbOutput } from '../../src/tools/gdb.js';

describe('parseGdbOutput', () => {
  it('extracts registers (rip, rsp) and backtrace from raw GDB output', () => {
    const raw = `
GNU gdb (Ubuntu 12.1) 12.1
(gdb) info registers
rax            0x0                 0
rbx            0x0                 0
rcx            0x7ffff7af4a77      140737348742775
rdx            0x0                 0
rsp            0x7fffffffe4a0      0x7fffffffe4a0
rip            0x4141414141414141  0x4141414141414141
(gdb) backtrace
#0  0x4141414141414141 in ?? ()
#1  0x00007fffffffe4b8 in ?? ()
#2  0x0000000000000000 in ?? ()
    `.trim();

    const result = parseGdbOutput(raw);

    expect(result.registers['rip']).toBe('0x4141414141414141');
    expect(result.registers['rsp']).toBe('0x7fffffffe4a0');
    expect(result.backtrace).toHaveLength(3);
    expect(result.backtrace[0]).toContain('0x4141414141414141');
  });
});
