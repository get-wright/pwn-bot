---
name: pwn-hunter
description: Interactively hunt for vulnerabilities in a C/C++ binary using hypothesis-driven analysis
---

## Prerequisites
Ensure recon exists. If no output/recon.json, run: `! agent-fuzz recon {{binary}}`
Read the recon output first.

## Process

For each function ranked 4-5 in recon.json:

### Phase A: Hypothesize
Read the decompiled code. For each potential vulnerability:
- What class? (stack_overflow, heap_uaf, format_string, etc.)
- Where exactly? (line, variable, buffer)
- What triggers it? (what input)
- What primitive? (controlled_rip, arbitrary_write, info_leak)
- What constraints? (bad bytes, length limits)

### Phase B: Confirm with GDB
```bash
python3 -c "from pwn import *; sys.stdout.buffer.write(cyclic(200))" > /tmp/payload
gdb -batch -ex "run < /tmp/payload" -ex "info registers" -ex "bt" {{binary}}
```
Check: Does RIP/EIP contain cyclic pattern? What offset?
```bash
python3 -c "from pwn import *; print(cyclic_find(0x<value_from_rip>))"
```

### Phase C: Confirm with ASan (if source available)
```bash
gcc -fsanitize=address -g -o target_asan {{source}}
./target_asan < /tmp/payload
```

### Phase D: Generate fuzz harness (if applicable)
Write an AFL++ harness targeting the vulnerable function.

Present findings after each function. Ask: continue hunting or proceed to exploit?
