---
name: pwn-recon
description: Analyze a C/C++ binary for security properties, protections, and attack surface
---

## Input
The user provides a binary path, optionally with source dir, libc, or remote target.

## Process

1. **Run checksec**: `checksec --file={{binary}}`
   Report: NX, canary, PIE, RELRO, Fortify status.

2. **Identify binary properties**: `file {{binary}}`
   Report: architecture, linking, stripped status.

3. **Extract symbols**: `nm -D {{binary}} 2>/dev/null; readelf -s {{binary}} | grep FUNC`
   Look for: system, execve, win, flag, or other interesting names.

4. **Extract strings**: `strings {{binary}} | grep -iE 'flag|password|admin|/bin/sh|system'`

5. **Decompile** (if Ghidra available):
   `analyzeHeadless /tmp/ghidra proj -import {{binary}} -postScript DecompileAllFunctions.py /tmp/decompiled.json -deleteProject`
   If Ghidra unavailable: `objdump -d -M intel {{binary}}`

6. **Libc identification** (if libc provided):
   `one_gadget {{libc}}`
   `python3 -c "from pwn import *; e=ELF('{{libc}}',checksec=False); print(hex(e.symbols['system']), hex(next(e.search(b'/bin/sh'))))"`

7. **Rank functions** by vulnerability likelihood (1-5):
   - 5: User input handling (gets, read, scanf, recv)
   - 4: Memory/string ops (printf, strcpy, malloc/free)
   - 3: Control flow logic
   - 2: Init/config utilities
   - 1: Runtime stubs

8. **Assess protections** and determine viable strategies.

9. **Write output/recon.json** with all findings.

## Output
Present findings to user. Highlight top-ranked functions, viable strategies, required leaks.
