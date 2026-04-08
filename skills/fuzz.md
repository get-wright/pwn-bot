---
name: fuzz
description: Run AFL++ fuzzing against a binary target
---

Run AFL++ fuzzing via the orchestrator:

```bash
agent-fuzz fuzz {{args}}
```

This: runs recon, generates harness, compiles with afl-clang-fast, runs afl-fuzz, triages crashes.

Options:
- `--fuzz-timeout <seconds>` (default: 600)
- `--source <dir>` for targeted harness generation
