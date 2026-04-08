---
name: pwn
description: Run the full automated exploitation pipeline (recon -> hunt -> exploit)
---

Run the agent-fuzz orchestrator:

```bash
agent-fuzz pwn {{args}}
```

This runs: recon -> hunt -> exploit. All artifacts written to ./output/.

Common usage:
- `! agent-fuzz pwn ./binary`
- `! agent-fuzz pwn ./binary --libc ./libc.so.6 --remote host:1337`
- `! agent-fuzz pwn ./binary --provider openai --model codex-mini-latest`
