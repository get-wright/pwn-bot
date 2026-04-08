# Agent Fuzz - Binary Exploitation Tools

## Available Commands

| Command | Description |
|---------|-------------|
| `agent-fuzz pwn <binary>` | Full pipeline: recon -> hunt -> exploit |
| `agent-fuzz recon <binary>` | Analyze binary protections and structure |
| `agent-fuzz hunt <binary>` | Find vulnerabilities with LLM + debugging |
| `agent-fuzz fuzz <binary>` | AFL++ fuzzing only |
| `agent-fuzz exploit <binary>` | Generate exploit from existing analysis |
| `agent-fuzz full <binary>` | Fuzz + hunt in parallel |
| `agent-fuzz batch <dir>` | Process multiple challenges |

## Common Options

- `--libc <path>` - Path to libc for offset calculation
- `--source <dir>` - Source code directory
- `--remote <host:port>` - Remote target for exploit testing
- `--provider openai` - Use OpenAI models (default for Codex)
- `--model <name>` - Model override
- `--output <dir>` - Output directory (default: ./output)

## Interactive Analysis

For hands-on work, use the tools directly:

```bash
checksec --file=<binary>
file <binary>
python3 -c "from pwn import *; print(ELF('<binary>').checksec())"
python3 -c "from pwn import *; print(cyclic(200))" | gdb -batch -ex run -ex 'info reg' <binary>
ROPgadget --binary <binary> --only "pop|ret"
one_gadget <libc>
```

## Output

All artifacts in ./output/:
- recon.json, hunter.json, exploit.py, harnesses/, crashes/
