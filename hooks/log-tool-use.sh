#!/usr/bin/env bash
# Claude Code post-tool-use hook
# Reads tool use JSON from stdin, appends to run_log.jsonl
set -euo pipefail

OUTPUT_DIR="${AGENT_FUZZ_OUTPUT:-$PWD/output}"
LOG_FILE="$OUTPUT_DIR/run_log.jsonl"
SESSION_ID="${CLAUDE_SESSION_ID:-claude-$(date +%s)}"

mkdir -p "$OUTPUT_DIR"

# Read tool context from stdin
TOOL_JSON=$(cat)

# Extract fields
if command -v jq &>/dev/null; then
  TOOL_NAME=$(echo "$TOOL_JSON" | jq -r '.tool_name // "unknown"')
  TOOL_INPUT=$(echo "$TOOL_JSON" | jq -c '.input // {}')
  TOOL_OUTPUT=$(echo "$TOOL_JSON" | jq -c '.output // ""')
else
  TOOL_NAME=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('tool_name','unknown'))" <<< "$TOOL_JSON" 2>/dev/null || echo "unknown")
  TOOL_INPUT=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('input',{})))" <<< "$TOOL_JSON" 2>/dev/null || echo "{}")
  TOOL_OUTPUT=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('output','')))" <<< "$TOOL_JSON" 2>/dev/null || echo '""')
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")

printf '{"timestamp":"%s","run_id":"%s","source":"claude-code","event_type":"agent.tool_use","payload":{"tool_name":"%s","input":%s,"output":%s}}\n' \
  "$TIMESTAMP" "$SESSION_ID" "$TOOL_NAME" "$TOOL_INPUT" "$TOOL_OUTPUT" >> "$LOG_FILE"
