#!/usr/bin/env bash
# Codex CLI wrapper that captures session logs into run_log.jsonl
set -euo pipefail

OUTPUT_DIR="${AGENT_FUZZ_OUTPUT:-$PWD/output}"
LOG_FILE="$OUTPUT_DIR/run_log.jsonl"
RUN_ID="codex-$(date +%s)-$$"

mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")

# Log pipeline start
printf '{"timestamp":"%s","run_id":"%s","source":"codex","event_type":"pipeline.start","payload":{"args":"%s"}}\n' \
  "$TIMESTAMP" "$RUN_ID" "$*" >> "$LOG_FILE"

START_TIME=$(date +%s)

# Run codex, capture output
CODEX_OUTPUT=$(mktemp)
codex "$@" 2>&1 | tee "$CODEX_OUTPUT"
CODEX_EXIT=$?

END_TIME=$(date +%s)
DURATION_MS=$(( (END_TIME - START_TIME) * 1000 ))

# Parse Codex logs if available
CODEX_LOG_DIR="${HOME}/.codex/logs"
if [ -d "$CODEX_LOG_DIR" ]; then
  LATEST_LOG=$(find "$CODEX_LOG_DIR" -name "*.log" -newer "$CODEX_OUTPUT" -type f 2>/dev/null | sort | tail -1)

  if [ -n "$LATEST_LOG" ] && [ -f "$LATEST_LOG" ]; then
    while IFS= read -r line; do
      TOOL_NAME=$(echo "$line" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name',''))" 2>/dev/null || true)
      if [ -n "$TOOL_NAME" ]; then
        TOOL_INPUT=$(echo "$line" | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('input',{})))" 2>/dev/null || echo "{}")
        TOOL_OUTPUT=$(echo "$line" | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('output','')))" 2>/dev/null || echo '""')
        TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        printf '{"timestamp":"%s","run_id":"%s","source":"codex","event_type":"agent.tool_use","payload":{"tool_name":"%s","input":%s,"output":%s}}\n' \
          "$TS" "$RUN_ID" "$TOOL_NAME" "$TOOL_INPUT" "$TOOL_OUTPUT" >> "$LOG_FILE"
      fi
    done < "$LATEST_LOG"
  fi
fi

# Log pipeline end
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
printf '{"timestamp":"%s","run_id":"%s","source":"codex","event_type":"pipeline.end","duration_ms":%d,"payload":{"exit_code":%d,"success":%s}}\n' \
  "$TIMESTAMP" "$RUN_ID" "$DURATION_MS" "$CODEX_EXIT" "$([ $CODEX_EXIT -eq 0 ] && echo true || echo false)" >> "$LOG_FILE"

rm -f "$CODEX_OUTPUT"
exit $CODEX_EXIT
