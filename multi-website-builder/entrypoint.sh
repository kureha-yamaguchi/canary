#!/usr/bin/env bash
set -euo pipefail

cd /site

PROMPT_FILE="/site/prompt.txt"
LOG_DIR="/site/logs"
DEV_LOG="${LOG_DIR}/dev.log"
RUN_LOG="${LOG_DIR}/run.log"
CLAUDE_LOG="${LOG_DIR}/claude.log"
MAX_ATTEMPTS=3

if [ ! -s "$PROMPT_FILE" ]; then
  echo "Prompt file not found or empty at $PROMPT_FILE"
  exit 1
fi

mkdir -p /site "$LOG_DIR"
: > "$DEV_LOG"
: > "$RUN_LOG"
: > "$CLAUDE_LOG"

log() {
  echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*" | tee -a "$RUN_LOG"
}

set -a; source .env.local; set +a;

CLAUDE_PROMPT="$(cat "$PROMPT_FILE")"
{
  echo "===== Prompt used ====="
  echo "$CLAUDE_PROMPT"
  echo "======================="
} >> "$RUN_LOG"

run_claude() {
  local prompt="$1"
  log "Running Claude Code to create app..."
  IS_SANDBOX=1 claude -p --max-turns 500 \
    --output-format text \
    --dangerously-skip-permissions \
    "$prompt" 2>&1 | tee -a "$CLAUDE_LOG" | tee -a "$RUN_LOG"
}

attempt=1
while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
  prompt_to_use="$CLAUDE_PROMPT"

  if [ "$attempt" -gt 1 ] && [ -f "$DEV_LOG" ]; then
    error_context="$(tail -n 200 "$DEV_LOG" || true)"
    prompt_to_use="$CLAUDE_PROMPT

The last dev server attempt failed with exit code ${dev_exit_code:-1}.
Here are the recent logs:
${error_context}

Please fix the project accordingly and stop when ready."
  fi

  log "Attempt $attempt/$MAX_ATTEMPTS: generating code with Claude..."
  run_claude "$prompt_to_use"

  log "Installing dependencies..."
  npm install

  log "Starting Next.js dev server on port 3000..."
  set +e
  npm run dev -- --hostname 0.0.0.0 --port 3000 2>&1 | tee "$DEV_LOG" | tee -a "$RUN_LOG"
  dev_exit_code=${PIPESTATUS[0]}
  set -e

  if [ "$dev_exit_code" -eq 0 ]; then
    log "Dev server exited cleanly."
    exit 0
  fi

  if [ "$attempt" -eq "$MAX_ATTEMPTS" ]; then
    log "Dev server failed after $MAX_ATTEMPTS attempt(s). Check $DEV_LOG for details."
    exit "$dev_exit_code"
  fi

  log "Dev server failed (exit $dev_exit_code). Re-running Claude with error context..."
  attempt=$((attempt + 1))
done
