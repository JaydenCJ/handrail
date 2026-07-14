#!/usr/bin/env bash
# A minimal pre/post guardrail gate around any command that turns a prompt
# into a reply. Here the "model" is a stand-in `sed`; swap in your real
# inference call. Fully offline.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK="$ROOT/examples/packs/pii-basics.yaml"
HANDRAIL="${HANDRAIL:-$ROOT/handrail}"
if [ ! -x "$HANDRAIL" ]; then
  (cd "$ROOT" && go build -o "$HANDRAIL" ./cmd/handrail)
fi

PROMPT='Summarize the ticket from sam@example.test about the login bug.'

echo "== pre: sanitize the inbound prompt"
if ! SAFE_PROMPT="$(printf '%s' "$PROMPT" | "$HANDRAIL" check --pack "$PACK" --stage pre --redacted -)"; then
  echo "refused: prompt hit a block rule" >&2
  exit 1
fi
echo "model sees: $SAFE_PROMPT"

echo "== the model answers (stand-in)"
REPLY="$(printf '%s' "$SAFE_PROMPT" | sed 's/^Summarize/Summary of/')"

echo "== post: re-check the outbound reply"
if ! printf '%s' "$REPLY" | "$HANDRAIL" check --pack "$PACK" --stage post --redacted -; then
  echo "refused: reply hit a block rule" >&2
  exit 1
fi
echo
echo "gate: OK"
