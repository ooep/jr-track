#!/usr/bin/env bash
# finalize.sh — always-on cleanup/verification step. Plaintext by design: it
# must work even when the decrypt step never succeeded, and it carries no
# business identifiers. Optional $1 is an extra scratch path to remove.
set -uo pipefail
extra="${1:-}"
python3 encryption/decrypt.py clean --out . >/dev/null 2>&1 || true
if [ -n "$extra" ]; then
  rm -rf "$extra"
fi
if [ -n "$(git status --porcelain)" ]; then
  echo "::error::worktree not clean"
  git status --porcelain | python3 encryption/shellredact.py
  exit 9
fi
echo "STEP OK"
