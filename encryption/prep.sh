#!/usr/bin/env bash
# prep.sh — decrypt entry (plaintext by design: must run before any ciphertext
# is opened). Keeps the long decrypt flags out of the workflow log; the log
# only shows this entry name and the mode digit.
#   1 = verify everything, write nothing
#   2 = re-verify and materialize plaintext in place
set -Eeuo pipefail
case "${1:?}" in
  1) exec python3 encryption/decrypt.py decrypt --verify-only --enc encrypted --manifest encryption/manifest.tsv --out . ;;
  2) exec python3 encryption/decrypt.py decrypt --enc encrypted --manifest encryption/manifest.tsv --out . ;;
  *) echo "::error::bad mode" >&2; exit 9 ;;
esac
