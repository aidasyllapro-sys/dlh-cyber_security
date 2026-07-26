#!/bin/bash
#
# 3-hash_verify.sh
#
# MedDefense Health Systems -- File Integrity Verification
#
# Computes the SHA-256 hash of a file and compares it against an
# expected hash value, reporting a clear pass/fail result with a
# matching exit code so this script can be used directly in automated
# backup or patch-verification pipelines.
#
# Usage:
#   ./3-hash_verify.sh <file_path> <expected_sha256_hash>

set -uo pipefail

# --- Argument validation ------------------------------------------------

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <file_path> <expected_sha256_hash>" >&2
    exit 1
fi

FILE_PATH="$1"
EXPECTED_HASH="$2"

if [ ! -f "$FILE_PATH" ]; then
    echo "Error: file '$FILE_PATH' not found." >&2
    exit 1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "Error: sha256sum is not installed or not on PATH." >&2
    exit 1
fi

# Normalize both hashes to lowercase before comparing, since hash values
# are case-insensitive hex but a human-typed "expected" value could
# plausibly arrive in uppercase.
EXPECTED_HASH_NORMALIZED=$(echo "$EXPECTED_HASH" | tr '[:upper:]' '[:lower:]')

# --- Compute and compare -------------------------------------------------

ACTUAL_HASH=$(sha256sum "$FILE_PATH" | awk '{print $1}')
ACTUAL_HASH_NORMALIZED=$(echo "$ACTUAL_HASH" | tr '[:upper:]' '[:lower:]')

if [ "$ACTUAL_HASH_NORMALIZED" = "$EXPECTED_HASH_NORMALIZED" ]; then
    echo "INTEGRITY OK"
    exit 0
else
    echo "INTEGRITY FAILED - expected $EXPECTED_HASH got $ACTUAL_HASH"
    exit 1
fi
