#!/bin/bash
#
# 5-sign_verify.sh
#
# MedDefense Health Systems -- Digital Signature Automation
#
# Signs a file with SHA-256 and an RSA private key, or verifies an
# existing signature against a file and an RSA public key. Built for
# exactly the kind of record this program's own context describes:
# prescriptions, consent forms, and audit logs where integrity,
# authentication, and non-repudiation are not optional properties.
#
# Usage:
#   Sign:   ./5-sign_verify.sh sign <file_path> <private_key_path>
#             Produces <file_path>.sig
#   Verify: ./5-sign_verify.sh verify <file_path> <signature_path> <public_key_path>
#             Prints the verification result

set -uo pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage:" >&2
    echo "  $0 sign <file_path> <private_key_path>" >&2
    echo "  $0 verify <file_path> <signature_path> <public_key_path>" >&2
    exit 1
fi

MODE="$1"

if ! command -v openssl >/dev/null 2>&1; then
    echo "Error: openssl is not installed or not on PATH." >&2
    exit 1
fi

# --- Sign mode ------------------------------------------------------------

if [ "$MODE" = "sign" ]; then
    if [ "$#" -ne 3 ]; then
        echo "Usage: $0 sign <file_path> <private_key_path>" >&2
        exit 1
    fi

    FILE_PATH="$2"
    PRIVATE_KEY_PATH="$3"

    if [ ! -f "$FILE_PATH" ]; then
        echo "Error: file '$FILE_PATH' not found." >&2
        exit 1
    fi

    if [ ! -f "$PRIVATE_KEY_PATH" ]; then
        echo "Error: private key '$PRIVATE_KEY_PATH' not found." >&2
        exit 1
    fi

    SIGNATURE_PATH="${FILE_PATH}.sig"

    if ! openssl dgst -sha256 -sign "$PRIVATE_KEY_PATH" -out "$SIGNATURE_PATH" "$FILE_PATH"; then
        echo "Error: signing failed." >&2
        exit 1
    fi

    echo "Signed: $FILE_PATH"
    echo "Signature written to: $SIGNATURE_PATH"
    exit 0
fi

# --- Verify mode ------------------------------------------------------------

if [ "$MODE" = "verify" ]; then
    if [ "$#" -ne 4 ]; then
        echo "Usage: $0 verify <file_path> <signature_path> <public_key_path>" >&2
        exit 1
    fi

    FILE_PATH="$2"
    SIGNATURE_PATH="$3"
    PUBLIC_KEY_PATH="$4"

    for path in "$FILE_PATH" "$SIGNATURE_PATH" "$PUBLIC_KEY_PATH"; do
        if [ ! -f "$path" ]; then
            echo "Error: '$path' not found." >&2
            exit 1
        fi
    done

    if openssl dgst -sha256 -verify "$PUBLIC_KEY_PATH" -signature "$SIGNATURE_PATH" "$FILE_PATH"; then
        echo "VERIFICATION OK: $FILE_PATH matches signature $SIGNATURE_PATH"
        exit 0
    else
        echo "VERIFICATION FAILED: $FILE_PATH does not match signature $SIGNATURE_PATH" >&2
        echo "This means either the file was modified after signing, or the" >&2
        echo "wrong public key/signature pair was used." >&2
        exit 1
    fi
fi

# --- Unknown mode -----------------------------------------------------------

echo "Error: mode must be 'sign' or 'verify', got '$MODE'." >&2
exit 1
