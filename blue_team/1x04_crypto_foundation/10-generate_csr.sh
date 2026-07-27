#!/bin/bash
#
# 10-generate_csr.sh
#
# MedDefense Health Systems -- Key and CSR Generation Automation
#
# Automates steps 1 through 3 of the certificate lifecycle: private key
# generation, CSR creation, and CSR inspection/verification. Steps 4
# onward (CA submission, validation, issuance, installation) require
# interaction with an external Certificate Authority and are described
# as a procedure, not automated here, in 10-csr_workshop.md.
#
# Usage:
#   ./10-generate_csr.sh <common_name> <output_prefix> [san1,san2,...]
#
#   <common_name>   The primary hostname, e.g. portal.meddefense.local
#   <output_prefix> Base name for output files, e.g. portal
#                     produces <output_prefix>_key.pem and
#                     <output_prefix>.csr
#   [san1,san2,...] Optional comma-separated list of additional SAN
#                     DNS entries. The common name is always included
#                     as the first SAN automatically, since modern
#                     certificate validation relies on the SAN
#                     extension, not the deprecated Common Name field
#                     alone (Task 8 of this project).
#
# Organization fields (O, OU, L, ST, C) are fixed to MedDefense's own
# values below rather than accepted as arguments, since these should
# not vary between certificate requests issued by this organization.

set -uo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <common_name> <output_prefix> [san1,san2,...]" >&2
    exit 1
fi

COMMON_NAME="$1"
OUTPUT_PREFIX="$2"
EXTRA_SANS="${3:-}"

KEY_FILE="${OUTPUT_PREFIX}_key.pem"
CSR_FILE="${OUTPUT_PREFIX}.csr"
CONFIG_FILE="${OUTPUT_PREFIX}_openssl.cnf"

if ! command -v openssl >/dev/null 2>&1; then
    echo "Error: openssl is not installed or not on PATH." >&2
    exit 1
fi

# --- Step 1: Private key generation (ECC P-256) --------------------------
# ECC P-256 is used rather than RSA, matching this project's own
# Algorithm Reference Table (Task 6) and certificate profile
# recommendation (Task 8): equivalent security to RSA-2048 at a
# fraction of the computational cost, with essentially universal
# support across any client capable of a modern TLS handshake.

echo "Step 1: Generating ECC P-256 private key..."
if ! openssl ecparam -genkey -name prime256v1 -out "$KEY_FILE"; then
    echo "Error: key generation failed." >&2
    exit 1
fi
chmod 600 "$KEY_FILE"
echo "  Private key written to: $KEY_FILE (permissions restricted to owner)"
echo ""

# --- Step 2: CSR generation ------------------------------------------------

echo "Step 2: Generating CSR for CN=$COMMON_NAME..."

# Build the SAN list: the common name is always included first.
SAN_LIST="DNS:${COMMON_NAME}"
if [ -n "$EXTRA_SANS" ]; then
    IFS=',' read -ra SAN_ARRAY <<< "$EXTRA_SANS"
    for san in "${SAN_ARRAY[@]}"; do
        SAN_LIST="${SAN_LIST},DNS:${san}"
    done
fi

cat > "$CONFIG_FILE" << EOF
[ req ]
default_bits       = 256
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
CN = ${COMMON_NAME}
O  = MedDefense Health Systems
OU = Information Technology
L  = Springfield
ST = Illinois
C  = US

[ req_ext ]
subjectAltName = ${SAN_LIST}
EOF

if ! openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -config "$CONFIG_FILE"; then
    echo "Error: CSR generation failed." >&2
    exit 1
fi
echo "  CSR written to: $CSR_FILE"
echo "  Config file written to: $CONFIG_FILE"
echo ""

# --- Step 3: CSR inspection and verification ------------------------------

echo "Step 3: Verifying CSR signature..."
if ! openssl req -in "$CSR_FILE" -noout -verify; then
    echo "Error: CSR signature verification failed." >&2
    exit 1
fi
echo ""

echo "Step 3: CSR field summary..."
echo "--------------------------------------------------------------"
openssl req -in "$CSR_FILE" -noout -subject
openssl req -in "$CSR_FILE" -noout -text | grep -A2 "Subject Alternative Name"
openssl req -in "$CSR_FILE" -noout -text | grep "Public Key Algorithm"
echo "--------------------------------------------------------------"
echo ""
echo "Done. Next step: submit $CSR_FILE to the Certificate Authority."
echo "See 10-csr_workshop.md, Part 4, for the full remaining lifecycle."
