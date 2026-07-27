#!/bin/bash
#
# 12-luks_manager.sh
#
# MedDefense Health Systems -- LUKS Volume Management Automation
#
# Creates, opens, and closes a LUKS-encrypted volume backed by a file
# (a loop device target).
#
# Usage:
#   ./12-luks_manager.sh create <volume_file> <size_MB> <mapper_name>
#   ./12-luks_manager.sh open   <volume_file> <mapper_name> <mount_point>
#   ./12-luks_manager.sh close  <mapper_name> <mount_point>

set -uo pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage:" >&2
    echo "  $0 create <volume_file> <size_MB> <mapper_name>" >&2
    echo "  $0 open   <volume_file> <mapper_name> <mount_point>" >&2
    echo "  $0 close  <mapper_name> <mount_point>" >&2
    exit 1
fi

MODE="$1"

if ! command -v cryptsetup >/dev/null 2>&1; then
    echo "Error: cryptsetup is not installed. On Debian/Ubuntu:" >&2
    echo "  sudo apt install cryptsetup" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root (LUKS and loop device" >&2
    echo "operations require root privileges)." >&2
    exit 1
fi

# --- create mode ------------------------------------------------------------

if [ "$MODE" = "create" ]; then
    if [ "$#" -ne 4 ]; then
        echo "Usage: $0 create <volume_file> <size_MB> <mapper_name>" >&2
        exit 1
    fi
    VOLUME_FILE="$2"
    SIZE_MB="$3"
    MAPPER_NAME="$4"

    if [ -e "$VOLUME_FILE" ]; then
        echo "Error: '$VOLUME_FILE' already exists; refusing to overwrite." >&2
        exit 1
    fi

    echo "Creating a ${SIZE_MB}MB backing file at $VOLUME_FILE..."
    if ! dd if=/dev/zero of="$VOLUME_FILE" bs=1M count="$SIZE_MB" status=progress; then
        echo "Error: failed to create backing file." >&2
        exit 1
    fi

    echo "Formatting $VOLUME_FILE with LUKS..."
    echo "You will be prompted to confirm and to set a passphrase."
    if ! cryptsetup luksFormat "$VOLUME_FILE"; then
        echo "Error: luksFormat failed." >&2
        rm -f "$VOLUME_FILE"
        exit 1
    fi

    echo "Opening the new volume as /dev/mapper/$MAPPER_NAME to build a filesystem..."
    if ! cryptsetup luksOpen "$VOLUME_FILE" "$MAPPER_NAME"; then
        echo "Error: luksOpen failed immediately after formatting." >&2
        exit 1
    fi

    echo "Creating an ext4 filesystem on /dev/mapper/$MAPPER_NAME..."
    if ! mkfs.ext4 -q "/dev/mapper/$MAPPER_NAME"; then
        echo "Error: mkfs.ext4 failed." >&2
        cryptsetup luksClose "$MAPPER_NAME"
        exit 1
    fi

    cryptsetup luksClose "$MAPPER_NAME"
    echo "Volume created and closed. Use 'open' mode to mount it for use."
    exit 0
fi

# --- open mode --------------------------------------------------------------

if [ "$MODE" = "open" ]; then
    if [ "$#" -ne 4 ]; then
        echo "Usage: $0 open <volume_file> <mapper_name> <mount_point>" >&2
        exit 1
    fi
    VOLUME_FILE="$2"
    MAPPER_NAME="$3"
    MOUNT_POINT="$4"

    if [ ! -f "$VOLUME_FILE" ]; then
        echo "Error: volume file '$VOLUME_FILE' not found." >&2
        exit 1
    fi

    echo "Opening $VOLUME_FILE as /dev/mapper/$MAPPER_NAME..."
    echo "You will be prompted for the passphrase."
    if ! cryptsetup luksOpen "$VOLUME_FILE" "$MAPPER_NAME"; then
        echo "Error: luksOpen failed. Wrong passphrase, or volume already open?" >&2
        exit 1
    fi

    mkdir -p "$MOUNT_POINT"
    if ! mount "/dev/mapper/$MAPPER_NAME" "$MOUNT_POINT"; then
        echo "Error: mount failed after successful luksOpen." >&2
        cryptsetup luksClose "$MAPPER_NAME"
        exit 1
    fi

    echo "Volume open and mounted at $MOUNT_POINT."
    exit 0
fi

# --- close mode -------------------------------------------------------------

if [ "$MODE" = "close" ]; then
    if [ "$#" -ne 3 ]; then
        echo "Usage: $0 close <mapper_name> <mount_point>" >&2
        exit 1
    fi
    MAPPER_NAME="$2"
    MOUNT_POINT="$3"

    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        if ! umount "$MOUNT_POINT"; then
            echo "Error: umount failed. Is a program still using $MOUNT_POINT?" >&2
            exit 1
        fi
    fi

    if ! cryptsetup luksClose "$MAPPER_NAME"; then
        echo "Error: luksClose failed." >&2
        exit 1
    fi

    echo "Volume unmounted and closed."
    exit 0
fi

echo "Error: mode must be 'create', 'open', or 'close', got '$MODE'." >&2
exit 1
