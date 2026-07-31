#!/usr/bin/env bash
# Builds flasher/manifest.json + flasher/firmware/*.bin from the current
# PlatformIO build, then (only with --deploy) rsyncs flasher/ to the
# flash.flink.club web root.
#
# Usage:
#   ./deploy.sh              # local build only: refreshes firmware/ + manifest.json
#   ./deploy.sh --no-build   # skip `pio run`, reuse existing .pio/build output
#   ./deploy.sh --deploy     # build, then rsync to the remote web root
#
# Deploy target (REMOTE_HOST/REMOTE_PATH/SSH_KEY) is read from deploy.env,
# which is gitignored — copy deploy.env.example to deploy.env and fill in
# your own server details before using --deploy.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLASHER_DIR="$REPO_ROOT/flasher"
BUILD_DIR="$REPO_ROOT/.pio/build/tdisplay-s3"
BOOT_APP0="$HOME/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin"

ENV_FILE="$FLASHER_DIR/deploy.env"

DO_BUILD=1
DO_DEPLOY=0
for arg in "$@"; do
  case "$arg" in
    --no-build) DO_BUILD=0 ;;
    --deploy) DO_DEPLOY=1 ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [[ "$DO_BUILD" -eq 1 ]]; then
  echo "==> pio run"
  ( cd "$REPO_ROOT" && "$HOME/.platformio-venv/bin/pio" run )
fi

for f in bootloader.bin partitions.bin firmware.bin; do
  [[ -f "$BUILD_DIR/$f" ]] || { echo "missing $BUILD_DIR/$f — build first" >&2; exit 1; }
done
[[ -f "$BOOT_APP0" ]] || { echo "missing $BOOT_APP0" >&2; exit 1; }

echo "==> copying binaries into flasher/firmware/"
mkdir -p "$FLASHER_DIR/firmware"
cp "$BUILD_DIR/bootloader.bin" "$FLASHER_DIR/firmware/bootloader.bin"
cp "$BUILD_DIR/partitions.bin" "$FLASHER_DIR/firmware/partitions.bin"
cp "$BUILD_DIR/firmware.bin"   "$FLASHER_DIR/firmware/firmware.bin"
cp "$BOOT_APP0"                "$FLASHER_DIR/firmware/boot_app0.bin"

GIT_HASH="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
FW_SEMVER="$(sed -n 's/^#define FW_VERSION "\(.*\)"$/\1/p' "$REPO_ROOT/src/main.cpp")"
FW_VERSION_LABEL="${FW_SEMVER:-unknown} ($GIT_HASH)"
FW_SHA256="$(sha256sum "$FLASHER_DIR/firmware/firmware.bin" | cut -d' ' -f1)"

echo "==> writing manifest.json (version $FW_VERSION_LABEL)"
python3 - "$FLASHER_DIR/manifest.json" "$FW_VERSION_LABEL" "$FW_SHA256" <<'PY'
import json, sys
out_path, version, fw_sha256 = sys.argv[1], sys.argv[2], sys.argv[3]
manifest = {
    "name": "NSD-S3 firmware",
    "version": version,
    "new_install_prompt_erase": False,
    "builds": [
        {
            "chipFamily": "ESP32-S3",
            "parts": [
                {"path": "firmware/bootloader.bin", "offset": 0},
                {"path": "firmware/partitions.bin", "offset": 32768},
                {"path": "firmware/boot_app0.bin", "offset": 57344},
                {"path": "firmware/firmware.bin", "offset": 65536, "sha256": fw_sha256},
            ],
        }
    ],
}
with open(out_path, "w") as fh:
    json.dump(manifest, fh, indent=2)
    fh.write("\n")
PY

echo "==> firmware.bin sha256: $FW_SHA256"
echo "==> manifest.json version: $GIT_HASH"

if [[ "$DO_DEPLOY" -eq 1 ]]; then
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "Missing $ENV_FILE — copy flasher/deploy.env.example to flasher/deploy.env and fill in REMOTE_HOST/REMOTE_PATH/SSH_KEY." >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  : "${REMOTE_HOST:?REMOTE_HOST not set in $ENV_FILE}"
  : "${REMOTE_PATH:?REMOTE_PATH not set in $ENV_FILE}"
  : "${SSH_KEY:?SSH_KEY not set in $ENV_FILE}"
  if [[ ! -f "$SSH_KEY" ]]; then
    echo "SSH key $SSH_KEY not found — check SSH_KEY in $ENV_FILE." >&2
    exit 1
  fi
  # plain scp, not rsync: the remote box has no rsync installed (same reason
  # the original flink.club deploy used scp)
  echo "==> scp to $REMOTE_HOST:$REMOTE_PATH"
  scp -i "$SSH_KEY" -r \
    "$FLASHER_DIR/index.html" "$FLASHER_DIR/manifest.json" \
    "$FLASHER_DIR/apple-touch-icon.png" \
    "$FLASHER_DIR/vendor" "$FLASHER_DIR/firmware" \
    "$REMOTE_HOST:$REMOTE_PATH"
  ssh -i "$SSH_KEY" "$REMOTE_HOST" "chown -R caddy:caddy '$REMOTE_PATH'"
  echo "==> deployed."
else
  echo "==> local build only (pass --deploy, with flasher/deploy.env configured, to publish)"
fi
