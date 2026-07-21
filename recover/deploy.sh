#!/usr/bin/env bash
# Deploys recover/index.html to the recover.flink.club web root.
# Single static file, no build step -- unlike flasher/deploy.sh there's no
# firmware/manifest to regenerate.
#
# Usage:
#   ./deploy.sh --deploy

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RECOVER_DIR="$REPO_ROOT/recover"
ENV_FILE="$RECOVER_DIR/deploy.env"

if [[ "${1:-}" != "--deploy" ]]; then
  echo "usage: $0 --deploy" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE — copy recover/deploy.env.example to recover/deploy.env and fill in REMOTE_HOST/REMOTE_PATH/SSH_KEY." >&2
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
# flash.flink.club/flink.club deploys use scp too)
echo "==> scp to $REMOTE_HOST:$REMOTE_PATH"
scp -i "$SSH_KEY" "$RECOVER_DIR/index.html" "$REMOTE_HOST:${REMOTE_PATH}index.html"
ssh -i "$SSH_KEY" "$REMOTE_HOST" "chown caddy:caddy '${REMOTE_PATH}index.html'"
echo "==> deployed to https://recover.flink.club"
