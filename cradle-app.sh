#!/usr/bin/env bash
# Build (if needed) and launch the Cradle desktop app.
#
# Usage:
#   ./cradle-app.sh
#   CRADLE_APP_RELEASE=1 ./cradle-app.sh   # release build instead of debug
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

# Default on so the auth-prompt / host-I/O-error timestamps in backup.rs
# actually land somewhere — override by exporting RUST_LOG yourself first.
export RUST_LOG="${RUST_LOG:-cradle_core=info,idevice=warn}"

if [[ "${CRADLE_APP_RELEASE:-}" == "1" ]]; then
  cargo run --release -p cradle-app
else
  cargo run -p cradle-app
fi
