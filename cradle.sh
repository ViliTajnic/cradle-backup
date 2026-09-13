#!/usr/bin/env bash
# Build (if needed) and run the cradle CLI, forwarding all arguments.
#
# Usage:
#   ./cradle.sh devices
#   ./cradle.sh backup --udid <UDID>
#   CRADLE_DEBUG=1 ./cradle.sh devices   # use a debug build instead of release
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

# Default on so the auth-prompt / host-I/O-error timestamps in backup.rs
# actually land somewhere — override by exporting RUST_LOG yourself first.
export RUST_LOG="${RUST_LOG:-cradle_core=info,idevice=warn}"

if [[ "${CRADLE_DEBUG:-}" == "1" ]]; then
  cargo build -p cradle
  exec target/debug/cradle "$@"
else
  cargo build --release -p cradle
  exec target/release/cradle "$@"
fi
