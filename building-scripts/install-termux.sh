#!/usr/bin/env sh
# Flow sketch: action selection -> build/install action -> CLI availability
# Pseudo-block:
#   parse args -> run step -> print result
# this script packs hiking boots for termux before the scan starts.

set -eu

if [ -z "${PREFIX:-}" ]; then
  echo "error: TERMUX PREFIX is not set. Run this script inside Termux." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Installing Termux build dependencies..."
pkg update -y
pkg install -y rust clang pkg-config make

NETPROBE_RS_OS_TAG="termux" \
NETPROBE_RS_DEFAULT_INSTALL_DIR="${NETPROBE_RS_INSTALL_DIR:-$PREFIX/bin}" \
sh "$SCRIPT_DIR/install.sh" "$@"

echo "Tip: run 'tsu' or 'su' for root-required scan modes when using --root-only."

