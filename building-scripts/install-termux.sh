#!/usr/bin/env sh
set -eu

if [ -z "${PREFIX:-}" ]; then
  echo "error: TERMUX PREFIX is not set. Run this script inside Termux." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_DIR="${NETPROBE_RS_INSTALL_DIR:-$PREFIX/bin}"

echo "Installing Termux build dependencies..."
pkg update -y
pkg install -y rust clang pkg-config make

echo "Building netprobe-rs (release)..."
cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml"

SRC_BIN="$ROOT_DIR/target/release/netprobe-rs"
if [ ! -f "$SRC_BIN" ]; then
  echo "error: release binary not found at $SRC_BIN" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
DEST_BIN="$INSTALL_DIR/recon"
cp "$SRC_BIN" "$DEST_BIN"
chmod +x "$DEST_BIN"

echo "Installed: $DEST_BIN"
echo "Tip: run 'tsu' or 'su' for root-required scan modes."
