#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_DIR="${NETPROBE_RS_INSTALL_DIR:-$HOME/.local/bin}"

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
echo "Tip: ensure '$INSTALL_DIR' is in your PATH"

