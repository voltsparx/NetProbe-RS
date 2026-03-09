#!/usr/bin/env sh
# Flow sketch: action selection -> build/install action -> CLI availability
# Pseudo-block:
#   parse args -> run step -> print result
# this script is the project mechanic; wrench first, test later.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

detect_os_tag() {
  case "$(uname -s)" in
    Linux) printf '%s\n' "linux" ;;
    Darwin) printf '%s\n' "macos" ;;
    *) uname -s | tr '[:upper:]' '[:lower:]' ;;
  esac
}

OS_TAG="${NPROBE_RS_OS_TAG:-$(detect_os_tag)}"
INSTALL_DIR="${NPROBE_RS_INSTALL_DIR:-}"
PATH_UPDATE_MODE="ask"
INSTALL_DEPS="no"

default_install_dir() {
  if [ -n "${NPROBE_RS_DEFAULT_INSTALL_DIR:-}" ]; then
    printf '%s\n' "$NPROBE_RS_DEFAULT_INSTALL_DIR"
    return
  fi

  if [ -n "${NPROBE_RS_INSTALL_DIR:-}" ]; then
    printf '%s\n' "$NPROBE_RS_INSTALL_DIR"
    return
  fi

  case "$OS_TAG" in
    linux)
      printf '%s\n' "/usr/local/bin"
      ;;
    macos)
      if command -v brew >/dev/null 2>&1; then
        brew_prefix="$(brew --prefix 2>/dev/null || true)"
        if [ -n "$brew_prefix" ]; then
          printf '%s\n' "$brew_prefix/bin"
          return
        fi
      fi
      printf '%s\n' "/usr/local/bin"
      ;;
    *)
      printf '%s\n' "$HOME/.local/bin"
      ;;
  esac
}

DEFAULT_INSTALL_DIR="$(default_install_dir)"

cargo_bin_dir() {
  if [ -n "${CARGO_HOME:-}" ]; then
    printf '%s\n' "$CARGO_HOME/bin"
    return
  fi

  printf '%s\n' "$HOME/.cargo/bin"
}

ensure_supported_shell_platform() {
  if [ "$OS_TAG" = "linux" ] || [ "$OS_TAG" = "macos" ]; then
    return
  fi

  echo "error: building-scripts/install.sh supports Linux and macOS hosts only." >&2
  echo "Use building-scripts/install.ps1 or install.bat on Windows." >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  ./building-scripts/install.sh [action] [options]

Actions:
  deps               Install build dependencies for Linux/macOS when supported
  install            Install binary to local/custom bin and optionally add PATH
  update             Rebuild and replace existing installed binary
  test               Build a test binary into build-<os>/ in repo root
  uninstall          Remove installed binaries and optionally clean PATH entry

Prompt mode:
  Run without an action to choose from an interactive menu.

Compatibility aliases:
  phase1 -> test, phase2 -> install, phase3 -> update, phase4 -> uninstall
  upgrade -> update, remove -> uninstall, install-deps -> deps

Options:
  --install-dir <dir>  Install/uninstall target directory
  --install-deps       Install build dependencies before install/update/test
  --add-to-path        Add install dir to PATH without prompting
  --no-path-update     Do not add install dir to PATH
  -h, --help           Show this help
EOF
}

ACTION=""
if [ "$#" -gt 0 ]; then
  case "$1" in
    phase1|phase2|phase3|phase4|test|install|update|uninstall|upgrade|remove|deps|install-deps)
      ACTION="$1"
      shift
      ;;
    -*)
      ;;
    *)
      echo "error: unknown action '$1'" >&2
      usage
      exit 1
      ;;
  esac
fi

while [ "$#" -gt 0 ]; do
  case "$1" in
    --install-dir)
      shift
      if [ "$#" -eq 0 ]; then
        echo "error: --install-dir requires a value" >&2
        exit 1
      fi
      INSTALL_DIR="$1"
      ;;
    --install-deps)
      INSTALL_DEPS="yes"
      ;;
    --add-to-path)
      PATH_UPDATE_MODE="yes"
      ;;
    --no-path-update)
      PATH_UPDATE_MODE="no"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option '$1'" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

normalize_action() {
  case "$1" in
    phase1|test) printf '%s\n' "test" ;;
    phase2|install) printf '%s\n' "install" ;;
    phase3|upgrade|update) printf '%s\n' "update" ;;
    phase4|remove|uninstall) printf '%s\n' "uninstall" ;;
    deps|install-deps) printf '%s\n' "deps" ;;
    *)
      echo "error: unknown action '$1'" >&2
      usage
      exit 1
      ;;
  esac
}

choose_action_interactive() {
  if [ -t 0 ]; then
    printf '%s\n' "Choose action:"
    printf '%s\n' "1) install (local/custom + PATH prompt)"
    printf '%s\n' "2) update"
    printf '%s\n' "3) test"
    printf '%s\n' "4) uninstall"
    printf '%s\n' "5) deps (prepare build dependencies)"
    printf '%s' "Choose [1/2/3/4/5] (default: 1): "
    IFS= read -r choice || choice=""
    case "$choice" in
      2) printf '%s\n' "update" ;;
      3) printf '%s\n' "test" ;;
      4) printf '%s\n' "uninstall" ;;
      5) printf '%s\n' "deps" ;;
      *) printf '%s\n' "install" ;;
    esac
    return
  fi

  printf '%s\n' "install"
}

if [ -z "$ACTION" ]; then
  ACTION="$(choose_action_interactive)"
fi
ACTION="$(normalize_action "$ACTION")"

run_elevated_cmd() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi

  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
    return
  fi

  if command -v doas >/dev/null 2>&1; then
    doas "$@"
    return
  fi

  "$@"
}

ensure_linux_build_deps() {
  echo "Installing build dependencies for $OS_TAG..."
  if command -v apt-get >/dev/null 2>&1; then
    run_elevated_cmd apt-get update
    run_elevated_cmd apt-get install -y build-essential pkg-config curl clang
  elif command -v dnf >/dev/null 2>&1; then
    run_elevated_cmd dnf install -y gcc gcc-c++ make pkgconf-pkg-config curl clang
  elif command -v yum >/dev/null 2>&1; then
    run_elevated_cmd yum install -y gcc gcc-c++ make pkgconfig curl clang
  elif command -v pacman >/dev/null 2>&1; then
    run_elevated_cmd pacman -Sy --needed --noconfirm base-devel pkgconf curl clang
  elif command -v zypper >/dev/null 2>&1; then
    run_elevated_cmd zypper install -y gcc gcc-c++ make pkg-config curl clang
  elif command -v apk >/dev/null 2>&1; then
    run_elevated_cmd apk add --no-cache build-base pkgconf curl clang
  else
    echo "error: unsupported package manager for automatic dependency install." >&2
    echo "Install Rust toolchain, clang, make, and pkg-config manually, then rerun." >&2
    exit 1
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    echo "warning: cargo is still not available. Install Rust with rustup: https://rustup.rs/" >&2
  fi
}

ensure_macos_build_deps() {
  echo "Installing build dependencies for macOS..."

  if ! xcode-select -p >/dev/null 2>&1; then
    echo "error: Xcode Command Line Tools are required on macOS." >&2
    echo "Run 'xcode-select --install', then rerun this script." >&2
    exit 1
  fi

  if ! command -v brew >/dev/null 2>&1; then
    echo "error: Homebrew is required for automatic macOS dependency install." >&2
    echo "Install Homebrew or install Rust and pkg-config manually, then rerun." >&2
    exit 1
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    brew install rust
  fi

  if ! command -v pkg-config >/dev/null 2>&1; then
    brew install pkg-config
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    echo "warning: cargo is still not available. Install Rust with rustup: https://rustup.rs/" >&2
  fi
}

ensure_unix_build_deps() {
  case "$OS_TAG" in
    linux) ensure_linux_build_deps ;;
    macos) ensure_macos_build_deps ;;
    *)
      echo "error: unsupported Unix platform '$OS_TAG' for automatic dependency install." >&2
      exit 1
      ;;
  esac
}

maybe_install_deps() {
  if [ "$INSTALL_DEPS" = "yes" ]; then
    ensure_unix_build_deps
    INSTALL_DEPS="done"
  fi
}

build_release_binary() {
  maybe_install_deps
  if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found in PATH. Install Rust toolchain first: https://rustup.rs/" >&2
    exit 1
  fi

  echo "Building nprobe-rs and nprs (release)..."
  cargo build --release --bins --manifest-path "$ROOT_DIR/Cargo.toml"
}

release_binary_path() {
  printf '%s\n' "$ROOT_DIR/target/release/nprobe-rs"
}

release_alias_binary_path() {
  printf '%s\n' "$ROOT_DIR/target/release/nprs"
}

require_release_binary() {
  SRC_BIN="$(release_binary_path)"
  if [ ! -f "$SRC_BIN" ]; then
    echo "error: release binary not found at $SRC_BIN" >&2
    exit 1
  fi
}

require_release_alias_binary() {
  ALIAS_SRC_BIN="$(release_alias_binary_path)"
  if [ ! -f "$ALIAS_SRC_BIN" ]; then
    echo "error: release alias binary not found at $ALIAS_SRC_BIN" >&2
    exit 1
  fi
}

choose_install_dir_interactive() {
  if [ -n "$INSTALL_DIR" ]; then
    return
  fi

  if [ -t 0 ]; then
    printf '%s\n' "Install target:"
    printf '1) %s\n' "$DEFAULT_INSTALL_DIR"
    printf '%s\n' "2) custom path"
    printf '%s' "Choose [1/2] (default: 1): "
    IFS= read -r choice || choice=""
    case "$choice" in
      2)
        printf '%s' "Enter custom install directory: "
        IFS= read -r custom_dir || custom_dir=""
        if [ -z "$custom_dir" ]; then
          echo "error: custom directory cannot be empty" >&2
          exit 1
        fi
        INSTALL_DIR="$custom_dir"
        ;;
      *)
        INSTALL_DIR="$DEFAULT_INSTALL_DIR"
        ;;
    esac
  else
    INSTALL_DIR="$DEFAULT_INSTALL_DIR"
  fi
}

path_contains_dir() {
  case ":$PATH:" in
    *":$1:"*) return 0 ;;
    *) return 1 ;;
  esac
}

target_dir_is_user_writable() {
  target_dir="$1"
  if [ -d "$target_dir" ]; then
    [ -w "$target_dir" ]
    return
  fi

  parent_dir="$(dirname "$target_dir")"
  while [ ! -d "$parent_dir" ] && [ "$parent_dir" != "/" ]; do
    parent_dir="$(dirname "$parent_dir")"
  done

  [ -w "$parent_dir" ]
}

rc_file_for_current_shell() {
  if [ -n "${NPROBE_RS_SHELL_RC:-}" ]; then
    printf '%s\n' "$NPROBE_RS_SHELL_RC"
    return
  fi

  shell_name="$(basename "${SHELL:-}")"
  case "$shell_name" in
    zsh) printf '%s\n' "$HOME/.zshrc" ;;
    bash) printf '%s\n' "$HOME/.bashrc" ;;
    fish) printf '%s\n' "" ;;
    *) printf '%s\n' "$HOME/.profile" ;;
  esac
}

append_path_export() {
  target_dir="$1"
  rc_file="$(rc_file_for_current_shell)"

  if [ -z "$rc_file" ]; then
    echo "Detected fish shell. Add this manually to your config:"
    echo "set -gx PATH \"$target_dir\" \$PATH"
    return
  fi

  marker="# nprobe-rs installer"
  export_line="export PATH=\"$target_dir:\$PATH\" $marker"
  rc_parent="$(dirname "$rc_file")"
  mkdir -p "$rc_parent"
  if [ ! -f "$rc_file" ]; then
    : > "$rc_file"
  fi

  if ! grep -F "$export_line" "$rc_file" >/dev/null 2>&1; then
    printf '\n%s\n' "$export_line" >> "$rc_file"
    echo "Updated PATH in $rc_file"
  else
    echo "PATH entry already present in $rc_file"
  fi

  if ! path_contains_dir "$target_dir"; then
    PATH="$target_dir:$PATH"
    export PATH
  fi
}

maybe_update_path() {
  target_dir="$1"

  if path_contains_dir "$target_dir"; then
    echo "PATH already contains $target_dir"
    return
  fi

  apply_update="$PATH_UPDATE_MODE"
  if [ "$PATH_UPDATE_MODE" = "ask" ]; then
    if [ -t 0 ]; then
      printf '%s' "Add '$target_dir' to PATH? [Y/n]: "
      IFS= read -r answer || answer=""
      case "$answer" in
        n|N) apply_update="no" ;;
        *) apply_update="yes" ;;
      esac
    else
      apply_update="yes"
    fi
  fi

  if [ "$apply_update" = "yes" ]; then
    append_path_export "$target_dir"
  else
    echo "Skipped PATH update."
  fi
}

install_binary_to_dir() {
  target_dir="$1"
  build_release_binary
  require_release_binary
  require_release_alias_binary

  SRC_BIN="$(release_binary_path)"
  ALIAS_SRC_BIN="$(release_alias_binary_path)"
  PRIMARY_BIN="$target_dir/nprobe-rs"
  ALIAS_BIN="$target_dir/nprs"

  if target_dir_is_user_writable "$target_dir"; then
    mkdir -p "$target_dir"
    cp "$SRC_BIN" "$PRIMARY_BIN"
    chmod +x "$PRIMARY_BIN"
    cp "$ALIAS_SRC_BIN" "$ALIAS_BIN"
    chmod +x "$ALIAS_BIN"
  else
    run_elevated_cmd mkdir -p "$target_dir"
    run_elevated_cmd cp "$SRC_BIN" "$PRIMARY_BIN"
    run_elevated_cmd chmod +x "$PRIMARY_BIN"
    run_elevated_cmd cp "$ALIAS_SRC_BIN" "$ALIAS_BIN"
    run_elevated_cmd chmod +x "$ALIAS_BIN"
  fi

  echo "Installed: $PRIMARY_BIN"
  echo "Alias installed: $ALIAS_BIN"
}

installed_binary_dir_guess() {
  if [ -n "$INSTALL_DIR" ]; then
    printf '%s\n' "$INSTALL_DIR"
    return
  fi

  if command -v nprobe-rs >/dev/null 2>&1; then
    dirname "$(command -v nprobe-rs)"
    return
  fi

  if command -v nprs >/dev/null 2>&1; then
    dirname "$(command -v nprs)"
    return
  fi

  CARGO_BIN_DIR="$(cargo_bin_dir)"
  if [ -f "$CARGO_BIN_DIR/nprobe-rs" ] || [ -f "$CARGO_BIN_DIR/nprs" ]; then
    printf '%s\n' "$CARGO_BIN_DIR"
    return
  fi

  printf '%s\n' "$DEFAULT_INSTALL_DIR"
}

remove_path_exports() {
  rc_file="$(rc_file_for_current_shell)"
  if [ -z "$rc_file" ] || [ ! -f "$rc_file" ]; then
    return 1
  fi

  if ! grep -F "# nprobe-rs installer" "$rc_file" >/dev/null 2>&1; then
    return 1
  fi

  tmp_file="$rc_file.nprobe-rs.tmp"
  sed '/# nprobe-rs installer/d' "$rc_file" > "$tmp_file"
  mv "$tmp_file" "$rc_file"
  return 0
}

maybe_remove_path_exports() {
  apply_update="$PATH_UPDATE_MODE"
  if [ "$PATH_UPDATE_MODE" = "ask" ]; then
    if [ -t 0 ]; then
      printf '%s' "Remove nprobe-rs PATH entry from shell config? [y/N]: "
      IFS= read -r answer || answer=""
      case "$answer" in
        y|Y) apply_update="yes" ;;
        *) apply_update="no" ;;
      esac
    else
      apply_update="no"
    fi
  fi

  if [ "$apply_update" = "yes" ]; then
    if remove_path_exports; then
      echo "Removed nprobe-rs PATH entry from shell config."
    else
      echo "No nprobe-rs PATH entry found in shell config."
    fi
  else
    echo "Skipped PATH update removal."
  fi
}

action_test() {
  build_release_binary
  require_release_binary
  require_release_alias_binary

  BUILD_DIR="$ROOT_DIR/build-$OS_TAG"
  mkdir -p "$BUILD_DIR"
  SRC_BIN="$(release_binary_path)"
  ALIAS_SRC_BIN="$(release_alias_binary_path)"
  DEST_BIN="$BUILD_DIR/nprobe-rs"
  ALIAS_BIN="$BUILD_DIR/nprs"
  cp "$SRC_BIN" "$DEST_BIN"
  chmod +x "$DEST_BIN"
  cp "$ALIAS_SRC_BIN" "$ALIAS_BIN"
  chmod +x "$ALIAS_BIN"
  echo "Test binary ready: $DEST_BIN"
  echo "Alias binary ready: $ALIAS_BIN"
}

action_install() {
  choose_install_dir_interactive
  install_binary_to_dir "$INSTALL_DIR"
  maybe_update_path "$INSTALL_DIR"
}

action_update() {
  INSTALL_DIR="$(installed_binary_dir_guess)"
  install_binary_to_dir "$INSTALL_DIR"
  maybe_update_path "$INSTALL_DIR"
  echo "Update complete."
}

action_uninstall() {
  TARGET_DIR="$(installed_binary_dir_guess)"
  BIN_PATH="$TARGET_DIR/nprobe-rs"
  ALIAS_PATH="$TARGET_DIR/nprs"
  removed="no"
  if [ -f "$BIN_PATH" ]; then
    if [ -w "$BIN_PATH" ]; then
      rm -f "$BIN_PATH"
    else
      run_elevated_cmd rm -f "$BIN_PATH"
    fi
    echo "Removed: $BIN_PATH"
    removed="yes"
  fi
  if [ -f "$ALIAS_PATH" ]; then
    if [ -w "$ALIAS_PATH" ]; then
      rm -f "$ALIAS_PATH"
    else
      run_elevated_cmd rm -f "$ALIAS_PATH"
    fi
    echo "Removed: $ALIAS_PATH"
    removed="yes"
  fi

  if [ "$removed" = "no" ]; then
    echo "No installed binaries found in $TARGET_DIR"
  fi

  maybe_remove_path_exports
}

action_deps() {
  ensure_unix_build_deps
}

ensure_supported_shell_platform

case "$ACTION" in
  deps) action_deps ;;
  test) action_test ;;
  install) action_install ;;
  update) action_update ;;
  uninstall) action_uninstall ;;
esac

