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
DEFAULT_INSTALL_DIR="${NPROBE_RS_DEFAULT_INSTALL_DIR:-${NPROBE_RS_INSTALL_DIR:-$HOME/.local/bin}}"
INSTALL_DIR="${NPROBE_RS_INSTALL_DIR:-}"
PATH_UPDATE_MODE="ask"

usage() {
  cat <<'EOF'
Usage:
  ./building-scripts/install.sh [action] [options]

Actions:
  install            Install binary to local/custom bin and optionally add PATH
  update             Rebuild and replace existing installed binary
  test               Build a test binary into build-<os>/ in repo root
  uninstall          Remove installed binary and optionally clean PATH entry

Prompt mode:
  Run without an action to choose from an interactive menu.

Compatibility aliases:
  phase1 -> test, phase2 -> install, phase3 -> update, phase4 -> uninstall
  upgrade -> update, remove -> uninstall

Options:
  --install-dir <dir>  Install/uninstall target directory
  --add-to-path        Add install dir to PATH without prompting
  --no-path-update     Do not add install dir to PATH
  -h, --help           Show this help
EOF
}

ACTION=""
if [ "$#" -gt 0 ]; then
  case "$1" in
    phase1|phase2|phase3|phase4|test|install|update|uninstall|upgrade|remove)
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
    printf '%s' "Choose [1/2/3/4] (default: 1): "
    IFS= read -r choice || choice=""
    case "$choice" in
      2) printf '%s\n' "update" ;;
      3) printf '%s\n' "test" ;;
      4) printf '%s\n' "uninstall" ;;
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

build_release_binary() {
  if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found in PATH. Install Rust toolchain first: https://rustup.rs/" >&2
    exit 1
  fi

  echo "Building nprobe-rs (release)..."
  cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml"
}

release_binary_path() {
  printf '%s\n' "$ROOT_DIR/target/release/nprobe-rs"
}

require_release_binary() {
  SRC_BIN="$(release_binary_path)"
  if [ ! -f "$SRC_BIN" ]; then
    echo "error: release binary not found at $SRC_BIN" >&2
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

rc_file_for_current_shell() {
  if [ -n "${NPROBE_RS_SHELL_RC:-}" ]; then
    printf '%s\n' "$NPROBE_RS_SHELL_RC"
    return
  fi

  shell_name="$(basename "${SHELL:-}")"
  case "$shell_name" in
    zsh) printf '%s\n' "$HOME/.zshrc" ;;
    bash)
      if [ "$OS_TAG" = "macos" ]; then
        if [ -f "$HOME/.bashrc" ]; then
          printf '%s\n' "$HOME/.bashrc"
        else
          printf '%s\n' "$HOME/.bash_profile"
        fi
      else
        printf '%s\n' "$HOME/.bashrc"
      fi
      ;;
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

  SRC_BIN="$(release_binary_path)"
  mkdir -p "$target_dir"
  DEST_BIN="$target_dir/nprobe-rs"
  cp "$SRC_BIN" "$DEST_BIN"
  chmod +x "$DEST_BIN"
  echo "Installed: $DEST_BIN"
}

installed_binary_guess() {
  if [ -n "$INSTALL_DIR" ]; then
    printf '%s\n' "$INSTALL_DIR/nprobe-rs"
    return
  fi

  if command -v nprobe-rs >/dev/null 2>&1; then
    command -v nprobe-rs
    return
  fi

  printf '%s\n' "$DEFAULT_INSTALL_DIR/nprobe-rs"
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

  BUILD_DIR="$ROOT_DIR/build-$OS_TAG"
  mkdir -p "$BUILD_DIR"
  SRC_BIN="$(release_binary_path)"
  DEST_BIN="$BUILD_DIR/nprobe-rs"
  cp "$SRC_BIN" "$DEST_BIN"
  chmod +x "$DEST_BIN"
  echo "Test binary ready: $DEST_BIN"
}

action_install() {
  choose_install_dir_interactive
  install_binary_to_dir "$INSTALL_DIR"
  maybe_update_path "$INSTALL_DIR"
}

action_update() {
  BIN_PATH="$(installed_binary_guess)"
  INSTALL_DIR="$(dirname "$BIN_PATH")"
  install_binary_to_dir "$INSTALL_DIR"
  maybe_update_path "$INSTALL_DIR"
  echo "Update complete."
}

action_uninstall() {
  BIN_PATH="$(installed_binary_guess)"
  removed="no"
  if [ -f "$BIN_PATH" ]; then
    rm -f "$BIN_PATH"
    echo "Removed: $BIN_PATH"
    removed="yes"
  fi

  if [ "$removed" = "no" ]; then
    echo "No installed binary found at $BIN_PATH"
  fi

  maybe_remove_path_exports
}

case "$ACTION" in
  test) action_test ;;
  install) action_install ;;
  update) action_update ;;
  uninstall) action_uninstall ;;
esac

