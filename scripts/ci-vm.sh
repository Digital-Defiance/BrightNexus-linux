#!/usr/bin/env bash
# CI-style build/test for BrightNexus-linux on Ubuntu 24.04 (Noble) VMs — e.g. Parallels.
#
# Usage:
#   ./scripts/ci-vm.sh              # apt deps + tests
#   ./scripts/ci-vm.sh --release    # also build release bridge + GTK UI
#   ./scripts/ci-vm.sh --install-rust   # force rustup install even if rustc exists
#
# Environment:
#   REPO_DIR  checkout path (default: ~/BrightNexus-linux)

set -euo pipefail

REPO_DIR="${REPO_DIR:-$HOME/BrightNexus-linux}"
REPO_URL="https://github.com/Digital-Defiance/BrightNexus-linux.git"
MIN_RUST_VERSION="1.85"
SOCKET_PATH="${HOME}/.brightchain/brightnexus/brightnexus.sock"

INSTALL_RUST=false
DO_RELEASE=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Run BrightNexus-linux CI checks on an Ubuntu Noble VM.

Options:
  --install-rust   Install or refresh rustup even when rustc is already present
  --release        After tests, build release bridge and GTK UI binaries
  -h, --help       Show this help

Environment:
  REPO_DIR         Repository checkout (default: ~/BrightNexus-linux)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-rust)
      INSTALL_RUST=true
      shift
      ;;
    --release)
      DO_RELEASE=true
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

section() {
  echo
  echo "== $1 =="
  echo
}

version_ge() {
  # True when $1 >= $2 (semver-ish, e.g. 1.85.0 >= 1.85).
  printf '%s\n%s\n' "$2" "$1" | sort -C -V
}

section "Repository"
if [[ ! -d "$REPO_DIR/.git" ]]; then
  echo "Cloning into $REPO_DIR ..."
  git clone "$REPO_URL" "$REPO_DIR"
else
  echo "Updating existing checkout at $REPO_DIR ..."
  git -C "$REPO_DIR" pull --ff-only
fi
cd "$REPO_DIR"
echo "Working tree: $(pwd)"

section "System dependencies (apt)"
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  libsecp256k1-dev \
  libgtk-4-dev \
  libadwaita-1-dev \
  libsecret-1-dev \
  geoclue-2.0 \
  git \
  curl

section "Rust toolchain"
if command -v cargo >/dev/null 2>&1; then
  cargo_path="$(command -v cargo)"
  if [[ "$cargo_path" == /usr/bin/cargo ]]; then
    echo "WARNING: $cargo_path is Ubuntu Noble's apt cargo (Rust 1.75)."
    echo "It is too old for this workspace (MSRV ${MIN_RUST_VERSION}+)."
    echo
    echo "Install rustup and ensure ~/.cargo/bin is first on PATH:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "  source \"\$HOME/.cargo/env\""
    echo "  rustup default stable"
    echo
    echo "Optional: sudo apt remove -y cargo rustc"
    echo "Or re-run this script with --install-rust"
    echo
  fi
fi

if ! command -v rustc >/dev/null 2>&1 || [[ "$INSTALL_RUST" == true ]]; then
  echo "Installing rustup (stable) ..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
fi

# shellcheck disable=SC1091
source "$HOME/.cargo/env"
rustup default stable

rustc_version="$(rustc --version | awk '{print $2}')"
echo "rustc $rustc_version ($(command -v rustc))"

if ! version_ge "$rustc_version" "$MIN_RUST_VERSION"; then
  echo "ERROR: rustc $rustc_version is below MSRV ${MIN_RUST_VERSION}." >&2
  echo "Install rustup stable and re-run with --install-rust if apt rustc is still first on PATH." >&2
  exit 1
fi

section "Workspace tests"
export BRIGHTNEXUS_GEO_SOURCE=fixed
echo "BRIGHTNEXUS_GEO_SOURCE=$BRIGHTNEXUS_GEO_SOURCE"
cargo test --workspace

if [[ "$DO_RELEASE" == true ]]; then
  section "Release builds"
  cargo build --release -p brightnexus-bridge
  cargo build --release -p brightnexus-gtk --features ui
fi

section "Success"
echo "All checks passed."
echo
echo "Bridge Unix socket (default): $SOCKET_PATH"
echo
echo "Run the headless bridge:"
echo "  BRIGHTNEXUS_GEO_SOURCE=fixed ./target/release/brightnexus-bridge"
echo
if [[ "$DO_RELEASE" == true ]]; then
  echo "Run the GTK UI (after --release build):"
  echo "  ./target/release/brightnexus"
  echo
fi
echo "Override socket path with BRIGHTNEXUS_SOCKET if needed."
