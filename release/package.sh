#!/usr/bin/env bash
#
# package.sh — build the single wirefinder .deb (daemon + cli + gui) locally.
#
# This is the ONE command for the otherwise-manual flow: it compiles the daemon
# and CLI (cargo), compiles the desktop GUI (Tauri), and assembles them into one
# .deb with cargo-deb. CI (.github/workflows/release.yml) runs this exact script,
# so a local build and a released build can't drift.
#
# Requires: the Tauri Linux deps for the GUI build (webkit2gtk-4.1, GTK, etc.).
# Without them the GUI step fails with a clear linker error.
#
#   release/package.sh            # → target/debian/wirefinder_<ver>_amd64.deb
#   release/package.sh --install  # also `sudo apt install` the result
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"          # the cargo workspace (repo root)
cd "$ROOT_DIR"

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }

say "building daemon + CLI (release)"
cargo build --release

say "building the desktop GUI (Tauri, compile only)"
( cd ui && pnpm install --frozen-lockfile && pnpm tauri build --no-bundle )

say "ensuring cargo-deb is available"
command -v cargo-deb >/dev/null 2>&1 || cargo install cargo-deb --locked

say "assembling the .deb"
cargo deb -p wirefinderd --no-build

DEB="$(ls -t "$ROOT_DIR"/target/debian/*.deb | head -1)"
say "built: $DEB"

if [[ "${1:-}" == "--install" ]]; then
  say "installing (sudo)"
  sudo apt install -y "$DEB"
else
  printf '   install it with:  sudo apt install %s\n' "$DEB"
fi
