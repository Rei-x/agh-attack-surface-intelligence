#!/bin/sh
# Dzięcioł installer - downloads the single `dzieciol` binary from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/Rei-x/agh-attack-surface-intelligence/main/install.sh | sh
#
# Environment:
#   DZIECIOL_VERSION        release tag to install (default: latest), e.g. v1.2.0
#   DZIECIOL_INSTALL_DIR    target directory (default: /usr/local/bin as root, else ~/.local/bin)
#   DZIECIOL_DOWNLOAD_BASE  alternative base URL holding dzieciol-<os>-<arch> + checksums.txt (mirror)
#
# The script verifies the SHA-256 checksum from checksums.txt and never uses sudo.
#
# Remote scanning agent (Linux + systemd, run as root): install the binary and the
# dzieciol-agent service in one go. Arguments after --agent go to `dzieciol agent install`:
#
#   curl -fsSL .../install.sh | sudo sh -s -- --agent --server https://dzieciol.example.edu \
#        --token aet_... [--name wydzial-x] [--allow-cidr 10.20.0.0/16]
set -eu

AGENT=0
if [ "${1:-}" = "--agent" ]; then
  AGENT=1
  shift
fi

REPO="Rei-x/agh-attack-surface-intelligence"
VERSION="${DZIECIOL_VERSION:-latest}"
INSTALL_DIR="${DZIECIOL_INSTALL_DIR:-}"
DOWNLOAD_BASE="${DZIECIOL_DOWNLOAD_BASE:-}"

say() { printf '%s\n' "dzieciol-install: $*"; }
die() { printf '%s\n' "dzieciol-install: error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

os=$(uname -s 2>/dev/null || echo unknown)
arch=$(uname -m 2>/dev/null || echo unknown)
case "$os" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  MINGW*|MSYS*|CYGWIN*) os=windows ;;
  *) die "unsupported OS: $os (download a binary manually from https://github.com/$REPO/releases)" ;;
esac
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) die "unsupported CPU architecture: $arch" ;;
esac
if [ "$os" = windows ] && [ "$arch" != amd64 ]; then
  die "only windows/amd64 builds are published"
fi
ext=""
[ "$os" = windows ] && ext=".exe"
asset="dzieciol-${os}-${arch}${ext}"

if [ -n "$DOWNLOAD_BASE" ]; then
  base="${DOWNLOAD_BASE%/}"
elif [ "$VERSION" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "need curl or wget"
fi
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "need sha256sum or shasum to verify the download"
fi
need awk
need uname

if [ -n "$INSTALL_DIR" ]; then
  dir="$INSTALL_DIR"
elif [ "$(id -u 2>/dev/null || echo 1)" = 0 ]; then
  dir="/usr/local/bin"
else
  dir="${HOME}/.local/bin"
fi
mkdir -p "$dir" || die "cannot create $dir (set DZIECIOL_INSTALL_DIR)"
[ -w "$dir" ] || die "$dir is not writable (set DZIECIOL_INSTALL_DIR, e.g. DZIECIOL_INSTALL_DIR=\$HOME/.local/bin)"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t dzieciol)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $asset ($VERSION) from $base"
fetch "$base/$asset" "$tmp/$asset" || die "download failed: $base/$asset"
fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "download failed: $base/checksums.txt"

expected=$(awk -v f="$asset" '{ name=$2; sub(/^\*/, "", name); if (name == f) print $1 }' "$tmp/checksums.txt")
[ -n "$expected" ] || die "no checksum for $asset in checksums.txt"
actual=$(sha256 "$tmp/$asset")
[ "$expected" = "$actual" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"
say "checksum OK ($actual)"

target="$dir/dzieciol$ext"
chmod 0755 "$tmp/$asset"
mv -f "$tmp/$asset" "$target"
say "installed $target"
"$target" version || true

if [ "$AGENT" = 1 ]; then
  [ "$os" = linux ] || die "--agent installs a systemd service (Linux); elsewhere run: dzieciol agent --server ... --token ..."
  [ "$(id -u)" = 0 ] || die "--agent must run as root (pipe into: sudo sh -s -- --agent ...)"
  command -v nmap >/dev/null 2>&1 || say "note: nmap not found - the agent uses its built-in TCP connect scanner (apt install nmap for richer fingerprints)"
  exec "$target" agent install "$@"
fi

case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "note: $dir is not on your PATH - add it, e.g.: echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile" ;;
esac

if ! command -v nmap >/dev/null 2>&1; then
  say "optional: install nmap for richer service fingerprints (dzieciol works without it):"
  case "$os" in
    darwin) say "  brew install nmap" ;;
    linux) say "  sudo apt install nmap   # or: sudo dnf install nmap" ;;
    windows) say "  winget install Insecure.Nmap" ;;
  esac
fi

say "done. Start with:  dzieciol serve    (then open http://localhost:8080)"
