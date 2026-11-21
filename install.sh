#!/bin/sh
# AegisASI installer - downloads the single `aegis` binary from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/Rei-x/agh-attack-surface-intelligence/main/install.sh | sh
#
# Environment:
#   AEGIS_VERSION      release tag to install (default: latest), e.g. v1.2.0
#   AEGIS_INSTALL_DIR  target directory (default: /usr/local/bin as root, else ~/.local/bin)
#   AEGIS_DOWNLOAD_BASE  alternative base URL holding aegis-<os>-<arch> + checksums.txt (mirror)
#
# The script verifies the SHA-256 checksum from checksums.txt and never uses sudo.
set -eu

REPO="Rei-x/agh-attack-surface-intelligence"
VERSION="${AEGIS_VERSION:-latest}"

say() { printf '%s\n' "aegis-install: $*"; }
die() { printf '%s\n' "aegis-install: error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

# --- detect platform ---------------------------------------------------------
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
asset="aegis-${os}-${arch}${ext}"

if [ -n "${AEGIS_DOWNLOAD_BASE:-}" ]; then
  base="${AEGIS_DOWNLOAD_BASE%/}"
elif [ "$VERSION" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

# --- pick downloader & hasher -----------------------------------------------
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

# --- install dir --------------------------------------------------------------
if [ -n "${AEGIS_INSTALL_DIR:-}" ]; then
  dir="$AEGIS_INSTALL_DIR"
elif [ "$(id -u 2>/dev/null || echo 1)" = 0 ]; then
  dir="/usr/local/bin"
else
  dir="${HOME}/.local/bin"
fi
mkdir -p "$dir" || die "cannot create $dir (set AEGIS_INSTALL_DIR)"
[ -w "$dir" ] || die "$dir is not writable (set AEGIS_INSTALL_DIR, e.g. AEGIS_INSTALL_DIR=\$HOME/.local/bin)"

# --- download & verify --------------------------------------------------------
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t aegis)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $asset ($VERSION) from $base"
fetch "$base/$asset" "$tmp/$asset" || die "download failed: $base/$asset"
fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "download failed: $base/checksums.txt"

expected=$(awk -v f="$asset" '{ name=$2; sub(/^\*/, "", name); if (name == f) print $1 }' "$tmp/checksums.txt")
[ -n "$expected" ] || die "no checksum for $asset in checksums.txt"
actual=$(sha256 "$tmp/$asset")
[ "$expected" = "$actual" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"
say "checksum OK ($actual)"

target="$dir/aegis$ext"
chmod 0755 "$tmp/$asset"
mv -f "$tmp/$asset" "$target"
say "installed $target"
"$target" version || true

case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "note: $dir is not on your PATH - add it, e.g.: echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile" ;;
esac

if ! command -v nmap >/dev/null 2>&1; then
  say "optional: install nmap for richer service fingerprints (aegis works without it):"
  case "$os" in
    darwin) say "  brew install nmap" ;;
    linux) say "  sudo apt install nmap   # or: sudo dnf install nmap" ;;
    windows) say "  winget install Insecure.Nmap" ;;
  esac
fi

say "done. Start with:  aegis serve    (then open http://localhost:8080)"
