#!/bin/sh
# caniac installer — downloads the prebuilt codeanalyzer-iac (`caniac`) binary for your
# platform from the GitHub Release and installs it. Mirrors the cargo-dist installer pattern.
#
# Usage:
#   curl --proto '=https' --tlsv1.2 -LsSf https://github.com/codellm-devkit/codeanalyzer-iac/releases/latest/download/caniac-installer.sh | sh
#
# Environment overrides:
#   CANIAC_INSTALL_DIR   install location           (default: ~/.local/bin)
#   CANIAC_VERSION       release tag, e.g. v0.3.0   (default: latest)
set -eu

REPO="codellm-devkit/codeanalyzer-iac"
INSTALL_DIR="${CANIAC_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${CANIAC_VERSION:-latest}"

os="$(uname -s)"
arch="$(uname -m)"

# Map the host platform to the published Release asset name (see packaging/python/build_wheels.sh
# targets and packaging/homebrew/generate_formula.sh).
case "$os" in
  Darwin)
    case "$arch" in
      arm64 | aarch64) asset="caniac-macosx_11_0_arm64" ;;
      x86_64) asset="caniac-macosx_11_0_x86_64" ;;
      *) echo "caniac: unsupported macOS architecture: $arch" >&2; exit 1 ;;
    esac
    ;;
  Linux)
    case "$arch" in
      x86_64) asset="caniac-manylinux_2_17_x86_64" ;;
      aarch64 | arm64) asset="caniac-manylinux_2_17_aarch64" ;;
      *) echo "caniac: unsupported Linux architecture: $arch" >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "caniac: unsupported OS '$os'. Try: pip install codeanalyzer-iac" >&2
    exit 1
    ;;
esac

if [ "$VERSION" = "latest" ]; then
  url="https://github.com/$REPO/releases/latest/download/$asset"
else
  url="https://github.com/$REPO/releases/download/$VERSION/$asset"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "caniac: downloading $asset ($VERSION)..."
if command -v curl >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -fLsS "$url" -o "$tmp/caniac"
elif command -v wget >/dev/null 2>&1; then
  wget -q "$url" -O "$tmp/caniac"
else
  echo "caniac: need curl or wget to download" >&2
  exit 1
fi

chmod +x "$tmp/caniac"
mkdir -p "$INSTALL_DIR"
mv "$tmp/caniac" "$INSTALL_DIR/caniac"
echo "caniac: installed to $INSTALL_DIR/caniac"

# PATH hint when the install dir isn't already on PATH.
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "caniac: add it to your PATH:  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
