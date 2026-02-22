#!/bin/bash
set -euo pipefail

# ota-touchid installer
# Usage: curl -fsSL https://raw.githubusercontent.com/pproenca/ota-touchid/master/scripts/install.sh | bash

VERSION="${OTA_TOUCHID_VERSION:-latest}"
INSTALL_DIR="${OTA_TOUCHID_DIR:-$HOME/.local/bin}"
BIN_LINK="$INSTALL_DIR/ota-touchid"
REPO="pproenca/ota-touchid"
FORCE="${OTA_TOUCHID_FORCE:-0}"

# --- Colors ---
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
green() { printf "\033[32m%s\033[0m\n" "$1"; }
dim()   { printf "\033[2m%s\033[0m\n" "$1"; }
bold()  { printf "\033[1m%s\033[0m\n" "$1"; }

# --- Prerequisites ---
check_prerequisites() {
  local failed=0

  # macOS
  if [[ "$(uname)" != "Darwin" ]]; then
    red "ota-touchid requires macOS."
    exit 1
  fi

  # Apple Silicon
  if [[ "$(uname -m)" != "arm64" ]]; then
    red "ota-touchid requires Apple Silicon (arm64). Intel Macs are not supported."
    exit 1
  fi

  green "Prerequisites OK"
}

# --- Version Check ---
check_existing() {
  if command -v ota-touchid &>/dev/null; then
    local current
    current="$(ota-touchid help 2>&1 | head -1 || echo 'unknown')"
    dim "  Existing installation: $(which ota-touchid)"

    if [[ "$FORCE" != "1" && "$VERSION" != "latest" ]]; then
      green "Already installed. Set OTA_TOUCHID_FORCE=1 to reinstall."
      exit 0
    fi
  fi
}

# --- Download ---
download() {
  local url

  if [[ "$VERSION" == "latest" ]]; then
    url="https://github.com/$REPO/releases/latest/download/ota-touchid-macos-arm64.tar.gz"
  else
    url="https://github.com/$REPO/releases/download/$VERSION/ota-touchid-macos-arm64.tar.gz"
  fi

  echo "Downloading ota-touchid..."
  dim "  $url"

  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  if ! curl -fsSL "$url" -o "$tmp/ota-touchid.tar.gz"; then
    red "Download failed."
    echo "  Check the URL and your network connection."
    exit 1
  fi

  tar -xzf "$tmp/ota-touchid.tar.gz" -C "$tmp"

  # Verify the binary works before replacing anything
  if [[ -f "$tmp/ota-touchid/ota-touchid" ]]; then
    if ! "$tmp/ota-touchid/ota-touchid" help &>/dev/null; then
      red "Downloaded binary failed verification."
      exit 1
    fi
  else
    red "Expected binary not found in archive."
    exit 1
  fi

  # Install (no sudo — installs to ~/.local/bin)
  echo "Installing to $INSTALL_DIR..."
  mkdir -p "$INSTALL_DIR"
  cp "$tmp/ota-touchid/ota-touchid" "$BIN_LINK"
  chmod 755 "$BIN_LINK"

  green "Installed ota-touchid to $BIN_LINK"
}

# --- Verify ---
verify() {
  if ! command -v ota-touchid &>/dev/null; then
    # Check if ~/.local/bin is on PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
      echo ""
      red "ota-touchid installed but $INSTALL_DIR is not on your PATH."
      echo ""
      echo "  Add to your shell profile:"
      echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
      echo ""
      echo "  Then restart your shell or run:"
      echo "    source ~/.zshrc"
      return
    fi

    red "Installation failed — ota-touchid not found on PATH."
    exit 1
  fi

  echo ""
  ota-touchid help 2>&1 | head -1
  echo ""
  green "Ready."
  echo ""
  echo "  Server (Mac with Touch ID):  ota-touchid setup"
  echo "  Client (remote Mac):         ota-touchid pair <psk>"
}

# --- Main ---
bold "ota-touchid installer"
echo ""
check_prerequisites
echo ""
check_existing
echo ""
download
echo ""
verify
