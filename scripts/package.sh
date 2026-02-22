#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
DIST="$ROOT/dist"
TARBALL="$DIST/ota-touchid-macos-arm64.tar.gz"

echo "Building release..."
cd "$ROOT"
swift build -c release --disable-sandbox 2>&1

echo "Packaging..."
rm -rf "$DIST"
mkdir -p "$DIST/ota-touchid"

# Copy binary
cp .build/release/ota-touchid "$DIST/ota-touchid/ota-touchid"

# Strip debug symbols for smaller size
strip -x "$DIST/ota-touchid/ota-touchid" 2>/dev/null || true

# Ad-hoc codesign (required on Apple Silicon)
codesign --force --sign - "$DIST/ota-touchid/ota-touchid" 2>/dev/null || true

# Create tarball
cd "$DIST"
tar -czf ota-touchid-macos-arm64.tar.gz ota-touchid/

# Show result
echo ""
echo "Distribution:"
ls -lh "$DIST/ota-touchid/ota-touchid"
echo ""
echo "Tarball:"
ls -lh "$TARBALL"
