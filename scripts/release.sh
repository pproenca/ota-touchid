#!/bin/bash
set -euo pipefail

# ota-touchid release script
# Usage: ./scripts/release.sh [major|minor|patch]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
REPO="pproenca/ota-touchid"
TAP_REPO="pproenca/homebrew-tap"

# --- Argument ---
BUMP="${1:-}"
if [[ ! "$BUMP" =~ ^(major|minor|patch)$ ]]; then
  echo "Usage: $0 [major|minor|patch]"
  exit 1
fi

# --- Current version from latest git tag ---
cd "$ROOT"
LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
CURRENT="${LATEST_TAG#v}"
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

case "$BUMP" in
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
  minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
  patch) PATCH=$((PATCH + 1)) ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
NEW_TAG="v${NEW_VERSION}"

echo "Releasing: ${LATEST_TAG} → ${NEW_TAG} (${BUMP})"
echo ""

# --- Preflight checks ---
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Error: working tree is dirty. Commit or stash changes first."
  exit 1
fi

if git rev-parse "$NEW_TAG" >/dev/null 2>&1; then
  echo "Error: tag ${NEW_TAG} already exists."
  exit 1
fi

# --- Build & package ---
echo "Building release..."
"$SCRIPT_DIR/package.sh"

TARBALL="$ROOT/dist/ota-touchid-macos-arm64.tar.gz"
if [[ ! -f "$TARBALL" ]]; then
  echo "Error: tarball not found at $TARBALL"
  exit 1
fi

SHA256=$(shasum -a 256 "$TARBALL" | awk '{print $1}')
echo "SHA256: $SHA256"
echo ""

# --- Tag & push ---
echo "Tagging ${NEW_TAG}..."
git tag -a "$NEW_TAG" -m "Release ${NEW_TAG}"
git push origin master --tags

# --- GitHub release ---
echo "Creating GitHub release ${NEW_TAG}..."
gh release create "$NEW_TAG" "$TARBALL" \
  --repo "$REPO" \
  --title "$NEW_TAG" \
  --generate-notes

# --- Update Homebrew tap ---
echo "Updating Homebrew formula in ${TAP_REPO}..."
FORMULA_PATH="Formula/ota-touchid.rb"

# Fetch current formula
CURRENT_FORMULA=$(gh api "repos/${TAP_REPO}/contents/${FORMULA_PATH}" --jq '.content' | base64 -d)
CURRENT_SHA=$(gh api "repos/${TAP_REPO}/contents/${FORMULA_PATH}" --jq '.sha')

# Replace url, sha256, and version
UPDATED_FORMULA=$(echo "$CURRENT_FORMULA" \
  | sed -E "s|url \"https://github.com/${REPO}/releases/download/v[^\"]+/|url \"https://github.com/${REPO}/releases/download/${NEW_TAG}/|" \
  | sed -E "s|sha256 \"[a-f0-9]+\"|sha256 \"${SHA256}\"|" \
  | sed -E "s|version \"[^\"]+\"|version \"${NEW_VERSION}\"|")

# Push updated formula
echo "$UPDATED_FORMULA" | gh api "repos/${TAP_REPO}/contents/${FORMULA_PATH}" \
  --method PUT \
  --field message="Update ota-touchid to ${NEW_TAG}" \
  --field sha="$CURRENT_SHA" \
  --raw-field content="$(echo "$UPDATED_FORMULA" | base64)" \
  --silent

echo ""
echo "Done! Released ${NEW_TAG}"
echo "  GitHub: https://github.com/${REPO}/releases/tag/${NEW_TAG}"
echo "  Brew:   brew upgrade ota-touchid"
