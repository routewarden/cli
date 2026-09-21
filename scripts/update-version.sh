#!/usr/bin/env bash
# scripts/update-version.sh
# RouteWarden CLI version update and synchronization script.
#
# Usage:
#   ./scripts/update-version.sh              # Reads version directly from version.json
#   ./scripts/update-version.sh v1.1.0       # Updates version.json and syncs across all files
#   ./scripts/update-version.sh 1.1.0        # Supports semver without 'v' prefix

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${ROOT_DIR}/version.json"

# If a version argument was provided, update version.json first
if [ -n "${1:-}" ]; then
  RAW_VERSION="$1"

  # Ensure format has leading 'v'
  if [[ ! "$RAW_VERSION" =~ ^v ]]; then
    NEW_VERSION="v${RAW_VERSION}"
  else
    NEW_VERSION="${RAW_VERSION}"
  fi

  # Validate semver pattern (e.g. v1.2.3, v1.2.3-beta.1)
  if [[ ! "$NEW_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "❌ Error: Invalid semantic version format: '$RAW_VERSION'"
    echo "Expected format: vMAJOR.MINOR.PATCH (e.g. v1.1.0)"
    exit 1
  fi

  # Write back to version.json
  cat <<EOF > "$VERSION_FILE"
{
  "version": "${NEW_VERSION}"
}
EOF
fi

# Ensure version.json exists
if [ ! -f "$VERSION_FILE" ]; then
  echo "❌ Error: ${VERSION_FILE} not found and no version argument provided."
  echo "Usage: $0 [version]"
  exit 1
fi

# Extract version from version.json (compatible with grep/sed without requiring jq)
TARGET_VERSION=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$VERSION_FILE" | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$TARGET_VERSION" ]; then
  echo "❌ Error: Could not read 'version' key from ${VERSION_FILE}."
  exit 1
fi

SEMVER_NO_V="${TARGET_VERSION#v}"

echo "🔄 Synchronizing RouteWarden CLI version: ${TARGET_VERSION} (${SEMVER_NO_V})"

UPDATED_COUNT=0

# 1. Update main.go (var version = "X.Y.Z")
if [ -f "${ROOT_DIR}/main.go" ]; then
  sed -i '' -E "s|(var[[:space:]]+version[[:space:]]*=[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${SEMVER_NO_V}\3|g" "${ROOT_DIR}/main.go"
  echo "  ✓ Synchronized main.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 2. Update package.json ("version": "X.Y.Z")
if [ -f "${ROOT_DIR}/package.json" ]; then
  sed -i '' -E "s|(\"version\"[[:space:]]*:[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${SEMVER_NO_V}\3|g" "${ROOT_DIR}/package.json"
  echo "  ✓ Synchronized package.json"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 3. Update install.sh (fallback LATEST_TAG="vX.Y.Z")
if [ -f "${ROOT_DIR}/install.sh" ]; then
  sed -i '' -E "s|(LATEST_TAG=\")v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${TARGET_VERSION}\3|g" "${ROOT_DIR}/install.sh"
  sed -i '' -E "s|(Fallback to )v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?|\1${TARGET_VERSION}|g" "${ROOT_DIR}/install.sh"
  echo "  ✓ Synchronized install.sh"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 4. Update docs/public/install.sh if present
if [ -f "${ROOT_DIR}/docs/public/install.sh" ]; then
  sed -i '' -E "s|(LATEST_TAG=\")v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${TARGET_VERSION}\3|g" "${ROOT_DIR}/docs/public/install.sh"
  sed -i '' -E "s|(Fallback to )v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?|\1${TARGET_VERSION}|g" "${ROOT_DIR}/docs/public/install.sh"
  echo "  ✓ Synchronized docs/public/install.sh"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 5. Update README.md version comment
if [ -f "${ROOT_DIR}/README.md" ]; then
  sed -i '' -E "s|(# rwarden version )[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?|\1${SEMVER_NO_V}|g" "${ROOT_DIR}/README.md"
  echo "  ✓ Synchronized README.md"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 6. Update docs/index.md if present
if [ -f "${ROOT_DIR}/docs/index.md" ]; then
  sed -i '' -E "s|(# rwarden version )[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?|\1${SEMVER_NO_V}|g" "${ROOT_DIR}/docs/index.md"
  echo "  ✓ Synchronized docs/index.md"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

echo ""
echo "✨ Successfully synchronized version ${TARGET_VERSION} across ${UPDATED_COUNT} file(s)!"
echo "👉 Next steps:"
echo "   git diff"
echo "   git commit -am 'chore: release ${TARGET_VERSION}'"
echo "   git tag ${TARGET_VERSION}"
echo "   git push origin main --tags"
