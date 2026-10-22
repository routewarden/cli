#!/usr/bin/env bash
# scripts/update-version.sh
# RouteWarden CLI version update and synchronization script.
#
# Usage:
#   ./scripts/update-version.sh              # Reads version directly from version.json
#   ./scripts/update-version.sh v5.0.2       # Updates version.json and syncs across all files
#   ./scripts/update-version.sh 5.0.2        # Supports semver without 'v' prefix

set -euo pipefail

# 0. Help / Usage flag handling
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  echo "RouteWarden CLI Version Synchronization Tool"
  echo ""
  echo "Usage:"
  echo "  $0                  # Reads version from version.json and syncs codebase"
  echo "  $0 <version>        # Updates version.json and syncs across codebase"
  echo ""
  echo "Examples:"
  echo "  $0 v5.0.2"
  echo "  $0 5.1.0"
  echo "  $0 5.2.0-rc.1"
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${ROOT_DIR}/version.json"

# Helper for cross-platform in-place sed (macOS BSD sed vs Linux GNU sed)
if sed --version 2>&1 | grep -q GNU; then
  SED_IS_GNU=true
else
  SED_IS_GNU=false
fi

sed_inplace() {
  if [ "$SED_IS_GNU" = true ]; then
    sed -i -E "$@"
  else
    sed -i '' -E "$@"
  fi
}

# If a version argument was provided, update version.json first
if [ -n "${1:-}" ]; then
  RAW_VERSION="$1"

  # Ensure format has leading 'v'
  if [[ ! "$RAW_VERSION" =~ ^v ]]; then
    NEW_VERSION="v${RAW_VERSION}"
  else
    NEW_VERSION="${RAW_VERSION}"
  fi

  # Validate semver pattern (e.g. v1.2.3, v1.2.3-beta.1, v5.0.1+build.42)
  if [[ ! "$NEW_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
    echo "❌ Error: Invalid semantic version format: '$RAW_VERSION'"
    echo "Expected format: vMAJOR.MINOR.PATCH (e.g. v5.0.2 or 5.0.2)"
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

# Normalize TARGET_VERSION to always have leading 'v'
if [[ ! "$TARGET_VERSION" =~ ^v ]]; then
  TARGET_VERSION="v${TARGET_VERSION}"
fi

# Ensure version.json stays canonically formatted
cat <<EOF > "$VERSION_FILE"
{
  "version": "${TARGET_VERSION}"
}
EOF

SEMVER_NO_V="${TARGET_VERSION#v}"

echo "🔄 Synchronizing RouteWarden CLI version: ${TARGET_VERSION} (${SEMVER_NO_V})"

UPDATED_COUNT=0

# 1. Update main.go, cmd/shipper/main.go, and cmd/dashboard/main.go (var version = "X.Y.Z")
if [ -f "${ROOT_DIR}/main.go" ]; then
  sed_inplace "s|(var[[:space:]]+version[[:space:]]*=[[:space:]]*\")[^\"]*(\")|\1${SEMVER_NO_V}\2|g" "${ROOT_DIR}/main.go"
  echo "  ✓ Synchronized main.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

if [ -f "${ROOT_DIR}/cmd/shipper/main.go" ]; then
  sed_inplace "s|(var[[:space:]]+version[[:space:]]*=[[:space:]]*\")[^\"]*(\")|\1${SEMVER_NO_V}\2|g" "${ROOT_DIR}/cmd/shipper/main.go"
  echo "  ✓ Synchronized cmd/shipper/main.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

if [ -f "${ROOT_DIR}/cmd/dashboard/main.go" ]; then
  sed_inplace "s|(var[[:space:]]+version[[:space:]]*=[[:space:]]*\")[^\"]*(\")|\1${SEMVER_NO_V}\2|g" "${ROOT_DIR}/cmd/dashboard/main.go"
  echo "  ✓ Synchronized cmd/dashboard/main.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

if [ -f "${ROOT_DIR}/cmd/tcp-warden/main.go" ]; then
  sed_inplace "s|([[:space:]]*version[[:space:]]*=[[:space:]]*\")[^\"]*(\")|\1${SEMVER_NO_V}\2|g" "${ROOT_DIR}/cmd/tcp-warden/main.go"
  echo "  ✓ Synchronized cmd/tcp-warden/main.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

if [ -f "${ROOT_DIR}/proxy/plugins/sdk/sdk.go" ]; then
  sed_inplace "s|(const[[:space:]]+Version[[:space:]]*=[[:space:]]*\")[^\"]*(\")|\1${SEMVER_NO_V}\2|g" "${ROOT_DIR}/proxy/plugins/sdk/sdk.go"
  echo "  ✓ Synchronized proxy/plugins/sdk/sdk.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 2. Update package.json ("version": "X.Y.Z") if present
if [ -f "${ROOT_DIR}/package.json" ]; then
  sed_inplace "s|(\"version\"[[:space:]]*:[[:space:]]*\")[^\"]*(\")|\1${SEMVER_NO_V}\2|g" "${ROOT_DIR}/package.json"
  echo "  ✓ Synchronized package.json"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 3. Update observability/custom_dashboard.go (version badges and runtime specification)
if [ -f "${ROOT_DIR}/observability/custom_dashboard.go" ]; then
  sed_inplace "s|(RouteWarden Core v)[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9A-Za-z.-]+)?|\1${SEMVER_NO_V}|g" "${ROOT_DIR}/observability/custom_dashboard.go"
  sed_inplace "s|(CORE v)[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9A-Za-z.-]+)?|\1${SEMVER_NO_V}|g" "${ROOT_DIR}/observability/custom_dashboard.go"
  sed_inplace "s|(<span class=\"dash-version-badge\"[^>]*>v)[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9A-Za-z.-]+)?(</span>)|\1${SEMVER_NO_V}\4|g" "${ROOT_DIR}/observability/custom_dashboard.go"
  echo "  ✓ Synchronized observability/custom_dashboard.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 4. Update observability/auth_screen.go (terminal login version tag)
if [ -f "${ROOT_DIR}/observability/auth_screen.go" ]; then
  sed_inplace "s|(terminal\.login\.v)[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9A-Za-z.-]+)?|\1${SEMVER_NO_V}|g" "${ROOT_DIR}/observability/auth_screen.go"
  echo "  ✓ Synchronized observability/auth_screen.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 5. Update observability/manager.go (dashboard API and package Version)
if [ -f "${ROOT_DIR}/observability/manager.go" ]; then
  sed_inplace "s|(var[[:space:]]+Version[[:space:]]*=[[:space:]]*\")[^\"]*(\")|\1${SEMVER_NO_V}\2|g" "${ROOT_DIR}/observability/manager.go"
  sed_inplace "s|(\"version\":[[:space:]]+\")[^\"]*(\")|\1${SEMVER_NO_V}\2|g" "${ROOT_DIR}/observability/manager.go"
  echo "  ✓ Synchronized observability/manager.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 6. Update engine/audit.go (SARIF security linter report version)
if [ -f "${ROOT_DIR}/engine/audit.go" ]; then
  sed_inplace "s|(Version:[[:space:]]+\")[^\"]*(\",[[:space:]]*// tool version)|\1${SEMVER_NO_V}\2|g" "${ROOT_DIR}/engine/audit.go"
  echo "  ✓ Synchronized engine/audit.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 7. Update README.md version comment
if [ -f "${ROOT_DIR}/README.md" ]; then
  sed_inplace "s|(#?[[:space:]]*rwarden version )[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9A-Za-z.-]+)?|\1${SEMVER_NO_V}|g" "${ROOT_DIR}/README.md"
  echo "  ✓ Synchronized README.md"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 8. Update VERSIONING.md (canonical version block)
if [ -f "${ROOT_DIR}/VERSIONING.md" ]; then
  sed_inplace "s|(\"version\":[[:space:]]*\")v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${TARGET_VERSION}\3|g" "${ROOT_DIR}/VERSIONING.md"
  echo "  ✓ Synchronized VERSIONING.md"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 9. Update Dockerfiles (version documentation examples)
for DOCKERFILE in "${ROOT_DIR}/Dockerfile" "${ROOT_DIR}/Dockerfile.dashboard" "${ROOT_DIR}/Dockerfile.shipper" "${ROOT_DIR}/Dockerfile.tcp-warden"; do
  if [ -f "$DOCKERFILE" ]; then
    sed_inplace "s|(#[[:space:]]*VERSION[[:space:]]+.*\(e\.g\.[[:space:]]*)v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\))|\1${TARGET_VERSION}\3|g" "$DOCKERFILE"
    echo "  ✓ Synchronized $(basename "$DOCKERFILE")"
    UPDATED_COUNT=$((UPDATED_COUNT + 1))
  fi
done

# 10. Update test files if hardcoded version strings exist
if [ -f "${ROOT_DIR}/observability/ingest_test.go" ]; then
  sed_inplace "s|(res\[\"version\"\][[:space:]]*!=[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${SEMVER_NO_V}\3|g" "${ROOT_DIR}/observability/ingest_test.go"
  sed_inplace "s|(expected version )[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(,)|\1${SEMVER_NO_V}\3|g" "${ROOT_DIR}/observability/ingest_test.go"
  echo "  ✓ Synchronized observability/ingest_test.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

if [ -f "${ROOT_DIR}/integration_test.go" ]; then
  sed_inplace "s|(pubResp\.Version[[:space:]]*!=[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${SEMVER_NO_V}\3|g" "${ROOT_DIR}/integration_test.go"
  echo "  ✓ Synchronized integration_test.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

if [ -f "${ROOT_DIR}/man_unit_test.go" ]; then
  sed_inplace "s|(GenerateManPage\(\")[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\"\))|\1${SEMVER_NO_V}\3|g" "${ROOT_DIR}/man_unit_test.go"
  sed_inplace "s|(\"rwarden )[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${SEMVER_NO_V}\3|g" "${ROOT_DIR}/man_unit_test.go"
  echo "  ✓ Synchronized man_unit_test.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 11. Optional sync with sibling docs if present in RouteWarden monorepo
for DOC_VER in "${ROOT_DIR}/../docs/docs/version.json" "${ROOT_DIR}/../docs/version.json"; do
  if [ -f "$DOC_VER" ]; then
    sed_inplace "s|(\"cli\"[[:space:]]*:[[:space:]]*\")[^\"]*(\")|\1${TARGET_VERSION}\2|g" "$DOC_VER"
    echo "  ✓ Synchronized $(echo "$DOC_VER" | sed "s|${ROOT_DIR}/../||") (cli: ${TARGET_VERSION})"
    UPDATED_COUNT=$((UPDATED_COUNT + 1))
  fi
done

for SCRIPT in "${ROOT_DIR}/../docs/public/install.sh" "${ROOT_DIR}/../docs/docs/public/install.sh"; do
  if [ -f "$SCRIPT" ]; then
    sed_inplace "s|(LATEST_TAG=\")[^\"]*(\")|\1${TARGET_VERSION}\2|g" "$SCRIPT"
    sed_inplace "s|(Fallback to )v?[0-9]+\.[0-9]+\.[0-9]+|\1${TARGET_VERSION}|g" "$SCRIPT"
    echo "  ✓ Synchronized $(echo "$SCRIPT" | sed "s|${ROOT_DIR}/../||") (fallback: ${TARGET_VERSION})"
    UPDATED_COUNT=$((UPDATED_COUNT + 1))
  fi
done

# 12. Check CHANGELOG.md for release entry reminder
if [ -f "${ROOT_DIR}/CHANGELOG.md" ]; then
  if ! grep -q -E "\[${TARGET_VERSION}\]|\[v?${SEMVER_NO_V}\]" "${ROOT_DIR}/CHANGELOG.md"; then
    echo ""
    echo "  ⚠️  Note: ${TARGET_VERSION} is not yet mentioned in CHANGELOG.md. Don't forget to document your release notes!"
  fi
fi

echo ""
echo "✨ Successfully synchronized version ${TARGET_VERSION} across ${UPDATED_COUNT} target(s)!"
echo "👉 Next steps:"
echo "   git diff"
echo "   git commit -am 'chore: release ${TARGET_VERSION}'"
echo "   git tag ${TARGET_VERSION}"
echo "   git push origin main --tags"
