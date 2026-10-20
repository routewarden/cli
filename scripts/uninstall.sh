#!/usr/bin/env bash
# RouteWarden CLI (rwarden) Universal Uninstaller
# Usage: curl -fsSL https://routewarden.github.io/uninstall.sh | bash
#
# Automatically stops all background services (dashboard, push shipper, containers)
# and removes the binary from the system PATH.

set -e

BINARY="rwarden"

echo "🛑 Stopping RouteWarden services and removing active containers..."
if command -v "${BINARY}" >/dev/null 2>&1; then
  "${BINARY}" stop >/dev/null 2>&1 || true
  "${BINARY}" cleanup >/dev/null 2>&1 || true
elif [ -x "/usr/local/bin/${BINARY}" ]; then
  /usr/local/bin/${BINARY} stop >/dev/null 2>&1 || true
  /usr/local/bin/${BINARY} cleanup >/dev/null 2>&1 || true
elif [ -x "$HOME/.local/bin/${BINARY}" ]; then
  "$HOME/.local/bin/${BINARY}" stop >/dev/null 2>&1 || true
  "$HOME/.local/bin/${BINARY}" cleanup >/dev/null 2>&1 || true
fi

# Stop any running docker dashboard container if docker is accessible
if command -v docker >/dev/null 2>&1; then
  docker rm -f routewarden-dashboard >/dev/null 2>&1 || true
fi

# Locate and remove binary
REMOVED=0
TARGET_PATHS=(
  "/usr/local/bin/${BINARY}"
  "$HOME/.local/bin/${BINARY}"
  "/usr/bin/${BINARY}"
)

WHICH_PATH="$(command -v ${BINARY} 2>/dev/null || true)"
if [ -n "${WHICH_PATH}" ]; then
  TARGET_PATHS+=("${WHICH_PATH}")
fi

for TARGET in "${TARGET_PATHS[@]}"; do
  if [ -f "${TARGET}" ] || [ -L "${TARGET}" ]; then
    echo "🗑️  Removing ${TARGET}..."
    if [ -w "$(dirname "${TARGET}")" ] || [ "$(id -u)" = "0" ]; then
      rm -f "${TARGET}"
    else
      sudo rm -f "${TARGET}"
    fi
    REMOVED=1
  fi
done

if [ "${REMOVED}" -eq 1 ]; then
  echo "✅ Successfully uninstalled ${BINARY}."
else
  echo "ℹ️  No ${BINARY} binary found in standard install locations."
fi

# Clean up ~/.routewarden runtime data if present
RW_DATA_DIR="$HOME/.routewarden"
if [ -d "${RW_DATA_DIR}" ]; then
  echo "🧹 Removing ~/.routewarden runtime data and state..."
  rm -rf "${RW_DATA_DIR}"
fi

echo "✨ RouteWarden uninstallation complete."
