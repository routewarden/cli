#!/usr/bin/env bash
# RouteWarden CLI (rwarden) Universal Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/routewarden/cli/main/install.sh | bash
#
# Supports:
#   - Linux (x86_64, arm64)
#   - macOS / Darwin (x86_64, Apple Silicon arm64)
#   - Windows via Git Bash / WSL

set -e

OWNER="routewarden"
REPO="cli"
BINARY="rwarden"

# Detect OS
OS="$(uname -s)"
case "${OS}" in
  Linux*)  TARGET_OS="linux" ;;
  Darwin*) TARGET_OS="darwin" ;;
  CYGWIN*|MINGW*|MSYS*) TARGET_OS="windows" ;;
  *)
    echo "❌ Error: Unsupported operating system '${OS}'." >&2
    exit 1
    ;;
esac

# Detect Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64) TARGET_ARCH="amd64" ;;
  arm64|aarch64) TARGET_ARCH="arm64" ;;
  *)
    echo "❌ Error: Unsupported architecture '${ARCH}'." >&2
    exit 1
    ;;
esac

# Destination directory
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
if [ ! -w "${INSTALL_DIR}" ] && [ "$(id -u)" != "0" ]; then
  USE_SUDO="sudo"
else
  USE_SUDO=""
fi

echo "🔍 Detecting latest version of ${BINARY}..."

# Fetch latest release tag
LATEST_TAG=$(curl -s "https://api.github.com/repos/${OWNER}/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "${LATEST_TAG}" ]; then
  # Fallback to v1.1.0 if GitHub API rate limit is exceeded
  LATEST_TAG="v1.1.0"
fi

VERSION="${LATEST_TAG#v}"
EXT="tar.gz"
if [ "${TARGET_OS}" = "windows" ]; then
  EXT="zip"
fi

ARCHIVE_NAME="${BINARY}_${VERSION}_${TARGET_OS}_${TARGET_ARCH}.${EXT}"
DOWNLOAD_URL="https://github.com/${OWNER}/${REPO}/releases/download/${LATEST_TAG}/${ARCHIVE_NAME}"

echo "📦 Downloading ${BINARY} ${LATEST_TAG} (${TARGET_OS}/${TARGET_ARCH})..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

if ! curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/${ARCHIVE_NAME}"; then
  echo "❌ Error: Failed to download release archive from:" >&2
  echo "   ${DOWNLOAD_URL}" >&2
  exit 1
fi

echo "📂 Extracting archive..."
if [ "${EXT}" = "zip" ]; then
  unzip -q "${TMP_DIR}/${ARCHIVE_NAME}" -d "${TMP_DIR}"
else
  tar -xzf "${TMP_DIR}/${ARCHIVE_NAME}" -C "${TMP_DIR}"
fi

echo "🚀 Installing ${BINARY} to ${INSTALL_DIR}..."
${USE_SUDO} mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
${USE_SUDO} chmod +x "${INSTALL_DIR}/${BINARY}"

if [ "${TARGET_OS}" = "darwin" ] && command -v xattr >/dev/null 2>&1; then
  ${USE_SUDO} xattr -d com.apple.quarantine "${INSTALL_DIR}/${BINARY}" >/dev/null 2>&1 || true
fi

echo "✅ Successfully installed ${BINARY} (${LATEST_TAG}) to ${INSTALL_DIR}/${BINARY}!"
echo ""
echo "Run '${BINARY} --help' or '${BINARY} test --path \"/.env\"' to get started."
