#!/bin/sh
# RouteWarden CLI Pre-Removal Script (NFPM hook for deb, rpm, apk)
# Automatically stops running background services (dashboard, push shipper)
# and removes active sandbox containers before package removal.

set -e

# Stop background services and cleanup sandbox containers if rwarden is available
if command -v rwarden >/dev/null 2>&1; then
  rwarden stop >/dev/null 2>&1 || true
  rwarden cleanup >/dev/null 2>&1 || true
elif [ -x "/usr/local/bin/rwarden" ]; then
  /usr/local/bin/rwarden stop >/dev/null 2>&1 || true
  /usr/local/bin/rwarden cleanup >/dev/null 2>&1 || true
elif [ -x "/usr/bin/rwarden" ]; then
  /usr/bin/rwarden stop >/dev/null 2>&1 || true
  /usr/bin/rwarden cleanup >/dev/null 2>&1 || true
fi

# Stop standalone tcp-warden daemon if installed and running
if command -v tcp-warden >/dev/null 2>&1; then
  tcp-warden stop >/dev/null 2>&1 || true
elif [ -x "/usr/local/bin/tcp-warden" ]; then
  /usr/local/bin/tcp-warden stop >/dev/null 2>&1 || true
elif [ -x "/usr/bin/tcp-warden" ]; then
  /usr/bin/tcp-warden stop >/dev/null 2>&1 || true
fi

# Stop any running docker dashboard container if docker is accessible
if command -v docker >/dev/null 2>&1; then
  docker rm -f routewarden-dashboard >/dev/null 2>&1 || true
fi

exit 0
