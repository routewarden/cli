# Changelog

All notable changes to RouteWarden CLI (`rwarden`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v1.1.1] - 2026-09-21

### Fixed
- **CLI Test Output Formatting**: Fixed `rwarden test` command output to properly resolve and display custom HTTP status codes and response modes configured under `response.mode` and `response.statusCode` (e.g., `rateLimitChallenge`, `captcha`, `redirect`, `silentDrop`).
- **Response Mode Validation**: Ensured all engine response modes (including `rateLimitChallenge`, `proxy`, `infiniteStream`, etc.) compile, validate, and resolve correctly.

### Documentation & Packaging
- Synchronized CLI version across repository manifests (`version.json`, `main.go`, `package.json`, installation scripts, and documentation).

---

## [v1.1.0] - 2026-09-20

### Added
- Multi-architecture container images published to GitHub Container Registry (`ghcr.io/routewarden/cli`).
- Automated releases and cross-platform binary builds via GoReleaser.
- Version synchronization automation via `scripts/update-version.sh`.

### Fixed
- Fixed `generate` command flag handling and edge case test suites.
- Resolved macOS binary quarantine and installation issues.

---

## [v1.0.0] - 2026-09-20

### Added
- Initial release of RouteWarden CLI (`rwarden`).
- Security inspection and policy evaluation commands (`test`, `validate`, `generate`, `inspect`, `version`).
- Multi-platform standalone binary releases for macOS, Linux, and Windows.
