# Changelog

All notable changes to RouteWarden CLI (`rwarden`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v2.0.0] - 2026-09-21

### Added
- **Ephemeral Gateway Sandbox (`rwarden sandbox`)**:
  - Spin up live, ephemeral container environments for **Traefik**, **Caddy**, and **NGINX (OpenResty)** pre-configured with RouteWarden security rules.
  - Automatically translates and mounts native dynamic configurations (`dynamic.yml`, `Caddyfile`, `nginx.conf`) into isolated test containers.
  - Interactive foreground mode with instant graceful teardown on `Ctrl+C`.
  - Detached background mode (`--detach` / `-d`) for local dev workflows and integration testing.
  - Automated probe testing (`--test`) to execute live HTTP test suites asserting blocking and bypass behavior directly against the running container.
  - Dry-run mode (`--dry-run`) to inspect generated gateway configurations and exact Docker run commands without launching containers.
  - Print configuration option (`--print-config` / `-p`) to output generated gateway configuration before launching.
- **Custom RouteWarden Plugin Support**:
  - `--plugin-version`: Specify custom plugin version/tag/branch for testing specific releases (Traefik plugin catalog version, Caddy / NGINX container tag).
  - `--plugin-path`: Mount local plugin repository directories for real-time plugin development and verification.
- **Pre-flight Environment Validation**:
  - Added early Docker installation and daemon accessibility checks (`CheckDockerInstalled`) to fail fast with actionable guidance before preparing or running containers.
- **Enhanced Container Tooling**:
  - Included `docker-cli` inside the RouteWarden container image (`ghcr.io/routewarden/cli`) to enable running sandboxes from within Docker via `/var/run/docker.sock`.

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
