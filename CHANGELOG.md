# Changelog

All notable changes to RouteWarden CLI (`rwarden`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v3.0.0] - 2026-09-25

### Added

- **Self-Hosted Security Dashboard (`rwarden dashboard`)**:
  - Launch a real-time, zero-dependency web dashboard embedded directly inside the `rwarden` binary (`go:embed`) — no Node.js, no external database, no cloud services required.
  - **Zero-Config Docker Discovery**: Auto-detects and streams logs from running Traefik, Caddy, and NGINX gateway containers via the local Docker socket (`/var/run/docker.sock`).
  - **Log File Tailing**: Tail local log files or wildcard glob patterns (e.g. `/var/log/routewarden/*.log`) with automatic log rotation support.
  - **Real-Time Live Event Feed**: Low-latency WebSocket / SSE stream of blocked requests with paginated feed, full-text search, container filtering, pause/resume, and clear controls.
  - **Attack Analytics**: Interactive 24-hour, 6-hour, and 1-hour timelines, blocks-per-minute chart, top attacked endpoints, top offender IPs, response mode distribution.
  - **Sources & Container Management**: View all active Docker containers and tailed log files with live status badges and one-click filtering.

- **v1.2 — GeoIP & IP Intelligence**:
  - Country resolution with flag emojis via embedded MaxMind GeoLite2 MMDB or free `ip-api.com` live fallback.
  - **Deep IP Intelligence View** (`/api/ip/:ip`): Comprehensive per-IP profiling including threat risk score (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), ISP / ASN resolution, geographic location, behavioral pattern breakdown, top targeted endpoints, HTTP methods, response modes, and paginated event history.
  - **Config Viewer** (`/api/config/:id`): Inspect and render the live `routewarden.json` label configuration read from any discovered Docker container without leaving the dashboard.

- **Tailscale & NetBird Mesh VPN Auto-Detection**:
  - Native identification of Tailscale CGNAT peers (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) and NetBird overlay peers (`100.64.0.0/16`, `fd00::/8 ULA`) with dedicated `🔒` flag emoji, `VPN` country code, and full ISP/network metadata.
  - RFC 5737 documentation networks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) correctly classified as `LAN` / `Reserved Test Network`.

- **Dashboard REST & WebSocket API**:
  - `GET /api/health` — health check
  - `GET /api/events?n=N` — last N security events
  - `GET /api/stats?hours=N` — aggregated analytics
  - `GET /api/sources` — active log sources list
  - `POST /api/sources/clear` — remove stopped sources
  - `GET /api/config/:id` — container config viewer
  - `GET /api/geoip?ip=...` — IP geolocation lookup
  - `GET /api/ip/:ip` or `GET /api/ip?ip=...` — full IP intelligence
  - `WS /ws/events` — live event streaming

- **CLI Flags for `dashboard` command**:

  | Flag | Default | Description |
  |:---|:---|:---|
  | `--port` | `9090` | Port to serve the dashboard |
  | `--host` | `127.0.0.1` | Bind address (`0.0.0.0` for Docker/remote) |
  | `--log` | `""` | Log file path or glob pattern (repeatable) |
  | `--no-docker` | `false` | Disable Docker socket discovery |
  | `--socket` | `/var/run/docker.sock` | Docker socket path |
  | `--history` | `1000` | Events retained in memory |
  | `--no-open` | `false` | Suppress auto-opening the browser |

### Changed

- Documentation site updated with a dedicated **Security Dashboard** section in the VitePress sidebar, covering all dashboard views with real screenshots.
- Sidebar scroll-spy updated to dynamically track all anchor IDs (including all dashboard subsections) and auto-scroll the sidebar container to keep the active section in view.
- Top navigation bar updated with a direct **Dashboard** entry.

---

## [v2.1.0] - 2026-09-24

### Added
- **Flexible Positional Arguments & Lenient Flag Parsing**:
  - Direct positional inputs for all commands: `rwarden test /.env`, `rwarden validate [config]`, `rwarden generate <target> [config]`, and `rwarden sandbox <target> [config]`.
  - Flags can now be placed interchangeably before or after positional arguments.
  - Automatic fallback to `routewarden.json` in current working directory when `--config` is omitted in `validate` and `generate`.
- **Shorthand Flag Aliases**:
  - Added `-c` for `--config`, `-t` for `--target`, `-q` for `--query`, `-X` and `-m` for `--method`, `-H` (repeatable) for `--header`, `-n` for `--dry-run`, `-d` for `--detach`, `-p` for `--print-config`, and `-v` for `version`.
- **Target & Format Aliases**:
  - Target generator and sandbox accept standard aliases: `yaml`, `yml`, `toml`, `compose`, `labels`, `docker-compose`, `caddyfile`, `openresty`.
- **Production Gateway Config Adaptation in Sandbox**:
  - Support for passing complete, production Traefik (`traefik.yaml`, `traefik.toml`), Docker Compose (`docker-compose.yaml`), Caddy (`Caddyfile`), and NGINX (`nginx.conf`) files directly to `rwarden sandbox`.
  - In-memory auto-adaptation: rewrites external upstream backend URLs, proxies, and certificates for isolated local testing without modifying original configuration files.
  - Live probe testing (`--test`) accommodates upstream reachability (HTTP 200, 502, 504) as allowlist pass-through.
- **Dedicated Sandbox Teardown Command**:
  - `rwarden cleanup` (and `rwarden sandbox cleanup`) to stop and prune dangling or detached sandbox containers in one command.

### Fixed
- **Regex & Configuration Parsing**:
  - Fixed RE2 regex backreference in Traefik label parsing to ensure 100% Go regexp standard library compliance.
  - Prevented multiline upstream regex greediness in NGINX config adaptation from corrupting `server {` blocks.
  - Injected missing `middlewares:` parent block in synthetic Traefik sandbox YAML generation.
  - Enhanced label normalization to recognize root-level response parameters (`status`, `statusCode`, `mode`, `action`, `customResponseText`).
  - Removed legacy direct boolean `silentDrop` property from `Config` schema, structs, and Docker label converters (use `mode: "silentDrop"`, `action: "silentDrop"`, or `response.mode: "silentDrop"` instead).

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
