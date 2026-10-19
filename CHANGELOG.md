# RouteWarden CLI Changelog

All notable changes to the RouteWarden CLI (`rwarden`) are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and the CLI adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v5.0.1] - 2026-10-19 (Latest)

### Added
- **Top-Level `rwarden up` Command**:
  - Added `rwarden up` and `rwarden start` as direct top-level shortcuts for launching the real-time SOC security dashboard without needing `rwarden dashboard up`.
  - Added full shell autocompletions for `up` across Bash, Zsh, Fish, and PowerShell (`rwarden completion`).
  - Updated manual page generator (`rwarden man`) with documentation for `up`.
- **Zero-Touch Environment Variable Auto-Configuration**:
  - Added support for `RW_DASHBOARD_URL` (or `RW_URL`) and `RW_AGENT_KEY` (or `RW_KEY`) in both `rwarden push` and `rwarden register` (as well as `rwarden-shipper`). Nodes can now stream logs or register directly without command-line flags or pre-existing config files, ideal for containerized deployments.
  - Added `PORT` and `RW_DASHBOARD_HOST` environment variable support for `rwarden up` / `rwarden dashboard` and `rwarden-dashboard`.
- **Dynamic Public Key Auto-Discovery**:
  - `rwarden push` and `rwarden-shipper` now automatically query `/api/v1/pubkey` from the central dashboard on startup when `server_pubkey` is not present in local configuration, enabling full end-to-end asymmetric encryption (X25519 ECDH + AES-256-GCM) without requiring a prior manual `register` command.
- **Continuous Monitored File Streaming Daemon (`watchAndStreamFile`)**:
  - Added dedicated continuous log streaming for `rwarden dashboard --file <path>` with automatic log rotation detection (inode change tracking) and file truncation handling.

### Fixed
- **10MB Buffer Support for High-Volume Log Streaming**:
  - Increased `bufio.NewScanner` buffer limits from Go's default 64KB up to 10MB across all streaming and tailing pipelines (`tailFileToChan`, `tailContainerToChan`, `streamContainerLogs`, `watchAndStreamContainers`, and `watchAndStreamFile`), eliminating `bufio.Scanner: token too long` crashes on high-volume access logs or wide JSON payloads.
- **Windows Detached Process Liveness & Console Isolation**:
  - Fixed Windows daemon alive checks in `daemon_windows.go` and `daemon/daemon_windows.go` by verifying process exit codes (`STILL_ACTIVE` 259) via `GetExitCodeProcess` and testing non-blocking synchronization with `WaitForSingleObject`, eliminating phantom running statuses for killed background processes.
  - Isolated background processes from the parent console using `CREATE_NEW_PROCESS_GROUP | 0x08000008` (DETACHED_PROCESS).
- **Flexible Log Timestamp Parsing**:
  - Added `parseFlexibleTimestamp` supporting `RFC3339Nano`, space-separated timestamps (`2006-01-02 15:04:05`), and Apache/NGINX common log formats (`02/Jan/2006:15:04:05 -0700`).
- **Memory Capping for High-Volume Ingestion**:
  - Added automated cache pruning when tracking unique IPs (>5,000) and unique paths (>5,000) in `EventStore`, capping memory consumption for long-lived production dashboard instances.
- **Flag Binding Aliases**:
  - Bound short flag aliases directly to identical pointers using `fs.StringVar` / `fs.BoolVar` across `handleGenerate`, `handleSandbox`, and `handleTest`, preventing flag override bugs.
- **Automated Version Synchronization & Test Assertion Stability**:
  - Overhauled `scripts/update-version.sh` with robust GNU/BSD `sed` detection, multi-target synchronization across micro-binaries, Dockerfiles, test assertions, VitePress docs registry, and installer scripts.
  - Exported `observability.Version` package variable preventing version-mismatch test breakages on version bumps.

---

## [v5.0.0] - 2026-10-18

### Added
- **Distributed Remote Log Shipping & Enrollment (`rwarden push`, `keys`, `register`)**:
  - Introduced a CrowdSec-style distributed log shipping model allowing multiple remote edge servers, cloud VMs, and Kubernetes clusters to stream live telemetry to a central RouteWarden dashboard.
  - **`rwarden keys`**: Generate (`keys create <name>`), list (`keys list`), and revoke (`keys revoke <id>`) 24-byte cryptographically secure agent authentication tokens (`rw_sec_...`).
  - **`rwarden register`**: One-time registration handshake connecting remote nodes to the central dashboard, automatically fetching the server's public key, and persisting configuration in `~/.routewarden/agent.json` with strict `0600` permissions.
  - **`rwarden push`**: Zero-flag background log shipper reading saved credentials, auto-discovering labeled Docker containers (`routewarden=true`) or tailing local log files (`--file`), and streaming encrypted batches.
  - **In-Memory Ring Buffer**: Implemented a 2,000-event in-memory ring buffer (~2MB max RAM) ensuring zero disk wear on edge SSDs.
  - **Resilience & Backoff**: Added automated 30-second heartbeat pings and 3-stage exponential backoff retry on network drops.
- **End-to-End Asymmetric Cryptography (X25519 ECDH + AES-256-GCM)**:
  - Central server maintains a master X25519 keypair (`server.key` / `server.pub`).
  - Remote agents derive ephemeral shared secrets via X25519 ECDH with SHA-256 HKDF and encrypt log batches with AES-256-GCM.
  - Intermediate proxies or network observers cannot inspect or tamper with log payloads in transit.
- **Native Detached Background Daemon Execution (`--detach` / `-d`, `status`, `stop`)**:
  - Added native background process detachment for both `rwarden dashboard` and `rwarden push` via `--detach` (or `-d`).
  - Implemented cross-platform PID tracking (`~/.routewarden/*.pid`) and persistent background log redirection (`~/.routewarden/*.log`).
  - Added global and subsystem-scoped management commands: `rwarden status [dashboard|push]` and `rwarden stop [dashboard|push]`.
- **Standalone Micro-Binaries (`cmd/shipper` & `cmd/dashboard`)**:
  - **`rwarden-shipper` (`cmd/shipper`)**: Ultra-lean micro-binary (**~6.2 MB**) stripped of SQLite, embedded Web UI assets, HTML/JS/CSS, and GeoIP code. Dedicated for edge nodes and low-RAM VPS instances.
  - **`rwarden-dashboard` (`cmd/dashboard`)**: Standalone SOC dashboard server binary (**~11 MB**) dedicated to web serving, SQLite persistence, and SSE event streaming.
  - **Monolithic Host CLI (`rwarden`)**: Unified full toolkit maintained at ~12 MB with zero external runtime dependencies.
- **Dedicated Container Distribution Images (`cli`, `shipper`, `dashboard`)**:
  - Published three targeted images to GitHub Container Registry (`ghcr.io/routewarden`):
    - **`ghcr.io/routewarden/cli:latest`**: Unified full toolkit (~12 MB binary) with Docker CLI for container tailing.
    - **`ghcr.io/routewarden/shipper:latest`**: Ultra-lean micro-image (**~6.2 MB binary**) with zero SQLite and zero UI assets, supporting Docker socket tailing, multiple access log files, and hybrid ingestion.
    - **`ghcr.io/routewarden/dashboard:latest`**: Standalone SOC security dashboard image (~11 MB binary) serving port `7890`.
- **Concurrent Multi-Source & Multiple File Ingestion**:
  - Added support for concurrent multiple log file tailing via repeatable `-f`, comma-separated paths, glob patterns (`*.log`), and positional arguments alongside Docker container discovery.
- **Real-Time Central Dashboard Status Ribbon & Sources API**:
  - Injected real-time status ribbon into SOC dashboard interface displaying both local containers and remote nodes with dynamic online/idle/offline health pulses.
  - Extended `/api/sources` to return live telemetry and event counters for all connected remote agents.
  - Added automated log translation from Traefik JSON, Nginx text, Caddy JSON, and RouteWarden security verdicts into unified NCSA/Combined log format.
- **Ultra-Lightweight Real-Time Security Dashboard (`rwarden dashboard`)**:
  - Replaced the multi-container monitoring stack with an ultra-lightweight real-time security dashboard powered by RouteWarden's embedded SOC engine and SQLite persistence.
  - Drastically reduced memory footprint from ~350MB+ down to **~8MB RAM**.
  - Single-port embedded HTTP web server and SSE stream serving live interactive analytics at `http://localhost:7890`.
  - Automatic Docker container discovery for `routewarden=true` / `routewarden.logs=true` via `/var/run/docker.sock`.
  - Native execution engine: serves self-contained SOC dashboard and real-time SSE stream with zero external dependencies.
  - Added flexible flags: `--port` (default 7890), `--file` (monitor specific log file), `--container` (tail target container), `--label` (custom Docker discovery label), `--no-open`, and `--export`.
- **Built-in Roff Man Page Generator (`rwarden man`)**:
  - Expanded `man.go` generator to cover `keys`, `register`, `push`, `status`, and `stop` subcommands and flags.
- **Shell Autocompletion Scripts (`rwarden completion`)**:
  - Added completion for `-d` / `--detach`, `status`, `stop`, `dashboard_cmds`, and `push_cmds` across Bash, Zsh, Fish, and PowerShell.
- **Comprehensive Unit & Integration Test Suites**:
  - Added zero-socket integration and unit tests covering cryptographic edge cases (`crypto_test.go`), keystore management (`keys_test.go`), ingestion endpoints (`ingest_test.go`), registration & flusher retries (`register_test.go`, `push_flusher_test.go`), and concurrent multi-agent streaming (`integration_test.go`).
- **Native Linux Package Management via NFPM (`.deb`, `.rpm`, `.apk`)**:
  - Configured GoReleaser NFPM packager to build and publish native packages across major Linux distributions:
    - **Debian / Ubuntu (`.deb`)**: Direct installation via APT (`curl -fsSLO ... && sudo apt install ./rwarden_linux_amd64.deb`) with automated dependency resolution.
    - **Red Hat / Fedora / CentOS / Rocky Linux (`.rpm`)**: Direct package installation via RPM (`sudo rpm -ivh ...`).
    - **Alpine Linux (`.apk`)**: Standalone APK package installation (`apk add --allow-untrusted ...`).
  - Standardized package metadata, license file mapping to `/usr/share/doc/rwarden/copyright`, and binary placement in `/usr/local/bin/rwarden`.
- **Official Homebrew Tap Integration (`routewarden/homebrew-tap`)**:
  - Published official Homebrew formula `Formula/rwarden.rb` supporting native compilation and bottled releases via `brew install routewarden/tap/rwarden`.
  - Added automated GoReleaser v2 `brews` formula publishing pipeline triggered on release tags with fine-grained GitHub token authentication.
- **Dedicated macOS and Linux Installation Documentation**:
  - Redesigned the [CLI Installation Guide](/cli/installation) and [CLI Overview](/cli/) with tabbed, platform-specific installation workflows for macOS (Homebrew, automated curl installer, manual binary, Gatekeeper quarantine mitigation) and Linux (APT, Homebrew, RPM, APK, curl, manual binary).
  - Added comprehensive uninstallation commands covering Homebrew, APT, RPM, APK, and standalone binaries.

### Changed
- **Multi-Image CI/CD Workflows**:
  - Updated GitHub Actions workflows (`ci.yml` and `release.yml`) to build, test, and publish `cli`, `shipper`, and `dashboard` container images.
- **Synchronized Versioning Script (`scripts/update-version.sh`)**:
  - Synchronizes versions across root `main.go`, `cmd/shipper/main.go`, and `cmd/dashboard/main.go`.
- **Version Alignment & Installer Script Synchronization**:
  - Upgraded universal installer script (`install.sh`) fallback and default tag to `v5.0.0`.
  - Synced documentation version registry (`version.json`) and release download artifacts to `v5.0.0`.

---

## [v4.5.3] - 2026-10-17

### Added
- **Official Homebrew Tap Integration (`routewarden/homebrew-tap`)**:
  - Published official Homebrew formula `Formula/rwarden.rb` supporting installation via `brew install routewarden/tap/rwarden`.
  - Added GoReleaser v2 `brews` automated formula publishing configuration in `.goreleaser.yaml` and release workflow.

---

## [v4.5.2] - 2026-10-17

### Fixed
- **Duplicate Time Column in Incident Triage Table (`routewarden-overview.json`)**:
  - Excluded raw JSON timestamp attributes (`timestamp`, `time`, `ts`) in the `organize` transformation of Panel 50 (**🚨 Interactive Threat Incident Triage Table**), eliminating the duplicate time column.
  - Excluded auxiliary and middleware fields (`request_uri`, `geoip_country_code`, `geoip_country_name`, `is_private`, `duration`) to prevent unindexed columns from cluttering the incident triage grid.
- **Observability Dashboard Metric & Legend Standardization**:
  - Added clean `legendFormat` templating across **Top Target Paths** (`{{path}}`), **Top Triggered Rules / Signatures** (`{{matched_pattern}}`), **Security Events by Verdict Over Time** (`{{verdict}}`), and **Verdict Breakdown** (`{{verdict}}`), eliminating raw Loki label syntax.
  - Standardized verdict color mappings (`BLOCK` = red, `ALLOW` = green, `THROTTLED` = yellow, `BYPASS` = blue) across trend graphs and donut charts.

---

## [v4.5.1] - 2026-10-17

### Fixed
- **Pure Non-Root GeoIP Init Container Execution (`docker-compose.yml`)**:
  - Reconfigured `geoip-init` volume mount target to `/home/curl_user` (the native home directory of `curl_user`), eliminating root permission write errors (`curl: (23) client returned ERROR on write`).
  - Removed requirement for elevated container privileges (`user: "0:0"`), ensuring the entire RouteWarden observability stack runs strictly under unprivileged user contexts.

---

## [v4.5.0] - 2026-10-17

### Added
- **Automated Ingestion-Time GeoIP Resolution (`config.alloy` & `docker-compose.yml`)**:
  - Integrated `stage.geoip` into the log processing pipeline to resolve raw `client_ip` against MaxMind `GeoLite2-Country.mmdb`.
  - Added template stages normalizing `country_code` (injecting MaxMind ISO 3166-1 alpha-2 code and classifying RFC 1918 / loopback ranges as `LAN`) and human-readable `country_name` (or `"Local Network"`).
  - Added automated `geoip-init` service in bundled Docker Compose stack with configurable `GEOIP_DB_URL` mirror for zero-friction database acquisition.
  - Exposed `geoip-data` persistent volume mounted read-only to Alloy (`/etc/alloy/geoip:ro`).
- **Enhanced Threat Profiling & Observability Panels (`routewarden-overview.json`)**:
  - Renamed "Top Attacked Endpoints" to **"Top Target Paths"** and upgraded LogQL query with dynamic template filtering (`verdict=~"$verdict"`).
  - Added **`🛡️ Defense Action Breakdown`** donut chart panel visualizing enforcement mode distributions (`silentDrop`, `text`, `json`, `custom`, `default`).
  - Added **`🌐 Top Protected Virtual Hosts & Services`** bar gauge panel displaying the top backend services and virtual hosts under threat.
  - Added **`⏱️ Threat Inspection Latency & Tarpit Timing`** dual-series timeseries panel tracking p95 and average execution latency (`duration_ms` / `latency_ms`).
  - Rebalanced Threat Analysis grid layout into a structured 3-column row and adjusted downstream incident triage table and log stream rows.

---

## [v4.4.0] - 2026-10-16

### Added
- **File-Based Configuration (`configFile` / `config_file`)**:
  - Added support for loading a base `routewarden.json` policy file and merging inline options on top across the evaluation engine (`engine.NewEngine`) and all gateway generators.
  - Added `configFile` and `config_file` properties to the official RouteWarden JSON Schema (`config.schema.json`) and `rwarden schema` output.
  - Added Docker labels parsing support for `traefik.http.middlewares.<name>.plugin.routewarden.configFile` (and snake_case alias).
  - Added generator support for emitting `configFile` across Traefik Dynamic YAML, Traefik TOML, Traefik Docker labels, Caddyfile (`config_file`), and OpenResty NGINX Lua (`config_file`).
  - Added base config file path diagnostics in `rwarden validate`.
- **Observability Dashboard Map Layer Update**:
  - Migrated the GeoIP threat map layer in the bundled dashboards from Carto to OpenStreetMap.
- **Comprehensive Test Coverage & Anti-Evasion Matrix**:
  - Added extensive unit and integration tests across Docker labels parsing, candidate path evasions (multi-consecutive slashes, mixed backslashes, matrix parameters, and multi-layer percent encoding), response mode generators, and CLI commands.

### Security
- **CRLF Injection Prevention in Gateway Config Generators (`engine/engine.go`)**:
  - Sanitized carriage-return (`\r`) and newline (`\n`) characters from user-supplied pattern strings before emitting gateway-specific configuration snippets (Traefik TOML, Traefik Docker labels, NGINX Lua).
  - Characters `\r` and `\n` are replaced with their literal `\r` and `\n` escape sequences in all generated outputs, preserving pattern intent while eliminating injection risk.

### Changed
- **Canonical Directive Standardization & Gateway Generator Alignment (`engine/engine.go`)**:
  - Emitted strictly canonical `status_code`, `retry_after_seconds`, and `tarpit_max_duration_seconds` directives in Caddyfile generation (`rwarden generate --target caddy`), aligning with Caddy Warden v1.5.0+.
  - Standardized CLI configuration samples and generator templates on canonical `blockPatterns` / `block_patterns` and `allowPatterns` / `allow_patterns`.
- **JSON Schema Parity & Alias Cleanup (`config.schema.json`)**:
  - Removed deprecated legacy alias properties (`pathPatterns`, `action`) from official embedded schema (`rwarden schema`) in favor of canonical `blockPatterns`, `allowPatterns`, and `mode`.
  - Added `trustedProxies` definitions across official schemas and evaluation engines.

---

## [v4.3.0] - 2026-10-05

### Added
- **Request Body Security Inspection (`checkBody` & `checkBodyPatterns`)**:
  - Integrated request body payload inspection into the CLI evaluation engine (`engine/config.go` & `engine/engine.go`), allowing offline simulation of body pattern matching across Traefik, Caddy, and NGINX.
  - Added `-b`, `--body` and `--check-body` CLI flags to `rwarden test` for auditing HTTP `POST`, `PUT`, and `PATCH` payloads.
  - Supported configurable body truncation (`checkBodyMaxBytes`, default: 65536 bytes) across simulation engines.
- **Default Pattern Configuration Toggles & Gateway Generator Alignment**:
  - Added support for `disableDefaultPatterns` and `disableDefaultAllowPatterns` configuration aliases alongside `enableDefaultPatterns` and `enableDefaultAllowPatterns`.
  - Updated Caddy (`enable_default_patterns`), NGINX (`enable_default_patterns`), and Traefik generator templates to seamlessly output native pattern toggles.
- **Comprehensive CLI Automation Test Suite**:
  - Added automated test cases covering stdin config piping (`cat config.json | rwarden test -c - /path`), schema validation (`rwarden schema`), query testing flags (`-q`), and client IP allowlist verification (`--ip`).

### Fixed
- **IPv6 Scope Zone Identifier Normalization (`engine/ip.go`)**:
  - Stripped RFC 4007 interface zone identifiers (`%eth0`) and normalized bracketed IPv6 remote addresses during IP allowlist evaluation, preventing valid link-local and scoped addresses from being rejected.
- **Docker Compose Indexed Array Label Conversion**:
  - Added support for array index notation in Docker labels (e.g. `blockPatterns[0]`, `blockPatterns[1]`, `allowedIps[0]`), ensuring ordered conversion into YAML list sequences for Traefik.
- **Flag Canonicalization & Alias Cleanup**:
  - Canonicalized CLI flag definitions across `test`, `validate`, `generate`, and `sandbox`, removing redundant aliases in favor of POSIX standard flags.

---

## [v4.2.0] - 2026-10-04

### Added
- **Threat Geography & GeoIP Intelligence Suite**:
  - Global Attack Origins Map (`geomap` panel) rendering real-time geospatial attack concentrations and clusters across the globe mapped to ISO 3166-1 alpha-2 country codes.
  - Top Attacking Countries (`bargauge` panel) ranking top nation-state sources of blocked probes and malicious traffic.
  - Country Threat Share (`piechart` panel) showing percentage distribution of hostile requests by origin nation.
  - Interactive `$country_code` template variable with multi-select support to filter events and metrics across the dashboard by origin country.
- **Malicious User-Agent & Scanner Profiling**:
  - Automated scanner detection (`bargauge` panel) identifying and profiling offensive security toolkits (Nuclei, Nikto, sqlmap, Gobuster, Nmap, Masscan, curl, python-requests, and Go-http-client).
  - Attacked HTTP Methods & Verbs distribution (`piechart` panel) revealing threat actor request methods (`GET`, `POST`, `HEAD`, `CONNECT`, `OPTIONS`).
- **Layer 4 & Layer 7 Multi-Protocol Convergence**:
  - L4 vs L7 Threat Convergence Over Time (`timeseries` panel) correlating HTTP reverse proxy blocks (Traefik, Caddy, NGINX) with Layer 4 TCP connection bans and UDP packet drops.
  - Protocol Breakdown (`piechart` panel) tracking traffic proportions across protected protocols (`http`, `ssh`, `dns`, `dht`, `tcp`, `udp`).
  - Transport Split (`bargauge` panel) comparing connection-oriented TCP vs datagram UDP flows.
  - Interactive `$protocol` and `$transport` template filter variables for fine-grained multi-protocol drilldowns.
- **Optional Threat Alerting & Automated Incident Notification Channels**:
  - Pre-configured alerting rules, optional and disabled by default (enabled via `rwarden dashboard up --enable-alerting`):
    - `rw-ddos-attack-spike`: Hostile attack rate spike alert triggering when block rate exceeds 10 req/s over 5m.
    - `rw-sensitive-path-probe`: Immediate critical alert on hostile access attempts to `.env`, `.git`, or cloud credential files.
    - `rw-l4-brute-force`: Layer 4 brute-force surge alert when >15 connection drops or bans occur within 3m.
    - `rw-scanner-nuclei-sqlmap`: High-urgency alert when active exploitation tool signatures are detected.
  - Multi-channel notification receivers pre-configured for Slack (`${SLACK_WEBHOOK_URL}`), Discord (`${DISCORD_WEBHOOK_URL}`), PagerDuty (`${PAGERDUTY_KEY}`), and Generic Webhooks (`${ALERT_WEBHOOK_URL}`).
- **Public & Shared Dashboards with Iframe Embedding**:
  - Enabled `publicDashboards` feature toggle for zero-login public links to live threat telemetry.
  - Enabled frame embedding for embedding threat widgets directly into SecOps intranets or customer portals.
- **Interactive SOC Incident Triage Table & Threat Intelligence Drilldowns**:
  - Dedicated SOC triage grid (`table` panel) displaying real-time forensic event records.
  - Interactive one-click investigative drilldowns on attacker client IPs:
    - **AbuseIPDB**: Instant IP reputation check, report counts, and abuse confidence score (`https://www.abuseipdb.com/check/${__data.fields.client_ip}`).
    - **VirusTotal**: Cross-engine malware, scanner, and infrastructure scoring (`https://www.virustotal.com/gui/ip-address/${__data.fields.client_ip}`).
    - **Shodan**: Open ports, running daemons, and banner reconnaissance (`https://www.shodan.io/host/${__data.fields.client_ip}`).
    - **Forensic Threat Hunter**: Instant pivot into explore view pre-filtered to the attacker's client IP.
  - Direct top-bar navigation shortcuts for rapid threat hunting.

### Fixed
- **Docker Label Conversion for Indexed Array Notation (`labels.go`)**:
  - Added support for array index syntax in Traefik Docker labels (e.g. `blockPatterns[0]`, `blockPatterns[1]`, `allowedIps[0]`), properly preserving order and converting indexed entries into formatted YAML list sequences.
- **Dashboard Offender IP Data Links (Panel 8)**: Replaced `${__series.name}` with `${__field.labels.client_ip}` in "Top Offender IP Addresses & GeoIP", preventing country code suffixes (e.g. `[US]`) from leaking into external threat intelligence URLs (AbuseIPDB, VirusTotal, Shodan, and Loki Explore).
- **Dashboard Template Variable Filter Wiring**: Enabled multi-select and dynamic regex filtering (`allValue: ".*"`, `multi: true`, `refresh: 1`) on `$gateway` and `$verdict`, and wired stream selector filters across dashboard panels so that toolbar dropdowns properly filter panels.
- **Block Ratio Division by Zero Protection (Panel 4)**: Added `"noValue": "0%"` to the Block Ratio stat panel to gracefully display `0%` during fresh installations with zero logs instead of `NaN%`.
- **Secret-Safe Alerting Configuration**: Replaced placeholder Slack/Discord/PagerDuty dummy keys with clean environment variable references, fully preventing GitHub Push Protection and Secret Scanner false-positive blocks.

---

## [v4.1.1] - 2026-10-02

### Fixed
- **Alloy Multi-Label Relabel Matching (`config.alloy`)**:
  - Fixed an issue in `discovery.relabel` where multi-source label evaluation with semicolon separators failed when evaluating `routewarden.logs=true` alongside legacy `routewarden=true` labels (`regex = ".*(true|1|yes).*"`).
- **Premature Security Log Drop in Pipeline (`config.alloy`)**:
  - Eliminated a duplicate `stage.drop` rule running before the verdict template normalization. Gateways emitting `type="routewarden_block"` (Traefik) and `action="blocked"` (TCP Warden) now properly normalize to `verdict="BLOCK"` before unparseable noise is dropped.
- **HTTP Gateway Log Normalization (`config.alloy`)**:
  - Mapped `type="routewarden_block"` to `verdict="BLOCK"` and `type="routewarden_allow"` to `verdict="ALLOW"` across Traefik, Caddy, and NGINX logs.
- **TCP Warden Metadata Extraction (`config.alloy`)**:
  - Extracted full Layer 4 metadata (`service`, `protocol`, `transport`, `client_ip`, `country_code`, `flag_emoji`, `level`, and `reason`) for unified dashboard correlation.
- **Runtime Environment Overrides (`rwarden dashboard up`)**:
  - Added repeatable `--env` / `-e` flags to `rwarden dashboard up`.
  - Added `${ENV_VAR:-default}` parameter fallbacks across `docker-compose.yml` so custom environment variables, SMTP credentials, and OAuth SSO settings are respected at runtime.
- **TCP Warden Sample Configuration & Obsolete Flags**:
  - Fixed `samples/tcp-warden/docker-compose.yaml`, `README.md`, and `tcp-warden.yaml` by removing non-existent flags (`--tcp-warden`, `--host`, `--no-docker`) and adding the proper `routewarden.logs=true` label for the RouteWarden Observability Stack.
- **UDP Port Exposure in Docker Image**:
  - Added `1514/udp` to the `EXPOSE` directive in `Dockerfile` for network UDP syslog ingestion.

### Changed
- **Pure Opt-In Container Discovery & Self-Logging Protection**:
  - Replaced broad container name regex matching (`.*(routewarden|traefik|caddy|nginx|tcp-warden).*`) with a strict, label-based **Pure Opt-In** model (`routewarden.logs=true` or `routewarden=true`).
  - Completely prevents the observability stack from capturing its own internal logs or scraping unrelated host containers (databases, web applications, or unmanaged proxies).
  - Added stream-level log noise filtering to automatically discard plain-text container startup banners, health check probes, and ordinary proxy access lines lacking structured RouteWarden security fields (`verdict` or `action`).
  - Simplified `docker-compose.yml` by eliminating negative exclusion labels across all observability services.

---

## [v4.1.0] - 2026-10-01

### Added
- **Security Observability Stack (`rwarden dashboard`)**:
  - Replaced the embedded monolithic web dashboard with a cloud-native telemetry stack.
  - Added `rwarden dashboard up` (default) to orchestrate and launch the full stack via Docker Compose with pre-provisioned data sources and security dashboards.
  - Added `rwarden dashboard down` to cleanly stop and remove running stack containers.
  - Added `rwarden dashboard status` to inspect container health, active port bindings, and endpoint URLs.
  - Added `rwarden dashboard export [dir]` (and `--dir <path>`) to extract `docker-compose.yml` and dashboard assets to disk for standalone customization and GitOps workflows.
- **Trusted Proxies Support Across All Generators (`trustedProxies`)**:
  - Full code generator support for `trustedProxies` across all supported targets:
    - Traefik Dynamic File Provider YAML (`http.middlewares.routewarden.plugin.routewarden.ipFilter.trustedProxies`)
    - Traefik Dynamic File Provider TOML (`[http.middlewares.routewarden.plugin.routewarden.ipFilter] trustedProxies = [...]`)
    - Traefik Docker Compose Labels (`traefik.http.middlewares.<name>.plugin.routewarden.ipfilter.trustedproxies=...`)
    - Caddyfile (`trusted_proxies <ips/cidrs...>`)
    - NGINX OpenResty Lua (`trusted_proxies = { ... }`)
- **Redirect Mode Security Hardening (`redirectUrl`)**:
  - Strict URL scheme validation in `rwarden validate` and `engine.NewEngine`, restricting `redirectUrl` to `http://`, `https://`, or root-relative paths (`/...`) to eliminate open-redirect and `javascript:` attack vectors.
- **Centralized Documentation & Universal Installer Integration**:
  - Centralized CLI documentation and guide hosted at [RouteWarden Documentation](/cli/).
  - Integrated with the unified ecosystem installation script served directly at `https://routewarden.github.io/install.sh`.
- **Multi-Architecture Docker Container Build Optimization**:
  - Upgraded Dockerfile with BuildKit cache mounting (`--mount=type=cache`) for Go package modules and build caches, substantially speeding up container build times.
  - Added native cross-compilation support utilizing `BUILDPLATFORM`, `TARGETOS`, and `TARGETARCH` with automatic fallback to `linux`.

### Fixed
- **Dashboard Export `--dir` Flag Parsing**:
  - Fixed an issue where passing `rwarden dashboard export --dir <dir>` treated the literal flag `"--dir"` as the destination folder. The export command now seamlessly accepts both flag and positional arguments.
- **Dashboard Subcommand Routing**:
  - Disallowed implicit fallback on unknown dashboard subcommands; invalid subcommands now report a helpful error with valid choices rather than silently launching containers.
- **TCP Warden YAML Detection in `validate`**:
  - Tightened heuristics in `rwarden validate` to require a `.yaml`/`.yml` extension or a top-level `version:` key, preventing false-positive skips for JSON configs containing nested version fields.

---

## [v4.0.1] - 2026-09-26

### Added
- **Multi-App Version Sync**:
  - Unified version synchronizer and multi-target documentation linking in RouteWarden ecosystem docs.
- **Enhanced Error Diagnostics**:
  - Clearer syntax error messages when validating malformed `tcp-warden.yaml` configurations.

---

## [v4.0.0] - 2026-09-25

### Added
- **RouteWarden TCP Warden Integration (`rwarden generate tcp-warden` & `rwarden validate`)**:
  - Declarative generation of `tcp-warden.yaml` configurations directly from centralized RouteWarden JSON policies.
  - Strict syntax, schema, and CIDR validation for `tcp-warden.yaml` via CLI arguments or stdin pipelines.
- **Real-Time TCP Monitoring in RouteWarden Dashboard**:
  - Direct ingestion and real-time visualization of structured `tcp-warden.jsonl` event streams.
  - GeoIP mapping, protocol breakdowns, connection velocity metrics, and dynamic ban tracking.
- **RouteWarden TCP Warden Standalone Application** ([TCP Warden Docs](/tcp/)):
  - Dedicated, zero-allocation Layer 4 TCP security proxy daemon for SSH, SMTP, POP3, IMAP, and generic TCP tunnels.
  - Bidirectional CrowdSec integration (LAPI bouncer decision ingestion and scenario log export).
  - Built-in management REST and SSE API (`:9091`) with hot-reload support (`SIGHUP`).
  - Official JSON Schema `tcp-warden.schema.json` and Docker Compose recipes.

---

## [v3.0.0] - 2026-09-25

### Added
- **Self-Hosted Security Dashboard (`rwarden dashboard`)**:
  - Real-time, zero-dependency web UI embedded in the `rwarden` binary — no Node.js, no external database, no cloud services required.
  - **Zero-Config Docker Discovery**: Auto-detects and streams logs from running Traefik, Caddy, and NGINX containers via the local Docker socket.
  - **Log File Tailing**: Tail local log files or wildcard glob patterns with automatic log rotation support.
  - **Real-Time Live Event Feed**: WebSocket / SSE stream of blocked requests with full-text search, container filtering, pause/resume, and clear controls.
  - **Attack Analytics**: Interactive timelines (24h, 6h, 1h), blocks-per-minute chart, top attacked endpoints, top offender IPs, and response mode distribution.
  - **Sources & Container Management**: View all active log sources with live status badges and one-click filtering.
- **v1.2 — GeoIP & IP Intelligence**:
  - Country resolution with flag emojis via embedded GeoLite2 MMDB or `ip-api.com` live fallback.
  - **Deep IP Intelligence** (`/api/ip/:ip`): Threat risk score, ISP / ASN resolution, geographic location, behavioral patterns, top targeted endpoints, and paginated event history.
  - **Config Viewer** (`/api/config/:id`): Inspect and render the live `routewarden.json` from any discovered container.
- **Tailscale & NetBird Mesh VPN Auto-Detection**:
  - Native identification of Tailscale CGNAT peers (`100.64.0.0/10`) and NetBird ULA overlay peers (`fd00::/8`) with dedicated metadata and flag emoji (`🔒`).
  - RFC 5737 documentation ranges correctly classified as `LAN / Reserved Test Network`.

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
- Fixed RE2 regex backreference in Traefik label parsing to ensure 100% Go regexp standard library compliance.
- Prevented multiline upstream regex greediness in NGINX config adaptation from corrupting `server {` blocks.
- Injected missing `middlewares:` parent block in synthetic Traefik sandbox YAML generation.
- Enhanced label normalization to recognize root-level response parameters (`status`, `statusCode`, `mode`, `action`, `customResponseText`).
- Removed legacy direct boolean `silentDrop` property from `Config` schema, structs, and Docker label converters.

---

## [v2.0.0] - 2026-09-21

### Added
- **Ephemeral Gateway Sandbox (`rwarden sandbox`)**:
  - Spin up live, ephemeral container environments for **Traefik**, **Caddy**, and **NGINX (OpenResty)** pre-configured with RouteWarden security rules.
  - Automatically translates and mounts native dynamic configurations into isolated test containers.
  - Interactive foreground mode with instant graceful teardown on `Ctrl+C`.
  - Detached background mode (`--detach` / `-d`) for local dev workflows and integration testing.
  - Automated probe testing (`--test`) to execute live HTTP test suites asserting blocking and bypass behavior.
  - Dry-run mode (`--dry-run`) to inspect generated gateway configurations and exact Docker run commands without launching containers.
- **Custom RouteWarden Plugin Support**:
  - `--plugin-version`: Specify custom plugin version/tag/branch for testing specific releases.
  - `--plugin-path`: Mount local plugin repository directories for real-time plugin development.
- **Pre-flight Environment Validation**:
  - Added early Docker installation and daemon accessibility checks to fail fast with actionable guidance.
- **Enhanced Container Tooling**:
  - Included `docker-cli` inside the RouteWarden container image (`ghcr.io/routewarden/cli`).

---

## [v1.1.0] - 2026-09-21

### Added
- **Multi-Gateway Config Generator (`generate`)**:
  - Convert `routewarden.json` into native configuration for Traefik Dynamic YAML, Traefik Docker Labels, Caddy Caddyfile, and NGINX / OpenResty Lua.
  - Added support for `--config -` to stream configuration via standard input.
- **Client IP Whitelist Simulation (`test --ip`)**:
  - Test client IP evaluation against CIDR blocks and single IP allowlists offline.
- **HTTP Header Smuggling Inspection (`test --header`)**:
  - Test custom headers in `Key:Value` format to evaluate reverse proxy path normalization anti-evasion.
- **Config & Query Precedence in Offline Testing**:
  - Added `--config <path>` flag to `rwarden test`.
  - Added `--check-query` boolean flag.
- **Comprehensive Configuration Validation (`validate`)**:
  - Added HTTP status code range checks (100–599).
  - Added response mode validation and required target URL validation.
  - Added CAPTCHA provider validation.

---

## [v1.0.0] - 2026-09-20

### Initial Release
- **Path Anti-Evasion Inspection Engine (`test`)**:
  - Offline candidate path extraction simulating Traefik and Caddy middleware pipelines.
  - Recursive multi-layer URL percent-decoding (`%252e%252e`).
  - Semicolon matrix parameter stripping (`/;param/.env`).
  - Windows/IIS backslash normalization (`\..\`).
  - Null-byte injection scrubbing (`%00`).
  - Dot-segment path traversal resolving (`/static/../.env`).
  - Default block pattern matching across sensitive files.
  - Default allow pattern overrides.
- **Configuration Validator (`validate`)**:
  - Offline schema validation of `routewarden.json`.
  - Detection of invalid regular expressions and malformed CIDR blocks.
- **Official JSON Schema Export (`schema`)**:
  - CLI command emitting `config.schema.json` directly for IDE integration.
- **Distribution**:
  - Single-binary zero-dependency Go distribution for macOS, Linux, and Windows.
  - Automated installation script (`curl -fsSL https://routewarden.github.io/install.sh | bash`).
  - Official multi-architecture Docker container image on GitHub Container Registry (`ghcr.io/routewarden/cli:latest`).
