# RouteWarden CLI (`rwarden`)

`rwarden` is a developer CLI for testing path security rules, verifying RouteWarden configuration files offline, and emitting the official JSON Schema.

> 📖 **Official Documentation**: See the [RouteWarden CLI Documentation](https://routewarden.github.io/cli/) for the complete command reference, security dashboard guide, and CI/CD tutorials.

---

## Installation

### 1. One-Liner Script (macOS & Linux)

Download and install the latest pre-compiled release binary automatically:

```bash
curl -fsSL https://routewarden.github.io/install.sh | bash
```

Custom installation directory (e.g. `~/.local/bin`):

```bash
curl -fsSL https://routewarden.github.io/install.sh | INSTALL_DIR=$HOME/.local/bin bash
```

---

### 2. Homebrew (macOS & Linux)

```bash
brew install routewarden/tap/rwarden
```

---

### 3. Debian / Ubuntu (APT)

Install the official `.deb` package directly using `apt`:

```bash
# Download and install with automatic dependency handling
curl -fsSLO https://github.com/routewarden/cli/releases/latest/download/rwarden_linux_amd64.deb
sudo apt install ./rwarden_linux_amd64.deb

# For ARM64 (e.g. Raspberry Pi / AWS Graviton):
# curl -fsSLO https://github.com/routewarden/cli/releases/latest/download/rwarden_linux_arm64.deb
# sudo apt install ./rwarden_linux_arm64.deb
```

---

### 4. Pre-built Release Binaries

Download standalone binaries for **Linux** (`amd64`, `arm64`), **macOS** (Apple Silicon `arm64` & Intel `amd64`), and **Windows** directly from [GitHub Releases](https://github.com/routewarden/cli/releases/latest).

---

### 5. Container Image (Docker / CI/CD)

Run `rwarden` via container without installing any local binaries:

```bash
# Validate configuration file directly
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest validate --config /routewarden.json

# Test path interactively
docker run --rm ghcr.io/routewarden/cli:latest test --path "/.env"
```

---

### 6. From Source (Go)

```bash
git clone https://github.com/routewarden/cli.git
cd cli
go build -o /usr/local/bin/rwarden .
```

Verify installation:

```bash
rwarden version
# rwarden version 5.2.0
```

---

## Updating to the Latest Version

To update `rwarden` to the newest released version:

### 1. One-Liner Re-installation (macOS & Linux)
Re-running the universal installer automatically queries GitHub Releases for the latest version tag, downloads the matching pre-compiled binary, and safely replaces your existing binary:

```bash
# Default system-wide (/usr/local/bin):
curl -fsSL https://routewarden.github.io/install.sh | bash

# Or custom user directory (~/.local/bin):
curl -fsSL https://routewarden.github.io/install.sh | INSTALL_DIR=$HOME/.local/bin bash
```

### 2. Upgrading Docker Container Image
If using the containerized client, pull the latest image tag:

```bash
# Full CLI Toolkit (Policy engine, AST linter, Diff, Sandbox, Dashboard, Shipper)
docker pull ghcr.io/routewarden/cli:latest

# Dedicated Minimal Edge Shipper (Lightweight companion for remote reverse proxies)
docker pull ghcr.io/routewarden/shipper:latest

# Dedicated SOC Security Dashboard (Standalone telemetry server)
docker pull ghcr.io/routewarden/dashboard:latest
```

### Official Container Images

| Image | Description | Default Entrypoint |
| :--- | :--- | :--- |
| **`ghcr.io/routewarden/cli`** | Full-featured CLI container with Docker CLI tools | `rwarden` |
| **`ghcr.io/routewarden/shipper`** | Minimal, dedicated log shipper companion for edge nodes | `rwarden push` |
| **`ghcr.io/routewarden/dashboard`** | Dedicated standalone SOC security dashboard server | `rwarden dashboard --no-open` |

### 3. Upgrading From Source (Go)
Pull the latest commits and rebuild:

```bash
cd cli
git pull origin main
go build -o /usr/local/bin/rwarden .
```

Confirm the upgraded version:

```bash
rwarden version
```

---

## Versioning & Release Automation (Maintainers)

The CLI repository includes [`scripts/update-version.sh`](scripts/update-version.sh) to synchronize version tags across [`version.json`](version.json), Go source files (`main.go`), installer fallbacks, documentation manifests, and `package.json`:

```bash
# Update version across all files and version.json
./scripts/update-version.sh v1.1.0

# Or using npm
npm run version:update v1.1.0
```

For full details on the release workflow, see [VERSIONING.md](VERSIONING.md).

---

### Uninstallation

`rwarden` packages include automated pre-removal hooks that gracefully stop any background services (dashboard, push shipper) and active sandbox containers:

```bash
# Homebrew (automatically executes uninstall hook):
brew uninstall rwarden

# Debian / Ubuntu (automatically executes preremove script):
sudo apt remove rwarden

# RHEL / Fedora (RPM):
sudo rpm -e rwarden

# Alpine Linux (APK):
apk del rwarden

# Universal automated uninstaller:
curl -fsSL https://routewarden.github.io/uninstall.sh | bash

# Manual binary removal:
rwarden stop && rwarden cleanup
sudo rm -f /usr/local/bin/rwarden
```

---

## Commands

### 1. Test URL Paths & Queries (`test`)

Simulate candidate path extraction, normalization, and pattern matching on an arbitrary path without starting Traefik, Caddy, or NGINX:

**CLI:**
```bash
# Test a sensitive file path (positional or --path)
rwarden test /.env
rwarden test --path "/.env"

# Test double URL encoding anti-evasion
rwarden test "/static/%252e%252e/.env"

# Test query string inspection (-q or --query)
rwarden test -q "file=secret.conf" /search

# Test custom HTTP methods (-X, -m, or --method)
rwarden test -X POST /wp-config.php

# Test custom HTTP headers (-H or --header, repeatable)
rwarden test -H "X-Forwarded-Uri: /.env" /api

# Test against a custom RouteWarden config file (-c or --config)
rwarden test -c routewarden.json /admin/dashboard

# Test client IP whitelisting
rwarden test -c routewarden.json --ip "10.0.0.1" /admin

# Pipe configuration via stdin
cat routewarden.json | rwarden test -c - /admin
```

**Docker:**
```bash
# Test a sensitive path
docker run --rm ghcr.io/routewarden/cli:latest test /.env

# Test evasion via query inspection
docker run --rm ghcr.io/routewarden/cli:latest test -q "file=secret.conf" /search

# Test against custom config file
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest test -c /routewarden.json --ip "10.0.0.1" /admin
```

| Flag | Type | Default | Description |
|:---|:---|:---|:---|
| `[path]`, `--path` | string | `""` | Request path to evaluate (e.g. `/.env` or `/api/v1`) |
| `-c`, `--config` | string | `""` | Optional path to `routewarden.json` (or `-` for stdin) |
| `-q`, `--query` | string | `""` | Optional request query string to evaluate |
| `-X`, `-m`, `--method` | string | `"GET"` | HTTP method (e.g. `GET`, `POST`, `HEAD`) |
| `--ip` | string | `""` | Optional client IP address to evaluate against `allowedIps` |
| `-H`, `--header` | string | `""` | Optional header in `Key:Value` format to test (repeatable) |
| `-b`, `--body` | string | `""` | Optional request body payload to evaluate |
| `--check-query` | bool | `true` | Enable or disable query string inspection |
| `--check-body` | bool | `false` | Enable or disable request body inspection |

**Example Output**:
```text
🔍 Testing: GET /static/%252e%252e/.env
  Candidate paths extracted (2):
    - /static/%252e%252e/.env
    - /.env

Result: 🛑 BLOCKED (HTTP Status 403)
  Reason:  block_pattern_match
  Target:  /.env
  Pattern: (?i)\.env
```

---

### 2. Validate Configurations (`validate`)

Validate a RouteWarden JSON configuration file before deploying:

**CLI:**
```bash
# Validate routewarden.json directly (positional or --config)
rwarden validate routewarden.json
rwarden validate -c routewarden.json

# Auto-detects routewarden.json in current directory if omitted
rwarden validate

# Validate tcp-warden.yaml directly
rwarden validate tcp-warden.yaml

# Validate piped config via stdin
cat routewarden.json | rwarden validate
```

**Docker:**
```bash
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest validate /routewarden.json
docker run --rm -v $(pwd)/tcp-warden.yaml:/tcp-warden.yaml ghcr.io/routewarden/cli:latest validate /tcp-warden.yaml
```

**Example Output**:
```text
✓ Configuration routewarden.json is VALID.
  - Enabled: true
  - Default patterns enabled: true
  - Default allow patterns enabled: true
  - Methods: [GET]
  - Custom block patterns: 2
  - Monitored headers: [X-Forwarded-Uri]
```

Exits with non-zero status code if invalid regexes, CIDRs, or configuration options are encountered, making it ideal for CI/CD pipelines.

---

### 3. Output JSON Schema (`schema`)

Print the official RouteWarden configuration JSON Schema:

**CLI:**
```bash
rwarden schema > routewarden.schema.json
```

**Docker:**
```bash
docker run --rm ghcr.io/routewarden/cli:latest schema > routewarden.schema.json
```

---

### 4. Generate Gateway Configs (`generate`)

Convert `routewarden.json` into native gateway configuration — no manual translation required.

**CLI:**
```bash
# Traefik: dynamic YAML middleware definition
rwarden generate traefik-yaml [routewarden.json] > dynamic.yml
rwarden generate yaml > dynamic.yml

# Traefik: dynamic TOML middleware definition
rwarden generate traefik-toml [routewarden.json] > dynamic.toml
rwarden generate toml > dynamic.toml

# Traefik: Docker Compose labels block
rwarden generate traefik-labels [routewarden.json]
rwarden generate compose

# Caddy: Caddyfile directive block
rwarden generate caddy [routewarden.json]

# NGINX / OpenResty: Lua init table for nginx.conf
rwarden generate nginx [routewarden.json]

# TCP Warden: tcp-warden.yaml configuration
rwarden generate tcp-warden [routewarden.json] > tcp-warden.yaml
```

**Docker:**
```bash
# Traefik: dynamic YAML middleware definition
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate traefik-yaml /routewarden.json > dynamic.yml

# Traefik: dynamic TOML middleware definition
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate traefik-toml /routewarden.json > dynamic.toml

# Traefik: Docker Compose labels block
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate traefik-labels /routewarden.json

# Caddy: Caddyfile directive block
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate caddy /routewarden.json

# NGINX / OpenResty: Lua init table for nginx.conf
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate nginx /routewarden.json

# TCP Warden: output as tcp-warden.yaml configuration
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate tcp-warden /routewarden.json > tcp-warden.yaml
```

| Target / Alias | Output |
|:---|:---|
| `traefik-yaml`, `traefik`, `yaml` | Traefik dynamic YAML middleware definition (`dynamic.yml`) |
| `traefik-toml`, `toml` | Traefik dynamic TOML middleware definition (`dynamic.toml`) |
| `traefik-labels`, `compose`, `labels` | Docker Compose `labels:` block |
| `caddy`, `caddyfile` | Caddyfile `routewarden { ... }` directive block |
| `nginx`, `openresty` | OpenResty Lua table for `init_by_lua_block` in `nginx.conf` |
| `tcp-warden`, `tcp`, `tcpwarden` | TCP Warden YAML configuration (`tcp-warden.yaml`) |

---

### 5. Live Gateway Sandbox (`sandbox`)

Test configurations against an ephemeral Docker container running **Traefik**, **Caddy**, or **NGINX**.

`rwarden sandbox` supports:
1. **Generic JSON** (`routewarden.json`): automatically synthesized into full gateway configurations.
2. **Actual Gateway Configs**: pass real `traefik.toml`, `traefik.yaml` / `dynamic.yml`, `docker-compose.yaml`, `Caddyfile`, or `nginx.conf` directly. Target gateway and format are **auto-detected** from filename and content.
3. **Inline Docker Labels**: test Traefik label snippets directly via `--labels`.
4. **Snippets & Complete Production Configs**:
   - **Snippets**: Middleware-only snippets are automatically wrapped with sandbox entrypoints and mock upstream endpoints returning `200 OK` for passing traffic.
   - **Complete Configs**: Full configurations with backend service URLs, upstreams, or proxies are automatically adapted for ephemeral sandboxes in-memory without modifying your source file:
     - **Traefik**: External loadBalancer service URLs (`url`, `service`) are redirected to Traefik's internal ping service (`ping@internal`), entrypoints guarantee `:8080` binding, and router TLS directives are safely neutralized for local HTTP testing.
     - **Caddy**: Upstream `reverse_proxy` targets are replaced with mock `200 OK` responders, `order routewarden first` and `auto_https off` are injected, and custom site blocks bind to `:8080`.
     - **NGINX**: External `upstream` hostnames are neutralized with `down` to prevent OpenResty startup DNS failures, `proxy_pass` directives are converted to mock Lua `200 OK` responders, local SSL certificate requirements are bypassed, and `listen 8080;` is configured.
   - **Live Upstream Reachability**: In `--test` mode, RouteWarden recognizes upstream reachability (HTTP `200`, or HTTP `502`/`504` from an offline production backend) as an allowlist pass-through.

#### CLI Usage Examples

```bash
# 1. Test actual Traefik TOML configuration (auto-detects target & mounts dynamic.toml)
rwarden sandbox --config traefik.toml

# 2. Test actual Traefik YAML / dynamic.yml
rwarden sandbox --config dynamic.yml

# 3. Test Docker Compose with Traefik labels (extracts labels & translates to dynamic YAML)
rwarden sandbox --config docker-compose.yaml

# 4. Test Traefik labels inline
rwarden sandbox --labels "traefik.http.middlewares.shield.plugin.routewarden.enabled=true"

# 5. Test actual Caddyfile (auto-detects target caddy & wraps standalone route if needed)
rwarden sandbox --config Caddyfile

# 6. Test actual nginx.conf (auto-detects OpenResty target & mounts configuration)
rwarden sandbox --config nginx.conf

# 7. Automated live probe verification with custom path and IP allowlist assertion
rwarden sandbox --config docker-compose.yaml --test --probe-path "/immich/api/admin" --probe-ip "10.0.0.1"

# 8. Dry-run: inspect generated/wrapped gateway config & exact docker run command
rwarden sandbox --config traefik.toml --dry-run --print-config

# Ready-to-test working examples are available in the samples/ folder:
rwarden sandbox --config samples/traefik/dynamic.yml --dry-run --print-config
rwarden sandbox --config samples/traefik/dynamic.toml --dry-run --print-config
rwarden sandbox --config samples/traefik/docker-compose.yaml --dry-run --print-config
rwarden sandbox --config samples/caddy/Caddyfile --dry-run --print-config
rwarden sandbox --config samples/nginx/nginx.conf --dry-run --print-config
rwarden sandbox --target traefik --config samples/json/routewarden.json --dry-run --print-config
```

See [samples/README.md](samples/README.md) for full documentation of each sample.

#### Running via Docker (`ghcr.io/routewarden/cli`)

When running `rwarden` via Docker, mount the Docker socket (`/var/run/docker.sock`) so `rwarden` can spin up sibling gateway containers on the host, and mount the current directory or config file:

```bash
# Test actual traefik.toml via Docker
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/traefik.toml:/config/traefik.toml:ro \
  -p 8080:8080 \
  ghcr.io/routewarden/cli:latest sandbox --config /config/traefik.toml

# Test Docker Compose Traefik labels via Docker
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/docker-compose.yaml:/config/docker-compose.yaml:ro \
  -p 8080:8080 \
  ghcr.io/routewarden/cli:latest sandbox --config /config/docker-compose.yaml --test

# Test inline labels without mounting files
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -p 8080:8080 \
  ghcr.io/routewarden/cli:latest sandbox \
  --labels "traefik.http.middlewares.shield.plugin.routewarden.enabled=true" \
  --test
```

| Flag | Type | Default | Description |
|:---|:---|:---|:---|
| `-t`, `--target` | string | `""` | Target gateway: `traefik`, `caddy`, or `nginx` (optional if auto-detected or passed as positional argument) |
| `-c`, `--config` | string | `""` | Path to gateway config (`traefik.toml`, `traefik.yaml`, `docker-compose.yaml`, `Caddyfile`, `nginx.conf`, `routewarden.json`, or `-`) |
| `--format` | string | `""` | Explicit format: `traefik-toml`, `traefik-yaml`, `traefik-labels`, `caddy`, `nginx`, `json` |
| `--labels` | string | `""` | Direct Traefik Docker labels string (e.g. `'traefik.http.middlewares.warden...'`) |
| `--probe-path` | string | `""` | Custom endpoint path to verify blocked during `--test` |
| `--probe-ip` | string | `""` | Client IP to simulate via `X-Forwarded-For` to verify allowlist bypass during `--test` |
| `--port` | int | `8080` | Local port to bind the gateway |
| `--version` | string | `""` | Target gateway container version tag (e.g. `v3.3`, `2.11.4`, `alpine`) |
| `--plugin-version` | string | `""` | RouteWarden plugin version/tag/branch (e.g. `v1.2.0`, `v1.1.0`, `main`) |
| `--plugin-path` | string | `""` | Local path to RouteWarden plugin directory to mount for development |
| `-p`, `--print-config` | bool | `false` | Print generated/wrapped gateway configuration before running |
| `--test` | bool | `false` | Run automated live HTTP probe assertions against container then exit |
| `-n`, `--dry-run` | bool | `false` | Generate config and show docker command without starting container |
| `-d`, `--detach` | bool | `false` | Run container in background mode |

#### Testing Live with `curl`

```bash
# Direct sensitive file access (blocked)
curl -i http://localhost:8080/.env

# Path traversal & double URL encoding evasion (blocked)
curl -i http://localhost:8080/static/%252e%252e/.env

# Query parameter inspection (blocked if checkQuery enabled)
curl -i "http://localhost:8080/search?file=secret.conf"

# Header smuggling injection (blocked if checkHeaders enabled)
curl -i -H "X-Forwarded-Uri: /.env" http://localhost:8080/api/dashboard

# Legitimate public endpoint (allowed downstream)
curl -i http://localhost:8080/robots.txt

# Client IP whitelisting test (simulating a request from whitelisted IP 192.168.1.50)
curl -i -H "X-Forwarded-For: 192.168.1.50" http://localhost:8080/.env
```

> **Security Note:** In local testing, `X-Forwarded-For` allows simulating whitelisted IPs without reconfiguring network interfaces. In production, edge reverse proxies (Cloudflare, AWS ALB, Traefik, NGINX) overwrite or sanitize untrusted client-supplied headers with the real TCP socket address.

---

### 6. Security Observability Dashboard (`dashboard`)

RouteWarden includes a turnkey, ultra-lightweight real-time security dashboard powered by RouteWarden's embedded Go server and SQLite persistence. It provides an instantaneous, live executive SOC dashboard consuming only **~8MB of RAM** with zero external dependencies.

The dashboard automatically discovers Docker containers tagged with `routewarden=true` (or `routewarden.logs=true`), multiplexes their logs concurrently, and presents a live terminal-styled web UI with zero manual configuration.

#### Architecture & Highlights

- **Ultra-lightweight footprint**: Consumes ~8MB RAM with sub-second startup and zero external dependencies.
- **Embedded SQLite Persistence**: Long-term log retention (`~/.routewarden/dashboard/events.db`) using high-throughput WAL mode and asynchronous batch writing. Telemetry survives restarts with automatic 30-day pruning.
- **Live SOC Stream & Stream Controls**: Real-time Server-Sent Events (SSE) feed with instant filter tabs (`ALL`, `BLOCK` 🛑, `TARPIT` ⏳, `ALLOW` 🛡️).
- **Connected Node & Source Filtering**: Filter events by specific Docker container, remote push agent, or local log file using the `📡 All Nodes` matrix dropdown or interactive badges in the `🌐 MONITORED NODES` ribbon.
- **Server-Backed Pagination**: Configurable page sizes (`25`, `50`, `100`, `250`), direct page jump, First / Prev / Next / Last buttons, and keyboard controls (<kbd>[</kbd> / <kbd>]</kbd> or Left/Right arrows).
- **Optional HTTP Basic Auth & API Protection**: Secure the UI and `/api/*` endpoints with `--auth <user:password>` or `RW_DASHBOARD_AUTH`. Whitelists static assets (`/favicon.ico`, `/icon.svg`) and agent push encryption (`/api/v1/*`).
- **Stream Freeze / Resume**: Click **⏸ Pause** or hit <kbd>Space</kbd> to freeze the log table for forensic inspection. Incoming logs are buffered with a counter badge (`⏸ PAUSED (+N new)`).
- **Time Window Filtering**: Rapid rolling time ranges (`1m`, `5m`, `15m`, `30m`, `1h`, `6h`, `24h`, `Custom Date Range`) querying SQLite directly via `GET /api/logs`.
- **Threat Intelligence & IP Modal**: Top Attacking Client IPs with breakdown ratios. Click any IP to inspect autonomous systems (ASN), reverse DNS, origin country, CIDR prefix, and AbuseIPDB records.
- **Global Threat Geography**: Interactive world map visualizing attack origins using RouteWarden's autonomous country engine (built-in CIDR & RIR + MaxMind GeoLite2 discovery).
- **Theme Switching**: Built-in Auto (system preference), Light, and Dark terminal themes (<kbd>T</kbd>).
- **Encrypted Remote Ingest**: Accepts logs from remote edge nodes via `rwarden push` using **X25519 + ChaCha20-Poly1305** zero-knowledge encryption (`/api/v1/events`).

#### Quickstart with CLI

```bash
# 1. Launch dashboard (auto-discovers labeled containers & opens http://localhost:7890)
rwarden dashboard

# 2. Launch with optional HTTP Basic Auth protection
rwarden dashboard up --auth admin:supersecret

# 3. Launch in detached background mode
rwarden dashboard -d
# or: rwarden dashboard up --port 7890 --auth admin:secret --detach

# 4. Launch on a custom port and bind to localhost only without opening browser
rwarden dashboard up --port 8080 --host 127.0.0.1 --no-open

# 5. Monitor a specific container by name
rwarden dashboard --container traefik

# 6. Monitor an NGINX or Apache access log file
rwarden dashboard --file /var/log/nginx/access.log

# 7. Check status of running dashboard
rwarden dashboard status
# or global: rwarden status

# 8. Stop background dashboard
rwarden dashboard stop
# or: rwarden dashboard down
# or global: rwarden stop

# 9. Export standalone Docker Compose and configuration files
rwarden dashboard export ./dashboard
```

#### Standalone Docker Compose Deployment

If you prefer running without the CLI binary in production, export the embedded stack:

```bash
# Export configuration files
rwarden dashboard export ./deploy/dashboard

# Run with standard Docker Compose
cd ./deploy/dashboard
docker compose up -d
```

```yaml
# deploy/dashboard/docker-compose.yml
services:
  dashboard:
    image: ghcr.io/routewarden/cli:latest
    container_name: routewarden-dashboard
    restart: unless-stopped
    command: dashboard --port 7890 --no-open
    ports:
      - "${PORT:-7890}:7890"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ~/.routewarden/dashboard:/root/.routewarden/dashboard
    environment:
      - TZ=UTC
```

#### Command Flags & Subcommands

| Command / Flag | Type | Default | Description |
|:---|:---|:---|:---|
| `up` | subcommand | — | Launch real-time SOC security dashboard (default subcommand) |
| `down` | subcommand | — | Stop running dashboard containers |
| `status` | subcommand | — | Check status of dashboard containers |
| `export [dir]` | subcommand | `./dashboard` | Export compose and configuration assets to disk |
| `-a`, `--auth` | string | `""` | Optional HTTP Basic Auth credentials (`user:password` or `RW_DASHBOARD_AUTH`) |
| `--user` | string | `""` | Optional Basic Auth username (used with `--password`) |
| `--password` | string | `""` | Optional Basic Auth password (used with `--user`) |
| `--host` | string | `""` | Host IP interface to bind (e.g. `127.0.0.1` or `0.0.0.0`, default: all interfaces) |
| `--port` | int | `7890` | Port for dashboard web UI and SSE stream |
| `-f`, `--file` | string | `""` | Log file to monitor (default: auto-discovered Docker containers) |
| `-c`, `--container` | string | `""` | Tail a specific Docker container by name or ID |
| `-l`, `--label` | string | `routewarden=true` | Docker label to filter containers |
| `--dir` | string | `~/.routewarden/dashboard` | Working directory storing SQLite `events.db` and keys |
| `--no-open` | bool | `false` | Do not automatically launch the system default browser |

---

### 7. Policy Static Analyzer & Linter (`audit`)

Perform deep static analysis on a RouteWarden policy file to catch ReDoS vulnerabilities, unescaped dots, universal wildcard traps, and header spoofing risks before deployment:

```bash
# Audit default routewarden.json
rwarden audit

# Audit custom configuration file
rwarden audit ./config/routewarden.json

# Fail on warnings as well as critical errors (ideal for CI/CD)
rwarden audit --strict routewarden.json

# Output as JSON
rwarden audit --format json routewarden.json

# Output in OASIS SARIF v2.1.0 format for GitHub Code Scanning
rwarden audit --format sarif routewarden.json > results.sarif
```

---

### 8. Policy Diffing (`diff`)

Compare two RouteWarden policies and assess the delta on your production security posture:

```bash
# Compare production policy against candidate update
rwarden diff prod.json candidate.json

# Output diff as machine-readable JSON
rwarden diff --format json prod.json candidate.json

# Fail with exit code 1 if differences exist, or code 2 if security posture is relaxed
rwarden diff --exit-code prod.json candidate.json
```

---

### 9. Live Terminal Threat Monitoring (`monitor`)

Tail, multiplex, and colorize live reverse proxy security events directly in the terminal from Docker containers, log files, or standard input.

#### Automatic Docker Discovery via Labels

If no file or stdin pipe is provided, `rwarden monitor` automatically discovers running Docker containers tagged with the label `routewarden=true` (or `routewarden.logs=true`) and streams them concurrently with container attribution tags (`[traefik]`, `[nginx]`, etc.):

```yaml
# docker-compose.yaml
services:
  traefik:
    image: traefik:v3.1
    labels:
      - "routewarden=true"
  nginx:
    image: openresty/openresty:alpine
    labels:
      - "routewarden=true"
```

```bash
# Auto-discover and multiplex all containers with routewarden=true label
rwarden monitor

# Tail a specific container by name or ID
rwarden monitor --container traefik

# Filter by custom Docker label
rwarden monitor --label "env=production"

# Tail an NGINX or Apache access log file
rwarden monitor --file /var/log/nginx/access.log

# Filter exclusively for blocked threats or specific IP / path
rwarden monitor --verdict BLOCK
rwarden monitor --path "/.env" --ip "192.168.1."
```

#### Piping Raw Logs to External Analyzers

Use `--raw` to emit unformatted log lines and pipe directly into external log visualizers, jq, or SIEM pipelines:

```bash
# Stream unformatted raw log lines into analyzers or jq
rwarden monitor --raw | jq .
```

Press `Ctrl+C` at any time to output an aggregate threat summary report (total requests, block rate, traffic per container, and top targeted attack paths).

---

### 10. Interactive Terminal REPL (`tui`)

Launch an interactive terminal simulator to experiment with paths, query strings, headers, and client IPs in real time:

```bash
# Launch interactive REPL
rwarden tui

# Or with an alias
rwarden interactive

# Launch with pre-loaded configuration
rwarden tui ./routewarden.json
```

Inside the TUI:
- Type any path (e.g. `/.env`, `/%252e%252e/.env`, `/admin;p=1/config`) for instant candidate path normalization & verdict analysis.
- Use `:method POST`, `:ip 10.0.0.1`, `:query key=val`, `:header Key: Val`, `:load <file>`, `:status`, or `:help`.

---

### 11. Shell Autocompletion (`completion`)

Generate autocompletion scripts for subcommands, flags, and targets:

```bash
# Bash
source <(rwarden completion bash)

# Zsh
rwarden completion zsh > ~/.zsh/completion/_rwarden

# Fish
rwarden completion fish | source

# PowerShell
rwarden completion powershell | Out-String | Invoke-Expression
```

---

### 12. System Manpage (`man`)

Output the standard system manual page formatted in roff/troff:

```bash
# View manpage directly
rwarden man | man -l -

# Save to system man directory
sudo rwarden man -o /usr/share/man/man1/rwarden.1
```

---

### 13. Cleanup Sandboxes (`cleanup`)

Stop and remove all running or detached RouteWarden sandbox containers:

**CLI:**
```bash
rwarden cleanup

# Or via sandbox subcommand:
rwarden sandbox cleanup
```

**Docker:**
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/routewarden/cli:latest cleanup
```

---

### 14. Check CLI Version (`version`)

Display the current RouteWarden CLI version:

**CLI:**
```bash
rwarden version
rwarden --version
rwarden -v
```

**Docker:**
```bash
docker run --rm ghcr.io/routewarden/cli:latest version
```

**Example Output:**
```text
rwarden version 4.0.0
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
