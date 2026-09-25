# RouteWarden CLI (`rwarden`)

`rwarden` is a lightweight developer CLI for testing path rules, verifying RouteWarden configs offline, and outputting the official JSON Schema.

---

## Installation {#installation}

### 1. One-Liner Script (macOS & Linux)

Download and install the latest pre-compiled release binary automatically:

```bash
curl -fsSL https://routewarden.github.io/cli/install.sh | bash
```

To install without `sudo` into a user directory like `~/.local/bin`:

```bash
curl -fsSL https://routewarden.github.io/cli/install.sh | INSTALL_DIR=$HOME/.local/bin bash
```

---

### 2. Pre-built Release Binaries

Download standalone, statically compiled binaries for **Linux**, **macOS**, and **Windows** directly from [GitHub Releases](https://github.com/routewarden/cli/releases/latest):

| Platform | Architecture | Archive |
|:---|:---|:---|
| **macOS** | Apple Silicon (`arm64`) | [rwarden_3.0.0_darwin_arm64.tar.gz](https://github.com/routewarden/cli/releases/download/v3.0.0/rwarden_3.0.0_darwin_arm64.tar.gz) |
| **macOS** | Intel (`amd64`) | [rwarden_3.0.0_darwin_amd64.tar.gz](https://github.com/routewarden/cli/releases/download/v3.0.0/rwarden_3.0.0_darwin_amd64.tar.gz) |
| **Linux** | 64-bit (`amd64`) | [rwarden_3.0.0_linux_amd64.tar.gz](https://github.com/routewarden/cli/releases/download/v3.0.0/rwarden_3.0.0_linux_amd64.tar.gz) |
| **Linux** | ARM64 (`arm64`) | [rwarden_3.0.0_linux_arm64.tar.gz](https://github.com/routewarden/cli/releases/download/v3.0.0/rwarden_3.0.0_linux_arm64.tar.gz) |
| **Windows**| 64-bit (`amd64`) | [rwarden_3.0.0_windows_amd64.zip](https://github.com/routewarden/cli/releases/download/v3.0.0/rwarden_3.0.0_windows_amd64.zip) |

::: tip macOS Gatekeeper Notice
If macOS displays *"Apple could not verify “rwarden” is free of malware..."* when running a downloaded binary, macOS Gatekeeper has placed it in quarantine. You can remove the quarantine flag using:

```bash
xattr -d com.apple.quarantine $(which rwarden)
# Or for a downloaded binary directly:
xattr -d com.apple.quarantine rwarden
```

Alternatively, navigate to **System Settings > Privacy & Security** and click **"Allow Anyway"** next to the `rwarden` prompt.
:::

All downloads and checksums are verified on the [Releases Page](https://github.com/routewarden/cli/releases/latest).

---

### 3. Container Image (Docker / CI/CD)

Run `rwarden` via container without installing any local binaries:

```bash
# Validate configuration file directly
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest validate --config /routewarden.json

# Test path interactively
docker run --rm ghcr.io/routewarden/cli:latest test --path "/.env"
```

---

### 4. From Source (Go)

```bash
git clone https://github.com/routewarden/cli.git
cd cli
go build -o /usr/local/bin/rwarden .
```

Verify installation:

::: code-group

```bash [CLI]
rwarden version
# rwarden version 3.0.0
```

```bash [Docker]
docker run --rm ghcr.io/routewarden/cli:latest version
# rwarden version 3.0.0
```

:::

---

### Uninstallation

`rwarden` is a single self-contained binary with no background background services or external runtime dependencies. To completely remove it from your machine:

```bash
# If installed system-wide (default):
sudo rm -f /usr/local/bin/rwarden

# If installed in user directory:
rm -f ~/.local/bin/rwarden
```

---

## Commands {#commands}

### 1. Test URL Paths & Queries (`test`)

Simulate candidate path extraction, normalization, and pattern matching on an arbitrary path without starting Traefik, Caddy, or NGINX:

::: code-group

```bash [CLI]
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

```bash [Docker]
# Test a sensitive path
docker run --rm ghcr.io/routewarden/cli:latest test /.env

# Test double URL encoding anti-evasion
docker run --rm ghcr.io/routewarden/cli:latest test "/static/%252e%252e/.env"

# Test evasion via query inspection
docker run --rm ghcr.io/routewarden/cli:latest test -q "file=secret.conf" /search

# Test against custom config file
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest test -c /routewarden.json --ip "10.0.0.1" /admin
```

:::

| Flag | Type | Default | Description |
|:---|:---|:---|:---|
| `[path]`, `--path` | string | `""` | Request path to evaluate (e.g. `/.env` or `/api/v1`) |
| `-c`, `--config` | string | `""` | Optional path to `routewarden.json` (or `-` for stdin) |
| `-q`, `--query` | string | `""` | Optional request query string to evaluate |
| `-X`, `-m`, `--method` | string | `"GET"` | HTTP method (e.g. `GET`, `POST`, `HEAD`) |
| `-H`, `--header` | string | `""` | Optional header in `Key:Value` format to test (repeatable) |
| `--ip` | string | `""` | Optional client IP address to evaluate against `allowedIps` |
| `--check-query` | bool | `true` | Enable or disable query string inspection |

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

::: code-group

```bash [CLI]
# Validate routewarden.json directly (positional or --config)
rwarden validate routewarden.json
rwarden validate -c routewarden.json

# Auto-detects routewarden.json in current directory if omitted
rwarden validate

# Validate piped config via stdin
cat routewarden.json | rwarden validate
```

```bash [Docker]
# Validate mounted config file
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest validate /routewarden.json
```

:::

| Flag | Type | Default | Description |
|:---|:---|:---|:---|
| `[config]`, `-c`, `--config` | string | `"routewarden.json"` | Path to RouteWarden JSON config file (or `-` for stdin) |

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

::: code-group

```bash [CLI]
rwarden schema > routewarden.schema.json
```

```bash [Docker]
docker run --rm ghcr.io/routewarden/cli:latest schema > routewarden.schema.json
```

:::

---

### 4. Generate Gateway Configs (`generate`)

Convert `routewarden.json` into native gateway configuration — no manual translation required. Flags and positional arguments may be used interchangeably:

::: code-group

```bash [CLI]
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
```

```bash [Docker]
# Traefik: output as dynamic YAML middleware definition
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate traefik-yaml /routewarden.json > dynamic.yml

# Traefik: output as dynamic TOML middleware definition
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate traefik-toml /routewarden.json > dynamic.toml

# Traefik: output as Docker Compose labels block
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate traefik-labels /routewarden.json

# Caddy: output as Caddyfile directive block
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate caddy /routewarden.json

# NGINX / OpenResty: output as Lua init table for nginx.conf
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate nginx /routewarden.json
```

:::

| Flag | Type | Default | Description |
|:---|:---|:---|:---|
| `<target>`, `-t`, `--target` | string | `""` | Target gateway format (e.g. `traefik-yaml`, `caddy`, `nginx`) |
| `[config]`, `-c`, `--config` | string | `"routewarden.json"` | Path to RouteWarden JSON config file (or `-` for stdin) |

**Available Targets & Aliases:**

| Target / Alias | Output |
|:---|:---|
| `traefik-yaml`, `traefik`, `yaml`, `yml` | Traefik dynamic YAML middleware definition (`dynamic.yml`) |
| `traefik-toml`, `toml` | Traefik dynamic TOML middleware definition (`dynamic.toml`) |
| `traefik-labels`, `compose`, `docker-compose`, `labels` | Docker Compose `labels:` block |
| `caddy`, `caddyfile` | Caddyfile `routewarden { ... }` directive block |
| `nginx`, `openresty` | OpenResty Lua table for `init_by_lua_block` in `nginx.conf` |

---

### 5. Live Gateway Sandbox (`sandbox`)

Test configurations against an ephemeral Docker container running **Traefik**, **Caddy**, or **NGINX**.

`rwarden sandbox` supports:
1. **Generic JSON (`routewarden.json`)**: Automatically synthesized into complete gateway configurations.
2. **Actual Gateway Configs**: Pass real `traefik.toml`, `traefik.yaml` / `dynamic.yml`, `docker-compose.yaml`, `Caddyfile`, or `nginx.conf` directly. Target gateway and format are **auto-detected** from filename and content.
3. **Inline Docker Labels**: Test Traefik label snippets directly via `--labels`.
4. **Snippets & Complete Production Configs**:
   - **Snippets**: Middleware-only snippets are automatically wrapped with sandbox entrypoints and mock upstream endpoints returning `200 OK` for passing traffic.
   - **Complete Configs**: Full configurations with backend service URLs, upstreams, or proxies are automatically adapted for ephemeral sandboxes in-memory without modifying your source file:
     - **Traefik**: External loadBalancer service URLs (`url`, `service`) are redirected to Traefik's internal ping service (`ping@internal`), entrypoints guarantee `:8080` binding, and router TLS directives are safely neutralized for local HTTP testing.
     - **Caddy**: Upstream `reverse_proxy` targets are replaced with mock `200 OK` responders, `order routewarden first` and `auto_https off` are injected, and custom site blocks bind to `:8080`.
     - **NGINX**: External `upstream` hostnames are neutralized with `down` to prevent OpenResty startup DNS failures, `proxy_pass` directives are converted to mock Lua `200 OK` responders, local SSL certificate requirements are bypassed, and `listen 8080;` is configured.
   - **Live Upstream Reachability**: In `--test` mode, RouteWarden recognizes upstream reachability (HTTP `200`, or HTTP `502`/`504` from an offline production backend) as an allowlist pass-through.

::: code-group

```bash [CLI]
# 1. Test actual Traefik TOML configuration (auto-detects target & mounts dynamic.toml)
rwarden sandbox traefik.toml
rwarden sandbox -c traefik.toml

# 2. Test actual Traefik YAML / dynamic.yml
rwarden sandbox dynamic.yml

# 3. Test Docker Compose with Traefik labels
rwarden sandbox docker-compose.yaml

# 4. Test Traefik labels inline
rwarden sandbox --labels "traefik.http.middlewares.shield.plugin.routewarden.enabled=true"

# 5. Test actual Caddyfile
rwarden sandbox Caddyfile

# 6. Test actual nginx.conf
rwarden sandbox nginx.conf

# 7. Automated live probe verification with custom path and IP allowlist assertion
rwarden sandbox docker-compose.yaml --test --probe-path "/immich/api/admin" --probe-ip "10.0.0.1"

# 8. Dry-run: inspect generated/wrapped gateway config & exact docker run command
rwarden sandbox traefik.toml -n -p

# 9. Run in detached background mode
rwarden sandbox caddy Caddyfile -d

# 10. Run against specific RouteWarden plugin version or local plugin path
rwarden sandbox traefik --plugin-version v1.2.0
rwarden sandbox traefik --plugin-path ../traefik-warden
```

```bash [Docker]
# Test actual traefik.toml via Docker (mounts docker.sock):
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/traefik.toml:/config/traefik.toml:ro \
  -p 8080:8080 \
  ghcr.io/routewarden/cli:latest sandbox /config/traefik.toml

# Test Docker Compose Traefik labels via Docker:
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/docker-compose.yaml:/config/docker-compose.yaml:ro \
  -p 8080:8080 \
  ghcr.io/routewarden/cli:latest sandbox /config/docker-compose.yaml --test

# Test inline labels without mounting files:
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -p 8080:8080 \
  ghcr.io/routewarden/cli:latest sandbox \
  --labels "traefik.http.middlewares.shield.plugin.routewarden.enabled=true" \
  --test
```

:::

| Flag | Type | Default | Description |
|:---|:---|:---|:---|
| `[config]`, `-c`, `--config` | string | `""` | Path to gateway config (`traefik.toml`, `dynamic.yml`, `docker-compose.yaml`, `Caddyfile`, `nginx.conf`, `routewarden.json`, or `-`) |
| `-t`, `--target` | string | `""` | Target gateway: `traefik`, `caddy`, or `nginx` (optional if auto-detected or passed as positional argument) |
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

Once your sandbox container is running on port `8080`, test real HTTP requests against it:

```bash
# 1. Direct sensitive file access (blocked)
curl -i http://localhost:8080/.env

# 2. Path traversal & double URL encoding evasion (blocked)
curl -i http://localhost:8080/static/%252e%252e/.env

# 3. Query string inspection (blocked if checkQuery is enabled)
curl -i "http://localhost:8080/search?file=secret.conf"

# 4. Semicolon matrix parameter evasion (blocked)
curl -i "http://localhost:8080/app;jsessionid=123/.env"

# 5. Reverse proxy header smuggling (blocked if checkHeaders is enabled)
curl -i -H "X-Forwarded-Uri: /.env" http://localhost:8080/api/dashboard

# 6. Legitimate public asset (allowed downstream)
curl -i http://localhost:8080/robots.txt

# 7. Client IP whitelisting test (simulating a request from whitelisted IP 192.168.1.50)
curl -i -H "X-Forwarded-For: 192.168.1.50" http://localhost:8080/.env
```

::: tip Security Note on Client IP & Reverse Proxies
In local testing and the sandbox, passing `X-Forwarded-For` allows you to simulate requests from whitelisted IPs without reconfiguring your network.

In **production deployments**, edge reverse proxies (Cloudflare, AWS ALB, Traefik, or NGINX) strip or overwrite untrusted client-supplied `X-Forwarded-For` headers with the client's actual TCP socket IP. Ensure your edge gateway is configured to only trust upstream proxy headers from verified addresses (e.g. `trustedIPs` in Traefik, `trusted_proxies` in Caddy, or `set_real_ip_from` in NGINX).
:::

---

### 6. Self-Hosted Security Dashboard (`dashboard`) {#dashboard}

Launch a lightweight, self-hosted web dashboard to visualize real-time security events, blocked probes, honeypot tarpit engagements, and attack analytics across your Traefik, Caddy, and NGINX instances.

![RouteWarden Dashboard - Live Event Feed](/dashboard-feed.png)

#### Key Capabilities {#dashboard-features}

- **Zero-Config Docker Discovery**: Attaches directly to the local Docker daemon (`/var/run/docker.sock`) to auto-discover and stream logs from running Traefik, Caddy, and NGINX gateway containers in real time.
- **Log File Tailing**: Tail local log files or wildcard patterns (e.g. `/var/log/routewarden/*.log`) with automatic log rotation handling.
- **Real-Time Live Feed**: Low-latency WebSocket / SSE stream of blocked requests, client IPs with flag emojis, matched URI patterns, HTTP methods, and triggered response modes.
- **Visual Analytics**: Interactive 24-hour attack timelines, blocks per minute, top attacked endpoints, top offender IPs, response mode breakdown (`block`, `tarpit`, `gzipBomb`, `silentDrop`, `fakeSuccess`), and gateway distribution.
- **v1.2 Config Viewer**: Inspect running container configuration and `routewarden.json` labels directly from the UI without leaving the dashboard.
- **GeoIP & Autonomous System Intelligence**: Country resolution with flag emojis via embedded MaxMind GeoLite2 MMDB or live fallback, including ASN, ISP, and location metadata.
- **Tailscale & NetBird Mesh Auto-Detection**: Native identification for Tailscale (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) and NetBird (`100.64.0.0/16`, `fd00::/8`) overlay networks as well as RFC 5737 testnets (`203.0.113.0/24`).
- **Deep IP Intelligence View**: Comprehensive threat risk scoring (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), payload patterns, targeted gateways, and paginated event histories per IP.
- **Zero-Dependency Single Binary**: The modern React SPA frontend is pre-compiled and embedded directly inside the `rwarden` Go binary (`go:embed`). No Node.js runtime, external database, or cloud dependencies required.

---

#### Dashboard Views {#dashboard-views}

##### 1. Live Event Feed {#dashboard-live-feed}
Stream security events from all gateways with instant search, container filtering, pause/resume, and server-assisted pagination.

![RouteWarden Dashboard - Live Event Feed](/dashboard-feed.png)

##### 2. Analytics & Attack Trends {#dashboard-analytics}
Inspect 24-hour, 6-hour, and 1-hour attack timelines, rolling block rates, and distribution charts for endpoints, offender IPs, and defense actions.

![RouteWarden Dashboard - Attack Analytics & Statistics](/dashboard-stats.png)

##### 3. Sources & Container Management {#dashboard-sources}
Monitor all discovered Docker containers and tailed log files. Inspect the active `routewarden.json` configuration for any gateway with a single click.

![RouteWarden Dashboard - Active Log Sources & Containers](/dashboard-sources.png)

##### 4. Deep IP Intelligence & Risk Scoring {#dashboard-ip-intelligence}
Analyze any IP address with behavioral profiling, ASN/ISP lookup, geographic location, and threat risk assessment.

![RouteWarden Dashboard - IP Threat Intelligence](/dashboard-ip-details.png)

##### 5. Mesh VPN & Private Overlay Recognition {#dashboard-mesh-vpn}
Automatic recognition of Tailscale and NetBird mesh peers (`100.64.0.0/10` CGNAT, `fd7a:115c:a1e0::/48`, and `fd00::/8` ULA) with dedicated `🔒` indicator badges.

![RouteWarden Dashboard - Tailscale & NetBird VPN Intelligence](/dashboard-ip-vpn.png)

---

#### CLI Usage Examples {#dashboard-usage}

::: code-group

```bash [CLI]
# 1. Start dashboard with Docker auto-discovery and open browser automatically
rwarden dashboard

# 2. Bind to a custom port without auto-opening the browser
rwarden dashboard --port 8080 --no-open

# 3. Tail one or more local RouteWarden log files
rwarden dashboard --log /var/log/routewarden.log

# 4. Tail wildcard patterns and multiple log sources simultaneously
rwarden dashboard --log "/var/log/routewarden/*.log" --log /var/log/nginx/access.log

# 5. Standalone file-only mode (disable Docker socket discovery)
rwarden dashboard --no-docker --log /var/log/routewarden.log

# 6. Customize memory retention (number of past events loaded)
rwarden dashboard --history 2500 --port 9090
```

```bash [Docker]
# Auto-discover gateway containers via Docker socket
docker run -d \
  --name routewarden-dashboard \
  --restart unless-stopped \
  -p 9090:9090 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ghcr.io/routewarden/cli:latest

# Or tail log files from a host volume
docker run -d \
  --name routewarden-dashboard \
  --restart unless-stopped \
  -p 9090:9090 \
  -v /var/log/routewarden:/logs:ro \
  ghcr.io/routewarden/cli:latest \
  dashboard --host 0.0.0.0 --no-docker --log "/logs/*.log"
```

```yaml [Docker Compose]
version: "3.8"

services:
  traefik:
    image: traefik:v3.3
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik.yml:/etc/traefik/traefik.yml:ro

  routewarden-dashboard:
    image: ghcr.io/routewarden/cli:latest
    container_name: routewarden-dashboard
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    command: ["dashboard", "--host", "0.0.0.0", "--no-open"]
```

:::

#### Command Flags {#dashboard-flags}

| Flag | Type | Default | Description |
|:---|:---|:---|:---|
| `--port` | int | `9090` | Port to serve the dashboard web interface |
| `--host` | string | `127.0.0.1` | Host address to bind (`0.0.0.0` in Docker / remote access) |
| `--log` | string | `""` | Path or glob pattern to log file(s) to tail (repeatable) |
| `--no-docker` | bool | `false` | Disable Docker daemon socket discovery |
| `--socket` | string | `/var/run/docker.sock` | Path to Docker daemon Unix socket |
| `--history` | int | `1000` | Number of events retained in memory and loaded on startup |
| `--no-open` | bool | `false` | Do not automatically launch the system default browser |

#### Built-in REST & WebSocket Endpoints {#dashboard-api}

The dashboard server exposes an HTTP API for external integrations, status checks, and monitoring systems:

| Endpoint | Method | Description |
|:---|:---|:---|
| `/api/health` | `GET` | Health check returning status, version, and active client count |
| `/api/events?n=500` | `GET` | Fetch the last `n` recorded security events as JSON |
| `/api/stats?hours=24` | `GET` | Aggregated analytics snapshot (rates, top IPs, top paths, response modes, gateway distribution) |
| `/api/sources` | `GET` | List of active log sources (Docker containers & tailed files) and their statuses |
| `/api/sources/clear` | `POST` | Remove stopped or disconnected log sources from memory |
| `/api/config/:id` | `GET` | Retrieve and parse `routewarden.json` configuration from a Docker container |
| `/api/geoip?ip=...` | `GET` | Resolve IP geolocation, country code, flag emoji, and ISP details |
| `/api/ip/:ip` | `GET` | Deep intelligence summary for a specific IP (threat score, top paths, methods, history) |
| `/ws/events` | `GET` | Real-time WebSocket connection for live event streaming |

---

### 7. Cleanup Sandbox Containers (`cleanup`)

Stop and remove all running or detached RouteWarden sandbox containers:

::: code-group

```bash [CLI]
rwarden cleanup

# Or via sandbox subcommand:
rwarden sandbox cleanup
```

```bash [Docker]
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/routewarden/cli:latest cleanup
```

:::

---

### 8. Check CLI Version (`version`)

Display the current RouteWarden CLI version:

::: code-group

```bash [CLI]
rwarden version
rwarden --version
rwarden -v
```

```bash [Docker]
docker run --rm ghcr.io/routewarden/cli:latest version
```

:::

**Example Output**:
```text
rwarden version 2.1.0
```

---

## JSON Schema & IDE Setup {#json-schema}

The official RouteWarden JSON Schema is hosted at:
```text
https://routewarden.github.io/cli/schema.json
```
*(Also mirrored at `https://raw.githubusercontent.com/routewarden/cli/main/config.schema.json`)*

It provides real-time validation, syntax checking, and inline autocomplete for:
- Traefik dynamic middleware YAML/JSON configurations
- Caddy JSON API routes and handler configurations
- Standalone RouteWarden JSON/YAML configs loaded by NGINX Lua or CI/CD pipelines

---

### 1. Visual Studio Code Setup

Add schema mappings to your workspace `.vscode/settings.json`:

```json
{
  "json.schemas": [
    {
      "fileMatch": [
        "routewarden*.json",
        "*traefik*.json",
        "caddy*.json"
      ],
      "url": "https://raw.githubusercontent.com/routewarden/cli/main/config.schema.json"
    }
  ],
  "yaml.schemas": {
    "https://raw.githubusercontent.com/routewarden/cli/main/config.schema.json": [
      "routewarden*.yml",
      "routewarden*.yaml",
      "dynamic_conf.yml",
      "traefik-dynamic*.yml"
    ]
  }
}
```

> **Tip**: Ensure the official Red Hat YAML extension (`redhat.vscode-yaml`) is installed for YAML file validation.

---

### 2. JetBrains IDEs (IntelliJ, GoLand, WebStorm)

1. Open **Settings / Preferences** (`⌘,` on macOS or `Ctrl+Alt+S` on Linux/Windows).
2. Navigate to **Languages & Frameworks** → **Schemas and DTDs** → **JSON Schema Mappings**.
3. Click **+** (Add):
   - **Name**: `RouteWarden`
   - **Schema file or URL**: `https://raw.githubusercontent.com/routewarden/cli/main/config.schema.json`
   - **Schema version**: `JSON Schema version 7` or `2020-12`
4. Under **File path pattern**, add:
   - `routewarden*.json`
   - `routewarden*.yml`
   - `dynamic_conf.yml`
   - `caddy*.json`

---

### 3. Gateway Usage Examples

#### Traefik Dynamic YAML Configuration
Use top-of-file modeline comment to bind schema directly without global IDE settings:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/routewarden/cli/main/config.schema.json
enabled: true
enableDefaultPatterns: true
checkQuery: true
checkHeaders:
  - X-Forwarded-Uri
  - X-Rewrite-URL
methods:
  - GET
  - POST
response:
  mode: json
  statusCode: 403
  body: '{"error":"Forbidden: Sensitive access blocked"}'
```

#### Caddy JSON Configuration
When configuring Caddy via the REST API or JSON files, map the `route_warden` handler directly:

```json
{
  "$schema": "https://raw.githubusercontent.com/routewarden/cli/main/config.schema.json",
  "enabled": true,
  "enableDefaultPatterns": true,
  "checkQuery": false,
  "checkHeaders": ["X-Forwarded-Uri"],
  "methods": ["GET", "HEAD"],
  "response": {
    "mode": "json",
    "statusCode": 403
  }
}
```

#### NGINX / OpenResty JSON Configuration
If your NGINX Lua configuration reads external JSON configs via `cjson.decode(io.open("/etc/nginx/routewarden.json"):read("*a"))`:

```json
{
  "$schema": "https://raw.githubusercontent.com/routewarden/cli/main/config.schema.json",
  "enabled": true,
  "enableDefaultPatterns": true,
  "enableDefaultAllowPatterns": true,
  "checkQuery": true,
  "checkHeaders": ["X-Forwarded-Uri", "X-Rewrite-URL"],
  "methods": ["GET", "POST"],
  "response": {
    "mode": "rateLimitChallenge",
    "statusCode": 429,
    "retryAfterSeconds": 300
  }
}
```

And in NGINX `init_by_lua_block`:

```nginx
init_by_lua_block {
    local cjson = require("cjson")
    local routewarden = require("resty.routewarden")

    local f = io.open("/etc/nginx/routewarden.json", "r")
    local cfg_json = f:read("*all")
    f:close()

    local cfg = cjson.decode(cfg_json)
    warden = routewarden.new(cfg)
}
```

---

## Using `routewarden.json` in Production {#production}

`routewarden.json` is a **universal, gateway-agnostic security configuration file**. It lets you decouple your security posture from your web server configurations, allowing security and DevOps teams to maintain rules centrally with schema validation.

### Workflow Overview

```text
┌──────────────────────────────────────────────────────────┐
│                   routewarden.json                       │
│  - Built with schema autocomplete ($schema)              │
│  - Tested & validated via rwarden in CI/CD               │
└────────────────────────────┬─────────────────────────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       ▼                     ▼                     ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ NGINX / Lua  │      │   Traefik    │      │    Caddy     │
│ JSON Loader  │      │ File Provider│      │   REST API   │
└──────────────┘      └──────────────┘      └──────────────┘
```

---

### 1. Offline Verification & CI/CD Pipeline Linting

Before pushing updates to production, use `rwarden` to validate your `routewarden.json` configuration file:

::: code-group

```bash [CLI]
# Offline syntax, regex, and CIDR validation
rwarden validate --config routewarden.json

# Simulate request evaluation against the rules
rwarden test --path "/.env"
rwarden test --path "/dashboard" --header "X-Forwarded-Uri:/.env"
```

```bash [Docker]
# Offline syntax, regex, and CIDR validation via container
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest validate --config /routewarden.json

# Simulate request evaluation against the rules
docker run --rm ghcr.io/routewarden/cli:latest test --path "/.env"
docker run --rm ghcr.io/routewarden/cli:latest test --path "/dashboard" --header "X-Forwarded-Uri:/.env"
```

:::

#### GitHub Actions CI Example (`.github/workflows/verify-rules.yml`)

::: code-group

```yaml [Go Tool / Binary]
name: Verify Security Rules

on:
  pull_request:
    paths:
      - 'routewarden.json'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - name: Install RouteWarden CLI
        run: go install github.com/routewarden/cli@latest
      - name: Validate Configuration
        run: rwarden validate --config routewarden.json
```

```yaml [Docker Container (Zero Setup)]
name: Verify Security Rules

on:
  pull_request:
    paths:
      - 'routewarden.json'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate Configuration via Docker
        run: docker run --rm -v ${{ github.workspace }}/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest validate --config /routewarden.json
```

:::

---

### 2. Loading into NGINX / OpenResty

Instead of hardcoding rules in `nginx.conf`, mount `routewarden.json` into your container and load it dynamically during worker startup:

#### `docker-compose.yml`
```yaml
services:
  nginx:
    image: openresty/openresty:alpine
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./routewarden.json:/etc/nginx/routewarden.json:ro
```

#### `nginx.conf`
```nginx
http {
    init_by_lua_block {
        local cjson = require("cjson")
        local routewarden = require("resty.routewarden")

        -- Load external JSON configuration
        local f, err = io.open("/etc/nginx/routewarden.json", "r")
        if not f then
            ngx.log(ngx.ERR, "failed to read routewarden.json: ", err)
            return
        end
        local content = f:read("*all")
        f:close()

        local config = cjson.decode(content)
        warden = routewarden.new(config)
    }

    server {
        listen 80;

        access_by_lua_block {
            warden:check()
        }

        location / {
            proxy_pass http://backend_upstream;
        }
    }
}
```

To update rules without restarting NGINX, simply modify `routewarden.json` and reload:
```bash
nginx -s reload
```

---

### 3. Traefik Dynamic File Provider

Traefik natively supports JSON for dynamic configuration providers:

#### `traefik.yml` (Static Config)
```yaml
providers:
  file:
    filename: /etc/traefik/dynamic_conf.json
    watch: true
```

#### `dynamic_conf.json`
```json
{
  "$schema": "https://raw.githubusercontent.com/routewarden/cli/main/config.schema.json",
  "http": {
    "middlewares": {
      "security-warden": {
        "plugin": {
          "routewarden": {
            "enabled": true,
            "enableDefaultPatterns": true,
            "checkQuery": true,
            "checkHeaders": ["X-Forwarded-Uri", "X-Rewrite-URL"],
            "response": {
              "mode": "json",
              "statusCode": 403
            }
          }
        }
      }
    }
  }
}
```

---

### 4. Caddy JSON API Automation

Caddy's runtime configuration is completely addressable via JSON. You can push `routewarden.json` directly to Caddy's admin API endpoint with zero downtime:

```bash
# Push RouteWarden config to the first route handler
curl -X POST "http://localhost:2019/config/apps/http/servers/srv0/routes/0/handle/0" \
  -H "Content-Type: application/json" \
  -d @routewarden.json
```

Or inspect how a Caddyfile translates into the JSON schema:
```bash
caddy adapt --config Caddyfile --pretty
```

---

## Changelog {#changelog}

All notable changes to the RouteWarden CLI (`rwarden`) are documented below. The CLI adheres to [Semantic Versioning](https://semver.org/).

### [v3.0.0] - 2026-09-25

#### Added
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

#### Changed
- Documentation site updated with a dedicated **Security Dashboard** section in the VitePress sidebar, covering all views with real screenshots.
- Sidebar scroll-spy updated to track all dashboard subsection anchors and auto-scroll the sidebar to keep the active item visible.
- Top navigation updated with a direct **Dashboard** link.

---

### [v2.1.0] - 2026-09-24

#### Added
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

#### Fixed
- **Regex & Configuration Parsing**:
  - Fixed RE2 regex backreference in Traefik label parsing to ensure 100% Go regexp standard library compliance.
  - Prevented multiline upstream regex greediness in NGINX config adaptation from corrupting `server {` blocks.
  - Injected missing `middlewares:` parent block in synthetic Traefik sandbox YAML generation.
  - Enhanced label normalization to recognize root-level response parameters (`status`, `statusCode`, `mode`, `action`, `customResponseText`).
  - Removed legacy direct boolean `silentDrop` property from `Config` schema, structs, and Docker label converters (use `mode: "silentDrop"`, `action: "silentDrop"`, or `response.mode: "silentDrop"` instead).

---

### [v2.0.0] - 2026-09-21

#### Added
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

### [v1.1.0] - 2026-09-21

#### Added
- **Multi-Gateway Config Generator (`generate`)**:
  - Convert `routewarden.json` into native configuration for **Traefik Dynamic YAML** (`--target traefik`), **Traefik Docker Labels** (`--target traefik-labels`), **Caddy Caddyfile** (`--target caddy`), and **NGINX / OpenResty Lua** (`--target nginx`).
  - Added support for `--config -` to stream configuration via standard input (stdin).
  - Accurate serialization for `checkQuery`, `checkHeaders`, `methods`, and nested `response { mode, status, body }` blocks.
- **Client IP Whitelist Simulation (`test --ip`)**:
  - Test client IP evaluation against CIDR blocks and single IP allowlists offline (`rwarden test --config routewarden.json --path "/admin" --ip "10.0.0.1"`).
- **HTTP Header Smuggling Inspection (`test --header`)**:
  - Test custom headers in `Key:Value` format (e.g., `X-Forwarded-Uri`, `X-Rewrite-URL`, `X-Original-URL`) to evaluate reverse proxy path normalization anti-evasion.
- **Config & Query Precedence in Offline Testing**:
  - Added `--config <path>` flag to `rwarden test` to evaluate paths directly against custom configurations with full rule normalization.
  - Added `--check-query` boolean flag (default `true` for interactive CLI usage, respects configuration file when provided).
- **Comprehensive Configuration Validation (`validate`)**:
  - Added HTTP status code range checks (100–599) across top-level and response configs.
  - Added response mode validation (`text`, `json`, `html`, `captcha`, `redirect`, `silentDrop`, `drop`, `gzipBomb`, `tarpit`, `fakeSuccess`, `rateLimitChallenge`, `proxy`, `infiniteStream`).
  - Added required target URL validation for `redirect` (`redirectUrl`) and `proxy` (`proxyUrl`) modes.
  - Added CAPTCHA provider validation (`turnstile`, `hcaptcha`, `recaptcha`, `custom`).
- **Release Automation**:
  - Added `scripts/update-version.sh` and `VERSIONING.md` for maintainers.

#### Changed
- Normalized top-level `mode`, `action`, and `silentDrop` aliases uniformly into `Response.Mode`.
- Modernized Caddyfile generator output to use the standard `response { mode ... status ... body ... }` directive block.

---

### [v1.0.0] - 2026-09-20

#### Initial Release
- **Path Anti-Evasion Inspection Engine (`test`)**:
  - Offline candidate path extraction simulating Traefik and Caddy middleware pipelines.
  - Recursive multi-layer URL percent-decoding (`%252e%252e`).
  - Semicolon matrix parameter stripping (`/;param/.env`).
  - Windows/IIS backslash normalization (`\..\`).
  - Null-byte injection scrubbing (`%00`).
  - Dot-segment path traversal resolving (`/static/../.env`).
  - Default block pattern matching across sensitive files (`.env`, `server.key`, `cert.pem`, `Dockerfile`, `.git`, etc.).
  - Default allow pattern overrides (`robots.txt`, `favicon.ico`, `sitemap.xml`, `.well-known`).
- **Configuration Validator (`validate`)**:
  - Offline schema validation of `routewarden.json`.
  - Detection of invalid regular expressions and malformed CIDR blocks.
  - Detailed summary breakdown of active rules, allowlists, and monitored headers.
- **Official JSON Schema Export (`schema`)**:
  - CLI command emitting `config.schema.json` directly for IDE integration (VS Code, JetBrains, Neovim) and CI/CD validation.
- **Distribution**:
  - Single-binary zero-dependency Go distribution for macOS (`amd64`, `arm64`), Linux (`amd64`, `arm64`), and Windows (`amd64`).
  - Automated installation script (`curl -fsSL https://routewarden.github.io/cli/install.sh | bash`).
  - Official multi-architecture Docker container image on GitHub Container Registry (`ghcr.io/routewarden/cli:latest`).



