# RouteWarden CLI (`rwarden`)

`rwarden` is a developer CLI for testing path security rules, verifying RouteWarden configuration files offline, and emitting the official JSON Schema.

---

## Installation

### 1. One-Liner Script (macOS & Linux)

Download and install the latest pre-compiled release binary automatically:

```bash
curl -fsSL https://routewarden.github.io/cli/install.sh | bash
```

Custom installation directory (e.g. `~/.local/bin`):

```bash
curl -fsSL https://routewarden.github.io/cli/install.sh | INSTALL_DIR=$HOME/.local/bin bash
```

*(Or via raw GitHub fallback: `curl -fsSL https://raw.githubusercontent.com/routewarden/cli/main/install.sh | bash`)*

---

### 2. Pre-built Release Binaries

Download standalone binaries for **Linux** (`amd64`, `arm64`), **macOS** (Apple Silicon `arm64` & Intel `amd64`), and **Windows** directly from [GitHub Releases](https://github.com/routewarden/cli/releases/latest).

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

```bash
rwarden version
# rwarden version 2.1.0
```

---

## Updating to the Latest Version

To update `rwarden` to the newest released version:

### 1. One-Liner Re-installation (macOS & Linux)
Re-running the universal installer automatically queries GitHub Releases for the latest version tag, downloads the matching pre-compiled binary, and safely replaces your existing binary:

```bash
# Default system-wide (/usr/local/bin):
curl -fsSL https://routewarden.github.io/cli/install.sh | bash

# Or custom user directory (~/.local/bin):
curl -fsSL https://routewarden.github.io/cli/install.sh | INSTALL_DIR=$HOME/.local/bin bash
```

### 2. Upgrading Docker Container Image
If using the containerized client, pull the latest image tag:

```bash
docker pull ghcr.io/routewarden/cli:latest
```

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

`rwarden` installs as a single standalone binary without hidden system daemons or dependencies. To remove it:

```bash
# Default system-wide installation:
sudo rm -f /usr/local/bin/rwarden

# Or user-local installation:
rm -f ~/.local/bin/rwarden
```

---

## Commands

### 1. Test URL Paths & Queries (`test`)

Simulate candidate path extraction, normalization, and pattern matching on an arbitrary path without starting Traefik, Caddy, or NGINX:

**CLI:**
```bash
# Test a sensitive file path
rwarden test --path "/.env"

# Test double URL encoding anti-evasion
rwarden test --path "/static/%252e%252e/.env"

# Test query string inspection
rwarden test --path "/search" --query "file=secret.conf"

# Test custom HTTP methods
rwarden test --method POST --path "/wp-config.php"

# Test custom HTTP headers
rwarden test --path "/api" --header "X-Forwarded-Uri: /.env"

# Test against a custom RouteWarden config file
rwarden test --config routewarden.json --path "/admin/dashboard"

# Test client IP whitelisting
rwarden test --config routewarden.json --path "/admin" --ip "10.0.0.1"

# Pipe configuration via stdin
cat routewarden.json | rwarden test --config - --path "/admin"
```

**Docker:**
```bash
# Test a sensitive path
docker run --rm ghcr.io/routewarden/cli:latest test --path "/.env"

# Test evasion via query inspection
docker run --rm ghcr.io/routewarden/cli:latest test --path "/search" --query "file=secret.conf"

# Test against custom config file
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest test --config /routewarden.json --path "/admin" --ip "10.0.0.1"
```

| Flag | Type | Default | Description |
|:---|:---|:---|:---|
| `--path` | string | `""` | **Required**. Request path to evaluate (e.g. `/.env` or `/api/v1`) |
| `--config` | string | `""` | Optional path to `routewarden.json` (or `-` for stdin) |
| `--query` | string | `""` | Optional request query string to evaluate |
| `--method` | string | `"GET"` | HTTP method (e.g. `GET`, `POST`, `HEAD`) |
| `--ip` | string | `""` | Optional client IP address to evaluate against `allowedIps` |
| `--header` | string | `""` | Optional header in `Key:Value` format to test |
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

**CLI:**
```bash
rwarden validate --config routewarden.json
```

**Docker:**
```bash
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest validate --config /routewarden.json
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
rwarden generate --target traefik-yaml --config routewarden.json > dynamic.yml

# Traefik: dynamic TOML middleware definition
rwarden generate --target traefik-toml --config routewarden.json > dynamic.toml

# Traefik: Docker Compose labels block
rwarden generate --target traefik-labels --config routewarden.json

# Caddy: Caddyfile directive block
rwarden generate --target caddy --config routewarden.json

# NGINX / OpenResty: Lua init table for nginx.conf
rwarden generate --target nginx --config routewarden.json
```

**Docker:**
```bash
# Traefik: dynamic YAML middleware definition
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate --target traefik-yaml --config /routewarden.json > dynamic.yml

# Traefik: dynamic TOML middleware definition
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate --target traefik-toml --config /routewarden.json > dynamic.toml

# Traefik: Docker Compose labels block
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate --target traefik-labels --config /routewarden.json

# Caddy: Caddyfile directive block
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate --target caddy --config /routewarden.json

# NGINX / OpenResty: Lua init table for nginx.conf
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate --target nginx --config /routewarden.json
```

| `--target` | Output |
|:---|:---|
| `traefik-yaml` (or `traefik`) | Traefik dynamic YAML middleware definition (`dynamic.yml`) |
| `traefik-toml` | Traefik dynamic TOML middleware definition (`dynamic.toml`) |
| `traefik-labels` | Docker Compose `labels:` block |
| `caddy` | Caddyfile `routewarden { ... }` directive block |
| `nginx` | OpenResty Lua table for `init_by_lua_block` in `nginx.conf` |

---

### 5. Live Gateway Sandbox (`sandbox`)

Test configurations against an ephemeral Docker container running **Traefik**, **Caddy**, or **NGINX**.

`rwarden sandbox` supports:
1. **Generic JSON** (`routewarden.json`): automatically synthesized into full gateway configurations.
2. **Actual Gateway Configs**: pass real `traefik.toml`, `traefik.yaml` / `dynamic.yml`, `docker-compose.yaml`, `Caddyfile`, or `nginx.conf` directly. Target gateway and format are **auto-detected** from filename and content.
3. **Inline Docker Labels**: test Traefik label snippets directly via `--labels`.
4. **Snippets & Complete Configs**: middleware-only snippets are automatically wrapped with sandbox entrypoints and mock upstream endpoints returning `200 OK` for passing traffic.

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
| `--target` | string | `""` | Target gateway: `traefik`, `caddy`, or `nginx` (optional if auto-detected) |
| `--config` | string | `""` | Path to gateway config (`traefik.toml`, `traefik.yaml`, `docker-compose.yaml`, `Caddyfile`, `nginx.conf`, `routewarden.json`, or `-`) |
| `--format` | string | `""` | Explicit format: `traefik-toml`, `traefik-yaml`, `traefik-labels`, `caddy`, `nginx`, `json` |
| `--labels` | string | `""` | Direct Traefik Docker labels string (e.g. `'traefik.http.middlewares.warden...'`) |
| `--probe-path` | string | `""` | Custom endpoint path to verify blocked during `--test` |
| `--probe-ip` | string | `""` | Client IP to simulate via `X-Forwarded-For` to verify allowlist bypass during `--test` |
| `--port` | int | `8080` | Local port to bind the gateway |
| `--version` | string | `""` | Target gateway container version tag (e.g. `v3.3`, `2.11.4`, `alpine`) |
| `--plugin-version` | string | `""` | RouteWarden plugin version/tag/branch (e.g. `v1.2.0`, `v1.1.0`, `main`) |
| `--plugin-path` | string | `""` | Local path to RouteWarden plugin directory to mount for development |
| `--print-config`, `-p` | bool | `false` | Print generated/wrapped gateway configuration before running |
| `--test` | bool | `false` | Run automated live HTTP probe assertions against container then exit |
| `--dry-run` | bool | `false` | Generate config and show docker command without starting container |
| `--detach`, `-d` | bool | `false` | Run container in background mode |

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

## License

MIT License. See [LICENSE](LICENSE) for details.
