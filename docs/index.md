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
| **macOS** | Apple Silicon (`arm64`) | [rwarden_2.0.0_darwin_arm64.tar.gz](https://github.com/routewarden/cli/releases/download/v2.0.0/rwarden_2.0.0_darwin_arm64.tar.gz) |
| **macOS** | Intel (`amd64`) | [rwarden_2.0.0_darwin_amd64.tar.gz](https://github.com/routewarden/cli/releases/download/v2.0.0/rwarden_2.0.0_darwin_amd64.tar.gz) |
| **Linux** | 64-bit (`amd64`) | [rwarden_2.0.0_linux_amd64.tar.gz](https://github.com/routewarden/cli/releases/download/v2.0.0/rwarden_2.0.0_linux_amd64.tar.gz) |
| **Linux** | ARM64 (`arm64`) | [rwarden_2.0.0_linux_arm64.tar.gz](https://github.com/routewarden/cli/releases/download/v2.0.0/rwarden_2.0.0_linux_arm64.tar.gz) |
| **Windows**| 64-bit (`amd64`) | [rwarden_2.0.0_windows_amd64.zip](https://github.com/routewarden/cli/releases/download/v2.0.0/rwarden_2.0.0_windows_amd64.zip) |

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
# rwarden version 2.0.0
```

```bash [Docker]
docker run --rm ghcr.io/routewarden/cli:latest version
# rwarden version 2.0.0
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
# Test a sensitive file path
rwarden test --path "/.env"

# Test double URL encoding anti-evasion
rwarden test --path "/static/%252e%252e/.env"

# Test query string inspection
rwarden test --path "/search" --query "file=secret.conf"

# Test custom HTTP methods
rwarden test --method POST --path "/wp-config.php"
```

```bash [Docker]
# Test a sensitive file path
docker run --rm ghcr.io/routewarden/cli:latest test --path "/.env"

# Test double URL encoding anti-evasion
docker run --rm ghcr.io/routewarden/cli:latest test --path "/static/%252e%252e/.env"

# Test query string inspection
docker run --rm ghcr.io/routewarden/cli:latest test --path "/search" --query "file=secret.conf"

# Test custom HTTP methods
docker run --rm ghcr.io/routewarden/cli:latest test --method POST --path "/wp-config.php"
```

:::

**Example Output**:
```text
🔍 Testing: GET /static/%252e%252e/.env
  Candidate paths extracted (2):
    - /static/%252e%252e/.env
    - /.env

Result: 🛑 BLOCKED (HTTP Status 403)
```

---

### 2. Validate Configurations (`validate`)

Validate a RouteWarden JSON configuration file before deploying:

::: code-group

```bash [CLI]
# Validate local configuration file
rwarden validate --config routewarden.json
```

```bash [Docker]
# Mount configuration file directly into container and validate
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest validate --config /routewarden.json
```

:::

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

Convert a `routewarden.json` specification into native gateway configuration format — no manual translation required:

::: code-group

```bash [CLI]
# Traefik: output as dynamic YAML middleware definition
rwarden generate --target traefik --config routewarden.json > dynamic.yml

# Traefik: output as Docker Compose label block
rwarden generate --target traefik-labels --config routewarden.json

# Caddy: output as Caddyfile directive block
rwarden generate --target caddy --config routewarden.json

# NGINX / OpenResty: output as Lua init table for nginx.conf
rwarden generate --target nginx --config routewarden.json
```

```bash [Docker]
# Traefik: output as dynamic YAML middleware definition
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate --target traefik --config /routewarden.json > dynamic.yml

# Traefik: output as Docker Compose label block
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate --target traefik-labels --config /routewarden.json

# Caddy: output as Caddyfile directive block
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate --target caddy --config /routewarden.json

# NGINX / OpenResty: output as Lua init table for nginx.conf
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json ghcr.io/routewarden/cli:latest generate --target nginx --config /routewarden.json
```

:::

**Available `--target` values:**

| Target | Output |
| :--- | :--- |
| `traefik` | Traefik dynamic YAML middleware definition (mountable as `dynamic.yml`) |
| `traefik-labels` | Docker Compose `labels:` block for direct service configuration |
| `caddy` | Caddyfile `routewarden { ... }` directive block |
| `nginx` | OpenResty Lua table for `init_by_lua_block` in `nginx.conf` |

---

### 5. Live Gateway Sandbox (`sandbox`)

Test your `routewarden.json` against a real, live gateway container (**Traefik**, **Caddy**, or **NGINX**) without manual setup or deployment.

`rwarden sandbox` automatically generates the native configuration, mounts it into an ephemeral container, binds your specified port, and cleanly terminates on `Ctrl+C`.

::: code-group

```bash [CLI]
# Run Traefik sandbox on localhost:8080
rwarden sandbox --target traefik --config routewarden.json

# Print the generated gateway configuration before launching
rwarden sandbox --target traefik --config routewarden.json --print-config

# Run Caddy sandbox with specific version and port
rwarden sandbox --target caddy --version 2.8.4 --port 9090

# Run NGINX (OpenResty) sandbox
rwarden sandbox --target nginx --port 8080

# Automated test mode: probes live container with test requests, asserts HTTP codes, then exits
rwarden sandbox --target traefik --config routewarden.json --test

# Dry-run: output docker command and generated config without starting container
rwarden sandbox --target caddy --dry-run --print-config

# Test against a specific RouteWarden plugin version/tag/branch
rwarden sandbox --target traefik --plugin-version v1.2.0

# Mount local plugin repository for rapid local plugin testing
rwarden sandbox --target traefik --plugin-path ../traefik-warden
```

```bash [Docker]
# Run Traefik sandbox from within Docker container (mounts docker.sock):
docker run -it --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/routewarden.json:/routewarden.json \
  --net=host \
  ghcr.io/routewarden/cli:latest sandbox --target traefik --config /routewarden.json

# Dry-run from Docker (requires no docker.sock mounting):
docker run --rm -v $(pwd)/routewarden.json:/routewarden.json \
  ghcr.io/routewarden/cli:latest sandbox --target traefik --dry-run --print-config --config /routewarden.json
```

:::

**Available `sandbox` Flags:**

| Flag | Default | Description |
| :--- | :---: | :--- |
| `--target` *(required)* | — | Target gateway: `traefik`, `caddy`, or `nginx` |
| `--config` | `./routewarden.json` | Path to RouteWarden JSON configuration file (or `-` for stdin) |
| `--port` | `8080` | Local port to bind the gateway |
| `--version` | `latest` | Target gateway container image tag (e.g. `v3.3`, `2.11.4`, `alpine`) |
| `--plugin-version` | `""` | RouteWarden plugin version/tag/branch (e.g. `v1.2.0`, `v1.1.0`, `main`) |
| `--plugin-path` | `""` | Local path to RouteWarden plugin directory to mount for development |
| `--print-config`, `-p` | `false` | Print generated gateway config (YAML / Caddyfile / Lua) before running |
| `--test` | `false` | Run automated live HTTP probe assertions against the container and exit |
| `--dry-run` | `false` | Generate config and show docker command without starting container |
| `--detach`, `-d` | `false` | Run container in background and print container ID |

#### Testing Your Sandbox with `curl`

Once your sandbox container is running on port `8080`, test real HTTP requests against it:

```bash
# 1. Direct sensitive file access (should be blocked)
curl -i http://localhost:8080/.env

# 2. Path traversal & double URL encoding evasion (should be blocked)
curl -i http://localhost:8080/static/%252e%252e/.env

# 3. Query string inspection (should be blocked if checkQuery is enabled)
curl -i "http://localhost:8080/search?file=secret.conf"

# 4. Semicolon matrix parameter evasion (should be blocked)
curl -i "http://localhost:8080/app;jsessionid=123/.env"

# 5. Reverse proxy header smuggling (should be blocked if checkHeaders is enabled)
curl -i -H "X-Forwarded-Uri: /.env" http://localhost:8080/api/dashboard

# 6. Legitimate public asset (should pass downstream to upstream)
curl -i http://localhost:8080/robots.txt

# 7. Client IP whitelisting test (simulating a request from whitelisted IP 192.168.1.50)
curl -i -H "X-Forwarded-For: 192.168.1.50" http://localhost:8080/.env
```

::: tip Security Note on Client IP & Reverse Proxies
In local testing and the sandbox, passing `X-Forwarded-For` allows you to simulate requests from whitelisted IPs without reconfiguring your network.

In **production deployments**, edge reverse proxies (Cloudflare, AWS ALB, Traefik, or NGINX) strip or overwrite untrusted client-supplied `X-Forwarded-For` headers with the client's actual TCP socket IP. Ensure your edge gateway is configured to only trust upstream proxy headers from verified addresses (e.g. `trustedIPs` in Traefik, `trusted_proxies` in Caddy, or `set_real_ip_from` in NGINX).
:::

---

### 6. Check CLI Version (`version`)

::: code-group

```bash [CLI]
rwarden version
```

```bash [Docker]
docker run --rm ghcr.io/routewarden/cli:latest version
```

:::

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



