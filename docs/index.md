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

Download standalone, statically compiled binaries for **Linux** (`amd64`, `arm64`), **macOS** (Apple Silicon `arm64` & Intel `amd64`), and **Windows** directly from [GitHub Releases](https://github.com/routewarden/cli/releases/latest).

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
# rwarden version 1.0.0
```

```bash [Docker]
docker run --rm ghcr.io/routewarden/cli:latest version
# rwarden version 1.0.0
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

### 4. Check CLI Version (`version`)

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


