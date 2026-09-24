# RouteWarden Sandbox Samples

This directory provides working, ready-to-test gateway configuration samples for testing with `rwarden sandbox` across all supported targets and formats:

| Format / Gateway | Sample File | Auto-detected Target | Description |
|:---|:---|:---|:---|
| **Traefik (YAML)** | [`traefik/dynamic.yml`](traefik/dynamic.yml) | `traefik` | Standalone Traefik dynamic YAML configuration with router, service, and middleware |
| **Traefik (TOML)** | [`traefik/dynamic.toml`](traefik/dynamic.toml) | `traefik` | Standalone Traefik TOML configuration with table sections and middleware |
| **Docker Compose** | [`traefik/docker-compose.yaml`](traefik/docker-compose.yaml) | `traefik` | Docker Compose service with Traefik label declarations |
| **Caddy** | [`caddy/Caddyfile`](caddy/Caddyfile) | `caddy` | Standalone Caddyfile with `routewarden { ... }` directive block and response handler |
| **NGINX / OpenResty** | [`nginx/nginx.conf`](nginx/nginx.conf) | `nginx` | OpenResty configuration with Lua `resty.routewarden` initialization |
| **Generic JSON** | [`json/routewarden.json`](json/routewarden.json) | User choice | Universal RouteWarden JSON configuration validated against official schema |

---

## Testing Commands

All samples can be tested immediately using `rwarden sandbox`:

### 1. Traefik YAML (`dynamic.yml`)
```bash
# Dry-run inspection
rwarden sandbox --config samples/traefik/dynamic.yml --dry-run --print-config

# Run container & execute automated live HTTP assertions
rwarden sandbox --config samples/traefik/dynamic.yml --test
```

### 2. Traefik TOML (`dynamic.toml`)
```bash
# Dry-run inspection (verifies mounting dynamic.toml)
rwarden sandbox --config samples/traefik/dynamic.toml --dry-run --print-config

# Run container & test live
rwarden sandbox --config samples/traefik/dynamic.toml --test
```

### 3. Docker Compose Labels (`docker-compose.yaml`)
```bash
# Dry-run inspection (verifies label parsing & translation to dynamic YAML)
rwarden sandbox --config samples/traefik/docker-compose.yaml --dry-run --print-config

# Run container & test live with custom probe path
rwarden sandbox --config samples/traefik/docker-compose.yaml --test --probe-path "/backup/secret.sql"
```

### 4. Inline Labels
```bash
rwarden sandbox \
  --labels "traefik.http.middlewares.shield.plugin.routewarden.enabled=true,traefik.http.middlewares.shield.plugin.routewarden.response.statusCode=403" \
  --dry-run \
  --print-config
```

### 5. Caddyfile (`Caddyfile`)
```bash
# Dry-run inspection
rwarden sandbox --config samples/caddy/Caddyfile --dry-run --print-config

# Run container & test live
rwarden sandbox --config samples/caddy/Caddyfile --test
```

### 6. NGINX / OpenResty (`nginx.conf`)
```bash
# Dry-run inspection
rwarden sandbox --config samples/nginx/nginx.conf --dry-run --print-config

# Run container & test live
rwarden sandbox --config samples/nginx/nginx.conf --test
```

### 7. Universal JSON (`routewarden.json`)
```bash
# Synthesize Traefik config
rwarden sandbox --target traefik --config samples/json/routewarden.json --dry-run --print-config

# Synthesize Caddy config
rwarden sandbox --target caddy --config samples/json/routewarden.json --dry-run --print-config

# Synthesize NGINX config
rwarden sandbox --target nginx --config samples/json/routewarden.json --dry-run --print-config
```

---

## Testing via Docker Container

If running `rwarden` via Docker image (`ghcr.io/routewarden/cli`), mount `/var/run/docker.sock` and the sample file:

```bash
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/samples/traefik/dynamic.toml:/config/dynamic.toml:ro \
  -p 8080:8080 \
  ghcr.io/routewarden/cli:latest sandbox --config /config/dynamic.toml --test
```
