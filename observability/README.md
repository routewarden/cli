# RouteWarden Lightweight Security Dashboard (GoAccess)

Turnkey, real-time security dashboard powered by [GoAccess](https://goaccess.io/) and `rwarden monitor`. Replaces heavy multi-container monitoring stacks (Grafana + Loki + Alloy) with an instantaneous, in-memory dashboard consuming **~15MB of RAM**.

## Quickstart

### 1. Launch via CLI (Recommended)
```bash
# Auto-discovers all containers with label 'routewarden=true'
rwarden dashboard

# Or specify a custom port or log file
rwarden dashboard up --port 7890
rwarden dashboard up --file /var/log/nginx/access.log
```

Open your browser to:
👉 **`http://localhost:7890`**

### 2. Standalone Docker Compose Deployment
```bash
# Export configuration
rwarden dashboard export ./dashboard

# Launch container
cd ./dashboard
docker compose up -d
```

### 3. Piping Directly from CLI
```bash
# Stream from auto-discovered Docker containers straight into GoAccess
rwarden monitor --raw | goaccess --config-file=./goaccess.conf -
```

## Features
- **Ultra-lightweight**: ~15 MB RAM, sub-second startup
- **Live WebSocket streaming**: Real-time traffic, threat statistics, and HTTP status codes
- **GeoIP Threat Geography**: Integrated client IP locations and top offending countries
- **Target Attack Paths**: Real-time tracking of probed endpoints (`/.env`, `/.git`, `/wp-login.php`)
- **Zero Configuration**: Auto-discovers containers labeled `routewarden=true`
