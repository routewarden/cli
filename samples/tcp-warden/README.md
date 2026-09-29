# TCP Warden CLI Dashboard Integration Sample

This sample demonstrates how to connect the **RouteWarden CLI Dashboard** to a running **TCP Warden** L4 proxy & firewall daemon.

---

## Quick Start (Local)

### 1. Start TCP Warden
In a terminal, run TCP Warden with the sample configuration:
```bash
tcp-warden run --config tcp-warden.yaml
```

TCP Warden begins listening on:
- `:9091` — Management & Metrics REST/SSE API
- `:2222` — SSH Guard
- `:5432` — PostgreSQL Bastion
- `:2525` — SMTP Guard
- `:7000` — Generic TCP Proxy

### 2. Launch the RouteWarden Dashboard
In another terminal, run `rwarden dashboard` with the `--tcp-warden` flag:
```bash
rwarden dashboard --tcp-warden http://127.0.0.1:9091
```

Open `http://localhost:9090` in your browser. The dashboard automatically displays:
- **Services Explorer**: View active listeners, live concurrency, allowed vs blocked connections, and throughput.
- **Ban Manager**: Inspect Layer 4 IP bans, add temporary or permanent manual bans, and unban IPs in real-time.
- **Plugins Catalog**: Browse all 14 official RouteWarden protocol plugins, check compatibility, and copy CLI install commands.
- **Live Feed**: Stream L4 security events alongside container HTTP events.

---

## Quick Start (Docker Compose)

To run both services in Docker:
```bash
docker compose up -d
```

Navigate to `http://localhost:9090`.
