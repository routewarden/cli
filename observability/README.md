# RouteWarden Native SOC Security Dashboard & Observability Engine

Turnkey, zero-dependency, real-time security dashboard powered by RouteWarden's embedded Go server and SQLite persistence. Consumes only **~8MB of RAM** with zero external daemons or heavy monitoring stacks required.

---

## Quickstart

### 1. Launch via CLI (Recommended)
```bash
# Auto-discovers all containers with label 'routewarden=true' or 'routewarden.logs=true'
rwarden dashboard

# Or specify a custom port or monitor a specific access log file
rwarden dashboard up --port 7890
rwarden dashboard up --file /var/log/nginx/access.log
rwarden dashboard up --no-open
```

Open your browser to:
👉 **`http://localhost:7890`**

### 2. Standalone Docker Compose Deployment
```bash
# Export configuration and assets
rwarden dashboard export ./dashboard
cd ./dashboard

# Launch container stack
docker compose up -d
```

---

## Core Capabilities

### 1. Embedded SQLite Telemetry Persistence
- **Zero-Latency Batching**: Ingested events are buffered and written asynchronously in transactions every 200ms or 100 events.
- **WAL Mode**: Uses Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) with `synchronous=NORMAL` for concurrent, non-blocking reads and writes.
- **Crash & Restart Survival**: On restart, recent events and threat telemetry are preloaded from `~/.routewarden/dashboard/events.db` so historical metrics remain intact.
- **Auto-Pruning Retention**: Automatically deletes telemetry older than 30 days (`PruneOlderThan(30)`) to maintain a lean storage footprint (~10–30 MB).
- **Log Query API**: Accessible via `GET /api/logs?start=...&end=...&verdict=...&ip=...&limit=250`.

### 2. Live Security Operations Log Stream (`stream.audit.live`)
- **Real-Time SSE Streaming**: Live event broadcast via Server-Sent Events (`/api/stream`) with sub-millisecond dispatch.
- **Verdict Filtering**: One-click tabs for `ALL`, `BLOCK` (🛑), `TARPIT` (⏳), and `ALLOW` (🛡️).
- **Time Range Filtering**: Fast rolling window selector (`1m`, `5m`, `15m`, `30m`, `Custom Date Range`).
- **Interactive Search**: Grep across IPs, paths, rules, and countries with live active chip badges.
- **Stream Pause / Resume**:
  - Click **⏸ Pause** or press <kbd>Space</kbd> to freeze the table view for log inspection.
  - Incoming logs are buffered with a live counter badge (`⏸ PAUSED (+N new)`).
  - Background stats polling suspends while paused to prevent dashboard shift.
  - Clicking **▶ Resume** instantly catches up and displays buffered events.

### 3. Threat Intelligence & Attacker Hotspots
- **Top Attacking Client IPs**: Highlights repeat offenders with a threat breakdown bar showing Block vs. Tarpit ratios.
- **IP Threat Intelligence Modal**: Clicking any client IP opens a dossier showing reverse DNS, autonomous system (ASN), country origin, CIDR prefix, and direct one-click AbuseIPDB lookup.
- **Top Probed Target Paths**: Real-time counter of attacker reconnaissance (`/.env`, `/.git`, `/wp-admin`, `actuator/env`).
- **HTTP Status Codes**: Visual breakdown of HTTP 200, 403 Forbidden, 429 Tarpit, and 5xx errors.

### 4. Global Threat Geography & Autonomous Country Engine
- **Interactive Leaflet World Map**: Visualizes geographical distribution of attacks with country pins and density heat.
- **Autonomous Country Resolution**: High-speed offline resolver using built-in CIDR & RIR databases, with automatic MaxMind GeoLite2 database auto-discovery if present.

### 5. Encrypted Remote Node Ingestion
- Accepts remote encrypted log streams from edge servers via `rwarden push` using **X25519 + ChaCha20-Poly1305** zero-knowledge encryption (`/api/v1/events`).

---

## Keyboard Shortcuts

| Shortcut | Action |
|:---|:---|
| <kbd>Space</kbd> | Toggle Stream Pause / Resume |
| <kbd>T</kbd> | Toggle Theme (System / Light / Dark) |
| <kbd>W</kbd> | Focus Time Range filter |
| <kbd>/</kbd> | Focus Search / Grep input |
| <kbd>F</kbd> | Focus Country filter dropdown |
| <kbd>R</kbd> | Reset all active filters |
| <kbd>ESC</kbd> | Close IP dossier or event detail modal |

---

## API Endpoints

| Endpoint | Method | Description |
|:---|:---|:---|
| `/` | `GET` | Native SOC Security Dashboard HTML UI |
| `/api/stats` | `GET` | Real-time threat KPIs, timeline, and top attacker metrics |
| `/api/logs` | `GET` | Query SQLite persisted logs with date range and filter parameters |
| `/api/stream` | `GET` | Server-Sent Events (SSE) live telemetry stream |
| `/api/ip-lookup` | `GET` | IP geolocation and threat intelligence lookup (`?ip=...`) |
| `/api/sources` | `GET` | Status of discovered containers and remote nodes |
| `/api/v1/pubkey` | `GET` | Public key for X25519 encrypted log ingestion |
| `/api/v1/events` | `POST` | Ingest encrypted logs from remote `rwarden push` nodes |
