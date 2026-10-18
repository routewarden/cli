# RouteWarden Native SOC Security Dashboard & Observability Engine

Turnkey, zero-dependency, real-time security dashboard powered by RouteWarden's embedded Go server and SQLite persistence. Consumes only **~8MB of RAM** with zero external daemons or heavy monitoring stacks required.

---

## Quickstart

### 1. Launch via CLI (Recommended)
```bash
# Auto-discovers all containers with label 'routewarden=true' or 'routewarden.logs=true'
rwarden dashboard

# Protect dashboard with HTTP Basic Auth
rwarden dashboard up --auth admin:supersecret

# Bind to custom interface and port
rwarden dashboard up --host 127.0.0.1 --port 7890 --auth admin:supersecret
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
- **Node & Source Filtering**: Dedicated `📡 All Nodes` selector dynamically populated from discovered Docker containers and remote encrypted nodes.
- **Verdict Filtering**: One-click tabs for `ALL`, `BLOCK` (🛑), `TARPIT` (⏳), and `ALLOW` (🛡️).
- **Time Range Filtering**: Fast rolling window selector (`1m`, `5m`, `15m`, `30m`, `Custom Date Range`).
- **Interactive Search**: Grep across IPs, paths, rules, and countries with live active chip badges.
- **Server-Side Pagination**: Navigate historical events with page controls and jump-to-page input (`page` and `limit` query support in `/api/logs`).
- **Stream Pause / Resume**:
  - Click **⏸ Pause** or press <kbd>Space</kbd> to freeze the table view for log inspection.
  - Incoming logs are buffered with a live counter badge (`⏸ PAUSED (+N new)`).
  - Background stats polling suspends while paused to prevent dashboard shift.
  - Clicking **▶ Resume** instantly catches up and displays buffered events.

### 3. Password Protection & Dedicated Cyber Auth Screen
- **Custom Cyber Login Screen**: Web browser requests to `http://localhost:7890` without credentials automatically present a cyber-styled login screen (`/login`) featuring the RouteWarden brand icon, username & access key fields, visibility toggle, and error states.
- **Session Cookie Authentication**: Successful login sets an encrypted session cookie (`routewarden_auth`) with 30-day persistence.
- **Header Sign Out**: Operators can terminate sessions at any time via the **🚪 Sign Out** button in the dashboard header.
- **Flexible Auth Verification**: Supports HTTP Basic Auth (`Authorization: Basic <base64>`), Bearer tokens (`Authorization: Bearer <token>`), session cookies, and browser query tokens (`?token=<token>`).
- **Whitelisted Ingestion**: Zero-knowledge encrypted remote ingestion endpoints (`/api/v1/pubkey` and `/api/v1/events`) remain open for edge forwarders.
- **Status Indicator**: Security status badge (`🔒 AUTH: <username>`) rendered in the dashboard header indicating active access control.

### 4. Mobile & Tablet Optimization
- **Responsive Layout (< 768px & < 480px)**: 36–44px touch targets and viewport-fit formatting.
- **Compact 2-Column KPI Grid**: Displays all critical security indicators (Blocks, Tarpits, Total Events, EPS) cleanly on phones.
- **Mobile Cyber Hero**: Automatically swaps the large desktop ASCII banner for a clean, branded mobile hero header on smaller screens.
- **Touch-Optimized Filters & Search**: Full-width search bar and grid-based filter dropdowns with 16px inputs to prevent iOS auto-zooming.
- **Mobile Bottom-Sheet Modals**: IP Threat Dossiers and Event Detail inspectors transition to bottom sheets on mobile devices.
- **Auto-Hiding Desktop Shortcuts**: The fixed bottom keyboard shortcut bar automatically hides on touch devices.

### 5. Threat Intelligence & Attacker Hotspots
- **Top Attacking Client IPs**: Highlights repeat offenders with a threat breakdown bar showing Block vs. Tarpit ratios.
- **IP Threat Intelligence Modal**: Clicking any client IP opens a dossier showing reverse DNS, autonomous system (ASN), country origin, CIDR prefix, and direct one-click AbuseIPDB lookup.
- **Top Probed Target Paths**: Real-time counter of attacker reconnaissance (`/.env`, `/.git`, `/wp-admin`, `actuator/env`).
- **HTTP Status Codes**: Visual breakdown of HTTP 200, 403 Forbidden, 429 Tarpit, and 5xx errors.

### 6. Global Threat Geography & Autonomous Country Engine
- **Interactive Leaflet World Map**: Visualizes geographical distribution of attacks with country pins and density heat.
- **Autonomous Country Resolution**: High-speed offline resolver using built-in CIDR & RIR databases, with automatic MaxMind GeoLite2 database auto-discovery if present.

### 7. Encrypted Remote Node Ingestion
- Accepts remote encrypted log streams from edge servers via `rwarden push` using **X25519 + ChaCha20-Poly1305** zero-knowledge encryption (`/api/v1/events`).

---

## Keyboard Shortcuts (Desktop)

| Shortcut | Action |
|:---|:---|
| <kbd>Space</kbd> | Toggle Stream Pause / Resume |
| <kbd>[</kbd> | Previous Log Page |
| <kbd>]</kbd> | Next Log Page |
| <kbd>T</kbd> | Toggle Theme (System / Light / Dark) |
| <kbd>W</kbd> | Focus Time Range filter |
| <kbd>/</kbd> | Focus Search / Grep input |
| <kbd>F</kbd> | Focus Country filter dropdown |
| <kbd>R</kbd> | Reset all active filters |
| <kbd>ESC</kbd> | Close IP dossier or event detail modal |

---

## API Endpoints

> [!NOTE]
> When `--auth` is enabled, all UI and telemetry endpoints require authentication (`Authorization: Basic`, cookie, or `?token=...`). Encrypted remote ingestion endpoints remain accessible to edge forwarders using X25519 authentication.

| Endpoint | Method | Description | Auth Required (when enabled) |
|:---|:---|:---|:---:|
| `/` | `GET` | Native SOC Security Dashboard HTML UI (redirects to `/login` if unauthenticated in browser) | Yes |
| `/login` | `GET` | Custom Cyber Authentication Screen | No (Public) |
| `/logout` | `GET` | Clear session cookie and redirect to `/login` | No (Public) |
| `/api/auth/login` | `POST` | Authenticate credentials and issue session cookie | No (Public) |
| `/api/auth/logout` | `POST` | Invalidate dashboard session cookie | No (Public) |
| `/api/stats` | `GET` | Real-time threat KPIs, timeline, and top attacker metrics | Yes |
| `/api/logs` | `GET` | Query SQLite persisted logs with pagination, date range, node, and filter parameters | Yes |
| `/api/stream` | `GET` | Server-Sent Events (SSE) live telemetry stream | Yes |
| `/api/ip-lookup` | `GET` | IP geolocation and threat intelligence lookup (`?ip=...`) | Yes |
| `/api/sources` | `GET` | Status of discovered containers and remote nodes | Yes |
| `/api/v1/pubkey` | `GET` | Public key for X25519 encrypted log ingestion | No (Whitelisted) |
| `/api/v1/events` | `POST` | Ingest encrypted logs from remote `rwarden push` nodes | No (Whitelisted) |
