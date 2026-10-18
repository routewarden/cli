# TCP Warden Security Dashboard Integration Sample

This sample demonstrates how to run **TCP Warden** (Layer 4 proxy & firewall daemon) and visualize security events, blocked connections, and threat metrics in the **RouteWarden Security Dashboard**.

---

## Quick Start (Docker Compose)

### 1. Start TCP Warden Container
Run TCP Warden with RouteWarden logging enabled:
```bash
docker compose up -d
```

The container automatically carries the label `routewarden.logs=true`, allowing `rwarden dashboard` to discover and ingest its structured JSON logs.

### 2. Launch RouteWarden Security Dashboard
In your terminal, launch the dashboard:
```bash
rwarden dashboard
```

Open `http://localhost:7890` in your browser. The live SOC dashboard displays:
- **L4 Security Events**: Blocked connections, brute force attempts, port sweeps, and rate limit triggers.
- **Service Breakdown**: Multi-protocol correlation for SSH, PostgreSQL, SMTP, DNS, and generic TCP/UDP.
- **Top Offender IPs**: Top hostile client IPs attempting to breach your Layer 4 bastions, enriched with GeoIP flags.
- **Live Event Feed**: Real-time log stream with severity badges and detailed connection metadata.

---

## Quick Start (Local Binary)

If running TCP Warden locally as a host service:
```bash
# Start TCP Warden daemon
tcp-warden run --config tcp-warden.yaml

# In another terminal, launch the security dashboard
rwarden dashboard
```

Logs written to `/var/log/routewarden/*.log` or streamed from labeled containers are automatically aggregated and displayed at `http://localhost:7890`.
