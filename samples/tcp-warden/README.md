# TCP Warden Dashboard & Observability Integration Sample

This sample demonstrates how to run **TCP Warden** (Layer 4 proxy & firewall daemon) and visualize security events, blocked connections, and threat metrics in the **RouteWarden Observability Stack** (Grafana, Loki, and Alloy).

---

## Quick Start (Docker Compose)

### 1. Start TCP Warden Container
Run TCP Warden with RouteWarden logging enabled:
```bash
docker compose up -d
```

The container automatically carries the label `routewarden.logs=true`, allowing Grafana Alloy to discover and ingest its structured JSON logs.

### 2. Launch RouteWarden Observability Stack
In your terminal, launch the dashboard:
```bash
rwarden dashboard
```

Open `http://localhost:3000` in your browser. The pre-configured **"RouteWarden — Threat & Security Intelligence"** dashboard displays:
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

# In another terminal, launch the observability dashboard
rwarden dashboard
```

Logs written to `/var/log/routewarden/*.log` or streamed over network UDP syslog (`127.0.0.1:1514`) are automatically collected by Alloy and displayed in Grafana.
