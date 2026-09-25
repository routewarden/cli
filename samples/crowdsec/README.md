# CrowdSec Integration for RouteWarden Guard

This directory provides ready-to-use CrowdSec parsers, scenarios, and acquisition configuration for **RouteWarden Guard (`rwarden guard`)**.

---

## Architecture Overview

```
                            ┌──────────────────────────────────────────────┐
                            │            RouteWarden Guard Daemon          │
                            │                                              │
                            │  1. Check in-memory CrowdSec decision cache  │
                            │  2. Fast L4 TCP Proxy (SSH/SMTP/POP3/IMAP)   │
                            │  3. Emit JSON events to file                 │
                            └───────────────────────┬──────────────────────┘
                                                    │
                                                    │ writes /var/log/rwarden/guard.jsonl
                                                    ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CrowdSec Engine Stack                                │
│                                                                                        │
│   [acquis.yaml]  ──────► [routewarden-guard.yaml] ──────► [Scenarios]                  │
│   Reads guard.jsonl       Extracts IP, service, reason    • guard-ssh-bf.yaml          │
│                                                           • guard-smtp-bf.yaml         │
│                                                           • guard-portscan.yaml        │
│                                                                  │                     │
│                                                                  ▼                     │
│   [rwarden guard] ◄────────────────────────────────── [Local API (LAPI)]               │
│   Refreshes decision cache every 15s                   Creates ban / remediation       │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Setup (5 Steps)

### 1. Install CrowdSec
Follow the official instructions at [doc.crowdsec.net](https://doc.crowdsec.net/):

```bash
# Debian / Ubuntu
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
sudo apt install crowdsec
```

### 2. Generate a Bouncer API Key for Guard
```bash
sudo cscli bouncers add routewarden-guard
```
Copy the generated API key (e.g. `guard-bouncer-secret-key`).

### 3. Copy Parser, Scenarios, and Acquisition Config
```bash
# Parser
sudo cp parsers/s01-parse/routewarden-guard.yaml /etc/crowdsec/parsers/s01-parse/

# Scenarios
sudo cp scenarios/*.yaml /etc/crowdsec/scenarios/

# Acquisition
sudo cp acquis.yaml /etc/crowdsec/acquis.d/routewarden-guard.yaml

# Reload CrowdSec
sudo systemctl reload crowdsec
```

### 4. Configure `netguard.json`
Enable CrowdSec in your `netguard.json`:

```json
{
  "crowdsec": {
    "enabled": true,
    "lapiUrl": "http://127.0.0.1:8080",
    "apiKey": "<YOUR_GENERATED_API_KEY>",
    "updateIntervalSeconds": 15
  },
  "global": {
    "logFile": "/var/log/rwarden/guard.jsonl"
  }
}
```

### 5. Start Guard Daemon
```bash
rwarden guard --config netguard.json
```

Verify status:
```bash
rwarden guard status --api http://127.0.0.1:9091
```

Expected output:
```text
🛡️  RouteWarden Guard Status:
   Status:      healthy
   CrowdSec:    connected=true (cached decisions: 42)
```
