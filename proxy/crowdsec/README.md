# CrowdSec Integration for TCP Warden

This directory provides official CrowdSec parsers, scenarios, and acquisition configuration for **TCP Warden**.

## Architecture

```
[Attacker] ──► [tcp-warden] (L4 Reverse Proxy) ──► writes /var/log/routewarden/tcp-warden.jsonl
                     │                                           │
                     │                                           ▼
                     │                                   [CrowdSec Engine]
                     │                                   • acquis.yaml
                     │                                   • routewarden-tcp-warden.yaml (parser)
                     │                                   • Scenarios (ssh-bf, smtp-bf, portscan)
                     │                                           │
                     ▼                                           ▼
              [Live Decisions] ◄────── GET /v1/decisions ── [Local API (LAPI)]
```

## Quick Start

### 1. Register Bouncer with CrowdSec LAPI
```bash
sudo cscli bouncers add routewarden-tcp-warden
```
Copy the generated API key.

### 2. Install Parser and Scenarios
```bash
sudo cp parsers/s01-parse/routewarden-tcp-warden.yaml /etc/crowdsec/parsers/s01-parse/
sudo cp scenarios/*.yaml /etc/crowdsec/scenarios/
sudo cp acquis.yaml /etc/crowdsec/acquis.d/routewarden-tcp-warden.yaml
sudo systemctl reload crowdsec
```

### 3. Enable in `tcp-warden.yaml`
```yaml
crowdsec:
  enabled: true
  lapi_url: "http://127.0.0.1:8080"
  api_key: "${CROWDSEC_API_KEY}"
  update_frequency: "10s"
```
