# Enterprise Detection & Response Agent — SOC Lab

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![100% Open Source](https://img.shields.io/badge/Open%20Source-100%25-brightgreen)](.)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL2%20%7C%20macOS-lightgrey)](.)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-blueviolet)](CONTRIBUTING.md)

> A hands-on, fully open-source Security Operations Center lab running 28+ production-grade tools via Docker Compose. Built for SOC Level 2/3 analyst training, blue team skill development, and adversary emulation — all on a single machine.

**Author:** Debasish Lenka  
**Stack:** 28+ tools · 100% free · MITRE ATT&CK v14 · Docker Compose  
**Minimum:** 16 GB RAM · 50 GB disk · Linux / WSL2 / macOS

---

## Screenshots

### Command Center Portal
![SOC Lab Portal](dashboards/screenshots/00_portal.png)

### SOC Overview — Live Alert Feed
![SOC Overview](dashboards/screenshots/01_soc_overview.png)

### OpenSearch SIEM — 24h Event Timeline
![OpenSearch SIEM](dashboards/screenshots/02_opensearch_siem.png)

### Zeek NSM — Network Traffic Analysis
![Zeek Network](dashboards/screenshots/03_zeek_network.png)

### Suricata IDS — EVE JSON Alert Feed
![Suricata IDS](dashboards/screenshots/04_suricata_ids.png)

### AI Agents — CrewAI Threat Analysis
![AI Agents](dashboards/screenshots/05_ai_agents.png)

### DFIR-IRIS — Case Management & Attack Timeline
![DFIR-IRIS](dashboards/screenshots/06_iris_cases.png)

### MITRE Caldera — Adversary Emulation
![Caldera](dashboards/screenshots/07_caldera_attack.png)

### MISP — Threat Intelligence Platform
![MISP](dashboards/screenshots/08_misp_ti.png)

### Velociraptor — Live Forensics & DFIR
![Velociraptor](dashboards/screenshots/09_velociraptor.png)

### Red Team — Responder + LLMNR Poisoning
![Red Team](dashboards/screenshots/10_responder_redteam.png)

### File Integrity — Endpoint FIM, No Agent Required
![File Integrity](dashboards/screenshots/11_file_integrity.png)

---

## Overview

The Advanced SOC Lab v2.0 is a complete, self-contained security operations environment designed for hands-on learning. Every component is open-source and orchestrated with Docker Compose, so you can spin up a full SOC stack in under 15 minutes.

### What You Get

| Layer | Tool | Purpose |
|---|---|---|
| **SIEM** | OpenSearch 2.13 + Dashboards | Log ingestion, search, visualization |
| **Log Pipeline** | Vector 0.38 | Unified log routing and transformation |
| **Detection** | ElastAlert2 | Rule-based alerting from OpenSearch |
| **Network NSM** | Zeek 6.0 + Suricata 7.0 | Packet-level network security monitoring — Suricata supports optional inline IPS (auto-block) mode, see below |
| **SOAR** | StackStorm 3.8 | Automated response playbooks |
| **Case Mgmt** | DFIR-IRIS 2.4 | Incident tracking, timelines, IOCs |
| **Threat Intel** | MISP | IOC sharing, feeds, attribution |
| **DFIR** | Velociraptor | Live forensics, VQL hunting |
| **Attack Sim** | MITRE Caldera 5.x | Adversary emulation, ATT&CK mapping |
| **Red Team** | Responder | LLMNR/NBT-NS poisoning (lab profile) |
| **AI Analysis** | Ollama + CrewAI | LLM-powered SOC agents |
| **File Integrity** | Native PowerShell watcher (no agent) | Endpoint file created/modified/renamed/moved/deleted tracking, AD-user attribution, ZIP restore |
| **EDR** | Wazuh 4.7.5 | Host-based log analysis, active response, CVE vulnerability detection — push-only agent, no new inbound ports on endpoints |

### Detection Rules (16 Sigma + 9 ElastAlert2 built-in)

| Rule | Technique | Severity |
|---|---|---|
| Brute Force / Password Spray | T1110.001 | High |
| LSASS Memory Dump | T1003.001 | Critical |
| PowerShell Encoded Command | T1059.001 | High |
| Lateral Movement via SMB | T1021.002 | Critical |
| LLMNR/NBT-NS Poisoning | T1557.001 | High |
| Scheduled Task Creation | T1053.005 | Medium |
| Registry Run Key Persistence | T1547.001 | Medium |
| DNS Tunneling C2 | T1071.004 | High |
| Pass-the-Hash | T1550.002 | Critical |
| Network Port Scan | T1046 | Medium |
| Data Exfiltration over C2 | T1041 | Critical |
| Defender Disabled | T1562.001 | Critical |
| WMI Execution | T1047 | Medium |
| Spearphishing Attachment | T1566.001 | High |
| Bulk File Collection | T1039 | Medium |
| After-Hours Account Login | T1078 | Medium |

### AI Agents

| Agent | Role | Capability |
|---|---|---|
| Threat Analyst | APT attribution, TTP mapping | Correlates IOCs with threat actors |
| Incident Responder | Triage and containment | Generates response playbooks |
| Threat Hunter | Proactive hunting | Builds VQL queries from hypotheses |
| Detection Engineer | Rule creation | Writes ElastAlert2 and Sigma rules |

---

## Architecture

```
Internet / Lab Network
        │
   ┌────▼─────────────────────────────────────────────┐
   │              Docker Compose Network               │
   │                                                   │
   │  ┌──────────┐  ┌──────────┐  ┌────────────────┐  │
   │  │  Zeek    │  │ Suricata │  │  Log Sources   │  │
   │  │ (NSM)    │  │ (IDS)    │  │  Sysmon/Win    │  │
   │  └────┬─────┘  └────┬─────┘  └───────┬────────┘  │
   │       └─────────────┴────────────────┘           │
   │                     │ Vector 0.38                 │
   │               ┌─────▼──────┐                      │
   │               │ OpenSearch │◄─── ElastAlert2      │
   │               │  (SIEM)    │                      │
   │               └─────┬──────┘                      │
   │                     │                             │
   │        ┌────────────┼────────────┐                │
   │        ▼            ▼            ▼                │
   │   StackStorm    DFIR-IRIS      MISP               │
   │   (SOAR)       (Cases)        (Threat Intel)      │
   │        │            │            │                │
   │        └────────────┴────────────┘                │
   │                     │                             │
   │              ┌──────▼──────┐                      │
   │              │  AI Agents  │                      │
   │              │ Ollama/Crew │                      │
   │              └─────────────┘                      │
   │                                                   │
   │  ┌──────────────┐   ┌──────────────┐              │
   │  │    Caldera   │   │  Velociraptor│              │
   │  │  (Attack Sim)│   │    (DFIR)    │              │
   │  └──────────────┘   └──────────────┘              │
   └───────────────────────────────────────────────────┘
```

---

## Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| RAM | 14 GB | 16–32 GB |
| Disk | 30 GB | 50 GB |
| CPU | 4 cores | 8 cores |
| OS | Ubuntu 22.04 / Debian 12 / WSL2 | Ubuntu 22.04 LTS |
| Docker | 24.x | Latest |
| Docker Compose | v2.x | Latest |

---

## Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/debasish-lenka/Enterprise-Detection-Response-Agent-SOC.git
cd Enterprise-Detection-Response-Agent-SOC
```

### Step 2 — Make Scripts Executable

```bash
chmod +x setup.sh health-check.sh simulate-attack.sh
```

### Step 3 — Run the Setup Script

The setup script handles everything: environment config, kernel tuning, Docker image pulls, and staged service deployment.

```bash
sudo ./setup.sh
```

The script runs in 4 stages:

```
── Stage 1/4 — Core infrastructure (OpenSearch, Vector) ──
── Stage 2/4 — Security tools (MISP, IRIS, Velociraptor) ──
── Stage 3/4 — SOAR + Detection (StackStorm, ElastAlert2) ──
── Stage 4/4 — AI agents + Attack simulation (Ollama, Caldera) ──
```

> **First run:** Ollama downloads `llama3.2:3b` (~2 GB). Total setup time: 10–20 minutes depending on internet speed.

### Step 4 — Verify All Services Are Healthy

```bash
./health-check.sh
```

Expected output:

```
  Advanced SOC Lab v2.0 — Health Check

  Core Infrastructure
  ✔  OpenSearch         cluster:green · 0 documents
  ✔  OpenSearch Node 1  container running
  ✔  OpenSearch Node 2  container running
  ✔  OpenSearch Dashboards  HTTP 200
  ✔  Vector Pipeline    container running

  Security Tools
  ✔  DFIR-IRIS          HTTP 200
  ✔  MISP               HTTP 200
  ✔  Velociraptor       HTTP 200
  ✔  StackStorm         HTTP 200
  ✔  ElastAlert2        container running

  Attack Simulation & AI
  ✔  MITRE Caldera      HTTP 200
  ✔  AI Agents API      HTTP 200
  ✔  Ollama LLM         HTTP 200
  ✔  WebSocket Streamer container running

  Results: 14 passed  0 failed  1 warnings  (15 checks)
  All critical services healthy.
```

### Step 5 — Open the Dashboard Portal

Open `dashboards/index.html` in your browser. All 11 dashboards are accessible from the portal.

---

## Configuration

### Environment Variables

Credentials are auto-generated by `setup.sh` into `.env`. Review and customize before use:

```bash
cat .env
```

Key variables:

| Variable | Default | Description |
|---|---|---|
| `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | auto-generated | OpenSearch admin password |
| `IRIS_SECRET_KEY` | auto-generated | DFIR-IRIS Flask secret |
| `IRIS_ADMIN_PASSWORD` | auto-generated | DFIR-IRIS admin password |
| `MISP_ADMIN_PASSWORD` | auto-generated | MISP admin password |
| `CALDERA_API_KEY_RED` | auto-generated | Caldera red team API key |
| `CALDERA_API_KEY_BLUE` | auto-generated | Caldera blue team API key |
| `CALDERA_RED_PASS` | `changeme` | Caldera red team password |
| `CALDERA_BLUE_PASS` | `changeme` | Caldera blue team password |
| `ST2_AUTH_TOKEN` | auto-generated | StackStorm auth token |

> **Important:** Change `CALDERA_RED_PASS` and `CALDERA_BLUE_PASS` before deploying.

### Kernel Parameters

OpenSearch requires a higher memory map limit. The setup script applies this automatically:

```bash
sudo sysctl -w vm.max_map_count=262144

# Make permanent
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Endpoint Agent Installation

**Windows (PowerShell — run as Administrator):**

```powershell
# Install Velociraptor agent
$url = "http://YOUR_LAB_IP:8889/api/v1/GetFile?name=velociraptor-agent-windows.exe"
Invoke-WebRequest -Uri $url -OutFile "velociraptor-agent.exe"
.\velociraptor-agent.exe --config agent.config.yaml service install

# Install Sysmon for detailed process logging
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath Sysmon
.\Sysmon\Sysmon64.exe -accepteula -i config/sysmon/sysmon-config.xml
```

**Linux:**

```bash
# Install Velociraptor agent
curl -L http://YOUR_LAB_IP:8889/api/v1/GetFile?name=velociraptor-agent-linux \
  -o velociraptor-agent
chmod +x velociraptor-agent
sudo ./velociraptor-agent --config agent.config.yaml service install
```

---

## Running Attack Simulations

The `simulate-attack.sh` script injects realistic MITRE ATT&CK events directly into OpenSearch for analyst training.

### APT-29 Kill Chain (13 Techniques)

```bash
./simulate-attack.sh apt29
```

Injects events for: T1566.001 → T1059.001 → T1053.005 → T1547.001 → T1003.001 → T1110.001 → T1557.001 → T1021.002 → T1550.002 → T1046 → T1041 → T1071.004 → T1562.001

### Brute Force / Password Spray

```bash
./simulate-attack.sh bruteforce
```

Simulates password spray across 12 accounts with account lockout events.

### Insider Threat

```bash
./simulate-attack.sh insider
```

Simulates bulk file collection, cloud upload exfiltration, and log deletion.

### Run All Scenarios

```bash
./simulate-attack.sh all
```

### Verify Events Were Indexed

```bash
./simulate-attack.sh verify
```

---

## Service URLs

> ⚠️ **SECURITY — Change ALL default passwords before starting any service.**  
> Run `grep -n "changeme\|admin" .env` to find every default credential.  
> Never expose any lab port to the internet with default credentials.

| Service | URL | Credentials |
|---|---|---|
| **Dashboard Portal** | http://localhost | — |
| **OpenSearch Dashboards** | http://localhost:5601 | admin / `$OPENSEARCH_INITIAL_ADMIN_PASSWORD` |
| **DFIR-IRIS** | https://localhost:8443 | administrator / `$IRIS_ADMIN_PASSWORD` |
| **MITRE Caldera** | http://localhost:8888 | red / `$CALDERA_RED_PASS` |
| **Velociraptor** | http://localhost:8889 | admin / `changeme` |
| **MISP** | http://localhost:8080 | admin@soc.lab / `$MISP_ADMIN_PASSWORD` |
| **StackStorm** | http://localhost:9101 | st2admin / `$ST2_AUTH_TOKEN` |
| **AI Agents API** | http://localhost:8500/docs | — |
| **Ollama** | http://localhost:11434 | — |
| **OpenSearch API** | http://localhost:9200 | admin / `$OPENSEARCH_INITIAL_ADMIN_PASSWORD` |

---

## Optional: Red Team Profile

The Responder container (LLMNR/NBT-NS poisoning) is disabled by default. Start it only on an isolated lab network:

```bash
# Start red team profile
docker compose --profile redteam up -d

# Stop red team profile
docker compose --profile redteam down
```

> **Warning:** Never run Responder on a production network or any network without explicit written authorization. Lab network only.

---

## Optional: Suricata IPS (Inline Blocking) Mode

By default Suricata runs as a passive IDS — it alerts, it never blocks. Set `SURICATA_IPS_MODE=true`
in `.env` and restart the container to switch it to inline IPS mode, where it actually drops matching
traffic instead of just logging it:

```bash
# .env
SURICATA_IPS_MODE=true

docker compose up -d --build suricata
```

**How it works:** the container redirects host traffic through an NFQUEUE (`iptables ... -j NFQUEUE
--queue-num 0 --queue-bypass`) and Suricata inspects it inline. `--queue-bypass` (plus `fail-open: yes`
in `suricata.yaml`) means that if Suricata crashes or its queue backs up, traffic **passes through
unfiltered** rather than the whole network going dark — see `config/suricata/entrypoint.sh`.

**What actually gets blocked:** only 4 of the 5 custom rules in
`detection-rules/suricata/soc_custom.rules` are set to `drop` (PowerShell download cradle, Cobalt
Strike beacon pattern, inside→outside port scanning, SSH brute force) — chosen because they're
low-false-positive, specific signatures. The LLMNR/Responder detection rule is deliberately left as
`alert`-only even in IPS mode, since it fires on a normal Windows broadcast protocol and blocking it
network-wide would break legitimate name resolution — see the comment above that rule for the
reasoning. In plain IDS mode, `drop` rules behave exactly like `alert` (Suricata can't block without
being inline), so leaving IPS mode off is always safe.

> **Warning:** IPS mode changes real network behavior. Test in a lab/isolated network first, and confirm
> the 4 `drop` rules match what you actually want blocked before enabling this anywhere that matters.

---

## Wazuh EDR — Connected to the Org's Real Wazuh (siem.dbi360.com)

This is no longer a lab-only exercise — Wazuh is the org's real, production EC2-hosted
deployment. The local `standalone-wazuh` manager this lab used to run was fully retired
(2026-09-16) once that real deployment came online; there is no local Wazuh service anymore.

```bash
# .env
WAZUH_INDEXER_URL=https://<indexer-host-or-private-ip>:9200
WAZUH_INDEXER_USER=<indexer username>
WAZUH_INDEXER_PASSWORD=<indexer password>

docker compose --profile remote-wazuh up -d --build
```

`wazuh-remote-connector/poller.py` polls the remote Wazuh **indexer's** `_search` API every 30s
(`WAZUH_POLL_INTERVAL_SECS`) for new documents in `wazuh-alerts-*`, and forwards each one into this
lab's Vector, which indexes it into `soc-logs-*` (filter `log_type: wazuh-remote`).

**Why polling instead of pushing:** most remote Wazuh deployments correctly expose only the
dashboard (443) to the internet and keep the indexer (9200), manager API (55000), and agent ports
(1514/1515) internal-only for security — this lab confirmed exactly that pattern when testing
against a real EC2-hosted instance. Polling only needs *this lab* to reach *your* indexer; it never
needs your remote host to reach back into this lab's network.

**What you need to open on the remote side:** a security-group rule allowing TCP 9200 inbound from
this lab's public IP only (not `0.0.0.0/0`) — check your current IP with `curl https://api.ipify.org`.
That's the only port needed for alert ingestion. Enrolling *new* endpoints against that same remote
manager would additionally require opening 1514/1515 the same way — a separate decision, not needed
just to see its existing alerts here.

> **Dual-WAN / multiple public IPs:** if this lab's network has more than one active internet uplink
> (e.g. two ISP lines, both active/load-balanced rather than pure failover), outbound requests can
> leave via *either* public IP unpredictably per-connection — add a separate security-group rule for
> **each** public IP, not just the one you happen to see in a single `curl` check, or the poller will
> intermittently fail whenever traffic routes out the un-whitelisted link.
>
> ```bash
> aws ec2 authorize-security-group-ingress --group-id sg-xxxxxxxx \
>   --protocol tcp --port 9200 --cidr <WAN-1-IP>/32
> aws ec2 authorize-security-group-ingress --group-id sg-xxxxxxxx \
>   --protocol tcp --port 9200 --cidr <WAN-2-IP>/32
> ```

**Verify the index/field names first:** this connector assumes the standard Wazuh 4.x index pattern
(`wazuh-alerts-*`) and timestamp field (`timestamp`). Confirm both in your Wazuh Dashboard (Stack
Management → Index Patterns, or Discover) before relying on it — override via `WAZUH_ALERT_INDEX` /
edit `WAZUH_TIMESTAMP_FIELD` in `wazuh-remote-connector/poller.py` if they differ.

**If the indexer is reachable on 443/9200 per the security group but every connection attempt still
"Connection refused" (not "timed out")** — that was actually a security-group false negative, not a
real fix: the indexer had genuinely become reachable at the network layer, but OpenSearch itself was
still only bound to `127.0.0.1` (`network.host` in `opensearch.yml`), so nothing outside the host
could ever complete a connection to it regardless of firewall rules. Fixed on the indexer host with:
```bash
sudo sed -i 's/network.host: "127.0.0.1"/network.host: ["127.0.0.1", "<its own private IP>"]/' /etc/wazuh-indexer/opensearch.yml
sudo systemctl restart wazuh-indexer
```
(keep `127.0.0.1` in the list too — the Wazuh Dashboard on that same host talks to the indexer over
localhost, and removing it broke dashboard login entirely until re-added.)

### Wazuh's built-in FIM (syscheck) runs independently of this lab's own FIM tool

This lab's own File Integrity Monitoring watcher (`endpoint-configs/windows/fim/`) covers ground
syscheck doesn't — AD-user attribution, rename/move/copy correlation, content preview, and per-user
ZIP restore. Since Wazuh is now a real, externally-managed deployment, this lab doesn't control its
shared agent configuration the way it could with the old local manager — syscheck runs on whatever
that manager's own policy dictates, independently of (and potentially overlapping with) this lab's
FIM tool. That overlap is accepted, not actively suppressed, for the same reason: this project no
longer owns that manager's config.

---

## Stopping and Managing the Lab

```bash
# Stop all services (keep data)
docker compose down

# Stop and delete all data volumes
docker compose down -v

# Restart a single service
docker compose restart elastalert2

# View logs for a service
docker compose logs -f ai-agents

# Check resource usage
docker stats
```

---

## Project Structure

```
advanced-soc-lab-v2/
├── docker-compose.yml          # All 12 services + red team profile
├── .env.example                # Environment variable template
├── setup.sh                    # One-command deployment script
├── health-check.sh             # Service health validation
├── simulate-attack.sh          # Attack scenario injection
├── README.md                   # This file
│
├── dashboards/                 # Web UI dashboards
│   ├── index.html              # Main portal
│   ├── soc-theme.css           # Shared dark design system
│   ├── 01_soc_overview.html    # Live alert feed + MITRE heatmap
│   ├── 02_opensearch_siem.html # 24h timeline + index stats
│   ├── 03_zeek_network.html    # conn.log stream + DNS anomalies
│   ├── 04_suricata_ids.html    # EVE JSON feed + top signatures
│   ├── 05_ai_agents.html       # CrewAI agent console
│   ├── 06_iris_cases.html      # Incident cases + IOC tracker
│   ├── 07_caldera_attack.html  # ATT&CK coverage matrix
│   ├── 08_misp_ti.html         # IOC lookup + feed status
│   ├── 09_velociraptor.html    # Hunt progress + VQL console
│   ├── 10_responder_redteam.html # NTLMv2 capture + blue response
│   └── 11_file_integrity.html  # Endpoint FIM — no agent, Excel-style filters, ZIP restore
│
├── config/
│   ├── opensearch/             # OpenSearch + Dashboards config
│   ├── elastalert2/rules/      # 9 ElastAlert2 rules (YAML)
│   ├── caldera/operations/     # APT-29 + Insider Threat operations
│   ├── nginx/                  # Reverse proxy config
│   └── misp/                   # MISP server config
│
├── ai-agents/                  # CrewAI SOC agents
│   ├── agents/                 # threat_analyst, incident_responder,
│   │                           # threat_hunter, detection_engineer
│   ├── tools/                  # OpenSearch, MISP, IRIS, Velociraptor tools
│   └── api.py                  # FastAPI + WebSocket server
│
├── soar-playbooks/             # StackStorm automation packs
├── detection-rules/            # Sigma rules + ElastAlert2 configs
├── endpoint-configs/           # Sysmon, Velociraptor, Zeek configs, FIM watcher (fim/)
├── cloud-logs/                 # AWS CloudTrail, Azure, GCP parsers
└── threat-hunting/             # Pre-built hunting queries
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| OpenSearch won't start | `vm.max_map_count` too low | `sudo sysctl -w vm.max_map_count=262144` |
| Cluster status RED | Not enough memory | Close other apps; ensure 16 GB free |
| Caldera agent offline | Firewall blocking port 8888 | `ufw allow 8888` |
| Ollama model missing | Download failed | `docker exec ollama ollama pull llama3.2:3b` |
| Container keeps restarting | Out of disk space | Free space: `docker system prune` |
| ElastAlert2 no alerts | No data in OpenSearch | Run `./simulate-attack.sh apt29` first |
| MISP login fails | Container still initializing | Wait 2–3 min after startup |

### View Service Logs

```bash
docker compose logs -f opensearch-node1
docker compose logs -f elastalert2
docker compose logs -f ai-agents
docker compose logs -f caldera
```

### Full Reset

```bash
docker compose down -v
sudo rm -rf data/
./setup.sh
```

---

## Learning Exercises

Once the lab is running, work through these exercises in order:

1. **Alert Triage** — Run `./simulate-attack.sh apt29`, open OpenSearch Dashboards, and triage the 13 injected alerts by severity
2. **Case Creation** — Open DFIR-IRIS and create a new case for the APT-29 intrusion. Add IOCs and link MITRE techniques
3. **Network Forensics** — Review the Zeek Network dashboard for LLMNR poisoning and DNS tunneling indicators
4. **Threat Hunting** — Use the Velociraptor VQL console to hunt for suspicious scheduled tasks and LSASS access
5. **Detection Gap Analysis** — Run the Caldera APT-29 operation and review which techniques were detected vs missed
6. **SOAR Automation** — Trigger a StackStorm playbook by injecting a brute force scenario and observing automated response
7. **AI-Assisted Analysis** — Use the AI Agents dashboard to run the APT-29 attribution scenario and review the LLM analysis
8. **File Integrity Monitoring** — Deploy `endpoint-configs/windows/fim/Deploy-FIM.ps1` to a Windows host, then use the File Integrity dashboard to filter events by AD user/action/time range, inspect a file's version history and diff, and restore a deleted file as a ZIP
8. **Red Team (optional)** — Enable the red team profile, capture NTLMv2 hashes via Responder, and follow the blue team response timeline

---

## Contributing

Pull requests are welcome. Please open an issue first to discuss significant changes.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-detection-rule`
3. Commit your changes: `git commit -m 'Add T1055 process injection detection rule'`
4. Push to the branch: `git push origin feature/my-detection-rule`
5. Open a Pull Request

---

## License

MIT License — free to use, modify, and distribute for educational and research purposes.

---

## Author

**Debasish Lenka**
- GitHub: [@deba751002](https://github.com/deba751002)
- LinkedIn: [linkedin.com/in/debasish-lenka-0a9815352](https://www.linkedin.com/in/debasish-lenka-0a9815352)
- Email: captainfun160@gmail.com

Built as a hands-on SOC training environment for blue team skill development, threat detection practice, and adversary emulation research.

> *"The best way to learn detection is to run the attack yourself."*

---

*Enterprise Detection & Response Agent · 28+ tools · 100% open-source · MITRE ATT&CK v14*

---
⭐ **Star this repo if it helped you — it helps other SOC analysts find it!**

