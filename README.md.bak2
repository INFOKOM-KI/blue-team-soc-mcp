# Blue Team MCP Server

A defensive security MCP server for Claude Desktop or any MCP Client — the defender's counterpart to [mcp-kali-server](https://www.kali.org/blog/kali-llm-claude-desktop/).

Where Kali Linux gives Claude offensive tools (nmap, gobuster, sqlmap), this gives Claude **blue team / SOC analyst tools** to investigate, monitor, and harden your systems.

**Programmer** : `NAuliajati` (`csirt[at]tangerangkota[.]go[.]id`)
**Recoded** :  `https://github.com/not2cleverdotme/blue-team-mcp`

---

## Architecture

`blue_team_server.py` is a **single, unified MCP server** with 37 tools spanning host forensics, Wazuh SIEM, and multi-source threat intelligence. It supports three transports:

| Transport | Use case | MCP client connection |
|---|---|---|
| `stdio` | Local subprocess or SSH pipe | Direct (Claude Desktop stdio) |
| `sse` | Legacy remote HTTP service | `http://<host>:<port>/sse` |
| `streamable_http` | Modern remote HTTP service (**recommended**) | `http://<host>:<port>/mcp` |

```
                          ┌──────────────────────────────────┐
                          │     blue_team_server.py          │
                          │     37 tools · 1 file · 3 transports  │
                          │                                  │
                          │  ┌────────────────────────────┐  │
                          │  │ Host Forensics (26 tools)  │  │
                          │  │ • Log analysis             │  │
                          │  │ • Network monitoring       │  │
                          │  │ • Fail2Ban management      │  │
                          │  │ • File integrity           │  │
                          │  │ • System hardening (Lynis) │  │
                          │  │ • User/session monitoring  │  │
                          │  │ • Process & cron analysis  │  │
                          │  │ • System health            │  │
                          │  └────────────────────────────┘  │
                          │  ┌────────────────────────────┐  │
                          │  │ Wazuh SIEM (5 tools)       │  │
                          │  │ • Agent inventory & status │  │
                          │  │ • Security alerts          │  │
                          │  │ • Manager logs             │  │
                          │  │ • OpenSearch indexer query │  │
                          │  └────────────────────────────┘  │
                          │  ┌────────────────────────────┐  │
                          │  │ Threat Intel (6 tools)     │  │
                          │  │ • AbuseIPDB IP reputation  │  │
                          │  │ • VirusTotal hash & domain │  │
                          │  │ • CrowdSec CTI (2 tools)   │  │
                          │  │ • GreyNoise Community      │  │
                          │  └────────────────────────────┘  │
                          └──────────────────────────────────┘
                            │          │           │
                       stdio        SSE    streamable_http
                      (default)   :8000/sse   :8000/mcp
```

### Two deployment modes

**Mode 1 — Local via SSH (stdio):** Claude Desktop connects over SSH; the server runs as a subprocess on the defender host.

```
┌─────────────────────┐        SSH + stdio     ┌─────────────────────────┐
│   Your Workstation  │ ────────────────────── │    Defender Host        │
│   Claude Desktop    │                        │   Ubuntu/Debian Server  │
└─────────────────────┘                        │   blue_team_server.py   │
                                               └─────────────────────────┘
```

**Mode 2 — Remote service (SSE / Streamable HTTP):** The server runs as a persistent HTTP service. Any MCP client connects over the network — no SSH required.

```
┌─────────────────────┐     HTTP (SSE or       ┌─────────────────────────┐
│   Any MCP Client    │     Streamable HTTP)    │    Defender Host        │
│   (Claude Desktop,  │ ────────────────────── │   systemd service:      │
│    custom client)   │     http://host:8000    │   blue_team_server.py   │
└─────────────────────┘                        │   --transport http      │
                                               └─────────────────────────┘
```

### Standalone files (optional backward-compat)

The CrowdSec and GreyNoise tools also ship as separate files for users who prefer modular deployment:

| File | Tools | When to use |
|---|---|---|
| `blue_team_server.py` | **All 37 tools** | **Recommended** — single process, single endpoint |
| `blue_team_server_crowdsec.py` | 2 CrowdSec CTI tools | Only if you want an isolated CrowdSec-only server |
| `blue_team_server_greynoise.py` | 1 GreyNoise Community tool | Only if you want an isolated GreyNoise-only server |

---

## Quick Start

### 1. On your Defender Host (Ubuntu/Debian)

```bash
git clone <this repo>
cd blue-team-mcp
sudo bash setup.sh
```

The setup script will:
- Install system packages (tcpdump, fail2ban, lynis, rkhunter, chkrootkit, and Python 3 toolchain)
- Create a Python virtualenv with MCP dependencies at `/opt/blue-team-mcp/venv`
- Copy all server files, `requirements.txt`, and `README.md` to `/opt/blue-team-mcp/`
- Place the `mcp-server-blueteam` wrapper in `/usr/local/bin`
- Grant tcpdump network capture capabilities

### 2. Set API Keys and Wazuh (optional but recommended)

Edit the config file created by setup:

```bash
sudo nano /opt/blue-team-mcp/config.env
```

Uncomment and set the variables you need:

- **CROWDSEC_API_KEY** — https://www.crowdsec.net/en/user/profile (free CTI tier; powers the `crowdsec_ip_reputation` tools)
- **ABUSEIPDB_API_KEY** — https://www.abuseipdb.com/account/api
- **VIRUSTOTAL_API_KEY** — https://www.virustotal.com/gui/my-apikey
- **WAZUH_API_URL** — `https://localhost:55000` (if Wazuh is on same host) or `https://<host>:55000`
- **WAZUH_API_USER** — `wazuh-wui` (Wazuh Docker default)
- **WAZUH_API_PASSWORD** — e.g. `MyS3cr37P450r.*-` (Wazuh Docker default)
- **WAZUH_API_VERIFY_SSL** — `false` for self-signed certs
- **WAZUH_INDEXER_URL** — `https://localhost:9200` (if on same host) or `https://<host>:9200`
- **WAZUH_INDEXER_USER** — `admin` (indexer default)
- **WAZUH_INDEXER_PASSWORD** — indexer password (often different from Wazuh API)
- **WAZUH_INDEXER_VERIFY_SSL** — `false` for self-signed certs

**GreyNoise Community requires no API key** — the `greynoise_ip_context` tool works out of the box (rate-limited per GreyNoise's fair-use policy).

**Note:** The indexer (port 9200) stores HYDRA-DC Windows events in OpenSearch. Its password may differ from the Wazuh API. For Wazuh Docker, check your `docker-compose` or `.env` for `OPENSEARCH_INITIAL_ADMIN_PASSWORD`. If adding Indexer support to an existing install, re-run `setup.sh` to update the wrapper with the new exports.

### 3. Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS).

**Option A — Local deployment (SSH + stdio):**

```json
{
  "mcpServers": {
    "blue-team-mcp": {
      "command": "ssh",
      "args": [
        "-i", "/Users/you/.ssh/ubuntu-soc",
        "soc-admin@192.168.153.5",
        "mcp-server-blueteam"
      ],
      "transport": "stdio"
    }
  }
}
```

**Option B — Remote service (Streamable HTTP, recommended for shared SOC use):**

First start the server on the defender host:
```bash
python3 blue_team_server.py --transport streamable_http --host 0.0.0.0 --port 8000
```

Then point Claude Desktop at it:
```json
{
  "mcpServers": {
    "blue-team-mcp": {
      "url": "http://192.168.153.5:8000/mcp",
      "transport": "streamable-http"
    }
  }
}
```

Replace `192.168.153.5` with the IP reachable from your workstation (`192.168.153.5` for NAT, `172.16.101.5` for LAB).

Restart Claude Desktop. You should see all 37 blue-team-mcp tools available.

### 4. Remote Service Deployment (systemd)

For a persistent remote service accessible to multiple MCP clients, run `blue_team_server.py` as a systemd unit:

```ini
# /etc/systemd/system/blue-team-mcp.service
[Unit]
Description=Blue Team MCP Server
After=network.target

[Service]
Type=simple
User=blue-team
WorkingDirectory=/opt/blue-team-mcp
EnvironmentFile=/opt/blue-team-mcp/config.env
Environment="MCP_HOST=0.0.0.0"
Environment="MCP_PORT=8000"
ExecStart=/opt/blue-team-mcp/venv/bin/python3 blue_team_server.py --transport streamable_http
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable blue-team-mcp
sudo systemctl start blue-team-mcp
sudo systemctl status blue-team-mcp (make sure service is running)
```

The server is now reachable at `http://<host>:8000/mcp` (Streamable HTTP) or `http://<host>:8000/sse` (SSE).

Transport can be controlled via environment variables instead of CLI flags:
- `MCP_TRANSPORT` — `stdio` (default), `sse`, or `streamable_http`
- `MCP_HOST` — bind address (default `127.0.0.1`; use `0.0.0.0` for remote access)
- `MCP_PORT` — bind port (default `8000`)

---

## Available Tools

All tools below are registered on `blue_team_server.py`. Tools not requiring a specific API key work out of the box; optional API keys unlock additional capabilities as noted.

### Log Analysis
| Tool | Description |
|------|-------------|
| `blueteam_read_auth_log` | SSH/sudo/PAM events from auth.log |
| `blueteam_read_syslog` | General system events |
| `blueteam_read_web_log` | nginx/Apache access & error logs |
| `blueteam_journalctl` | Query any systemd unit's journal |

### Network Monitoring
| Tool | Description |
|------|-------------|
| `blueteam_list_listening_ports` | All open/listening ports with process |
| `blueteam_list_connections` | Established TCP connections |
| `blueteam_capture_traffic` | Live packet capture via tcpdump |

### Wazuh SIEM
| Tool | Description |
|------|-------------|
| `blueteam_wazuh_agents` | List all Wazuh agents (status, IP, OS) |
| `blueteam_wazuh_agents_summary` | Agent count by status (active/disconnected) |
| `blueteam_wazuh_manager_logs` | Manager daemon logs (api, cluster, integrations) |
| `blueteam_wazuh_alerts` | Security alerts from alerts.json (when MCP runs on manager host) |
| `blueteam_wazuh_indexer_search` | Query OpenSearch for agent alerts/events (HYDRA-DC Windows events) |

### Threat Intelligence
| Tool | Description |
|------|-------------|
| `blueteam_lookup_ip_abuseipdb` | IP reputation via AbuseIPDB |
| `blueteam_lookup_hash_virustotal` | File hash lookup via VirusTotal |
| `blueteam_lookup_domain_virustotal` | Domain reputation via VirusTotal |

### CrowdSec CTI
*Requires `CROWDSEC_API_KEY`*

| Tool | Description |
|------|-------------|
| `crowdsec_ip_reputation` | Single IP reputation via CrowdSec CTI Smoke API (behaviors, MITRE ATT&CK, CVEs) |
| `crowdsec_ip_reputation_bulk` | Batch reputation lookup for up to 10 IPs |

### GreyNoise Community
*Free — no API key required*

| Tool | Description |
|------|-------------|
| `greynoise_ip_context` | Check if an IP is a known internet scanner (noise) or trusted business service (RIOT) |

### Fail2Ban
| Tool | Description |
|------|-------------|
| `blueteam_fail2ban_status` | List all jails and ban counts |
| `blueteam_fail2ban_jail_status` | Detailed status of a specific jail |
| `blueteam_fail2ban_unban` | Unban an IP from a jail |

### File Integrity
| Tool | Description |
|------|-------------|
| `blueteam_hash_file` | Hash any file (MD5/SHA1/SHA256/SHA512) |
| `blueteam_find_suid_files` | Find unexpected SUID/SGID binaries |
| `blueteam_find_world_writable` | Find world-writable files (persistence indicator) |
| `blueteam_rootkit_scan` | Run rkhunter or chkrootkit |

### System Hardening
| Tool | Description |
|------|-------------|
| `blueteam_lynis_audit` | Full Lynis hardening audit |
| `blueteam_check_updates` | Check for pending security updates |
| `blueteam_check_open_firewall` | View ufw/nftables/iptables rules |

### User & Session Monitoring
| Tool | Description |
|------|-------------|
| `blueteam_who_is_logged_in` | Active user sessions with source IPs |
| `blueteam_last_logins` | Login history (last 50) |
| `blueteam_failed_logins` | Failed login attempts |
| `blueteam_sudo_history` | Sudo command usage |
| `blueteam_list_users` | All local accounts with risk flags |
| `blueteam_check_ssh_authorized_keys` | All authorized_keys files |

### Process & Persistence
| Tool | Description |
|------|-------------|
| `blueteam_list_processes` | All running processes |
| `blueteam_list_cron_jobs` | System and user cron jobs |

### System Health
| Tool | Description |
|------|-------------|
| `blueteam_system_health` | Uptime, disk, memory, CPU load |

---

## Example Prompts

Once connected via Claude Desktop, you can ask:

```
"Check the last 2 hours of auth.log and tell me if there are any brute force 
 attempts. Group by source IP."

"Show me all listening ports. Are any unexpected services running?"

"Here are 5 IPs from my nginx access log: 1.2.3.4, 5.6.7.8, 9.10.11.12,
 13.14.15.16, 200.1.2.3 — look them all up on AbuseIPDB."

"Run a Lynis audit and give me the top 5 highest priority hardening items."

"Check for any SUID binaries that aren't in the standard list of expected ones."

"Who is currently logged into this server, and when did they log in?"

"Scan all user cron jobs and flag anything that looks suspicious."

"Hash /usr/bin/sshd and check it against VirusTotal."

"Check the CrowdSec reputation of 185.220.101.1 — does it have known attack
 behaviors or associated CVEs?"

"Is 71.6.135.131 a known internet scanner? Check with GreyNoise and tell me
 if it's noise I can ignore or something to investigate."

"Triage these 5 IPs from my firewall logs against both GreyNoise and CrowdSec.
 Filter out known scanners and business services, then prioritize the rest
 by reputation."
```

---

## MAESTRO Framework Alignment (currently for dev only)

This server aligns with the [CSA MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) framework for agentic AI security. See [MAESTRO.md](MAESTRO.md) for the threat model and mitigations.

### Optional: Audit Logging (Repudiation Mitigation)

Enable audit logging to record tool invocations:

```bash
export BLUETEAM_AUDIT_LOG=/var/log/blue-team-mcp-audit.jsonl
```

Ensure log rotation (e.g., logrotate) to prevent unbounded growth.

### Optional: Rate Limiting (DoS Mitigation)

Limit tool calls per minute:

```bash
export BLUETEAM_RATE_LIMIT=60
```

---

## Security Notes

- The MCP server runs with **whatever privileges the SSH user has**. Running as a dedicated low-privilege user (with sudo for specific tools) is recommended for production.
- Threat intel tools make **outbound API calls** to:
  - AbuseIPDB (`api.abuseipdb.com`)
  - VirusTotal (`www.virustotal.com`)
  - CrowdSec CTI (`cti.api.crowdsec.net`) — requires `CROWDSEC_API_KEY`
  - GreyNoise Community (`api.greynoise.io`) — free, no auth required
  Ensure outbound HTTPS to these endpoints is acceptable in your environment.
- `blueteam_capture_traffic` requires `CAP_NET_RAW` or root. The setup script attempts to grant this to tcpdump via `setcap`.
- Log files under `/var/log/` often require root or membership in the `adm` group to read. Add your SSH user to the `adm` group: `usermod -aG adm youruser`
- **Path restrictions:** `blueteam_hash_file` allows paths under `/var`, `/etc`, `/home`, `/opt`, `/usr` (configurable via `BLUETEAM_ALLOWED_PATHS`). `blueteam_capture_traffic` writes pcap files only under `BLUETEAM_CAPTURE_DIR` (default `/tmp`).

---

## Requirements

**Defender Host:**
- Ubuntu 20.04+ or Debian 11+ (other distros work with minor adjustments)
- Python 3.11+ (required for modern type hints and Pydantic v2)
- OpenSSH server

**Optional system tools** (setup.sh installs these):
- `tcpdump`, `fail2ban`, `lynis`, `rkhunter`, `chkrootkit`

**Python packages** (auto-installed in venv):
- `mcp>=1.0.0,<2.0.0`
- `httpx>=0.27.0,<0.28.0`
- `pydantic>=2.0.0,<3.0.0`

**Server files:**

| File | Role |
|---|---|
| `blue_team_server.py` | **Primary** — all 37 tools, all three transports (stdio / SSE / Streamable HTTP) |
| `blue_team_server_crowdsec.py` | Standalone CrowdSec-only server (backward compat) |
| `blue_team_server_greynoise.py` | Standalone GreyNoise-only server (backward compat) |
