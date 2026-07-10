# Blue Team MCP Server

A defensive security MCP server for Claude Desktop or any MCP Client - the defender's counterpart to [mcp-kali-server](https://www.kali.org/blog/kali-llm-claude-desktop/).

Where Kali Linux gives Claude offensive tools (nmap, gobuster, sqlmap), this gives Claude **blue team / SOC analyst tools** to investigate, monitor, and harden your systems.

**Programmer** : `NAuliajati` (`csirt[at]tangerangkota[.]go[.]id`)
**Recoded** :  `https://github.com/not2cleverdotme/blue-team-mcp`

---

## Architecture

`blue_team_server.py` is a **single, unified MCP server** with 43 tools spanning host forensics, Wazuh SIEM, and multi-source threat intelligence. It supports two transports:

| Transport | Use case | MCP client connection |
|---|---|---|
| `stdio` | Local subprocess or SSH pipe | Direct (Claude Desktop stdio) |
| `streamable_http` | Remote HTTP service | `http://<host>:<port>/mcp` |

```
                          ┌──────────────────────────────────┐
                          │     blue_team_server.py          │
                          │     43 tools · 1 file · 2 transports  │
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
                          │  │ Wazuh SIEM (10 tools)      │  │
                          │  │ • Agent inventory & status │  │
                          │  │ • Security alerts          │  │
                          │  │ • Manager logs             │  │
                          │  │ • OpenSearch indexer query │  │
                          │  │ • Email/domain compromise  │  │
                          │  │ • Alert timeline           │  │
                          │  │ • Attack velocity          │  │
                          │  └────────────────────────────┘  │
                          │  ┌────────────────────────────┐  │
                          │  │ Threat Intel (7 tools)     │  │
                          │  │ • AbuseIPDB IP reputation  │  │
                          │  │ • VirusTotal hash & domain │  │
                          │  │ • CrowdSec CTI (2 tools)   │  │
                          │  │ • GreyNoise Community      │
                          │  │ • Netra multi-source        │  │
                          │  └────────────────────────────┘  │
                          └──────────────────────────────────┘
                            │              │
                       stdio      streamable_http
                      (default)      :8000/mcp
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

**Mode 2 — Remote service (Streamable HTTP):** The server runs as a persistent HTTP service. Any MCP client connects over the network — no SSH required.

```
┌─────────────────────┐     Streamable HTTP     ┌─────────────────────────┐
│   Any MCP Client    │ ────────────────────── │    Defender Host        │
│   (Claude Desktop,  │     http://<host>:8000    │   systemd service:      │
│    custom client)   │                        │   blue_team_server.py   │
└─────────────────────┘                        │   --transport http      │
                                               └─────────────────────────┘
```

### Standalone files (archived)

The CrowdSec and GreyNoise standalone servers (`blue_team_server_crowdsec.py`, `blue_team_server_greynoise.py`) have been moved to `archive/`. Both tools are fully integrated into the unified server.

| File | Tools | When to use |
|---|---|---|
| `blue_team_server.py` | **All 43 tools** | **Recommended** — full capabilities, circuit breaker, credential stripping, PII redaction |

---

## Performance Architecture

The suite has been refactored for **bulk data processing and concurrent workloads** beyond single-analyst interactive triage. Every server in the suite now shares the same performance patterns.

### Wazuh Server (`blue_team_server.py`)

#### Cursor-Based Pagination (Bulk Data Without Hard Caps)

All Wazuh tools support iterative cursor pagination via base64-encoded JSON tokens. Each page returns a `next_cursor`; pass it back as the `cursor` parameter to fetch the next page. `next_cursor` is `null` when the dataset is exhausted.

| Tool | Pagination Mechanism | Max per Page | Cursor Shape |
|---|---|---|---|
| `blueteam_wazuh_indexer_search` | OpenSearch `search_after` (sort-key traversal) — also supports **auto-pagination** via `max_scanned` | 10,000 | `{"search_after": [<sort_values>]}` |
| `blueteam_wazuh_agents` | Wazuh API `offset`/`limit` | 10,000 | `{"offset": N}` |
| `blueteam_wazuh_manager_logs` | Wazuh API `offset`/`limit` | **500** (auto capped) | `{"offset": N}` |
| `blueteam_wazuh_alerts` | Line-offset in local `alerts.json` | 2,000 | `{"scanned": N}` |
| `wazuh_email_lookup` | OpenSearch `search_after` (sort-key traversal) | 1,000 | `{"search_after": [<sort_values>]}` |
| `wazuh_domain_lookup` | OpenSearch `search_after` (sort-key traversal) — also supports **auto-pagination** via `max_scanned` | 10,000 | `{"search_after": [<sort_values>]}` |
| `wazuh_compromised_emails_analysis` | OpenSearch `search_after` (sort-key traversal) — auto-paginates internally per batch | 1,000 | `{"search_after": [<sort_values>]}` |
| `wazuh_alert_timeline` | OpenSearch `date_histogram` (size:0, server-side) | ∞ (covers all matching docs) | n/a — no cursor needed |
| `wazuh_attack_velocity` | OpenSearch `date_histogram` (size:0, server-side) | ∞ (covers all matching docs) | n/a — no cursor needed |

**Agent workflow:**
```
1. Call tool (no cursor) → page 1 + next_cursor
2. Call tool(cursor=next_cursor) → page 2 + next_cursor
3. Repeat until next_cursor is null — all results retrieved
```

All input schemas are **backward-compatible** — `cursor` is optional and defaults are unchanged.

#### Relative Time Expressions

All Wazuh tools accept **relative time expressions** for `since`/`until` parameters in addition to ISO 8601 strings:

| Expression | Meaning | Example |
|---|---|---|
| `Ns` | N seconds ago | `15s` — last 15 seconds |
| `Nm` | N minutes ago | `5m` / `30m` — last 5 / 30 minutes |
| `Nh` | N hours ago | `1h` / `24h` / `6h` — last N hours |
| `Nd` | N days ago | `1d` / `7d` / `30d` — last N days |
| `Nw` | N weeks ago | `1w` / `4w` — last N weeks |
| ISO 8601 | Absolute timestamp (pass-through) | `2026-07-07T17:00:00Z` |

Supported by: `blueteam_wazuh_alerts`, `blueteam_wazuh_indexer_search`, `wazuh_email_lookup`, `wazuh_domain_lookup`, `wazuh_compromised_emails_analysis`, `wazuh_alert_timeline`, `wazuh_attack_velocity`.

#### Paging via `search_after` (`blueteam_wazuh_indexer_search`)

The Wazuh Indexer search tool was migrated from offset-based pagination (`from`/`size`) to OpenSearch's `search_after` cursor, eliminating the 10,000-document `max_result_window` ceiling:

- **Sort anchor**: Results are ordered by `@timestamp` (ascending) with `_id` as a deterministic tie-breaker. This guarantees every document has a unique, stable sort key.
- **Cursor traversal**: `next_cursor` encodes the raw sort values of the last document in the current page. On the next call, those values are sent as the `search_after` array — OpenSearch resumes the scan from exactly where the previous page ended.
- **Truncation metadata**: The response exposes `total` as an object `{"value": <int>, "relation": <"eq"|"gte">}`. When `relation` is `"gte"` (greater-than-or-equal), the LLM client knows the true document count exceeds the reported ceiling and continues paginating.
- **Natural exhaustion**: `next_cursor` becomes `null` when the number of returned documents is strictly less than the requested `limit` — no arithmetic against a capped `total.value`.

#### Auto Cap Limit Guard (Self Healing Defense)

The Wazuh Manager API (`/manager/logs`) rejects `limit > 500` with HTTP 400. The Pydantic input model allows up to 1,000, creating a gap where LLM clients can inadvertently construct failing requests. The `blueteam_wazuh_manager_logs` tool now applies an inline safety clamp before the HTTP call:

```python
wazuh_safe_limit = min(params.limit, 500)
```

This silently caps the value to 500 at the application layer. The client still receives the full pagination metadata (`next_cursor`, `total`) and can iterate through all results without ever triggering a validation error.

In addition, the global `_handle_api_error` helper returns a specific, actionable message for HTTP 400 (Bad Request) advising the caller to reduce limit size or switch filter parameters. This guard is deployed across all three server files.

#### Remote Architecture Fallback (`blueteam_wazuh_alerts`)

When the Wazuh Manager runs on a remote host, the local `alerts.json` file is absent. Instead of a generic OS error, the tool returns a strict metadata instruction:

```
[CRITICAL METADATA] This tool is disabled because the Wazuh Manager
is running on a remote host. DO NOT RETRY this local tool. You MUST
immediately switch to 'blueteam_wazuh_indexer_search' or
'blueteam_wazuh_manager_logs' to query security events.
```

This prevents the LLM client from wasting context loops retrying a fundamentally unavailable data path and directs it toward the correct remote-capable alternatives.

#### Shared HTTP Client with Connection Pooling

Four dedicated `httpx.AsyncClient` instances, one per SSL trust domain:

| Client | `verify` | Endpoints |
|---|---|---|
| `_get_http_client()` | `True` (public CA) | AbuseIPDB, VirusTotal, CrowdSec CTI, GreyNoise |
| `_get_netra_http_client()` | `NETRA_VERIFY_SSL` (default `false`) | Netra Threat Intelligence (staging-gitlab:8013) |
| `_get_wazuh_client()` | `WAZUH_API_VERIFY_SSL` (default `true`) | Wazuh Manager API (port 55000) |
| `_get_indexer_client()` | `WAZUH_INDEXER_VERIFY_SSL` (default `true`) | OpenSearch (port 9200) |

Each client pools connections independently (20 keepalive / 100 max for public APIs; 5 / 20 for Netra staging; 10 / 50 for Wazuh and Indexer). SSL verification is set at client creation — no per-request `verify=` keyword arguments.

#### Wazuh JWT Token Caching

Cached for **300 seconds (5 minutes)** with automatic cache clearance on authentication failure.

#### Non-Blocking Subprocess Execution

`_run_async()` wraps synchronous subprocess calls in `asyncio.to_thread()`, preventing 30 tools from blocking the event loop under concurrent load.

### CrowdSec CTI — In-Memory TTL Cache + Bulk Lookups

CrowdSec IP reputation is integrated directly into the unified server (`blue_team_server.py`). The standalone `blue_team_server_crowdsec.py` and `blue_team_server_greynoise.py` files have been archived — all functionality is available through the main server.

#### In-Memory Cache (CrowdSec CTI Only)

Per `SKILLS.md` §3.1, CrowdSec CTI responses are cached in-process with configurable TTL:

- **Default TTL**: 900 seconds (15 minutes) — configurable via `CROWDSEC_CACHE_TTL`
- **Cache scope**: per-IP, per-path — identical requests hit the cache; different IPs do not
- **Error exclusion**: HTTP 4xx/5xx responses are NEVER cached (structurally excluded — `raise_for_status()` throws before the cache-store point)
- **Cache hit**: returns stored data immediately with no HTTP call
- **Cache expired**: stale entry is deleted, fresh HTTP call is made, result is re-cached

#### Parallel Bulk IP Lookups (CrowdSec Only)

`crowdsec_ip_reputation_bulk` executes up to 10 IP lookups concurrently via `asyncio.gather()` bounded by an `asyncio.Semaphore`:

- **Default concurrency**: 5 (configurable via `BLUETEAM_BULK_CONCURRENCY`)
- **Error isolation**: per-IP failure does not affect sibling lookups
- **Latency**: ~5× speedup vs serial iteration

### Circuit Breaker (External API Resilience)

Ported from the Wazuh-MCP-Server resilience pattern. A three-state circuit breaker prevents cascading failures when upstream APIs are unreachable — the LLM sees actionable errors instead of retrying indefinitely against a dead backend.

**State machine:**
```
CLOSED ──5 consecutive failures──▶ OPEN ──60s timeout──▶ HALF_OPEN
  ▲                                 ▲                      │
  │                                 │                 probe fails?
  │                                 └──────────────────────┘ yes
  │                                                        │
  └────────── probe succeeds ──────────────────────────────┘ no
```

**Per-service breakers:**

| Breaker | Guards | Threshold | Recovery | Applied at |
|---------|--------|-----------|----------|------------|
| `_cb_crowdsec` | CrowdSec CTI API (`cti.api.crowdsec.net`) | 5 failures | 60s | `_crowdsec_request()` HTTP GET |
| `_cb_wazuh_indexer` | Wazuh Indexer / OpenSearch | 5 failures | 60s | `_wazuh_indexer_search()` HTTP POST |

**Key properties:**
- **Async-safe**: `asyncio.Lock` protects state transitions under concurrent load
- **Cache-aware**: CrowdSec cache hits skip the circuit breaker entirely (no API call → no failure counted)
- **Self-healing**: HALF_OPEN probe on success → CLOSED with all counters reset
- **Actionable errors**: `CircuitBreakerOpenError` includes remaining timeout so the LLM sees a retry hint

### Credential & Secret Stripping (Output Sanitization)

Ported from the Wazuh-MCP-Server output sanitization pattern. Before any Wazuh alert or traffic capture data reaches the LLM context, `_redact_alert_data()` strips credentials, API keys, and secret material from `full_log` and other text fields.

**Applied automatically** to all output from `blueteam_wazuh_alerts`, `blueteam_wazuh_indexer_search`, and `blueteam_capture_traffic`. Controlled by `BLUETEAM_REDACT_PII` (default: `true`) with a per-call `bypass_redaction` parameter for audit investigations.

**Stripping rules (15 regex patterns, applied before PII masking):**

| Category | Patterns detected | Replacement |
|----------|------------------|-------------|
| Auth headers | `Authorization: Bearer <token>`, `Authorization: Basic <creds>` | `<BEARER_REDACTED>`, `<BASIC_REDACTED>` |
| API keys | `x-api-key: <key>`, `api_key=<value>` | `<API_KEY_REDACTED>` |
| JWT tokens | 3-segment base64url tokens starting with `eyJ` | `<JWT_REDACTED>` |
| Private keys | PEM blocks (`-----BEGIN ... PRIVATE KEY-----`) | `<PRIVATE_KEY_REDACTED>` |
| Cloud keys | AWS (`AKIA...`), Google (`AIza...`) | `<AWS_ACCESS_KEY_REDACTED>`, `<GOOGLE_API_KEY_REDACTED>` |
| Payment keys | Stripe (`sk_live_...`, `sk_test_...`) | `<STRIPE_KEY_REDACTED>` |
| VCS tokens | GitHub (`ghp_...`, `gho_...`, etc.), GitLab (`glpat-...`) | `<GITHUB_TOKEN_REDACTED>`, `<GITLAB_TOKEN_REDACTED>` |
| AI API keys | Anthropic (`sk-ant-...`), OpenAI (`sk-proj-...`) | `<AI_API_KEY_REDACTED>` |
| Messaging | Slack (`xoxb-...`, `xoxp-...`, etc.) | `<SLACK_TOKEN_REDACTED>` |
| Passwords | `password=`, `passwd=`, `pwd=`, `secret=` params | `password=<PASSWORD_REDACTED>` |

The credential stripping runs **before** PII masking (email/RFC1918 IP redaction) inside `_redact_alert_data()`. Both layers are independently controlled by the same `BLUETEAM_REDACT_PII` guard. The original alert data on disk is never modified.

### GreyNoise Community — Free, No API Key

GreyNoise context lookups (`greynoise_ip_context`) are integrated into the unified server and require no authentication. The Community API classifies IPs as internet scanners (noise), business services (RIOT), or both — with interpretation guidance in the markdown output.

---

## Configuration Reference

All environment variables accepted by the suite. Variables marked **[unified]** apply to all three servers; others are server-specific.

### Performance & Limits [unified]

| Variable | Default | Description |
|---|---|---|
| `BLUETEAM_CHARACTER_LIMIT` | `100000` | Maximum characters per tool response before truncation |
| `BLUETEAM_HTTP_TIMEOUT` | `30.0` | HTTP request timeout in seconds (applies to `_get_http_client()`) |
| `BLUETEAM_VERIFY_SSL` | `true` | SSL certificate verification for the shared HTTP client (set `false` for proxies or mirror endpoints with self-signed certs) |

### CrowdSec Bulk Lookups

| Variable | Default | Description |
|---|---|---|
| `BLUETEAM_BULK_CONCURRENCY` | `5` | Max parallel IP lookups in `crowdsec_ip_reputation_bulk` |

### Wazuh API

| Variable | Default | Description |
|---|---|---|
| `WAZUH_API_URL` | (empty) | Wazuh Manager API base URL (`https://<host>:55000`) |
| `WAZUH_API_USER` | `wazuh-wui` | Wazuh API username |
| `WAZUH_API_PASSWORD` | (empty) | Wazuh API password |
| `WAZUH_API_VERIFY_SSL` | `false` | TLS certificate verification for Wazuh API |

### Wazuh Indexer (OpenSearch)

| Variable | Default | Description |
|---|---|---|
| `WAZUH_INDEXER_URL` | (empty) | OpenSearch base URL (`https://<host>:9200`) |
| `WAZUH_INDEXER_USER` | `admin` | OpenSearch username |
| `WAZUH_INDEXER_PASSWORD` | (empty) | OpenSearch password |
| `WAZUH_INDEXER_VERIFY_SSL` | `false` | TLS certificate verification for indexer |
| `WAZUH_INDEXER_MAX_SIZE` | `10000` | Max documents per page in `_wazuh_indexer_search` |

### Threat Intelligence APIs

| Variable | Default | Description |
|---|---|---|
| `CROWDSEC_API_KEY` | (empty) | CrowdSec CTI API key (required for CrowdSec tools) |
| `ABUSEIPDB_API_KEY` | (empty) | AbuseIPDB API key |
| `VIRUSTOTAL_API_KEY` | (empty) | VirusTotal API key |
| `NETRA_API_KEY` | (empty) | Netra Threat Intelligence API key |
| `NETRA_VERIFY_SSL` | `false` | TLS certificate verification for Netra API (set `true` for production) |

### Transport & Deployment

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | Transport mode: `stdio`, `sse`, or `streamable_http` |
| `MCP_HOST` | `127.0.0.1` | Bind address for SSE/HTTP transports |
| `MCP_PORT` | `8000` | Bind port for SSE/HTTP transports |
| `LOG_LEVEL` | `INFO` | Python logging level |

### Security & Auditing

| Variable | Default | Description |
|---|---|---|
| `BLUETEAM_AUDIT_LOG` | (empty) | Path to JSONL audit log file |
| `BLUETEAM_RATE_LIMIT` | `0` (disabled) | Max tool calls per minute |
| `BLUETEAM_ALLOWED_PATHS` | `/var:/etc:/home:/opt:/usr` | Colon-separated path allowlist for file tools |
| `BLUETEAM_CAPTURE_DIR` | `/tmp` | Output directory for `blueteam_capture_traffic` pcap files |

---

## Quick Start

### 1. On your Defender Host (Ubuntu/Debian)

```bash
git clone https://github.com/INFOKOM-KI/blue-team-soc-mcp.git
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
- **WAZUH_API_URL** — `https://<host>:55000` (if Wazuh is on same host) or `https://<host>:55000`
- **WAZUH_API_USER** — `wazuh-wui` (Wazuh Docker default)
- **WAZUH_API_PASSWORD** — e.g. `MyS3cr37P450r.*-` (Wazuh Docker default)
- **WAZUH_API_VERIFY_SSL** — `false` for self-signed certs
- **WAZUH_INDEXER_URL** — `https://<host>:9200` (if on same host) or `https://<host>:9200`
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
        "-i", "/Users/defence/.ssh/ubuntu-soc",
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

Restart Claude Desktop. You should see all 43 blue-team-mcp tools available.

### 4. Remote Service Deployment (systemd)

For a persistent remote service accessible to multiple MCP clients, run `blue_team_server.py` as a systemd unit:

```ini
# /etc/systemd/system/blue-team-mcp.service
[Unit]
Description=Blue Team MCP Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/blue-team-mcp
Environment="MCP_TRANSPORT=streamable_http"
Environment="MCP_HOST=0.0.0.0"
Environment="MCP_PORT=8000"
ExecStart=/usr/local/bin/mcp-server-blueteam
Restart=on-failure
RestartSec=5

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
*All ten tools support cursor-based pagination — see [Cursor-Based Pagination](#cursor-based-pagination-bulk-data-without-hard-caps). `blueteam_wazuh_indexer_search` and `wazuh_domain_lookup` also support **auto-pagination** via the `max_scanned` parameter for full-period coverage in a single call.*

| Tool | Description |
|------|-------------|
| `blueteam_wazuh_agents` | List all Wazuh agents — paginated via `cursor`/`limit` (up to 10,000/page) |
| `blueteam_wazuh_agents_summary` | Agent count by status (active/disconnected) |
| `blueteam_wazuh_manager_logs` | Manager daemon logs — paginated via `cursor`/`limit` (up to 1,000/page) |
| `blueteam_wazuh_alerts` | Security alerts from alerts.json — paginated via `cursor`/`limit` (up to 2,000/page) |
| `blueteam_wazuh_indexer_search` | Query OpenSearch for agent alerts/events — paginated via `cursor`/`limit` (up to 10,000/page). Set `max_scanned` for auto-pagination. |
| `wazuh_email_lookup` | Find top-N compromised email addresses by scanning `full_log` + `data.account` fields (auto-paginates up to `max_scanned`) |
| `wazuh_domain_lookup` | Search alerts by domain name with cursor pagination and source IP aggregation. Set `max_scanned` for auto-pagination. |
| `wazuh_compromised_emails_analysis` | Correlate compromised emails with attacker IPs, optional Netra enrichment (auto-paginates per batch) |
| `wazuh_alert_timeline` | Time-bucketed alert aggregation using OpenSearch `date_histogram` — covers ALL matching alerts |
| `wazuh_attack_velocity` | Compare two time windows to detect attack acceleration/deceleration — covers ALL matching alerts |

### Threat Intelligence
| Tool | Description |
|------|-------------|
| `blueteam_lookup_ip_abuseipdb` | IP reputation via AbuseIPDB |
| `blueteam_lookup_hash_virustotal` | File hash lookup via VirusTotal |
| `blueteam_lookup_domain_virustotal` | Domain reputation via VirusTotal |

### Netra Threat Intelligence
*Requires `NETRA_API_KEY`*

| Tool | Description |
|------|-------------|
| `netra_ip_analysis` | Multi-source IP analysis aggregating VirusTotal, AbuseIPDB, CrowdSec, IPAPI, and Argus with composite threat score and AI-generated insight |

### CrowdSec CTI
*Requires `CROWDSEC_API_KEY`*

| Tool | Description |
|------|-------------|
| `crowdsec_ip_reputation` | Single IP reputation via CrowdSec CTI Smoke API (behaviors, MITRE ATT&CK, CVEs) |
| `crowdsec_ip_reputation_bulk` | Batch reputation lookup for up to 10 IPs — **parallel execution** via `asyncio.gather()` + semaphore (configurable concurrency) |

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

"Search the Wazuh indexer for all alerts from agent HYDRA-DC in the last 24 hours.
 Use cursor pagination to iterate through all results — don't stop at the first page."

"List every Wazuh agent across the fleet. We have over 1,500 endpoints, so use
 cursor pagination to enumerate them all — then group by OS and status."
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
| `blue_team_server.py` | **Primary** — all 43 tools, all three transports (stdio / SSE / Streamable HTTP) |
| `blue_team_server_crowdsec.py` | Standalone CrowdSec-only server (backward compat) |
| `blue_team_server_greynoise.py` | Standalone GreyNoise-only server (backward compat) |
