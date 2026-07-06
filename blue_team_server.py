#!/usr/bin/env python3
"""
Blue Team MCP Server
A defensive security MCP server for Claude Desktop, mirroring the Kali mcp-kali-server setup but for blue team / defenders.

MAESTRO Framework: Aligned with CSA MAESTRO (Layer 3 Agent Frameworks, Layer 5 Observability, Layer 6 Security & Compliance).

Tools included:
  - Log analysis (auth, syslog, journald, nginx/apache)
  - Network monitoring (open ports, active connections, traffic capture)
  - Threat intelligence (IP/domain reputation via AbuseIPDB, VirusTotal)
  - Fail2ban management (view jails, banned IPs, unban)
  - File integrity checking (AIDE/manual hash comparison)
  - System hardening audit (Lynis, open SUID files, world-writable paths)
  - User & session monitoring (who is logged in, sudo history)
  - CVE / vulnerability lookup

Usage:
  pip install mcp httpx pydantic
  python blue_team_server.py

Claude Desktop config (claude_desktop_config.json):
  {
    "mcpServers": {
      "blue-team-mcp": {
        "command": "ssh",
        "args": ["-i", "/path/to/key", "user@DEFENDER_HOST", "python3 /opt/blue-team-mcp/blue_team_server.py"],
        "transport": "stdio"
      }
    }
  }
"""

from __future__ import annotations
import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Logging - Must go to stderr. stdout is used by the MCP stdio protocol.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("blue_team_mcp")

# Server init

mcp = FastMCP("blue_team_mcp")

# Configuration (set via environment variables)
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
MAX_LOG_LINES = 2000   # safety cap for log reads
TIMEOUT = 30           # seconds for subprocess calls
MAX_GREP_PATTERN_LENGTH = 200   # ReDoS mitigation
BLUETEAM_AUDIT_LOG = os.environ.get("BLUETEAM_AUDIT_LOG", "")
BLUETEAM_RATE_LIMIT = int(os.environ.get("BLUETEAM_RATE_LIMIT", "0"))  # max calls/min, 0=disabled

# Path safety: allowlist for blueteam_hash_file (colon-separated, e.g. /var:/etc:/home:/opt)
ALLOWED_PATH_PREFIXES = [
    p.strip() for p in os.environ.get("BLUETEAM_ALLOWED_PATHS", "/var:/etc:/home:/opt:/usr").split(":")
    if p.strip()
]
# Capture output directory for blueteam_capture_traffic
CAPTURE_OUTPUT_DIR = os.environ.get("BLUETEAM_CAPTURE_DIR", "/tmp")

# Wazuh API (optional - set to enable blueteam_wazuh_* tools)
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "").rstrip("/")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")
WAZUH_API_VERIFY_SSL = os.environ.get("WAZUH_API_VERIFY_SSL", "false").lower() in ("1", "true", "yes")

# Wazuh Indexer / OpenSearch (optional - for blueteam_wazuh_indexer_search; HYDRA-DC events live here)
WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
WAZUH_INDEXER_VERIFY_SSL = os.environ.get("WAZUH_INDEXER_VERIFY_SSL", "false").lower() in ("1", "true", "yes")

# CrowdSec CTI (optional — set CROWDSEC_API_KEY to enable the crowdsec_ip_reputation tools)
CROWDSEC_BASE_URL = "https://cti.api.crowdsec.net"
CROWDSEC_API_KEY_ENV = "CROWDSEC_API_KEY"

# GreyNoise Community (free, no API key required)
GREYNOISE_COMMUNITY_BASE_URL = "https://api.greynoise.io/v3/community"

# Shared HTTP / response config
HTTP_TIMEOUT = 30.0
CHARACTER_LIMIT = int(os.environ.get("BLUETEAM_CHARACTER_LIMIT", "25000"))
_WAZUH_INDEXER_MAX_SIZE = int(os.environ.get("WAZUH_INDEXER_MAX_SIZE", "10000"))
_WAZUH_TOKEN_TTL = 300  # seconds — cache Wazuh JWT for 5 min

# Private / reserved IP ranges — threat-intel tools are for public IPs only
_PRIVATE_NETWORKS = [
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]

# Shared HTTP client with connection pooling
_shared_http_client: Optional[httpx.AsyncClient] = None

async def _get_http_client() -> httpx.AsyncClient:
    """Return a shared httpx.AsyncClient with connection pooling.
    Lazily initialized; reuse across all tool invocations to avoid
    connection-establishment overhead on every call."""
    global _shared_http_client
    if _shared_http_client is None or _shared_http_client.is_closed:
        _shared_http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(HTTP_TIMEOUT),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
        )
    return _shared_http_client


# Cursor utilities for pagination
def _encode_cursor(data: dict) -> str:
    """Encode pagination state as a base64 JSON cursor string."""
    return base64.b64encode(json.dumps(data).encode()).decode()


def _decode_cursor(cursor: str) -> Optional[dict]:
    """Decode a pagination cursor; returns None on invalid/malformed input."""
    try:
        return json.loads(base64.b64decode(cursor).decode())
    except Exception:
        return None


# Wazuh JWT token cache
_wazuh_token: Optional[str] = None
_wazuh_token_expiry: float = 0.0

# Shared enums & formatting utilities
class ResponseFormat(str, Enum):
    """Output format for threat-intel tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"

def _is_private_or_reserved(ip: str) -> bool:
    """Check whether an IP belongs to a private or reserved range (not routable)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETWORKS)

def _handle_api_error(e: Exception, context: str = "") -> str:
    """Consistent, actionable error formatting for all API-based tools."""
    prefix = f"[{context}] " if context else ""
    if isinstance(e, httpx.HTTPStatusError):
        status = e.response.status_code
        if status == 401:
            return f"{prefix}Error: Invalid or missing API key (401). Check your environment variables."
        if status == 404:
            return f"{prefix}Error: No data found for this target (404)."
        if status == 429:
            retry_after = e.response.headers.get("Retry-After")
            hint = f" Retry after {retry_after} seconds." if retry_after else " Retry later."
            return f"{prefix}Error: Rate limit reached (429).{hint}"
        return f"{prefix}Error: API request failed with status {status}."
    if isinstance(e, httpx.TimeoutException):
        return f"{prefix}Error: Request timed out after {HTTP_TIMEOUT}s. Try again."
    if isinstance(e, RuntimeError):
        return f"{prefix}Error: {e}"
    logger.exception("Unexpected error in %s", context)
    return f"{prefix}Error: Unexpected error ({type(e).__name__})."

def _truncate_if_needed(text: str) -> str:
    """Cap response at CHARACTER_LIMIT to keep MCP messages manageable."""
    if len(text) <= CHARACTER_LIMIT:
        return text
    truncated = text[:CHARACTER_LIMIT]
    return (
        truncated
        + f"\n\n... [truncated — response exceeds {CHARACTER_LIMIT} characters, "
        "use a more specific filter]"
    )

# Input validation and sanitization helpers
def _sanitize_regex(pattern: str) -> str:
    """Sanitize grep pattern to mitigate ReDoS. Use simple substring when regex metacharacters present."""
    if not pattern:
        return pattern
    if len(pattern) > MAX_GREP_PATTERN_LENGTH:
        return pattern[:MAX_GREP_PATTERN_LENGTH]
    # If pattern has regex metacharacters that could cause ReDoS, use re.escape for safety
    dangerous = set("+*{?()[]|^$")
    if any(c in pattern for c in dangerous):
        return re.escape(pattern)
    return pattern

def _validate_path(path: str, allowed_prefixes: List[str], allow_symlinks: bool = False) -> tuple[bool, str]:
    """Validate path is under allowed prefixes. Returns (ok, error_msg)."""
    try:
        resolved = Path(path).resolve()
    except Exception:
        return False, "Invalid path"
    if ".." in path:
        return False, "Path traversal (..) not allowed"
    for prefix in allowed_prefixes:
        prefix_path = Path(prefix).resolve()
        try:
            if resolved.relative_to(prefix_path):
                return True, ""
        except ValueError:
            continue
    return False, f"Path not under allowed prefixes: {allowed_prefixes}"

_BPF_SAFE_RE = re.compile(r"^[a-zA-Z0-9\.\s\-\_\:\(\)]+$")
_BPF_FORBIDDEN = (" -w", "-w ", " -r", "-r ", "|", ";", "&&", "||", "`", "$(")

def _validate_bpf_filter(expr: str) -> tuple[bool, str]:
    """Validate BPF filter expression to prevent argument injection."""
    if not expr:
        return True, ""
    if len(expr) > 200:
        return False, "BPF filter too long"
    lower = expr.lower()
    for fb in _BPF_FORBIDDEN:
        if fb in lower or fb in expr:
            return False, "BPF filter contains forbidden characters (no -w, -r, shell meta)"
    if not _BPF_SAFE_RE.match(expr):
        return False, "BPF filter contains invalid characters (use alphanumeric, spaces, port, host, and, or)"
    return True, ""

# Audit logging (optional, Layer 6)
def _audit_log(tool_name: str, params: dict, result_preview: str = "") -> None:
    """Append audit entry to BLUETEAM_AUDIT_LOG if configured."""
    if not BLUETEAM_AUDIT_LOG:
        return
    try:
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "tool": tool_name,
            "params": {k: str(v)[:100] for k, v in params.items() if k not in ("api_key", "key")},
            "result_preview": (result_preview or "")[:200],
        }
        with open(BLUETEAM_AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

# Rate limiting (optional, Layer 3 DoS)
_rate_limit_count = 0
_rate_limit_reset_time = 0.0

def _check_rate_limit() -> bool:
    """Return True if allowed, False if rate limited."""
    if BLUETEAM_RATE_LIMIT <= 0:
        return True
    global _rate_limit_count, _rate_limit_reset_time
    now = time.time()
    if now > _rate_limit_reset_time:
        _rate_limit_count = 0
        _rate_limit_reset_time = now + 60
    _rate_limit_count += 1
    return _rate_limit_count <= BLUETEAM_RATE_LIMIT

# Shared helpers
def _run(cmd: List[str], timeout: int = TIMEOUT) -> Dict[str, Any]:
    """Run a shell command and return stdout/stderr/returncode dict."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"Command timed out after {timeout}s", "returncode": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"Command not found: {cmd[0]}", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


async def _run_async(cmd: List[str], timeout: int = TIMEOUT) -> Dict[str, Any]:
    """Non-blocking wrapper around _run() — offloads subprocess to a thread pool.
    Use in async tool handlers to avoid blocking the event loop."""
    return await asyncio.to_thread(_run, cmd, timeout)

def _tool_not_found(tool: str) -> str:
    return json.dumps({
        "error": f"'{tool}' is not installed or not in PATH.",
        "fix": f"Install it with: sudo apt install {tool}  (Debian/Ubuntu)"
    }, indent=2)

def _tail_file(path: str, lines: int) -> str:
    """Return last N lines of a file, with error handling."""
    p = Path(path)
    if not p.exists():
        return json.dumps({"error": f"File not found: {path}"})
    r = _run(["tail", "-n", str(lines), path])
    return r["stdout"] or r["stderr"]


async def _http_get(url: str, headers: Dict[str, str], params: Dict[str, str] = None) -> Dict:
    client = await _get_http_client()
    resp = await client.get(url, headers=headers, params=params or {})
    resp.raise_for_status()
    return resp.json()

# Wazuh API helper (openWorld - external API calls)
async def _wazuh_get_token() -> Optional[str]:
    """Obtain JWT token from Wazuh API with 300 s TTL cache. Returns None if not configured or auth fails."""
    global _wazuh_token, _wazuh_token_expiry
    if not WAZUH_API_URL or not WAZUH_API_PASSWORD:
        return None
    now = time.monotonic()
    if _wazuh_token and now < _wazuh_token_expiry:
        return _wazuh_token
    try:
        url = f"{WAZUH_API_URL}/security/user/authenticate?raw=true"
        client = await _get_http_client()
        resp = await client.post(
            url,
            auth=(WAZUH_API_USER, WAZUH_API_PASSWORD),
            verify=WAZUH_API_VERIFY_SSL,
        )
        resp.raise_for_status()
        _wazuh_token = resp.text.strip().strip('"')
        _wazuh_token_expiry = now + _WAZUH_TOKEN_TTL
        return _wazuh_token
    except httpx.HTTPStatusError as e:
        logger.warning("Wazuh auth failed: HTTP %s — %s", e.response.status_code, e.response.text[:200])
        _wazuh_token = None
        _wazuh_token_expiry = 0.0
        return None
    except Exception as e:
        logger.warning("Wazuh auth failed: %s", e)
        _wazuh_token = None
        _wazuh_token_expiry = 0.0
        return None

async def _wazuh_api_get(path: str, params: Dict[str, str] = None) -> Dict:
    """Call Wazuh API GET endpoint. path should start with / (e.g. /agents)."""
    if not WAZUH_API_URL or not WAZUH_API_PASSWORD:
        return {"error": "WAZUH_API_URL and WAZUH_API_PASSWORD must be set. See README for Wazuh setup."}
    token = await _wazuh_get_token()
    if not token:
        return {
            "error": "Wazuh API authentication failed",
            "detail": (
                f"Could not authenticate to {WAZUH_API_URL} as '{WAZUH_API_USER}'. "
                "Check credentials and that the Wazuh Manager API is running on port 55000. "
                "If using Wazuh 4.7+, the user may need the 'administrator' role assigned via the Wazuh dashboard."
            ),
        }
    url = f"{WAZUH_API_URL}{path}"
    try:
        client = await _get_http_client()
        resp = await client.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params or {},
            verify=WAZUH_API_VERIFY_SSL,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        return {"error": f"Wazuh API error: {e.response.status_code}", "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": str(e)}

async def _wazuh_indexer_search(
    index_pattern: str,
    agent_name: Optional[str],
    size: int,
    from_: int = 0,
) -> Dict:
    """Query Wazuh Indexer (OpenSearch) for alerts/events. Read-only _search only.
    Supports from_/size pagination for iterative bulk retrieval."""
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return {"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set. See README for Indexer setup."}
    url = f"{WAZUH_INDEXER_URL}/{index_pattern}/_search"
    # Build query: filter by agent.name if provided, else match_all
    if agent_name and agent_name.strip():
        query = {"match": {"agent.name": agent_name.strip()}}
    else:
        query = {"match_all": {}}
    body = {
        "from": from_,
        "size": min(size, _WAZUH_INDEXER_MAX_SIZE),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": query,
    }
    try:
        client = await _get_http_client()
        resp = await client.post(
            url,
            auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
            json=body,
            headers={"Content-Type": "application/json"},
            verify=WAZUH_INDEXER_VERIFY_SSL,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        return {"error": f"Indexer API error: {e.response.status_code}", "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": str(e)}

# CrowdSec CTI helpers
def _get_crowdsec_api_key() -> str:
    """Read CrowdSec CTI API key from environment."""
    key = os.environ.get(CROWDSEC_API_KEY_ENV)
    if not key:
        raise RuntimeError(
            f"Environment variable {CROWDSEC_API_KEY_ENV} is not set. "
            "Set your CrowdSec CTI API key before using crowdsec_ip_reputation tools. "
            "Get a free key at https://www.crowdsec.net/en/user/profile"
        )
    return key

async def _crowdsec_request(path: str) -> dict[str, Any]:
    """Reusable async GET request to the CrowdSec CTI API."""
    headers = {
        "x-api-key": _get_crowdsec_api_key(),
        "accept": "application/json",
        "User-Agent": "blue-team-mcp/1.0.0 (TangerangKota-CSIRT)",
    }
    url = f"{CROWDSEC_BASE_URL}{path}"
    client = await _get_http_client()
    response = await client.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def _format_crowdsec_markdown(ip: str, raw: dict[str, Any]) -> str:
    """Render CrowdSec CTI API response as a human-readable markdown report."""
    if "reputation" not in raw and "attack_details" not in raw:
        return f"# CrowdSec Reputation — {ip}\n\nNo threat data found for this IP (clean)."

    lines = [f"# CrowdSec Reputation — {ip}", ""]
    reputation = raw.get("reputation", "unknown")
    lines.append(f"- **Reputation**: {reputation}")

    if "ip_range_score" in raw:
        lines.append(f"- **IP Range Score**: {raw['ip_range_score']}")
    if "as_name" in raw:
        lines.append(f"- **ASN**: {raw['as_name']}")
    if "history" in raw and isinstance(raw["history"], dict):
        last_seen = raw["history"].get("last_seen")
        first_seen = raw["history"].get("first_seen")
        if last_seen:
            lines.append(f"- **Last Seen**: {last_seen}")
        if first_seen:
            lines.append(f"- **First Seen**: {first_seen}")

    behaviors = raw.get("behaviors") or []
    if behaviors:
        lines.append("")
        lines.append("## Behaviors")
        for b in behaviors:
            name = b.get("name", "unknown")
            label = b.get("label", "")
            lines.append(f"- **{name}**{' — ' + label if label else ''}")

    attack_details = raw.get("attack_details") or []
    if attack_details:
        lines.append("")
        lines.append("## Attack Details")
        for a in attack_details:
            lines.append(f"- {a.get('name', 'unknown')}")

    mitre = raw.get("mitre_techniques") or []
    if mitre:
        lines.append("")
        lines.append("## MITRE ATT&CK Techniques")
        for m in mitre:
            lines.append(f"- {m.get('name', 'unknown')} ({m.get('label', '')})")

    cves = raw.get("cves") or []
    if cves:
        lines.append("")
        lines.append("## Related CVEs")
        for cve in cves:
            lines.append(f"- {cve}")

    return "\n".join(lines)

# CrowdSec CTI input models
class CrowdsecIpReputationInput(BaseModel):
    """Input model for single IP reputation lookup via CrowdSec CTI."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ip: str = Field(
        ...,
        description="Public IPv4 or IPv6 address to check (e.g. '185.220.101.1').",
        min_length=3,
        max_length=45,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for a human-readable report, 'json' for structured data.",
    )

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"'{v}' is not a valid IP address (IPv4/IPv6).") from exc
        return v

class CrowdsecIpReputationBulkInput(BaseModel):
    """Input model for batch IP reputation lookup via CrowdSec CTI."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ips: list[str] = Field(
        ...,
        description="List of public IP addresses to check (max 10 per call to avoid rate limits).",
        min_length=1,
        max_length=10,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for a human-readable report, 'json' for structured data.",
    )

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, v: list[str]) -> list[str]:
        invalid = []
        for ip in v:
            try:
                ipaddress.ip_address(ip.strip())
            except ValueError:
                invalid.append(ip)
        if invalid:
            raise ValueError(f"Invalid IP(s): {', '.join(invalid)}")
        return [ip.strip() for ip in v]

# CROWDSEC CTI TOOLS
@mcp.tool(
    name="crowdsec_ip_reputation",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def crowdsec_ip_reputation(params: CrowdsecIpReputationInput) -> str:
    """
    Check the threat reputation of a public IP address using the CrowdSec CTI Smoke API.

    This tool is READ-ONLY — it queries CrowdSec's threat intelligence database to
    retrieve reputation, observed attack behaviors, related MITRE ATT&CK techniques,
    CVEs exploited from this IP, and first/last-seen history.

    Args:
        params (CrowdsecIpReputationInput): Validated parameters containing:
            - ip (str): Public IPv4/IPv6 address to check (e.g. "185.220.101.1")
            - response_format ('markdown' | 'json'): Output format (default: markdown)

    Returns:
        str: If markdown, a formatted reputation report. If json, an object with fields:
        {
            "ip": str,
            "reputation": str,             # "malicious" | "suspicious" | "safe" | "unknown"
            "as_name": str,                 # optional
            "ip_range_score": int,          # optional
            "behaviors": [{"name": str, "label": str}],
            "attack_details": [{"name": str}],
            "mitre_techniques": [{"name": str, "label": str}],
            "cves": [str],
            "history": {"first_seen": str, "last_seen": str}
        }

    Example usage:
        - Use when: "IP 185.220.101.1 appeared in Wazuh alerts — check its reputation"
        - Don't use when: checking many IPs at once (use crowdsec_ip_reputation_bulk instead)

    Error Handling:
        - "Error: Invalid or missing API key (401)" if CROWDSEC_API_KEY is missing/wrong
        - "Error: Rate limit reached (429)" if API quota is exhausted
        - IP format validation is handled automatically by Pydantic before the request
    """
    try:
        raw = await _crowdsec_request(f"/v2/smoke/{params.ip}")
    except Exception as e:  # noqa: BLE001 — converted to actionable messages below
        return _handle_api_error(e, context="crowdsec_ip_reputation")

    if params.response_format == ResponseFormat.JSON:
        output = {
            "ip": params.ip,
            "reputation": raw.get("reputation", "unknown"),
            "as_name": raw.get("as_name"),
            "ip_range_score": raw.get("ip_range_score"),
            "behaviors": raw.get("behaviors", []),
            "attack_details": raw.get("attack_details", []),
            "mitre_techniques": raw.get("mitre_techniques", []),
            "cves": raw.get("cves", []),
            "history": raw.get("history", {}),
        }
        result = json.dumps(output, indent=2, ensure_ascii=False)
    else:
        result = _format_crowdsec_markdown(params.ip, raw)

    return _truncate_if_needed(result)

@mcp.tool(
    name="crowdsec_ip_reputation_bulk",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def crowdsec_ip_reputation_bulk(params: CrowdsecIpReputationBulkInput) -> str:
    """
    Check threat reputation for multiple public IPs at once (max 10) using CrowdSec CTI.

    This tool is READ-ONLY. Useful when triaging a list of IPs from logs/alerts
    (e.g., top talkers in firewall logs) that need reputation-based prioritization.

    Args:
        params (CrowdsecIpReputationBulkInput): Validated parameters containing:
            - ips (list[str]): 1-10 IP addresses
            - response_format ('markdown' | 'json'): Output format (default: markdown)

    Returns:
        str: Per-IP summary. Markdown format is a bullet list; JSON format is an array
        of objects with the same schema as crowdsec_ip_reputation per element, plus an
        optional "error" field (string) if the lookup for a specific IP failed.

    Example usage:
        - Use when: "I have 5 suspicious IPs from yesterday's alerts — check them all"
        - Don't use when: only 1 IP (use crowdsec_ip_reputation — simpler)

    Error Handling:
        - Failure for one IP does not abort the entire batch — per-IP errors are
          reported inline in the results rather than stopping the process.
    """
    results: list[dict[str, Any]] = []
    for ip in params.ips:
        try:
            raw = await _crowdsec_request(f"/v2/smoke/{ip}")
            results.append(
                {
                    "ip": ip,
                    "reputation": raw.get("reputation", "unknown"),
                    "behaviors": raw.get("behaviors", []),
                    "cves": raw.get("cves", []),
                }
            )
        except Exception as e:  # noqa: BLE001
            results.append({"ip": ip, "error": _handle_api_error(e, context=ip)})

    if params.response_format == ResponseFormat.JSON:
        result = json.dumps(results, indent=2, ensure_ascii=False)
    else:
        lines = ["# CrowdSec Bulk Reputation Lookup", ""]
        for r in results:
            if "error" in r:
                lines.append(f"- **{r['ip']}** — ⚠️ {r['error']}")
                continue
            behaviors_str = ", ".join(b.get("name", "") for b in r["behaviors"]) or "-"
            lines.append(
                f"- **{r['ip']}** — reputation: `{r['reputation']}` | behaviors: {behaviors_str}"
            )
        result = "\n".join(lines)

    return _truncate_if_needed(result)

# GreyNoise Community helpers
async def _greynoise_community_request(ip: str) -> dict[str, Any]:
    """Reusable async GET request to the GreyNoise Community API (no auth)."""
    headers = {
        "accept": "application/json",
        "User-Agent": "blue-team-mcp/1.0.0 (TangerangKota-CSIRT)",
    }
    url = f"{GREYNOISE_COMMUNITY_BASE_URL}/{ip}"
    client = await _get_http_client()
    response = await client.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def _format_greynoise_markdown(ip: str, raw: dict[str, Any]) -> str:
    """Render GreyNoise Community API response as a human-readable markdown report."""
    lines = [f"# GreyNoise Community — {ip}", ""]

    message = raw.get("message", "")
    if message and message != "Success":
        lines.append(f"> ⚠️ {message}")
        lines.append("")

    lines.append(f"- **IP**: {raw.get('ip', ip)}")

    # Noise
    noise = raw.get("noise")
    if noise is True:
        lines.append("- **Noise**: ✅ Yes — this IP has been observed scanning the internet")
    elif noise is False:
        lines.append("- **Noise**: ❌ No — this IP has not been observed scanning")
    else:
        lines.append("- **Noise**: unknown")

    # RIOT (business service)
    riot = raw.get("riot")
    if riot is True:
        lines.append("- **RIOT**: ✅ Yes — this IP is a known business service (trusted)")
    elif riot is False:
        lines.append("- **RIOT**: ❌ No — not a known business service")
    else:
        lines.append("- **RIOT**: unknown")

    classification = raw.get("classification", "unknown")
    lines.append(f"- **Classification**: `{classification}`")

    name = raw.get("name")
    if name and name != "unknown":
        lines.append(f"- **Organization**: {name}")
    else:
        lines.append("- **Organization**: unknown")

    last_seen = raw.get("last_seen")
    if last_seen:
        lines.append(f"- **Last Seen**: {last_seen}")

    link = raw.get("link")
    if link:
        lines.append(f"- **Link**: {link}")

    # Quick interpretation
    lines.append("")
    lines.append("## Interpretation")
    if noise and not riot:
        lines.append(
            "This IP is a **known internet scanner** and is NOT a trusted business service. "
            "Activity from this IP should be treated as background noise — investigate "
            "only if it is targeting unusual ports or generating application-level events."
        )
    elif riot and not noise:
        lines.append(
            "This IP is a **known business service** (e.g., CDN, cloud provider, SaaS). "
            "Activity is likely legitimate and can generally be ignored in triage."
        )
    elif noise and riot:
        lines.append(
            "This IP is BOTH a known scanner AND a known business service — unusual. "
            "Review the GreyNoise Visualizer link for full context."
        )
    else:
        lines.append(
            "No scanner or business-service data available. The IP may be benign, "
            "or it may not have been observed by GreyNoise sensors yet."
        )

    return "\n".join(lines)

# GreyNoise Community input model
class GreynoiseIpContextInput(BaseModel):
    """Input model for GreyNoise Community IP context lookup."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ip: str = Field(
        ...,
        description="Public IPv4 or IPv6 address to check against GreyNoise (e.g. '71.6.135.131').",
        min_length=3,
        max_length=45,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for a human-readable report, 'json' for structured data.",
    )

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"'{v}' is not a valid IP address (IPv4/IPv6).") from exc
        return v

# GREYNOISE COMMUNITY TOOL
@mcp.tool(
    name="greynoise_ip_context",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def greynoise_ip_context(params: GreynoiseIpContextInput) -> str:
    """
    Check whether a public IP address is a known internet scanner or business service
    using the GreyNoise Community API (free, no auth required).

    This tool is READ-ONLY — it queries GreyNoise's internet-wide sensor data to
    determine whether an IP has been observed scanning (noise), is a trusted business
    service (RIOT), or both. SOC analysts use this to filter out background noise
    from triage queues and focus on truly suspicious activity.

    Args:
        params (GreynoiseIpContextInput): Validated parameters containing:
            - ip (str): Public IPv4/IPv6 address to check (e.g. "71.6.135.131")
            - response_format ('markdown' | 'json'): Output format (default: markdown)

    Returns:
        str: If markdown, a formatted report with interpretation guidance. If json:
        {
            "ip": str,
            "noise": bool,           # true if IP has been observed scanning
            "riot": bool,            # true if IP is a known business service
            "classification": str,   # "malicious" | "benign" | "unknown"
            "name": str,             # organization name
            "link": str,             # URL to GreyNoise Visualizer
            "last_seen": str,        # date last observed (YYYY-MM-DD)
            "message": str           # status message (e.g. "Success")
        }

    Example usage:
        - Use when: "I see 71.6.135.131 in my firewall logs — is it just a scanner?"
        - Use when: "Triage suspicious IPs — filter out known noise first"
        - Don't use when: you need full context (actors, CVEs, tags) — the Community
          API is a lightweight subset; use the full GreyNoise API for deep dives.

    Error Handling:
        - "Error: No data found for this target (404)" — IP hasn't been observed
        - "Error: Rate limit reached (429)" — back off per GreyNoise fair-use policy
        - IP format validation is handled automatically by Pydantic before the request
    """
    try:
        raw = await _greynoise_community_request(params.ip)
    except Exception as e:  # noqa: BLE001 — converted to actionable messages below
        return _handle_api_error(e, context="greynoise_ip_context")

    if params.response_format == ResponseFormat.JSON:
        output = {
            "ip": raw.get("ip", params.ip),
            "noise": raw.get("noise"),
            "riot": raw.get("riot"),
            "classification": raw.get("classification", "unknown"),
            "name": raw.get("name"),
            "link": raw.get("link"),
            "last_seen": raw.get("last_seen"),
            "message": raw.get("message"),
        }
        result = json.dumps(output, indent=2, ensure_ascii=False)
    else:
        result = _format_greynoise_markdown(params.ip, raw)

    return _truncate_if_needed(result)

# LOG ANALYSIS
class LogInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    lines: int = Field(default=200, description="Number of recent lines to return", ge=1, le=MAX_LOG_LINES)
    grep: Optional[str] = Field(default=None, max_length=MAX_GREP_PATTERN_LENGTH, description="Optional keyword/regex to filter lines (case-insensitive)")

@mcp.tool(
    name="blueteam_read_auth_log",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_read_auth_log(params: LogInput) -> str:
    """Read and optionally filter /var/log/auth.log for SSH, sudo, and PAM events.

    Args:
        params.lines (int): How many tail lines to read (default 200, max 2000)
        params.grep (str, optional): Filter to lines containing this pattern

    Returns:
        str: Matching log lines or error JSON
    """
    log_path = "/var/log/auth.log"
    # Fallback for systems using journald only
    if not Path(log_path).exists():
        cmd = ["journalctl", "-u", "ssh", "-n", str(params.lines), "--no-pager"]
        if params.grep:
            cmd += ["--grep", params.grep]
        r = _run(cmd)
        return r["stdout"] or r["stderr"]

    content = _tail_file(log_path, params.lines)
    if params.grep:
        safe_grep = _sanitize_regex(params.grep)
        lines = [l for l in content.splitlines() if re.search(safe_grep, l, re.IGNORECASE)]
        return "\n".join(lines) if lines else f"No lines matched filter: {params.grep}"
    return content

@mcp.tool(
    name="blueteam_read_syslog",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_read_syslog(params: LogInput) -> str:
    """Read /var/log/syslog or journalctl for general system events.

    Args:
        params.lines (int): Lines to return
        params.grep (str, optional): Filter pattern

    Returns:
        str: Log content
    """
    for path in ["/var/log/syslog", "/var/log/messages"]:
        if Path(path).exists():
            content = _tail_file(path, params.lines)
            if params.grep:
                safe_grep = _sanitize_regex(params.grep)
                lines = [l for l in content.splitlines() if re.search(safe_grep, l, re.IGNORECASE)]
                return "\n".join(lines) if lines else f"No matches for: {params.grep}"
            return content
    # Fallback to journalctl
    cmd = ["journalctl", "-n", str(params.lines), "--no-pager"]
    if params.grep:
        cmd += ["--grep", params.grep]
    r = _run(cmd)
    return r["stdout"] or r["stderr"]

class WebLogInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    server: str = Field(default="nginx", description="Web server: 'nginx' or 'apache'")
    log_type: str = Field(default="access", description="Log type: 'access' or 'error'")
    lines: int = Field(default=200, ge=1, le=MAX_LOG_LINES)
    grep: Optional[str] = Field(default=None, max_length=MAX_GREP_PATTERN_LENGTH, description="Optional filter pattern")

@mcp.tool(
    name="blueteam_read_web_log",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_read_web_log(params: WebLogInput) -> str:
    """Read nginx or Apache access/error logs. Great for spotting web attacks.

    Args:
        params.server: 'nginx' or 'apache'
        params.log_type: 'access' or 'error'
        params.lines: Lines to read
        params.grep: Optional filter

    Returns:
        str: Log lines
    """
    paths = {
        "nginx": {
            "access": "/var/log/nginx/access.log",
            "error": "/var/log/nginx/error.log",
        },
        "apache": {
            "access": "/var/log/apache2/access.log",
            "error": "/var/log/apache2/error.log",
        },
    }
    server = params.server.lower()
    if server not in paths:
        return json.dumps({"error": f"Unknown server '{params.server}'. Use 'nginx' or 'apache'."})
    log_type = params.log_type.lower()
    if log_type not in paths[server]:
        return json.dumps({"error": f"Unknown log type '{params.log_type}'. Use 'access' or 'error'."})

    path = paths[server][log_type]
    content = _tail_file(path, params.lines)
    if params.grep:
        safe_grep = _sanitize_regex(params.grep)
        lines = [l for l in content.splitlines() if re.search(safe_grep, l, re.IGNORECASE)]
        return "\n".join(lines) if lines else f"No matches for: {params.grep}"
    return content

class JournalInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    unit: Optional[str] = Field(default=None, max_length=64, description="Systemd unit name, e.g. 'sshd', 'nginx', 'cron'")
    since: Optional[str] = Field(default="1 hour ago", max_length=64, description="Time range, e.g. '2 hours ago', '2024-01-15 10:00'")
    lines: int = Field(default=200, ge=1, le=MAX_LOG_LINES)
    grep: Optional[str] = Field(default=None, max_length=MAX_GREP_PATTERN_LENGTH)

@mcp.tool(
    name="blueteam_journalctl",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_journalctl(params: JournalInput) -> str:
    """Query systemd journal for any service. Useful for services without flat log files.

    Args:
        params.unit: Systemd unit (optional — omit for all units)
        params.since: Time range string
        params.lines: Max lines
        params.grep: Filter pattern

    Returns:
        str: Journal output
    """
    cmd = ["journalctl", "--no-pager", "-n", str(params.lines)]
    if params.unit:
        cmd += ["-u", params.unit]
    if params.since:
        cmd += ["--since", params.since]
    if params.grep:
        cmd += ["--grep", params.grep]
    r = _run(cmd)
    return r["stdout"] or r["stderr"]

# NETWORK MONITORING
@mcp.tool(
    name="blueteam_list_listening_ports",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_list_listening_ports() -> str:
    """List all TCP/UDP ports currently listening, with owning process.
    Equivalent to 'ss -tulpn'. Identifies unexpected services.

    Returns:
        str: Port table with process names and PIDs
    """
    r = _run(["ss", "-tulpn"])
    if r["returncode"] != 0:
        r = _run(["netstat", "-tulpn"])
    return r["stdout"] or r["stderr"]


@mcp.tool(
    name="blueteam_list_connections",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_list_connections() -> str:
    """List all established TCP connections with remote IPs and local processes.
    Useful for spotting unexpected outbound connections (beaconing, exfil).

    Returns:
        str: Active connection table
    """
    r = _run(["ss", "-tnp", "state", "established"])
    if r["returncode"] != 0:
        r = _run(["netstat", "-tnp"])
    return r["stdout"] or r["stderr"]


class CaptureInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    interface: str = Field(default="eth0", max_length=32, description="Network interface to capture on")
    count: int = Field(default=100, description="Number of packets to capture", ge=1, le=5000)
    filter_expr: Optional[str] = Field(default=None, max_length=200, description="BPF filter expression, e.g. 'port 80', 'host 10.0.0.5'")
    output_file: Optional[str] = Field(default=None, max_length=256, description="Optional path to save .pcap file (must be under CAPTURE_OUTPUT_DIR)")


@mcp.tool(
    name="blueteam_capture_traffic",
    annotations={"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True}
)
async def blueteam_capture_traffic(params: CaptureInput) -> str:
    """Capture live network traffic using tcpdump. Requires root or CAP_NET_RAW.
    Read-only for packet inspection; writes pcap files when output_file is set.
    Makes network I/O (openWorldHint).

    Args:
        params.interface: Network interface
        params.count: Packet count to capture then stop
        params.filter_expr: BPF filter (optional)
        params.output_file: Save pcap to this path (optional, under CAPTURE_OUTPUT_DIR)

    Returns:
        str: Packet summary or path to saved pcap
    """
    if not _check_rate_limit():
        return json.dumps({"error": "Rate limit exceeded"})
    if not shutil.which("tcpdump"):
        return _tool_not_found("tcpdump")
    if params.filter_expr:
        ok, err = _validate_bpf_filter(params.filter_expr)
        if not ok:
            return json.dumps({"error": err})
    output_path = params.output_file
    if output_path:
        if not output_path.startswith("/"):
            output_path = os.path.join(CAPTURE_OUTPUT_DIR, output_path)
        ok, err = _validate_path(output_path, [CAPTURE_OUTPUT_DIR])
        if not ok:
            return json.dumps({"error": f"output_file must be under {CAPTURE_OUTPUT_DIR}: {err}"})

    cmd = ["tcpdump", "-i", params.interface, "-c", str(params.count), "-nn", "-q"]
    if params.filter_expr:
        cmd.append(params.filter_expr)
    if output_path:
        cmd += ["-w", output_path]

    r = _run(cmd, timeout=60)
    result = r["stdout"] + r["stderr"]
    if output_path and r["returncode"] == 0:
        result = json.dumps({"status": "captured", "file": output_path, "packets": params.count})
    _audit_log("blueteam_capture_traffic", {"interface": params.interface, "count": params.count}, result[:200])
    return result

# WAZUH SIEM
class WazuhAgentsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    limit: int = Field(default=100, description="Agents per page", ge=1, le=10000)
    cursor: Optional[str] = Field(
        default=None,
        description="Pagination cursor from previous response (next_cursor). Omit for first page.",
    )

@mcp.tool(
    name="blueteam_wazuh_agents",
    annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}
)
async def blueteam_wazuh_agents(params: WazuhAgentsInput) -> str:
    """List Wazuh agents with cursor pagination — one page per call.
    Pass the returned next_cursor back as the cursor parameter for the next page.
    Requires WAZUH_API_URL and WAZUH_API_PASSWORD.

    Args:
        params.limit: Agents per page (default 100, max 10000)
        params.cursor: next_cursor from previous response (omit for first page)

    Returns:
        str: JSON with agents, total, offset, limit, and next_cursor
    """
    offset = 0
    if params.cursor:
        decoded = _decode_cursor(params.cursor)
        if decoded:
            offset = decoded.get("offset", 0)

    data = await _wazuh_api_get("/agents", {
        "offset": str(offset),
        "limit": str(params.limit),
        "pretty": "true",
    })
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)
    items = data.get("data", {}).get("affected_items", [])
    total = data.get("data", {}).get("total_affected_items", len(items))
    summary = [{
        "id": a.get("id"),
        "name": a.get("name"),
        "ip": a.get("ip"),
        "status": a.get("status"),
        "os": a.get("os", {}).get("name") if isinstance(a.get("os"), dict) else a.get("os"),
        "version": a.get("version"),
    } for a in items]

    next_offset = offset + len(items)
    next_cursor = _encode_cursor({"offset": next_offset}) if next_offset < total else None

    return json.dumps({
        "agents": summary,
        "total": total,
        "offset": offset,
        "limit": params.limit,
        "next_cursor": next_cursor,
    }, indent=2)

@mcp.tool(
    name="blueteam_wazuh_agents_summary",
    annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}
)
async def blueteam_wazuh_agents_summary() -> str:
    """Get Wazuh agent count by status (active, disconnected, pending, never_connected).
    Quick overview of agent health.

    Returns:
        str: JSON with counts per status
    """
    data = await _wazuh_api_get("/agents/summary/status")
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)
    return json.dumps(data.get("data", data), indent=2)

# Wazuh 4.x API uses "tag" (not "type") to filter manager logs by component
_WAZUH_LOG_TAG = {
    "alerts": "wazuh-analysisd",   # analysis daemon processes events/alerts
    "api": "wazuh-api",
    "cluster": "wazuh-clusterd",
    "integrations": "wazuh-integratord",
}


class WazuhLogsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    log_type: str = Field(default="alerts", description="Log type: alerts, api, cluster, integrations")
    limit: int = Field(default=50, description="Max log entries per page", ge=1, le=1000)
    cursor: Optional[str] = Field(
        default=None,
        description="Pagination cursor from previous response (next_cursor). Omit for first page.",
    )


@mcp.tool(
    name="blueteam_wazuh_manager_logs",
    annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}
)
async def blueteam_wazuh_manager_logs(params: WazuhLogsInput) -> str:
    """Fetch Wazuh manager logs with cursor pagination — one page per call.
    Pass the returned next_cursor back as cursor for the next page.
    Compatible with Wazuh 4.x API (uses 'tag' parameter).

    Args:
        params.log_type: alerts, api, cluster, or integrations
        params.limit: Max entries per page (default 50, max 1000)
        params.cursor: next_cursor from previous response (omit for first page)

    Returns:
        str: JSON with logs, total, offset, limit, and next_cursor
    """
    valid = ("alerts", "api", "cluster", "integrations")
    if params.log_type not in valid:
        return json.dumps({"error": f"log_type must be one of: {valid}"})

    offset = 0
    if params.cursor:
        decoded = _decode_cursor(params.cursor)
        if decoded:
            offset = decoded.get("offset", 0)

    api_params = {"offset": str(offset), "limit": str(params.limit), "pretty": "true"}
    tag = _WAZUH_LOG_TAG.get(params.log_type)
    if tag:
        api_params["tag"] = tag
    # Never send "type" - Wazuh 4.x only accepts "tag"; "type" causes 400
    api_params.pop("type", None)
    data = await _wazuh_api_get("/manager/logs", api_params)
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)

    items = data.get("data", {}).get("affected_items", data.get("data", []))
    if isinstance(items, dict):
        items = [items]
    total = data.get("data", {}).get("total_affected_items", len(items))

    next_offset = offset + len(items)
    next_cursor = _encode_cursor({"offset": next_offset}) if next_offset < total else None

    return json.dumps({
        "logs": items,
        "total": total,
        "offset": offset,
        "limit": params.limit,
        "next_cursor": next_cursor,
    }, indent=2)


# Path to Wazuh alerts file (on the host where MCP runs; must be Wazuh manager or have mounts)
_WAZUH_ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"
_WAZUH_ALERTS_MAX_LINES = 2000  # safety cap


class WazuhAlertsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    agent_name: Optional[str] = Field(default=None, max_length=64, description="Filter by agent name (e.g. HYDRA-DC)")
    limit: int = Field(default=100, description="Max alerts per page", ge=1, le=2000)
    cursor: Optional[str] = Field(
        default=None,
        description="Pagination cursor from previous response (next_cursor). Omit for first page.",
    )


@mcp.tool(
    name="blueteam_wazuh_alerts",
    annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}
)
async def blueteam_wazuh_alerts(params: WazuhAlertsInput) -> str:
    """Read security alerts from Wazuh alerts.json with cursor pagination.
    Use when the MCP runs on the Wazuh manager host (or has /var/ossec/logs/alerts mounted).
    Returns one page per call. Pass next_cursor back as cursor for the next page.

    Args:
        params.agent_name: Optional filter by agent name (e.g. HYDRA-DC)
        params.limit: Max alerts per page (default 100, max 2000)
        params.cursor: next_cursor from previous response (omit for first page)

    Returns:
        str: JSON with alerts, count, scanned, next_cursor
    """
    ok, err = _validate_path(_WAZUH_ALERTS_PATH, ALLOWED_PATH_PREFIXES)
    if not ok:
        return json.dumps({"error": err})
    p = Path(_WAZUH_ALERTS_PATH)
    if not p.exists():
        return json.dumps({
            "error": "alerts.json not found on this host",
            "path": _WAZUH_ALERTS_PATH,
            "hint": "This tool runs on the MCP host. Alerts live on the Wazuh manager. "
                    "If Wazuh is on another host, use the indexer/OpenSearch API or run the command there directly."
        }, indent=2)

    # Decode cursor to find how many lines were already scanned
    skip_lines = 0
    if params.cursor:
        decoded = _decode_cursor(params.cursor)
        if decoded:
            skip_lines = decoded.get("scanned", 0)

    # Read from tail — fetch enough lines to cover skip + limit with filtering overhead
    page_size = min((skip_lines + params.limit) * 3, _WAZUH_ALERTS_MAX_LINES)
    r = await _run_async(["tail", "-n", str(page_size), _WAZUH_ALERTS_PATH])
    if r.get("returncode", 0) != 0:
        return json.dumps({"error": "Failed to read alerts", "stderr": r.get("stderr", "")})

    alerts = []
    agent_filter = (params.agent_name or "").strip()
    scanned = 0
    for line in (r.get("stdout") or "").strip().splitlines():
        scanned += 1
        # Skip already-returned lines
        if scanned <= skip_lines:
            continue
        if len(alerts) >= params.limit:
            break
        line = line.strip()
        if not line:
            continue
        try:
            a = json.loads(line)
            if agent_filter:
                agent = (a.get("agent") or {})
                if isinstance(agent, dict):
                    name = agent.get("name") or agent.get("id", "")
                else:
                    name = str(agent)
                if agent_filter.lower() not in (name or "").lower():
                    continue
            alerts.append(a)
        except json.JSONDecodeError:
            continue

    next_cursor = _encode_cursor({"scanned": scanned}) if len(alerts) >= params.limit else None

    return json.dumps({
        "alerts": alerts,
        "count": len(alerts),
        "next_cursor": next_cursor,
    }, indent=2)


# Wazuh Indexer index patterns (OpenSearch)
_WAZUH_INDEX_PATTERNS = {
    "alerts": "wazuh-alerts-*",
    "events": "wazuh-events-*",
    "vulnerabilities": "wazuh-states-vulnerabilities-*",
}

# Agent name: alphanumeric, hyphen, underscore, dot only (prevents injection)
_AGENT_NAME_SAFE_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

class WazuhIndexerSearchInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    agent_name: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Agent name to filter (e.g. 'HYDRA-DC'). Leave empty to search all agents.",
    )
    index_type: str = Field(default="alerts", description="Index: alerts, events, or vulnerabilities")
    limit: int = Field(default=100, description="Max docs to return per page", ge=1, le=10000)
    cursor: Optional[str] = Field(
        default=None,
        description="Pagination cursor from previous response (next_cursor). Omit for first page.",
    )

    @field_validator("agent_name")
    @classmethod
    def validate_agent_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                return None
            if len(v) > 64:
                raise ValueError("agent_name too long (max 64)")
            if not _AGENT_NAME_SAFE_RE.match(v):
                raise ValueError("agent_name: use only letters, numbers, hyphen, underscore, dot")
        return v

@mcp.tool(
    name="blueteam_wazuh_indexer_search",
    annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}
)
async def blueteam_wazuh_indexer_search(params: WazuhIndexerSearchInput) -> str:
    """Query Wazuh Indexer (OpenSearch) for alerts/events by agent with cursor pagination.
    Use for HYDRA-DC Windows events and security alerts stored in OpenSearch.
    Requires WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD (port 9200).

    Returns one page per call. Pass the returned next_cursor back as the cursor
    parameter to fetch the next page. next_cursor is null when all results are exhausted.

    Args:
        params.agent_name: Agent name (e.g. HYDRA-DC)
        params.index_type: alerts (default), events, or vulnerabilities
        params.limit: Max documents per page (default 100, max 10000)
        params.cursor: next_cursor from previous response (omit for first page)

    Returns:
        str: JSON with documents, total, from, size, count, and next_cursor
    """
    if params.index_type not in _WAZUH_INDEX_PATTERNS:
        return json.dumps({"error": f"index_type must be one of: {list(_WAZUH_INDEX_PATTERNS)}"})
    index_pattern = _WAZUH_INDEX_PATTERNS[params.index_type]

    # Decode pagination cursor
    from_ = 0
    if params.cursor:
        decoded = _decode_cursor(params.cursor)
        if decoded:
            from_ = decoded.get("from", 0)

    data = await _wazuh_indexer_search(
        index_pattern=index_pattern,
        agent_name=params.agent_name,
        size=params.limit,
        from_=from_,
    )
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)
    hits = data.get("hits", {})
    total = hits.get("total", {})
    total_val = total.get("value", 0) if isinstance(total, dict) else total
    docs = [h.get("_source", h) for h in hits.get("hits", [])]

    # Build next cursor
    next_offset = from_ + len(docs)
    next_cursor = _encode_cursor({"from": next_offset}) if next_offset < total_val else None

    return json.dumps({
        "total": total_val,
        "count": len(docs),
        "from": from_,
        "size": params.limit,
        "next_cursor": next_cursor,
        "documents": docs,
    }, indent=2)

# THREAT INTELLIGENCE
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[\da-fA-F:]+$")

class IPInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: str = Field(..., max_length=45, description="IPv4 or IPv6 address to look up")
    max_age_days: int = Field(default=90, description="Only return reports from the last N days", ge=1, le=365)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        if not v or len(v) > 45:
            raise ValueError("Invalid IP format or length")
        if _IPV4_RE.match(v) or _IPV6_RE.match(v):
            return v
        raise ValueError("Invalid IP format")


@mcp.tool(
    name="blueteam_lookup_ip_abuseipdb",
    annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}
)
async def blueteam_lookup_ip_abuseipdb(params: IPInput) -> str:
    """Check an IP address against AbuseIPDB for known malicious activity reports.
    Requires ABUSEIPDB_API_KEY environment variable.

    Args:
        params.ip: IP address to check
        params.max_age_days: Lookback window in days

    Returns:
        str: JSON with abuse confidence score, report count, country, ISP, usage type
    """
    if not ABUSEIPDB_API_KEY:
        return json.dumps({
            "error": "ABUSEIPDB_API_KEY not set",
            "fix": "Set environment variable: export ABUSEIPDB_API_KEY=your_key_here",
            "get_key": "https://www.abuseipdb.com/account/api"
        })
    try:
        data = await _http_get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": params.ip, "maxAgeInDays": str(params.max_age_days), "verbose": ""}
        )
        d = data.get("data", {})
        return json.dumps({
            "ip": d.get("ipAddress"),
            "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "last_reported": d.get("lastReportedAt"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "usage_type": d.get("usageType"),
            "domain": d.get("domain"),
            "is_tor": d.get("isTor"),
            "is_vpn": d.get("isPublic"),
        }, indent=2)
    except httpx.HTTPStatusError as e:
        return json.dumps({"error": f"AbuseIPDB API error: {e.response.status_code}", "detail": e.response.text})
    except Exception as e:
        return json.dumps({"error": str(e)})


_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")

class HashInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    hash_value: str = Field(..., max_length=64, description="MD5 (32), SHA1 (40), or SHA256 (64) hash hex")

    @field_validator("hash_value")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        if not _HASH_RE.match(v) or len(v) not in (32, 40, 64):
            raise ValueError("Hash must be 32 (MD5), 40 (SHA1), or 64 (SHA256) hex chars")
        return v


@mcp.tool(
    name="blueteam_lookup_hash_virustotal",
    annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}
)
async def blueteam_lookup_hash_virustotal(params: HashInput) -> str:
    """Check a file hash against VirusTotal to see if it's known malware.
    Requires VIRUSTOTAL_API_KEY environment variable.

    Args:
        params.hash_value: MD5/SHA1/SHA256 of the file

    Returns:
        str: JSON with detection ratio, malware names, and scan date
    """
    if not VIRUSTOTAL_API_KEY:
        return json.dumps({
            "error": "VIRUSTOTAL_API_KEY not set",
            "fix": "Set environment variable: export VIRUSTOTAL_API_KEY=your_key_here",
            "get_key": "https://www.virustotal.com/gui/my-apikey"
        })
    try:
        data = await _http_get(
            f"https://www.virustotal.com/api/v3/files/{params.hash_value}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}
        )
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})
        # Only include detections (positives)
        detections = {
            engine: r["result"]
            for engine, r in results.items()
            if r.get("category") == "malicious"
        }
        return json.dumps({
            "hash": params.hash_value,
            "name": attrs.get("meaningful_name"),
            "type": attrs.get("type_description"),
            "size_bytes": attrs.get("size"),
            "first_seen": attrs.get("first_submission_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "detections": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            "malware_names": detections,
        }, indent=2)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return json.dumps({"result": "Not found in VirusTotal — hash is unknown or clean"})
        return json.dumps({"error": f"VirusTotal API error: {e.response.status_code}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


class DomainInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    domain: str = Field(..., max_length=253, description="Domain name to look up, e.g. 'example.com'")

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        if not v or len(v) > 253:
            raise ValueError("Invalid domain length")
        if ".." in v:
            raise ValueError("Invalid domain format")
        return v


@mcp.tool(
    name="blueteam_lookup_domain_virustotal",
    annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}
)
async def blueteam_lookup_domain_virustotal(params: DomainInput) -> str:
    """Check a domain against VirusTotal for malicious reputation.

    Args:
        params.domain: Domain to check

    Returns:
        str: JSON with reputation score and detection details
    """
    if not VIRUSTOTAL_API_KEY:
        return json.dumps({"error": "VIRUSTOTAL_API_KEY not set. See blueteam_lookup_hash_virustotal for setup."})
    try:
        data = await _http_get(
            f"https://www.virustotal.com/api/v3/domains/{params.domain}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}
        )
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return json.dumps({
            "domain": params.domain,
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories", {}),
            "detections": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "whois": attrs.get("whois", "")[:500],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})



# FAIL2BAN
@mcp.tool(
    name="blueteam_fail2ban_status",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_fail2ban_status() -> str:
    """List all active fail2ban jails and their ban counts.

    Returns:
        str: Jail list with banned IP counts
    """
    if not shutil.which("fail2ban-client"):
        return _tool_not_found("fail2ban")
    r = _run(["fail2ban-client", "status"])
    return r["stdout"] or r["stderr"]


class JailInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    jail: str = Field(..., description="Jail name, e.g. 'sshd', 'nginx-http-auth'")


@mcp.tool(
    name="blueteam_fail2ban_jail_status",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_fail2ban_jail_status(params: JailInput) -> str:
    """Get detailed status of a specific fail2ban jail, including all banned IPs.

    Args:
        params.jail: Jail name

    Returns:
        str: Jail stats and list of currently banned IPs
    """
    if not shutil.which("fail2ban-client"):
        return _tool_not_found("fail2ban")
    r = _run(["fail2ban-client", "status", params.jail])
    return r["stdout"] or r["stderr"]


class UnbanInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    jail: str = Field(..., max_length=64, description="Jail name")
    ip: str = Field(..., max_length=45, description="IP address to unban")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        if not v or len(v) > 45:
            raise ValueError("Invalid IP format or length")
        if _IPV4_RE.match(v) or _IPV6_RE.match(v):
            return v
        raise ValueError("Invalid IP format")


@mcp.tool(
    name="blueteam_fail2ban_unban",
    annotations={"readOnlyHint": False, "destructiveHint": True}
)
async def blueteam_fail2ban_unban(params: UnbanInput) -> str:
    """Unban an IP address from a specific fail2ban jail.
    DESTRUCTIVE: Modifies security state (removes ban).

    Args:
        params.jail: Jail name
        params.ip: IP address to unban

    Returns:
        str: Result of unban operation
    """
    if not _check_rate_limit():
        return json.dumps({"error": "Rate limit exceeded"})
    if not shutil.which("fail2ban-client"):
        return _tool_not_found("fail2ban")
    r = _run(["fail2ban-client", "set", params.jail, "unbanip", params.ip])
    out = r["stdout"] or r["stderr"]
    _audit_log("blueteam_fail2ban_unban", {"jail": params.jail, "ip": params.ip}, out[:200])
    return out



# FILE INTEGRITY
class HashFileInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., max_length=4096, description="Absolute path to file to hash (must be under /, /var, /etc, /home, /opt)")
    algorithm: str = Field(default="sha256", description="Hash algorithm: 'md5', 'sha1', 'sha256', 'sha512'")


@mcp.tool(
    name="blueteam_hash_file",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_hash_file(params: HashFileInput) -> str:
    """Compute a cryptographic hash of a file. Use to detect tampering.
    Pair with blueteam_lookup_hash_virustotal to check for known malware.

    Args:
        params.path: File path
        params.algorithm: Hash algorithm

    Returns:
        str: JSON with file path, size, hash algorithm, and hash value
    """
    algo_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    algo = params.algorithm.lower()
    if algo not in algo_map:
        return json.dumps({"error": f"Unknown algorithm '{params.algorithm}'. Use: md5, sha1, sha256, sha512"})

    ok, err = _validate_path(params.path, ALLOWED_PATH_PREFIXES)
    if not ok:
        return json.dumps({"error": f"Path not allowed: {err}"})

    p = Path(params.path)
    if not p.exists():
        return json.dumps({"error": f"File not found: {params.path}"})
    if not p.is_file():
        return json.dumps({"error": f"Not a regular file: {params.path}"})

    try:
        h = algo_map[algo]()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        result = json.dumps({
            "path": str(p),
            "size_bytes": p.stat().st_size,
            "algorithm": algo,
            "hash": h.hexdigest(),
            "modified": datetime.fromtimestamp(p.stat().st_mtime).isoformat(),
        }, indent=2)
        _audit_log("blueteam_hash_file", {"path": params.path, "algorithm": algo}, result[:200])
        return result
    except PermissionError:
        return json.dumps({"error": f"Permission denied reading {params.path}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool(
    name="blueteam_find_suid_files",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_find_suid_files() -> str:
    """Find all SUID/SGID binaries on the system. Unexpected SUID files
    can indicate privilege escalation backdoors.

    Returns:
        str: List of SUID/SGID files with permissions and owner
    """
    r = _run(["find", "/", "-type", "f", r"-perm", "/6000", "-ls"], timeout=60)
    return r["stdout"] or r["stderr"]


@mcp.tool(
    name="blueteam_find_world_writable",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_find_world_writable() -> str:
    """Find world-writable files and directories (excluding /proc, /sys, /dev).
    World-writable files in unexpected places are common persistence mechanisms.

    Returns:
        str: List of world-writable paths
    """
    cmd = [
        "find", "/",
        "-not", "-path", "/proc/*",
        "-not", "-path", "/sys/*",
        "-not", "-path", "/dev/*",
        "-not", "-path", "/run/*",
        "-perm", "-o+w",
        "-ls"
    ]
    r = _run(cmd, timeout=60)
    return r["stdout"] or r["stderr"]


class RootkitInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    tool: str = Field(default="rkhunter", description="Tool to use: 'rkhunter' or 'chkrootkit'")


@mcp.tool(
    name="blueteam_rootkit_scan",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_rootkit_scan(params: RootkitInput) -> str:
    """Run a rootkit scanner (rkhunter or chkrootkit) to check for known rootkits.

    Args:
        params.tool: Scanner to use

    Returns:
        str: Scan output with warnings and clean checks
    """
    tool = params.tool.lower()
    if tool == "rkhunter":
        if not shutil.which("rkhunter"):
            return _tool_not_found("rkhunter")
        r = _run(["rkhunter", "--check", "--skip-keypress", "--nocolors"], timeout=120)
    elif tool == "chkrootkit":
        if not shutil.which("chkrootkit"):
            return _tool_not_found("chkrootkit")
        r = _run(["chkrootkit"], timeout=120)
    else:
        return json.dumps({"error": f"Unknown tool '{tool}'. Use 'rkhunter' or 'chkrootkit'"})

    return r["stdout"] or r["stderr"]


# SYSTEM HARDENING
@mcp.tool(
    name="blueteam_lynis_audit",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_lynis_audit() -> str:
    """Run a Lynis system hardening audit. Checks hundreds of security controls
    and produces prioritized recommendations. Takes 1-2 minutes.

    Returns:
        str: Lynis audit output with hardening index and suggestions
    """
    if not shutil.which("lynis"):
        return _tool_not_found("lynis")
    r = _run(["lynis", "audit", "system", "--quick", "--no-colors"], timeout=180)
    return r["stdout"] or r["stderr"]


@mcp.tool(
    name="blueteam_check_updates",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_check_updates() -> str:
    """Check for available security updates (Debian/Ubuntu: apt, RHEL: dnf/yum).

    Returns:
        str: List of packages with available updates
    """
    if shutil.which("apt"):
        r = _run(["apt", "list", "--upgradeable"], timeout=60)
        return r["stdout"] or r["stderr"]
    elif shutil.which("dnf"):
        r = _run(["dnf", "check-update", "--security"], timeout=60)
        return r["stdout"] or r["stderr"]
    elif shutil.which("yum"):
        r = _run(["yum", "check-update", "--security"], timeout=60)
        return r["stdout"] or r["stderr"]
    return json.dumps({"error": "No supported package manager found (apt, dnf, yum)"})


@mcp.tool(
    name="blueteam_check_open_firewall",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_check_open_firewall() -> str:
    """Show current firewall rules (iptables/nftables/ufw). Identifies
    overly permissive rules or missing protections.

    Returns:
        str: Current firewall ruleset
    """
    if shutil.which("ufw"):
        r = _run(["ufw", "status", "verbose"])
        if r["returncode"] == 0:
            return r["stdout"]
    if shutil.which("nft"):
        r = _run(["nft", "list", "ruleset"])
        if r["returncode"] == 0:
            return r["stdout"]
    r = _run(["iptables", "-L", "-n", "-v"])
    return r["stdout"] or r["stderr"]



# USER & SESSION MONITORING
@mcp.tool(
    name="blueteam_who_is_logged_in",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_who_is_logged_in() -> str:
    """Show currently logged-in users, their source IPs, and session times.
    Useful for detecting unauthorized active sessions.

    Returns:
        str: Active user session table
    """
    r = _run(["w", "-h"])
    return r["stdout"] or r["stderr"]


@mcp.tool(
    name="blueteam_last_logins",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_last_logins() -> str:
    """Show recent login history from /var/log/wtmp. Includes successful
    and failed logins with source IP and timestamps.

    Returns:
        str: Login history (last 50 entries)
    """
    r = _run(["last", "-n", "50", "-a", "-i"])
    return r["stdout"] or r["stderr"]


@mcp.tool(
    name="blueteam_failed_logins",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_failed_logins() -> str:
    """Show all failed login attempts from /var/log/btmp (lastb).
    High counts from a single IP indicate brute force.

    Returns:
        str: Failed login history (last 100 entries)
    """
    r = _run(["lastb", "-n", "100", "-a", "-i"])
    if r["returncode"] != 0:
        # Try parsing auth.log directly
        r2 = _run(["grep", "-i", r"failed password\|authentication failure", "/var/log/auth.log"])
        lines = r2["stdout"].splitlines()
        return "\n".join(lines[-100:]) if lines else "No failed logins found in auth.log"
    return r["stdout"] or r["stderr"]


@mcp.tool(
    name="blueteam_sudo_history",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_sudo_history() -> str:
    """Show recent sudo command usage from auth.log.
    Identifies privilege escalation abuse.

    Returns:
        str: Lines from auth.log containing sudo activity
    """
    r = _run(["grep", "sudo:", "/var/log/auth.log"])
    lines = r["stdout"].splitlines()
    return "\n".join(lines[-200:]) if lines else "No sudo activity found (or no auth.log)"


@mcp.tool(
    name="blueteam_list_users",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_list_users() -> str:
    """List all local user accounts with UID, GID, home dir, and shell.
    Highlights users with UID 0 (root-level) and users with login shells.

    Returns:
        str: JSON array of user accounts with risk flags
    """
    users = []
    try:
        with open("/etc/passwd") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                uid = int(parts[2])
                shell = parts[6]
                has_login_shell = shell not in ["/sbin/nologin", "/usr/sbin/nologin", "/bin/false", ""]
                users.append({
                    "username": parts[0],
                    "uid": uid,
                    "gid": int(parts[3]),
                    "home": parts[5],
                    "shell": shell,
                    "flags": {
                        "uid_zero_root": uid == 0,
                        "has_login_shell": has_login_shell,
                        "system_account": uid < 1000 and uid != 0,
                    }
                })
    except Exception as e:
        return json.dumps({"error": str(e)})

    # Sort: UID 0 first, then regular users, then system accounts
    users.sort(key=lambda u: (not u["flags"]["uid_zero_root"], not u["flags"]["has_login_shell"], u["uid"]))
    return json.dumps(users, indent=2)


@mcp.tool(
    name="blueteam_check_ssh_authorized_keys",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_check_ssh_authorized_keys() -> str:
    """List all SSH authorized_keys files across all user home directories.
    Unexpected keys indicate backdoors or persistence mechanisms.

    Returns:
        str: JSON with each user's authorized keys (fingerprints)
    """
    result = {}
    for home in Path("/home").iterdir():
        ak = home / ".ssh" / "authorized_keys"
        if ak.exists():
            try:
                result[home.name] = ak.read_text().strip().splitlines()
            except PermissionError:
                result[home.name] = ["<permission denied>"]

    # Also check root
    root_ak = Path("/root/.ssh/authorized_keys")
    if root_ak.exists():
        try:
            result["root"] = root_ak.read_text().strip().splitlines()
        except PermissionError:
            result["root"] = ["<permission denied>"]

    return json.dumps(result, indent=2) if result else json.dumps({"result": "No authorized_keys files found"})



# PROCESS & CRON ANALYSIS
@mcp.tool(
    name="blueteam_list_processes",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_list_processes() -> str:
    """List all running processes with CPU, memory, PID, and command line.
    Useful for spotting unexpected processes or cryptominers.

    Returns:
        str: Process table sorted by CPU usage
    """
    r = _run(["ps", "auxf"])
    return r["stdout"] or r["stderr"]


@mcp.tool(
    name="blueteam_list_cron_jobs",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_list_cron_jobs() -> str:
    """List all system and user cron jobs. Attackers often add cron jobs
    for persistence. Check for unexpected entries.

    Returns:
        str: All cron jobs across system and users
    """
    output = []

    # System crontabs
    for path in ["/etc/crontab", "/etc/cron.d/"]:
        p = Path(path)
        if p.is_file():
            output.append(f"=== {path} ===\n{p.read_text()}")
        elif p.is_dir():
            for f in p.iterdir():
                try:
                    output.append(f"=== {f} ===\n{f.read_text()}")
                except Exception:
                    pass

    # User crontabs
    r = _run(["ls", "/var/spool/cron/crontabs"])
    if r["returncode"] == 0:
        for user in r["stdout"].strip().splitlines():
            r2 = _run(["crontab", "-u", user.strip(), "-l"])
            if r2["returncode"] == 0:
                output.append(f"=== crontab for {user} ===\n{r2['stdout']}")

    return "\n\n".join(output) if output else "No cron jobs found (or insufficient permissions)"



# SYSTEM HEALTH
@mcp.tool(
    name="blueteam_system_health",
    annotations={"readOnlyHint": True, "destructiveHint": False}
)
async def blueteam_system_health() -> str:
    """Get an overview of system health: uptime, disk, memory, CPU load.
    Useful baseline before deeper investigation.

    Returns:
        str: JSON with system vitals
    """
    uptime = _run(["uptime", "-p"])
    disk = _run(["df", "-h", "--exclude-type=tmpfs", "--exclude-type=devtmpfs"])
    mem = _run(["free", "-h"])
    load = _run(["cat", "/proc/loadavg"])
    hostname = _run(["hostname", "-f"])
    kernel = _run(["uname", "-r"])

    return json.dumps({
        "hostname": hostname["stdout"].strip(),
        "kernel": kernel["stdout"].strip(),
        "uptime": uptime["stdout"].strip(),
        "load_average": load["stdout"].strip(),
        "memory": mem["stdout"],
        "disk": disk["stdout"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }, indent=2)



# ENTRY POINT / TRANSPORT SELECTION
def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with multi-transport support."""
    parser = argparse.ArgumentParser(
        description="blue_team_mcp — Unified blue-team MCP server (TangerangKota-CSIRT)"
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable_http", "http"],
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
        help="MCP transport to use (default: stdio, or env MCP_TRANSPORT).",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("MCP_HOST", "127.0.0.1"),
        help="Bind host for sse/streamable_http transports (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("MCP_PORT", "8000")),
        help="Port for sse/streamable_http transports (default: 8000).",
    )
    return parser


def main() -> None:
    """Start the MCP server on the selected transport."""
    args = _build_arg_parser().parse_args()

    if args.transport == "stdio":
        logger.info("Starting blue_team_mcp via stdio transport")
        mcp.run(transport="stdio")
        return

    # FastMCP sets host/port via settings attributes before .run() is called.
    mcp.settings.host = args.host
    mcp.settings.port = args.port

    # Update transport security to allow the actual host the client connects to.
    # FastMCP auto-enables DNS rebinding protection for localhost only - if we're
    # binding to a different IP (e.g. 172.16.9.125 or 0.0.0.0), we must add it
    # to the allowed_hosts so the Host header validation passes (MCP spec security).
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        transport_security = mcp.settings.transport_security
        if transport_security is None:
            from mcp.server.transport_security import TransportSecuritySettings
            transport_security = TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
            )
            mcp.settings.transport_security = transport_security
        transport_security.allowed_hosts.extend([
            f"{args.host}:{args.port}",
            f"{args.host}:*",
        ])
        transport_security.allowed_origins.extend([
            f"http://{args.host}:{args.port}",
            f"http://{args.host}:*",
        ])

    if args.transport == "sse":
        logger.info(
            "Starting blue_team_mcp via SSE transport on %s:%s", args.host, args.port
        )
        mcp.run(transport="sse")
    elif args.transport in ("streamable_http", "http"):
        logger.info(
            "Starting blue_team_mcp via Streamable HTTP transport on %s:%s",
            args.host,
            args.port,
        )
        mcp.run(transport="streamable-http")
    else:  # pragma: no cover — unreachable due to argparse choices
        raise ValueError(f"Unknown transport: {args.transport}")


if __name__ == "__main__":
    main()
