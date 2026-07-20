#!/usr/bin/env python3
"""
Programmer : NAuliajati (csirt[at]tangerangkota[.]go[.]id)
© TangerangKota-CSIRT

Blue Team Wazuh MCP Server
A defensive security MCP server for Claude Desktop and Compatible with any MCP Host. 
Mirroring the Kali mcp-kali-server setup but for blue team / defenders / SOC.

MAESTRO Framework (currently under development): Aligned with CSA MAESTRO (Layer 3 Agent Frameworks, Layer 5 Observability, Layer 6 Security & Compliance).

Tools included:
  - Log analysis (auth, syslog, journald, nginx/apache)
  - Network monitoring (open ports, active connections, traffic capture)
  - Threat intelligence (IP/domain reputation via AbuseIPDB, VirusTotal, Netra, CrowdSec, GreyNoise)
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
import math
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from collections import Counter
from typing import Any, Dict, List, Optional, Literal
import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, AliasChoices, field_validator, model_validator
from pydantic import AfterValidator
from typing import Annotated

# 3 Sum Correlation Engine
from correlation.three_sum_core import (
    evaluate_engine_a, evaluate_engine_b, format_evaluation_dict,
    normalize_srcip_to_cidr,
    DEFAULT_THRESHOLD_SCORE, DEFAULT_Z_THRESHOLD, DEFAULT_WINDOW_MINUTES,
)

# Logging - Must go to stderr. stdout is used by the MCP stdio protocol.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("blue_team_mcp")

# Server name — normalized to lowercase to prevent LLM casing mismatches.
# Users configure this via BLUE_TEAM_MCP_SERVER_NAME env var for total naming freedom.
_MCP_SERVER_NAME = os.environ.get("BLUE_TEAM_MCP_SERVER_NAME", "blue_team_mcp").strip().lower()
if os.environ.get("BLUE_TEAM_MCP_SERVER_NAME", "").strip() and os.environ.get("BLUE_TEAM_MCP_SERVER_NAME", "").strip() != _MCP_SERVER_NAME:
    logger.warning(
        "BLUE_TEAM_MCP_SERVER_NAME contains uppercase characters — "
        "normalized to '%s'. Some LLM clients may mishandle case-sensitive "
        "server names; if you experience tool-routing issues, "
        "use an all-lowercase name.",
        _MCP_SERVER_NAME,
    )
mcp = FastMCP(_MCP_SERVER_NAME)

# Configuration (set via environment variables)
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
MAX_LOG_LINES = 2000   # safety cap for log reads
TIMEOUT = 30           # seconds for subprocess calls
MAX_GREP_PATTERN_LENGTH = 200   # ReDoS mitigation
BLUETEAM_AUDIT_LOG = os.environ.get("BLUETEAM_AUDIT_LOG", "")
BLUETEAM_RATE_LIMIT = int(os.environ.get("BLUETEAM_RATE_LIMIT", "0"))  # max calls/min, 0=disabled
BLUETEAM_REDACT_PII = os.environ.get("BLUETEAM_REDACT_PII", "true").lower() in ("1", "true", "yes")
BLUETEAM_REDACT_EMAILS = os.environ.get("BLUETEAM_REDACT_EMAILS", "true").lower() in ("1", "true", "yes")
BLUETEAM_REDACT_DOMAINS = os.environ.get("BLUETEAM_REDACT_DOMAINS", "true").lower() in ("1", "true", "yes")
BLUETEAM_REDACT_LOCATIONS = os.environ.get("BLUETEAM_REDACT_LOCATIONS", "true").lower() in ("1", "true", "yes")
BLUETEAM_REDACT_UAS = os.environ.get("BLUETEAM_REDACT_UAS", "true").lower() in ("1", "true", "yes")

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
WAZUH_API_VERIFY_SSL = os.environ.get("WAZUH_API_VERIFY_SSL", "true").lower() in ("1", "true", "yes")
if not WAZUH_API_VERIFY_SSL:
    logger.warning("WAZUH_API_VERIFY_SSL is disabled — TLS certificate verification is OFF for Wazuh Manager API connections")

# Wazuh Indexer / OpenSearch (optional - for blueteam_wazuh_indexer_search; HYDRA-DC events live here)
WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
WAZUH_INDEXER_VERIFY_SSL = os.environ.get("WAZUH_INDEXER_VERIFY_SSL", "true").lower() in ("1", "true", "yes")
if not WAZUH_INDEXER_VERIFY_SSL:
    logger.warning("WAZUH_INDEXER_VERIFY_SSL is disabled — TLS certificate verification is OFF for Wazuh Indexer/OpenSearch connections")

# CrowdSec CTI (optional - set CROWDSEC_API_KEY to enable the crowdsec_ip_reputation tools)
CROWDSEC_BASE_URL = "https://cti.api.crowdsec.net"
CROWDSEC_API_KEY_ENV = "CROWDSEC_API_KEY"
CROWDSEC_CACHE_TTL = int(os.environ.get("CROWDSEC_CACHE_TTL", "900"))  # seconds, default 15 min
_crowdsec_cache: dict[str, tuple[float, dict[str, Any]]] = {}  # ip -> (expiry_timestamp, data)

# GreyNoise Community (free, no API key required)
GREYNOISE_COMMUNITY_BASE_URL = "https://api.greynoise.io/v3/community"

# Netra Threat Intelligence (optional — set NETRA_API_KEY to enable the netra_ip_analysis tool)
NETRA_BASE_URL = "https://yourdreams.gov:8013/api/v1"
NETRA_API_KEY_ENV = "NETRA_API_KEY"
NETRA_VERIFY_SSL = os.environ.get("NETRA_VERIFY_SSL", "false").lower() in ("1", "true", "yes")

# Argus Threat Intelligence (optional — set ARGUS_API_KEY to enable the argus_ip_lookup tool)
ARGUS_BASE_URL = os.environ.get("ARGUS_BASE_URL", "").rstrip("/")
ARGUS_API_KEY_ENV = "ARGUS_API_KEY"
ARGUS_VERIFY_SSL = os.environ.get("ARGUS_VERIFY_SSL", "false").lower() in ("1", "true", "yes")

# Sangfor Blocklist (optional — set SANGFOR_BLOCKLIST_TOKEN to enable sangfor_blocklist_* tools)
SANGFOR_BLOCKLIST_URL = os.environ.get("SANGFOR_BLOCKLIST_URL", "").rstrip("/")
SANGFOR_BLOCKLIST_TOKEN = os.environ.get("SANGFOR_BLOCKLIST_TOKEN", "")
SANGFOR_BLOCKLIST_TIMEOUT = float(os.environ.get("SANGFOR_BLOCKLIST_TIMEOUT", "15"))
SANGFOR_BLOCKLIST_VERIFY_SSL = os.environ.get("SANGFOR_BLOCKLIST_VERIFY_SSL", "false").lower() in ("1", "true", "yes")

# Shared HTTP / response config
HTTP_TIMEOUT = 30.0
CHARACTER_LIMIT = int(os.environ.get("BLUETEAM_CHARACTER_LIMIT", "100000"))
_WAZUH_INDEXER_MAX_SIZE = int(os.environ.get("WAZUH_INDEXER_MAX_SIZE", "10000"))
BLUETEAM_ALLOW_UNTRUNCATED = os.environ.get("BLUETEAM_ALLOW_UNTRUNCATED", "false").lower() in ("1", "true", "yes")
if BLUETEAM_ALLOW_UNTRUNCATED:
    logger.warning(
        "BLUETEAM_ALLOW_UNTRUNCATED=true - character-limit bypass and include_all_docs are ENABLED. "
        "Unbounded response payloads may exhaust LLM context windows or MCP transport buffers. "
        "Use only for forensic deep-dives with explicit scope constraints (small time windows, "
        "specific agents/IPs, conservative max_scanned values)."
    )
_WAZUH_TOKEN_TTL = 300  # seconds — cache Wazuh JWT for 5 min

# Private / reserved IP ranges — threat-intel tools are for public IPs only
_PRIVATE_NETWORKS: list = []  # kept for import compatibility — functionality replaced by ipaddress.is_private

# Shared HTTP clients by name - lazy-init, pooled per SSL trust domain
_clients: dict[str, httpx.AsyncClient] = {}


async def _get_client(
    name: str,
    verify: bool = True,
    max_keepalive: int = 20,
    max_connections: int = 100,
) -> httpx.AsyncClient:
    """Return a pooled httpx.AsyncClient by name, creating lazily if needed."""
    if name not in _clients or _clients[name].is_closed:
        _clients[name] = httpx.AsyncClient(
            timeout=httpx.Timeout(HTTP_TIMEOUT),
            limits=httpx.Limits(max_keepalive_connections=max_keepalive, max_connections=max_connections),
            verify=verify,
        )
    return _clients[name]


async def _api_call(method: str, url: str, *, client_name: str = "http", verify: bool = True, **kw) -> httpx.Response:
    """Unified async HTTP helper. Returns raw response — caller calls .json() or .text."""
    client = await _get_client(client_name, verify=verify)
    resp = await getattr(client, method.lower())(url, **kw)
    resp.raise_for_status()
    return resp


def response_pipeline(tool_name: str):
    """Decorator: auto-applies redact → truncate → audit on tool return values.

    Extracts bypass_redaction from the first positional arg (params object).
    Chains: _redact_alert_data → json.dumps → _truncate_if_needed → _audit_log.
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            params = args[0] if args else None
            bypass_redact = getattr(params, "bypass_redaction", False)
            bypass_char = getattr(params, "bypass_character_limit", False)
            # Redact if result is dict/list
            if isinstance(result, (dict, list)):
                result = _redact_alert_data(result, bypass=bypass_redact)
            # Serialize
            if isinstance(result, (dict, list)):
                result = json.dumps(result, indent=2, ensure_ascii=False)
            # Truncate + audit
            result = _truncate_if_needed(str(result) if not isinstance(result, str) else result, bypass=bypass_char)
            _audit_log(tool_name, {} if params is None else params.model_dump() if hasattr(params, "model_dump") else {},
                       str(result)[:200] if isinstance(result, str) else "")
            return result
        return wrapper
    return decorator


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


# Time-window utilities
# Pattern for relative time expressions: "5m", "1h", "24h", "7d", "4w", "15s"
_RELATIVE_TIME_RE = re.compile(r"^(\d+)([smhdw])$")
# Pattern for ISO 8601: Ex: "2026-07-07T17:00:00Z" or "2026-07-07"
_ISO_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")

def _parse_time_window(
    since: Optional[str],
    until: Optional[str],
    default_back: timedelta = timedelta(days=365),
) -> tuple[str, str]:
    """Parse since/until parameters accepting ISO 8601 or relative expressions.

    Relative expressions: "N" followed by one of {s, m, h, d, w}:
      - ``5m`` / ``30m`` → 5 / 30 minutes ago
      - ``1h`` / ``24h`` / ``6h`` → N hours ago
      - ``1d`` / ``7d`` / ``30d`` → N days ago
      - ``1w`` / ``4w`` → N weeks ago
      - ``15s`` → 15 seconds ago

    ISO 8601 strings (must start with ``YYYY-MM-DD``) pass through unchanged.
    Returns ``(since_iso, until_iso)`` — absolute ISO 8601 strings in UTC.
    ``until`` defaults to ``now``; ``since`` defaults to ``default_back`` ago.
    """
    now = datetime.utcnow()
    until_dt = now

    # Parse until
    if until and until.strip():
        until_str = until.strip()
        if _ISO_TIME_RE.match(until_str):
            until_dt = datetime.fromisoformat(
                until_str.replace("Z", "+00:00").rstrip("Z")
            )
        else:
            m = _RELATIVE_TIME_RE.match(until_str)
            if m:
                n, unit = int(m.group(1)), m.group(2)
                delta = _relative_delta(n, unit)
                until_dt = now - delta
            # else: pass through as-is (trust the caller for bare strings)

    # Parse since
    if since and since.strip():
        since_str = since.strip()
        if _ISO_TIME_RE.match(since_str):
            since_dt = datetime.fromisoformat(
                since_str.replace("Z", "+00:00").rstrip("Z")
            )
        else:
            m = _RELATIVE_TIME_RE.match(since_str)
            if m:
                n, unit = int(m.group(1)), m.group(2)
                delta = _relative_delta(n, unit)
                since_dt = now - delta
            else:
                since_dt = now - default_back
    else:
        since_dt = now - default_back

    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return since_dt.strftime(fmt), until_dt.strftime(fmt)


def _relative_delta(n: int, unit: str) -> timedelta:
    """Convert a relative time token to a timedelta."""
    _UNIT_MAP = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
    if unit not in _UNIT_MAP:
        return timedelta(days=365)  # fallback — shouldn't happen with validated regex
    return timedelta(**{_UNIT_MAP[unit]: n})


# Wazuh JWT token cache
_wazuh_token: Optional[str] = None
_wazuh_token_expiry: float = 0.0

# Shared enums & formatting utilities
ResponseFormat = Literal["markdown", "json"]
# Shared field descriptions — single source of truth
_BYPASS_REDACTION_DESC = "When true, skip PII/credential redaction for audit investigations."
_RESPONSE_FORMAT_DESC = "Output format: 'markdown' (default) or 'json'."
_SINCE_DESC = "ISO 8601 start time in UTC. Defaults to 365 days ago."
_UNTIL_DESC = "ISO 8601 end time in UTC. Defaults to now."
_AGENT_NAME_DESC = "Optional agent name filter."
_AGENT_NAME_SAFE_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

# Practical email regex for extraction from log fields — covers >99% of real addresses
# Handles dots-in-local-part, plus-sign aliases, and multi-level TLDs
_EMAIL_RE = re.compile(
    r'[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}'
)

# Shared keyword search fields - used across all Wazuh Indexer query helpers.
# Each tuple is (field_name, boost). boost=0 means the field is searched
# but does not influence score ranking.
_KEYWORD_SEARCH_FIELDS: list[tuple[str, int]] = [
    ("full_log", 3),
    ("rule.description", 2),
    ("rule.info", 2),
    ("data.srcip", 2),
    ("data.srcip2", 2),
    ("srcip", 2),
    ("data.url", 0),
    ("data.domain", 0),
    ("data.user_agent", 0),
    ("data.referrer", 0),
]

def _validate_keyword_field(v: Optional[str]) -> Optional[str]:
    """Shared keyword validator — strip, reject null bytes / control chars."""
    if v is not None:
        v = v.strip()
        if not v:
            return None
        if len(v) > 1024:
            raise ValueError("keyword too long (max 1024)")
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", v):
            raise ValueError("keyword contains invalid control characters")
    return v

def _validate_agent_name_field(v: Optional[str]) -> Optional[str]:
    """Shared agent_name validator — strip, length-check, safe-chars-only."""
    if v is not None:
        v = v.strip()
        if not v:
            return None
        if len(v) > 64:
            raise ValueError("agent_name too long (max 64)")
        if not _AGENT_NAME_SAFE_RE.match(v):
            raise ValueError("agent_name: use only letters, numbers, hyphen, underscore, dot")
    return v


def _validate_rule_groups_field(v: Optional[str]) -> Optional[str]:
    """Shared rule_groups validator — comma-split, strip, safe-chars-only."""
    if v is not None:
        v = v.strip()
        if not v:
            return None
        for g in v.split(","):
            g = g.strip()
            if not g:
                raise ValueError("Empty rule group name in comma-separated list")
            if not _AGENT_NAME_SAFE_RE.match(g):
                raise ValueError(f"Invalid rule group name: '{g}'")
    return v

# Annotated types for reusable field validation (replaces per-model validators)
ValidKeyword = Annotated[Optional[str], AfterValidator(_validate_keyword_field)]
ValidAgentName = Annotated[Optional[str], AfterValidator(_validate_agent_name_field)]
ValidRuleGroups = Annotated[Optional[str], AfterValidator(_validate_rule_groups_field)]


def _is_private_or_reserved(ip: str) -> bool:
    """Check whether an IP belongs to a private or reserved range (not routable)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _validate_public_ip(v: str) -> str:
    """Reject private/reserved IPs for public threat-intel tools (SSRF guard — MCP05).

    Called by field validators AFTER ``ipaddress.ip_address()`` confirms the string
    is a valid IP.  Wazuh Manager/Indexer tools are exempted — they legitimately
    target internal infrastructure.
    """
    if _is_private_or_reserved(v):
        raise ValueError(
            f"'{v}' is a private/reserved IP address. "
            "This tool only accepts public IPs for threat intelligence lookup. "
            "Use Wazuh Indexer search tools for internal IP investigation."
        )
    return v


ValidPublicIp = Annotated[str, AfterValidator(_validate_public_ip)]

def _handle_api_error(e: Exception, context: str = "") -> str:
    """Consistent, actionable error formatting for all API-based tools."""
    prefix = f"[{context}] " if context else ""
    if isinstance(e, httpx.HTTPStatusError):
        status = e.response.status_code
        if status == 400:
            return (f"{prefix}Error: Bad request (400) — the API rejected the parameters. "
                    "Try a smaller limit (e.g. limit=50) or a different filter.")
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

def _truncate_if_needed(text: str, *, bypass: bool = False) -> str:
    """Cap response at CHARACTER_LIMIT. When bypass=True, prepends forensic warning."""
    if bypass:
        banner = (
            "⚠️ UNREDACTED - FORENSIC USE ONLY. Contains PII/internal IPs.\n {HANYA UNTUK KEBUTUHAN FORENSIK & AUDIT!!!}"
        )
        text = banner + text
        # Append forensic trace to audit log
        if BLUETEAM_AUDIT_LOG:
            try:
                with open(BLUETEAM_AUDIT_LOG, "a") as f:
                    f.write(json.dumps({
                        "ts": datetime.utcnow().isoformat() + "Z",
                        "event": "forensic_bypass_response",
                        "response_sha256": hashlib.sha256(text.encode()).hexdigest(),
                        "response_bytes": len(text.encode()),
                    }) + "\n")
            except Exception:
                pass
        if BLUETEAM_ALLOW_UNTRUNCATED:
            return text
    if len(text) <= CHARACTER_LIMIT:
        return text
    truncated = text[:CHARACTER_LIMIT]
    return (
        truncated
        + f"\n\n... [truncated — response exceeds {CHARACTER_LIMIT} characters. "
        "Use a smaller limit per page (e.g. limit=50) or iterate with the next_cursor "
        "to process results incrementally.]"
    )


def _escape_md_table(value: str) -> str:
    """Escape pipe and newline characters for safe markdown table rendering."""
    return value.replace("|", "\\|").replace("\n", " ").replace("\r", "")


# Circuit Breaker - prevents cascading failures when upstream APIs are down.
# 3 Sum throttle state — prevents rapid-fire Indexer queries
_last_eval_time: float = 0.0
_last_eval_result: Optional[Dict[str, Any]] = None

# MITRE ATT&CK tactic → 3-Sum category mapping (Phase 1/2)
MITRE_TACTIC_TO_CATEGORY: Dict[str, str] = {
    "Reconnaissance":          "A",
    "Resource Development":    "A",
    "Discovery":               "A",
    "Initial Access":          "B",
    "Credential Access":       "B",
    "Privilege Escalation":    "B",
    "Defense Evasion":         "B",
    "Execution":               "B",
    "Persistence":             "C",
    "Command and Control":     "C",
    "Exfiltration":            "C",
    "Impact":                  "C",
    "Collection":              "C",
}

# Source IP field paths - Wazuh decoders may emit the attacker IP under different data.* fields
# depending on the log source. Engine A queries all known paths via multi_terms aggregation
# to avoid silent false negatives from decoder field-path fragmentation.
_SRCIP_FIELD_PATHS: list[str] = [
    "data.srcip.keyword",
    "data.src_ip.keyword",
    "data.client_ip.keyword",
    "data.remote_ip.keyword",
    "data.source_ip.keyword",
    "data.ip.keyword",
    "srcip.keyword",
]


def _compute_adaptive_thresholds(
    baseline_alert_volume: tuple[float, float, int],  # (mu, sigma, buckets)
    baseline_high_severity: tuple[float, float, int],
) -> tuple[int, float]:
    """Compute adaptive 3-Sum thresholds from baselines.

    Cold-start safeguard: returns defaults if σ=0 or buckets<2.
    Formula:
      threshold_score = clamp(6, 30, 10 + (mu_high / max(sigma_high,1)) * 0.5)
      z_threshold     = clamp(1.5, 5.0, 2.5 - (sigma_vol / max(mu_vol,1)) * 0.3)
    """
    mu_vol, sigma_vol, buckets_vol = baseline_alert_volume
    mu_high, sigma_high, buckets_high = baseline_high_severity

    # Cold-start check
    if sigma_vol == 0.0 or sigma_high == 0.0 or buckets_vol < 2 or buckets_high < 2:
        return (DEFAULT_THRESHOLD_SCORE, DEFAULT_Z_THRESHOLD)

    import math
    score = 10 + (mu_high / max(sigma_high, 1.0)) * 0.5
    if math.isnan(score):
        score = 10
    threshold_score = max(6, min(30, int(round(score))))

    z_val = 2.5 - (sigma_vol / max(mu_vol, 1.0)) * 0.3
    if math.isnan(z_val):
        z_val = 2.5
    z_threshold = max(1.5, min(5.0, round(z_val, 1)))

    return (threshold_score, z_threshold)


def _classify_alert_mitre(
    mitre_tactics: Optional[list[str]],
    target_category: str,
) -> tuple[float, Optional[str]]:
    """Weighted MITRE ATT&CK tactic classification (Phase 1/2).

    Alpha (α = 0.6) groups-match score: handled by the caller — a srcip is already
    in ``srcips_by_label[category]`` if its rule.groups match that category.

    Beta (β = 0.4) MITRE overlay score: computed here. If ANY tactic in the alert's
    ``rule.mitre.tactic`` array maps to ``target_category``, returns (0.4, tactic_name).

    The combined total = α + β > 0 qualifies the srcip for the category.
    """
    if not mitre_tactics:
        return (0.0, None)
    for tactic in mitre_tactics:
        if MITRE_TACTIC_TO_CATEGORY.get(tactic) == target_category:
            return (0.4, tactic)
    return (0.0, None)


# PII redaction patterns - applied to alert payloads when BLUETEAM_REDACT_PII is enabled
_REDACT_EMAIL_RE = re.compile(r"([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")

# Credential/secret stripping patterns - applied BEFORE PII redaction.
# Prevents tokens, keys, and secrets in Wazuh full_log fields from leaking to the LLM.
# Each entry is (compiled_regex, replacement_string). Applied in order.
_CREDENTIAL_STRIP_RULES: list[tuple[re.Pattern, str]] = [
    # Bearer tokens: "Authorization: Bearer eyJ..." -> "Authorization: Bearer <BEARER_REDACTED>"
    (re.compile(r'Authorization:\s*Bearer\s+\S+', re.IGNORECASE),
     'Authorization: Bearer <BEARER_REDACTED>'),
    # Basic auth: "Authorization: Basic dXNlcjpwYXNz..." -> "Authorization: Basic <BASIC_REDACTED>"
    (re.compile(r'Authorization:\s*Basic\s+\S+', re.IGNORECASE),
     'Authorization: Basic <BASIC_REDACTED>'),
    # x-api-key / X-API-Key headers
    (re.compile(r'x-api-key:\s*\S+', re.IGNORECASE),
     'x-api-key: <API_KEY_REDACTED>'),
    # api_key / apikey query params or inline assignments
    (re.compile(r'(?:api[_-]?key)\s*[=:]\s*\S+', re.IGNORECASE),
     'api_key=<API_KEY_REDACTED>'),
    # JWT tokens — three base64url segments separated by dots, header starts with "eyJ"
    (re.compile(r'\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{0,1000}\b'),
     '<JWT_REDACTED>'),
    # Private key PEM blocks (RSA, EC, OpenSSH, DSA, Ed25519, generic)
    (re.compile(
        r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ED25519 |ENCRYPTED )?PRIVATE KEY-----'
        r'.*?'
        r'-----END (?:RSA |EC |OPENSSH |DSA |ED25519 |ENCRYPTED )?PRIVATE KEY-----',
        re.DOTALL,
    ), '<PRIVATE_KEY_REDACTED>'),
    # Cloud API keys: AWS (AKIA...) + Stripe (sk_live_/sk_test_)
    (re.compile(r'\b(AKIA[0-9A-Z]{16}|sk_(?:live|test)_[a-zA-Z0-9]{24,})\b'),
     '<CLOUD_API_KEY_REDACTED>'),
    # VCS tokens: GitHub (ghp_/gho_...) + GitLab (glpat-)
    (re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,}|glpat-[A-Za-z0-9_-]{20,})\b'),
     '<VCS_TOKEN_REDACTED>'),
    # OpenAI / Anthropic API keys: sk- (but NOT Stripe sk_live/sk_test which are handled above)
    (re.compile(r'\b(?:sk-(?!live|test)|sk-ant-)[a-zA-Z0-9_-]{20,}\b'), '<AI_API_KEY_REDACTED>'),
    # Generic password/secret/passwd/pwd query params or inline: "password=value" -> "password=<REDACTED>"
    (re.compile(r'(password|passwd|pwd|secret)\s*[=:]\s*\S+', re.IGNORECASE),
     r'\1=<PASSWORD_REDACTED>'),
    # Platform tokens: Slack (xoxb-/xoxp-...) + Google (AIza...)
    (re.compile(r'\b(xox[abpro]-[0-9]+-[0-9]+-[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)?|AIza[0-9A-Za-z_-]{35})\b'),
     '<PLATFORM_TOKEN_REDACTED>'),
]

# Forensic email hashing - preserves domain visibility for SOC analysis while
# keeping the raw email out of the LLM context.  The hash is deterministic
# (SHA-256 salted with BLUETEAM_REDACT_SALT, defaulting to hostname-derived)
# so the same email produces the same hash across tool calls and server restarts.
_REDACT_SALT = os.environ.get(
    "BLUETEAM_REDACT_SALT",
    hashlib.sha256(os.uname().nodename.encode()).hexdigest()[:16]
)


def _hash_email_for_audit(email: str) -> str:
    """Return an 8-char hex hash prefix for forensic cross-referencing.

    Deterministic: same (salt, email) → same hash every time.  The analyst
    can verify by computing SHA-256 locally:

        echo -n "<salt>:admin@hallow.gov" | sha256sum | cut -c1-8

    and matching the result against the ``[h:xxxxxxxx]`` suffix in the output.
    """
    return hashlib.sha256(f"{_REDACT_SALT}:{email}".encode()).hexdigest()[:8]


def _mask_domain(domain: str) -> str:
    """Mask subdomain part, keep parent domain + TLD visible."""
    parts = domain.rstrip(".").split(".")
    if len(parts) < 3:
        return domain
    sub = parts[0]
    if len(sub) <= 2:
        masked = sub[0] + "*" * (len(sub) - 1)
    else:
        masked = sub[0] + "*" * (len(sub) - 2) + sub[-1]
    return f"{masked}." + ".".join(parts[1:])


def _redact_alert_data(data: Any, *, bypass: bool = False) -> Any:
    """Apply redacted-but-real PII and credential masking to alert payloads.

    **Six layers — apply in strict priority order:**

    1. **Credential stripping** (layer 1 — MANDATORY, never configurable)
    2. **Email redaction** (layer 2 — ``BLUETEAM_REDACT_EMAILS``)
    3. **Internal IP masking** (layer 3 — ``BLUETEAM_REDACT_PII``)
       RFC1918 + loopback (127.x.x.x) + link-local (169.254.x.x) + IPv6 ::1
       **Public IPs (attacker IoCs) are NEVER masked.**
    4. **Domain/hostname masking** (layer 4 — ``BLUETEAM_REDACT_DOMAINS``)
       Subdomains masked, parent+TLD visible. ``data.url`` NEVER masked.
    5. **Log location masking** (layer 5 — ``BLUETEAM_REDACT_LOCATIONS``)
       Directory tree stripped, leaf + forensic hash preserved.
    6. **User-agent truncation** (layer 6 — ``BLUETEAM_REDACT_UAS``)
       Truncated to 80 chars (OS/browser preserved).

    Layer 1 is NEVER bypassable. Bypass usage is logged to stderr.
    """
    if bypass:
        logger.warning("REDACTION BYPASSED — raw PII/internal IPs exposed to caller")
    if isinstance(data, str):
        # Layer 1: Credential stripping (MANDATORY — no env var override)
        for pattern, replacement in _CREDENTIAL_STRIP_RULES:
            data = pattern.sub(replacement, data)

        # Layer 2: Email redaction (BLUETEAM_REDACT_EMAILS)
        if not bypass and BLUETEAM_REDACT_EMAILS:
            def _redact_email(m: re.Match) -> str:
                local, domain = m.group(1), m.group(2)
                full_email = f"{local}@{domain}"
                forensic_hash = _hash_email_for_audit(full_email)
                if len(local) <= 2:
                    rlocal = local[0] + "*" * (len(local) - 1)
                else:
                    rlocal = local[0] + "*" * max(1, len(local) - 2) + local[-1]
                return f"{rlocal}@{domain} [h:{forensic_hash}]"
            data = _REDACT_EMAIL_RE.sub(_redact_email, data)

        # Layer 3: Internal IP masking (BLUETEAM_REDACT_PII)
        # RFC1918 + 127.x.x.x + 169.254.x.x + IPv6 ::1
        if not bypass and BLUETEAM_REDACT_PII:
            def _redact_internal_ip(m: re.Match) -> str:
                ip = m.group(0)
                octets = ip.split(".")
                if octets[0] == "10":
                    return f"10.{'***'}.{'***'}.{octets[3]}"
                elif octets[0] == "172" and 16 <= int(octets[1]) <= 31:
                    return f"172.{octets[1]}.{'***'}.{octets[3]}"
                elif octets[0] == "192" and octets[1] == "168":
                    return f"192.168.{'***'}.{octets[3]}"
                elif octets[0] == "127":
                    return f"127.{'***'}.{'***'}.{octets[3]}"
                elif octets[0] == "169" and octets[1] == "254":
                    return f"169.254.{'***'}.{octets[3]}"
                return ip
            data = re.sub(
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
                r"192\.168\.\d{1,3}\.\d{1,3}|"
                r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                r"169\.254\.\d{1,3}\.\d{1,3})\b",
                _redact_internal_ip, data,
            )
            # IPv6 loopback
            data = re.sub(r"\b::1\b", "<LOOPBACK_REDACTED>", data)

        # Layer 4: Domain/hostname masking in text (BLUETEAM_REDACT_DOMAINS)
        if not bypass and BLUETEAM_REDACT_DOMAINS:
            data = re.sub(
                r"(?<![@\w])([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
                r"\.(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9]+))\b",
                lambda m: _mask_domain(m.group(1)), data,
            )

        # Layer 5: Log location masking in full_log
        # Mask absolute Unix paths found in full_log strings (e.g.
        # /containers/bangjaka/logs/nginx/access.log). Preserves leaf
        # filename + forensic hash so analysts can still identify the
        # log source without exposing full directory structure.
        if not bypass and BLUETEAM_REDACT_LOCATIONS:
            def _redact_log_path(m: re.Match) -> str:
                path = m.group(0)
                parts = path.rstrip("/").split("/")
                leaf = parts[-1] if len(parts) > 1 else path
                path_hash = hashlib.sha256(f"{_REDACT_SALT}:{path}".encode()).hexdigest()[:6]
                return f".../{leaf} [h:{path_hash}]"
            data = re.sub(
                r"/(?:[a-zA-Z0-9._-]+/){2,}[a-zA-Z0-9._-]+",
                _redact_log_path, data,
            )

        # Layer 6: UA truncation in full_log
        if not bypass and BLUETEAM_REDACT_UAS:
            if len(data) > 80 and re.search(r"Mozilla|Chrome|Safari|Firefox|curl|wget|python", data):
                data = data[:80] + "..."

        return data

    if isinstance(data, dict):
        result: dict[str, Any] = {}
        for k, v in data.items():
            if not bypass:
                if k == "domain" and isinstance(v, str) and BLUETEAM_REDACT_DOMAINS:
                    v = _mask_domain(v)
                elif k == "location" and isinstance(v, str) and BLUETEAM_REDACT_LOCATIONS:
                    parts = v.rstrip("/").split("/")
                    leaf = parts[-1] if len(parts) > 1 else v
                    path_hash = hashlib.sha256(f"{_REDACT_SALT}:{v}".encode()).hexdigest()[:6]
                    v = f".../{leaf} [h:{path_hash}]"
                elif k == "user_agent" and isinstance(v, str) and BLUETEAM_REDACT_UAS and len(v) > 80:
                    v = v[:80] + "..."
            result[k] = _redact_alert_data(v, bypass=bypass)
        return result

    if isinstance(data, list):
        return [_redact_alert_data(item, bypass=bypass) for item in data]

    return data


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
            "redaction_bypassed": params.get("bypass_redaction", False),
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
    client = await _get_client("http")
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
        resp = await _api_call("post", url, client_name="wazuh", verify=WAZUH_API_VERIFY_SSL,
                                auth=(WAZUH_API_USER, WAZUH_API_PASSWORD))
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
        resp = await _api_call("get", url, client_name="wazuh", verify=WAZUH_API_VERIFY_SSL,
                                headers={"Authorization": f"Bearer {token}"},
                                params=params or {})
        return resp.json()
    except httpx.HTTPStatusError as e:
        return {"error": f"Wazuh API error: {e.response.status_code}", "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": str(e)}


async def _wazuh_indexer_search(
    index_pattern: str,
    agent_name: Optional[str],
    size: int,
    search_after: Optional[list] = None,
    srcip: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    keyword: Optional[str] = None,
    srcips: Optional[list[str]] = None,
    fields: Optional[list[str]] = None,
    rule_groups: Optional[list[str]] = None,
    geo_country: Optional[str] = None,
) -> Dict:
    """Query Wazuh Indexer (OpenSearch) for alerts/events. Read-only _search only.
    Uses search_after cursor pagination — bypasses the 10000 doc max_result_window
    by traversing sort keys instead of numeric offsets."""
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return {"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set. See README for Indexer setup."}
    url = f"{WAZUH_INDEXER_URL}/{index_pattern}/_search"
    # Build query: bool with must clauses for agent name, srcip, and time range
    must_clauses = []
    if agent_name and agent_name.strip():
        must_clauses.append({"match": {"agent.name": agent_name.strip()}})
    if srcip and srcip.strip():
        must_clauses.append({
            "bool": {
                "should": [
                    {"match": {"data.srcip": srcip.strip()}},
                    {"match": {"data.srcip2": srcip.strip()}},
                    {"match": {"srcip": srcip.strip()}},
                    {"match_phrase": {"full_log": srcip.strip()}},
                ],
                "minimum_should_match": 1,
            }
        })
    # Multi IP search: OR-of-AND within each IP, AND between different IPs.
    # Each IP searched across data.srcip, data.srcip2, srcip, and full_log.
    if srcips:
        # Deduplicate and strip
        unique_ips: list[str] = []
        seen: set[str] = set()
        for ip in srcips:
            ip = ip.strip()
            if ip and ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)
        for ip in unique_ips:
            must_clauses.append({
                "bool": {
                    "should": [
                        {"match": {"data.srcip": ip}},
                        {"match": {"data.srcip2": ip}},
                        {"match": {"srcip": ip}},
                        {"match_phrase": {"full_log": ip}},
                    ],
                    "minimum_should_match": 1,
                }
            })
    # Rule-groups filter: match documents whose rule.groups array contains ANY
    # of the specified group names. Uses OpenSearch terms query for exact matching
    # against the array field — more precise than free-text keyword on rule.description.
    if rule_groups:
        must_clauses.append({"terms": {"rule.groups": rule_groups}})
    # GeoLocation country filter — exact match on Wazuh Indexer GeoIP enrichment.
    # Only alerts that passed through GeoIP processing will match.
    if geo_country and geo_country.strip():
        must_clauses.append({"term": {"GeoLocation.country_name": geo_country.strip()}})
    # Time-range filter on @timestamp (UTC). Accepts ISO 8601 AND relative time
    # expressions ('24h', '1h', '7d', '30d', '5m') via _parse_time_window().
    # Supports since-only, until-only, or both together.
    time_range: dict[str, str] = {}
    if since or until:
        since_parsed, until_parsed = _parse_time_window(since, until)
        if since_parsed:
            time_range["gte"] = since_parsed
        if until_parsed:
            time_range["lt"] = until_parsed
    if time_range:
        time_range["format"] = "strict_date_optional_time"
        must_clauses.append({"range": {"@timestamp": time_range}})
    # Free-text keyword search using query_string with field-scoped groups.
    # Each field gets a boost embedded in the Lucene query string (field: (...)^N).
    # query_string is used (not simple_query_string) because the Wazuh Indexer
    # resolves explicit field qualifiers reliably — the same pattern used by
    # _wazuh_indexer_domain_search and _wazuh_indexer_email_search.
    # lenient=True prevents parse errors from crashing the entire query.
    if keyword and keyword.strip():

        k = keyword.strip()
        field_parts = []
        for fname, boost in _KEYWORD_SEARCH_FIELDS:
            if boost:
                field_parts.append(f'{fname}: ({k})^{boost}')
            else:
                field_parts.append(f'{fname}: ({k})')
        must_clauses.append({
            "query_string": {
                "query": " OR ".join(field_parts),
                "default_operator": "AND",
                "lenient": True,
            }
        })
    query = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}
    # Default _source: only retrieve essential fields to keep payload small.
    # The markdown renderer needs rule.level and agent.name — include them in defaults.
    # Override by passing the 'fields' tool parameter for additional/alternative fields.
    if fields:
        _source_fields = fields
    else:
        _source_fields = [
            "@timestamp",
            "agent.name",
            "rule.id",
            "rule.level",
            "rule.description",
            "data.srcip",
            "data.url",
        ]
    body = {
        "size": min(size, _WAZUH_INDEXER_MAX_SIZE),
        "sort": [
            {"@timestamp": {"order": "asc"}},
            {"_id": {"order": "asc"}},
        ],
        "query": query,
        "_source": _source_fields,
    }
    # search_after must ONLY be present when a non-empty cursor array is supplied.
    # Omitting it on the first page avoids a malformed-query error.
    if search_after is not None:
        body["search_after"] = search_after

    try:
        resp = await _api_call("post", url, client_name="indexer", verify=WAZUH_INDEXER_VERIFY_SSL,
                                auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
                                json=body,
                                headers={"Content-Type": "application/json"})
        result = resp.json()
        # Report clamping when _WAZUH_INDEXER_MAX_SIZE caps the requested size,
        # so callers can programmatically detect incomplete pages.
        applied = body["size"]
        if size > applied:
            result["applied_size"] = applied
            result["requested_size"] = size
        return result
    except httpx.HTTPStatusError as e:
        return {"error": f"Indexer API error: {e.response.status_code}", "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": str(e)}


# Wazuh Indexer search helpers
async def _wazuh_indexer_email_search(
    agent_name: Optional[str],
    size: int,
    search_after: Optional[list] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    rule_groups: Optional[list[str]] = None,
    keyword: Optional[str] = None,
) -> Dict:
    """Query Wazuh Indexer for alerts containing email-address-like strings.
    Searches ``full_log`` (query_string wildcard ``*@*.*``) and the structured
    ``data.account`` field (wildcard ``*@*``).  Both clauses are combined with
    ``minimum_should_match: 1`` so a document only needs to match one of them.
    Optional filters: agent_name, time range, and a list of rule groups
    (matched against the ``rule.groups`` keyword field).
    """
    index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]

    # Build bool query — should clauses for the two email sources
    should_clauses: list[dict] = [
        {"query_string": {"query": r"full_log: *@*.*", "default_operator": "AND"}},
        {"wildcard": {"data.account": {"value": "*@*"}}},
    ]

    must_clauses: list[dict] = []
    if agent_name and agent_name.strip():
        must_clauses.append({"match": {"agent.name": agent_name.strip()}})

    if rule_groups:
        must_clauses.append({"terms": {"rule.groups": list(rule_groups)}})

    time_range: dict[str, str] = {}
    if since and since.strip():
        time_range["gte"] = since.strip()
    if until and until.strip():
        time_range["lt"] = until.strip()
    if time_range:
        time_range["format"] = "strict_date_optional_time"
        must_clauses.append({"range": {"@timestamp": time_range}})

    if keyword and keyword.strip():
        k = keyword.strip()
        field_parts = []
        for fname, boost in _KEYWORD_SEARCH_FIELDS:
            if boost:
                field_parts.append(f'{fname}: ({k})^{boost}')
            else:
                field_parts.append(f'{fname}: ({k})')
        must_clauses.append({
            "query_string": {
                "query": " OR ".join(field_parts),
                "default_operator": "AND",
                "lenient": True,
            }
        })

    bool_part: dict[str, list] = {
        "should": should_clauses,
        "minimum_should_match": 1,
    }
    if must_clauses:
        bool_part["must"] = must_clauses
    query = {"bool": bool_part}

    body: dict = {
        "size": min(size, _WAZUH_INDEXER_MAX_SIZE),
        "sort": [{"@timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}],
        "query": query,
        # Only fetch fields we actually need - raw full_log can be huge
        "_source": [
            "full_log",
            "data.account",
            "data.srcip",
            "rule.id",
            "rule.description",
            "rule.groups",
            "rule.level",
            "@timestamp",
            "agent.name",
        ],
    }
    if search_after is not None:
        body["search_after"] = search_after

    return await _wazuh_indexer_post(body, index_pattern)


async def _wazuh_indexer_domain_search(
    domain: str,
    agent_name: Optional[str],
    size: int,
    search_after: Optional[list] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    include_full_log: bool = False,
    keyword: Optional[str] = None,
) -> Dict:
    """Query Wazuh Indexer for alerts matching a domain name.

    Searches the structured ``data.domain`` field with a match query (boosted
    so structured matches sort higher) and falls back to a ``query_string``
    phrase match on ``full_log``.
    """
    index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]

    should_clauses: list[dict] = [
        {"match": {"data.domain": {"query": domain, "boost": 2.0}}},
        {"query_string": {"query": f'full_log: "{domain}"', "default_operator": "AND"}},
    ]

    must_clauses: list[dict] = []
    if agent_name and agent_name.strip():
        must_clauses.append({"match": {"agent.name": agent_name.strip()}})

    time_range: dict[str, str] = {}
    if since and since.strip():
        time_range["gte"] = since.strip()
    if until and until.strip():
        time_range["lt"] = until.strip()
    if time_range:
        time_range["format"] = "strict_date_optional_time"
        must_clauses.append({"range": {"@timestamp": time_range}})

    if keyword and keyword.strip():
        k = keyword.strip()
        field_parts = []
        for fname, boost in _KEYWORD_SEARCH_FIELDS:
            if boost:
                field_parts.append(f'{fname}: ({k})^{boost}')
            else:
                field_parts.append(f'{fname}: ({k})')
        must_clauses.append({
            "query_string": {
                "query": " OR ".join(field_parts),
                "default_operator": "AND",
                "lenient": True,
            }
        })

    bool_part: dict[str, list] = {
        "should": should_clauses,
        "minimum_should_match": 1,
    }
    if must_clauses:
        bool_part["must"] = must_clauses
    query = {"bool": bool_part}

    _source_fields: list[str] = [
        "data.srcip",
        "data.account",
        "data.domain",
        "rule.id",
        "rule.description",
        "rule.groups",
        "rule.level",
        "@timestamp",
        "agent.name",
    ]
    if include_full_log:
        _source_fields.append("full_log")

    body: dict = {
        "size": min(size, _WAZUH_INDEXER_MAX_SIZE),
        "sort": [{"@timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}],
        "query": query,
        "_source": _source_fields,
    }
    if search_after is not None:
        body["search_after"] = search_after

    return await _wazuh_indexer_post(body, index_pattern)


async def _wazuh_indexer_multi_email_search(
    emails: list[str],
    agent_name: Optional[str],
    size: int,
    search_after: Optional[list] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    keyword: Optional[str] = None,
) -> Dict:
    """Query Wazuh Indexer for alerts mentioning any of the given email addresses.

    Uses a ``query_string`` OR-of-phrases on ``full_log`` plus a ``terms``
    query on ``data.account``.  Limited to 25 emails per sub-query to stay
    within OpenSearch clause-count limits; callers with larger lists should
    fan out across multiple calls and merge the results client-side.
    """

    if len(emails) > 25:
        emails = emails[:25]

    index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]

    # Build query_string: full_log: ("e1@x.com" OR "e2@y.com" ...)
    quoted = [f'"{e}"' for e in emails]
    email_query = " OR ".join(quoted)
    should_clauses: list[dict] = [
        {"query_string": {"query": f"full_log: ({email_query})", "default_operator": "AND"}},
        {"terms": {"data.account": list(emails)}},
    ]

    must_clauses: list[dict] = []
    if agent_name and agent_name.strip():
        must_clauses.append({"match": {"agent.name": agent_name.strip()}})

    time_range: dict[str, str] = {}
    if since and since.strip():
        time_range["gte"] = since.strip()
    if until and until.strip():
        time_range["lt"] = until.strip()
    if time_range:
        time_range["format"] = "strict_date_optional_time"
        must_clauses.append({"range": {"@timestamp": time_range}})

    if keyword and keyword.strip():
        k = keyword.strip()
        field_parts = []
        for fname, boost in _KEYWORD_SEARCH_FIELDS:
            if boost:
                field_parts.append(f'{fname}: ({k})^{boost}')
            else:
                field_parts.append(f'{fname}: ({k})')
        must_clauses.append({
            "query_string": {
                "query": " OR ".join(field_parts),
                "default_operator": "AND",
                "lenient": True,
            }
        })

    bool_part: dict[str, list] = {
        "should": should_clauses,
        "minimum_should_match": 1,
    }
    if must_clauses:
        bool_part["must"] = must_clauses
    query = {"bool": bool_part}

    body: dict = {
        "size": min(size, _WAZUH_INDEXER_MAX_SIZE),
        "sort": [{"@timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}],
        "query": query,
        "_source": [
            "data.srcip",
            "data.account",
            "full_log",
            "rule.id",
            "rule.description",
            "rule.groups",
            "@timestamp",
            "agent.name",
        ],
    }
    if search_after is not None:
        body["search_after"] = search_after

    return await _wazuh_indexer_post(body, index_pattern)


async def _wazuh_indexer_aggregate(
    bucket_interval: str,
    since: str,
    until: str,
    agent_name: Optional[str] = None,
    rule_groups: Optional[list[str]] = None,
    rule_level_min: Optional[int] = None,
    top_n_rules: int = 3,
    top_n_srcips: int = 5,
    top_n_agents: int = 3,
    keyword: Optional[str] = None,
    geo_country: Optional[str] = None,
) -> Dict:
    """Query Wazuh Indexer with a date_histogram aggregation — no document hits.

    Returns only the aggregation buckets (``size: 0``), which means the query
    covers ALL matching documents regardless of ``max_result_window``.

    Sub-aggregations nested under each time bucket:
    - ``by_level`` — range aggregation on ``rule.level`` (low ≤4, medium 5-9, high ≥10)
    - ``top_rules`` — terms aggregation on ``rule.id.keyword`` or ``rule.id``
    - ``top_srcips`` — terms aggregation on ``data.srcip``
    - ``top_agents`` — terms aggregation on ``agent.name``
    """
    index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]

    # Filter context (no scoring needed - filter is faster than query)
    filter_clauses: list[dict] = [
        {"range": {
            "@timestamp": {
                "gte": since,
                "lt": until,
                "format": "strict_date_optional_time",
            }
        }},
    ]
    if agent_name and agent_name.strip():
        filter_clauses.append({"match": {"agent.name": agent_name.strip()}})
    if rule_groups:
        filter_clauses.append({"terms": {"rule.groups": list(rule_groups)}})
    if rule_level_min is not None:
        filter_clauses.append({"range": {"rule.level": {"gte": rule_level_min}}})
    if geo_country and geo_country.strip():
        filter_clauses.append({"term": {"GeoLocation.country_name": geo_country.strip()}})
    # Free-text keyword filter - same query_string pattern as _wazuh_indexer_search
    if keyword and keyword.strip():
        k = keyword.strip()
        field_parts = []
        for fname, boost in _KEYWORD_SEARCH_FIELDS:
            if boost:
                field_parts.append(f'{fname}: ({k})^{boost}')
            else:
                field_parts.append(f'{fname}: ({k})')
        filter_clauses.append({
            "query_string": {
                "query": " OR ".join(field_parts),
                "default_operator": "AND",
                "lenient": True,
            }
        })

    # Sub-aggregations nested under each date bucket
    sub_aggs: dict = {
        "by_level": {
            "range": {
                "field": "rule.level",
                "ranges": [
                    {"key": "low", "to": 5},
                    {"key": "medium", "from": 5, "to": 10},
                    {"key": "high", "from": 10},
                ],
            }
        },
        "top_rules": {
            "terms": {
                "field": "rule.id.keyword",
                "size": top_n_rules,
                "missing": "unknown",
            }
        },
        "top_srcips": {
            "terms": {
                "field": "data.srcip.keyword",
                "size": top_n_srcips,
                "missing": "0.0.0.0",
            }
        },
        "top_agents": {
            "terms": {
                "field": "agent.name.keyword",
                "size": top_n_agents,
                "missing": "unknown",
            }
        },
    }

    body: dict = {
        "size": 0,
        "query": {"bool": {"filter": filter_clauses}},
        "aggs": {
            "alerts_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": bucket_interval,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": since, "max": until},
                },
                "aggs": sub_aggs,
            }
        },
    }

    return await _wazuh_indexer_post(body, index_pattern)


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
    """Reusable async GET request to the CrowdSec CTI API.
    Implements an in-memory TTL cache (default 15 min, configurable via
    CROWDSEC_CACHE_TTL) . Cache entries are keyed by the exact path (which includes the IP). Error responses (HTTP
    4xx/5xx) are never cached.
    """
    #cache lookup
    now = time.monotonic()
    if path in _crowdsec_cache:
        expiry, data = _crowdsec_cache[path]
        if now < expiry:
            logger.debug("CrowdSec cache HIT for %s (expires in %.0fs)", path, expiry - now)
            return data
        else:
            logger.debug("CrowdSec cache EXPIRED for %s", path)
            del _crowdsec_cache[path]

    headers = {
        "x-api-key": _get_crowdsec_api_key(),
        "accept": "application/json",
        "User-Agent": "blue-team-mcp/1.0.0 (TangerangKota-CSIRT)",
    }
    url = f"{CROWDSEC_BASE_URL}{path}"

    # circuit-breaker-wrapped HTTP call - cache hits skip this entirely
    resp = await _api_call("get", url, headers=headers)
    data = resp.json()

    #Cache store
    _crowdsec_cache[path] = (now + CROWDSEC_CACHE_TTL, data)
    merged = len(_crowdsec_cache)
    logger.debug("CrowdSec cache STORE for %s (TTL=%ds, cache_size=%d)", path, CROWDSEC_CACHE_TTL, merged)

    return data

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

    ip: ValidPublicIp = Field(
        ...,
        description="Public IPv4 or IPv6 address to check (e.g. '185.220.101.1').",
        min_length=3,
        max_length=45,
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="_RESPONSE_FORMAT_DESC",
    )

class CrowdsecIpReputationBulkInput(BaseModel):
    """Input model for batch IP reputation lookup via CrowdSec CTI."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ips: list[str] = Field(
        ...,
        description="List of public IP addresses to check (max 25 per call). "
                    "Runs concurrently — 25 IPs resolve in ~3s.",
        min_length=1,
        max_length=25,
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="_RESPONSE_FORMAT_DESC",
    )

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, v: list[str]) -> list[str]:
        invalid = []
        private_ips = []
        for ip in v:
            try:
                ipaddress.ip_address(ip.strip())
            except ValueError:
                invalid.append(ip)
        if invalid:
            raise ValueError(f"Invalid IP(s): {', '.join(invalid)}")
        result: list[str] = []
        for ip in v:
            ip = ip.strip()
            if _is_private_or_reserved(ip):
                private_ips.append(ip)
                logger.warning("crowdsec_ip_reputation_bulk: skipping private/reserved IP %s", ip)
                continue
            result.append(ip)
        if not result:
            raise ValueError(
                f"All IPs are private/reserved ({', '.join(private_ips)}). "
                "This tool only accepts public IPs for threat intelligence lookup. "
                "Use Wazuh Indexer search tools for internal IP investigation."
            )
        return result

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
    Check the threat reputation of a public IP address using the CrowdSec API.

    This tool is READ-ONLY — it queries CrowdSec's threat intelligence database to
    retrieve reputation, observed attack behaviors, related MITRE ATT&CK techniques,
    CVEs exploited from this IP, and first/last-seen history.

    Args:
        params (CrowdsecIpReputationInput): Validated parameters containing:
            - params.ip (str): Public IPv4/IPv6 address to check (e.g. "185.220.101.1")
            - params.response_format ('markdown' | 'json'): Output format (default: markdown)

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
    _audit_log("crowdsec_ip_reputation", {"ip": params.ip})
    try:
        raw = await _crowdsec_request(f"/v2/smoke/{params.ip}")
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        return _handle_api_error(e, context="crowdsec_ip_reputation")

    if params.response_format == "json":
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
            - params.ips (list[str]): 1-10 IP addresses
            - params.response_format ('markdown' | 'json'): Output format (default: markdown)

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
    _audit_log("crowdsec_ip_reputation_bulk", {"count": len(params.ips)})

    async def _lookup_one(ip: str) -> dict[str, Any]:
        try:
            raw = await _crowdsec_request(f"/v2/smoke/{ip}")
            return {"ip": ip, "reputation": raw.get("reputation", "unknown"),
                    "behaviors": raw.get("behaviors", []),
                    "cves": raw.get("cves", [])}
        except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
            return {"ip": ip, "error": _handle_api_error(e, context=ip)}

    results: list[dict[str, Any]] = await asyncio.gather(*[_lookup_one(ip) for ip in params.ips])

    if params.response_format == "json":
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
    client = await _get_client("http")
    response = await client.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def _format_greynoise_markdown(ip: str, raw: dict[str, Any]) -> str:
    """Render GreyNoise Community API response as a human-readable markdown report."""
    lines = [f"# GreyNoise Community — {ip}", ""]

    message = raw.get("message", "")
    if message and message != "Success":
        lines.append(f"> {message}")
        lines.append("")

    lines.append(f"- **IP**: {raw.get('ip', ip)}")

    # Noise
    noise = raw.get("noise")
    if noise is True:
        lines.append("- **Noise**: Yes - this IP has been observed scanning the internet")
    elif noise is False:
        lines.append("- **Noise**: No - this IP has not been observed scanning")
    else:
        lines.append("- **Noise**: unknown")

    # RIOT (business service)
    riot = raw.get("riot")
    if riot is True:
        lines.append("- **RIOT**: Yes - this IP is a known business service (trusted)")
    elif riot is False:
        lines.append("- **RIOT**: No - not a known business service")
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

@mcp.tool(
    name="greynoise_ip_context",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def greynoise_ip_context(ip: ValidPublicIp, response_format: Literal["markdown", "json"] = "markdown") -> str:
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
    _audit_log("greynoise_ip_context", {"ip": ip})
    try:
        raw = await _greynoise_community_request(ip)
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        return _handle_api_error(e, context="greynoise_ip_context")

    if response_format == "json":
        output = {
            "ip": raw.get("ip", ip),
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
        result = _format_greynoise_markdown(ip, raw)

    return _truncate_if_needed(result)


# NETRA THREAT INTELLIGENCE (Adjusted by the response of NETRA TI)
# Set NETRA_API_KEY to enable the netra_ip_analysis tool.
def _get_netra_api_key() -> str:
    """Read Netra Threat Intelligence API key from environment."""
    key = os.environ.get(NETRA_API_KEY_ENV)
    if not key:
        raise RuntimeError(
            f"Environment variable {NETRA_API_KEY_ENV} is not set. "
            "Set your Netra Threat Intelligence API key before using netra_ip_analysis. "
            "Request a key from your Netra administrator."
        )
    return key


async def _netra_request(path: str) -> dict[str, Any]:
    """Reusable async GET request to the Netra Threat Intelligence API."""
    headers = {
        "X-API-Key": _get_netra_api_key(),
        "accept": "application/json",
        "User-Agent": "blue-team-mcp/1.0.0 (TangerangKota-CSIRT)",
    }
    url = f"{NETRA_BASE_URL}{path}"
    client = await _get_client("netra", verify=NETRA_VERIFY_SSL, max_keepalive=5, max_connections=20)
    response = await client.get(url, headers=headers)
    response.raise_for_status()
    return response.json()


def _format_netra_markdown(ip: str, raw: dict[str, Any]) -> str:
    """Render Netra Threat Intelligence API response as a human-readable markdown report.

    Netra aggregates multiple threat-intel sources (VirusTotal, AbuseIPDB, CrowdSec,
    IPAPI, Argus, and optional ThreatBook/CriminalIP/OpenCTI) and produces a composite
    threat score plus an AI-generated insight.
    """
    data = raw.get("data", {})
    results = data.get("results", {})
    meta = raw.get("meta", {})

    ts = results.get("threat_score", {})
    ai = results.get("ai_insight", {})
    vt = results.get("virustotal", {})
    ab = results.get("abuseipdb", {})
    cs = results.get("crowdsec", {})
    ipapi = results.get("ipapi", {})
    argus = results.get("argus_reports", {})

    # Header From Netra Response
    threat_score_val = ts.get("score", "?")
    threat_level = ts.get("level", "unknown")

    level_emoji = {
        "CLEAN": "🟢",
        "LOW": "🟡",
        "MEDIUM": "🟠",
        "HIGH": "🔴",
        "CRITICAL": "⛔",
    }
    emoji = level_emoji.get(threat_level.upper(), "⚪")

    lines = [f"# {emoji} Netra Threat Intelligence — {ip}", ""]
    lines.append(f"**Threat Level**: {threat_level}  |  **Score**: {threat_score_val}/100")

    # Source availability
    available = ts.get("sources_available", [])
    failed = ts.get("sources_failed", [])
    if available:
        lines.append(f"\n**Sources queried**: {', '.join(s for s in available if s != 'cyberprotect')}")
    if failed:
        lines.append(f"**Sources unavailable**: {', '.join(failed)}")

    # Threat Score Breakdown
    breakdown = ts.get("breakdown", {})
    if breakdown:
        lines.append("")
        lines.append("## 📊 Threat Score Breakdown")
        for source, detail in breakdown.items():
            if not isinstance(detail, dict):
                continue
            raw_score = detail.get("raw")
            weight = detail.get("weight", 0)
            if raw_score is not None and weight > 0:
                lines.append(f"- **{source}**: {raw_score:.1f} (weight: {weight:.0%})")

    # AI Insight Netra
    if ai.get("success") is not False and (ai.get("assessment") or ai.get("indicators")):
        lines.append("")
        lines.append("## 🤖 AI Assessment")
        lines.append(f"**Model**: {ai.get('model', 'unknown')}  |  **Confidence**: {ai.get('confidence', 'N/A')}")
        lines.append("")
        lines.append(f"> {ai.get('assessment', 'No assessment available.')}")

        indicators = ai.get("indicators") or []
        if indicators:
            lines.append("")
            lines.append("### Key Indicators")
            for ind in indicators:
                lines.append(f"- {ind}")

        actions = ai.get("actions") or []
        if actions:
            lines.append("")
            lines.append("### Recommended Actions")
            for act in actions:
                lines.append(f"- {act}")

    # Individual Source Results
    lines.append("")
    lines.append("## 🔍 Source Results")

    # VirusTotal
    if vt.get("success") and vt.get("results"):
        vt_data = vt["results"].get("data", {})
        vt_attrs = vt_data.get("attributes", {})
        vt_stats = vt_attrs.get("last_analysis_stats", {})
        vt_total = sum(vt_stats.values()) if vt_stats else 0
        vt_mal = vt_stats.get("malicious", 0)
        vt_sus = vt_stats.get("suspicious", 0)
        lines.append(f"- **VirusTotal**: {vt_mal} malicious / {vt_sus} suspicious / {vt_total} total  "
                     f"| Reputation: {vt_attrs.get('reputation', 'N/A')}  "
                     f"| ASN: {vt_attrs.get('asn', 'N/A')} ({vt_attrs.get('as_owner', 'N/A')})")

    # AbuseIPDB
    if ab.get("success") and ab.get("results"):
        ab_data = ab["results"].get("data", {})
        lines.append(
            f"- **AbuseIPDB**: Confidence {ab_data.get('abuseConfidenceScore', '?')}%  "
            f"| {ab_data.get('totalReports', 0)} reports  "
            f"| ISP: {ab_data.get('isp', 'N/A')}  "
            f"| Country: {ab_data.get('countryCode', 'N/A')}"
        )

    # CrowdSec
    if cs.get("success") and cs.get("results"):
        cs_data = cs["results"]
        cs_reputation = cs_data.get("reputation", "unknown")
        cs_fps = cs_data.get("classifications", {}).get("false_positives", [])
        cs_fp_labels = [fp.get("label", "") for fp in cs_fps] if cs_fps else []
        fp_note = f" (⚠️ known as: {', '.join(cs_fp_labels)})" if cs_fp_labels else ""
        lines.append(
            f"- **CrowdSec**: Reputation: {cs_reputation}{fp_note}  "
            f"| Confidence: {cs_data.get('confidence', '?')}  "
            f"| AS: {cs_data.get('as_name', 'N/A')} (AS{cs_data.get('as_num', '?')})  "
            f"| First seen: {cs_data.get('history', {}).get('first_seen', '?')}"
        )

    # IPAPI / Geo
    if ipapi.get("success") and ipapi.get("results"):
        geo = ipapi["results"]
        lines.append(
            f"- **IPAPI (Geo)**: {geo.get('city', '')}, {geo.get('regionName', '')}, "
            f"{geo.get('country', '')} ({geo.get('countryCode', '')})  "
            f"| ISP: {geo.get('isp', 'N/A')}  "
            f"| AS: {geo.get('as', 'N/A')}"
        )

    # Argus Reports
    if argus.get("success") and argus.get("results"):
        ar = argus["results"]
        lines.append(f"- **Argus Reports**: {ar.get('total_reports', 0)} reports  "
                     f"| Score: {ar.get('scores', 0)}  "
                     f"| Unique reporters: {ar.get('unique_reporters', 0)}")

    # Failed Sources (with error details) From Netra
    error_sources = {k: v for k, v in results.items()
                     if isinstance(v, dict) and v.get("success") is False and v.get("error")}
    if error_sources:
        lines.append("")
        lines.append("## ⚠️ Source Errors")
        for name, detail in sorted(error_sources.items()):
            error_msg = str(detail.get("error", "unknown"))
            # Truncate long error messages
            if len(error_msg) > 200:
                error_msg = error_msg[:200] + "..."
            lines.append(f"- **{name}**: {error_msg}")

    # Meta
    lines.append("")
    lines.append("---")
    analyzed_at = meta.get("analyzed_at", data.get("created_at", "unknown"))
    lines.append(f"*Analyzed at: {analyzed_at}*")

    rl = meta.get("rate_limit", {})
    if rl:
        lines.append(f"*Rate limit: {rl.get('used', '?')}/{rl.get('max', '?')} "
                     f"({rl.get('remaining', '?')} remaining)*")

    return "\n".join(lines)


@mcp.tool(
    name="netra_ip_analysis",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def netra_ip_analysis(ip: ValidPublicIp, response_format: Literal["markdown", "json"] = "markdown", bypass_redaction: bool = False) -> str:
    """Analyze a public IP address using Netra Threat Intelligence.

    This tool is READ ONLY - it queries the Netra Threat Intelligence API to
    retrieve threat analysis, classification, and contextual data for a given IP.

    Args:
        params (NetraIpAnalysisInput): Validated parameters containing:
            - ip (str): Public IPv4/IPv6 address to analyze (e.g. "185.220.101.1")
            - response_format ('markdown' | 'json'): Output format (default: markdown)

    Returns:
        str: If markdown, a formatted analysis report with threat score, AI assessment,
        per-source detection summaries, and rate-limit metadata.
        If json, a structured object with the same data organized for machine consumption.

    Example usage:
        - Use when: "Check if IP 185.220.101.1 is malicious according to Netra"
        - Use when: "Triaging an alert — get Netra's analysis of the source IP"
        - Do NOT use for private/internal IPs — this tool queries an external API

    Error Handling:
        - "Error: Invalid or missing API key (401)" if NETRA_API_KEY is missing/wrong
        - "Error: No data found for this target (404)" if IP has no analysis data
        - "Error: Rate limit reached (429)" if API quota is exhausted
        - IP format validation is handled automatically by Pydantic before the request
    """
    _audit_log("netra_ip_analysis", {"ip": ip})
    try:
        raw = await _netra_request(f"/analysis/{ip}")
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        return _handle_api_error(e, context="netra_ip_analysis")

    if response_format == "json":
        data = raw.get("data", {})
        results = data.get("results", {})
        meta = raw.get("meta", {})

        ts = results.get("threat_score", {})
        ai = results.get("ai_insight", {})
        vt = results.get("virustotal", {})
        ab = results.get("abuseipdb", {})
        cs = results.get("crowdsec", {})
        ipapi = results.get("ipapi", {})
        argus = results.get("argus_reports", {})

        # Extract key VT fields
        vt_attrs = {}
        if vt.get("success") and vt.get("results"):
            vt_attrs = vt["results"].get("data", {}).get("attributes", {})

        # Extract key AbuseIPDB fields
        ab_data = {}
        if ab.get("success") and ab.get("results"):
            ab_data = ab["results"].get("data", {})

        # Extract key CrowdSec fields
        cs_data = {}
        if cs.get("success") and cs.get("results"):
            cs_res = cs["results"]
            cs_data = {
                "reputation": cs_res.get("reputation"),
                "confidence": cs_res.get("confidence"),
                "as_name": cs_res.get("as_name"),
                "as_num": cs_res.get("as_num"),
                "first_seen": cs_res.get("history", {}).get("first_seen"),
                "last_seen": cs_res.get("history", {}).get("last_seen"),
                "false_positives": [
                    fp.get("label") for fp in
                    cs_res.get("classifications", {}).get("false_positives", [])
                ],
            }

        # Extract geo
        geo = {}
        if ipapi.get("success") and ipapi.get("results"):
            geo = ipapi["results"]

        output = {
            "ip": ip,
            "observable": data.get("observable"),
            "analyzed_at": meta.get("analyzed_at"),
            "threat_score": {
                "score": ts.get("score"),
                "level": ts.get("level"),
                "breakdown": {
                    source: {
                        "raw": detail.get("raw") if isinstance(detail, dict) else None,
                        "weight": detail.get("weight") if isinstance(detail, dict) else None,
                    }
                    for source, detail in ts.get("breakdown", {}).items()
                    if isinstance(detail, dict) and detail.get("weight", 0) > 0
                },
                "sources_available": ts.get("sources_available"),
                "sources_failed": ts.get("sources_failed"),
            },
            "ai_insight": {
                "assessment": ai.get("assessment"),
                "indicators": ai.get("indicators"),
                "actions": ai.get("actions"),
                "confidence": ai.get("confidence"),
                "model": ai.get("model"),
            } if ai.get("success") is not False else None,
            "virustotal": {
                "malicious": vt_attrs.get("last_analysis_stats", {}).get("malicious"),
                "suspicious": vt_attrs.get("last_analysis_stats", {}).get("suspicious"),
                "harmless": vt_attrs.get("last_analysis_stats", {}).get("harmless"),
                "undetected": vt_attrs.get("last_analysis_stats", {}).get("undetected"),
                "reputation": vt_attrs.get("reputation"),
                "as_owner": vt_attrs.get("as_owner"),
                "country": vt_attrs.get("country"),
            } if vt.get("success") else None,
            "abuseipdb": {
                "abuse_confidence_score": ab_data.get("abuseConfidenceScore"),
                "total_reports": ab_data.get("totalReports"),
                "isp": ab_data.get("isp"),
                "country": ab_data.get("countryCode"),
                "usage_type": ab_data.get("usageType"),
                "last_reported": ab_data.get("lastReportedAt"),
            } if ab.get("success") else None,
            "crowdsec": cs_data if cs.get("success") else None,
            "ipapi_geo": geo if ipapi.get("success") else None,
            "argus_reports": {
                "total_reports": argus.get("results", {}).get("total_reports"),
                "score": argus.get("results", {}).get("scores"),
            } if argus.get("success") else None,
            "source_errors": {
                k: str(v.get("error", "unknown"))[:200]
                for k, v in results.items()
                if isinstance(v, dict) and v.get("success") is False and v.get("error")
            } or None,
            "rate_limit": {
                "used": meta.get("rate_limit", {}).get("used"),
                "max": meta.get("rate_limit", {}).get("max"),
                "remaining": meta.get("rate_limit", {}).get("remaining"),
            },
        }
        # Strip None values for cleaner output
        output = {k: v for k, v in output.items() if v is not None}
        result = json.dumps(output, indent=2, ensure_ascii=False)
    else:
        result = _format_netra_markdown(ip, raw)

    return _truncate_if_needed(result)


# ARGUS THREAT INTELLIGENCE (AUL : Adjusted from ARGUS Responses.)
# Set ARGUS_API_KEY and ARGUS_BASE_URL to enable the argus_ip_lookup tool.
def _get_argus_api_key() -> str:
    """Read Argus Threat Intelligence API key from environment."""
    key = os.environ.get(ARGUS_API_KEY_ENV)
    if not key:
        raise RuntimeError(
            f"Environment variable {ARGUS_API_KEY_ENV} is not set. "
            "Set your Argus Threat Intelligence API key before using argus_ip_lookup. "
            "Request a key from your Argus administrator."
        )
    return key


async def _argus_request(path: str, payload: dict) -> dict[str, Any]:
    """Reusable async POST request to the Argus Threat Intelligence API."""
    if not ARGUS_BASE_URL:
        raise RuntimeError(
            "ARGUS_BASE_URL is not set. "
            "Set the Argus Threat Intelligence base URL before using argus_ip_lookup."
        )
    headers = {
        "Authorization": f"Bearer {_get_argus_api_key()}",
        "Content-Type": "application/json",
        "accept": "application/json",
        "User-Agent": "blue-team-mcp/1.0.0 (TangerangKota-CSIRT)",
    }
    url = f"{ARGUS_BASE_URL}{path}"

    resp = await _api_call("post", url, client_name="argus", verify=ARGUS_VERIFY_SSL,
                            headers=headers, json=payload)
    return resp.json()


def _format_argus_markdown(ip: str, raw: dict[str, Any]) -> str:
    """Render Argus Threat Intelligence API response as a human-readable markdown report."""
    results = raw.get("results", {})
    ipapi = results.get("ipapi", {})
    vt = results.get("virustotal", {})
    ab = results.get("abuseipdb", {})
    cp = results.get("cyberprotect", {})
    cs = results.get("crowdsec", {})
    tb = results.get("threatbook", {})
    argus_r = results.get("argus_reports", {})

    created_at = raw.get("created_at", "unknown")

    lines: list[str] = [
        f"# Argus Threat Intelligence — {ip}",
        "",
        f"**Analyzed**: {created_at}",
        "",
        "## Threat Summary",
        "",
        "| Source | Status | Key Finding |",
        "|--------|--------|-------------|",
    ]

    # VirusTotal summary
    if vt.get("success") and vt.get("results"):
        vt_attrs = vt["results"].get("data", {}).get("attributes", {})
        vt_stats = vt_attrs.get("last_analysis_stats", {})
        vt_mal = vt_stats.get("malicious", 0)
        vt_total = sum(vt_stats.values())
        lines.append(f"| VirusTotal | ✓ | {vt_mal}/{vt_total} malicious |")
    else:
        vt_err = vt.get("error", "") if isinstance(vt, dict) else ""
        lines.append(f"| VirusTotal | ⚠️ | {vt_err[:50] or 'No data'} |")

    # AbuseIPDB summary
    if ab.get("success") and ab.get("results"):
        ab_data = ab["results"].get("data", {})
        ab_score = ab_data.get("abuseConfidenceScore", 0)
        ab_reports = ab_data.get("totalReports", 0)
        lines.append(f"| AbuseIPDB | ✓ | {ab_score}% confidence, {ab_reports} reports |")
    else:
        ab_err = ab.get("error", "") if isinstance(ab, dict) else ""
        lines.append(f"| AbuseIPDB | ⚠️ | {ab_err[:50] or 'No data'} |")

    # CyberProtect summary
    if cp.get("success") and cp.get("results"):
        cp_ts = cp["results"].get("threatscore", {})
        cp_score = cp_ts.get("value", "?")
        cp_level = cp_ts.get("level", "unknown")
        lines.append(f"| CyberProtect | ✓ | {cp_level} ({cp_score}) |")
    else:
        cp_err = cp.get("error", "") if isinstance(cp, dict) else ""
        lines.append(f"| CyberProtect | ⚠️ | {cp_err[:50] or 'No data'} |")

    # CrowdSec summary
    if cs.get("success") and cs.get("results"):
        cs_rep = cs["results"].get("reputation", "?")
        lines.append(f"| CrowdSec | ✓ | Reputation: {cs_rep} |")
    else:
        cs_err = cs.get("error", "") if isinstance(cs, dict) else ""
        lines.append(f"| CrowdSec | ⚠️ | {cs_err[:50] or 'No data'} |")

    # ThreatBook summary
    if tb.get("success") and tb.get("results"):
        lines.append(f"| ThreatBook | ✓ | Data available |")
    else:
        tb_err = tb.get("error", "") if isinstance(tb, dict) else ""
        lines.append(f"| ThreatBook | ⚠️ | {tb_err[:50] or 'No data'} |")

    lines.append("")

    # Geo (IPAPI)
    if ipapi.get("success") and ipapi.get("results"):
        geo = ipapi["results"]
        lines.extend([
            "## Geo (IPAPI)",
            "",
            f"- **Country**: {geo.get('country', '?')} ({geo.get('countryCode', '?')})",
            f"- **Region**: {geo.get('regionName', '?')}, {geo.get('city', '?')}",
            f"- **ISP**: {geo.get('isp', '?')} | **AS**: {geo.get('as', '?')}",
            "",
        ])

    # VirusTotal details
    if vt.get("success") and vt.get("results"):
        vt_attrs = vt["results"].get("data", {}).get("attributes", {})
        vt_stats = vt_attrs.get("last_analysis_stats", {})
        vt_mal = vt_stats.get("malicious", 0)
        vt_sus = vt_stats.get("suspicious", 0)
        vt_harm = vt_stats.get("harmless", 0)
        vt_und = vt_stats.get("undetected", 0)
        vt_tags = vt_attrs.get("tags", [])
        vt_as_owner = vt_attrs.get("as_owner", "?")
        vt_asn = vt_attrs.get("asn", "?")
        lines.extend([
            "## VirusTotal",
            "",
            f"- {vt_mal} malicious / {vt_sus} suspicious / {vt_harm} harmless / {vt_und} undetected",
            f"- Reputation: {vt_attrs.get('reputation', '?')}",
            f"- ASN: {vt_asn} ({vt_as_owner})",
        ])
        if vt_tags:
            lines.append(f"- Tags: {', '.join(vt_tags)}")
        lines.append("")

    # AbuseIPDB details
    if ab.get("success") and ab.get("results"):
        ab_data = ab["results"].get("data", {})
        ab_score = ab_data.get("abuseConfidenceScore", 0)
        ab_reports = ab_data.get("totalReports", 0)
        ab_users = ab_data.get("numDistinctUsers", 0)
        ab_last = ab_data.get("lastReportedAt", "?")
        ab_isp = ab_data.get("isp", "?")
        ab_usage = ab_data.get("usageType", "?")
        lines.extend([
            "## AbuseIPDB",
            "",
            f"- **Confidence**: {ab_score}% | **Reports**: {ab_reports} from {ab_users} reporters",
            f"- **ISP**: {ab_isp}",
            f"- **Usage**: {ab_usage} | **Last reported**: {ab_last}",
        ])
        # Top 3 recent report comments
        ab_reports_list = ab_data.get("reports", [])
        if ab_reports_list:
            lines.append("- **Recent reports**:")
            for r in ab_reports_list[:3]:
                comment = (r.get("comment", "") or "")[:120]
                if comment:
                    lines.append(f"  - {comment}")
        lines.append("")

    # CyberProtect details
    if cp.get("success") and cp.get("results"):
        cp_data = cp["results"]
        cp_ts = cp_data.get("threatscore", {})
        cp_score = cp_ts.get("value", "?")
        cp_level = cp_ts.get("level", "unknown")
        cp_cats = cp_ts.get("categories", [])
        cp_tags = cp_data.get("tags", [])
        cp_sources = cp_data.get("sources", [])
        cp_obs = cp_data.get("observable", {})
        cp_first = cp_obs.get("first_seen", "?")
        cp_last = cp_obs.get("last_seen", "?")
        bl_count = sum(1 for s in cp_sources if s.get("type") == "blocklist")
        rep_count = sum(1 for s in cp_sources if s.get("type") == "reputation")
        lines.extend([
            "## CyberProtect",
            "",
            f"- **Score**: {cp_score} ({cp_level})",
            f"- **Categories**: {', '.join(cp_cats) if cp_cats else 'none'}",
            f"- **Tags**: {', '.join(cp_tags) if cp_tags else 'none'}",
            f"- **Sources**: {bl_count} blocklist, {rep_count} reputation",
            f"- **First seen**: {cp_first} | **Last seen**: {cp_last}",
            "",
        ])

    # Argus Reports
    if argus_r.get("success") and argus_r.get("results"):
        ar = argus_r["results"]
        ar_total = ar.get("total_reports", 0)
        ar_unique = ar.get("unique_reporters", 0)
        ar_score = ar.get("scores", 0)
        lines.extend([
            "## Argus Reports",
            "",
            f"- {ar_total} reports from {ar_unique} reporter(s) | Score: {ar_score}",
        ])
        ar_reports = ar.get("reports", [])
        for r in ar_reports[:5]:
            desc = (r.get("description", "") or "")[:120]
            reporter = r.get("reporter", "?")
            created = r.get("created_at", "?")
            lines.append(f"- **{reporter}** ({created}): {desc}")
        lines.append("")

    # Source Errors
    error_sources = {}
    for name, src in [
        ("VirusTotal", vt), ("AbuseIPDB", ab), ("CyberProtect", cp),
        ("CrowdSec", cs), ("ThreatBook", tb), ("IPAPI", ipapi),
        ("Argus Reports", argus_r),
    ]:
        if isinstance(src, dict) and src.get("success") is False:
            error_sources[name] = (src.get("error") or "")[:200]
    if error_sources:
        lines.append("## Source Errors")
        for name, err in error_sources.items():
            lines.append(f"- **{name}**: {err}")
        lines.append("")

    lines.append("---")
    lines.append(f"*Analyzed at: {created_at}*")

    return "\n".join(lines)


@mcp.tool(
    name="argus_ip_lookup",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def argus_ip_lookup(ip: ValidPublicIp, response_format: Literal["markdown", "json"] = "markdown") -> str:
    """Analyze a public IP address using Argus Threat Intelligence by TangerangKota-CSIRT.

    This tool is READ-ONLY — it queries the Argus Threat Intelligence API which
    aggregates data from multiple sources: VirusTotal, AbuseIPDB, CyberProtect,
    CrowdSec CTI, ThreatBook, IPAPI geo-location, and local Argus reports.

    Each source result is surfaced independently; partial source failures
    (e.g., rate-limited upstream) are reported inline and do not abort the call.

    Args:
        params (ArgusIpLookupInput): Validated parameters containing:
            - ip (str): Public IPv4/IPv6 address to analyze
            - response_format ('markdown' | 'json'): Output format (default: markdown)

    Returns:
        str: If markdown, a formatted analysis report with threat summary table,
        per-source details (VirusTotal, AbuseIPDB, CyberProtect, Argus Reports),
        geo-location, and source error reporting.
        If json, the raw aggregated API response.

    Example usage:
        - Use when: "Check if IP 117.247.110.24 is malicious according to Argus TI"
        - Use when: "Get multi-source threat intel on a suspicious IP"
        - Do NOT use for private/internal IPs — this tool queries an external API

    Error Handling:
        - "Error: Invalid or missing API key (401)" if ARGUS_API_KEY is missing/wrong
        - "Error: ARGUS_BASE_URL is not set" if base URL is not configured
        - "Error: No data found for this target (404)" if IP has no data
        - "Error: Rate limit reached (429)" if API quota is exhausted
        - Per-source failures (e.g., ThreatBook 429) are reported in the output
    """
    _audit_log("argus_ip_lookup", {"ip": ip})
    try:
        raw = await _argus_request("/lookup-jobs", {"observable": ip})
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        return _handle_api_error(e, context="argus_ip_lookup")

    if response_format == "json":
        return _truncate_if_needed(json.dumps(raw, indent=2, ensure_ascii=False))

    result = _format_argus_markdown(ip, raw)
    return _truncate_if_needed(result)


# LOG ANALYSIS
class LogInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    lines: int = Field(default=200, description="Number of recent lines to return", ge=1, le=MAX_LOG_LINES)
    grep: Optional[str] = Field(default=None, max_length=MAX_GREP_PATTERN_LENGTH, description="Optional keyword/regex to filter lines (case-insensitive)")
    bypass_redaction: bool = Field(default=False, description="When true, skip PII/credential redaction for audit investigations")

@mcp.tool(
    name="blueteam_read_auth_log",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_read_auth_log(params: LogInput) -> str:
    """Read and optionally filter /var/log/auth.log for SSH, sudo, and PAM events.

    Args:
        params.lines (int): How many tail lines to read (default 200, max 2000)
        params.grep (str, optional): Filter to params.lines containing this pattern

    Returns:
        str: Matching log params.lines or error JSON
    """
    _audit_log("blueteam_read_auth_log", {"lines": params.lines})
    log_path = "/var/log/auth.log"
    # Fallback for systems using journald only
    if not Path(log_path).exists():
        cmd = ["journalctl", "-u", "ssh", "-n", str(params.lines), "--no-pager"]
        if params.grep:
            cmd += ["--grep", params.grep]
        r = _run(cmd)
        return _redact_alert_data(r["stdout"] or r["stderr"], bypass=params.bypass_redaction)

    content = _tail_file(log_path, params.lines)
    if params.grep:
        safe_grep = _sanitize_regex(params.grep)
        params.lines = [l for l in content.splitlines() if re.search(safe_grep, l, re.IGNORECASE)]
        return "\n".join(params.lines) if params.lines else f"No params.lines matched filter: {params.grep}"
    return content

@mcp.tool(
    name="blueteam_read_syslog",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_read_syslog(params: LogInput) -> str:
    """Read /var/log/syslog or journalctl for general system events.

    Args:
        params.lines (int): Lines to return
        params.grep (str, optional): Filter pattern

    Returns:
        str: Log content
    """
    _audit_log("blueteam_read_syslog", {"lines": params.lines})
    for path in ["/var/log/syslog", "/var/log/messages"]:
        if Path(path).exists():
            content = _tail_file(path, params.lines)
            if params.grep:
                safe_grep = _sanitize_regex(params.grep)
                lines = [l for l in content.splitlines() if re.search(safe_grep, l, re.IGNORECASE)]
                return _redact_alert_data("\n".join(lines), bypass=params.bypass_redaction) if lines else f"No matches for: {params.grep}"
            return _redact_alert_data(content, bypass=params.bypass_redaction)
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
    path: Optional[str] = Field(default=None, max_length=256, description="Override log path. Auto-resolved from server+log_type if omitted.")
    bypass_redaction: bool = Field(default=False, description="When true, skip PII/credential redaction for audit investigations")

@mcp.tool(
    name="blueteam_read_web_log",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_read_web_log(params: WebLogInput) -> str:
    """Read nginx or Apache access/error logs. Great for spotting web attacks.

    Args:
        params.server: 'nginx' or 'apache'
        params.log_type: 'access' or 'error'
        params.lines: Lines to read
        params.grep: Optional filter

    Returns:
        str: Log params.lines
    """
    _audit_log("blueteam_read_web_log", {"lines": params.lines})
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
    if params.log_type not in paths[server]:
        return json.dumps({"error": f"Unknown log type '{params.log_type}'. Use 'access' or 'error'."})

    log_path = params.path if params.path else paths[server][params.log_type]
    content = _tail_file(log_path, params.lines)
    if params.grep:
        safe_grep = _sanitize_regex(params.grep)
        filtered = [l for l in content.splitlines() if re.search(safe_grep, l, re.IGNORECASE)]
        return _redact_alert_data("\n".join(filtered) if filtered else f"No matches for: {params.grep}", bypass=params.bypass_redaction)
    return _redact_alert_data(content, bypass=params.bypass_redaction)

class JournalInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    unit: Optional[str] = Field(default=None, max_length=64, description="Systemd unit name, e.g. 'sshd', 'nginx', 'cron'")
    since: Optional[str] = Field(default="1 hour ago", max_length=64, description="Time range, e.g. '2 hours ago', '2024-01-15 10:00'")
    lines: int = Field(default=200, ge=1, le=MAX_LOG_LINES)
    grep: Optional[str] = Field(default=None, max_length=MAX_GREP_PATTERN_LENGTH)
    bypass_redaction: bool = Field(default=False, description="When true, skip PII/credential redaction for audit investigations")

@mcp.tool(
    name="blueteam_journalctl",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
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
    _audit_log("blueteam_journalctl", {"unit": params.unit})
    cmd = ["journalctl", "--no-pager", "-n", str(params.lines)]
    if params.unit:
        cmd += ["-u", params.unit]
    if params.since:
        cmd += ["--since", params.since]
    if params.grep:
        cmd += ["--grep", params.grep]
    r = _run(cmd)
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=params.bypass_redaction)

# NETWORK MONITORING
@mcp.tool(
    name="blueteam_list_listening_ports",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_list_listening_ports(bypass_redaction: bool = False) -> str:
    """List all TCP/UDP ports currently listening, with owning process.
    Equivalent to 'ss -tulpn'. Identifies unexpected services.

    Returns:
        str: Port table with process names and PIDs
    """
    _audit_log("blueteam_list_listening_ports", {})
    r = _run(["ss", "-tulpn"])
    if r["returncode"] != 0:
        r = _run(["netstat", "-tulpn"])
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)


@mcp.tool(
    name="blueteam_list_connections",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_list_connections(bypass_redaction: bool = False) -> str:
    """List all established TCP connections with remote IPs and local processes.
    Useful for spotting unexpected outbound connections (beaconing, exfil).

    Returns:
        str: Active connection table
    """
    _audit_log("blueteam_list_connections", {})
    r = _run(["ss", "-tnp", "state", "established"])
    if r["returncode"] != 0:
        r = _run(["netstat", "-tnp"])
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)


class CaptureInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    interface: str = Field(default="eth0", max_length=32, description="Network interface to capture on")
    count: int = Field(default=100, description="Number of packets to capture", ge=1, le=5000)
    filter_expr: Optional[str] = Field(default=None, max_length=200, description="BPF filter expression, e.g. 'port 80', 'host 10.0.0.5'")
    output_file: Optional[str] = Field(default=None, max_length=256, description="Optional path to save .pcap file (must be under CAPTURE_OUTPUT_DIR)")
    bypass_redaction: bool = Field(default=False, description="When true, return raw internal IPs without RFC1918 masking. Overrides BLUETEAM_REDACT_PII for this call only — use for internal audit investigations.")


@mcp.tool(
    name="blueteam_capture_traffic",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def blueteam_capture_traffic(params: CaptureInput) -> str:
    """Capture live network traffic using tcpdump. Requires root or CAP_NET_RAW.
    Read-only for packet inspection; writes pcap files when params.output_file is set.
    Makes network I/O (openWorldHint).

    Args:
        params.interface: Network interface
        params.count: Packet count to capture then stop
        params.filter_expr: BPF filter (optional)
        params.output_file: Save pcap to this params.path (optional, under CAPTURE_OUTPUT_DIR)

    Returns:
        str: Packet summary or params.path to saved pcap
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
    else:
        # Redact internal RFC1918 IPs from stdout text output.
        # Connection metadata contains internal endpoint IPs; mask them without altering
        # the packet-capture file itself (which is forensic evidence and always unredacted).
        result = _redact_alert_data(result, bypass=params.bypass_redaction)
    _audit_log("blueteam_capture_traffic", {"interface": params.interface, "count": params.count}, result[:200])
    return result

# WAZUH SIEM TANGKOT
@mcp.tool(
    name="blueteam_wazuh_agents",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_wazuh_agents(limit: int = 100, cursor: Optional[str] = None) -> str:
    """List Wazuh agents with cursor pagination — one page per call.
    Pass the returned next_cursor back as the cursor parameter for the next page.
    Requires WAZUH_API_URL and WAZUH_API_PASSWORD.

    Args:
        limit: Agents per page (default 100, max 10000)
        cursor: next_cursor from previous response (omit for first page)

    Returns:
        str: JSON with agents, total, offset, limit, and next_cursor
    """
    _audit_log("blueteam_wazuh_agents", {})
    offset = 0
    if cursor:
        decoded = _decode_cursor(cursor)
        if decoded:
            offset = decoded.get("offset", 0)

    data = await _wazuh_api_get("/agents", {
        "offset": str(offset),
        "limit": str(limit),
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

    return _truncate_if_needed(json.dumps({
        "agents": summary,
        "total": total,
        "offset": offset,
        "limit": limit,
        "next_cursor": next_cursor,
    }, indent=2))

@mcp.tool(
    name="blueteam_wazuh_agents_summary",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_wazuh_agents_summary() -> str:
    """Get Wazuh agent count by status (active, disconnected, pending, never_connected).
    Quick overview of agent health.

    Returns:
        str: JSON with counts per status
    """
    _audit_log("blueteam_wazuh_agents_summary", {})
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


@mcp.tool(
    name="blueteam_wazuh_manager_logs",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_wazuh_manager_logs(log_type: str = "alerts", limit: int = 50, cursor: Optional[str] = None) -> str:
    """Fetch Wazuh manager logs with cursor pagination — one page per call.
    Pass the returned next_cursor back as cursor for the next page.
    Compatible with Wazuh 4.x API (uses 'tag' parameter).

    Args:
        log_type: alerts, api, cluster, or integrations
        limit: Max entries per page (default 50, max 1000)
        cursor: next_cursor from previous response (omit for first page)

    Returns:
        str: JSON with logs, total, offset, limit, and next_cursor
    """
    _audit_log("blueteam_wazuh_manager_logs", {})
    valid = ("alerts", "api", "cluster", "integrations")
    if log_type not in valid:
        return json.dumps({"error": f"log_type must be one of: {valid}"})

    offset = 0
    if cursor:
        decoded = _decode_cursor(cursor)
        if decoded:
            offset = decoded.get("offset", 0)

    # Wazuh Manager API hard-caps limit at 500 - values > 500 return 400.
    # Auto-cap here so LLM clients pass large values without triggering API errors.
    wazuh_safe_limit = min(limit, 500)
    api_params = {"offset": str(offset), "limit": str(wazuh_safe_limit), "pretty": "true"}
    tag = _WAZUH_LOG_TAG.get(log_type)
    if tag:
        api_params["tag"] = tag
    # Never send "type" - Wazuh 4.x only accepts "tag"; "type" causes 400 ERROR
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

    return _truncate_if_needed(json.dumps({
        "logs": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "next_cursor": next_cursor,
    }, indent=2))


# Path to Wazuh alerts file (on the host where MCP runs; must be Wazuh manager or have mounts file system)
_WAZUH_ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"
_WAZUH_ALERTS_MAX_LINES = 2000  # safety cap


@mcp.tool(
    name="blueteam_wazuh_alerts",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
)
async def blueteam_wazuh_alerts(agent_name: Optional[str] = None, srcip: Optional[str] = None, since: Optional[str] = None, until: Optional[str] = None, limit: int = 500, cursor: Optional[str] = None, bypass_redaction: bool = False) -> str:
    """Read Wazuh security alerts — local alerts.json first, auto-fallback to Indexer.
    When /var/ossec/logs/alerts/alerts.json is available (MCP on Wazuh Manager host),
    reads directly from the file. When the file is absent (remote Wazuh Manager),
    automatically delegates to the Wazuh Indexer (OpenSearch) — no tool switch needed.

    Args:
        agent_name: Optional filter by agent name (e.g. HYDRA-DC)
        limit: Max alerts per page (default 100, max 2000)
        cursor: next_cursor from previous response (omit for first page)

    Returns:
        str: JSON with alerts, count, next_cursor, and source field ("local" or "wazuh-indexer")
    """
    _audit_log("blueteam_wazuh_alerts", {})
    ok, err = _validate_path(_WAZUH_ALERTS_PATH, ALLOWED_PATH_PREFIXES)
    if not ok:
        return json.dumps({"error": err})
    p = Path(_WAZUH_ALERTS_PATH)
    if not p.exists():
        # Self healing fallback: when alerts.json is absent (remote Wazuh Manager),
        # transparently delegate to the Wazuh Indexer instead of returning an error.
        # This avoids forcing the LLM to manually switch tools.
        if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
            return json.dumps({
                "error": "[CRITICAL METADATA] This tool is disabled because the Wazuh Manager "
                         "is running on a remote host and the Wazuh Indexer is not configured. "
                         "DO NOT RETRY this local tool. Set WAZUH_INDEXER_URL and "
                         "WAZUH_INDEXER_PASSWORD to enable automatic indexer fallback, "
                         "or use 'blueteam_wazuh_manager_logs' to query security events.",
                "path": _WAZUH_ALERTS_PATH,
            }, indent=2)

        # Decode cursor - handle both indexer search_after and legacy scanned formats
        search_after: Optional[list] = None
        if cursor:
            decoded = _decode_cursor(cursor)
            if decoded:
                search_after = decoded.get("search_after") or decoded.get("scanned")
                # "scanned" is a legacy integer — discard it; search_after needs an array
                if isinstance(search_after, int):
                    search_after = None

        data = await _wazuh_indexer_search(
            index_pattern="wazuh-alerts-*",
            agent_name=agent_name,
            size=limit,
            search_after=search_after,
            srcip=srcip,
            since=since,
            until=until,
        )
        if isinstance(data.get("error"), str):
            return json.dumps(data, indent=2)

        hits = data.get("hits", {})
        total = hits.get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else total
        total_relation = total.get("relation", "eq") if isinstance(total, dict) else "eq"
        docs = [h.get("_source", h) for h in hits.get("hits", [])]

        # Build next_cursor from last document's sort values
        next_cursor = None
        hit_list = hits.get("hits", [])
        if hit_list and len(docs) >= limit:
            last_sort = hit_list[-1].get("sort")
            if last_sort:
                next_cursor = _encode_cursor({"search_after": last_sort})

        return _truncate_if_needed(json.dumps({
            "source": "wazuh-indexer",  # signals auto-fallback to the LLM
            "total": {"value": total_val, "relation": total_relation},
            "count": len(docs),
            "limit": limit,
            "next_cursor": next_cursor,
            "alerts": _redact_alert_data(docs, bypass=bypass_redaction),
        }, indent=2))

    # Decode cursor to find how many lines were already scanned
    skip_lines = 0
    if cursor:
        decoded = _decode_cursor(cursor)
        if decoded:
            skip_lines = decoded.get("scanned", 0)

    # Read from tail — fetch enough lines to cover skip + limit with filtering overhead
    page_size = min((skip_lines + limit) * 3, _WAZUH_ALERTS_MAX_LINES)
    r = await _run_async(["tail", "-n", str(page_size), _WAZUH_ALERTS_PATH])
    if r.get("returncode", 0) != 0:
        return json.dumps({"error": "Failed to read alerts", "stderr": r.get("stderr", "")})

    alerts = []
    agent_filter = (agent_name or "").strip()
    ip_filter = (srcip or "").strip()
    scanned = 0
    for line in (r.get("stdout") or "").strip().splitlines():
        scanned += 1
        # Skip already-returned lines
        if scanned <= skip_lines:
            continue
        if len(alerts) >= limit:
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
            # Filter by source IP — checks data.srcip, data.srcip2, top-level
            # srcip (active-response), and full_log for the IP string
            if ip_filter:
                data_srcip = str(a.get("data", {}).get("srcip", ""))
                data_srcip2 = str(a.get("data", {}).get("srcip2", ""))
                top_srcip = str(a.get("srcip", ""))
                full_log = str(a.get("full_log", ""))
                if (ip_filter not in (data_srcip, data_srcip2, top_srcip)
                        and ip_filter not in full_log):
                    continue
            alerts.append(a)
        except json.JSONDecodeError:
            continue

    next_cursor = _encode_cursor({"scanned": scanned}) if len(alerts) >= limit else None

    return _truncate_if_needed(json.dumps({
        "source": "local",
        "alerts": alerts,
        "count": len(alerts),
        "next_cursor": next_cursor,
    }, indent=2))


# Sprint 2: Alert Enrichment Pipeline (F-1, F-2, F-3)
# Known attack chains for F-3 (rule.id regex -> phase label transition patterns)
_KNOWN_ATTACK_CHAINS: list[dict[str, Any]] = [
    {
        "id": "recon_to_bruteforce",
        "phases": ["recon", "bruteforce"],
        "pattern": [re.compile(r"^(600029|5710|5760|60100|33100)$"),
                     re.compile(r"^(5710|5712|5716|5760|6020|5551)$")],
        "description": "Reconnaissance → Brute-force / credential attack",
        "confidence": 0.75,
    },
    {
        "id": "recon_to_exploit",
        "phases": ["recon", "exploit"],
        "pattern": [re.compile(r"^(600029|5710|5760|60100|33100)$"),
                     re.compile(r"^(31100|31300|31500|31700|33300|33800)$")],
        "description": "Reconnaissance → Exploitation / payload delivery",
        "confidence": 0.80,
    },
    {
        "id": "bruteforce_to_access",
        "phases": ["bruteforce", "access"],
        "pattern": [re.compile(r"^(5710|5712|5716|5760|6020|5551)$"),
                     re.compile(r"^(5500|5501|5502|5503|60106|60122)$")],
        "description": "Brute-force → Successful authentication",
        "confidence": 0.90,
    },
    {
        "id": "recon_to_c2",
        "phases": ["recon", "c2_response"],
        "pattern": [re.compile(r"^(600029|5710|5760|60100|33100)$"),
                     re.compile(r"^(606029|510|520|530|540|550|560)$")],
        "description": "Reconnaissance → Active Response / C2 trigger",
        "confidence": 0.60,
    },
    {
        "id": "full_kill_chain",
        "phases": ["recon", "bruteforce", "access", "c2_response"],
        "pattern": [
            re.compile(r"^(600029|5710|5760|60100|33100)$"),
            re.compile(r"^(5710|5712|5716|5760|6020|5551)$"),
            re.compile(r"^(5500|5501|5502|5503|60106|60122)$"),
            re.compile(r"^(606029|510|520|530|540|550|560)$"),
        ],
        "description": "Full kill-chain: Recon → Brute-force → Access → C2/Response",
        "confidence": 0.95,
    },
]


# F-1: Alert Summarization
class AlertSummarizeInput(BaseModel):
    """Input model for blueteam_wazuh_alert_summarize."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="Source IP to summarize alerts for (e.g. '103.107.116.202').",
    )
    agent_name: ValidAgentName = Field(
        default=None,
        max_length=64,
        description="Optional Wazuh agent name filter.",
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window. ISO 8601 or relative ('5m','1h','24h','7d','30d').",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window. Defaults to now.",
    )
    limit: int = Field(
        default=200,
        ge=10,
        le=2000,
        description="Max alerts to fetch for summarization (default 200).",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="Output format: 'markdown' (human-readable digest) or 'json'.",
    )
    bypass_redaction: bool = Field(
        default=False,
        description=_BYPASS_REDACTION_DESC,
    )


@mcp.tool(
    name="blueteam_wazuh_alert_summarize",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def blueteam_wazuh_alert_summarize(params: AlertSummarizeInput) -> str:
    """Summarize Wazuh alerts for a source IP into a compact threat digest.

    Extracts IoCs (domains, URLs, user-agents), groups alerts by rule.id
    with counts, computes first_seen / last_seen per rule, and flags
    unusual user-agent strings (old browsers, scripted clients).

    Returns a markdown report or JSON with the structured digest — the LLM
    can reason about attack patterns from the summary without scanning
    raw alert documents.

    **Required Permissions**: Wazuh Indexer user with ``read`` access.

    **Worked Examples**

    1. *Basic IP summary*:
       ``blueteam_wazuh_alert_summarize(srcip="103.107.116.202")``

    2. *Focused time window*:
       ``blueteam_wazuh_alert_summarize(srcip="103.107.116.202", since="1h")``

    3. *Single agent only*:
       ``blueteam_wazuh_alert_summarize(srcip="103.107.116.202", agent_name="thezoo-prod")``
    """
    _audit_log("blueteam_wazuh_alert_summarize", {"srcip": params.srcip})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({
            "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set.",
        }, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)

    must_clauses: list[dict] = [
        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                     "format": "strict_date_optional_time"}}},
        {"bool": {
            "should": [
                {"match": {"data.srcip": params.srcip.strip()}},
                {"match_phrase": {"full_log": params.srcip.strip()}},
            ],
            "minimum_should_match": 1,
        }},
    ]
    if params.agent_name:
        must_clauses.append({"match": {"agent.name": params.agent_name.strip()}})

    body = {
        "size": min(params.limit, _WAZUH_INDEXER_MAX_SIZE),
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"bool": {"must": must_clauses}},
        "_source": [
            "@timestamp", "agent.name", "rule.id", "rule.level",
            "rule.description", "rule.groups", "rule.mitre.tactic",
            "data.srcip", "data.domain", "data.url", "data.user_agent",
        ],
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)

    hits = raw.get("hits", {}).get("hits", [])
    docs = [_redact_alert_data(h.get("_source", h), bypass=params.bypass_redaction)
            for h in hits]

    if not docs:
        result = {"srcip": params.srcip, "total_alerts": 0,
                  "summary": "No alerts found for this IP in the time window."}
        return json.dumps(result, indent=2) if params.response_format == "json" else (
            f"# Alert Digest - {params.srcip}\n\n**No alerts found** in window "
            f"`{since_iso}` -> `{until_iso}`.")

    # IoC extraction
    rule_counts: Counter[str] = Counter()
    rule_descriptions: dict[str, str] = {}
    rule_timestamps: dict[str, list[str]] = {}
    domains: set[str] = set()
    urls: list[dict[str, str]] = []
    uas: Counter[str] = Counter()
    unusual_uas: list[str] = []
    mitre_tactics: set[str] = set()
    first_ts = docs[0].get("@timestamp", "")
    last_ts = docs[-1].get("@timestamp", "")

    for d in docs:
        rid = str(d.get("rule", {}).get("id", "unknown"))
        rule_counts[rid] = rule_counts.get(rid, 0) + 1
        if rid not in rule_descriptions:
            rule_descriptions[rid] = str(d.get("rule", {}).get("description", rid))
        rule_timestamps.setdefault(rid, []).append(str(d.get("@timestamp", "")))

        data = d.get("data", {})
        if isinstance(data, dict):
            dom = str(data.get("domain", "")).strip()
            if dom and dom != "-":
                domains.add(dom)
            url = str(data.get("url", "")).strip()
            if url and url != "-":
                urls.append({"url": url, "ts": str(d.get("@timestamp", ""))})
            ua = str(data.get("user_agent", "")).strip()
            if ua and ua != "-":
                uas[ua] += 1

        mitre = d.get("rule", {}).get("mitre", {})
        if isinstance(mitre, dict):
            tactics = mitre.get("tactic", [])
            if isinstance(tactics, list):
                mitre_tactics.update(tactics)

    # Flag unusual UA
    _UA_SIGNALS = [
        (re.compile(r"Firefox/(?:[1-6]\d|7[0-7])\."), "Old Firefox (pre-78)"),
        (re.compile(r"Chrome/(?:[1-5]\d|6[0-9])\."), "Old Chrome (pre-70)"),
        (re.compile(r"curl|wget|python|go-http|libwww|Java/"), "Scripted/automated client"),
        (re.compile(r"zgrab|masscan|nmap|nikto|sqlmap|ffuf|burp"), "Scanner/exploitation tool"),
    ]
    for ua, _ in uas.most_common(20):
        for pat, label in _UA_SIGNALS:
            if pat.search(ua):
                unusual_uas.append(f"{label}: `{ua[:120]}`")
                break

    # Build response
    if params.response_format == "json":
        result = {
            "srcip": params.srcip,
            "window": {"since": since_iso, "until": until_iso},
            "total_alerts": len(docs),
            "first_seen": first_ts,
            "last_seen": last_ts,
            "rules": [
                {
                    "id": rid,
                    "count": cnt,
                    "description": rule_descriptions.get(rid, ""),
                    "first_seen": rule_timestamps[rid][0],
                    "last_seen": rule_timestamps[rid][-1],
                }
                for rid, cnt in rule_counts.most_common()
            ],
            "iocs": {
                "domains": sorted(domains),
                "urls": urls[:50],
                "top_user_agents": [{"ua": ua, "count": n}
                                    for ua, n in uas.most_common(5)],
            },
            "mitre_tactics": sorted(mitre_tactics),
            "unusual_user_agents": unusual_uas,
        }
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    # Markdown digest
    lines = [
        f"# Alert Digest - `{params.srcip}`",
        "",
        f"- **Window**: `{since_iso}` -> `{until_iso}`",
        f"- **Total alerts**: {len(docs)} | **First seen**: `{first_ts}` | **Last seen**: `{last_ts}`",
        "",
        "## Rules Triggered",
        "",
        "| Rule ID | Count | Description | First → Last |",
        "|---------|-------|-------------|--------------|",
    ]
    for rid, cnt in rule_counts.most_common():
        desc = _escape_md_table(rule_descriptions.get(rid, ""))[:80]
        fst = rule_timestamps[rid][0][:19] if rule_timestamps[rid] else "-"
        lst = rule_timestamps[rid][-1][:19] if rule_timestamps[rid] else "-"
        lines.append(f"| {rid} | {cnt} | {desc} | {fst} → {lst} |")

    if domains:
        lines.append("")
        lines.append("## Target Domains")
        for d in sorted(domains):
            lines.append(f"- `{d}`")

    if urls:
        lines.append("")
        lines.append(f"## URLs Accessed ({len(urls)} total, showing first 15)")
        for u in urls[:15]:
            ts_short = u["ts"][:19] if len(u["ts"]) > 19 else u["ts"]
            lines.append(f"- `[{ts_short}]` `{u['url'][:100]}`")
        if len(urls) > 15:
            lines.append(f"- ... and {len(urls) - 15} more")

    if mitre_tactics:
        lines.append("")
        lines.append("## MITRE ATT&CK Tactics")
        for t in sorted(mitre_tactics):
            cat = MITRE_TACTIC_TO_CATEGORY.get(t, "?")
            lines.append(f"- {t} (3-Sum Cat: `{cat}`)")

    if unusual_uas:
        lines.append("")
        lines.append("## ⚠️ Unusual User-Agents Flagged")
        for ua_flag in unusual_uas:
            lines.append(f"- {ua_flag}")

    if uas:
        lines.append("")
        lines.append("## Top User-Agents")
        for ua, n in uas.most_common(3):
            lines.append(f"- ({n}×) `{ua[:100]}`")

    return _truncate_if_needed("\n".join(lines))


# F-2: Beacon Detection
class BeaconDetectInput(BaseModel):
    """Input model for blueteam_beacon_detect."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="Source IP to analyze for C2 beaconing patterns.",
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window. ISO 8601 or relative.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window. Defaults to now.",
    )
    cv_threshold: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
        description="Coefficient of variation threshold. CV < threshold → regular beaconing. "
                    "Lower = stricter (0.15 for tight beacons, 0.35 for relaxed).",
    )
    min_events: int = Field(
        default=5,
        ge=3,
        le=1000,
        description="Minimum events required to compute beacon score.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="Output format: 'markdown' or 'json'.",
    )


@mcp.tool(
    name="blueteam_beacon_detect",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def blueteam_beacon_detect(params: BeaconDetectInput) -> str:
    """Detect C2 beaconing patterns via inter-arrival time analysis.
    Fetches ``@timestamp`` for all alerts from a given source IP, computes
    inter-arrival gaps, and calculates the coefficient of variation (CV =
    σ/μ). A low CV with consistent intervals is the statistical signature
    of periodic beaconing — a hallmark of C2 callbacks.

    Returns beacon score (0.0–1.0), estimated period, gap statistics,
    and a timeline summary.

    **Required Permissions**: Wazuh Indexer user with ``read`` access.

    **Worked Examples**

    1. *Default 24h scan*:
       ``blueteam_beacon_detect(srcip="103.107.116.202")``

    2. *7-day window, stricter threshold*:
       ``blueteam_beacon_detect(srcip="103.107.116.202", since="7d", cv_threshold=0.15)``

    3. *Short window for rapid beaconing*:
       ``blueteam_beacon_detect(srcip="103.107.116.202", since="1h", min_events=10)``
    """
    _audit_log("blueteam_beacon_detect", {"srcip": params.srcip})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({
            "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set.",
        }, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)

    body = {
        "size": 2000,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                             "format": "strict_date_optional_time"}}},
                    {"bool": {
                        "should": [
                            {"match": {"data.srcip": params.srcip.strip()}},
                            {"match_phrase": {"full_log": params.srcip.strip()}},
                        ],
                        "minimum_should_match": 1,
                    }},
                ]
            }
        },
        "_source": ["@timestamp"],
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)

    hits = raw.get("hits", {}).get("hits", [])
    if len(hits) < params.min_events:
        result = {
            "srcip": params.srcip,
            "beacon_score": 0.0,
            "verdict": "insufficient_data",
            "detail": f"Only {len(hits)} events — need at least {params.min_events}.",
        }
        return json.dumps(result, indent=2) if params.response_format == "json" else (
            f"# Beacon Detection — `{params.srcip}`\n\n"
            f"**Insufficient data**: {len(hits)} events (need ≥{params.min_events}). "
            f"Expand the time window and retry.")

    # Parse timestamps into epoch seconds
    timestamps: list[float] = []
    for h in hits:
        ts = h.get("_source", {}).get("@timestamp", "")
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            timestamps.append(dt.timestamp())
        except (ValueError, TypeError):
            continue

    if len(timestamps) < params.min_events:
        result = {
            "srcip": params.srcip,
            "beacon_score": 0.0,
            "verdict": "unparseable_timestamps",
            "detail": f"Only {len(timestamps)} parseable timestamps from {len(hits)} hits.",
        }
        return json.dumps(result, indent=2) if params.response_format == "json" else (
            f"# Beacon Detection - `{params.srcip}`\n\n"
            f"**Could not parse enough timestamps**: {len(timestamps)} valid from {len(hits)} total.")

    # Inter-arrival analysis
    gaps = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
    n = len(gaps)
    mean_gap = sum(gaps) / n
    variance = sum((g - mean_gap) ** 2 for g in gaps) / n
    stddev = math.sqrt(variance)
    cv = stddev / mean_gap if mean_gap > 0 else float("inf")

    # Beacon score: 1.0 = perfect periodicity, 0.0 = random
    # clamp CV to [0, 1] range via sigmoid-like decay
    beacon_score = max(0.0, min(1.0, 1.0 - (cv / 0.5)))

    # Estimate period - use median for robustness against outliers
    sorted_gaps = sorted(gaps)
    median_gap = sorted_gaps[n // 2] if n > 0 else 0.0
    period_secs = round(median_gap)

    # Detect multiple period candidates (e.g. 60s + 300s harmonics)
    gap_counter: Counter[int] = Counter()
    for g in gaps:
        gap_counter[int(round(g))] += 1
    top_periods = gap_counter.most_common(3)

    verdict = (
        "strong_beacon" if beacon_score >= 0.8 else
        "likely_beacon" if beacon_score >= 0.5 else
        "possible_beacon" if beacon_score >= 0.25 else
        "no_beacon"
    )

    if params.response_format == "json":
        result = {
            "srcip": params.srcip,
            "window": {"since": since_iso, "until": until_iso},
            "total_events": len(timestamps),
            "gaps": {
                "count": n,
                "mean_seconds": round(mean_gap, 1),
                "median_seconds": round(median_gap, 1),
                "stddev_seconds": round(stddev, 1),
                "cv": round(cv, 3),
            },
            "beacon_score": round(beacon_score, 3),
            "verdict": verdict,
            "estimated_period_seconds": period_secs,
            "top_periods": [{"seconds": p, "count": c} for p, c in top_periods],
            "timeline_preview": [
                {"ts": datetime.utcfromtimestamp(t).isoformat() + "Z",
                 "gap_from_prev_s": round(gaps[i - 1], 1) if i > 0 else None}
                for i, t in enumerate(timestamps[:20])
            ],
        }
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    # Markdown report Format
    verdict_icon = {"strong_beacon": "🔴", "likely_beacon": "🟠",
                     "possible_beacon": "🟡", "no_beacon": "🟢"}
    lines = [
        f"# Beacon Detection — `{params.srcip}`",
        "",
        f"- **Verdict**: {verdict_icon.get(verdict, '')} **{verdict.replace('_', ' ').title()}**",
        f"- **Beacon Score**: `{beacon_score:.3f}` (0.0 = random, 1.0 = perfect periodicity)",
        f"- **Events**: {len(timestamps)} over {since_iso} → {until_iso}",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Mean gap | {mean_gap:.1f}s |",
        f"| Median gap | {median_gap:.1f}s |",
        f"| StdDev | {stddev:.1f}s |",
        f"| CV (σ/μ) | {cv:.3f} |",
        "",
    ]
    if period_secs > 0:
        period_display = (
            f"{period_secs}s" if period_secs < 120 else
            f"{period_secs / 60:.1f}m" if period_secs < 3600 else
            f"{period_secs / 3600:.1f}h"
        )
        lines.append(f"**Estimated period**: ~{period_display}")

    if top_periods:
        lines.append("")
        lines.append("## Top Period Candidates")
        for secs, cnt in top_periods:
            d = f"{secs}s" if secs < 120 else f"{secs / 60:.1f}m"
            lines.append(f"- {d} — {cnt} occurrences")

    lines.append("")
    lines.append("## Gap Distribution (first 20 events)")
    lines.append("```")
    for i, t in enumerate(timestamps[:20]):
        ts_str = datetime.utcfromtimestamp(t).isoformat()[:19] + "Z"
        gap_str = f"+{gaps[i - 1]:.0f}s" if i > 0 else "start"
        bar = "█" * min(40, int(gaps[i - 1] / max(1, mean_gap) * 10)) if i > 0 else ""
        lines.append(f"  {ts_str}  {gap_str:>8s}  {bar}")
    if len(timestamps) > 20:
        lines.append(f"  ... and {len(timestamps) - 20} more events")
    lines.append("```")

    return _truncate_if_needed("\n".join(lines))


# F-3: Attack Chain Analysis
class AttackChainInput(BaseModel):
    """Input model for blueteam_attack_chain."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="Source IP to analyze for attack progression chains.",
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window.",
    )
    min_transitions: int = Field(
        default=2,
        ge=2,
        le=100,
        description="Minimum rule transitions to consider a chain.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="Output format: 'markdown' or 'json'.",
    )


@mcp.tool(
    name="blueteam_attack_chain",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def blueteam_attack_chain(params: AttackChainInput) -> str:
    """Analyze rule-to-rule transitions to reconstruct attack kill-chain progression.

    Fetches all alerts for a source IP ordered by timestamp, builds a
    Markov transition graph of ``rule.id`` sequences, and matches observed
    transitions against known attack chains (recon -> bruteforce -> access -> C2/response).

    Returns matched chains with confidence scores, the full transition
    matrix, and a timeline of key transitions.

    **Required Permissions**: Wazuh Indexer user with ``read`` access.

    **Worked Examples**

    1. *Default 24h*:
       ``blueteam_attack_chain(srcip="103.107.116.202")``

    2. *7-day forensic window*:
       ``blueteam_attack_chain(srcip="103.107.116.202", since="7d")``

    3. *Require 3+ transitions*:
       ``blueteam_attack_chain(srcip="103.107.116.202", min_transitions=3)``
    """
    _audit_log("blueteam_attack_chain", {"srcip": params.srcip})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({
            "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set.",
        }, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)

    body = {
        "size": 2000,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                             "format": "strict_date_optional_time"}}},
                    {"bool": {
                        "should": [
                            {"match": {"data.srcip": params.srcip.strip()}},
                            {"match_phrase": {"full_log": params.srcip.strip()}},
                        ],
                        "minimum_should_match": 1,
                    }},
                ]
            }
        },
        "_source": ["@timestamp", "rule.id", "rule.description", "rule.level", "rule.mitre.tactic"],
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)

    hits = raw.get("hits", {}).get("hits", [])
    docs = [h.get("_source", h) for h in hits]

    if len(docs) < params.min_transitions:
        result = {
            "srcip": params.srcip,
            "total_events": len(docs),
            "verdict": "insufficient_data",
            "detail": f"Need at least {params.min_transitions} rule transitions.",
        }
        return json.dumps(result, indent=2) if params.response_format == "json" else (
            f"# Attack Chain — `{params.srcip}`\n\n"
            f"**Insufficient data**: {len(docs)} events (need ≥{params.min_transitions} transitions).")

    # Build rule sequence and transition matrix
    rule_seq: list[str] = []
    rule_info: dict[str, dict[str, str]] = {}
    for d in docs:
        rid = str(d.get("rule", {}).get("id", "unknown"))
        rule_seq.append(rid)
        if rid not in rule_info:
            rule_info[rid] = {
                "description": str(d.get("rule", {}).get("description", rid)),
                "level": str(d.get("rule", {}).get("level", "?")),
            }

    # Compress consecutive duplicates (Aul Adjusted : same rule firing repeatedly = persistence, not a transition)
    compressed: list[str] = [rule_seq[0]]
    for rid in rule_seq[1:]:
        if rid != compressed[-1]:
            compressed.append(rid)

    transitions: list[tuple[str, str]] = []
    for i in range(len(compressed) - 1):
        transitions.append((compressed[i], compressed[i + 1]))

    # Count transitions
    trans_counter: Counter[tuple[str, str]] = Counter(transitions)

    # Match against known attack chains
    chain_matches: list[dict[str, Any]] = []
    for chain in _KNOWN_ATTACK_CHAINS:
        chain_ids = [rid for rid, _ in transitions]
        # Check if the compressed sequence contains the ordered pattern
        # Use a subsequence match: each phase must appear in order, not necessarily consecutive
        pattern = chain["pattern"]
        seq_idx = 0
        matched_ids: list[str] = []
        for rid in compressed:
            if seq_idx < len(pattern) and pattern[seq_idx].search(rid):
                matched_ids.append(rid)
                seq_idx += 1
        if seq_idx >= 2:  # at least 2 phases matched
            # Compute observed phase-by-phase transition details
            phase_detail: list[dict[str, Any]] = []
            for j in range(len(matched_ids) - 1):
                phase_detail.append({
                    "from_phase": chain["phases"][j],
                    "to_phase": chain["phases"][j + 1],
                    "from_rule": matched_ids[j],
                    "to_rule": matched_ids[j + 1],
                })
            adjusted_conf = chain["confidence"] * min(1.0, seq_idx / len(pattern))
            chain_matches.append({
                "chain_id": chain["id"],
                "description": chain["description"],
                "confidence": round(adjusted_conf, 2),
                "phases_matched": seq_idx,
                "phases_total": len(pattern),
                "matched_rules": matched_ids[:8],
                "phase_transitions": phase_detail,
            })
    chain_matches.sort(key=lambda c: c["confidence"], reverse=True)

    if params.response_format == "json":
        result = {
            "srcip": params.srcip,
            "window": {"since": since_iso, "until": until_iso},
            "total_events": len(docs),
            "unique_rules": len(rule_info),
            "transitions_observed": len(transitions),
            "compressed_sequence": compressed[:50],
            "rule_info": rule_info,
            "top_transitions": [
                {"from": f, "to": t, "count": c}
                for (f, t), c in trans_counter.most_common(15)
            ],
            "chain_matches": chain_matches,
        }
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    # Markdown report
    lines = [
        f"# Attack Chain — `{params.srcip}`",
        "",
        f"- **Window**: `{since_iso}` → `{until_iso}`",
        f"- **Events**: {len(docs)} → {len(compressed)} distinct rule transitions",
        f"- **Unique rules triggered**: {len(rule_info)}",
        "",
    ]

    if chain_matches:
        lines.append("## 🎯 Matched Kill-Chain Patterns")
        lines.append("")
        for cm in chain_matches[:5]:
            conf_bar = "█" * int(cm["confidence"] * 10) + "░" * (10 - int(cm["confidence"] * 10))
            lines.append(f"### {cm['chain_id']} (confidence: {cm['confidence']:.2f})")
            lines.append(f"`[{conf_bar}]`")
            lines.append(f"{cm['description']}")
            lines.append(f"- **Phases matched**: {cm['phases_matched']}/{cm['phases_total']}")
            # Draw ASCII chain
            arrow_parts: list[str] = []
            for pt in cm.get("phase_transitions", []):
                arrow_parts.append(
                    f"`{pt['from_phase']}`[{pt['from_rule']}] → "
                    f"`{pt['to_phase']}`[{pt['to_rule']}]"
                )
            lines.append(f"- **Path**: {' → '.join(arrow_parts) if arrow_parts else '(see matched_rules)'}")
            lines.append("")
    else:
        lines.append("## No known attack chain matched")
        lines.append("")

    # Compressed sequence visualization
    lines.append("## Rule Transition Sequence")
    lines.append("")
    lines.append("```")
    for i, rid in enumerate(compressed[:30]):
        info = rule_info.get(rid, {})
        desc = info.get("description", "?")[:70]
        lvl = info.get("level", "?")
        arrow = " → " if i < len(compressed[:30]) - 1 else ""
        lines.append(f"  [{lvl}] {rid} ({desc}){arrow}")
    if len(compressed) > 30:
        lines.append(f"  ... and {len(compressed) - 30} more transitions")
    lines.append("```")

    # Top transitions table
    if trans_counter:
        lines.append("")
        lines.append("## Top Rule Transitions")
        lines.append("")
        lines.append("| From | To | Count |")
        lines.append("|------|----|-------|")
        for (f, t), c in trans_counter.most_common(10):
            lines.append(f"| `{f}` | `{t}` | {c} |")

    return _truncate_if_needed("\n".join(lines))


# F-5: Threat Card Generation (AUL Adjusted)
class ThreatCardInput(BaseModel):
    """Input model for blueteam_threat_card."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="Source IP to generate a comprehensive threat card for.",
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window. Defaults to now.",
    )
    include_threat_intel: bool = Field(
        default=True,
        description="Include CrowdSec and GreyNoise reputation lookups (may add ~2s latency).",
    )
    bypass_redaction: bool = Field(
        default=False,
        description=_BYPASS_REDACTION_DESC,
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="'markdown' (default, human-readable) or 'json'.",
    )


@mcp.tool(
    name="blueteam_threat_card",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def blueteam_threat_card(params: ThreatCardInput) -> str:
    """Generate a comprehensive threat card for a source IP.
    Collapses alert summarization, attack chain analysis, MITRE ATT&CK
    mapping, and threat intelligence (CrowdSec + GreyNoise) into a single
    structured report. Designed as the one-stop triage tool — the LLM can
    understand the full threat context in one call.

    **Required Permissions**: Wazuh Indexer ``read`` access.
    CrowdSec/GreyNoise lookups are best-effort (fail gracefully if keys
    are not configured).

    **Worked Examples**

    1. *Default 24h card*:
       ``blueteam_threat_card(srcip="103.107.116.202")``

    2. *7-day forensic card*:
       ``blueteam_threat_card(srcip="103.107.116.202", since="7d")``

    3. *Skip threat intel for speed*:
       ``blueteam_threat_card(srcip="103.107.116.202", include_threat_intel=false)``
    """
    _audit_log("blueteam_threat_card", {"srcip": params.srcip})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({
            "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set.",
        }, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)

    # Fetch alerts for this IP
    body = {
        "size": 500,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                             "format": "strict_date_optional_time"}}},
                    {"bool": {
                        "should": [
                            {"match": {"data.srcip": params.srcip.strip()}},
                            {"match_phrase": {"full_log": params.srcip.strip()}},
                        ],
                        "minimum_should_match": 1,
                    }},
                ]
            }
        },
        "_source": [
            "@timestamp", "agent.name", "rule.id", "rule.level",
            "rule.description", "rule.groups", "rule.mitre.tactic",
            "data.srcip", "data.domain", "data.url", "data.user_agent",
        ],
    }

    # Fetch alerts + threat intel concurrently
    async def _fetch_alerts():
        raw = await _wazuh_indexer_post(body)
        if "error" in raw:
            return raw
        return [h.get("_source", h) for h in raw.get("hits", {}).get("hits", [])]

    async def _fetch_crowdsec():
        if not params.include_threat_intel or not os.environ.get(CROWDSEC_API_KEY_ENV):
            return None
        try:
            return await _crowdsec_request(f"/v2/smoke/{params.srcip}")
        except Exception:
            return None

    async def _fetch_greynoise():
        if not params.include_threat_intel:
            return None
        try:
            return await _greynoise_community_request(params.srcip)
        except Exception:
            return None

    docs, crowdsec_data, greynoise_data = await asyncio.gather(
        _fetch_alerts(), _fetch_crowdsec(), _fetch_greynoise(),
    )

    if isinstance(docs, dict) and "error" in docs:
        return json.dumps(docs, indent=2)

    docs = _redact_alert_data(docs, bypass=params.bypass_redaction)

    # Extract common data
    rule_counts: Counter[str] = Counter()
    rule_descs: dict[str, str] = {}
    mitre_tactics: set[str] = set()
    domains: set[str] = set()
    urls: list[str] = []
    levels: list[int] = []
    agents: set[str] = set()
    first_ts = str(docs[0].get("@timestamp", ""))[:19]
    last_ts = str(docs[-1].get("@timestamp", ""))[:19]

    for d in docs:
        r = d.get("rule", {})
        rid = str(r.get("id", "unknown"))
        rule_counts[rid] += 1
        if rid not in rule_descs:
            rule_descs[rid] = str(r.get("description", rid))
        lvl = r.get("level")
        if isinstance(lvl, (int, str)):
            try: levels.append(int(lvl))
            except (ValueError, TypeError): pass
        mitre = r.get("mitre", {})
        if isinstance(mitre, dict):
            tactics = mitre.get("tactic", [])
            if isinstance(tactics, list): mitre_tactics.update(tactics)
        data = d.get("data", {})
        if isinstance(data, dict):
            dom = str(data.get("domain", "")).strip()
            if dom and dom != "-": domains.add(dom)
            url = str(data.get("url", "")).strip()
            if url and url != "-": urls.append(url)
        ag = d.get("agent", {})
        if isinstance(ag, dict) and ag.get("name"): agents.add(str(ag["name"]))

    max_level = max(levels) if levels else 0
    avg_level = sum(levels) / len(levels) if levels else 0.0

    # Format output
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({
            "srcip": params.srcip,
            "window": {"since": since_iso, "until": until_iso},
            "total_events": len(docs),
            "first_seen": first_ts,
            "last_seen": last_ts,
            "max_level": max_level,
            "avg_level": round(avg_level, 1),
            "rules": [{"id": rid, "count": cnt, "description": rule_descs.get(rid, "")}
                      for rid, cnt in rule_counts.most_common(10)],
            "targeted_domains": sorted(domains),
            "urls_probed": list(set(urls))[:50],
            "mitre_tactics": sorted(mitre_tactics),
            "agents": sorted(agents),
            "threat_intel": {"crowdsec": crowdsec_data, "greynoise": greynoise_data},
        }, indent=2, ensure_ascii=False))

    # Markdown threat card
    lines = [
        f"# 🛡️ Threat Card — `{params.srcip}`",
        "",
        f"**Window**: `{since_iso}` → `{until_iso}` | **Total events**: {len(docs)}",
        "",
        "---",
        "",
    ]

    if not docs:
        lines.append("## No alerts found")
        lines.append(f"No Wazuh alerts for `{params.srcip}` in this time window.")
        return "\n".join(lines)

    # Section 1: Executive Summary
    lines.append("## 📊 Executive Summary")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| Total alerts | {len(docs)} |")
    lines.append(f"| Unique rules | {len(rule_counts)} |")
    lines.append(f"| Max rule level | {max_level} |")
    lines.append(f"| Avg rule level | {avg_level:.1f} |")
    lines.append(f"| Agents targeted | {len(agents)} ({', '.join(sorted(agents)[:3])}{"..." if len(agents) > 3 else ""}) |")
    lines.append(f"| First seen | `{first_ts}` |")
    lines.append(f"| Last seen | `{last_ts}` |")
    lines.append("")

    # Section 2: MITRE ATT&CK
    if mitre_tactics:
        lines.append("## 🎯 MITRE ATT&CK Tactics")
        lines.append("")
        lines.append("| Tactic | 3-Sum Category |")
        lines.append("|--------|---------------|")
        for t in sorted(mitre_tactics):
            cat = MITRE_TACTIC_TO_CATEGORY.get(t, "?")
            lines.append(f"| {t} | `{cat}` |")
        lines.append("")

    # Section 3: Rules Fired
    lines.append("## 🔥 Rules Triggered")
    lines.append("")
    lines.append("| Rule ID | Count | Description |")
    lines.append("|---------|-------|-------------|")
    for rid, cnt in rule_counts.most_common(10):
        desc = _escape_md_table(rule_descs.get(rid, ""))[:80]
        lines.append(f"| {rid} | {cnt} | {desc} |")
    lines.append("")

    # Section 4: Targeted Resources
    if domains:
        lines.append("## 🌐 Targeted Domains")
        for d in sorted(domains):
            lines.append(f"- `{d}`")
        lines.append("")
    if urls:
        lines.append(f"## 🔗 URLs Probed ({len(urls)} unique)")
        for u in sorted(set(urls))[:10]:
            lines.append(f"- `{u[:120]}`")
        if len(set(urls)) > 10:
            lines.append(f"- ... and {len(set(urls)) - 10} more")
        lines.append("")

    # Section 5: Threat Intelligence
    if crowdsec_data or greynoise_data:
        lines.append("## 🌍 External Threat Intelligence")
        lines.append("")
    if crowdsec_data:
        rep = crowdsec_data.get("reputation", "unknown")
        behaviors = [b.get("name", "") for b in crowdsec_data.get("behaviors", [])]
        lines.append(f"- **CrowdSec**: reputation `{rep}`")
        if behaviors:
            lines.append(f"  - Behaviors: {', '.join(behaviors[:5])}")
        cves = crowdsec_data.get("cves", [])
        if cves:
            lines.append(f"  - Related CVEs: {', '.join(cves[:5])}")
    if greynoise_data:
        noise = greynoise_data.get("noise")
        riot = greynoise_data.get("riot")
        classification = greynoise_data.get("classification", "unknown")
        lines.append(f"- **GreyNoise**: classification `{classification}`")
        if noise:
            lines.append(f"  - Internet scanner: ✅ (background noise)")
        if riot:
            lines.append(f"  - Known business service: ✅ (likely benign)")
    if crowdsec_data or greynoise_data:
        lines.append("")

    # Section 6: Recommended Actions
    lines.append("## 🛠️ Recommended Actions")
    lines.append("")

    # Heuristic recommendations based on alert patterns
    if max_level >= 12:
        lines.append("1. **🚨 IMMEDIATE**: Critical-severity alerts detected — initiate incident response")
        lines.append(f"2. Block `{params.srcip}` at perimeter firewall immediately")
    elif max_level >= 10:
        lines.append(f"1. **⚠️ HIGH**: Block `{params.srcip}` at perimeter firewall")
        lines.append("2. Review affected agent logs for signs of compromise")
    elif max_level >= 6:
        lines.append(f"1. **📋 MEDIUM**: Monitor `{params.srcip}` and add to watchlist")
        lines.append("2. Review web/app logs for suspicious request patterns")
    else:
        lines.append(f"1. **ℹ️ LOW**: `{params.srcip}` shows low-severity activity")
        lines.append("2. No immediate action required — continue monitoring")

    if crowdsec_data and crowdsec_data.get("reputation") == "malicious":
        lines.append("3. CrowdSec confirms malicious — escalate block priority")
    if len(agents) > 1:
        lines.append(f"4. IP targeted {len(agents)} agents — check for lateral movement")
    if len(mitre_tactics) >= 3:
        lines.append("5. Multiple MITRE tactics observed — full compromise assessment recommended")

    lines.append("")
    lines.append("---")
    lines.append(f"*Card generated by blue_team_mcp at {datetime.utcnow().isoformat()[:19]}Z*")

    return _truncate_if_needed("\n".join(lines))


# F-6: Alert Comparison
class AlertCompareInput(BaseModel):
    """Input model for blueteam_wazuh_alert_compare."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip_a: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="First source IP to compare.",
    )
    srcip_b: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="Second source IP to compare.",
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window. Defaults to now.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="Output format: 'markdown' (side-by-side) or 'json'.",
    )


@mcp.tool(
    name="blueteam_wazuh_alert_compare",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def blueteam_wazuh_alert_compare(params: AlertCompareInput) -> str:
    """Compare alert profiles of two source IPs side-by-side.

    Fetches alert counts, top rules, max severity, MITRE tactics, and
    beacon scores for both IPs and returns a structured comparison with
    a verdict on which IP is more suspicious.

    Saves the LLM from orchestrating 4+ sequential calls to analyze two
    IPs independently.

    **Required Permissions**: Wazuh Indexer ``read`` access.

    **Worked Examples**

    1. *Compare two suspicious IPs*:
       ``blueteam_wazuh_alert_compare(srcip_a="103.107.116.202", srcip_b="185.220.101.1")``

    2. *7-day comparison*:
       ``blueteam_wazuh_alert_compare(srcip_a="10.0.0.5", srcip_b="10.0.0.99", since="7d")``
    """
    _audit_log("blueteam_wazuh_alert_compare",
               {"srcip_a": params.srcip_a, "srcip_b": params.srcip_b})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({
            "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set.",
        }, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)

    async def _profile_ip(ip: str) -> dict[str, Any]:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                                 "format": "strict_date_optional_time"}}},
                        {"bool": {
                            "should": [
                                {"match": {"data.srcip": ip.strip()}},
                                {"match_phrase": {"full_log": ip.strip()}},
                            ],
                            "minimum_should_match": 1,
                        }},
                    ]
                }
            },
            "aggs": {
                "top_rules": {"terms": {"field": "rule.id.keyword", "size": 5}},
                "by_level": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "low", "to": 5},
                            {"key": "medium", "from": 5, "to": 10},
                            {"key": "high", "from": 10},
                        ],
                    }
                },
                "top_agents": {"terms": {"field": "agent.name.keyword", "size": 5}},
            },
        }
        raw = await _wazuh_indexer_post(body)
        if "error" in raw:
            return {"srcip": ip, "error": raw["error"]}
        total = raw.get("hits", {}).get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else total
        aggs = raw.get("aggregations", {})
        return {
            "srcip": ip,
            "total_alerts": total_val,
            "top_rules": [
                {"id": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_rules", {}).get("buckets", [])
            ],
            "severity": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_level", {}).get("buckets", [])
            },
            "agents": [
                {"name": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_agents", {}).get("buckets", [])
            ],
        }

    profile_a, profile_b = await asyncio.gather(
        _profile_ip(params.srcip_a), _profile_ip(params.srcip_b),
    )

    if params.response_format == "json":
        result = {
            "window": {"since": since_iso, "until": until_iso},
            "ip_a": profile_a,
            "ip_b": profile_b,
        }
        # Determine which is more suspicious
        a_score = profile_a.get("total_alerts", 0)
        b_score = profile_b.get("total_alerts", 0)
        if a_score > b_score * 2:
            result["verdict"] = f"{params.srcip_a} is significantly more active"
        elif b_score > a_score * 2:
            result["verdict"] = f"{params.srcip_b} is significantly more active"
        else:
            result["verdict"] = "Both IPs show comparable activity levels"
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    # Markdown side-by-side
    a_total = profile_a.get("total_alerts", 0)
    b_total = profile_b.get("total_alerts", 0)
    a_rules = ", ".join(f"`{r['id']}`({r['count']})"
                         for r in profile_a.get("top_rules", [])[:3]) or "-"
    b_rules = ", ".join(f"`{r['id']}`({r['count']})"
                         for r in profile_b.get("top_rules", [])[:3]) or "-"
    a_sev = profile_a.get("severity", {})
    b_sev = profile_b.get("severity", {})
    a_high = a_sev.get("high", 0)
    b_high = b_sev.get("high", 0)
    a_agents = len(profile_a.get("agents", []))
    b_agents = len(profile_b.get("agents", []))

    # Verdict
    if a_total > b_total * 2 and a_high > b_high:
        verdict = f"🔴 **{params.srcip_a}** is significantly more threatening"
    elif b_total > a_total * 2 and b_high > a_high:
        verdict = f"🔴 **{params.srcip_b}** is significantly more threatening"
    elif a_total > b_total:
        verdict = f"🟡 **{params.srcip_a}** has more activity — investigate first"
    elif b_total > a_total:
        verdict = f"🟡 **{params.srcip_b}** has more activity — investigate first"
    else:
        verdict = "🟢 Both IPs show comparable activity"

    lines = [
        f"# Alert Comparison",
        "",
        f"**Window**: `{since_iso}` → `{until_iso}`",
        "",
        f"| Metric | `{params.srcip_a}` | `{params.srcip_b}` |",
        f"|--------|{'-' * (len(params.srcip_a) + 4)}|{'-' * (len(params.srcip_b) + 4)}|",
        f"| Total alerts | **{a_total}** | **{b_total}** |",
        f"| High severity (L10+) | {a_high} | {b_high} |",
        f"| Medium severity (L5-9) | {a_sev.get('medium', 0)} | {b_sev.get('medium', 0)} |",
        f"| Low severity (L1-4) | {a_sev.get('low', 0)} | {b_sev.get('low', 0)} |",
        f"| Agents targeted | {a_agents} | {b_agents} |",
        f"| Top rules | {a_rules} | {b_rules} |",
        "",
        f"### Verdict",
        f"{verdict}",
    ]

    return _truncate_if_needed("\n".join(lines))


# Sprint 6: Geo-Aware Curated Threat Intelligence Pipeline (AUL Adjust)
# Composable filter specification - any combination of dimensions can be AND'd.
# Cross-source deduplication patterns (parent-child alert relationships).
# Each entry: (child_rule_id_regex, parent_rule_field_path_in_nested_alert)
# When deduplicate=True, child alerts matching these patterns are subtracted
# from aggregate counts to prevent double-counting.
_DEDUP_PATTERNS: list[tuple[str, str]] = [
    ("606029", "data.parameters.alert.rule.id"),  # Active Response wraps its trigger
    ("651",   "data.parameters.alert.rule.id"),   # Ossec agent-spawned alerts
]

# Maps directly to OpenSearch bool.must/filter clauses inside _build_curated_query().
class CuratedReportFilters(BaseModel):
    """Filter specification for blueteam_curated_threat_report. Every field is
    optional — only specified filters are applied. All filters are AND'd together.
    """
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    # Geo dimension
    geo_country: Optional[str] = Field(
        default=None, max_length=60,
        description="Exact match on GeoLocation.country_name, e.g. 'Indonesia'.")
    geo_country_pattern: Optional[str] = Field(
        default=None, max_length=60,
        description="Wildcard match, e.g. 'Indo*'.")

    # Domain dimension
    domain: Optional[str] = Field(
        default=None, max_length=253,
        description="Exact match on data.domain, e.g. 'bangjaka.tangerangkota.go.id'.")
    domain_pattern: Optional[str] = Field(
        default=None, max_length=253,
        description="Wildcard on data.domain, e.g. '*.tangerangkota.go.id'.")
    domain_contains: Optional[str] = Field(
        default=None, max_length=253,
        description="Substring match on data.domain, e.g. 'tangerangkota'.")

    # Rule dimension
    rule_ids: Optional[list[str]] = Field(default=None, max_length=30,
        description="Specific rule IDs, e.g. ['600029','606029'].")
    rule_level_min: Optional[int] = Field(default=None, ge=1, le=16,
        description="Minimum rule.level (severity floor).")
    rule_level_max: Optional[int] = Field(default=None, ge=1, le=16,
        description="Maximum rule.level (severity ceiling).")
    rule_groups: Optional[list[str]] = Field(default=None,
        description="Wazuh rule.groups tokens, e.g. ['recon','firewall_drop'].")
    mitre_tactics: Optional[list[str]] = Field(default=None,
        description="MITRE ATT&CK tactics, e.g. ['Discovery','Collection'].")
    mitre_techniques: Optional[list[str]] = Field(default=None,
        description="MITRE technique IDs, e.g. ['T1083','T1552'].")

    # Agent dimension
    agent_name: Optional[str] = Field(default=None, max_length=64,
        description="Target agent name, e.g. 'thezoo-prod'.")
    agent_ip: Optional[str] = Field(default=None, max_length=45,
        description="Target agent internal IP, e.g. '172.16.10.135'.")
    agent_id: Optional[str] = Field(default=None, max_length=32,
        description="Target agent ID, e.g. '227'.")
    decoder: Optional[str] = Field(default=None, max_length=64,
        description="Decoder name, e.g. 'web-accesslog', 'ar_log_json', 'sysmon'.")

    # HTTP dimension
    url_pattern: Optional[str] = Field(default=None, max_length=1024,
        description="Wildcard on data.url, e.g. '/.vscode/*'.")
    response_codes: Optional[list[str]] = Field(default=None,
        description="HTTP response codes, e.g. ['403','404'].")
    http_methods: Optional[list[str]] = Field(default=None,
        description="HTTP methods, e.g. ['POST','PUT'].")
    user_agent_contains: Optional[str] = Field(default=None, max_length=512,
        description="Substring in data.user_agent, e.g. 'Firefox'.")
    referrer_pattern: Optional[str] = Field(default=None, max_length=1024,
        description="Wildcard on data.referrer, e.g. '*tangerangkota*'.")
    response_size_min: Optional[int] = Field(default=None, ge=0,
        description="Minimum data.response_size in bytes (exfil indicator).")
    response_size_max: Optional[int] = Field(default=None, ge=0,
        description="Maximum data.response_size in bytes.")

    # Rule description dimension
    rule_desc_contains: Optional[str] = Field(default=None, max_length=512,
        description="Substring in rule.description, e.g. 'sensitive files'.")
    rule_firedtimes_min: Optional[int] = Field(default=None, ge=1,
        description="Minimum rule.firedtimes (persistence signal — rule triggered at least N times).")
    log_source_pattern: Optional[str] = Field(default=None, max_length=512,
        description="Wildcard on location field, e.g. '/containers/*/logs/*' to filter by log source path.")

    # Geo bounding box
    geo_bbox: Optional[str] = Field(default=None, max_length=80,
        description="Geo bounding box: 'lat1,lon1,lat2,lon2' (bottom-left, top-right). "
                    "Filters GeoLocation.location within box, e.g. '-7.0,106.5,-5.5,107.0' "
                    "for Jabodetabek area. Only alerts with GeoIP data are matched.")

    # IP dimension
    srcips: Optional[list[str]] = Field(default=None, max_length=25,
        description="Specific IPs to INCLUDE (max 25).")
    exclude_srcips: Optional[list[str]] = Field(default=None, max_length=25,
        description="IPs to EXCLUDE, e.g. known scanners.")

    # Threat intel pre-filter
    min_crowdsec_reputation: Optional[str] = Field(default=None,
        description="Pre-filter: only IPs with this CrowdSec reputation "
                    "('malicious','suspicious','safe','unknown'). "
                    "Requires CROWDSEC_API_KEY and adds per-IP API calls.")


def _build_curated_query(
    since_iso: str, until_iso: str, f: CuratedReportFilters,
) -> list[dict]:
    """Translate CuratedReportFilters into OpenSearch bool.must clauses.

    Each non-None filter field becomes an AND clause. Returns a list of
    OpenSearch query/filter dicts ready for a bool.must array.
    """
    clauses: list[dict] = [
        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                   "format": "strict_date_optional_time"}}},
    ]
    # Geo
    if f.geo_country:
        clauses.append({"term": {"GeoLocation.country_name": f.geo_country.strip()}})
    if f.geo_country_pattern:
        clauses.append({"wildcard": {"GeoLocation.country_name": f.geo_country_pattern.strip()}})

    # Domain
    if f.domain:
        clauses.append({"match": {"data.domain": f.domain.strip()}})
    if f.domain_pattern:
        clauses.append({"wildcard": {"data.domain.keyword": f.domain_pattern.strip()}})
    if f.domain_contains:
        clauses.append({"wildcard": {"data.domain.keyword": f"*{f.domain_contains.strip()}*"}})

    # Rule
    if f.rule_ids:
        clauses.append({"terms": {"rule.id.keyword": [r.strip() for r in f.rule_ids]}})
    if f.rule_level_min is not None:
        clauses.append({"bool": {"should": [
            {"range": {"rule.level": {"gte": f.rule_level_min}}},
        ], "minimum_should_match": 1}})
    if f.rule_level_max is not None:
        clauses.append({"bool": {"should": [
            {"range": {"rule.level": {"lte": f.rule_level_max}}},
        ], "minimum_should_match": 1}})
    if f.rule_groups:
        clauses.append({"bool": {"should": [
            {"terms": {"rule.groups": f.rule_groups}},
            {"terms": {"rule.groups.keyword": f.rule_groups}},
        ], "minimum_should_match": 1}})
    if f.mitre_tactics:
        clauses.append({"terms": {"rule.mitre.tactic": f.mitre_tactics}})
    if f.mitre_techniques:
        clauses.append({"terms": {"rule.mitre.id": f.mitre_techniques}})

    # Agent
    if f.agent_name:
        clauses.append({"match": {"agent.name": f.agent_name.strip()}})
    if f.agent_ip:
        clauses.append({"match": {"agent.ip": f.agent_ip.strip()}})
    if f.agent_id:
        clauses.append({"match": {"agent.id": f.agent_id.strip()}})
    if f.decoder:
        clauses.append({"term": {"decoder.name": f.decoder.strip()}})

    # HTTP
    if f.url_pattern:
        clauses.append({"wildcard": {"data.url.keyword": f.url_pattern.strip()}})
    if f.response_codes:
        clauses.append({"terms": {"data.response_code": f.response_codes}})
    if f.http_methods:
        clauses.append({"terms": {"data.method": f.http_methods}})
    if f.user_agent_contains:
        clauses.append({"wildcard": {"data.user_agent.keyword":
                                     f"*{f.user_agent_contains.strip()}*"}})
    if f.referrer_pattern:
        clauses.append({"wildcard": {"data.referrer.keyword": f.referrer_pattern.strip()}})
    if f.response_size_min is not None:
        clauses.append({"range": {"data.response_size": {"gte": f.response_size_min}}})
    if f.response_size_max is not None:
        clauses.append({"range": {"data.response_size": {"lte": f.response_size_max}}})

    # Rule description free-text
    if f.rule_desc_contains:
        clauses.append({"wildcard": {"rule.description.keyword":
                                     f"*{f.rule_desc_contains.strip()}*"}})
    if f.rule_firedtimes_min is not None:
        clauses.append({"range": {"rule.firedtimes": {"gte": f.rule_firedtimes_min}}})
    if f.log_source_pattern:
        clauses.append({"wildcard": {"location.keyword": f.log_source_pattern.strip()}})

    # Geo bounding box
    if f.geo_bbox:
        parts = [p.strip() for p in f.geo_bbox.split(",")]
        if len(parts) == 4:
            try:
                lat1, lon1, lat2, lon2 = float(parts[0]), float(parts[1]), float(parts[2]), float(parts[3])
                clauses.append({"bool": {"must": [
                    {"range": {"GeoLocation.location.lat": {"gte": min(lat1, lat2), "lte": max(lat1, lat2)}}},
                    {"range": {"GeoLocation.location.lon": {"gte": min(lon1, lon2), "lte": max(lon1, lon2)}}},
                ]}})
            except ValueError:
                pass  # invalid bbox -> skip filter silently

    # IP inclusion/exclusion
    if f.srcips:
        ip_clauses = []
        for ip in f.srcips:
            ip = ip.strip()
            if ip:
                ip_clauses.append({"bool": {"should": [
                    {"match": {"data.srcip": ip}},
                    {"match_phrase": {"full_log": ip}},
                ], "minimum_should_match": 1}})
        clauses.extend(ip_clauses)
    if f.exclude_srcips:
        for ip in f.exclude_srcips:
            ip = ip.strip()
            if ip:
                clauses.append({"bool": {"must_not": {"match": {"data.srcip": ip}}}})

    return clauses


# G-2: Geo Distribution
class GeoDistributionInput(BaseModel):
    """Input model for blueteam_wazuh_geo_distribution."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    since: Optional[str] = Field(default="24h", max_length=30,
        description="Start of time window.")
    until: Optional[str] = Field(default=None, max_length=30,
        description="End of time window. Defaults to now.")
    top_n: int = Field(default=15, ge=3, le=50,
        description="Number of top countries to return.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")
    bypass_redaction: bool = Field(
        default=False, description=_BYPASS_REDACTION_DESC)


@mcp.tool(
    name="blueteam_wazuh_geo_distribution",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_wazuh_geo_distribution(params: GeoDistributionInput) -> str:
    """Show top attacking countries by alert volume using Wazuh GeoIP data.

    Pure aggregation - zero documents fetched (size: 0). Returns a country
    ranking with alert counts and unique IP counts. Uses Wazuh Indexer's
    built-in GeoLocation.country_name field.

    **Required Permissions**: Wazuh Indexer read access.

    **Worked Examples**

    1. *Last 24h*:
       ``blueteam_wazuh_geo_distribution()``

    2. *Last 7 days, top 25*:
       ``blueteam_wazuh_geo_distribution(since="7d", top_n=25)``

    3. *Specific date range*:
       ``blueteam_wazuh_geo_distribution(since="2026-07-17T00:00:00Z", until="2026-07-18T00:00:00Z")``
    """
    _audit_log("blueteam_wazuh_geo_distribution", {})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)

    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                       "format": "strict_date_optional_time"}}},
            {"exists": {"field": "GeoLocation.country_name"}},
        ]}},
        "aggs": {
            "by_country": {
                "terms": {"field": "GeoLocation.country_name", "size": params.top_n,
                          "order": {"_count": "desc"}},
                "aggs": {
                    "unique_ips": {
                        "cardinality": {"field": "data.srcip.keyword",
                                        "precision_threshold": 40000},
                    },
                    "top_rules": {
                        "terms": {"field": "rule.id.keyword", "size": 3},
                    },
                },
            },
            "total_with_geo": {"value_count": {"field": "GeoLocation.country_name"}},
        },
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)

    aggs = raw.get("aggregations", {})
    total_with_geo = aggs.get("total_with_geo", {}).get("value", 0)
    buckets = aggs.get("by_country", {}).get("buckets", [])

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({
            "window": {"since": since_iso, "until": until_iso},
            "total_alerts_with_geo": total_with_geo,
            "countries": [
                {"country": b["key"], "alerts": b["doc_count"],
                 "unique_ips": b.get("unique_ips", {}).get("value", 0),
                 "top_rules": [r["key"] for r in b.get("top_rules", {}).get("buckets", [])]}
                for b in buckets
            ],
        }, indent=2))

    lines = [
        f"# 🌍 Attack Geography — `{since_iso}` → `{until_iso}`",
        "",
        f"**Alerts with GeoIP data**: {total_with_geo:,}",
        "",
        "| Country | Alerts | Unique IPs | Top Rules |",
        "|---------|--------|------------|-----------|",
    ]
    for b in buckets:
        ips = b.get("unique_ips", {}).get("value", 0)
        rules = ", ".join(f"`{r['key']}`" for r in b.get("top_rules", {}).get("buckets", [])[:2]) or "-"
        lines.append(f"| {b['key']} | {b['doc_count']:,} | {ips:,} | {rules} |")

    if not buckets:
        lines.append("| *(no data)* | - | - | - |")
        lines.append("")
        lines.append("> ⚠️ GeoIP enrichment may not be enabled on this Wazuh Indexer. "
                     "Check that the GeoIP processor is configured.")

    return _truncate_if_needed("\n".join(lines))


# G-3: Curated Threat Report
class CuratedThreatReportInput(BaseModel):
    """Input model for blueteam_curated_threat_report."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    since: Optional[str] = Field(default="24h", max_length=30,
        description="Start of time window.")
    until: Optional[str] = Field(default=None, max_length=30,
        description="End of time window. Defaults to now.")
    filters: CuratedReportFilters = Field(
        default_factory=CuratedReportFilters,
        description="Filter specification. Only specified fields are applied. "
                    "All filters are AND'd. E.g.: "
                    '{"geo_country": "Indonesia", "domain_pattern": "*.go.id", "rule_level_min": 6}.')
    include_threat_intel: bool = Field(
        default=True,
        description="Enrich top IPs with Argus + CrowdSec + GreyNoise (adds ~3s latency).")
    max_entities: int = Field(
        default=50, ge=10, le=100,
        description="Max unique IPs to enrich with detailed threat intel.")
    group_by: Literal["srcip", "domain", "rule.id", "agent"] = Field(
        default="srcip",
        description="Aggregation axis: 'srcip' (per attacker), 'domain' (per target domain), "
                    "'rule.id' (per rule), 'agent' (per target agent).")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")
    bypass_redaction: bool = Field(default=False,
        description=_BYPASS_REDACTION_DESC)
    compare_since: Optional[str] = Field(
        default=None, max_length=30,
        description="Comparison window start. When set, runs a second query for the "
                    "previous period of equal length and produces a delta report. "
                    "E.g., since='48h' + compare_since='168h' compares current 48h "
                    "against the 48h before that. Aliases: 'compare', 'baseline'.")
    investigation_depth: Literal["summary", "enriched", "deep"] = Field(
        default="enriched",
        description="'summary' = aggregation only (fast), "
                    "'enriched' = aggregation + threat intel (default), "
                    "'deep' = enriched + auto-generated per-IP threat cards and "
                    "attack chains for IPs with max_level≥10 or crowdsec=malicious.")
    deduplicate: bool = Field(
        default=False,
        description="Remove child alerts (e.g., Active Response wrappers triggered "
                    "by parent alerts) from counts. Reduces noise from 1:N alert "
                    "relationships. Recognizes rule 606029 as child of its parent "
                    "rule via data.parameters.alert.rule.id.")
    time_decay: Literal["none", "linear", "exponential"] = Field(
        default="none",
        description="Weight recent alerts higher: 'none' (all equal), "
                    "'linear' (weight = 1 - age/window), "
                    "'exponential' (weight = e^(-age/half_life)). "
                    "Applied via OpenSearch function_score gauss decay on @timestamp.")
    scoring_mode: Literal["volume", "diversity"] = Field(
        default="volume",
        description="Entity ranking: 'volume' = by alert count (default), "
                    "'diversity' = by rule group entropy (surfaces multi-phase "
                    "attackers with few alerts across many tactics).")


@mcp.tool(
    name="blueteam_curated_threat_report",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_curated_threat_report(params: CuratedThreatReportInput) -> str:
    """Generate a geo/domain/rule-filtered threat intelligence report in one call.

    Combines alert aggregation, IP extraction, and multi-source threat intel
    enrichment into a single structured report. Replace 8–12 sequential LLM
    tool calls with one.

    **Filter dimensions** (any combination, all AND'd):
      • geo_country / geo_country_pattern — GeoLocation.country_name
      • geo_bbox - bounding box "lat1,lon1,lat2,lon2" for area filtering
      • domain / domain_pattern / domain_contains — data.domain
      • rule_ids / rule_level_min / rule_level_max / rule_groups / rule_desc_contains — rule filtering
      • mitre_tactics / mitre_techniques — ATT&CK filtering
      • agent_name / agent_ip / agent_id — target agent
      • decoder - log decoder name (web-accesslog, sysmon, etc.)
      • url_pattern / referrer_pattern / response_codes / response_size_min / response_size_max / http_methods / user_agent_contains - HTTP layer
      • rule_firedtimes_min - persistence signal
      • log_source_pattern - wildcard on location field
      • srcips (include) / exclude_srcips — IP-level
      • min_crowdsec_reputation — pre-filter by threat intel

    **Threat Intel** (best-effort, concurrent):
      Argus (7 upstream sources) + CrowdSec CTI (behaviors, MITRE, CVE) +
      AbuseIPDB (abuse score, reports) + VirusTotal (engine verdicts) +
      GreyNoise Community (scanner/business classification).

    **Required Permissions**: Wazuh Indexer read access. CROWDSEC_API_KEY for
    CrowdSec enrichment. ARGUS_API_KEY for Argus enrichment.

    **Worked Example**

    1. *Indonesian attackers targeting .go.id domains*:
       ``blueteam_curated_threat_report(filters={"geo_country": "Indonesia", "domain_pattern": "*.go.id"})``

    2. *Critical-severity recon against thezoo-prod*:
       ``blueteam_curated_threat_report(filters={"rule_level_min": 10, "agent_name": "thezoo-prod", "rule_groups": ["recon"]})``

    3. *Visual Studio Code probing from Indonesia*:
       ``blueteam_curated_threat_report(filters={"geo_country": "Indonesia", "url_pattern": "/.vscode/*"})``

    4. *T1083 technique, 7-day window*:
       ``blueteam_curated_threat_report(since="7d", filters={"mitre_techniques": ["T1083"]})``

    5. *Exclude known scanner*:
       ``blueteam_curated_threat_report(filters={"exclude_srcips": ["203.0.113.42"]})``
    """
    _audit_log("blueteam_curated_threat_report", {"filters": str(params.filters)[:200]})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)
    f = params.filters

    # Phase 1: Aggregation query (size: 0, no documents fetched)
    clauses = _build_curated_query(since_iso, until_iso, f)

    # Time-decay weighting via function_score gauss decay on @timestamp
    query_wrapper: dict = {"bool": {"must": clauses}}
    if params.time_decay != "none":
        half_life = max(60, _duration_minutes(since_iso, until_iso) * 15)  # seconds
        decay_config = {"@timestamp": {"origin": until_iso, "scale": f"{half_life:.0f}s",
                                        "decay": 0.5}}
        query_wrapper = {
            "function_score": {
                "query": {"bool": {"must": clauses}},
                "functions": [{"gauss": decay_config}],
                "boost_mode": "replace",
            }
        }

    # Select primary aggregation axis based on group_by
    group_config: dict[str, tuple[str, str]] = {
        "srcip": ("data.srcip.keyword", "top_entities"),
        "domain": ("data.domain.keyword", "top_entities"),
        "rule.id": ("rule.id.keyword", "top_entities"),
        "agent": ("agent.name.keyword", "top_entities"),
    }
    agg_field, agg_name = group_config.get(params.group_by, group_config["srcip"])

    body = {
        "size": 0,
        "query": query_wrapper,
        "aggs": {
            agg_name: {
                "terms": {"field": agg_field, "size": params.max_entities,
                          "order": {"_count": "desc"}},
                "aggs": {
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "max_level": {"max": {"field": "rule.level"}},
                    "top_rules": {"terms": {"field": "rule.id.keyword", "size": 5}},
                    "top_urls": {"terms": {"field": "data.url.keyword", "size": 5}},
                    "sample_geo": {"top_hits": {"size": 1, "_source": {"includes": ["GeoLocation"]}}},
                },
            },
            "total_alerts": {"value_count": {"field": "_id"}},
            "total_with_geo": {"value_count": {"field": "GeoLocation.country_name"}},
            "top_rules": {"terms": {"field": "rule.id.keyword", "size": 10}},
            "top_agents": {"terms": {"field": "agent.name.keyword", "size": 10}},
            "top_domains": {"terms": {"field": "data.domain.keyword", "size": 10}},
            "severity_bands": {
                "range": {"field": "rule.level",
                          "ranges": [{"key": "low", "to": 5},
                                     {"key": "medium", "from": 5, "to": 10},
                                     {"key": "high", "from": 10}]},
            },
        },
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)

    aggs = raw.get("aggregations", {})
    total_alerts = aggs.get("total_alerts", {}).get("value", 0)
    total_with_geo = aggs.get("total_with_geo", {}).get("value", 0)
    geo_coverage_pct = round(total_with_geo / total_alerts * 100, 1) if total_alerts > 0 else 0.0
    entity_buckets = aggs.get(agg_name, {}).get("buckets", [])
    rule_buckets = aggs.get("top_rules", {}).get("buckets", [])
    rule_buckets = aggs.get("top_rules", {}).get("buckets", [])
    agent_buckets = aggs.get("top_agents", {}).get("buckets", [])
    domain_buckets = aggs.get("top_domains", {}).get("buckets", [])
    severity = {b["key"]: b["doc_count"] for b in aggs.get("severity_bands", {}).get("buckets", [])}

    # Deduplication: remove child alert wrapper counts
    dedup_note = ""
    if params.deduplicate:
        dedup_body = {
            "size": 0,
            "query": {"bool": {"must": clauses + [
                {"terms": {"rule.id": ["606029", "651"]}},
            ]}},
            "aggs": {"total_children": {"value_count": {"field": "_id"}}},
        }
        try:
            dedup_raw = await _wazuh_indexer_post(dedup_body)
            child_count = (dedup_raw.get("aggregations", {})
                          .get("total_children", {}).get("value", 0))
            total_alerts = max(0, total_alerts - child_count)
            dedup_note = f" ({child_count} Active Response wrappers deduplicated)"
        except Exception:
            dedup_note = ""

    # Compare mode: run second query for previous period
    compare_data: dict[str, Any] = {}
    if params.compare_since:
        try:
            curr_duration = _duration_minutes(since_iso, until_iso)
            window_mins = max(60, curr_duration)
            comp_since_dt = datetime.fromisoformat(since_iso.replace("Z", "+00:00").rstrip("Z"))
            comp_since_iso = (comp_since_dt - timedelta(minutes=window_mins)).strftime("%Y-%m-%dT%H:%M:%SZ")
            comp_until_iso = since_iso

            comp_clauses = _build_curated_query(comp_since_iso, comp_until_iso, f)
            comp_body = {
                "size": 0,
                "query": {"bool": {"must": comp_clauses}},
                "aggs": {
                    agg_name: {"terms": {"field": agg_field, "size": params.max_entities}},
                    "total_alerts": {"value_count": {"field": "_id"}},
                    "severity_bands": {"range": {"field": "rule.level",
                        "ranges": [{"key": "low", "to": 5},
                                   {"key": "medium", "from": 5, "to": 10},
                                   {"key": "high", "from": 10}]}},
                },
            }
            comp_raw = await _wazuh_indexer_post(comp_body)
            if "error" not in comp_raw:
                c_aggs = comp_raw.get("aggregations", {})
                compare_data = {
                    "total_alerts": c_aggs.get("total_alerts", {}).get("value", 0),
                    "entities": len(c_aggs.get(agg_name, {}).get("buckets", [])),
                    "severity": {b["key"]: b["doc_count"]
                        for b in c_aggs.get("severity_bands", {}).get("buckets", [])},
                    "window": {"since": comp_since_iso, "until": comp_until_iso},
                }
        except Exception:
            compare_data = {"error": "comparison_query_failed"}

    # min_crowdsec_reputation pre-filter (Phase 0.5)
    crowdsec_filter_note = ""
    if params.filters.min_crowdsec_reputation and entity_buckets and params.group_by == "srcip" and os.environ.get(CROWDSEC_API_KEY_ENV):
        threshold_rep = params.filters.min_crowdsec_reputation.strip()
        all_ips = [b["key"] for b in entity_buckets]
        cs_verdicts: dict[str, str] = {}
        for ip in all_ips[:50]:
            try:
                cs = await _crowdsec_request(f"/v2/smoke/{ip}")
                cs_verdicts[ip] = cs.get("reputation", "unknown")
            except Exception:
                cs_verdicts[ip] = "lookup_failed"
        before = len(entity_buckets)
        entity_buckets = [b for b in entity_buckets if cs_verdicts.get(b["key"]) == threshold_rep]
        removed = before - len(entity_buckets)
        crowdsec_filter_note = f" (CrowdSec pre-filter '{threshold_rep}': {removed} IPs removed, {len(entity_buckets)} retained)"

    # Diversity re-ranking (when scoring_mode="diversity")
    if params.scoring_mode == "diversity" and entity_buckets:
        # Score each entity by rule group diversity (Shannon entropy * alert_count)
        for b in entity_buckets:
            rule_buckets_inner = b.get("top_rules", {}).get("buckets", [])
            distinct_rules = len(rule_buckets_inner)
            alert_count = b["doc_count"]
            # Diversity score: distinct rules * log(1 + alert_count)
            # rewards multi-phase attackers with moderate volume over noisy single-rule scanners
            import math
            b["_diversity_score"] = distinct_rules * math.log(1 + alert_count)
        entity_buckets.sort(key=lambda b: b.get("_diversity_score", 0), reverse=True)

    # Phase 2: Concurrent threat intel enrichment
    threat_data: dict[str, dict] = {}
    if params.include_threat_intel and entity_buckets and params.group_by == "srcip":
        top_ips = [b["key"] for b in entity_buckets[:min(params.max_entities, 15)]]

        async def _enrich_ip(ip: str) -> tuple[str, dict]:
            result: dict = {}
            # CrowdSec (cached)
            if os.environ.get(CROWDSEC_API_KEY_ENV):
                try:
                    cs = await _crowdsec_request(f"/v2/smoke/{ip}")
                    result["crowdsec"] = {
                        "reputation": cs.get("reputation", "unknown"),
                        "behaviors": [b.get("name", "") for b in cs.get("behaviors", [])],
                        "cves": cs.get("cves", []),
                    }
                except Exception:
                    result["crowdsec"] = {"error": "lookup_failed"}
            # Argus
            if os.environ.get(ARGUS_API_KEY_ENV):
                try:
                    argus_data = await _argus_request("/api/v1/lookup", {"ip_address": ip})
                    result["argus"] = {
                        "overall_score": argus_data.get("overall_score"),
                        "sources": list(argus_data.get("sources", {}).keys()) if isinstance(argus_data.get("sources"), dict) else [],
                    }
                except Exception:
                    result["argus"] = {"error": "lookup_failed"}
            # AbuseIPDB
            if ABUSEIPDB_API_KEY:
                try:
                    client = await _get_client("http")
                    resp = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                        params={"ipAddress": ip, "maxAgeInDays": "90"},
                    )
                    resp.raise_for_status()
                    data = resp.json().get("data", {})
                    result["abuseipdb"] = {
                        "abuse_score": data.get("abuseConfidenceScore"),
                        "total_reports": data.get("totalReports"),
                        "country": data.get("countryCode"),
                    }
                except Exception:
                    result["abuseipdb"] = {"error": "lookup_failed"}
            # VirusTotal
            if VIRUSTOTAL_API_KEY:
                try:
                    client = await _get_client("http")
                    resp = await client.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"},
                    )
                    resp.raise_for_status()
                    vt_data = resp.json().get("data", {}).get("attributes", {})
                    stats = vt_data.get("last_analysis_stats", {})
                    result["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "total_engines": sum(stats.values()) if stats else 0,
                    }
                except Exception:
                    result["virustotal"] = {"error": "lookup_failed"}
            return (ip, result)

        enrich_results = await asyncio.gather(*[_enrich_ip(ip) for ip in top_ips])
        threat_data = dict(enrich_results)

    # Phase 3: Format report
    if params.response_format == "json":
        result = {
            "window": {"since": since_iso, "until": until_iso},
            "filters_applied": f.model_dump(exclude_none=True),
            "total_alerts": total_alerts,
            "severity": severity,
            "top_rules": [{"id": b["key"], "count": b["doc_count"]} for b in rule_buckets],
            "top_agents": [{"name": b["key"], "count": b["doc_count"]} for b in agent_buckets],
            "top_domains": [{"domain": b["key"], "count": b["doc_count"]} for b in domain_buckets],
            "dedup_note": dedup_note if dedup_note else None,
            "compare": compare_data if compare_data else None,
            "attackers": [
                {
                    "ip": b["key"],
                    "alerts": b["doc_count"],
                    "max_level": int(b.get("max_level", {}).get("value", 0)),
                    "first_seen": b.get("first_seen", {}).get("value_as_string", ""),
                    "last_seen": b.get("last_seen", {}).get("value_as_string", ""),
                    "top_rules": [r["key"] for r in b.get("top_rules", {}).get("buckets", [])],
                    "top_urls": list(set(u["key"] for u in b.get("top_urls", {}).get("buckets", [])))[:5],
                    "threat_intel": threat_data.get(b["key"], {}),
                }
                for b in entity_buckets[:params.max_entities]
            ],
        }
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    # Markdown report
    filter_desc_parts: list[str] = []
    for field_name in ["geo_country", "domain_pattern", "domain_contains", "rule_ids",
                        "rule_level_min", "rule_level_max", "rule_groups",
                        "rule_desc_contains", "mitre_tactics", "mitre_techniques",
                        "agent_name", "agent_ip", "agent_id", "decoder",
                        "url_pattern", "referrer_pattern",
                        "response_size_min", "response_size_max",
                        "rule_firedtimes_min", "log_source_pattern",
                        "response_codes", "http_methods", "user_agent_contains",
                        "geo_bbox", "exclude_srcips"]:
        val = getattr(f, field_name, None)
        if val:
            filter_desc_parts.append(f"`{field_name}={val}`")
    filter_desc = ", ".join(filter_desc_parts) if filter_desc_parts else "(none — all alerts)"

    lines = [
        f"# 🛡️ Curated Threat Report",
        "",
        f"**Window**: `{since_iso}` → `{until_iso}`",
        f"**Filters**: {filter_desc}",
        "",
        "---",
        "",
        "## 📊 Executive Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total alerts matching filters | **{total_alerts:,}** |",
        f"| Unique entities | **{len(entity_buckets)}** |",
        f"| High-severity (L10+) | {severity.get('high', 0):,} |",
        f"| Medium-severity (L5-9) | {severity.get('medium', 0):,} |",
        f"| Low-severity (L1-4) | {severity.get('low', 0):,} |",
        f"| Unique rules triggered | {len(rule_buckets)} |",
        f"| Agents targeted | {len(agent_buckets)} |",
        f"| GeoIP coverage | {total_with_geo:,} of {total_alerts:,} ({geo_coverage_pct}%) |",
        f"| Dedup note | {dedup_note or 'none'} |",
        f"| CrowdSec filter | {crowdsec_filter_note or 'none'} |",
        "",
    ]
    # Comparison delta table
    if compare_data and "error" not in compare_data:
        prev_total = compare_data.get("total_alerts", 0)
        delta = total_alerts - prev_total
        delta_pct = (delta / prev_total * 100) if prev_total > 0 else float("inf")
        arrow = "↑" if delta > 0 else "↓" if delta < 0 else "—"
        lines.append("")
        lines.append("## 📈 Comparison vs Previous Period")
        lines.append("")
        lines.append("| Metric | Current | Previous | Δ |")
        lines.append("|--------|---------|----------|---|")
        lines.append(f"| Total alerts | {total_alerts:,} | {prev_total:,} | {delta:+,} ({delta_pct:+.0f}%) {arrow} |")
        prev_entities = compare_data.get("entities", 0)
        e_delta = len(entity_buckets) - prev_entities
        lines.append(f"| Unique entities | {len(entity_buckets)} | {prev_entities} | {e_delta:+} |")
        prev_sev = compare_data.get("severity", {})
        for sev_key in ["high", "medium", "low"]:
            cur_s = severity.get(sev_key, 0)
            prev_s = prev_sev.get(sev_key, 0)
            s_delta = cur_s - prev_s
            lines.append(f"| {sev_key.title()} severity | {cur_s:,} | {prev_s:,} | {s_delta:+,} |")
        lines.append("")

    # Top entities table — heading changes based on group_by
    entity_labels: dict[str, str] = {
        "srcip": ("🔴 Top Attackers", "IP", "Alerts"),
        "domain": ("🌐 Top Targeted Domains", "Domain", "Alerts"),
        "rule.id": ("🔥 Top Rules Triggered", "Rule ID", "Alerts"),
        "agent": ("🖥️ Most Targeted Agents", "Agent", "Alerts"),
    }
    section_title, col_name, col_alerts = entity_labels.get(params.group_by, entity_labels["srcip"])

    if entity_buckets:
        lines.append(f"## {section_title}")
        lines.append("")
        if params.group_by == "srcip":
            lines.append(f"| {col_name} | {col_alerts} | Max Lvl | Threat Intel | Top Rules | First → Last |")
            lines.append("|----|--------|---------|-------------|-----------|-------------|")
            for b in entity_buckets[:30]:
                key = b["key"]
                alerts = b["doc_count"]
                lvl = int(b.get("max_level", {}).get("value", 0))
                rules = ", ".join(f"`{r['key']}`" for r in b.get("top_rules", {}).get("buckets", [])[:2])
                fst = (b.get("first_seen", {}).get("value_as_string", "") or "")[:19]
                lst = (b.get("last_seen", {}).get("value_as_string", "") or "")[:19]
                ti = threat_data.get(key, {})
                ti_parts = []
                cs = ti.get("crowdsec", {})
                if cs and "error" not in cs:
                    ti_parts.append(f"CS:`{cs.get('reputation','?')}`")
                arg = ti.get("argus", {})
                if arg and "error" not in arg and arg.get("overall_score"):
                    ti_parts.append(f"Arg:{arg['overall_score']}")
                ab = ti.get("abuseipdb", {})
                if ab and "error" not in ab and ab.get("abuse_score") is not None:
                    ti_parts.append(f"AB:{ab['abuse_score']}%")
                vt = ti.get("virustotal", {})
                if vt and "error" not in vt:
                    ti_parts.append(f"VT:{vt.get('malicious',0)}/{vt.get('total_engines',0)}")
                ti_str = " ".join(ti_parts) if ti_parts else "-"
                lines.append(f"| `{key}` | {alerts:,} | {lvl} | {ti_str} | {rules} | {fst} → {lst} |")
        else:
            lines.append(f"| {col_name} | {col_alerts} | Top Rules | First → Last |")
            lines.append("|----|--------|-----------|-------------|")
            for b in entity_buckets[:30]:
                key = b["key"]
                alerts = b["doc_count"]
                rules = ", ".join(f"`{r['key']}`" for r in b.get("top_rules", {}).get("buckets", [])[:3])
                fst = (b.get("first_seen", {}).get("value_as_string", "") or "")[:19]
                lst = (b.get("last_seen", {}).get("value_as_string", "") or "")[:19]
                lines.append(f"| `{key}` | {alerts:,} | {rules} | {fst} → {lst} |")

    if rule_buckets:
        lines.append("")
        lines.append("## 🔥 Top Rules")
        for b in rule_buckets:
            lines.append(f"- `{b['key']}` — {b['doc_count']:,} alerts")

    if domain_buckets:
        lines.append("")
        lines.append("## 🌐 Top Targeted Domains")
        for b in domain_buckets[:10]:
            lines.append(f"- `{b['key']}` — {b['doc_count']:,} alerts")

    if agent_buckets:
        lines.append("")
        lines.append("## 🖥️ Most Targeted Agents")
        for b in agent_buckets[:10]:
            lines.append(f"- `{b['key']}` — {b['doc_count']:,} alerts")

    lines.append("")
    lines.append("## 🛠️ Recommended Actions")

    high_entities = [b for b in entity_buckets if int(b.get("max_level", {}).get("value", 0)) >= 10]
    if high_entities:
        lines.append(f"1. 🚨 {len(high_entities)} entities triggered critical-severity rules — initiate incident response")
    for b in entity_buckets[:5]:
        ip = b["key"]
        ti = threat_data.get(ip, {})
        cs = ti.get("crowdsec", {})
        if cs and cs.get("reputation") == "malicious":
            lines.append(f"2. Block `{ip}` — confirmed malicious by CrowdSec")
            break
    else:
        lines.append("2. Review top-10 IPs in external threat intel platforms for confirmation")
    lines.append(f"3. Total {len(entity_buckets)} unique entities — add high-severity offenders to watchlist")

    # Deep investigation: auto-chain attack chain analysis
    if params.investigation_depth == "deep" and entity_buckets and params.group_by == "srcip":
        deep_ips = []
        for b in entity_buckets[:10]:
            key = b["key"]
            lvl = int(b.get("max_level", {}).get("value", 0))
            ti = threat_data.get(key, {})
            cs = ti.get("crowdsec", {})
            if lvl >= 10 or (cs.get("reputation") == "malicious" and "error" not in cs):
                deep_ips.append(key)

        if deep_ips:
            lines.append("")
            lines.append("## 🔬 Deep Investigation (Auto-Chained)")
            lines.append("")
            lines.append(f"*{len(deep_ips)} qualifying IPs (max_level≥10 or CrowdSec=malicious)*")
            lines.append("")

            async def _chain_for_ip(ip):
                cbody = {"size": 500, "sort": [{"@timestamp": {"order": "asc"}}],
                    "query": {"bool": {"must": [
                        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                                 "format": "strict_date_optional_time"}}},
                        {"bool": {"should": [{"match": {"data.srcip": ip}},
                                            {"match_phrase": {"full_log": ip}}],
                                  "minimum_should_match": 1}},
                    ]}},
                    "_source": ["@timestamp", "rule.id", "rule.description"]}
                cr = await _wazuh_indexer_post(cbody)
                if "error" in cr:
                    return (ip, None)
                hits = cr.get("hits", {}).get("hits", [])
                rule_seq = [str(h.get("_source", {}).get("rule", {}).get("id", "?")) for h in hits]
                # compress consecutive duplicates
                comp = []
                for r in rule_seq:
                    if not comp or r != comp[-1]:
                        comp.append(r)
                rc = Counter(rule_seq)
                return (ip, {"total": len(hits), "chain": comp[:15], "top": rc.most_common(4)})

            chain_results = await asyncio.gather(*[_chain_for_ip(ip) for ip in deep_ips])
            for ip, ci in chain_results:
                if ci is None:
                    continue
                lines.append(f"### `{ip}`")
                lines.append(f"- Alerts: {ci['total']} | Chain: `{' → '.join(ci['chain'][:10])}`")
                top_str = ", ".join(f"`{r}`({c})" for r, c in ci["top"][:4])
                lines.append(f"- Top rules: {top_str}")
                lines.append("")

    lines.append("")
    lines.append("---")
    lines.append(f"*Report generated by blue_team_mcp (Wazuh Ft. AI by TangerangKota-CSIRT) at {datetime.utcnow().isoformat()[:19]}Z*")

    return _truncate_if_needed("\n".join(lines))


# Statistical Baselining
class BaselineProfileInput(BaseModel):
    """Input model for blueteam_baseline_profile."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    agent_name: Optional[str] = Field(default=None, max_length=64,
        description="Target agent for per-agent baselining.")
    rule_groups: Optional[list[str]] = Field(default=None,
        description="Filter by rule groups for per-rule-type baselining.")
    metric: Literal["alert_volume", "unique_ips", "high_severity"] = Field(
        default="alert_volume",
        description="Baseline metric: alert_volume, unique_ips, or high_severity (L10+).")
    window: str = Field(default="7d", max_length=30,
        description="Historical window for baseline computation.")
    granularity: str = Field(default="1h", max_length=10,
        description="Bucket granularity: 15m, 1h, 6h, 1d.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_baseline_profile",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_baseline_profile(params: BaselineProfileInput) -> str:
    """Compute statistical baselines for alert volume, unique IPs, or severity.

    Queries historical alert data and returns mean (μ), standard deviation (σ),
    and per-bucket Z-scores so the LLM can answer: "Is this normal?"

    **Required Permissions**: Wazuh Indexer read access.

    **Worked Examples**

    1. *Is current alert volume normal for thezoo-prod?*:
       ``blueteam_baseline_profile(agent_name="thezoo-prod", metric="alert_volume", window="7d")``

    2. *High-severity baseline across all agents*:
       ``blueteam_baseline_profile(metric="high_severity", window="30d", granularity="6h")``

    3. *Unique IP baseline for recon alerts*:
       ``blueteam_baseline_profile(rule_groups=["recon","scan"], metric="unique_ips", window="7d")``
    """
    _audit_log("blueteam_baseline_profile", {"metric": params.metric})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)

    since_iso, until_iso = _parse_time_window(params.window, None)

    filter_clauses: list[dict] = [
        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                   "format": "strict_date_optional_time"}}},
    ]
    if params.agent_name:
        filter_clauses.append({"match": {"agent.name": params.agent_name.strip()}})
    if params.rule_groups:
        filter_clauses.append({"bool": {"should": [
            {"terms": {"rule.groups": params.rule_groups}},
            {"terms": {"rule.groups.keyword": params.rule_groups}},
        ], "minimum_should_match": 1}})
    if params.metric == "high_severity":
        filter_clauses.append({"range": {"rule.level": {"gte": 10}}})

    aggs: dict = {}
    if params.metric == "unique_ips":
        aggs["metric_value"] = {"cardinality": {"field": "data.srcip.keyword",
                                                 "precision_threshold": 40000}}
    else:
        aggs["metric_value"] = {"value_count": {"field": "_id"}}

    body = {
        "size": 0,
        "query": {"bool": {"filter": filter_clauses}},
        "aggs": {
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": params.granularity,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": since_iso, "max": until_iso},
                },
                "aggs": aggs,
            }
        },
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)

    buckets = raw.get("aggregations", {}).get("over_time", {}).get("buckets", [])
    values = [
        (b.get("metric_value", {}).get("value", 0) if params.metric == "unique_ips"
         else b.get("doc_count", 0))
        for b in buckets
    ]
    n = len(values)
    if n < 2:
        result = {"baseline": {"mean": values[0] if values else 0, "stddev": 0.0,
                  "buckets": n, "verdict": "insufficient_data"}}
        return json.dumps(result, indent=2)

    mean_val = sum(values) / n
    variance = sum((v - mean_val) ** 2 for v in values) / n
    stddev = math.sqrt(variance)

    # Current value = most recent bucket
    current = values[-1] if values else 0
    z_current = (current - mean_val) / stddev if stddev > 0.0001 else 0.0

    max_val = max(values)
    max_z = (max_val - mean_val) / stddev if stddev > 0.0001 else 0.0
    peak_at = buckets[values.index(max_val)]["key_as_string"] if values else None

    verdict = (
        "critical_anomaly" if abs(z_current) >= 3.0 else
        "significant" if abs(z_current) >= 2.0 else
        "elevated" if abs(z_current) >= 1.0 else
        "normal"
    )

    if params.response_format == "json":
        result = {
            "window": {"since": since_iso, "until": until_iso},
            "granularity": params.granularity,
            "metric": params.metric,
            "baseline": {"mean": round(mean_val, 2), "stddev": round(stddev, 2),
                        "buckets": n},
            "current": {"value": current, "z_score": round(z_current, 2),
                       "verdict": verdict},
            "peak": {"value": max_val, "z_score": round(max_z, 2), "at": peak_at},
        }
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    label = params.metric.replace("_", " ").title()
    lines = [
        f"# 📊 Baseline Profile — {label}",
        "",
        f"**Window**: `{since_iso}` → `{until_iso}` ({params.granularity} buckets)",
        "",
        f"| Statistic | Value |",
        f"|-----------|-------|",
        f"| Mean (μ) | {mean_val:.1f} |",
        f"| StdDev (σ) | {stddev:.1f} |",
        f"| Current | **{current}** |",
        f"| Current Z-score | **{z_current:+.1f}σ** |",
        f"| Verdict | {verdict.replace('_',' ').title()} |",
        f"| Peak | {max_val} at {peak_at or '?'} ({max_z:+.1f}σ) |",
        "",
    ]
    if abs(z_current) >= 2.0:
        lines.append(f"⚠️ Current value is **{abs(z_current):.1f}σ** from mean — investigate.")
    else:
        lines.append("✅ Current value is within normal range.")

    lines.append("")
    lines.append("## Per-Bucket Breakdown")
    lines.append("```")
    for i, (b, v) in enumerate(zip(buckets, values)):
        ts = b.get("key_as_string", f"b{i}")[:16]
        z = (v - mean_val) / stddev if stddev > 0.0001 else 0.0
        bar = "█" * min(30, int(abs(z) * 8)) if abs(z) > 0.5 else "▁"
        marker_flag = " ← current" if i == n - 1 else ""
        lines.append(f"  {ts}  {v:>6.0f}  Z:{z:+.1f}  {bar}{marker_flag}")
    lines.append("```")

    return _truncate_if_needed("\n".join(lines))



# Investigation History
_INVESTIGATION_HISTORY_FILE = os.environ.get("BLUETEAM_INVESTIGATION_HISTORY", "")
def _read_history() -> dict[str, dict]:
    """Read investigation history from JSONL file. Returns {ip: latest_entry}."""
    if not _INVESTIGATION_HISTORY_FILE:
        return {}
    history: dict[str, dict] = {}
    try:
        with open(_INVESTIGATION_HISTORY_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                ip = entry.get("srcip", "")
                if ip:
                    history[ip] = entry
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return history


def _write_history(srcip: str, verdict: str, summary: dict) -> None:
    """Append an investigation entry to the history file."""
    if not _INVESTIGATION_HISTORY_FILE:
        return
    try:
        entry = {"ts": datetime.utcnow().isoformat() + "Z", "srcip": srcip,
                 "verdict": verdict, "summary": summary}
        with open(_INVESTIGATION_HISTORY_FILE, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


class InvestigationHistoryInput(BaseModel):
    """Input model for blueteam_investigation_history."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: str = Field(..., min_length=7, max_length=45,
        description="Source IP to check investigation history for.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_investigation_history",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_investigation_history(params: InvestigationHistoryInput) -> str:
    """Check if an IP was previously investigated and what the verdict was.

    Reads from BLUETEAM_INVESTIGATION_HISTORY (JSONL file). Returns the last
    investigation entry for the IP with timestamp, verdict, and summary.

    **Required**: BLUETEAM_INVESTIGATION_HISTORY env var pointing to a writable
    JSONL file. Without it, returns empty history.

    **Worked Examples**

    1. *Check prior investigation*:
       ``blueteam_investigation_history(srcip="103.107.116.202")``

    2. *Verify if IP is new*:
       ``blueteam_investigation_history(srcip="185.220.101.1")``
    """
    _audit_log("blueteam_investigation_history", {"srcip": params.srcip})
    history = _read_history()
    entry = history.get(params.srcip.strip())

    if params.response_format == "json":
        return json.dumps({
            "srcip": params.srcip,
            "previously_investigated": entry is not None,
            "last_entry": entry,
        }, indent=2, ensure_ascii=False)

    if entry:
        ts = entry.get("ts", "?")[:19]
        verdict = entry.get("verdict", "unknown")
        summary = entry.get("summary", {})
        return (
            f"# Investigation History — `{params.srcip}`\n\n"
            f"- **Last analyzed**: {ts}\n"
            f"- **Verdict**: {verdict}\n"
            f"- **Summary**: {json.dumps(summary, indent=2)}\n\n"
            f"_History file: {_INVESTIGATION_HISTORY_FILE}_"
        )
    return (
        f"# Investigation History — `{params.srcip}`\n\n"
        f"**No prior investigation found**. This IP has not been analyzed before.\n\n"
        f"_History file: {_INVESTIGATION_HISTORY_FILE or '(not configured)'}_"
    )



# AUL Adjust - CAT-B: Calendar Heatmap (Periodicity Detection)
class CalendarHeatmapInput(BaseModel):
    """Input model for blueteam_calendar_heatmap."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: Optional[str] = Field(default=None, max_length=45,
        description="Source IP to analyze. If omitted, aggregates all IPs.")
    days: int = Field(default=30, ge=7, le=90,
        description="Number of days to analyze (7-90). Default 30.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_calendar_heatmap",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_calendar_heatmap(params: CalendarHeatmapInput) -> str:
    """Detect scheduled attack patterns via day×hour heatmap analysis.

    Queries 7-90 days of alert data and builds a day-of-week x hour-of-day
    matrix. High-density cells reveal periodic attack schedules - the
    hallmark of automated C2 beaconing, cron-job exploitation, or
    scheduled scanning campaigns.

    **Required Permissions**: Wazuh Indexer read access.

    **Worked Examples**

    1. *Check if an IP attacks on a schedule*:
       ``blueteam_calendar_heatmap(srcip="103.107.116.202", days=30)``

    2. *Global attack pattern across all IPs*:
       ``blueteam_calendar_heatmap(days=14)``

    3. *Extended 90-day analysis*:
       ``blueteam_calendar_heatmap(srcip="185.220.101.1", days=90)``
    """
    _audit_log("blueteam_calendar_heatmap", {"srcip": params.srcip, "days": params.days})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)

    since_dt = datetime.utcnow() - timedelta(days=params.days)
    until_dt = datetime.utcnow()
    since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    until_iso = until_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    must_clauses: list[dict] = [
        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                   "format": "strict_date_optional_time"}}},
    ]
    if params.srcip:
        must_clauses.append({"bool": {"should": [
            {"match": {"data.srcip": params.srcip.strip()}},
            {"match_phrase": {"full_log": params.srcip.strip()}},
        ], "minimum_should_match": 1}})

    body = {
        "size": 0,
        "query": {"bool": {"must": must_clauses}},
        "aggs": {
            "by_hour": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": since_iso, "max": until_iso},
                },
            },
        },
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)

    buckets = raw.get("aggregations", {}).get("by_hour", {}).get("buckets", [])

    # Build day x hour matrix (Mon-Sun rows, 0-23 hour columns)
    days_of_week = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    matrix: list[list[int]] = [[0] * 24 for _ in range(7)]
    total_alerts = 0

    for b in buckets:
        ts = b.get("key_as_string", "")
        count = b.get("doc_count", 0)
        total_alerts += count
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            dow = dt.weekday()  # 0=Mon, 6=Sun
            hour = dt.hour
            matrix[dow][hour] += count
        except (ValueError, TypeError):
            continue

    # Find peak cell and compute statistics
    max_val = max(max(row) for row in matrix)
    flat = [v for row in matrix for v in row]
    n_cells = len(flat)
    mean_val = sum(flat) / n_cells if n_cells > 0 else 0.0
    variance = sum((v - mean_val) ** 2 for v in flat) / n_cells if n_cells > 0 else 0.0
    stddev = math.sqrt(variance)

    # Find peak day and hour
    peak_day_idx, peak_hour = 0, 0
    for d in range(7):
        for h in range(24):
            if matrix[d][h] > matrix[peak_day_idx][peak_hour]:
                peak_day_idx, peak_hour = d, h

    # Detect strongly periodic patterns (Z > 2.5 in any cell)
    periodic_cells = []
    for d in range(7):
        for h in range(24):
            z = (matrix[d][h] - mean_val) / stddev if stddev > 0.001 else 0.0
            if z >= 2.5:
                periodic_cells.append((days_of_week[d], h, matrix[d][h], round(z, 1)))

    verdict = (
        "strong_periodicity" if len(periodic_cells) >= 3 else
        "possible_periodicity" if periodic_cells else
        "no_periodicity"
    )

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({
            "window": {"since": since_iso, "until": until_iso, "days": params.days},
            "srcip": params.srcip,
            "total_alerts": total_alerts,
            "stats": {"mean_per_cell": round(mean_val, 1), "stddev": round(stddev, 1)},
            "peak": {"day": days_of_week[peak_day_idx], "hour": peak_hour,
                    "count": matrix[peak_day_idx][peak_hour]},
            "verdict": verdict,
            "periodic_cells": [{"day": d, "hour": h, "count": c, "z": z}
                              for d, h, c, z in periodic_cells],
            "matrix": {days_of_week[d]: {str(h): matrix[d][h] for h in range(24)}
                      for d in range(7)},
        }, indent=2, ensure_ascii=False))

    # ASCII heatmap
    lines = [
        f"# 📅 Calendar Heatmap — {params.srcip or 'All IPs'}",
        "",
        f"**Window**: {params.days} days ({since_iso[:10]} → {until_iso[:10]})",
        f"**Total alerts**: {total_alerts:,}",
        f"**Verdict**: {verdict.replace('_', ' ').title()}",
        "",
    ]

    if periodic_cells:
        lines.append("## ⚠️ Periodic Hotspots (Z ≥ 2.5)")
        lines.append("")
        for d, h, c, z in periodic_cells[:8]:
            lines.append(f"- **{d} {h:02d}:00** — {c:,} alerts ({z:+.1f}σ)")
        lines.append("")

    lines.append(f"## Day × Hour Matrix  (peak: {days_of_week[peak_day_idx]} {peak_hour:02d}:00 = {matrix[peak_day_idx][peak_hour]:,})")
    lines.append("")
    # Header
    lines.append("```")
    header = "     " + "".join(f"{h:>4}" for h in range(24))
    lines.append(header)
    lines.append("    " + "-" * 96)

    for d in range(7):
        row_vals = matrix[d]
        # Find max in this row for scaling
        row_max = max(row_vals) if max(row_vals) > 0 else 1
        # Build ASCII bar row
        bars = ""
        for h in range(24):
            v = row_vals[h]
            if v == 0:
                bars += "   ·"
            else:
                intensity = int(v / row_max * 3)
                chars = ["░", "▒", "▓", "█"]
                bars += f"  {chars[min(intensity, 3)]}"
        marker = " ◀" if d == peak_day_idx else ""
        lines.append(f" {days_of_week[d]} {bars}{marker}")
    lines.append("```")
    lines.append("")
    lines.append("_· = 0   ░ = low   ▒ = medium   ▓ = high   █ = peak_")
    lines.append("")
    lines.append(f"**Peak**: {days_of_week[peak_day_idx]} at {peak_hour:02d}:00 UTC "
                 f"({matrix[peak_day_idx][peak_hour]:,} alerts)")

    return _truncate_if_needed("\n".join(lines))



# Wazuh Manager API Expansion (Phase 1)
class WazuhRulesInput(BaseModel):
    """Input model for blueteam_wazuh_get_rules."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    rule_id: Optional[str] = Field(default=None, max_length=16,
        description="Optional specific rule ID to fetch.")
    path: Optional[str] = Field(default=None, max_length=256,
        description="Optional rule file path filter.")
    limit: int = Field(default=50, ge=1, le=500,
        description="Max rules to return.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_wazuh_get_rules",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_wazuh_get_rules(params: WazuhRulesInput) -> str:
    """Fetch deployed Wazuh rules (custom and stock) from the Manager API.

    Queries GET /rules with optional rule_id/path filters.

    **Required Permissions**: Wazuh Manager API access (port 55000).

    **Worked Examples**

    1. *All rules*:
       ``blueteam_wazuh_get_rules()``

    2. *Specific rule*:
       ``blueteam_wazuh_get_rules(rule_id="600029")``
    """
    _audit_log("blueteam_wazuh_get_rules", {"rule_id": params.rule_id})
    api_params = {"limit": str(params.limit)}
    if params.rule_id:
        api_params["rule_ids"] = params.rule_id.strip()
    if params.path:
        api_params["path"] = params.path.strip()
    data = await _wazuh_api_get("/rules", api_params)
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)
    items = data.get("data", {}).get("affected_items", [])
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"count": len(items), "rules": items[:params.limit]}, indent=2))
    lines = [f"# Wazuh Rules ({len(items)} found)", ""]
    for r in items[:30]:
        rid = r.get("id", "?")
        desc = _escape_md_table(str(r.get("description", ""))[:80])
        lvl = r.get("level", "?")
        lines.append(f"- `{rid}` (L{lvl}): {desc}")
    return _truncate_if_needed("\n".join(lines))


class WazuhDecodersInput(BaseModel):
    """Input model for blueteam_wazuh_get_decoders."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    decoder_name: Optional[str] = Field(default=None, max_length=64,
        description="Optional decoder name filter.")
    limit: int = Field(default=50, ge=1, le=500)
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_wazuh_get_decoders",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_wazuh_get_decoders(params: WazuhDecodersInput) -> str:
    """Query GET /decoders to audit active Wazuh decoders.

    **Worked Examples**

    1. *All decoders*:
       ``blueteam_wazuh_get_decoders()``

    2. *Specific decoder*:
       ``blueteam_wazuh_get_decoders(decoder_name="web-accesslog")``
    """
    _audit_log("blueteam_wazuh_get_decoders", {"decoder_name": params.decoder_name})
    api_params = {"limit": str(params.limit)}
    if params.decoder_name:
        api_params["decoder_names"] = params.decoder_name.strip()
    data = await _wazuh_api_get("/decoders", api_params)
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)
    items = data.get("data", {}).get("affected_items", [])
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"count": len(items), "decoders": items[:params.limit]}, indent=2))
    lines = [f"# Wazuh Decoders ({len(items)} found)", ""]
    for d in items[:30]:
        name = d.get("name", "?")
        detail = _escape_md_table(str(d.get("details", ""))[:60])
        lines.append(f"- `{name}`: {detail}")
    return _truncate_if_needed("\n".join(lines))


class WazuhGroupsInput(BaseModel):
    """Input model for blueteam_wazuh_get_groups."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    group_name: Optional[str] = Field(default=None, max_length=64,
        description="Optional group name filter.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_wazuh_get_groups",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_wazuh_get_groups(params: WazuhGroupsInput) -> str:
    """List Wazuh agent groups from GET /groups.

    **Worked Examples**

    1. *All groups*:
       ``blueteam_wazuh_get_groups()``

    2. *Specific group*:
       ``blueteam_wazuh_get_groups(group_name="web-servers")``
    """
    _audit_log("blueteam_wazuh_get_groups", {"group_name": params.group_name})
    api_params = {}
    if params.group_name:
        api_params["group_list"] = params.group_name.strip()
    data = await _wazuh_api_get("/groups", api_params)
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)
    items = data.get("data", {}).get("affected_items", [])
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"count": len(items), "groups": items}, indent=2))
    lines = [f"# Wazuh Agent Groups ({len(items)} found)", ""]
    for g in items[:30]:
        name = g.get("name", "?")
        count = g.get("count", 0) if isinstance(g, dict) else 0
        lines.append(f"- `{name}` ({count} agents)")
    return _truncate_if_needed("\n".join(lines))


class WazuhSecurityEventsInput(BaseModel):
    """Input model for blueteam_wazuh_get_security_events."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    limit: int = Field(default=50, ge=1, le=500)
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_wazuh_get_security_events",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_wazuh_get_security_events(params: WazuhSecurityEventsInput) -> str:
    """Fetch Wazuh Manager security audit events from GET /security/events.

    Returns admin actions, auth attempts, and configuration changes.

    **Worked Examples**

    1. *Recent events*:
       ``blueteam_wazuh_get_security_events()``

    2. *Extended log*:
       ``blueteam_wazuh_get_security_events(limit=200)``
    """
    _audit_log("blueteam_wazuh_get_security_events", {"limit": params.limit})
    api_params = {"limit": str(min(params.limit, 500)), "sort": "-timestamp"}
    data = await _wazuh_api_get("/security/events", api_params)
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)
    items = data.get("data", {}).get("affected_items", [])
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"count": len(items), "events": items[:params.limit]}, indent=2))
    lines = [f"# Wazuh Security Events ({len(items)} found)", ""]
    for e in items[:20]:
        ts = str(e.get("timestamp", "?"))[:19]
        user = e.get("user", "?")
        action = _escape_md_table(str(e.get("action", "?"))[:80])
        lines.append(f"- `[{ts}]` {user}: {action}")
    return _truncate_if_needed("\n".join(lines))


class WazuhClusterNodesInput(BaseModel):
    """Input model for blueteam_wazuh_get_cluster_nodes."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_wazuh_get_cluster_nodes",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_wazuh_get_cluster_nodes(params: WazuhClusterNodesInput) -> str:
    """Query GET /cluster/nodes for multi-node Wazuh cluster health.

    **Worked Examples**

    1. *Cluster status*:
       ``blueteam_wazuh_get_cluster_nodes()``
    """
    _audit_log("blueteam_wazuh_get_cluster_nodes", {})
    data = await _wazuh_api_get("/cluster/nodes")
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)
    items = data.get("data", {}).get("affected_items", [])
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"count": len(items), "nodes": items}, indent=2))
    lines = [f"# Wazuh Cluster Nodes ({len(items)} found)", ""]
    for n in items:
        name = n.get("name", "?")
        typ = n.get("type", "?")
        version = n.get("version", "?")
        ip = n.get("ip", "?")
        lines.append(f"- `{name}` ({typ}) v{version} @ {ip}")
    return _truncate_if_needed("\n".join(lines))


# Alert Lifecycle & Investigation State (Phase 2)
class MarkInvestigatedInput(BaseModel):
    """Input model for blueteam_mark_investigated."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    srcip: str = Field(..., min_length=7, max_length=45,
        description="Source IP being investigated.")
    verdict: Literal["true_positive", "false_positive", "suspicious", "clean", "unknown"] = Field(
        ..., description="Investigation verdict.")
    notes: str = Field(default="", max_length=1024,
        description="Analyst notes (max 1024 chars).")


@mcp.tool(
    name="blueteam_mark_investigated",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
)
async def blueteam_mark_investigated(params: MarkInvestigatedInput) -> str:
    """Record an IP investigation verdict in the persistent JSONL history.

    Appends a timestamped entry to BLUETEAM_INVESTIGATION_HISTORY. This is the
    only tool that writes investigation state — all other tools (curated reports,
    threat cards, beacon detection) are read-only.

    **Required**: BLUETEAM_INVESTIGATION_HISTORY env var set to a writable path.

    **Worked Examples**

    1. *Mark malicious*:
       ``blueteam_mark_investigated(srcip="103.107.116.202", verdict="true_positive", notes="CrowdSec confirmed — C2 beaconing")``

    2. *Mark false positive*:
       ``blueteam_mark_investigated(srcip="8.8.8.8", verdict="false_positive", notes="Google DNS — scanner noise")``
    """
    _audit_log("blueteam_mark_investigated", {"srcip": params.srcip, "verdict": params.verdict})
    if not _INVESTIGATION_HISTORY_FILE:
        return json.dumps({"error": "BLUETEAM_INVESTIGATION_HISTORY env var not set.",
                           "detail": "Set this to a writable JSONL file path for investigation persistence."}, indent=2)
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "srcip": params.srcip.strip(),
        "verdict": params.verdict,
        "notes": params.notes[:1024],
    }
    try:
        with open(_INVESTIGATION_HISTORY_FILE, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return json.dumps({"status": "recorded", "entry": entry}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed to write history: {e}"}, indent=2)


class FalsePositiveTrackerInput(BaseModel):
    """Input model for blueteam_false_positive_tracker."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    rule_id: str = Field(..., max_length=16,
        description="Wazuh rule ID to check, e.g. '600029'.")
    since: Optional[str] = Field(default="30d", max_length=30,
        description="Time window. ISO 8601 or relative ('7d', '30d').")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_false_positive_tracker",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_false_positive_tracker(params: FalsePositiveTrackerInput) -> str:
    """Count how often a Wazuh rule fired but was later marked false-positive.

    Parses BLUETEAM_INVESTIGATION_HISTORY to find IPs investigated with
    verdict="false_positive", then cross-references rule_id from investigation
    summaries. Helps SOC tune noisy Wazuh rules.

    **Worked Examples**

    1. *Check rule 600029*:
       ``blueteam_false_positive_tracker(rule_id="600029", since="30d")``
    """
    _audit_log("blueteam_false_positive_tracker", {"rule_id": params.rule_id})
    if not _INVESTIGATION_HISTORY_FILE:
        return json.dumps({"error": "BLUETEAM_INVESTIGATION_HISTORY not set."}, indent=2)
    since_dt = datetime.utcnow() - timedelta(days=30 if params.since == "30d" else 7)
    history = _read_history()
    fp_ips = {ip for ip, e in history.items()
              if e.get("verdict") == "false_positive"
              and e.get("ts", "") >= since_dt.strftime("%Y-%m-%d")}
    # Cross-reference: count rule_id mentions in FP summaries
    fp_count = 0
    fp_ips_list: list[str] = []
    for ip, e in history.items():
        if ip not in fp_ips:
            continue
        summary = e.get("summary", {})
        rules = summary.get("rules", [])
        if isinstance(rules, list):
            for r in rules:
                if isinstance(r, dict) and str(r.get("id", "")) == params.rule_id:
                    fp_count += 1
                    fp_ips_list.append(ip)
                    break
    if params.response_format == "json":
        return json.dumps({"rule_id": params.rule_id, "false_positive_count": fp_count,
                           "ips": fp_ips_list[:50]}, indent=2)
    return (f"# False Positive Tracker — Rule `{params.rule_id}`\n\n"
            f"- **False positive verdicts**: {fp_count}\n"
            f"- **IPs flagged**: {', '.join(f'`{ip}`' for ip in fp_ips_list[:10]) if fp_ips_list else 'none'}\n"
            f"- **Window**: since {since_dt.strftime('%Y-%m-%d')}\n")


class InvestigationSummaryInput(BaseModel):
    """Input model for blueteam_investigation_summary."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    since: Optional[str] = Field(default="7d", max_length=30,
        description="Time window. ISO 8601 or relative.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_investigation_summary",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_investigation_summary(params: InvestigationSummaryInput) -> str:
    """Dashboard: unique IPs investigated, verdict breakdown, analyst notes.

    Reads BLUETEAM_INVESTIGATION_HISTORY and aggregates recent investigations.
    Prevents redundant re-analysis by showing which IPs already have verdicts.

    **Worked Examples**

    1. *Last 7 days*:
       ``blueteam_investigation_summary()``

    2. *Last 30 days*:
       ``blueteam_investigation_summary(since="30d")``
    """
    _audit_log("blueteam_investigation_summary", {"since": params.since})
    if not _INVESTIGATION_HISTORY_FILE:
        return json.dumps({"error": "BLUETEAM_INVESTIGATION_HISTORY not set."}, indent=2)
    since_dt = datetime.utcnow() - timedelta(days=7 if params.since == "7d" else 30)
    history = _read_history()
    recent = {ip: e for ip, e in history.items()
              if e.get("ts", "")[:10] >= since_dt.strftime("%Y-%m-%d")}
    verdicts: Counter[str] = Counter()
    for e in recent.values():
        verdicts[e.get("verdict", "unknown")] += 1

    if params.response_format == "json":
        return json.dumps({
            "window_since": since_dt.strftime("%Y-%m-%d"),
            "total_investigated": len(recent),
            "verdicts": dict(verdicts),
            "ips": sorted(recent.keys()),
        }, indent=2)

    lines = [
        f"# Investigation Summary — Since {since_dt.strftime('%Y-%m-%d')}",
        "",
        f"**Total IPs investigated**: {len(recent)}",
        "",
        "| Verdict | Count |",
        "|---------|-------|",
    ]
    for v, c in verdicts.most_common():
        lines.append(f"| {v} | {c} |")
    if recent:
        lines.append("")
        lines.append("## Recent Investigations")
        for ip, e in sorted(recent.items(), key=lambda x: x[1].get("ts", ""), reverse=True)[:15]:
            ts = e.get("ts", "?")[:19]
            v = e.get("verdict", "?")
            notes = (e.get("notes", "") or "")[:60]
            lines.append(f"- `[{ts}]` `{ip}` — {v}" + (f" ({notes})" if notes else ""))
    return _truncate_if_needed("\n".join(lines))


# Wazuh Indexer index patterns (OpenSearch)
_WAZUH_INDEX_PATTERNS = {
    "alerts": "wazuh-alerts-*",
    "events": "wazuh-events-*",
    "vulnerabilities": "wazuh-states-vulnerabilities-*",
}

# Agent name: alphanumeric, hyphen, underscore, dot only (prevents injection)
class WazuhIndexerSearchInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid", populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def resolve_alias_collisions(cls, data: Any) -> Any:
        """Remove alias keys when the canonical field name is also present.

        ``WazuhIndexerSearchInput`` uses ``validation_alias=AliasChoices(...)``
        to accept both legacy short-form keys (``format``, ``from``, ``to``)
        and canonical names (``response_format``, ``since``, ``until``).

        When an LLM passes BOTH forms in the same call, Pydantic v2 with
        ``extra="forbid"`` sees the canonical name as an extra key after the
        alias populates the field.  This validator removes the alias, keeping
        the canonical name, so the call succeeds regardless of which form(s)
        the LLM sends.

        Also auto-parses JSON-string input — MCP clients may send complex
        args as raw JSON strings instead of native objects.
        """
        if isinstance(data, str):
            import json as _json
            try:
                data = _json.loads(data)
            except _json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON: {e.msg} at position {e.pos}. Check commas and braces.")
        if not isinstance(data, dict):
            return data
        alias_map: dict[str, str] = {
            "agent": "agent_name", "host": "agent_name", "hostname": "agent_name",
            "index": "index_type", "type": "index_type",
            "size": "limit", "count": "limit", "max": "limit",
            "format": "response_format", "output": "response_format",
            "ip": "srcip", "src_ip": "srcip", "source_ip": "srcip",
            "from": "since", "start": "since", "after": "since",
            "to": "until", "end": "until", "before": "until",
            "query": "keyword", "search": "keyword",
            "src_ips": "srcips", "ips": "srcips", "source_ips": "srcips",
            "rule_group": "rule_groups", "rule": "rule_groups", "groups": "rule_groups",
            "page": "cursor", "token": "cursor",
            "field": "fields", "columns": "fields",
        }
        for alias, canonical in alias_map.items():
            if alias in data and canonical in data:
                del data[alias]
        return data

    agent_name: ValidAgentName = Field(
        default=None,
        validation_alias=AliasChoices("agent", "host", "hostname"),
        max_length=64,
        description="Agent name to filter (e.g. 'HYDRA-DC'). Leave empty to search all agents.",
    )
    index_type: str = Field(default="alerts", validation_alias=AliasChoices("index", "type"), description="Index: alerts, events, or vulnerabilities")
    limit: int = Field(default=500, validation_alias=AliasChoices("size", "count", "max"), description="Max docs to return per page (0 = count-only, no documents)", ge=0, le=10000)
    response_format: Literal["markdown", "json"] = Field(
        default="json",
        validation_alias=AliasChoices("format", "output"),
        description="'json' for structured data with documents/cursor/total, "
                    "'markdown' for a compact summary table of results.",
    )
    srcip: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("ip", "src_ip", "source_ip"),
        max_length=45,
        description="Source IP address to filter alerts by (e.g. '180.254.78.145'). "
                    "Searches data.srcip, srcip, and full_log fields. Leave empty for all IPs.",
    )
    since: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("from", "start", "after"),
        max_length=30,
        description="Start of time window - ISO 8601 ('2026-07-05T18:30:00Z') or relative "
                    "('5m', '1h', '24h', '7d', '30d'). "
                    "To convert WIB (GMT+7): subtract 7 hours. "
                    "Can be used alone (no until required).",
    )
    until: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("to", "end", "before"),
        max_length=30,
        description="End of time window — ISO 8601 or relative expression. "
                    "Defaults to now if omitted. Can be used alone (no since required).",
    )
    keyword: ValidKeyword = Field(
        default=None,
        validation_alias=AliasChoices("query", "search"),
        max_length=1024,
        description="Free-text keyword search across full_log, rule.description, rule.info, "
                    "data.srcip, data.url, data.domain, and other text fields. Supports simple operators: "
                    "+term (must), -term (must not), term1|term2 (OR), *wildcard*, "
                    '\"exact phrase\". Example: \'gambling OR "online gambling"\'',
    )
    srcips: Optional[list[str]] = Field(
        default=None,
        validation_alias=AliasChoices("src_ips", "ips", "source_ips"),
        min_length=1,
        max_length=25,
        description="List of source IP addresses to filter alerts by (max 25). "
                    "Matches ANY of the listed IPs across data.srcip, data.srcip2, "
                    "srcip, and full_log fields. Use for searching alerts by multiple "
                    "suspicious IPs in a single call. Example: ['114.10.116.20', '51.159.125.199']",
    )
    geo_country: Optional[str] = Field(
        default=None,
        max_length=60,
        description="Filter by GeoLocation.country_name (Wazuh Indexer GeoIP enrichment). "
                    "Exact match, e.g. 'Indonesia'. Only alerts processed through GeoIP "
                    "enrichment are matched — results represent a lower bound.",
    )
    rule_groups: Optional[list[str]] = Field(
        default=None,
        validation_alias=AliasChoices("rule_group", "rule", "groups"),
        min_length=1,
        max_length=50,
        description="Filter alerts by rule groups (matches ANY of the listed groups). "
                    "Searches the rule.groups array field via OpenSearch terms query for "
                    "exact matching — more precise than free-text keyword. "
                    "Example: ['malicious_login', 'webshell', 'bruteforce', "
                    "'credential_stuffing', 'authentication_attempt'].",
    )
    cursor: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("page", "token"),
        description="Pagination cursor from previous response (next_cursor). Uses search_after "
                    "sort-key traversal — no 10K-doc ceiling. Omit for first page.",
    )
    fields: Optional[list[str]] = Field(
        default=None,
        validation_alias=AliasChoices("field", "columns"),
        min_length=1,
        max_length=50,
        description="Custom _source fields to retrieve (e.g. ['data.url', 'data.srcip', "
                    "'rule.description']). Omit to use server defaults: @timestamp, agent.name, "
                    "rule.id, rule.level, rule.description, data.srcip, data.url. "
                    "Specify fields to reduce payload size or get additional fields "
                    "like data.file.path, data.username, full_log.",
    )
    bypass_redaction: bool = Field(default=False, description="When true, return raw alert documents without PII masking. Overrides BLUETEAM_REDACT_PII for this call only — use for internal audit investigations.")
    max_scanned: Optional[int] = Field(
        default=None,
        ge=1000,
        le=1000000,
        description="When set, auto-paginate through all matching alerts up to this limit. "
                    "Returns an aggregated summary (total counts, top IPs, top rules) "
                    "across ALL scanned pages. Combine with include_all_docs=True for "
                    "forensic deep-dives (requires BLUETEAM_ALLOW_UNTRUNCATED=true). "
                    "When None (default), returns a single "
                    "page with next_cursor for manual pagination.",
    )
    bypass_character_limit: bool = Field(
        default=False,
        description="When True AND BLUETEAM_ALLOW_UNTRUNCATED=true, skip the 100K-character "
                    "response truncation for this call. Required for retrieving large "
                    "result sets in forensic investigations. Ignored (treated as False) "
                    "if the environment guard is not active — set BLUETEAM_ALLOW_UNTRUNCATED=true "
                    "on the server to unlock this capability.",
    )
    include_all_docs: bool = Field(
        default=False,
        description="When True AND BLUETEAM_ALLOW_UNTRUNCATED=true AND max_scanned is set, "
                    "return ALL scanned documents in the response instead of aggregating "
                    "into counts and samples. Dangerous for large time windows — always "
                    "pair with a conservative max_scanned. Ignored if the environment guard "
                    "is not active.",
    )
    auto_enrich: bool = Field(
        default=False,
        description="When True, pre-fetches CrowdSec reputation for all unique srcips "
                    "in the result set and injects an '_enrichment' field into each "
                    "document. Adds ~1s latency per 10 IPs. Requires CROWDSEC_API_KEY.",
    )

    @field_validator("bypass_character_limit")
    @classmethod
    def guard_bypass_character_limit(cls, v: bool) -> bool:
        if v and not BLUETEAM_ALLOW_UNTRUNCATED:
            raise ValueError(
                "bypass_character_limit=True requires BLUETEAM_ALLOW_UNTRUNCATED=true "
                "on the server. Set this environment variable on the MCP host to "
                "unlock untruncated forensic responses."
            )
        return v

    @field_validator("include_all_docs")
    @classmethod
    def guard_include_all_docs(cls, v: bool, info: Any) -> bool:
        if v and not BLUETEAM_ALLOW_UNTRUNCATED:
            raise ValueError(
                "include_all_docs=True requires BLUETEAM_ALLOW_UNTRUNCATED=true "
                "on the server. Set this environment variable on the MCP host to "
                "unlock full-document forensic retrieval."
            )
        return v

    @field_validator("fields")
    @classmethod
    def validate_fields(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        """Validate _source field names — alphanumeric + @/dot/underscore/hyphen."""
        if v is not None:
            cleaned: list[str] = []
            for f in v:
                f = f.strip()
                if not f:
                    continue
                if not re.match(r"^[a-zA-Z0-9@._-]+$", f):
                    raise ValueError(f"fields: invalid field name '{f}'")
                cleaned.append(f)
            return cleaned if cleaned else None
        return v


    @field_validator("srcips")
    @classmethod
    def validate_srcips(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        """Validate each IP in the list using ipaddress — IPv4/IPv6 only."""
        if v is not None:
            if len(v) > 25:
                raise ValueError("srcips: max 25 IPs (OpenSearch clause limit)")
            valid: list[str] = []
            for ip in v:
                ip = ip.strip()
                if not ip:
                    continue
                try:
                    ipaddress.ip_address(ip)
                except ValueError as exc:
                    raise ValueError(f"srcips: '{ip}' is not a valid IP address (IPv4/IPv6)") from exc
                valid.append(ip)
            return valid if valid else None
        return v

    @field_validator("rule_groups", mode="before")
    @classmethod
    def coerce_rule_groups(cls, v: Any) -> Any:
        """Coerce rule_groups from dict-wrapped or string forms into a plain list.

        Handles three LLM serialization patterns:
          - {'item': ['a', 'b']} → ['a', 'b']  (dict with 'item' key)
          - 'a, b, c' → ['a', 'b', 'c']         (comma-separated string)
          - 'a' → ['a']                           (single string)
        """
        if isinstance(v, dict):
            # Unwrap {"item": [...]} or {"items": [...]} patterns
            for key in ("item", "items", "values"):
                if key in v and isinstance(v[key], list):
                    return v[key]
            # Fallback: collect all list values
            for val in v.values():
                if isinstance(val, list):
                    return val
            # Last resort: treat dict values as items
            return list(v.values())
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator("rule_groups")
    @classmethod
    def validate_rule_groups(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        """Validate rule group names — alphanumeric + underscore/hyphen/dot."""
        if v is not None:
            cleaned: list[str] = []
            for g in v:
                g = g.strip()
                if not g:
                    continue
                if not re.match(r"^[a-zA-Z0-9._-]+$", g):
                    raise ValueError(f"rule_groups: invalid group name '{g}'")
                cleaned.append(g)
            return cleaned if cleaned else None
        return v


    @field_validator("srcip")
    @classmethod
    def validate_srcip(cls, v: Optional[str]) -> Optional[str]:
        """Sanitize srcip: validate looks like an IP address to prevent injection."""
        if v is not None:
            v = v.strip()
            if not v:
                return None
            if len(v) > 45:
                raise ValueError("srcip too long (max 45)")
            # Allow IPv4, IPv6, and CIDR notation - reject obvious non-IP strings
            if not re.match(r"^[0-9a-fA-F.:/]+$", v):
                raise ValueError("srcip must be a valid IP address or CIDR range")
        return v

async def _full_scan_paginate(
    max_scanned: int,
    fetch_page,
    initial_search_after: Optional[list],
    *,
    redact: bool = False,
) -> dict:
    """Shared search_after pagination loop for full-scan analysis.

    Returns a dict with keys: ``total_val``, ``total_relation``, ``total_scanned``,
    ``pages``, ``exhausted``, ``sample_docs``, ``all_docs``.

    ``fetch_page`` must be an async callable ``(page_size, search_after) -> dict``
    returning an OpenSearch response.
    """
    internal_page_size = 1000
    total_scanned = 0
    pages = 0
    exhausted = False
    global_total_val: Optional[int] = None
    global_total_relation = "eq"
    all_docs: list[dict] = []
    sample_docs: list[dict] = []
    search_after = initial_search_after

    while total_scanned < max_scanned:
        remaining = max_scanned - total_scanned
        page_size = min(internal_page_size, remaining)
        data = await fetch_page(page_size, search_after)
        if isinstance(data.get("error"), str):
            return {
                "total_val": global_total_val, "total_relation": global_total_relation,
                "total_scanned": total_scanned, "pages": pages,
                "exhausted": False, "sample_docs": sample_docs,
                "all_docs": all_docs, "_error": data["error"],
            }

        hits = data.get("hits", {})
        total = hits.get("total", {})
        if global_total_val is None:
            global_total_val = total.get("value", 0) if isinstance(total, dict) else total
            global_total_relation = total.get("relation", "eq") if isinstance(total, dict) else "eq"

        hit_list = hits.get("hits", [])
        docs = [h.get("_source", h) for h in hit_list]
        if redact:
            docs = _redact_alert_data(docs, bypass=False)
        pages += 1

        if not docs:
            exhausted = True
            break

        all_docs.extend(docs)
        if pages == 1:
            sample_docs = docs[:50]

        total_scanned += len(docs)
        last_sort = hit_list[-1].get("sort")
        if not last_sort or len(docs) < page_size:
            exhausted = True
            break
        search_after = last_sort

    return {
        "total_val": global_total_val, "total_relation": global_total_relation,
        "total_scanned": total_scanned, "pages": pages,
        "exhausted": exhausted, "sample_docs": sample_docs,
        "all_docs": all_docs,
    }


async def _wazuh_indexer_search_full_scan(
    params: "WazuhIndexerSearchInput",
    index_pattern: str,
    initial_search_after: Optional[list],
) -> str:
    """Auto-paginate through all matching indexer documents and return a summary.

    Loops internally with ``search_after``, scanning up to ``params.max_scanned``
    documents across all pages.  Uses the shared ``_full_scan_paginate`` loop.
    """
    forensic_mode = params.include_all_docs and BLUETEAM_ALLOW_UNTRUNCATED

    async def _fetch_page(ps: int, sa):
        return await _wazuh_indexer_search(
            index_pattern=index_pattern,
            agent_name=params.agent_name,
            size=ps,
            search_after=sa,
            srcip=params.srcip,
            since=params.since,
            until=params.until,
            keyword=params.keyword,
            srcips=params.srcips,
            fields=params.fields,
            rule_groups=params.rule_groups,
        )

    result = await _full_scan_paginate(
        params.max_scanned, _fetch_page, initial_search_after, redact=True,
    )
    if result.get("_error"):
        return json.dumps({"error": result["_error"]}, indent=2)

    total_scanned = result["total_scanned"]
    pages = result["pages"]
    exhausted = result["exhausted"]
    global_total_val = result["total_val"]
    global_total_relation = result["total_relation"]
    coverage = "complete" if exhausted else "partial"
    all_docs = result["all_docs"]
    sample_docs = result["sample_docs"]

    # Accumulate counters from all scanned docs
    global_srcip_counter: Counter[str] = Counter()
    global_rule_counter: Counter[str] = Counter()
    for doc in all_docs:
        ip = (doc.get("data") or {}).get("srcip") or doc.get("srcip", "")
        if ip:
            global_srcip_counter[ip] += 1
        rule = doc.get("rule") or {}
        rule_id = rule.get("id", "")
        rule_desc = rule.get("description", "")
        if rule_id:
            global_rule_counter[f"{rule_id}: {rule_desc}"] += 1

    total_display = (
        f"{global_total_val or 0:,}"
        + ("+" if global_total_relation == "gte" else "")
    )

    # Forensic mode: collect all docs from paginator output
    if forensic_mode:
        all_docs = _redact_alert_data(all_docs, bypass=params.bypass_redaction)
    sample_docs = _redact_alert_data(sample_docs, bypass=params.bypass_redaction)
    if params.response_format == "json":
        output: dict = {
            "mode": "full_scan",
            "index": params.index_type,
            "total": {"value": global_total_val, "relation": global_total_relation},
            "scanned": total_scanned,
            "pages": pages,
            "coverage": coverage,
            "timezone": "UTC",
            "aggregations": {
                "top_srcips": [
                    {"ip": ip, "count": c}
                    for ip, c in global_srcip_counter.most_common(30)
                ],
                "top_rules": [
                    {"rule": r, "count": c}
                    for r, c in global_rule_counter.most_common(20)
                ],
            },
        }
        if forensic_mode:
            output["all_documents"] = all_docs
            output["document_count"] = len(all_docs)
        else:
            output["sample_documents"] = sample_docs
        if params.since:
            output["since"] = params.since
        if params.until:
            output["until"] = params.until
        return _truncate_if_needed(
            json.dumps(output, indent=2, ensure_ascii=False),
            bypass=params.bypass_character_limit,
        )

    #Markdown output
    lines: list[str] = [
        f"# Wazuh Indexer Search (Full Scan)",
        "",
        f"**Total matches in indexer**: {total_display}",
        f"**Scanned**: {total_scanned:,} docs across {pages} page(s)",
        f"**Coverage**: {coverage} "
        + ("(all matching alerts retrieved)" if coverage == "complete"
           else f"(hit max_scanned={params.max_scanned:,} limit)"),
    ]
    if forensic_mode:
        lines.append(f"**Mode**: FORENSIC (all {len(all_docs):,} documents returned)")
    lines.append(f"**Index**: {params.index_type} | **Timezone**: UTC")
    if params.since or params.until:
        window_str = f"{params.since or '...'} → {params.until or '...'}"
        lines.append(f"**Window**: {window_str}")
    lines.append("")

    if global_srcip_counter:
        lines.append("## Top Source IPs (global)")
        lines.append("| IP | Alert Count |")
        lines.append("|----|-------------|")
        for ip, c in global_srcip_counter.most_common(20):
            lines.append(f"| {_escape_md_table(ip)} | {c:,} |")
        lines.append("")

    if global_rule_counter:
        lines.append("## Top Rules (global)")
        lines.append("| Rule | Count |")
        lines.append("|------|-------|")
        for r, c in global_rule_counter.most_common(15):
            lines.append(f"| {_escape_md_table(r)} | {c:,} |")
        lines.append("")

    display_docs = all_docs if forensic_mode else sample_docs
    if display_docs:
        heading = "## All Documents" if forensic_mode else "## Sample Alerts (first 20 from page 1)"
        lines.append(heading)
        lines.append("")
        lines.append("| # | Timestamp (UTC) | Agent | Rule | Level | Src IP | Description |")
        lines.append("|---|-----------------|-------|------|-------|--------|-------------|")
        doc_limit = len(display_docs) if forensic_mode else min(20, len(display_docs))
        for i, d in enumerate(display_docs[:doc_limit], 1):
            ts = str(d.get("@timestamp", ""))[:19]
            agent = str((d.get("agent") or {}).get("name", ""))[:25]
            rule_id = str((d.get("rule") or {}).get("id", ""))
            level = str((d.get("rule") or {}).get("level", ""))
            srcip = str(
                (d.get("data") or {}).get("srcip")
                or d.get("srcip", "")
            )[:18]
            desc = str((d.get("rule") or {}).get("description", ""))[:60]
            lines.append(f"| {i} | {_escape_md_table(ts)} | {_escape_md_table(agent)} | {_escape_md_table(rule_id)} | {_escape_md_table(level)} | {_escape_md_table(srcip)} | {_escape_md_table(desc)} |")
        if forensic_mode and len(display_docs) > 50:
            lines.append(f"")
            lines.append(f"_(showing first 50 of {len(display_docs):,} documents in markdown — use response_format=json for full output)_")
        lines.append("")

    if coverage != "complete":
        lines.append(
            f"\n**Note:** Results are partial - scan hit the "
            f"`max_scanned={params.max_scanned:,}` limit. "
            f"Increase `max_scanned` (up to 1,000,000) for full coverage."
        )

    return _truncate_if_needed("\n".join(lines), bypass=params.bypass_character_limit)


@mcp.tool(
    name="blueteam_wazuh_indexer_search",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_wazuh_indexer_search(params: WazuhIndexerSearchInput = WazuhIndexerSearchInput()) -> str:
    """Query Wazuh Indexer (OpenSearch) for alerts/events with cursor pagination.
    Supports filtering by params.agent_name, params.srcip/s (source IP), keyword, or all simultaneously.
    Requires WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD (port 9200).

    **Three modes**:

    - **Single-page** (default, ``params.max_scanned`` not set): Returns one page per call.
      Pass the returned ``next_cursor`` back as the ``params.cursor`` parameter to fetch
      the next page. ``next_cursor`` is null when all results are exhausted.
    - **Full-scan aggregate** (set ``params.max_scanned``): Auto-paginates across ALL
      matching pages and returns aggregated summary (top IPs, top rules) with 50
      sample documents.
    - **Full-scan forensic** (``params.max_scanned`` + ``include_all_docs=True``): Returns
      ALL scanned documents alongside aggregations. Requires
      ``BLUETEAM_ALLOW_UNTRUNCATED=true`` on the server. Pair with
      ``bypass_character_limit=True`` to avoid the 100K-character response cap.

    Args:
        params.agent_name: Optional agent name filter (e.g. HYDRA-DC)
        params.srcip: Optional single source IP filter (e.g. '180.254.78.145')
        srcips: Optional list of source IPs to match ANY of (max 25)
                       (e.g. ['114.10.116.20', '51.159.125.199'])
        params.keyword: Optional free-text keyword search (e.g. 'gambling OR "brute force"')
        params.since: Optional ISO 8601 start time in UTC (e.g. '2026-07-05T18:30:00Z')
        params.until: Optional ISO 8601 end time in UTC (e.g. '2026-07-05T19:00:00Z')
        params.index_type: alerts (default), events, or vulnerabilities
        params.limit: Max documents per page in single-page mode (default 500, max 10000)
        params.cursor: next_cursor from previous response (omit for first page)
        params.max_scanned: When set, run full-scan auto-pagination (max 1,000,000)
        params.include_all_docs: When True, return all documents in full-scan mode
        params.bypass_character_limit: When True, skip 100K-char response cap

    Returns:
        str: In 'json' mode (default): JSON with documents, total, params.size, count, next_cursor,
             and timezone. Metadata includes ``applied_size`` when ``_WAZUH_INDEXER_MAX_SIZE``
             clamped the per-page document count.
    """
    _audit_log("blueteam_wazuh_indexer_search", {})
    if params.index_type not in _WAZUH_INDEX_PATTERNS:
        return json.dumps({"error": f"index_type must be one of: {list(_WAZUH_INDEX_PATTERNS)}"})
    index_pattern = _WAZUH_INDEX_PATTERNS[params.index_type]

    # Decode pagination cursor - search_after uses sort-key values, not numeric offsets
    search_after: Optional[list] = None
    if params.cursor:
        decoded = _decode_cursor(params.cursor)
        if decoded:
            search_after = decoded.get("search_after")

    # Auto-pagination mode - scan ALL pages internally, return aggregate
    if params.max_scanned is not None:
        return await _wazuh_indexer_search_full_scan(
            params, index_pattern, search_after
        )

    data = await _wazuh_indexer_search(
        index_pattern=index_pattern,
        agent_name=params.agent_name,
        size=params.limit,
        search_after=search_after,
        srcip=params.srcip,
        since=params.since,
        until=params.until,
        keyword=params.keyword,
        srcips=params.srcips,
        fields=params.fields,
        rule_groups=params.rule_groups,
        geo_country=params.geo_country,
    )
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)
    hits = data.get("hits", {})
    total = hits.get("total", {})
    total_val = total.get("value", 0) if isinstance(total, dict) else total
    total_relation = total.get("relation", "eq") if isinstance(total, dict) else "eq"
    docs = [h.get("_source", h) for h in hits.get("hits", [])]

    # Build next cursor from the last document's sort values
    next_cursor = None
    hit_list = hits.get("hits", [])
    if hit_list and len(docs) >= params.limit:
        last_sort = hit_list[-1].get("sort")
        if last_sort:
            next_cursor = _encode_cursor({"search_after": last_sort})

    # Auto-enrich: inject CrowdSec reputation inline
    if params.auto_enrich and docs and os.environ.get(CROWDSEC_API_KEY_ENV):
        unique_ips = set()
        for d in docs:
            data = d.get("data", {}) if isinstance(d, dict) else {}
            sip = str(data.get("srcip", "")).strip()
            if sip:
                unique_ips.add(sip)
        if unique_ips:
            enrich_map: dict[str, dict] = {}
            for ip in list(unique_ips)[:10]:  # cap at 10 IPs to avoid rate limits
                try:
                    cs = await _crowdsec_request(f"/v2/smoke/{ip}")
                    enrich_map[ip] = {
                        "reputation": cs.get("reputation", "unknown"),
                        "behaviors": [b.get("name", "") for b in cs.get("behaviors", [])[:3]],
                    }
                except Exception:
                    enrich_map[ip] = {"reputation": "lookup_failed"}
            for d in docs:
                data = d.get("data", {}) if isinstance(d, dict) else {}
                sip = str(data.get("srcip", "")).strip()
                if sip in enrich_map:
                    d["_enrichment"] = {"crowdsec": enrich_map[sip]}

    meta: dict = {
        "total": {"value": total_val, "relation": total_relation},
        "count": len(docs),
        "size": params.limit,
        "next_cursor": next_cursor,
        "timezone": "UTC",
        "documents": docs,
    }
    # Surface applied_size when _WAZUH_INDEXER_MAX_SIZE clamped the request.
    # This lets callers programmatically detect capped pages and adjust.
    if data.get("applied_size") is not None:
        meta["applied_size"] = data["applied_size"]
        meta["requested_size"] = data["requested_size"]
    if params.since:
        meta["since"] = params.since
    if params.until:
        meta["until"] = params.until

    if params.response_format == "json":
        meta["documents"] = _redact_alert_data(meta["documents"], bypass=params.bypass_redaction)
        return _truncate_if_needed(
            json.dumps(meta, indent=2),
            bypass=params.bypass_character_limit,
        )

    # Markdown: compact summary table
    lines = [
        f"# Wazuh Indexer Search Results",
        f"",
        f"**Total**: {total_val} ({total_relation}) | **Returned**: {len(docs)} | **Page params.size**: {params.limit}",
        f"**Index**: {params.index_type} | **Timezone**: UTC",
    ]
    if params.since or params.until:
        window = f"{params.since or '...'} → {params.until or '...'}"
        lines.append(f"**Window**: {window}")
    if next_cursor:
        lines.append(f"**Cursor**: `{next_cursor[:40]}...` (more pages available)")
    lines.append("")
    lines.append("| # | Timestamp (UTC) | Agent | Rule | Level | Src IP | Description |")
    lines.append("|---|-----------------|-------|------|-------|--------|-------------|")
    for i, d in enumerate(docs[:100], 1):
        ts = str(d.get("@timestamp", ""))[:19]
        agent = str((d.get("agent") or {}).get("name", ""))[:25]
        rule_id = str((d.get("rule") or {}).get("id", ""))
        level = str((d.get("rule") or {}).get("level", ""))
        srcip = str(
            (d.get("data") or {}).get("srcip")
            or d.get("srcip", "")
        )[:18]
        desc = str((d.get("rule") or {}).get("description", ""))[:60]
        lines.append(f"| {i} | {_escape_md_table(ts)} | {_escape_md_table(agent)} | {_escape_md_table(rule_id)} | {_escape_md_table(level)} | {_escape_md_table(srcip)} | {_escape_md_table(desc)} |")
    if len(docs) > 100:
        lines.append(f"")
        lines.append(f"_(showing first 100 of {len(docs)} documents — set response_format=json for full output)_")
    # Surface applied_size in markdown output when cap was enforced
    if data.get("applied_size") is not None:
        lines.append(f"")
        lines.append(
            f"**Note:** Requested page params.size {data['requested_size']} was clamped to "
            f"{data['applied_size']} by `WAZUH_INDEXER_MAX_SIZE`. "
            f"Raise this env var on the server for larger pages."
        )
    return _truncate_if_needed("\n".join(lines), bypass=params.bypass_character_limit)


# Wazuh Email & Domain Lookup
def _extract_emails_from_doc(doc: dict) -> set[str]:
    """Extract email addresses from a single Wazuh alert document.
    Checks ``data.account`` first (structured, most reliable), then scans
    ``full_log`` with the compiled ``_EMAIL_RE`` regex.  Returns a set of
    lowercased email addresses.
    """
    found: set[str] = set()
    # Structured account field (Zimbra alerts)
    account = (doc.get("data") or {}).get("account")
    if account and isinstance(account, str) and "@" in account:
        for m in _EMAIL_RE.finditer(account):
            found.add(m.group(0).lower())
    # Full log line
    full_log = doc.get("full_log")
    if full_log and isinstance(full_log, str):
        for m in _EMAIL_RE.finditer(full_log):
            found.add(m.group(0).lower())
    return found


class WazuhEmailLookupInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    agent_name: ValidAgentName = Field(
        default=None,
        max_length=64,
        description="Optional agent name filter (e.g. 'mailbox-new'). Omit to search all agents.",
    )
    since: Optional[str] = Field(
        default=None,
        max_length=30,
        description="Start of time window — ISO 8601 ('2026-07-07T00:00:00Z') or relative "
                    "('5m', '1h', '24h', '7d', '30d'). Defaults to 365 days ago if omitted.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window — ISO 8601 or relative expression. Defaults to now if omitted.",
    )
    top_n: int = Field(
        default=100,
        description="Number of top email addresses to return, ranked by frequency.",
        ge=1,
        le=500,
    )
    rule_groups: ValidRuleGroups = Field(
        default=None,
        max_length=1024,
        description="Comma-separated rule groups to filter by "
                    "(e.g. 'authentication_failed,brute_force'). "
                    "Omit to search all rule groups.",
    )
    max_scanned: int = Field(
        default=50000,
        description="Maximum number of alert documents to scan internally. "
                    "Higher values give more accurate counts but take longer.",
        ge=100,
        le=200000,
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="'markdown' for human-readable report, 'json' for structured data.",
    )
    keyword: ValidKeyword = Field(
        default=None,
        max_length=1024,
        description="Free-text keyword search to further narrow email results. "
                    "Same syntax as blueteam_wazuh_indexer_search.",
    )



@mcp.tool(
    name="wazuh_email_lookup",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def wazuh_email_lookup(params: WazuhEmailLookupInput) -> str:
    """Search Wazuh alerts for email addresses and rank top-N most frequently seen.

    Scans the ``full_log`` field (raw log line) and the structured ``data.account``
    field (Zimbra alerts) for email-address-like strings.  Aggregates every unique
    address with its occurrence count, associated source IPs, and the rule groups
    it appears in.  Results are sorted by frequency descending.

    Querying the full year requires scanning many documents.  The internal scanner
    pages through alerts using ``search_after`` cursors params.until either the Indexer
    is exhausted or ``params.max_scanned`` documents have been processed.

    Args:
        params.agent_name: Optional agent to filter (e.g. 'mailbox-new')
        params.since: ISO 8601 start (default: 365 days ago)
        params.until: ISO 8601 end (default: now)
        params.top_n: How many top emails to return (1-500, default 100)
        params.rule_groups: Comma-separated groups filter
        params.max_scanned: Hard cap on documents scanned (1000-200000, default 50000)
        params.response_format: 'markdown' or 'json'

    Returns:
        str: Ranked table of email addresses with counts, unique IPs,
        and associated rule categories.  Summary statistics are included.

    Example usage:
        - "Find the top 100 most compromised email addresses in the last year"
        - "Show me the most targeted mailboxes on agent mailbox-new"
    """
    _audit_log("wazuh_email_lookup", {"since": params.since})
    since_str, until_str = _parse_time_window(params.since, params.until)

    rule_group_list: Optional[list[str]] = None
    if params.rule_groups:
        rule_group_list = [g.strip() for g in params.rule_groups.split(",") if g.strip()]

    email_counter: Counter[str] = Counter()
    email_srcips: dict[str, set[str]] = {}    # email -> set of srcip
    email_rules: dict[str, set[str]] = {}     # email -> set of "rule_id: description"
    email_groups: dict[str, set[str]] = {}    # email -> set of rule groups
    email_first_seen: dict[str, str] = {}     # email -> earliest timestamp
    email_last_seen: dict[str, str] = {}      # email -> latest timestamp

    total_scanned = 0
    search_after: Optional[list] = None
    page_size = 1000
    try:
        while total_scanned < params.max_scanned:
            data = await _wazuh_indexer_email_search(
                agent_name=params.agent_name,
                size=page_size,
                search_after=search_after,
                since=since_str,
                until=until_str,
                rule_groups=rule_group_list,
                keyword=params.keyword,
            )
            if "error" in data:
                error_msg = data["error"]
                # If already collected some data, return partial results. (Aul Adjust)
                if total_scanned > 0:
                    break
                return json.dumps(data, indent=2)

            hits = data.get("hits", {})
            hit_list = hits.get("hits", [])
            docs = [h.get("_source", h) for h in hit_list]
            docs = _redact_alert_data(docs, bypass=False)
            if not docs:
                break

            for doc in docs:
                emails = _extract_emails_from_doc(doc)
                ts = doc.get("@timestamp", "")
                srcip = (doc.get("data") or {}).get("srcip", "")
                rule = doc.get("rule") or {}
                rule_id = rule.get("id", "")
                rule_desc = rule.get("description", "")
                groups = tuple(rule.get("groups", []))

                for email in emails:
                    email_counter[email] += 1
                    if srcip:
                        email_srcips.setdefault(email, set()).add(srcip)
                    if rule_id:
                        email_rules.setdefault(email, set()).add(f"{rule_id}: {rule_desc}")
                    for g in groups:
                        email_groups.setdefault(email, set()).add(g)
                    if email not in email_first_seen or (ts and ts < email_first_seen[email]):
                        email_first_seen[email] = ts
                    if email not in email_last_seen or (ts and ts > email_last_seen[email]):
                        email_last_seen[email] = ts

            total_scanned += len(docs)

            # Advance cursor or stop if exhausted
            if len(docs) < page_size:
                break
            last_sort = hit_list[-1].get("sort") if hit_list else None
            if last_sort:
                search_after = last_sort
            else:
                break

    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        if total_scanned == 0:
            return _handle_api_error(e, context="wazuh_email_lookup")
        # Partial results on transient error during pagination
        logging.getLogger(__name__).warning(
            "wazuh_email_lookup: error after %d docs scanned: %s", total_scanned, e
        )

    # Rank by frequency
    top_emails = email_counter.most_common(params.top_n)

    # Stats
    total_unique = len(email_counter)
    total_with_auth_fail = sum(
        1 for e in email_counter
        if any("authentication_fail" in g.lower() for g in email_groups.get(e, set()))
    )
    total_with_brute_force = sum(
        1 for e in email_counter
        if any("brute" in g.lower() for g in email_groups.get(e, set()))
    )
    high_freq = sum(1 for _, c in email_counter.items() if c >= 10)

    if params.response_format == "json":
        results = []
        for email, count in top_emails:
            results.append({
                "email": email,
                "count": count,
                "unique_srcips": len(email_srcips.get(email, set())),
                "top_srcips": sorted(email_srcips.get(email, set()))[:20],
                "rule_groups": sorted(email_groups.get(email, set())),
                "top_rules": sorted(email_rules.get(email, set()))[:10],
                "first_seen": email_first_seen.get(email),
                "last_seen": email_last_seen.get(email),
            })
        output = {
            "results": results,
            "summary": {
                "total_emails_found": total_unique,
                "documents_scanned": total_scanned,
                "time_window": {"since": since_str, "until": until_str},
                "auth_failure_emails": total_with_auth_fail,
                "brute_force_emails": total_with_brute_force,
                "emails_with_10plus_appearances": high_freq,
            },
            "query": {
                "agent_name": params.agent_name,
                "rule_groups": params.rule_groups,
                "since": since_str,
                "until": until_str,
                "max_scanned": params.max_scanned,
            },
        }
        return _truncate_if_needed(json.dumps(output, indent=2, ensure_ascii=False))

    # Markdown output
    lines: list[str] = [
        f"# Wazuh Email Lookup — Top {len(top_emails)} Emails",
        "",
        f"**Time window**: {since_str} to {until_str}",
        f"**Documents scanned**: {total_scanned:,}",
        f"**Unique emails found**: {total_unique:,}",
        f"**Agent**: {params.agent_name or 'all agents'}",
        f"**Rule groups**: {params.rule_groups or 'all'}",
        "",
        "## Top Email Addresses",
        "",
        "| # | Email | Count | Unique IPs | Top Rule Groups |",
        "|---|-------|-------|------------|-----------------|",
    ]
    for i, (email, count) in enumerate(top_emails, 1):
        ips = len(email_srcips.get(email, set()))
        top_groups = ", ".join(sorted(email_groups.get(email, set()))[:4])
        lines.append(f"| {i} | {_escape_md_table(email)} | {count:,} | {ips} | {_escape_md_table(top_groups)} |")

    lines.extend([
        "",
        "## Summary Statistics",
        f"- Total unique emails: {total_unique:,}",
        f"- Emails appearing in auth-failure rules: {total_with_auth_fail:,}",
        f"- Emails appearing in brute-force rules: {total_with_brute_force:,}",
        f"- Emails with ≥10 appearances: {high_freq:,}",
        "",
        "## Search Parameters",
        f"- Query: `full_log` contains email pattern (`*@*.*`) OR `data.account` contains `@`",
        f"- Max documents scanned: {params.max_scanned:,}",
        f"- Page size: {page_size}",
    ])
    return _truncate_if_needed("\n".join(lines))


class WazuhDomainLookupInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    domain: str = Field(
        ...,
        max_length=253,
        description="Domain name to search for in Wazuh alerts "
                    "(e.g. 'tangerangkota.go.id', 'gmail.com').",
    )
    agent_name: ValidAgentName = Field(
        default=None,
        max_length=64,
        description=_AGENT_NAME_DESC,
    )
    since: Optional[str] = Field(
        default=None,
        max_length=30,
        description=_SINCE_DESC,
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description=_UNTIL_DESC,
    )
    limit: int = Field(
        default=500,
        description="Max alerts per page.",
        ge=1,
        le=10000,
    )
    include_full_log: bool = Field(
        default=False,
        description="Include the full_log field in results. "
                    "The full_log field can be very large (100KB+ per alert). "
                    "Set to true only when you need the raw log line context.",
    )
    cursor: Optional[str] = Field(
        default=None,
        description="Pagination cursor from previous response (next_cursor).",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="'markdown' for human readable summary, 'json' for structured data.",
    )
    keyword: ValidKeyword = Field(
        default=None,
        max_length=1024,
        description="Free-text keyword search to further narrow domain results. "
                    "Same syntax as blueteam_wazuh_indexer_search.",
    )
    max_scanned: Optional[int] = Field(
        default=None,
        ge=1000,
        le=500000,
        description="When set, auto-paginate through all matching alerts up to this limit. "
                    "Returns aggregated results (counts, top IPs, top rules) across ALL "
                    "scanned pages - no need to manually iterate with next_cursor."
                    "When None (default), returns a single page with next_cursor for"
                    "manual pagination. include_full_log is forced to False in this mode.",
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        if not v or len(v) > 253:
            raise ValueError("Invalid domain length (max 253)")
        if ".." in v:
            raise ValueError("Invalid domain format")
        v = v.strip().lower()
        if not re.match(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',
            v,
        ):
            raise ValueError(
                "Invalid domain format — must be a valid domain name (e.g. example.com)"
            )
        return v


async def _wazuh_domain_lookup_full_scan(
    params: "WazuhDomainLookupInput",
    since_str: str,
    until_str: str,
    initial_search_after: Optional[list],
) -> str:
    """Auto-paginate through all matching alerts and return an aggregated summary.

    Uses the shared ``_full_scan_paginate`` loop internally.
    """
    async def _fetch_page(ps: int, sa):
        return await _wazuh_indexer_domain_search(
            domain=params.domain,
            agent_name=params.agent_name,
            size=ps,
            search_after=sa,
            since=since_str,
            until=until_str,
            include_full_log=False,
            keyword=params.keyword,
        )

    result = await _full_scan_paginate(
        params.max_scanned, _fetch_page, initial_search_after, redact=True,
    )
    if result.get("_error"):
        return json.dumps({"error": result["_error"]}, indent=2)

    total_scanned = result["total_scanned"]
    pages = result["pages"]
    exhausted = result["exhausted"]
    global_total_val = result["total_val"]
    global_total_relation = result["total_relation"]
    all_docs = result["all_docs"]
    sample_docs = result["sample_docs"]

    # Accumulate counters from all scanned docs
    global_srcip_counter: Counter[str] = Counter()
    global_rule_group_counter: Counter[str] = Counter()
    global_rule_counter: Counter[str] = Counter()
    for doc in all_docs:
        ip = (doc.get("data") or {}).get("srcip", "")
        if ip:
            global_srcip_counter[ip] += 1
        rule = doc.get("rule") or {}
        for g in rule.get("groups", []):
            global_rule_group_counter[g] += 1
        rule_id = rule.get("id", "")
        rule_desc = rule.get("description", "")
        if rule_id:
            global_rule_counter[f"{rule_id}: {rule_desc}"] += 1

    coverage = "complete" if exhausted else "partial"
    total_display = (
        f"{global_total_val or 0:,}"
        + ("+" if global_total_relation == "gte" else "")
    )

    if params.response_format == "json":
        output = {
            "domain": params.domain,
            "mode": "full_scan",
            "total": {"value": global_total_val, "relation": global_total_relation},
            "scanned": total_scanned,
            "pages": pages,
            "coverage": coverage,
            "timezone": "UTC",
            "since": since_str,
            "until": until_str,
            "agent": params.agent_name or "all agents",
            "aggregations": {
                "top_srcips": [
                    {"ip": ip, "count": c}
                    for ip, c in global_srcip_counter.most_common(30)
                ],
                "top_rule_groups": [
                    {"group": g, "count": c}
                    for g, c in global_rule_group_counter.most_common(30)
                ],
                "top_rules": [
                    {"rule": r, "count": c}
                    for r, c in global_rule_counter.most_common(20)
                ],
            },
            "sample_alerts": sample_docs,
        }
        return _truncate_if_needed(json.dumps(output, indent=2, ensure_ascii=False))

    #Markdown output
    lines: list[str] = [
        f"#Wazuh Domain Lookup - {params.domain} (Full Scan)",
        "",
        f"**Total matches in indexer**: {total_display}",
        f"**Scanned**: {total_scanned:,} docs across {pages} page(s)",
        f"**Coverage**: {coverage} "
        + ("(all matching alerts retrieved)" if coverage == "complete"
           else f"(hit max_scanned={params.max_scanned:,} limit)"),
        f"**Time window**: {since_str} to {until_str}",
        f"**Agent**: {params.agent_name or 'all agents'}",
        "",
    ]

    if global_srcip_counter:
        lines.append("## Top Source IPs (global)")
        lines.append("| IP | Alert Count |")
        lines.append("|----|-------------|")
        for ip, c in global_srcip_counter.most_common(20):
            lines.append(f"| {_escape_md_table(ip)} | {c:,} |")
        lines.append("")

    if global_rule_group_counter:
        lines.append("## Top Rule Groups (global)")
        lines.append("| Group | Count |")
        lines.append("|-------|-------|")
        for g, c in global_rule_group_counter.most_common(15):
            lines.append(f"| {_escape_md_table(g)} | {c:,} |")
        lines.append("")

    if global_rule_counter:
        lines.append("## Top Rules (global)")
        lines.append("| Rule | Count |")
        lines.append("|------|-------|")
        for r, c in global_rule_counter.most_common(15):
            lines.append(f"| {_escape_md_table(r)} | {c:,} |")
        lines.append("")

    if sample_docs:
        lines.append("## Sample Alerts (first 50 from page 1)")
        lines.append("")
        lines.append("| Time (UTC) | Agent | Rule | Level | Src IP | Account |")
        lines.append("|------------|-------|------|-------|--------|---------|")
        for doc in sample_docs[:20]:
            ts = (doc.get("@timestamp") or "")[:19]
            agent = (doc.get("agent") or {}).get("name", "-")
            rule = doc.get("rule") or {}
            rule_str = f"{rule.get('id', '-')}: {rule.get('description', '-')}"
            level = rule.get("level", "-")
            ip = (doc.get("data") or {}).get("srcip", "-")
            account = (doc.get("data") or {}).get("account", "-")
            lines.append(
                f"| {ts} | {_escape_md_table(agent)} | {_escape_md_table(rule_str)} "
                f"| {level} | {_escape_md_table(ip)} | {_escape_md_table(account)} |"
            )
        lines.append("")

    if coverage != "complete":
        lines.append(
            f"\n**Note:** Results are partial — scan hit the "
            f"`max_scanned={params.max_scanned:,}` limit. "
            f"Increase `max_scanned` (up to 500,000) for full coverage."
        )

    return _truncate_if_needed("\n".join(lines))


@mcp.tool(
    name="wazuh_domain_lookup",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def wazuh_domain_lookup(params: WazuhDomainLookupInput) -> str:
    """Search Wazuh alerts for a specific domain name.

    Queries the structured ``data.domain`` field (boosted) and also searches
    ``full_log`` for the params.domain as a phrase.

    **Two modes**:

    - **Single-page** (default, ``params.max_scanned`` not set): Returns one page of
      results with a ``next_cursor``.  Call repeatedly with the params.cursor to manually
      iterate through all pages.
    - **Full-scan** (set ``params.max_scanned`` to an integer ≥1000): Auto-paginates
      internally across ALL matching pages and returns an aggregated summary
      (global top IPs, top rule groups, top rules).  Set ``params.max_scanned`` high
      enough to cover the time window — the scan stops when the indexer is
      exhausted or the ceiling is hit.

    Args:
        params.domain: Domain to search for (e.g. 'tangerangkota.go.id')
        params.agent_name: Optional agent filter
        params.since: ISO 8601 start in UTC (default: 365 days ago)
        params.until: ISO 8601 end in UTC (default: now)
        params.limit: Max alerts per page in single-page mode (1-10000, default 500)
        params.include_full_log: Include raw log lines (default false — forced false in full-scan mode)
        params.cursor: Pagination params.cursor from previous response
        params.response_format: 'markdown' or 'json'
        params.max_scanned: When set, run full-scan auto-pagination (see above)
        params.keyword: Free-text keyword to further narrow results

    Returns:
        str: Paged alert results (single-page) or aggregated summary (full-scan).

    Example usage:
        - "Search for all alerts involving tangerangkota.go.id"
        - "Get the complete picture for this params.domain over the past 12h — use full-scan"
        - "Show me who's hitting the mail server params.domain"
    """
    _audit_log("wazuh_domain_lookup", {"domain": params.domain, "since": params.since})
    since_str, until_str = _parse_time_window(params.since, params.until)

    search_after: Optional[list] = None
    if params.cursor:
        decoded = _decode_cursor(params.cursor)
        if decoded:
            search_after = decoded.get("search_after")

    # Auto pagination mode - scan ALL pages internally, return aggregate.
    if params.max_scanned is not None:
        return await _wazuh_domain_lookup_full_scan(
            params, since_str, until_str, search_after
        )

    try:
        data = await _wazuh_indexer_domain_search(
            domain=params.domain,
            agent_name=params.agent_name,
            size=params.limit,
            search_after=search_after,
            since=since_str,
            until=until_str,
            include_full_log=params.include_full_log,
            keyword=params.keyword,
        )
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        return _handle_api_error(e, context="wazuh_domain_lookup")

    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)

    hits = data.get("hits", {})
    total = hits.get("total", {})
    total_val = total.get("value", 0) if isinstance(total, dict) else total
    total_relation = total.get("relation", "eq") if isinstance(total, dict) else "eq"
    hit_list = hits.get("hits", [])
    docs = [h.get("_source", h) for h in hit_list]
    docs = _redact_alert_data(docs, bypass=False)

    # Build next cursor
    next_cursor = None
    if hit_list and len(docs) >= params.limit:
        last_sort = hit_list[-1].get("sort")
        if last_sort:
            next_cursor = _encode_cursor({"search_after": last_sort})

    # Aggregations (client-side from the returned page)
    srcip_counter: Counter[str] = Counter()
    rule_group_counter: Counter[str] = Counter()
    rule_counter: Counter[str] = Counter()
    for doc in docs:
        ip = (doc.get("data") or {}).get("srcip", "")
        if ip:
            srcip_counter[ip] += 1
        rule = doc.get("rule") or {}
        for g in rule.get("groups", []):
            rule_group_counter[g] += 1
        rule_id = rule.get("id", "")
        rule_desc = rule.get("description", "")
        if rule_id:
            rule_counter[f"{rule_id}: {rule_desc}"] += 1

    if params.response_format == "json":
        output = {
            "domain": params.domain,
            "total": {"value": total_val, "relation": total_relation},
            "count": len(docs),
            "size": params.limit,
            "next_cursor": next_cursor,
            "timezone": "UTC",
            "since": since_str,
            "until": until_str,
            "alerts": docs,
            "aggregations": {
                "top_srcips": [
                    {"ip": ip, "count": c} for ip, c in srcip_counter.most_common(20)
                ],
                "top_rule_groups": [
                    {"group": g, "count": c} for g, c in rule_group_counter.most_common(20)
                ],
                "top_rules": [
                    {"rule": r, "count": c} for r, c in rule_counter.most_common(10)
                ],
            },
        }
        return _truncate_if_needed(json.dumps(output, indent=2, ensure_ascii=False))

    # Markdown output
    total_display = f"{total_val:,}" + ("+" if total_relation == "gte" else "")
    page_info = f"Page ({len(docs)} of {total_display})"
    lines: list[str] = [
        f"# Wazuh Domain Lookup — {params.domain}",
        "",
        f"**Total matches**: {total_display}",
        f"**{page_info}**",
        f"**Time window**: {since_str} to {until_str}",
        f"**Agent**: {params.agent_name or 'all agents'}",
        "",
        "## Alerts",
        "",
        "| Time (UTC) | Agent | Rule | Level | Src IP | Account |",
        "|------------|-------|------|-------|--------|---------|",
    ]
    for doc in docs:
        ts = (doc.get("@timestamp") or "")[:19]
        agent = (doc.get("agent") or {}).get("name", "-")
        rule = doc.get("rule") or {}
        rule_str = f"{rule.get('id', '-')}: {rule.get('description', '-')}"
        level = rule.get("level", "-")
        ip = (doc.get("data") or {}).get("srcip", "-")
        account = (doc.get("data") or {}).get("account", "-")
        lines.append(f"| {ts} | {_escape_md_table(agent)} | {_escape_md_table(rule_str)} | {level} | {ip} | {_escape_md_table(account)} |")

    lines.append("")
    if srcip_counter:
        lines.append("## Top Source IPs (this page)")
        lines.append("| IP | Alert Count |")
        lines.append("|----|-------------|")
        for ip, c in srcip_counter.most_common(20):
            lines.append(f"| {_escape_md_table(ip)} | {c:,} |")
        lines.append("")

    if rule_group_counter:
        lines.append("## Top Rule Groups (this page)")
        lines.append("| Group | Count |")
        lines.append("|-------|-------|")
        for g, c in rule_group_counter.most_common(10):
            lines.append(f"| {_escape_md_table(g)} | {c:,} |")
        lines.append("")

    if next_cursor:
        lines.append(f"\n**Next params.cursor**: `{next_cursor}`")
    else:
        lines.append("\n**No more pages** - all results returned.")

    return _truncate_if_needed("\n".join(lines))


class WazuhCompromisedEmailsAnalysisInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    emails: list[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="List of email addresses to analyze "
                    "(e.g. from wazuh_email_lookup results). Max 50.",
    )
    agent_name: ValidAgentName = Field(
        default=None,
        max_length=64,
        description=_AGENT_NAME_DESC,
    )
    since: Optional[str] = Field(
        default=None,
        max_length=30,
        description=_SINCE_DESC,
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description=_UNTIL_DESC,
    )
    top_ips: int = Field(
        default=20,
        description="Number of top attacker IPs to return, ranked by alert count.",
        ge=1,
        le=100,
    )
    enrich_with_netra: bool = Field(
        default=False,
        description="If true, query Netra for each attacker IP (adds latency). "
                    "Rate limiting applies. Only top 10 IPs are enriched.",
    )
    keyword: ValidKeyword = Field(
        default=None,
        max_length=1024,
        description="Free-text keyword search to further narrow results. "
                    "Same syntax as blueteam_wazuh_indexer_search.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="_RESPONSE_FORMAT_DESC",
    )

    @field_validator("emails")
    @classmethod
    def validate_emails(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        for email in v:
            email = email.strip()
            if not email:
                continue
            if len(email) > 254:
                raise ValueError(f"Email too long: {email[:50]}...")
            if "@" not in email or ".." in email:
                raise ValueError(f"Invalid email format: {email}")
            cleaned.append(email.lower())
        if not cleaned:
            raise ValueError("At least one valid email address is required")
        return cleaned


@mcp.tool(
    name="wazuh_compromised_emails_analysis",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def wazuh_compromised_emails_analysis(params: WazuhCompromisedEmailsAnalysisInput) -> str:
    """Correlate compromised email addresses with attacker IPs from Wazuh alerts.
    Given a list of email addresses (typically sourced from ``wazuh_email_lookup``),
    queries the Wazuh Indexer for alerts mentioning any of them, extracts and ranks
    the source IPs involved, and optionally enriches the top attacker IPs through
    Netra Threat Intelligence.

    Netra enrichment is **disabled by default** because it adds latency and consumes
    Netra API quota.  Set ``enrich_with_netra=true`` to enable it (max 10 IPs
    enriched regardless of ``params.top_ips``).

    Args:
        params.emails: List of email addresses to analyze (1-50)
        params.agent_name: Optional agent filter
        params.since: ISO 8601 start (default: 365 days ago)
        params.until: ISO 8601 end (default: now)
        params.top_ips: Number of top attacker IPs to rank (1-100, default 20)
        params.enrich_with_netra: Query Netra for top IPs (default false)
        params.response_format: 'markdown' or 'json'

    Returns:
        str: Ranked attacker IP list with targeted email counts, plus per-email
        breakdown.  If params.enrich_with_netra is true, Netra threat scores are included
        for the top 10 IPs.

    Example usage:
        - "Take the top 5 params.emails from the lookup and find who's attacking them"
        - "Enrich the attacker IPs for these compromised accounts through Netra"
    """
    _audit_log("wazuh_compromised_emails_analysis", {"top_ips": params.top_ips, "since": params.since})
    since_str, until_str = _parse_time_window(params.since, params.until)

    ip_counter: Counter[str] = Counter()
    ip_to_emails: dict[str, set[str]] = {}  # IP -> set of targeted params.emails
    email_to_ips: dict[str, Counter[str]] = {}  # email -> IP counter
    email_alert_counts: Counter[str] = Counter()  # email -> total alert count
    total_scanned = 0

    # Fan out across email batches (max 25 per API call)
    batch_size = 25
    try:
        for i in range(0, len(params.emails), batch_size):
            batch = params.emails[i:i + batch_size]
            search_after: Optional[list] = None
            page_size = 1000
            batch_scanned = 0
            max_batch_scanned = 20000  # per-batch cap to prevent runaway

            while batch_scanned < max_batch_scanned:
                data = await _wazuh_indexer_multi_email_search(
                    emails=batch,
                    agent_name=params.agent_name,
                    size=page_size,
                    search_after=search_after,
                    since=since_str,
                    until=until_str,
                    keyword=params.keyword,
                )
                if "error" in data:
                    # Accumulate partial results
                    break

                hits = data.get("hits", {})
                hit_list = hits.get("hits", [])
                docs = [h.get("_source", h) for h in hit_list]
                docs = _redact_alert_data(docs, bypass=False)
                if not docs:
                    break

                for doc in docs:
                    srcip = (doc.get("data") or {}).get("srcip", "")
                    # Also extract emails from this doc for association
                    doc_emails = _extract_emails_from_doc(doc)
                    # Intersect with our target list
                    matched = doc_emails & set(params.emails)
                    if not matched:
                        continue

                    if srcip:
                        ip_counter[srcip] += 1
                        ip_to_emails.setdefault(srcip, set()).update(matched)
                        for email in matched:
                            email_to_ips.setdefault(email, Counter())[srcip] += 1
                            email_alert_counts[email] += 1

                batch_scanned += len(docs)
                total_scanned += len(docs)

                if len(docs) < page_size:
                    break
                last_sort = hit_list[-1].get("sort") if hit_list else None
                if last_sort:
                    search_after = last_sort
                else:
                    break

    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        if total_scanned == 0:
            return _handle_api_error(e, context="wazuh_compromised_emails_analysis")
        logging.getLogger(__name__).warning(
            "wazuh_compromised_emails_analysis: error after %d docs: %s", total_scanned, e
        )

    top_ips = ip_counter.most_common(params.top_ips)

    # Netra enrichment for top IPs (max 10)
    netra_results: dict[str, dict] = {}
    if params.enrich_with_netra:
        enrich_count = min(len(top_ips), 10)
        for ip, _ in top_ips[:enrich_count]:
            try:
                raw = await _netra_request(f"/analysis/{ip}")
                data = raw.get("data", {})
                results = data.get("results", {})
                ts = results.get("threat_score", {})
                ai = results.get("ai_insight", {})
                vt = results.get("virustotal", {})
                ab = results.get("abuseipdb", {})
                geo = results.get("ipapi", {})
                netra_results[ip] = {
                    "threat_score": ts.get("score"),
                    "threat_level": ts.get("level"),
                    "breakdown": ts.get("breakdown"),
                    "ai_assessment": ai.get("assessment"),
                    "ai_confidence": ai.get("confidence"),
                    "virustotal_malicious": vt.get("malicious"),
                    "virustotal_total": vt.get("total"),
                    "abuseipdb_confidence": ab.get("abuseConfidenceScore"),
                    "abuseipdb_total_reports": ab.get("totalReports"),
                    "country": (geo.get("location") or {}).get("country"),
                    "country_name": geo.get("country_name"),
                    "isp": geo.get("isp"),
                }
                # Rate limit : 1s delay between Netra calls
                await asyncio.sleep(1)
            except (httpx.HTTPStatusError, httpx.TimeoutException, Exception) as e:
                netra_results[ip] = {"error": str(e)}

    if params.response_format == "json":
        attacker_ips = []
        for ip, count in top_ips:
            entry: dict = {
                "ip": ip,
                "alert_count": count,
                "targeted_emails": sorted(ip_to_emails.get(ip, set())),
                "targeted_email_count": len(ip_to_emails.get(ip, set())),
            }
            if ip in netra_results:
                entry["netra"] = netra_results[ip]
            attacker_ips.append(entry)

        per_email: dict[str, dict] = {}
        for email in params.emails:
            ips_for_email = email_to_ips.get(email, Counter())
            per_email[email] = {
                "total_alerts": email_alert_counts.get(email, 0),
                "attacker_ips": [
                    {"ip": ip, "count": c}
                    for ip, c in ips_for_email.most_common(20)
                ],
            }

        output = {
            "emails_analyzed": params.emails,
            "total_alerts_scanned": total_scanned,
            "top_attacker_ips": attacker_ips,
            "per_email": per_email,
            "enrichment_enabled": params.enrich_with_netra,
            "time_window": {"since": since_str, "until": until_str},
        }
        return _truncate_if_needed(json.dumps(output, indent=2, ensure_ascii=False))

    # Markdown output
    lines: list[str] = [
        "# Compromised Email Analysis",
        "",
        f"**Time window**: {since_str} to {until_str}",
        f"**Emails analyzed**: {len(params.emails)}",
        f"**Agent**: {params.agent_name or 'all agents'}",
        f"**Alerts scanned**: {total_scanned:,}",
        "",
        "## Top Attacker IPs",
        "",
    ]
    if params.enrich_with_netra:
        lines.append(
            "| # | IP | Alert Count | Targeted Emails | Netra Score | Netra Level | Country |"
        )
        lines.append(
            "|---|----|------------|-----------------|-------------|-------------|---------|"
        )
        for i, (ip, count) in enumerate(top_ips, 1):
            targeted = len(ip_to_emails.get(ip, set()))
            nr = netra_results.get(ip, {})
            score = nr.get("threat_score", "-")
            level = nr.get("threat_level", "-")
            country = nr.get("country_name") or nr.get("country") or "-"
            lines.append(
                f"| {i} | {_escape_md_table(ip)} | {count:,} | {targeted} | {score} | {_escape_md_table(str(level))} | {_escape_md_table(str(country))} |"
            )
    else:
        lines.append(
            "| # | IP | Alert Count | Targeted Emails |"
        )
        lines.append(
            "|---|----|------------|-----------------|"
        )
        for i, (ip, count) in enumerate(top_ips, 1):
            targeted = len(ip_to_emails.get(ip, set()))
            lines.append(f"| {i} | {_escape_md_table(ip)} | {count:,} | {targeted} |")

    lines.append("")
    lines.append("## Per-Email Summary")
    lines.append("")
    for email in params.emails:
        alert_count = email_alert_counts.get(email, 0)
        lines.append(f"### {email} ({alert_count:,} alerts)")
        ips_for_email = email_to_ips.get(email, Counter())
        if ips_for_email:
            lines.append("| IP | Count | Netra Level |")
            lines.append("|----|-------|-------------|")
            for ip, c in ips_for_email.most_common(10):
                level = (netra_results.get(ip) or {}).get("threat_level", "-")
                lines.append(f"| {_escape_md_table(ip)} | {c:,} | {_escape_md_table(str(level))} |")
        else:
            lines.append("_No attacker IPs found for this email._")
        lines.append("")

    if params.enrich_with_netra and netra_results:
        lines.append("## Netra Enrichment (top attacker IPs)")
        lines.append("")
        for ip, nr in netra_results.items():
            if "error" in nr:
                lines.append(f"### {ip} — Error: {nr['error']}")
                continue
            score = nr.get("threat_score", "-")
            level = nr.get("threat_level", "-")
            ai = nr.get("ai_assessment") or "No AI assessment available"
            vt = f"{nr.get('virustotal_malicious', '-')}/{nr.get('virustotal_total', '-')}"
            ab = (
                f"Confidence {nr.get('abuseipdb_confidence', '-')}%, "
                f"{nr.get('abuseipdb_total_reports', '-')} reports"
            )
            country = nr.get("country_name") or nr.get("country") or "-"
            isp = nr.get("isp") or "-"
            lines.append(f"### {ip} — Threat Level: {level} (Score: {score}/100)")
            lines.append(f"- **AI Assessment**: {ai}")
            lines.append(f"- **VirusTotal**: {vt} malicious")
            lines.append(f"- **AbuseIPDB**: {ab}")
            lines.append(f"- **Country**: {country}   |   **ISP**: {isp}")
            lines.append("")
    elif params.enrich_with_netra and not netra_results:
        lines.append("## Netra Enrichment")
        lines.append("")
        lines.append(
            "_Netra enrichment was enabled but no results were obtained. "
            "Check that NETRA_API_KEY is set._"
        )
    else:
        lines.append(
            "_Netra enrichment was disabled. Set `enrich_with_netra=true` to enable "
            "threat intelligence enrichment for attacker IPs._"
        )

    return _truncate_if_needed("\n".join(lines))


# Dynamic Time Based Alert Analysis
def _auto_bucket_interval(window_duration_minutes: float) -> str:
    """Pick a reasonable date_histogram bucket interval for a given time window.

    Targets ~60-120 buckets for readability.  Returns an OpenSearch
    ``fixed_interval`` value (e.g. ``"1m"``, ``"15m"``, ``"1h"``, ``"1d"``).
    """
    target_buckets = 100
    raw_minutes = window_duration_minutes / target_buckets
    if raw_minutes <= 1:
        return "1m"
    elif raw_minutes <= 5:
        return "5m"
    elif raw_minutes <= 15:
        return "15m"
    elif raw_minutes <= 60:
        return "1h"
    elif raw_minutes <= 360:
        return "6h"
    else:
        return "1d"


def _duration_minutes(since: str, until: str) -> float:
    """Return the duration in minutes between two ISO 8601 timestamps."""
    try:
        s = datetime.fromisoformat(params.since.replace("Z", "+00:00").rstrip("Z"))
        u = datetime.fromisoformat(params.until.replace("Z", "+00:00").rstrip("Z"))
        return (u - s).total_seconds() / 60.0
    except Exception:
        return 60.0  # fallback 1h


class WazuhAlertTimelineInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    since: str = Field(
        default="1h",
        max_length=30,
        description="Start of time window — ISO 8601 ('2026-07-07T00:00:00Z') or relative "
                    "('5m', '1h', '24h', '7d', '30d'). Default: '1h'.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window — ISO 8601 or relative. Defaults to now.",
    )
    bucket: str = Field(
        default="auto",
        max_length=10,
        description="Bucket size: '1m', '5m', '15m', '1h', '6h', '1d', or 'auto'. "
                    "'auto' picks based on window: ≤1h→1m, ≤24h→15m, ≤7d→1h, ≤30d→6h, ≤365d→1d.",
    )
    agent_name: ValidAgentName = Field(
        default=None,
        max_length=64,
        description=_AGENT_NAME_DESC,
    )
    rule_groups: ValidRuleGroups = Field(
        default=None,
        max_length=1024,
        description="Comma-separated rule groups to filter by (e.g. 'brute_force,authentication_failed').",
    )
    rule_level_min: Optional[int] = Field(
        default=None,
        ge=1,
        le=16,
        description="Minimum rule level (e.g., 8 for medium+ severity).",
    )
    keyword: ValidKeyword = Field(
        default=None,
        max_length=1024,
        description="Free-text keyword search to narrow the timeline. Same syntax as "
                    "blueteam_wazuh_indexer_search — supports +term, -term, OR, *wildcard*, "
                    '\"exact phrase\". Example: \'gambling OR "brute force"\'',
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="'markdown' for human-readable timeline, 'json' for structured bucket data.",
    )
    bypass_redaction: bool = Field(
        default=False, description=_BYPASS_REDACTION_DESC,
    )


    @field_validator("bucket")
    @classmethod
    def validate_bucket(cls, v: str) -> str:
        v = v.strip().lower()
        if v == "auto":
            return v
        if not re.match(r"^(\d+[smhd]|auto)$", v):
            raise ValueError("bucket: use 'auto', '1m', '5m', '15m', '1h', '6h', or '1d'")
        return v



@mcp.tool(
    name="wazuh_alert_timeline",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def wazuh_alert_timeline(params: WazuhAlertTimelineInput) -> str:
    """Return a time-bucketed breakdown of Wazuh alerts using OpenSearch date_histogram.

    Instead of fetching individual alert documents, this tool asks the Indexer to
    params.bucket alert counts by time interval (per minute, per 15 minutes, per hour, etc.)
    directly on the server — fast, even across millions of documents.

    Each params.bucket includes:
    - Total alert count
    - Count by severity band (low ≤4, medium 5-9, high ≥10)
    - Top rules, top source IPs, and top agents within that params.bucket

    Args:
        params.since: Start of time window (default '1h').  Accepts ISO 8601 or relative
                     expressions ('5m', '1h', '24h', '7d', '30d').
        params.until: End of time window.  Defaults to now.
        params.bucket: Bucket size — '1m', '5m', '15m', '1h', '6h', '1d', or 'auto'.
        params.agent_name: Optional agent filter.
        params.rule_groups: Optional comma-separated rule groups filter.
        params.rule_level_min: Only count alerts at or above this severity.
        params.keyword: Optional free-text keyword filter (e.g. 'gambling OR "brute force"').
        params.response_format: 'markdown' or 'json'.

    Returns:
        str: Timeline table with per-params.bucket counts, severity bands, and top indicators.

    Example usage:
        - "Show me the alert timeline for the last hour"
        - "Break down yesterday's brute force alerts by 15-minute intervals"
        - "What's the attack volume trend over the last 7 days?"
    """
    _audit_log("wazuh_alert_timeline", {"since": params.since, "bucket": params.bucket})
    since_str, until_str = _parse_time_window(params.since, params.until)

    # Determine bucket interval
    if params.bucket == "auto":
        dur = _duration_minutes(since_str, until_str)
        bucket_interval = _auto_bucket_interval(dur)
    else:
        bucket_interval = params.bucket

    rule_group_list: Optional[list[str]] = None
    if params.rule_groups:
        rule_group_list = [g.strip() for g in params.rule_groups.split(",") if g.strip()]

    try:
        data = await _wazuh_indexer_aggregate(
            bucket_interval=bucket_interval,
            since=since_str,
            until=until_str,
            agent_name=params.agent_name,
            rule_groups=rule_group_list,
            rule_level_min=params.rule_level_min,
            keyword=params.keyword,
            geo_country=params.geo_country if hasattr(params, 'geo_country') else None,
        )
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        return _handle_api_error(e, context="wazuh_alert_timeline")

    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)

    aggs = data.get("aggregations", {})
    timeline = aggs.get("alerts_over_time", {})
    buckets = timeline.get("buckets", [])

    if not buckets:
        return (
            "# Alert Timeline — No Data\n\n"
            f"**Window**: {since_str} → {until_str}\n"
            f"**Bucket**: {bucket_interval}\n\n"
            "_No alerts matched the query in this time window._"
        )

    total_alerts = sum(b.get("doc_count", 0) for b in buckets)

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({
            "window": {"since": since_str, "until": until_str},
            "bucket_interval": bucket_interval,
            "total_buckets": len(buckets),
            "total_alerts": total_alerts,
            "buckets": [
                {
                    "key": b.get("key_as_string", b.get("key", "")),
                    "doc_count": b.get("doc_count", 0),
                    "by_level": {
                        r.get("key", ""): r.get("doc_count", 0)
                        for r in (b.get("by_level", {}) or {}).get("buckets", [])
                    },
                    "top_rules": [
                        {"key": r.get("key", ""), "count": r.get("doc_count", 0)}
                        for r in (b.get("top_rules", {}) or {}).get("buckets", [])
                    ],
                    "top_srcips": [
                        {"key": r.get("key", ""), "count": r.get("doc_count", 0)}
                        for r in (b.get("top_srcips", {}) or {}).get("buckets", [])
                    ],
                    "top_agents": [
                        {"key": r.get("key", ""), "count": r.get("doc_count", 0)}
                        for r in (b.get("top_agents", {}) or {}).get("buckets", [])
                    ],
                }
                for b in buckets
            ],
        }, indent=2, ensure_ascii=False))

    # Markdown
    dur_str = f"{_duration_minutes(since_str, until_str):.0f} min" if _duration_minutes(since_str, until_str) < 120 else f"{_duration_minutes(since_str, until_str) / 60:.1f}h"
    lines: list[str] = [
        f"# Alert Timeline — Last {dur_str}",
        f"**Window**: {since_str} → {until_str}  |  **Bucket**: {bucket_interval}  |  **Total alerts**: {total_alerts:,}",
        "",
        "| Time (UTC) | Total | Low (≤4) | Med (5-9) | High (≥10) | Top Rule | Top Src IP |",
        "|------------|-------|----------|-----------|------------|----------|-----------|",
    ]

    for b in buckets:
        key = b.get("key_as_string", b.get("key", ""))
        ts = key[:16] if len(key) >= 16 else key  # e.g. "2026-07-07T18:00"
        total = b.get("doc_count", 0)
        by_level = {}
        for lv in (b.get("by_level", {}) or {}).get("buckets", []):
            by_level[lv.get("key", "")] = lv.get("doc_count", 0)
        low = by_level.get("low", 0)
        med = by_level.get("medium", 0)
        high = by_level.get("high", 0)
        top_rules = [
            r.get("key", "")[:30]
            for r in ((b.get("top_rules") or {}).get("buckets") or [])
        ]
        top_rule = top_rules[0] if top_rules else "-"
        top_srcips = [
            r.get("key", "")
            for r in ((b.get("top_srcips") or {}).get("buckets") or [])
        ]
        top_ip = top_srcips[0] if top_srcips else "-"
        lines.append(f"| {ts} | {total} | {low} | {med} | {high} | {_escape_md_table(top_rule)} | {_escape_md_table(top_ip)} |")

    # Peak analysis
    peak = max(buckets, key=lambda b: b.get("doc_count", 0)) if buckets else None
    quiet = min(buckets, key=lambda b: b.get("doc_count", 0)) if buckets else None

    lines.append("")
    lines.append("## Peak Activity")
    if peak:
        peak_key = peak.get("key_as_string", peak.get("key", ""))[:16]
        peak_count = peak.get("doc_count", 0)
        lines.append(f"- **Peak**: {peak_key} — {peak_count:,} alerts")
    if quiet:
        quiet_key = quiet.get("key_as_string", quiet.get("key", ""))[:16]
        quiet_count = quiet.get("doc_count", 0)
        lines.append(f"- **Quietest**: {quiet_key} — {quiet_count:,} alerts")

    # Per severity totals
    all_low = sum(
        next((r.get("doc_count", 0) for r in (b.get("by_level", {}) or {}).get("buckets", []) if r.get("key") == "low"), 0)
        for b in buckets
    )
    all_med = sum(
        next((r.get("doc_count", 0) for r in (b.get("by_level", {}) or {}).get("buckets", []) if r.get("key") == "medium"), 0)
        for b in buckets
    )
    all_high = sum(
        next((r.get("doc_count", 0) for r in (b.get("by_level", {}) or {}).get("buckets", []) if r.get("key") == "high"), 0)
        for b in buckets
    )
    lines.extend([
        "",
        "## Severity Summary",
        f"- Low (≤4): {all_low:,} ({all_low / max(total_alerts, 1) * 100:.0f}%)",
        f"- Medium (5-9): {all_med:,} ({all_med / max(total_alerts, 1) * 100:.0f}%)",
        f"- High (≥10): {all_high:,} ({all_high / max(total_alerts, 1) * 100:.0f}%)",
        "",
        "## Query Parameters",
        f"- Since: `{params.since}`",
        f"- Bucket: `{bucket_interval}`",
        f"- Agent: {params.agent_name or 'all'}",
        f"- Rule groups: {params.rule_groups or 'all'}",
        f"- Min level: {params.rule_level_min or 'none'}",
    ])

    return _truncate_if_needed("\n".join(lines))


class WazuhAttackVelocityInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    window: str = Field(
        default="1h",
        max_length=10,
        description="Window size for comparison — relative expression: '15m', '1h', '6h', '24h'. "
                    "'1h' compares the last hour against the hour before that.",
    )
    agent_name: ValidAgentName = Field(
        default=None,
        max_length=64,
        description=_AGENT_NAME_DESC,
    )
    rule_groups: ValidRuleGroups = Field(
        default=None,
        max_length=1024,
        description="Comma-separated rule groups to filter by.",
    )
    bucket: str = Field(
        default="auto",
        max_length=10,
        description="Bucket size within each window: '1m', '5m', '15m', '1h', or 'auto'.",
    )
    keyword: ValidKeyword = Field(
        default=None,
        max_length=1024,
        description="Free-text keyword search to narrow the analysis. Same syntax as "
                    "blueteam_wazuh_indexer_search.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="_RESPONSE_FORMAT_DESC",
    )
    bypass_redaction: bool = Field(
        default=False, description=_BYPASS_REDACTION_DESC,
    )


    @field_validator("window")
    @classmethod
    def validate_window(cls, v: str) -> str:
        if not _RELATIVE_TIME_RE.match(v.strip()):
            raise ValueError(
                "window must be a relative expression: '15m', '1h', '6h', '24h', '7d'"
            )
        return v.strip()




@mcp.tool(
    name="wazuh_attack_velocity",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def wazuh_attack_velocity(params: WazuhAttackVelocityInput = WazuhAttackVelocityInput()) -> str:
    """Compare two adjacent time windows to detect attack acceleration or deceleration.

    Queries the Wazuh Indexer for two adjacent windows of equal duration (current
    and previous), computes per-bucket deltas, and scores the overall trend:
    **accelerating** (>+25%), **steady** (−25% to +25%), or **decelerating** (<−25%).

    Also reports the top accelerating rules and source IPs across the two windows.

    Args:
        params.window: Window size — relative expression like '15m', '1h', '6h', '24h'.
                      '1h' compares the last hour against the hour before it.
        params.agent_name: Optional agent filter.
        params.rule_groups: Optional comma-separated rule groups filter.
        params.bucket: Bucket granularity within each params.window. 'auto' picks based on
                      params.window size.
        params.response_format: 'markdown' or 'json'.

    Returns:
        str: Velocity report with trend classification, per-bucket comparison table,
        and top accelerating rules / source IPs.

    Example usage:
        - "Is the brute force attack on the mail server speeding up?"
        - "Compare the last hour's alert volume to the previous hour"
    """
    _audit_log("wazuh_attack_velocity", {"window": params.window})
    window_str = params.window
    m = _RELATIVE_TIME_RE.match(window_str)
    n, unit = int(m.group(1)), m.group(2)
    window_delta = _relative_delta(n, unit)

    now = datetime.utcnow()
    current_start = now - window_delta
    previous_start = current_start - window_delta

    fmt = "%Y-%m-%dT%H:%M:%SZ"
    current_since = current_start.strftime(fmt)
    current_until = now.strftime(fmt)
    previous_since = previous_start.strftime(fmt)
    previous_until = current_start.strftime(fmt)

    # Determine bucket interval
    dur_min = window_delta.total_seconds() / 60.0
    if params.bucket == "auto":
        bucket_interval = _auto_bucket_interval(dur_min)
    else:
        bucket_interval = params.bucket

    rule_group_list: Optional[list[str]] = None
    if params.rule_groups:
        rule_group_list = [g.strip() for g in params.rule_groups.split(",") if g.strip()]

    # Query both windows
    try:
        current_data, previous_data = await asyncio.gather(
            _wazuh_indexer_aggregate(
                bucket_interval=bucket_interval,
                since=current_since,
                until=current_until,
                agent_name=params.agent_name,
                rule_groups=rule_group_list,
                keyword=params.keyword,
                geo_country=params.geo_country if hasattr(params, 'geo_country') else None,
            ),
            _wazuh_indexer_aggregate(
                bucket_interval=bucket_interval,
                since=previous_since,
                until=previous_until,
                agent_name=params.agent_name,
                rule_groups=rule_group_list,
                keyword=params.keyword,
                geo_country=params.geo_country if hasattr(params, 'geo_country') else None,
            ),
        )
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        return _handle_api_error(e, context="wazuh_attack_velocity")

    if isinstance(current_data.get("error"), str):
        return json.dumps(current_data, indent=2)
    if isinstance(previous_data.get("error"), str):
        return json.dumps(previous_data, indent=2)

    current_buckets = (
        current_data.get("aggregations", {})
        .get("alerts_over_time", {})
        .get("buckets", [])
    )
    previous_buckets = (
        previous_data.get("aggregations", {})
        .get("alerts_over_time", {})
        .get("buckets", [])
    )

    total_current = sum(b.get("doc_count", 0) for b in current_buckets)
    total_previous = sum(b.get("doc_count", 0) for b in previous_buckets)

    if total_previous > 0:
        velocity_pct = (total_current - total_previous) / total_previous * 100
    elif total_current > 0:
        velocity_pct = 100.0  # new attack pattern
    else:
        velocity_pct = 0.0

    if velocity_pct > 25:
        trend = "accelerating"
        trend_icon = "🔺"
    elif velocity_pct < -25:
        trend = "decelerating"
        trend_icon = "🔻"
    else:
        trend = "steady"
        trend_icon = "➖"

    # Align buckets by position
    max_buckets = max(len(current_buckets), len(previous_buckets))
    bucket_rows: list[dict] = []
    for i in range(max_buckets):
        cur = current_buckets[i].get("doc_count", 0) if i < len(current_buckets) else 0
        prev = previous_buckets[i].get("doc_count", 0) if i < len(previous_buckets) else 0
        delta = cur - prev
        d_trend = "🔺" if delta > 5 else ("🔻" if delta < -5 else "—")
        cb = current_buckets[i] if i < len(current_buckets) else {}
        ts = (cb.get("key_as_string", cb.get("key", "")))[:16] if i < len(current_buckets) else "—"
        bucket_rows.append({
            "timestamp": ts,
            "previous": prev,
            "current": cur,
            "delta": delta,
            "trend": d_trend,
        })

    if params.response_format == "json":
        output = {
            "velocity_pct": round(velocity_pct, 1),
            "trend": trend,
            "windows": {
                "current": {"since": current_since, "until": current_until, "total": total_current},
                "previous": {"since": previous_since, "until": previous_until, "total": total_previous},
            },
            "bucket_interval": bucket_interval,
            "buckets": bucket_rows,
        }
        return _truncate_if_needed(json.dumps(output, indent=2, ensure_ascii=False))

    # Markdown
    lines: list[str] = [
        f"# Attack Velocity — Last {window_str} vs Previous {window_str}",
        "",
        f"**Current params.window**: {current_since} → {current_until}  ({total_current:,} alerts)",
        f"**Previous params.window**: {previous_since} → {previous_until}  ({total_previous:,} alerts)",
        f"**Velocity**: {trend_icon} {velocity_pct:+.0f}% — **{trend}**",
        "",
        "| Bucket | Prev | Current | Delta | Trend |",
        "|--------|------|---------|-------|-------|",
    ]
    for r in bucket_rows[:50]:  # cap at 50 rows for readability
        lines.append(
            f"| {_escape_md_table(r['timestamp'])} | {r['previous']} | {r['current']} | "
            f"{r['delta']:+d} | {r['trend']} |"
        )

    # Per-severity velocity
    def severity_counts(buckets: list[dict], key: str) -> int:
        return sum(
            next(
                (lv.get("doc_count", 0)
                 for lv in (b.get("by_level", {}) or {}).get("buckets", [])
                 if lv.get("key") == key),
                0,
            )
            for b in buckets
        )

    lines.append("")
    lines.append("## Severity Velocity")
    for sev_key, sev_label in [("high", "High (≥10)"), ("medium", "Medium (5-9)"), ("low", "Low (≤4)")]:
        c_val = severity_counts(current_buckets, sev_key)
        p_val = severity_counts(previous_buckets, sev_key)
        sev_vel = (c_val - p_val) / max(p_val, 1) * 100 if p_val > 0 else (100 if c_val > 0 else 0)
        sev_icon = "🔺" if sev_vel > 25 else ("🔻" if sev_vel < -25 else "➖")
        lines.append(f"- {sev_label}: {p_val} → {c_val} ({sev_icon} {sev_vel:+.0f}%)")

    lines.extend([
        "",
        "## Query Parameters",
        f"- Window: `{params.window}`",
        f"- Bucket: `{bucket_interval}`",
        f"- Agent: {params.agent_name or 'all'}",
        f"- Rule groups: {params.rule_groups or 'all'}",
    ])

    return _truncate_if_needed("\n".join(lines))


# THREAT INTELLIGENCE
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[\da-fA-F:]+$")

@mcp.tool(
    name="blueteam_lookup_ip_abuseipdb",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_lookup_ip_abuseipdb(ip: ValidPublicIp, max_age_days: int = 90, response_format: Literal["markdown", "json"] = "markdown") -> str:
    """Check an IP address against AbuseIPDB for known malicious activity reports.
    Requires ABUSEIPDB_API_KEY environment variable.

    Args:
        ip: IP address to check
        max_age_days: Lookback window in days
        response_format: 'markdown' (default) or 'json'

    Returns:
        str: Markdown report (default) or JSON with abuse confidence score, report count, etc.
    """
    _audit_log("blueteam_lookup_ip_abuseipdb", {"ip": ip})
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
            params={"ipAddress": ip, "maxAgeInDays": str(max_age_days), "verbose": ""}
        )
        d = data.get("data", {})
        result = {
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
        }
        if response_format == "json":
            return json.dumps(result, indent=2)
        # markdown
        score = result["abuse_confidence_score"] or 0
        severity = "🔴 Malicious" if score >= 80 else ("🟠 Suspicious" if score >= 40 else "🟢 Clean")
        lines = [
            f"# AbuseIPDB — {result['ip']}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Confidence Score** | {score}% — {severity} |",
            f"| **Total Reports** | {result['total_reports']} |",
            f"| **Last Reported** | {result['last_reported'] or 'N/A'} |",
            f"| **Country** | {result['country'] or 'N/A'} |",
            f"| **ISP** | {result['isp'] or 'N/A'} |",
            f"| **Usage Type** | {result['usage_type'] or 'N/A'} |",
            f"| **Domain** | {result['domain'] or 'N/A'} |",
            f"| **Tor Exit Node** | {result['is_tor']} |",
            f"| **VPN/Public** | {result['is_vpn']} |",
        ]
        return "\n".join(lines)
    except (httpx.HTTPStatusError, httpx.TimeoutException, Exception) as e:
        return _handle_api_error(e, context="blueteam_lookup_ip_abuseipdb")


_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")

@mcp.tool(
    name="blueteam_lookup_hash_virustotal",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_lookup_hash_virustotal(hash: str, response_format: Literal["markdown", "json"] = "markdown") -> str:
    """Check a file hash against VirusTotal to see if it's known malware.
    Requires VIRUSTOTAL_API_KEY environment variable.

    Args:
        hash_value: MD5/SHA1/SHA256 of the file
        response_format: 'markdown' (default) or 'json'

    Returns:
        str: Markdown report (default) or JSON with detection ratio, malware names
    """
    _audit_log("blueteam_lookup_hash_virustotal", {"hash": hash_value[:8] + "..."})
    if not VIRUSTOTAL_API_KEY:
        return json.dumps({
            "error": "VIRUSTOTAL_API_KEY not set",
            "fix": "Set environment variable: export VIRUSTOTAL_API_KEY=your_key_here",
            "get_key": "https://www.virustotal.com/gui/my-apikey"
        })
    try:
        data = await _http_get(
            f"https://www.virustotal.com/api/v3/files/{hash_value}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}
        )
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})
        detections = {
            engine: r["result"]
            for engine, r in results.items()
            if r.get("category") == "malicious"
        }
        detection_ratio = f"{stats.get('malicious', 0)}/{sum(stats.values())}"
        result = {
            "hash": hash_value,
            "name": attrs.get("meaningful_name"),
            "type": attrs.get("type_description"),
            "size_bytes": attrs.get("size"),
            "first_seen": attrs.get("first_submission_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "detections": detection_ratio,
            "malware_names": detections,
        }
        if response_format == "json":
            return json.dumps(result, indent=2)
        # markdown
        malicious = stats.get("malicious", 0)
        severity = "🔴 Malicious" if malicious > 0 else "🟢 Clean"
        lines = [
            f"# VirusTotal Hash Lookup — `{hash_value}`",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **File Name** | {result['name'] or 'N/A'} |",
            f"| **Type** | {result['type'] or 'N/A'} |",
            f"| **Size** | {result['size_bytes'] or 'N/A'} bytes |",
            f"| **Detections** | {detection_ratio} — {severity} |",
            f"| **First Seen** | {result['first_seen'] or 'N/A'} |",
            f"| **Last Analysis** | {result['last_analysis_date'] or 'N/A'} |",
        ]
        if detections:
            lines.append("")
            lines.append("## Detected Malware Names")
            for engine, name in sorted(detections.items()):
                lines.append(f"- **{engine}**: {name}")
        return "\n".join(lines)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return json.dumps({"result": "Not found in VirusTotal — hash is unknown or clean"})
        return _handle_api_error(e, context="blueteam_lookup_hash_virustotal")
    except (httpx.TimeoutException, Exception) as e:
        return _handle_api_error(e, context="blueteam_lookup_hash_virustotal")


@mcp.tool(
    name="blueteam_lookup_domain_virustotal",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_lookup_domain_virustotal(domain: str, response_format: Literal["markdown", "json"] = "markdown") -> str:
    """Check a domain against VirusTotal for malicious reputation.

    Args:
        domain: Domain to check
        response_format: 'markdown' (default) or 'json'

    Returns:
        str: Markdown report (default) or JSON with reputation score and detection details
    """
    _audit_log("blueteam_lookup_domain_virustotal", {"domain": domain})
    if not VIRUSTOTAL_API_KEY:
        return json.dumps({"error": "VIRUSTOTAL_API_KEY not set. See blueteam_lookup_hash_virustotal for setup."})
    try:
        data = await _http_get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}
        )
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        detection_ratio = f"{stats.get('malicious', 0)}/{sum(stats.values())}"
        result = {
            "domain": domain,
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories", {}),
            "detections": detection_ratio,
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "whois": (attrs.get("whois", "") or "")[:500],
        }
        if response_format == "json":
            return json.dumps(result, indent=2)
        # markdown
        malicious = stats.get("malicious", 0)
        severity = "🔴 Malicious" if malicious > 0 else ("🟠 Suspicious" if (attrs.get("reputation") or 0) < 0 else "🟢 Clean")
        lines = [
            f"# VirusTotal Domain Lookup — `{domain}`",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Reputation** | {result['reputation']} |",
            f"| **Detections** | {detection_ratio} — {severity} |",
            f"| **Registrar** | {result['registrar'] or 'N/A'} |",
            f"| **Creation Date** | {result['creation_date'] or 'N/A'} |",
        ]
        cats = result.get("categories") or {}
        if cats:
            lines.append("")
            lines.append("## Categories")
            for engine, cat in sorted(cats.items()):
                lines.append(f"- **{engine}**: {cat}")
        return "\n".join(lines)
    except (httpx.HTTPStatusError, httpx.TimeoutException, Exception) as e:
        return _handle_api_error(e, context="blueteam_lookup_domain_virustotal")



# FAIL2BAN
@mcp.tool(
    name="blueteam_fail2ban_status",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_fail2ban_status(bypass_redaction: bool = False) -> str:
    """List all active fail2ban jails and their ban counts.

    Returns:
        str: Jail list with banned IP counts
    """
    _audit_log("blueteam_fail2ban_status", {})
    if not shutil.which("fail2ban-client"):
        return _tool_not_found("fail2ban")
    r = _run(["fail2ban-client", "status"])
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)


class JailInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    jail: str = Field(..., description="Jail name, e.g. 'sshd', 'nginx-http-auth'")
    bypass_redaction: bool = Field(default=False, description="When true, skip PII/credential redaction for audit investigations")


@mcp.tool(
    name="blueteam_fail2ban_jail_status",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_fail2ban_jail_status(params: JailInput) -> str:
    """Get detailed status of a specific fail2ban jail, including all banned IPs.

    Args:
        params.jail: Jail name

    Returns:
        str: Jail stats and list of currently banned IPs
    """
    _audit_log("blueteam_fail2ban_jail_status", {"jail": params.jail})
    if not shutil.which("fail2ban-client"):
        return _tool_not_found("fail2ban")
    r = _run(["fail2ban-client", "status", params.jail])
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=params.bypass_redaction)


class UnbanInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    jail: str = Field(..., max_length=64, description="Jail name")
    ip: str = Field(..., max_length=45, description="IP address to unban")
    bypass_redaction: bool = Field(default=False, description="When true, skip PII/credential redaction for audit investigations")

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
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
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
    bypass_redaction: bool = Field(default=False, description="When true, skip PII/credential redaction for audit investigations")


@mcp.tool(
    name="blueteam_hash_file",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_hash_file(params: HashFileInput) -> str:
    """Compute a cryptographic hash of a file. Use to detect tampering.
    Pair with blueteam_lookup_hash_virustotal to check for known malware.

    Args:
        params.path: File params.path
        params.algorithm: Hash algorithm

    Returns:
        str: JSON with file params.path, size, hash params.algorithm, and hash value
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
        return _redact_alert_data(result, bypass=params.bypass_redaction)
    except PermissionError:
        return json.dumps({"error": f"Permission denied reading {params.path}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool(
    name="blueteam_find_suid_files",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_find_suid_files(bypass_redaction: bool = False) -> str:
    """Find all SUID/SGID binaries on the system. Unexpected SUID files
    can indicate privilege escalation backdoors.

    Returns:
        str: List of SUID/SGID files with permissions and owner
    """
    _audit_log("blueteam_find_suid_files", {})
    r = _run(["find", "/", "-type", "f", r"-perm", "/6000", "-ls"], timeout=60)
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)


@mcp.tool(
    name="blueteam_find_world_writable",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_find_world_writable(bypass_redaction: bool = False) -> str:
    """Find world-writable files and directories (excluding /proc, /sys, /dev).
    World-writable files in unexpected places are common persistence mechanisms.

    Returns:
        str: List of world-writable paths
    """
    _audit_log("blueteam_find_world_writable", {})
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
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)


class RootkitInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    tool: str = Field(default="rkhunter", description="Tool to use: 'rkhunter' or 'chkrootkit'")
    bypass_redaction: bool = Field(default=False, description="When true, skip PII/credential redaction for audit investigations")


@mcp.tool(
    name="blueteam_rootkit_scan",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def blueteam_rootkit_scan(params: RootkitInput) -> str:
    """Run a rootkit scanner (rkhunter or chkrootkit) to check for known rootkits.

    Args:
        params.tool: Scanner to use

    Returns:
        str: Scan output with warnings and clean checks
    """
    _audit_log("blueteam_rootkit_scan", {"scanner": params.scanner})
    tool = params.tool.lower()
    if params.tool == "rkhunter":
        if not shutil.which("rkhunter"):
            return _tool_not_found("rkhunter")
        r = _run(["rkhunter", "--check", "--skip-keypress", "--nocolors"], timeout=120)
    elif params.tool == "chkrootkit":
        if not shutil.which("chkrootkit"):
            return _tool_not_found("chkrootkit")
        r = _run(["chkrootkit"], timeout=120)
    else:
        return json.dumps({"error": f"Unknown params.tool '{params.tool}'. Use 'rkhunter' or 'chkrootkit'"})

    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=params.bypass_redaction)


# SYSTEM HARDENING
@mcp.tool(
    name="blueteam_lynis_audit",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}
)
async def blueteam_lynis_audit(bypass_redaction: bool = False) -> str:
    """Run a Lynis system hardening audit. Checks hundreds of security controls
    and produces prioritized recommendations. Takes 1-2 minutes.

    Returns:
        str: Lynis audit output with hardening index and suggestions
    """
    _audit_log("blueteam_lynis_audit", {})
    if not shutil.which("lynis"):
        return _tool_not_found("lynis")
    r = _run(["lynis", "audit", "system", "--quick", "--no-colors"], timeout=180)
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)


@mcp.tool(
    name="blueteam_check_updates",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def blueteam_check_updates(bypass_redaction: bool = False) -> str:
    """Check for available security updates (Debian/Ubuntu: apt, RHEL: dnf/yum).

    Returns:
        str: List of packages with available updates
    """
    _audit_log("blueteam_check_updates", {})
    if shutil.which("apt"):
        r = _run(["apt", "list", "--upgradeable"], timeout=60)
        return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)
    elif shutil.which("dnf"):
        r = _run(["dnf", "check-update", "--security"], timeout=60)
        return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)
    elif shutil.which("yum"):
        r = _run(["yum", "check-update", "--security"], timeout=60)
        return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)
    return json.dumps({"error": "No supported package manager found (apt, dnf, yum)"})


@mcp.tool(
    name="blueteam_check_open_firewall",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_check_open_firewall(bypass_redaction: bool = False) -> str:
    """Show current firewall rules (iptables/nftables/ufw). Identifies
    overly permissive rules or missing protections.

    Returns:
        str: Current firewall ruleset
    """
    _audit_log("blueteam_check_open_firewall", {})
    if shutil.which("ufw"):
        r = _run(["ufw", "status", "verbose"])
        if r["returncode"] == 0:
            return _redact_alert_data(r["stdout"], bypass=bypass_redaction)
    if shutil.which("nft"):
        r = _run(["nft", "list", "ruleset"])
        if r["returncode"] == 0:
            return _redact_alert_data(r["stdout"], bypass=bypass_redaction)
    r = _run(["iptables", "-L", "-n", "-v"])
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)



# USER & SESSION MONITORING
@mcp.tool(
    name="blueteam_who_is_logged_in",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_who_is_logged_in(bypass_redaction: bool = False) -> str:
    """Show currently logged-in users, their source IPs, and session times.
    Useful for detecting unauthorized active sessions.

    Returns:
        str: Active user session table
    """
    _audit_log("blueteam_who_is_logged_in", {})
    r = _run(["w", "-h"])
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)


@mcp.tool(
    name="blueteam_last_logins",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_last_logins(bypass_redaction: bool = False) -> str:
    """Show recent login history from /var/log/wtmp. Includes successful
    and failed logins with source IP and timestamps.

    Returns:
        str: Login history (last 50 entries)
    """
    _audit_log("blueteam_last_logins", {})
    r = _run(["last", "-n", "50", "-a", "-i"])
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)


@mcp.tool(
    name="blueteam_failed_logins",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_failed_logins(bypass_redaction: bool = False) -> str:
    """Show all failed login attempts from /var/log/btmp (lastb).
    High counts from a single IP indicate brute force.

    Returns:
        str: Failed login history (last 100 entries)
    """
    _audit_log("blueteam_failed_logins", {})
    r = _run(["lastb", "-n", "100", "-a", "-i"])
    if r["returncode"] != 0:
        # Try parsing auth.log directly
        r2 = _run(["grep", "-i", r"failed password\|authentication failure", "/var/log/auth.log"])
        lines = r2["stdout"].splitlines()
        return _redact_alert_data("\n".join(lines[-100:], bypass=bypass_redaction) if lines else "No failed logins found in auth.log")
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)


@mcp.tool(
    name="blueteam_sudo_history",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_sudo_history(bypass_redaction: bool = False) -> str:
    """Show recent sudo command usage from auth.log.
    Identifies privilege escalation abuse.

    Returns:
        str: Lines from auth.log containing sudo activity
    """
    _audit_log("blueteam_sudo_history", {})
    r = _run(["grep", "sudo:", "/var/log/auth.log"])
    lines = r["stdout"].splitlines()
    return _redact_alert_data("\n".join(lines[-200:], bypass=bypass_redaction) if lines else "No sudo activity found (or no auth.log)")


@mcp.tool(
    name="blueteam_list_users",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_list_users(bypass_redaction: bool = False) -> str:
    """List all local user accounts with UID, GID, home dir, and shell.
    Highlights users with UID 0 (root-level) and users with login shells.

    Returns:
        str: JSON array of user accounts with risk flags
    """
    _audit_log("blueteam_list_users", {})
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

    # Sort: UID 0 first, then regular users, then system accounts.
    users.sort(key=lambda u: (not u["flags"]["uid_zero_root"], not u["flags"]["has_login_shell"], u["uid"]))
    return _redact_alert_data(json.dumps(users, indent=2, bypass=bypass_redaction))


@mcp.tool(
    name="blueteam_check_ssh_authorized_keys",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_check_ssh_authorized_keys(bypass_redaction: bool = False) -> str:
    """List all SSH authorized_keys files across all user home directories.
    Unexpected keys indicate backdoors or persistence mechanisms.

    Returns:
        str: JSON with each user's authorized keys (fingerprints)
    """
    _audit_log("blueteam_check_ssh_authorized_keys", {})
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

    return _redact_alert_data(json.dumps(result, indent=2, bypass=bypass_redaction) if result else json.dumps({"result": "No authorized_keys files found"}))



# PROCESS & CRON ANALYSIS
@mcp.tool(
    name="blueteam_list_processes",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_list_processes(bypass_redaction: bool = False) -> str:
    """List all running processes with CPU, memory, PID, and command line.
    Useful for spotting unexpected processes or cryptominers.

    Returns:
        str: Process table sorted by CPU usage
    """
    _audit_log("blueteam_list_processes", {})
    r = _run(["ps", "auxf"])
    return _redact_alert_data(r["stdout"] or r["stderr"], bypass=bypass_redaction)


@mcp.tool(
    name="blueteam_list_cron_jobs",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_list_cron_jobs(bypass_redaction: bool = False) -> str:
    """List all system and user cron jobs. Attackers often add cron jobs
    for persistence. Check for unexpected entries.

    Returns:
        str: All cron jobs across system and users
    """
    _audit_log("blueteam_list_cron_jobs", {})
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

    return _redact_alert_data("\n\n".join(output, bypass=bypass_redaction) if output else "No cron jobs found (or insufficient permissions)")



# SYSTEM HEALTH
@mcp.tool(
    name="blueteam_system_health",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_system_health(bypass_redaction: bool = False) -> str:
    """Get an overview of system health: uptime, disk, memory, CPU load.
    Useful baseline before deeper investigation.

    Returns:
        str: JSON with system vitals
    """
    _audit_log("blueteam_system_health", {})
    uptime = _run(["uptime", "-p"])
    disk = _run(["df", "-h", "--exclude-type=tmpfs", "--exclude-type=devtmpfs"])
    mem = _run(["free", "-h"])
    load = _run(["cat", "/proc/loadavg"])
    hostname = _run(["hostname", "-f"])
    kernel = _run(["uname", "-r"])

    return _redact_alert_data(json.dumps({
        "hostname": hostname["stdout"].strip(),
        "kernel": kernel["stdout"].strip(),
        "uptime": uptime["stdout"].strip(),
        "load_average": load["stdout"].strip(),
        "memory": mem["stdout"],
        "disk": disk["stdout"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }, indent=2), bypass=bypass_redaction)


# Shared aggregation helper - posts raw OpenSearch bodies with circuit breaker
async def _wazuh_indexer_post(body: dict, index_pattern: Optional[str] = None) -> Dict:
    """Post a raw OpenSearch query body to the Wazuh Indexer."""
    if index_pattern is None:
        index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return {"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set. See README for Indexer setup."}
    url = f"{WAZUH_INDEXER_URL}/{index_pattern}/_search"
    try:
        resp = await _api_call("post", url, client_name="indexer", verify=WAZUH_INDEXER_VERIFY_SSL,
                                auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
                                json=body, headers={"Content-Type": "application/json"})
        return resp.json()
    except httpx.HTTPStatusError as e:
        return {"error": f"Indexer API error: {e.response.status_code}", "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": str(e)}


_MSEARCH_FALLBACK_ERROR: dict = {"error": "_msearch_failed"}


async def _wazuh_indexer_msearch(bodies: list[dict], index_pattern: Optional[str] = None) -> list[dict]:
    """Send multiple OpenSearch queries in a single _msearch round-trip.

    Builds NDJSON payload: alternating index-header lines and body lines.
    Returns responses in the same order as the input bodies. On failure,
    returns error dicts — the caller is responsible for fallback.
    """
    if index_pattern is None:
        index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return [{"error": "WAZUH_INDEXER_URL/WAZUH_INDEXER_PASSWORD not set"}] * len(bodies)
    if not bodies:
        return []
    url = f"{WAZUH_INDEXER_URL}/{index_pattern}/_msearch"
    header = json.dumps({"index": index_pattern, "allow_partial_search_results": True})
    parts = []
    for body in bodies:
        parts.append(header)
        parts.append(json.dumps(body, separators=(",", ":"), default=str))
    ndjson = "\n".join(parts) + "\n"
    if not ndjson.endswith("\n"):
        ndjson += "\n"
    try:
        resp = await _api_call("post", url, client_name="indexer", verify=WAZUH_INDEXER_VERIFY_SSL,
                                auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
                                content=ndjson.encode("utf-8"),
                                headers={"Content-Type": "application/x-ndjson"})
        raw = resp.json()
        if isinstance(raw, dict) and "responses" in raw:
            return raw["responses"]
        return [raw] if not isinstance(raw, list) else raw
    except Exception as e:
        logger.warning("_msearch failed (%s) — caller should fall back to _wazuh_indexer_post", e)
        return [_MSEARCH_FALLBACK_ERROR] * len(bodies)


# Tier 1: wazuh_alert_aggregate_analysis - full period statistics (size: 0 -> summarizes a whole period with no document limit)
class AggregateAnalysisInput(BaseModel):
    """Input model for wazuh_alert_aggregate_analysis — zero-doc statistical analysis."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    mode: str = Field(
        default="summary",
        description=(
            "Analysis mode: 'topology' (top attack patterns by IP×rule×agent), "
            "'anomaly' (statistical-deviation detection per time-slice), "
            "'correlation' (significant IP↔rule co-occurrence), "
            "'trend' (multi-resolution rate-of-change detection), "
            "'summary' (all modes dispatched in parallel — recommended)."
        ),
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window. ISO 8601 ('2026-07-01T00:00:00Z') or "
                    "relative ('5m', '1h', '24h', '7d', '30d'). Default '24h'.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window. Defaults to now.",
    )
    agent_name: ValidAgentName = Field(
        default=None,
        max_length=64,
        description="Filter to a specific Wazuh agent.",
    )
    rule_groups: ValidRuleGroups = Field(
        default=None,
        description="Comma-separated rule group names (e.g. 'authentication_failure,bruteforce').",
    )
    rule_level_min: Optional[int] = Field(
        default=None,
        ge=1,
        le=16,
        description="Minimum rule level (e.g. 8 for medium+ severity).",
    )
    keyword: ValidKeyword = Field(
        default=None,
        max_length=1024,
        description="Free-text keyword filter. Supports +term, -term, OR, *wildcard*.",
    )
    top_n: int = Field(
        default=10,
        ge=3,
        le=50,
        description="Top-N bucket size for terms aggregations (default 10, max 50).",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="'markdown' for human-readable stats, 'json' for structured data.",
    )
    bypass_redaction: bool = Field(
        default=False,
        description=_BYPASS_REDACTION_DESC,
    )

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in ("topology", "anomaly", "correlation", "trend", "summary"):
            raise ValueError("mode must be one of: topology, anomaly, correlation, trend, summary")
        return v





def _build_filter_clauses(
    since_str: str,
    until_str: str,
    agent_name: Optional[str] = None,
    rule_groups: Optional[list[str]] = None,
    rule_level_min: Optional[int] = None,
    keyword: Optional[str] = None,
    geo_country: Optional[str] = None,
) -> list[dict]:
    """Build OpenSearch filter clauses shared across all Tier-1 modes."""
    filters: list[dict] = [
        {"range": {
            "@timestamp": {
                "gte": since_str,
                "lt": until_str,
                "format": "strict_date_optional_time",
            }
        }},
    ]
    if agent_name and agent_name.strip():
        filters.append({"match": {"agent.name": agent_name.strip()}})
    if rule_groups:
        filters.append({"terms": {"rule.groups": list(rule_groups)}})
    if rule_level_min is not None:
        filters.append({"range": {"rule.level": {"gte": rule_level_min}}})
    if geo_country and geo_country.strip():
        filters.append({"term": {"GeoLocation.country_name": geo_country.strip()}})
    if keyword and keyword.strip():
        _KW = _KEYWORD_SEARCH_FIELDS[:8]
        k = keyword.strip()
        parts = [f'{f}: ({k})^{b}' if b else f'{f}: ({k})' for f, b in _KW]
        filters.append({
            "query_string": {
                "query": " OR ".join(parts),
                "default_operator": "AND",
                "lenient": True,
            }
        })
    return filters


async def _aggregate_topology(
    filters: list[dict],
    top_n: int,
    since_str: str,
    until_str: str,
) -> dict:
    """Topology mode: top attack sources × rules × agents."""
    body = {
        "size": 0,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "top_srcips": {"terms": {"field": "data.srcip.keyword", "size": top_n, "missing": "0.0.0.0"}},
            "top_rules": {"terms": {"field": "rule.id.keyword", "size": top_n, "missing": "unknown"}},
            "top_agents": {"terms": {"field": "agent.name.keyword", "size": top_n, "missing": "unknown"}},
            "severity_bands": {
                "range": {
                    "field": "rule.level",
                    "ranges": [
                        {"key": "low", "to": 5},
                        {"key": "medium", "from": 5, "to": 10},
                        {"key": "high", "from": 10},
                    ],
                }
            },
        },
    }
    return await _wazuh_indexer_post(body)


async def _aggregate_anomaly(
    filters: list[dict],
    since_str: str,
    until_str: str,
) -> dict:
    """Anomaly mode: time-slice statistics with stddev-based deviation detection."""
    # Auto-select bucket interval based on window duration
    dur = _duration_minutes(since_str, until_str)
    bucket_interval = _auto_bucket_interval(dur)

    body = {
        "size": 0,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "time_slices": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": bucket_interval,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": since_str, "max": until_str},
                },
                "aggs": {
                    "by_severity": {
                        "range": {
                            "field": "rule.level",
                            "ranges": [
                                {"key": "low", "to": 5},
                                {"key": "medium", "from": 5, "to": 10},
                                {"key": "high", "from": 10},
                            ],
                        }
                    },
                },
            },
            "global_stats": {"stats_bucket": {"buckets_path": "time_slices>_count"}},
        },
    }
    return await _wazuh_indexer_post(body)


async def _aggregate_correlation(
    filters: list[dict],
    top_n: int,
) -> dict:
    """Correlation mode: significant IP↔rule co-occurrence."""
    body = {
        "size": 0,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "srcips": {
                "terms": {"field": "data.srcip.keyword", "size": top_n, "missing": "0.0.0.0"},
                "aggs": {
                    "significant_rules": {
                        "significant_terms": {
                            "field": "rule.id.keyword",
                            "size": 5,
                        }
                    }
                },
            },
        },
    }
    return await _wazuh_indexer_post(body)


async def _aggregate_trend(
    filters: list[dict],
    since_str: str,
    until_str: str,
    top_n: int,
) -> dict:
    """Trend mode: multi-resolution rate-of-change with derivative pipeline."""
    dur = _duration_minutes(since_str, until_str)
    fine = _auto_bucket_interval(dur)

    # Coarse = 6x fine interval for zoomed-out view
    unit = fine[-1]
    num = int(fine[:-1])
    coarse = f"{num * 6}{unit}"

    body = {
        "size": 0,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "fine_grained": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": fine,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": since_str, "max": until_str},
                },
                "aggs": {
                    "top_rules": {"terms": {"field": "rule.id.keyword", "size": top_n}},
                },
            },
            "coarse_grained": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": coarse,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": since_str, "max": until_str},
                },
                "aggs": {
                    "rate_of_change": {
                        "derivative": {"buckets_path": "_count"},
                    },
                    "top_rules": {"terms": {"field": "rule.id.keyword", "size": top_n}},
                },
            },
        },
    }
    return await _wazuh_indexer_post(body)


def _safe_float(val, default: float = 0.0) -> float:
    """Coerce a value to float, returning *default* on TypeError/ValueError.

    OpenSearch pipeline aggregations (stats_bucket, derivative) occasionally
    serialize numeric results as strings (e.g. ``"12345.0"``, ``"NaN"``).
    This helper prevents ``.1f`` format-string crashes in the markdown renderer
    by returning *default* for any non-finite result (NaN, Inf, -Inf) as well
    as for unparseable strings.
    """
    try:
        result = float(val)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(result):
        return default
    return result


def _format_aggregate_markdown(
    params: AggregateAnalysisInput,
    results_by_mode: dict,
    since_str: str,
    until_str: str,
    errors: dict,
) -> str:
    """Render aggregate analysis results as markdown."""
    lines = [
        f"# Wazuh Alert Aggregate Analysis",
        "",
        f"**Window**: {since_str} → {until_str}",
        f"**Mode(s)**: {params.mode}",
        "",
    ]

    for mode_name, display in [
        ("topology", "Attack Topology"),
        ("anomaly", "Anomaly Detection"),
        ("correlation", "IP↔Rule Correlation"),
        ("trend", "Multi-Resolution Trend"),
    ]:
        if mode_name not in results_by_mode:
            continue
        data = results_by_mode[mode_name]
        if isinstance(data.get("error"), str):
            errors[mode_name] = data["error"]
            continue
        lines.append(f"## {display}")
        lines.append("")

        aggs = data.get("aggregations", {})
        hits_total = data.get("hits", {}).get("total", {})

        if mode_name == "topology":
            total = hits_total.get("value", "?")
            lines.append(f"**Total matching alerts**: {total}")
            lines.append("")
            for agg_key, label in [
                ("top_srcips", "Top Source IPs"),
                ("top_rules", "Top Rules"),
                ("top_agents", "Top Agents"),
            ]:
                buckets = (aggs.get(agg_key, {}) or {}).get("buckets", [])
                if buckets:
                    lines.append(f"### {label}")
                    for b in buckets[:params.top_n]:
                        lines.append(f"- `{b.get('key', '?')}` — {b.get('doc_count', 0)} alerts")
                    lines.append("")
            sev = (aggs.get("severity_bands", {}) or {}).get("buckets", [])
            if sev:
                lines.append("### Severity Distribution")
                for b in sev:
                    lines.append(f"- **{b.get('key')}** (level {b.get('from', '')}–{b.get('to', '')}): {b.get('doc_count', 0)}")
                lines.append("")

        elif mode_name == "anomaly":
            gs = aggs.get("global_stats", {})
            avg_val = _safe_float(gs.get("avg", 0))
            std_val = _safe_float(gs.get("std_deviation", 0))
            lines.append(f"- **Mean alerts per slice**: {avg_val:.1f}")
            lines.append(f"- **StdDev**: {std_val:.1f}")
            lines.append(f"- **Min/Max per slice**: {gs.get('min', '?')} / {gs.get('max', '?')}")
            lines.append("")
            slices = (aggs.get("time_slices", {}) or {}).get("buckets", [])
            threshold = avg_val + 2 * std_val
            anomalies = [s for s in slices if s.get("doc_count", 0) > threshold]
            if anomalies:
                lines.append(f"### Anomalous Slices (>μ+2σ): {len(anomalies)}")
                lines.append("| Time | Count | Severity (L/M/H) |")
                lines.append("|------|-------|-------------------|")
                for s in anomalies[:10]:
                    ts = s.get("key_as_string", s.get("key", "?"))[:19]
                    sev = (s.get("by_severity", {}) or {}).get("buckets", [])
                    sev_str = " / ".join(f"{r.get('doc_count', 0)}" for r in sev)
                    lines.append(f"| {ts} | **{s.get('doc_count', 0)}** | {sev_str} |")
            else:
                lines.append("_No statistically anomalous slices detected._")
            lines.append("")

        elif mode_name == "correlation":
            srcips = (aggs.get("srcips", {}) or {}).get("buckets", [])
            if srcips:
                lines.append("| Source IP | Alert Count | Top Significant Rules |")
                lines.append("|-----------|-------------|----------------------|")
                for ip_b in srcips[:params.top_n]:
                    ip = ip_b.get("key", "?")
                    cnt = ip_b.get("doc_count", 0)
                    sig = (ip_b.get("significant_rules", {}) or {}).get("buckets", [])
                    rules_str = ", ".join(
                        f"`{r.get('key', '?')}` (×{r.get('doc_count', 0)})"
                        for r in sig[:3]
                    ) or "—"
                    lines.append(f"| `{ip}` | {cnt} | {rules_str} |")
            else:
                lines.append("_No significant correlations found._")
            lines.append("")

        elif mode_name == "trend":
            coarse_agg = aggs.get("coarse_grained", {})
            buckets = coarse_agg.get("buckets", [])
            if buckets:
                accelerating = [b for b in buckets if b.get("rate_of_change", {}).get("value", 0) > 0]
                decelerating = [b for b in buckets if b.get("rate_of_change", {}).get("value", 0) < 0]
                lines.append(f"- **Accelerating periods**: {len(accelerating)}")
                lines.append(f"- **Decelerating periods**: {len(decelerating)}")
                if accelerating:
                    peak = max(_safe_float(b.get('rate_of_change', {}).get('value', 0)) for b in accelerating)
                    lines.append(f"- **Peak rate of change**: +{peak:.1f} alerts/slice")
                lines.append("")
                # Show fine-grained top rules from the latest bucket
                fine = aggs.get("fine_grained", {}).get("buckets", [])
                if fine:
                    latest = fine[-1]
                    top_rules = (latest.get("top_rules", {}) or {}).get("buckets", [])
                    if top_rules:
                        lines.append("### Latest Time-Slice Top Rules")
                        for r in top_rules[:5]:
                            lines.append(f"- `{r.get('key', '?')}` — {r.get('doc_count', 0)} alerts")
                        lines.append("")
            else:
                lines.append("_No trend data available._")
                lines.append("")

    if errors:
        lines.append("## Errors")
        for mode_name, err in errors.items():
            lines.append(f"- **{mode_name}**: {err}")

    return "\n".join(lines)


@mcp.tool(
    name="wazuh_alert_aggregate_analysis",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def wazuh_alert_aggregate_analysis(params: AggregateAnalysisInput) -> str:
    """Full-period statistical analysis of Wazuh alerts - NO document limits.

    All matching alerts are processed server-side by the Wazuh Indexer (OpenSearch)
    using ``size: 0`` aggregations. Only statistics and bucketed summaries are
    returned — ZERO raw alert documents. This means 1M alerts and 10K alerts
    consume roughly the same LLM context budget (~10–50 KB).

    **Analysis modes:**
    - ``topology`` - Top-N (src_ip × rule_id × agent) attack patterns + severity bands
    - ``anomaly`` - Statistical-deviation detection: which time slices are >2σ above mean?
    - ``correlation`` - Significant IP↔rule co-occurrence via significant_terms
    - ``trend`` - Multi-resolution rate-of-change (acceleration/deceleration) detection
    - ``summary`` - All four modes dispatched in parallel (recommended)

    **Typical workflow:**
    1. Call with ``mode="summary"`` to get the full statistical picture
    2. Identify hot spots from the results (specific IPs, rules, time windows)
    3. Use ``wazuh_alert_focused_crawl`` to drill into those specific slices

    Args:
        params.mode: Analysis params.mode (default 'summary').
        params.since: Start of time window (default '24h').
        params.until: End of time window (default: now).
        params.agent_name: Optional agent filter.
        params.rule_groups: Optional comma-separated rule groups (e.g. 'authentication_failure').
        params.rule_level_min: Minimum rule level (e.g. 8).
        params.keyword: Optional free-text keyword filter.
        params.top_n: Top-N bucket size for terms aggregations (default 10).
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        str: Structured statistical report — no raw documents.

    Example usage:
        - "Give me a statistical summary of the last 24 hours of Wazuh alerts"
        - "Which source IPs are showing anomalous activity patterns this week?"
        - "Analyze attack correlation for agent HYDRA-DC across the past 48h"
        - "Is the attack velocity accelerating or decelerating over the last 6 hours?"

    Error Handling:
        - Returns partial results if individual modes fail (errors listed at end)
        - All modes go through the Wazuh Indexer circuit breaker
        - Timeout/connection failures surface actionable error messages per params.mode
    """
    _audit_log("wazuh_alert_aggregate_analysis", {"mode": params.mode, "since": params.since})
    since_str, until_str = _parse_time_window(params.since, params.until)

    rule_group_list: Optional[list[str]] = None
    if params.rule_groups:
        rule_group_list = [g.strip() for g in params.rule_groups.split(",") if g.strip()]

    filters = _build_filter_clauses(
        since_str=since_str,
        until_str=until_str,
        agent_name=params.agent_name,
        rule_groups=rule_group_list,
        rule_level_min=params.rule_level_min,
        keyword=params.keyword,
    )

    modes_to_run: dict[str, Any] = {}
    if params.mode == "summary":
        modes_to_run = {
            "topology": _aggregate_topology(filters, params.top_n, since_str, until_str),
            "anomaly": _aggregate_anomaly(filters, since_str, until_str),
            "correlation": _aggregate_correlation(filters, params.top_n),
            "trend": _aggregate_trend(filters, since_str, until_str, params.top_n),
        }
    elif params.mode == "topology":
        modes_to_run = {
            "topology": _aggregate_topology(filters, params.top_n, since_str, until_str),
        }
    elif params.mode == "anomaly":
        modes_to_run = {
            "anomaly": _aggregate_anomaly(filters, since_str, until_str),
        }
    elif params.mode == "correlation":
        modes_to_run = {
            "correlation": _aggregate_correlation(filters, params.top_n),
        }
    elif params.mode == "trend":
        modes_to_run = {
            "trend": _aggregate_trend(filters, since_str, until_str, params.top_n),
        }

    # Dispatch all modes concurrently
    tasks = dict(modes_to_run)
    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    results_by_mode: dict = {}
    errors: dict = {}
    for mode_name, result in zip(tasks.keys(), gathered):
        if isinstance(result, BaseException):
            errors[mode_name] = str(result)
        else:
            results_by_mode[mode_name] = result

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({
            "window": {"since": since_str, "until": until_str},
            "mode": params.mode,
            "results": results_by_mode,
        }, indent=2, default=str))
    return _format_aggregate_markdown(params, results_by_mode, since_str, until_str, errors)


# Tier 2: wazuh_alert_dsl_query - power user escape hatch (size: 0 enforced)
def _check_no_scripts(obj: Any, path: str = "") -> None:
    """Reject scripted aggregations - shared by DslQueryInput validators."""
    if isinstance(obj, dict):
        if "script" in obj and path:
            raise ValueError(
                f"Script found at '{path}' - scripted aggregations are not "
                "supported in this tool for security and performance reasons."
            )
        for k, val in obj.items():
            _check_no_scripts(val, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _check_no_scripts(item, f"{path}[{i}]")


class DslQueryInput(BaseModel):
    """Input model for wazuh_alert_dsl_query - structured OpenSearch DSL, aggregation-only.

    Two input paths (mutually exclusive):
    1. **Structured (preferred)**: pass ``aggs`` (and optionally ``query``) as native JSON
       objects. Pydantic validates the shape; the server serializes to the OpenSearch wire
       format. No JSON-in-JSON escaping — safe for LLM callers.
    2. **Raw string (deprecated)**: pass ``query_json`` as a pre-serialized DSL string.
       Requires correct double-escaping for nested quotes. Use only for backward compat.
    """
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def coerce_string_params(cls, data: Any) -> Any:
        """Auto-parse JSON-string params — MCP clients sometimes send args as raw JSON strings."""
        if isinstance(data, str):
            import json as _json
            try:
                data = _json.loads(data)
            except _json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON: {e.msg} at position {e.pos}. Check commas and braces.")
        return data

    # Structured path (preferred)
    aggs: Optional[dict[str, Any]] = Field(
        default=None,
        description=(
            "OpenSearch aggregation tree as a native JSON object. "
            "Example: {\"by_agent\": {\"terms\": {\"field\": \"agent.name\", \"size\": 50}}}. "
            "Pass this (not query_json) for all new queries — the server serializes to the "
            "wire format, eliminating the JSON-in-JSON escaping trap."
        ),
    )
    query: Optional[dict[str, Any]] = Field(
        default=None,
        description=(
            "Optional query filter dict (same shape as OpenSearch query DSL). "
            "Example: {\"bool\": {\"must\": [{\"range\": {\"@timestamp\": {\"gte\": \"now-6h\"}}}]}}. "
            "Only valid when ``aggs`` is set."
        ),
    )

    # Raw string path (deprecated - backward compat only)
    query_json: Optional[str] = Field(
        default=None,
        min_length=5,
        max_length=10240,
        description=(
            "[DEPRECATED] Raw OpenSearch DSL JSON string. Prefer ``aggs`` + ``query`` instead. "
            "MUST use 'size': 0 (aggregation-only). "
            "When using this path, Painless script quotes require quadruple backslash escaping "
            "(\\\\\") to survive JSON-in-JSON double-serialization."
        ),
    )

    index_pattern: str = Field(
        default="wazuh-alerts-*",
        max_length=128,
        description="OpenSearch index pattern (default 'wazuh-alerts-*'). "
                    "Also accepts 'wazuh-events-*', 'wazuh-states-vulnerabilities-*'.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="json",
        description="'json' (default, machine-readable) or 'markdown'.",
    )

    @model_validator(mode="after")
    def require_exactly_one_input_path(self):
        """Mutually exclusive: structured (aggs) or raw (query_json), not both, not neither."""
        has_aggs = self.aggs is not None
        has_query_json = self.query_json is not None
        if has_aggs and has_query_json:
            raise ValueError(
                "Pass either 'aggs' (structured, preferred) or 'query_json' (raw, deprecated), not both."
            )
        if not has_aggs and not has_query_json:
            raise ValueError(
                "Either 'aggs' (structured, preferred) or 'query_json' (raw, deprecated) is required."
            )
        if self.query is not None and not has_aggs:
            raise ValueError("'query' is only valid when 'aggs' is set, not with 'query_json'.")
        return self

    @field_validator("aggs")
    @classmethod
    def validate_aggs(cls, v: Optional[dict]) -> Optional[dict]:
        """Reject scripted aggregations in the structured path."""
        if v is not None:
            if not v:
                raise ValueError("'aggs' must contain at least one aggregation.")
            _check_no_scripts(v, "aggs")
        return v

    @field_validator("query_json")
    @classmethod
    def validate_dsl(cls, v: Optional[str]) -> Optional[str]:
        """Parse the JSON and enforce size: 0 — no document hits allowed. Deprecated path."""
        if v is None:
            return v
        try:
            parsed = json.loads(v)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in query_json: {e}") from e

        # Enforce aggregation-only: size must be 0
        size_val = parsed.get("size", 10)  # OpenSearch defaults size to 10
        if size_val != 0:
            raise ValueError(
                f"query_json has 'size': {size_val}. This tool only accepts size: 0 "
                "(aggregation-only queries). To retrieve raw alert documents, use "
                "wazuh_alert_focused_crawl instead."
            )

        # Must contain 'aggs' or 'aggregations'
        if "aggs" not in parsed and "aggregations" not in parsed:
            raise ValueError(
                "query_json must contain 'aggs' or 'aggregations' key. "
                "This tool is for aggregation queries only."
            )

        _check_no_scripts(parsed)
        return v

    @field_validator("index_pattern")
    @classmethod
    def validate_index_pattern(cls, v: str) -> str:
        v = v.strip()
        # Allow only safe index patterns: alphanumeric, *, -, _
        if not re.match(r"^[a-zA-Z0-9*_\-.,]+$", v):
            raise ValueError(
                "index_pattern must be a valid OpenSearch index pattern "
                "(e.g. 'wazuh-alerts-*', 'wazuh-events-*')"
            )
        return v


@mcp.tool(
    name="wazuh_alert_dsl_query",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def wazuh_alert_dsl_query(params: DslQueryInput) -> str:
    """Execute a raw OpenSearch DSL aggregation query against the Wazuh Indexer.

    This is an **aggregation-only** escape hatch for analytical questions that
    don't fit the pre-built ``wazuh_alert_aggregate_analysis`` modes. The input
    DSL must use ``"size": 0`` — raw document retrieval is rejected at validation
    time. Scripted aggregations are also blocked for security.

    **Two input paths** (mutually exclusive):
    - **Structured (preferred)**: pass ``params.aggs`` (and optionally ``params.query``)
      as native JSON objects. The server serializes to the OpenSearch wire format —
      no JSON-in-JSON escaping required. Safe for LLM callers.
    - **Raw string (deprecated)**: pass ``params.query_json`` as a pre-serialized DSL
      string. Requires correct double-escaping for nested quotes.

    Use this when you need a specific OpenSearch aggregation (percentiles,
    geo_distance, nested, reverse_nested, etc.) that the built-in tools
    do not expose.

    Args:
        params.aggs: OpenSearch aggregation tree as a native dict (preferred path).
        params.query: Optional query filter dict (only with ``aggs``).
        params.query_json: [DEPRECATED] Raw OpenSearch DSL JSON string.
        params.index_pattern: Index pattern (default 'wazuh-alerts-*').
        params.response_format: 'json' (default) or 'markdown'.

    Returns:
        str: OpenSearch aggregation response (JSON by default, markdown on request).

    Example usage (structured path):
        - aggs={"by_agent": {"terms": {"field": "agent.name", "size": 50}}}
        - aggs={"hourly": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}}},
          query={"bool": {"must": [{"range": {"@timestamp": {"gte": "now-24h"}}}]}}

    Example usage (deprecated raw path):
        - query_json='{"size":0,"aggs":{"by_agent":{"terms":{"field":"agent.name"}}}}'

    Error Handling:
        - Invalid JSON → rejected at Pydantic validation
        - ``size`` > 0 → rejected with guidance to use wazuh_alert_focused_crawl
        - Scripted aggs → rejected for security
        - HTTP errors → surfaced through the circuit breaker

    Docs: https://opensearch.org/docs/latest/aggregations/
    """
    _audit_log("wazuh_alert_dsl_query", {"index": params.index_pattern})

    # Build the DSL body - structured path (preferred) or raw path (deprecated)
    if params.aggs is not None:
        body: dict[str, Any] = {"size": 0, "aggs": params.aggs}
        if params.query is not None:
            body["query"] = params.query
    else:
        logger.warning("wazuh_alert_dsl_query: query_json (raw string) path is deprecated. "
                       "Use 'aggs' + 'query' dicts instead to avoid JSON-in-JSON escaping issues.")
        body = json.loads(params.query_json)  # type: ignore[arg-type]

    try:
        data = await _wazuh_indexer_post(
            body,
            index_pattern=params.index_pattern,
        )
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        return _handle_api_error(e, context="wazuh_alert_dsl_query")

    if params.response_format == "markdown":
        if isinstance(data.get("error"), str):
            return f"# DSL Query Error\n\n**Error**: {data['error']}\n\n**Detail**: {data.get('detail', 'N/A')}"
        aggs = data.get("aggregations", data.get("aggs", {}))
        return f"# DSL Query Result\n\n**Index**: {params.index_pattern}\n\n```json\n{json.dumps(aggs, indent=2, default=str)[:CHARACTER_LIMIT]}\n```"

    return _truncate_if_needed(json.dumps(data, indent=2, default=str))


# Tier 3: wazuh_alert_focused_crawl deep dive into hot spots
class FocusedCrawlInput(BaseModel):
    """Input model for wazuh_alert_focused_crawl — surgical deep-dive into specific alert clusters."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    src_ip: Optional[str] = Field(
        default=None,
        max_length=45,
        description="Specific source IP to drill into (e.g. the top abuser from aggregate analysis).",
    )
    rule_id: Optional[str] = Field(
        default=None,
        max_length=32,
        description="Specific rule ID to drill into (e.g. '5763' for authentication failure).",
    )
    agent_name: ValidAgentName = Field(
        default=None,
        max_length=64,
        description="Filter to a specific Wazuh agent.",
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window (ISO 8601 or relative expression). Default '24h'.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window. Defaults to now.",
    )
    sample_size: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Number of representative alert documents to retrieve (default 50, max 200).",
    )
    include_full_log: bool = Field(
        default=True,
        description="Include the full_log field in returned documents (PII-redacted per BLUETEAM_REDACT_PII).",
    )
    bypass_redaction: bool = Field(
        default=False,
        description="Bypass PII redaction for audit investigations (requires BLUETEAM_REDACT_PII disabled).",
    )
    fields: Optional[str] = Field(
        default=None,
        description="Comma-separated additional _source fields to retrieve beyond defaults. "
                    "Example: 'data.url,data.domain,data.user_agent'.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="'markdown' (default) for human-readable alert summaries, 'json' for structured data.",
    )

    @field_validator("src_ip")
    @classmethod
    def validate_src_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                return None
            try:
                ipaddress.ip_address(v)
            except ValueError as exc:
                raise ValueError(f"Invalid IP address: '{v}'") from exc
        return v

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                return None
            if not re.match(r"^\d{1,10}$", v):
                raise ValueError("rule_id must be numeric (e.g. '5763')")
        return v


    @field_validator("fields")
    @classmethod
    def validate_fields(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                return None
            parts = [p.strip() for p in v.split(",") if p.strip()]
            for p in parts:
                if not re.match(r"^[a-zA-Z0-9_@.\-]+$", p):
                    raise ValueError(f"Invalid field name: '{p}'. Use only alphanumeric, dots, underscores, @, hyphens.")
        return v


@mcp.tool(
    name="wazuh_alert_focused_crawl",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def wazuh_alert_focused_crawl(params: FocusedCrawlInput = FocusedCrawlInput()) -> str:
    """Surgical deep-dive into specific Wazuh alert clusters.

    After ``wazuh_alert_aggregate_analysis`` identifies hot spots (top source IPs,
    most-triggered rules, anomalous time windows), use this tool to retrieve
    representative alert samples from those specific slices with full context.

    This is the **drill-through** tool — it returns actual alert documents
    (PII-redacted per ``BLUETEAM_REDACT_PII``). Call it once per identified
    hot spot, not for the entire dataset.

    Args:
        params.src_ip: Specific source IP identified as a hot spot.
        params.rule_id: Specific rule ID (e.g. '5763') identified as a top offender.
        params.agent_name: Filter to a specific agent.
        params.since: Start of time window (default '24h').
        params.until: End of time window (default: now).
        params.sample_size: Alert documents to retrieve (default 50, max 200).
        params.include_full_log: Include raw log lines (PII-redacted).
        params.bypass_redaction: Skip PII masking for audit (if BLUETEAM_REDACT_PII allows).
        params.fields: Comma-separated extra _source fields to include.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        str: Representative alert documents with full context, PII-redacted.
             Includes next_cursor for further pagination into same slice.

    Example usage:
        - "Drill into the top abuser IP from the aggregate analysis"
        - "Show me 50 alerts for rule 5763 on agent HYDRA-DC from the past hour"
        - "Get full alert details for the anomalous 5-minute window at 03:15 UTC"

    Error Handling:
        - "No data found for this target" if the slice has no matching alerts
        - Circuit breaker open → actionable retry message
        - PII redaction applied automatically (bypass with bypass_redaction=True)
    """
    _audit_log("wazuh_alert_focused_crawl", {"src_ip": params.src_ip, "rule_id": params.rule_id, "sample_size": params.sample_size})
    since_str, until_str = _parse_time_window(params.since, params.until)

    # Build _source fields: defaults + user-specified extras
    source_fields = [
        "@timestamp",
        "agent.name",
        "rule.id",
        "rule.level",
        "rule.description",
        "data.srcip",
        "data.url",
        "predecoder.hostname",
        "location",
        "id",
    ]
    if params.include_full_log:
        source_fields.append("full_log")
    if params.fields:
        extras = [f.strip() for f in params.fields.split(",") if f.strip()]
        for f in extras:
            if f not in source_fields:
                source_fields.append(f)

    try:
        data = await _wazuh_indexer_search(
            index_pattern=_WAZUH_INDEX_PATTERNS["alerts"],
            agent_name=params.agent_name,
            size=params.sample_size,
            srcip=params.src_ip,
            since=since_str,
            until=until_str,
            fields=source_fields,
        )
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        return _handle_api_error(e, context="wazuh_alert_focused_crawl")

    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)

    hits = data.get("hits", {})
    total = hits.get("total", {})
    hit_list = hits.get("hits", [])

    # Apply PII redaction to all document bodies
    docs = [_redact_alert_data(h.get("_source", h), bypass=params.bypass_redaction) for h in hit_list]

    # Build next_cursor for further pagination within the same slice
    next_cursor = None
    if hit_list and len(docs) >= params.sample_size:
        last_sort = hit_list[-1].get("sort")
        if last_sort:
            next_cursor = _encode_cursor({"search_after": last_sort})

    # Count unique source IPs and rules in the sample
    unique_ips = set()
    unique_rules = set()
    level_counts: dict[str, int] = {}
    for d in docs:
        src = d.get("data", {}).get("srcip") if isinstance(d.get("data"), dict) else d.get("data.srcip")
        if src:
            unique_ips.add(str(src))
        rid = d.get("rule", {}).get("id") if isinstance(d.get("rule"), dict) else d.get("rule.id")
        if rid:
            unique_rules.add(str(rid))
        lvl = d.get("rule", {}).get("level") if isinstance(d.get("rule"), dict) else d.get("rule.level")
        if lvl is not None:
            band = "high" if lvl >= 10 else ("medium" if lvl >= 5 else "low")
            level_counts[band] = level_counts.get(band, 0) + 1

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({
            "window": {"since": since_str, "until": until_str},
            "filter": {
                "src_ip": params.src_ip,
                "rule_id": params.rule_id,
                "agent_name": params.agent_name,
            },
            "total": {"value": total.get("value", 0), "relation": total.get("relation", "eq")},
            "count": len(docs),
            "sample_unique_ips": len(unique_ips),
            "sample_unique_rules": len(unique_rules),
            "severity_bands": level_counts,
            "next_cursor": next_cursor,
            "alerts": docs,
        }, indent=2, default=str))

    # Markdown format
    total_val = total.get("value", 0)
    lines = [
        "# Wazuh Alert Focused Crawl",
        "",
        f"**Window**: {since_str} → {until_str}",
        "",
        "| Filter | Value |",
        "|--------|-------|",
    ]
    if params.src_ip:
        lines.append(f"| Source IP | `{params.src_ip}` |")
    if params.rule_id:
        lines.append(f"| Rule ID | `{params.rule_id}` |")
    if params.agent_name:
        lines.append(f"| Agent | `{params.agent_name}` |")
    lines.extend([
        f"| Total matching | {total_val} ({total.get('relation', 'eq')}) |",
        f"| Retrieved | {len(docs)} |",
        f"| Unique IPs in sample | {len(unique_ips)} |",
        f"| Unique rules in sample | {len(unique_rules)} |",
        "",
    ])
    if level_counts:
        lines.append(f"**Severity**: L:{level_counts.get('low', 0)} M:{level_counts.get('medium', 0)} H:{level_counts.get('high', 0)}")
        lines.append("")

    if not docs:
        lines.append("_No alerts matched the filter criteria in this time window._")
    else:
        lines.append(f"## Alert Samples ({len(docs)} of {total_val} total)")
        lines.append("")
        for i, d in enumerate(docs[:20], 1):
            ts = d.get("@timestamp", "?")
            rule = d.get("rule", {}) if isinstance(d.get("rule"), dict) else {}
            rid = rule.get("id", d.get("rule.id", "?"))
            desc = rule.get("description", d.get("rule.description", "?"))
            lvl = rule.get("level", d.get("rule.level", "?"))
            src = d.get("data", {}).get("srcip") if isinstance(d.get("data"), dict) else d.get("data.srcip", "?")
            agent = d.get("agent", {}).get("name") if isinstance(d.get("agent"), dict) else d.get("agent.name", "?")
            lines.append(f"**{i}.** `{ts}` | Level {lvl} | Rule {rid} — {desc}")
            lines.append(f"   - Source: `{src}` | Agent: `{agent}`")
            full = d.get("full_log", "")
            if full:
                lines.append(f"   - Log: `{str(full)[:200]}{'...' if len(str(full)) > 200 else ''}`")
            lines.append("")
        if len(docs) > 20:
            lines.append(f"_... and {len(docs) - 20} more alerts (use next_cursor for next page)_")

    if next_cursor:
        lines.append("")
        lines.append(f"**next_cursor**: `{next_cursor}` — pass this to the `cursor` parameter of `blueteam_wazuh_indexer_search` to continue paginating this slice.")

    return _truncate_if_needed("\n".join(lines))


# Tier 4: sangfor_blocklist_* - Sangfor firewall blocklist integration
class SangforBlocklistCheckInput(BaseModel):
    """Input model for sangfor_blocklist_check - single IP blocklist lookup."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ip_address: str = Field(
        ...,
        max_length=45,
        description="IPv4 or IPv6 address to check against the Sangfor blocklist.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="'markdown' (default, human-readable) or 'json'.",
    )

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v.strip())
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IPv4 or IPv6 address")
        return v.strip()


class SangforBlocklistListInput(BaseModel):
    """Input model for sangfor_blocklist_list — paginated blocklist listing."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    date_start: str = Field(
        default="24h",
        max_length=30,
        description="Start of time window - ISO 8601 (e.g. '2026-07-15T00:00:00') or relative ('24h', '7d').",
    )
    date_end: str = Field(
        default="now",
        max_length=30,
        description="End of time window - ISO 8601 or 'now' for current time.",
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Max entries per page (1-1000, default 100).",
    )
    offset: int = Field(
        default=0,
        ge=0,
        description="Pagination offset (0-based).",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="'markdown' (default, human-readable) or 'json'.",
    )


# Blockmode -> severity mapping per operational ground truth (TangerangKota-CSIRT)
_BLOCKMODE_SEVERITY: dict[str, str] = {
    "30m": "Temporary / Low Priority",
    "1h": "Temporary / Low Priority",
    "2h": "Temporary / Low Priority",
    "3d": "Active Mitigation / Medium Priority",
    "7d": "Active Mitigation / Medium Priority",
    "permanent": "Hard Block / High Priority",
}


def _get_sangfor_token() -> str:
    """Read Sangfor blocklist API token from environment."""
    if not SANGFOR_BLOCKLIST_TOKEN:
        raise RuntimeError(
            "SANGFOR_BLOCKLIST_TOKEN is not set. "
            "Set your Sangfor API bearer token before using sangfor_blocklist_* tools."
        )
    if not SANGFOR_BLOCKLIST_URL:
        raise RuntimeError(
            "SANGFOR_BLOCKLIST_URL is not set. "
            "Set the Sangfor blocklist API endpoint before using sangfor_blocklist_* tools."
        )
    return SANGFOR_BLOCKLIST_TOKEN


def _blockmode_severity(blockmode: str) -> str:
    """Map raw blockmode value to human-readable severity label."""
    return _BLOCKMODE_SEVERITY.get(blockmode, f"Unknown ({blockmode})")


def _format_sangfor_entry_markdown(entry: dict) -> str:
    """Render a single Sangfor blocklist entry as a markdown line item."""
    ip = entry.get("ip_address", "?")
    isp = entry.get("isp", "?")
    loc = entry.get("location", "?")
    mode = entry.get("blockmode", "?")
    severity = _blockmode_severity(mode)
    wazuh_s = entry.get("wazuh_score", 0)
    tip_s = entry.get("tip_score", 0)
    overall = entry.get("overall_score", 0)
    created = entry.get("created_at", "?")[:19]
    return (
        f"| `{ip}` | {isp} | {loc} | `{mode}` ({severity}) | "
        f"W:{wazuh_s} T:{tip_s} → **{overall}** | {created} |"
    )


@mcp.tool(
    name="sangfor_blocklist_check",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def sangfor_blocklist_check(params: SangforBlocklistCheckInput) -> str:
    """Check if a single IP address is currently blocked by the Sangfor firewall.

    Queries the Sangfor blocklist API for a specific IP. Returns the block record
    if found (with severity, scores, and block duration), or a NOT_BLOCKED status
    with a recommendation for manual IS analyst review.

    This tool is **informational only** — it never initiates or modifies firewall
    rules. When an IP is not on the list, it surfaces a MANUAL_IS_REVIEW action
    flag for the human analyst.

    Args:
        params.ip_address: IPv4 or IPv6 address to check.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        str: Blocklist status with IP details, scores, severity, and action flag.

    Example usage:
        - "Check if 180.254.78.145 is blocked by Sangfor"
        - "Verify blocklist status of a high-score 3-Sum correlation IP"

    Error Handling:
        - Invalid IP → rejected at Pydantic validation
        - Missing SANGFOR_BLOCKLIST_TOKEN → clear RuntimeError
        - HTTP errors → surfaced through standard error handling
    """
    _audit_log("sangfor_blocklist_check", {"ip": params.ip_address})
    ip = params.ip_address.strip()

    try:
        token = _get_sangfor_token()
    except RuntimeError as e:
        return json.dumps({"error": str(e)})

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "accept": "application/json",
        "User-Agent": "blue-team-mcp/1.0.0 (TangerangKota-CSIRT)",
    }

    # Query the blocklist with a narrow window - API requires date range
    now = datetime.now(timezone.utc)
    date_end = now.strftime("%Y-%m-%d %H:%M:%S")
    date_start = (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    payload = {"date_start": date_start, "date_end": date_end, "limit": 5000, "offset": 0}

    try:
        client = await _get_client("sangfor", verify=SANGFOR_BLOCKLIST_VERIFY_SSL, max_keepalive=2, max_connections=10)
        resp = await client.post(
            SANGFOR_BLOCKLIST_URL,
            headers=headers,
            json=payload,
            timeout=httpx.Timeout(SANGFOR_BLOCKLIST_TIMEOUT),
        )
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPStatusError as e:
        return _handle_api_error(e, context="sangfor_blocklist_check")
    except httpx.TimeoutException:
        return json.dumps({"error": f"Sangfor API timed out after {SANGFOR_BLOCKLIST_TIMEOUT}s", "ip": ip})
    except Exception as e:
        return json.dumps({"error": f"Sangfor API request failed: {e}", "ip": ip})

    # Search for the IP in the response array
    if not isinstance(data, list):
        return json.dumps({"error": "Unexpected API response format", "ip": ip, "raw_type": type(data).__name__})

    match = None
    for entry in data:
        if isinstance(entry, dict) and entry.get("ip_address", "").strip() == ip:
            match = entry
            break

    if params.response_format == "json":
        if match:
            match["status"] = "BLOCKED"
            match["severity"] = _blockmode_severity(match.get("blockmode", ""))
            match["action"] = "NO_ACTION_NEEDED"
            return _truncate_if_needed(json.dumps(match, indent=2, default=str))
        return json.dumps({
            "ip_address": ip,
            "status": "NOT_BLOCKED",
            "severity": "N/A",
            "action": "MANUAL_IS_REVIEW",
            "recommendation": "IP not found in Sangfor blocklist — IS analyst should evaluate for manual blocking.",
        }, indent=2)

    # Markdown format
    if match:
        lines = [
            "# Sangfor Blocklist -  IP Found (BLOCKED)",
            "",
            f"**IP**: `{ip}`",
            f"**Status**: 🔴 **BLOCKED** — no action needed",
            f"**ISP**: {match.get('isp', '?')}",
            f"**Location**: {match.get('location', '?')}",
            f"**Block Mode**: `{match.get('blockmode', '?')}` — {_blockmode_severity(match.get('blockmode', ''))}",
            "",
            "| Score Type | Value |",
            "|-----------|-------|",
            f"| Wazuh Score | {match.get('wazuh_score', '?')} |",
            f"| TIP Score | {match.get('tip_score', '?')} |",
            f"| **Overall Score** | **{match.get('overall_score', '?')}** |",
            "",
            f"**Created**: {match.get('created_at', '?')}",
        ]
        if match.get("updated_at"):
            lines.append(f"**Updated**: {match['updated_at']}")
        return "\n".join(lines)

    return (
        f"# Sangfor Blocklist — IP NOT FOUND\n\n"
        f"**IP**: `{ip}`\n"
        f"**Status**: 🟢 **NOT BLOCKED**\n\n"
        f"**Action Required**: `MANUAL_IS_REVIEW`\n"
        f"**Recommendation**: This IP is not on the Sangfor blocklist. "
        f"The IS analyst should evaluate the threat context (3-Sum scores, CrowdSec reputation) "
        f"and decide whether to add a manual block.\n"
    )


@mcp.tool(
    name="sangfor_blocklist_list",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def sangfor_blocklist_list(params: SangforBlocklistListInput) -> str:
    """List all IPs currently blocked by the Sangfor firewall in a time window.

    Returns a paginated list of blocked IPs with scores, severity mapping,
    and geolocation. Use this for situational awareness, threat hunting,
    and cross-referencing with 3-Sum correlation output.

    Args:
        params.date_start: Start of window — ISO 8601 or relative ('24h', '7d'). Default '24h'.
        params.date_end: End of window — ISO 8601 or 'now'. Default 'now'.
        params.limit: Max entries per page (1-1000, default 100).
        params.offset: Pagination offset (0-based, default 0).
        params.response_format: 'markdown' (default, human-readable) or 'json'.

    Returns:
        str: Paginated blocklist entries with next_offset cursor.

    Example usage:
        - "List all IPs blocked by Sangfor in the last 24 hours"
        - "Show the last 7 days of Sangfor blocks for threat hunting"

    Error Handling:
        - Invalid time expressions -> rejected at Pydantic validation
        - Missing SANGFOR_BLOCKLIST_TOKEN -> clear RuntimeError
        - HTTP errors → surfaced through standard error handling
    """
    _audit_log("sangfor_blocklist_list", {"date_start": params.date_start, "limit": params.limit, "offset": params.offset})

    try:
        token = _get_sangfor_token()
    except RuntimeError as e:
        return json.dumps({"error": str(e)})

    # Resolve time window
    since_parsed, until_parsed = _parse_time_window(params.date_start, params.date_end)
    date_start = since_parsed.replace("T", " ").replace("Z", "")[:19] if since_parsed else ""
    date_end = until_parsed.replace("T", " ").replace("Z", "")[:19] if until_parsed else ""

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "accept": "application/json",
        "User-Agent": "blue-team-mcp/1.0.0 (TangerangKota-CSIRT)",
    }
    payload = {"date_start": date_start, "date_end": date_end, "limit": params.limit, "offset": params.offset}

    try:
        client = await _get_client("sangfor", verify=SANGFOR_BLOCKLIST_VERIFY_SSL, max_keepalive=2, max_connections=10)
        resp = await client.post(
            SANGFOR_BLOCKLIST_URL,
            headers=headers,
            json=payload,
            timeout=httpx.Timeout(SANGFOR_BLOCKLIST_TIMEOUT),
        )
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPStatusError as e:
        return _handle_api_error(e, context="sangfor_blocklist_list")
    except httpx.TimeoutException:
        return json.dumps({"error": f"Sangfor API timed out after {SANGFOR_BLOCKLIST_TIMEOUT}s"})
    except Exception as e:
        return json.dumps({"error": f"Sangfor API request failed: {e}"})

    if not isinstance(data, list):
        return json.dumps({"error": "Unexpected API response format", "raw_type": type(data).__name__})

    entries = data
    next_offset = params.offset + params.limit if len(entries) >= params.limit else None

    # Enrich each entry with severity mapping
    for entry in entries:
        if isinstance(entry, dict):
            entry["severity"] = _blockmode_severity(entry.get("blockmode", ""))

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({
            "window": {"date_start": date_start, "date_end": date_end},
            "pagination": {"limit": params.limit, "offset": params.offset, "next_offset": next_offset},
            "count": len(entries),
            "entries": entries,
        }, indent=2, default=str))

    # Markdown format
    severity_counts: dict[str, int] = {}
    for e in entries:
        sev = e.get("severity", "Unknown") if isinstance(e, dict) else "Unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines = [
        "# Sangfor Blocklist",
        "",
        f"**Window**: {date_start} → {date_end}",
        f"**Returned**: {len(entries)} entries (offset {params.offset})",
        "",
        "## Severity Distribution",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev, count in sorted(severity_counts.items()):
        lines.append(f"| {sev} | {count} |")
    lines.extend([
        "",
        "## Blocked IPs",
        "",
        "| IP | ISP | Location | Block Mode | Scores (W/T→Overall) | Created |",
        "|----|-----|----------|------------|----------------------|--------|",
    ])
    for entry in entries:
        if isinstance(entry, dict):
            lines.append(_format_sangfor_entry_markdown(entry))

    if next_offset is not None:
        lines.append("")
        lines.append(f"**next_offset**: `{next_offset}` — pass as `offset` parameter for the next page.")

    return "\n".join(lines)


# ThreatFox by abuse.ch (APT attribution)
THREATFOX_API_KEY_ENV = "THREATFOX_API_KEY"
THREATFOX_BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"
_threatfox_cache: dict[str, tuple[float, dict[str, Any]]] = {}
THREATFOX_CACHE_TTL = 900
_threatfox_semaphore = asyncio.Semaphore(10)  # built-in rate limit: 10 concurrent requests


def _get_threatfox_api_key() -> str:
    key = os.environ.get(THREATFOX_API_KEY_ENV, "")
    if not key:
        raise RuntimeError(f"{THREATFOX_API_KEY_ENV} not set")
    return key


async def _threatfox_request(search_term: str, exact_match: bool = False) -> dict[str, Any]:
    """Query ThreatFox search_ioc. Cache hits skip rate limiter."""
    now = time.monotonic()
    cache_key = f"{search_term}:{exact_match}"
    if cache_key in _threatfox_cache:
        expiry, data = _threatfox_cache[cache_key]
        if now < expiry:
            return data
    async with _threatfox_semaphore:  # rate limit: max 10 concurrent HTTP calls
        headers = {"Auth-Key": _get_threatfox_api_key(), "Content-Type": "application/json"}
        body = {"query": "search_ioc", "search_term": search_term, "exact_match": exact_match}
        resp = await _api_call("post", THREATFOX_BASE_URL, headers=headers, json=body)
        data = resp.json()
    if data.get("query_status") == "ok":
        _threatfox_cache[cache_key] = (now + THREATFOX_CACHE_TTL, data)
    return data


def _format_threatfox_markdown(ip: str, data: dict) -> str:
    items = data.get("data", [])
    if not items:
        return f"# ThreatFox — `{ip}`\\n\\nNo ThreatFox data. IP not linked to known malware."
    lines = [f"# ThreatFox — `{ip}`", ""]
    for i, entry in enumerate(items[:10]):
        malware = entry.get("malware_printable") or entry.get("malware", "unknown")
        lines.append(f"## Match {i+1}: `{entry.get('ioc', ip)}`")
        lines.append(f"- **Malware**: {malware}")
        lines.append(f"- **Type**: {entry.get('threat_type_desc', entry.get('threat_type', '?'))}")
        lines.append(f"- **Confidence**: {entry.get('confidence_level', '?')}/100")
        lines.append(f"- **First seen**: {(entry.get('first_seen') or '?')[:19]}")
        last = entry.get('last_seen')
        lines.append(f"- **Last seen**: {last[:19] if last else 'still active'}")
        if entry.get("malware_alias"):
            lines.append(f"- **Aliases**: {entry['malware_alias']}")
        lines.append("")
    return "\\n".join(lines)


class ThreatFoxIpLookupInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: ValidPublicIp = Field(..., min_length=3, max_length=45)
    exact_match: bool = Field(default=False)
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@mcp.tool(
    name="threatfox_ip_lookup",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
)
async def threatfox_ip_lookup(params: ThreatFoxIpLookupInput) -> str:
    """Query ThreatFox by abuse.ch for IP → malware family attribution.

    Maps attacker IPs to specific malware families (Cobalt Strike, Emotet, etc.)
    with confidence scores — essential for APT group attribution.

    Requires THREATFOX_API_KEY env var.

    **Worked Examples**
    1. *Check an attacker IP*:
       ``threatfox_ip_lookup(ip="139.180.203.104")``
    2. *JSON output*:
       ``threatfox_ip_lookup(ip="139.180.203.104", response_format="json")``
    """
    _audit_log("threatfox_ip_lookup", {"ip": params.ip})
    try:
        data = await _threatfox_request(params.ip, params.exact_match)
    except Exception as e:
        return _handle_api_error(e, context="threatfox")
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"ip": params.ip, "threatfox": data}, indent=2))
    return _truncate_if_needed(_format_threatfox_markdown(params.ip, data))


class ThreatFoxIpLookupBulkInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ips: list[str] = Field(..., min_length=1, max_length=25)
    exact_match: bool = Field(default=False)
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, v):
        for ip in v:
            try: ipaddress.ip_address(ip.strip())
            except ValueError: raise ValueError(f"Invalid IP: {ip}")
        return v


@mcp.tool(
    name="threatfox_ip_lookup_bulk",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
)
async def threatfox_ip_lookup_bulk(params: ThreatFoxIpLookupBulkInput) -> str:
    """Check multiple IPs against ThreatFox concurrently (max 25)."""
    _audit_log("threatfox_ip_lookup_bulk", {"count": len(params.ips)})

    async def _lookup_one(ip: str) -> dict:
        try:
            data = await _threatfox_request(ip.strip(), params.exact_match)
            items = data.get("data", [])
            return {"ip": ip, "matches": len(items),
                    "malware": [e.get("malware_printable") or e.get("malware", "?") for e in items[:3]],
                    "confidence": max((e.get("confidence_level", 0) for e in items), default=0)}
        except Exception as e:
            return {"ip": ip, "error": _handle_api_error(e, context=ip)}

    results = await asyncio.gather(*[_lookup_one(ip) for ip in params.ips])
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(results, indent=2))
    lines = ["# ThreatFox Bulk Lookup", ""]
    for r in results:
        if "error" in r:
            lines.append(f"- **{r['ip']}** — {r['error']}")
        elif r["matches"] == 0:
            lines.append(f"- `{r['ip']}` — clean")
        else:
            lines.append(f"- `{r['ip']}` — {r['matches']} matches, malware: {', '.join(r['malware'][:3])}, confidence: {r['confidence']}/100")
    return _truncate_if_needed("\\n".join(lines))


# 3 Sum Threat Detection Correlation Tool
class ThreeSumCorrelationInput(BaseModel):
    """Evaluate 3-Sum threat detection across Wazuh alert categories.

    Runs two correlation engines:

    **Engine A — Multi-IoC Risk Thresholding**: Finds external IPs (srcip)
    appearing in alerts from 3 distinct categories within the time window,
    sums per-category risk scores, and flags combinations meeting or exceeding
    ``threshold_score`` (default 10, minimum 3+4+4=11 for default category scores).

    **Engine B — 3-Source Volumetric Z-Score**: Fetches per-minute alert counts
    from the same 3 categories, computes rolling mean and standard deviation
    over the sliding window, and triggers when all 3 sources simultaneously
    cross ``z_score_threshold`` in the same 1-minute bucket.

    Default category mappings reflect TangerangKota-CSIRT's infrastructure:
    recon (web/WAF), access_anomaly (auth/mail), c2_exfil (firewall/IDS).

    Requires: WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD env vars.
    Rate limits: Queries 4 Indexer aggregations per invocation (1 for Engine A
    with 3 grouped terms, 3 for Engine B's date_histograms).

    **Worked Examples**

    1. *Default scan over last 30 minutes*:
       ``three_sum_correlation()`` — returns any 3-sum triggers

    2. *Custom threshold + 1-hour window*:
       ``three_sum_correlation(time_window_minutes=60, threshold_score=12, z_score_threshold=3.0)``

    3. *Suppress known vendor scanner*:
       ``three_sum_correlation(exclude_srcips=["203.0.113.42"])``

    4. *Opt-in CIDR normalization for distributed attacks*:
       ``three_sum_correlation(cidr_normalize=true)`` — groups srcips to /24
       before evaluating intersection (catches attackers rotating last octet)

    5. *No events in window*:
       Returns ``{"engine_a": {"stats": {"intersection_count": 0}}, ...}``
       with summary "Engine-A: no threshold crossings".
    """

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    engine_a_enabled: bool = Field(
        default=True,
        description="Enable Engine A (Multi-IoC Risk Thresholding).",
    )
    engine_b_enabled: bool = Field(
        default=True,
        description="Enable Engine B (Volumetric Z-Score Anomaly Detection).",
    )
    time_window_minutes: int = Field(
        default=DEFAULT_WINDOW_MINUTES,
        ge=5,
        description="Sliding time window in minutes (minimum 5, no upper bound). Default: 30.",
    )
    threshold_score: int = Field(
        default=DEFAULT_THRESHOLD_SCORE,
        ge=6,
        le=30,
        description="Minimum combined risk score to trigger Engine A. Default: 10.",
    )
    z_score_threshold: float = Field(
        default=DEFAULT_Z_THRESHOLD,
        ge=1.0,
        le=5.0,
        description="Minimum Z-score to flag a bucket as anomalous in Engine B. Default: 2.5.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="Output format: 'markdown' (default, human-readable) or 'json' (machine-readable).",
    )
    categories_map: Optional[dict[str, dict[str, Any]]] = Field(
        default=None,
        description="Alternative compact syntax for category definitions. "
                    "Keys are category labels, values are dicts with 'groups' (list[str]) "
                    "and optional 'score' (int). Overrides category_*_groups/labels/scores when set. "
                    'Example: {"recon": {"groups": ["web_attack", "xss"], "score": 3}, "access_anomaly": {...}}.',
    )
    throttle: int = Field(
        default=0,
        ge=0,
        description="Minimum seconds between Indexer queries. 0 = disabled (default). "
                    "When > 0, repeated calls within the throttle window return a cached/quiet "
                    "response without hitting the Indexer. Prevents accidental resource exhaustion.",
    )
    use_mitre: bool = Field(
        default=False,
        description="Enable MITRE ATT&CK tactic refinement for Engine A classification. "
                    "When True, applies α=0.6 groups + β=0.4 mitre.tactic weighted scoring. "
                    "Dual-counts multi-tactic alerts (opt-in, default False).",
    )
    category_a_groups: list[str] = Field(
        default=["web", "attack", "webshell", "webshell_scan", "scan", "recon",
                 "evasion", "case_variation", "asp_extension", "syscheck", "accesslog",
                 "sqlinjection", "lfi", "rfi", "xss", "rce", "command_injection",
                 "vulnerability_scan", "encoded_payload", "injection", "suspicious_wp",
                 "path_traversal", "dir_traversal", "suspicious_url", "user_agent",
                 "suspicious_ua", "malicious_request", "content_violation", "web_scan",
                 "gambling"],
        description="Wazuh rule.groups for Category A (Recon/Probe). "
                    "Atomic tokens (web, attack, scan, recon, etc.) verified against "
                    "wazuh-alerts-4.x-2026.07.08 production index. TangerangKota-CSIRT taxonomy.",
    )
    category_b_groups: list[str] = Field(
        default=["authentication_failures", "bruteforce", "malicious_login", "blocklist",
                 "blacklist", "credential_breach", "account_compromised", "zimbra",
                 "spam", "postfix"],
        description="Wazuh rule.groups for Category B (Access Anomaly). "
                    "Partially validated against Zimbra alerts (authentication_failures, "
                    "bruteforce, blocklist, zimbra all present). MCP-TAXONOMY-V2: "
                    "spam/postfix included to capture mail-infrastructure reject scans. "
                    "TangerangKota-CSIRT taxonomy.",
    )
    category_c_groups: list[str] = Field(
        default=["firewall_drop", "exfiltration", "overflow", "opencti", "persistent",
                 "backdoor", "common_webshell", "react2shell", "defacement"],
        description="Wazuh rule.groups for Category C (C2/Exfil/Maintain). "
                    "UNVERIFIED — no production index diagnostic has been run. "
                    "May suffer same atomic-vs-compound mismatch as Category A. "
                    "MCP-TAXONOMY-V2: diagnostic scan required before trusting Engine A results.",
    )
    category_a_label: str = Field(
        default="recon",
        description="Human-readable label for Category A.",
    )
    category_b_label: str = Field(
        default="access_anomaly",
        description="Human-readable label for Category B.",
    )
    category_c_label: str = Field(
        default="c2_exfil",
        description="Human-readable label for Category C.",
    )
    category_a_score: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Risk score per srcip in Category A. Default: 3.",
    )
    category_b_score: int = Field(
        default=4,
        ge=1,
        le=10,
        description="Risk score per srcip in Category B. Default: 4.",
    )
    category_c_score: int = Field(
        default=4,
        ge=1,
        le=10,
        description="Risk score per srcip in Category C. Default: 4.",
    )
    cidr_normalize: bool = Field(
        default=False,
        description="Group srcips by /24 (IPv4) or /64 (IPv6) before intersection. Opt-in — disabled by default to avoid false matches from IP rotation.",
    )
    follow_up: Literal["none", "curated_report"] = Field(
        default="none",
        description="'none' = return 3-Sum results only. 'curated_report' = automatically run "
                    "curated threat report enrichment for each Engine-A trigger IP.",
    )
    exclude_srcips: list[str] = Field(
        default=[],
        description="Srcips to suppress before scoring (e.g., known vendor scanners). Evaluated early; matching IPs are dropped from all categories.",
    )


@mcp.tool(
    name="three_sum_correlation",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def three_sum_correlation(data: ThreeSumCorrelationInput) -> str:
    """Evaluate 3-Sum APT threat detection across 3 Wazuh alert categories.

    Runs Engine A (Multi-IoC Risk Thresholding via terms aggregation on
    data.srcip.keyword) and Engine B (3-source volumetric Z-score via
    date_histogram aggregation) concurrently. Both engines target the
    Wazuh Indexer API (read-only ``_search`` endpoint with ``size: 0``).

    Returns a JSON object with per-engine triggers, statistics, and a
    human-readable summary. All Indexer queries are aggregated — no
    individual alert documents are fetched, keeping memory bounded.

    **Required Permissions**: Wazuh Indexer user with ``read`` access to
    ``wazuh-alerts-*`` indices.
    """
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({
            "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set.",
            "detail": "Set these environment variables and restart to use the 3-Sum correlation engine.",
        }, indent=2)

    start_time = time.monotonic()

    # Throttle gate: skip Indexer query if within quiet period
    global _last_eval_time, _last_eval_result
    if data.throttle > 0 and _last_eval_time > 0:
        elapsed = start_time - _last_eval_time
        if elapsed < data.throttle:
            logger.info(
                "[3SUM-EVAL] Throttled — %.1fs since last evaluation (throttle=%ds). Returning cached result.",
                elapsed, data.throttle,
            )
            cached = dict(_last_eval_result) if _last_eval_result else {}
            cached["meta"] = dict(cached.get("meta", {}))
            cached["meta"]["throttled"] = True
            cached["meta"]["throttle_elapsed_s"] = round(elapsed, 1)
            return json.dumps(cached, indent=2)

    # Parse time window
    since_dt = (datetime.utcnow() - timedelta(minutes=data.time_window_minutes))
    until_dt = datetime.utcnow()
    since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    until_iso = until_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    logger.info(
        "[3SUM-EVAL] Starting evaluation window=%s -> %s (engineA=%s engineB=%s threshold=%d z=%.1f)",
        since_iso, until_iso,
        data.engine_a_enabled, data.engine_b_enabled,
        data.threshold_score, data.z_score_threshold,
    )

    try:
        engine_a_results = None
        engine_b_result = None

        # categories_map override: unpack compact syntax into flat fields
        cat_a_groups = data.category_a_groups
        cat_b_groups = data.category_b_groups
        cat_c_groups = data.category_c_groups
        cat_a_label = data.category_a_label
        cat_b_label = data.category_b_label
        cat_c_label = data.category_c_label
        if data.categories_map is not None:
            cm = data.categories_map
            # Each entry: {"groups": [...], "score": N (optional)}
            labels = list(cm.keys())
            if len(labels) != 3:
                return json.dumps({
                    "error": "categories_map must have exactly 3 entries (one per category).",
                    "detail": f"Got {len(labels)}: {labels}",
                }, indent=2)
            cat_a_label, cat_b_label, cat_c_label = labels[0], labels[1], labels[2]
            cat_a_groups = cm[cat_a_label].get("groups", [])
            cat_b_groups = cm[cat_b_label].get("groups", [])
            cat_c_groups = cm[cat_c_label].get("groups", [])
            logger.info(
                "[3SUM-EVAL] Using categories_map override: %s (%d groups), %s (%d groups), %s (%d groups)",
                cat_a_label, len(cat_a_groups), cat_b_label, len(cat_b_groups), cat_c_label, len(cat_c_groups),
            )

        # Engine A: terms aggregation per category (3 parallel queries)
        if data.engine_a_enabled:
            label_to_groups = [
                (cat_a_label, cat_a_groups),
                (cat_b_label, cat_b_groups),
                (cat_c_label, cat_c_groups),
            ]

            async def _fetch_srcip_terms(label: str, groups: list[str]) -> tuple[str, list[tuple[str, int]], dict[str, list[str]]]:
                """Fetch distinct srcips and their max rule.level per category via terms agg.

                Returns (label, [(srcip, score), ...], {srcip: [tactic, ...]}) where the
                third element is MITRE tactic data per srcip (empty dict when use_mitre=False).
                """
                aggs_inner: dict[str, Any] = {"max_level": {"max": {"field": "rule.level"}}}
                if data.use_mitre:
                    aggs_inner["sample_mitre"] = {
                        "top_hits": {"size": 1, "_source": {"includes": ["rule.mitre"]}},
                    }
                body = {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": since_iso,
                                            "lt": until_iso,
                                            "format": "strict_date_optional_time",
                                        },
                                    }
                                },
                                {
                                    "bool": {
                                        "should": [
                                            {"terms": {"rule.groups": groups}},
                                            {"terms": {"rule.groups.keyword": groups}},
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                },
                            ]
                        }
                    },
                    "aggs": {
                        "unique_srcips": {
                            "multi_terms": {
                                "terms": [{"field": f} for f in _SRCIP_FIELD_PATHS],
                                "size": 10000,
                                "min_doc_count": 1,
                            },
                            "aggs": aggs_inner,
                        }
                    },
                }
                raw = await _wazuh_indexer_post(body, _WAZUH_INDEX_PATTERNS["alerts"])
                if "error" in raw:
                    logger.warning("[3SUM-EVAL] Engine-A query failed for %s: %s", label, raw["error"])
                    return (label, [], {})

                buckets = raw.get("aggregations", {}).get("unique_srcips", {}).get("buckets", [])
                entries: list[tuple[str, int]] = []
                mitre_samples: dict[str, list[str]] = {}
                for b in buckets:
                    # multi_terms returns compound keys: [val_or_null per field path]
                    # Extract the first non-null IP from the key array
                    raw_key = b["key"]
                    if isinstance(raw_key, list):
                        srcip = next((v for v in raw_key if v is not None), "0.0.0.0")
                    else:
                        srcip = raw_key  # fallback for single-term compatibility
                    score = int(b.get("max_level", {}).get("value", 1))
                    entries.append((srcip, score))
                    if data.use_mitre:
                        hits = b.get("sample_mitre", {}).get("hits", {}).get("hits", [])
                        if hits and "_source" in hits[0]:
                            mitre_data = hits[0]["_source"].get("rule", {}).get("mitre", {})
                            tactics = mitre_data.get("tactic")
                            if tactics and isinstance(tactics, list):
                                mitre_samples[srcip] = list(tactics)
                return (label, entries, mitre_samples)

            label_a, label_b, label_c = (
                cat_a_label,
                cat_b_label,
                cat_c_label,
            )
            groups_a, groups_b, groups_c = (
                cat_a_groups,
                cat_b_groups,
                cat_c_groups,
            )

            fetched = await asyncio.gather(
                _fetch_srcip_terms(label_a, groups_a),
                _fetch_srcip_terms(label_b, groups_b),
                _fetch_srcip_terms(label_c, groups_c),
            )

            # Merge MITRE samples across all 3 categories
            all_mitre_samples: dict[str, list[str]] = {}
            if data.use_mitre:
                for _, _, mitre_samples in fetched:
                    for srcip, tactics in mitre_samples.items():
                        existing = all_mitre_samples.get(srcip, [])
                        all_mitre_samples[srcip] = list(set(existing + tactics))

            # Map label -> srcip list; apply CIDR normalization if requested
            srcips_by_label: dict[str, list[tuple[str, int]]] = {}
            label_to_cat = {label_a: "A", label_b: "B", label_c: "C"}
            cat_to_label = {"A": label_a, "B": label_b, "C": label_c}
            for label_ret, entries, _ in fetched:
                if data.cidr_normalize and entries:
                    ips = [e[0] for e in entries]
                    cidr_map = normalize_srcip_to_cidr(ips)
                    cidr_scores: dict[str, int] = {}
                    for srcip, score in entries:
                        cidr = cidr_map.get(srcip, srcip)
                        cidr_scores[cidr] = cidr_scores.get(cidr, 0) + score
                    srcips_by_label[label_ret] = [(cidr, score) for cidr, score in cidr_scores.items()]
                else:
                    srcips_by_label[label_ret] = list(entries)

            # MITRE overlay: dual-count srcips to additional categories via α+β scoring
            if data.use_mitre and all_mitre_samples:
                for srcip, tactics in all_mitre_samples.items():
                    for cat in ("A", "B", "C"):
                        target_label = cat_to_label[cat]
                        if any(e[0] == srcip for e in srcips_by_label.get(target_label, [])):
                            continue  # already classified via rule.groups
                        mitre_score, matching_tactic = _classify_alert_mitre(tactics, cat)
                        if mitre_score > 0:
                            for lbl in [label_a, label_b, label_c]:
                                for e in srcips_by_label.get(lbl, []):
                                    if e[0] == srcip:
                                        srcips_by_label[target_label].append((srcip, e[1]))
                                        logger.info(
                                            "[3SUM-EVAL] MITRE overlay: srcip=%s dual-counted "
                                            "to %s via tactic '%s' (β=%.1f, α=0.0, total=%.1f)",
                                            srcip, cat, matching_tactic, mitre_score, mitre_score,
                                        )
                                        break
                                else:
                                    continue
                                break

            triggers_a, stats_a = evaluate_engine_a(
                srcips_by_label.get(label_a, []),
                srcips_by_label.get(label_b, []),
                srcips_by_label.get(label_c, []),
                category_a_label=label_a,
                category_b_label=label_b,
                category_c_label=label_c,
                threshold_score=data.threshold_score,
                exclude_srcips=data.exclude_srcips if data.exclude_srcips else None,
            )

            engine_a_results = (triggers_a, stats_a)
            logger.info("[3SUM-EVAL] Engine-A evaluation complete — %d triggers", len(triggers_a))


        # Engine B: date_histogram per source (3 parallel queries)
        if data.engine_b_enabled:
            # Auto-select bucket interval based on time window (target ~60 buckets)
            window_mins = data.time_window_minutes
            b_interval = "1m"
            if window_mins > 120:
                b_interval = "5m"
            if window_mins > 600:
                b_interval = "15m"
            if window_mins > 1440:
                b_interval = "1h"

            async def _fetch_bucket_counts(label: str, groups: list[str]) -> tuple[str, list[dict[str, Any]]]:
                """Fetch per-minute alert counts for a single source."""
                body = {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": since_iso,
                                            "lt": until_iso,
                                            "format": "strict_date_optional_time",
                                        },
                                    }
                                },
                                {
                                    "bool": {
                                        "should": [
                                            {"terms": {"rule.groups": groups}},
                                            {"terms": {"rule.groups.keyword": groups}},
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                },
                            ]
                        }
                    },
                    "aggs": {
                        "alerts_over_time": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": b_interval,
                                "min_doc_count": 0,
                                "extended_bounds": {"min": since_iso, "max": until_iso},
                            }
                        }
                    },
                }
                raw = await _wazuh_indexer_post(body, _WAZUH_INDEX_PATTERNS["alerts"])
                if "error" in raw:
                    logger.warning("[3SUM-EVAL] Engine-B query failed for %s: %s", label, raw["error"])
                    return (label, [])

                buckets = (
                    raw.get("aggregations", {})
                    .get("alerts_over_time", {})
                    .get("buckets", [])
                )
                return (label, buckets)

            # All 3 source labels are the same categories
            label_a, label_b, label_c = (
                cat_a_label,
                cat_b_label,
                cat_c_label,
            )
            groups_a, groups_b, groups_c = (
                cat_a_groups,
                cat_b_groups,
                cat_c_groups,
            )

            fetched_b = await asyncio.gather(
                _fetch_bucket_counts(label_a, groups_a),
                _fetch_bucket_counts(label_b, groups_b),
                _fetch_bucket_counts(label_c, groups_c),
            )

            buckets_by_label: dict[str, list[dict[str, Any]]] = {}
            for label_ret, buckets in fetched_b:
                buckets_by_label[label_ret] = buckets

            # Query account lockout events for advisory volume signal.
            # Counts data.error events containing "locked" in the window —
            # never used as a scoring input, only metadata.
            account_lockouts_total = 0
            try:
                lockout_body = {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [
                                {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                                         "format": "strict_date_optional_time"}}},
                                {"query_string": {"query": "data.error: *locked*",
                                                  "default_operator": "AND"}},
                            ]
                        }
                    },
                }
                lockout_raw = await _wazuh_indexer_post(lockout_body, _WAZUH_INDEX_PATTERNS["alerts"])
                if "error" not in lockout_raw:
                    total = lockout_raw.get("hits", {}).get("total", {})
                    account_lockouts_total = total.get("value", 0) if isinstance(total, dict) else total
            except Exception:
                account_lockouts_total = 0  # advisory only — never fail the eval

            engine_b_result = evaluate_engine_b(
                buckets_by_label.get(label_a, []),
                buckets_by_label.get(label_b, []),
                buckets_by_label.get(label_c, []),
                source_1_label=label_a,
                source_2_label=label_b,
                source_3_label=label_c,
                z_score_threshold=data.z_score_threshold,
                account_lockouts_total=account_lockouts_total,
            )
            logger.info(
                "[3SUM-EVAL] Engine-B evaluation complete - %d simultaneous triggers",
                len(engine_b_result["simultaneous_triggers"]),
            )

        # Build unified result
        elapsed_ms = (time.monotonic() - start_time) * 1000

        result = format_evaluation_dict(
            window_since=since_iso,
            window_until=until_iso,
            engine_a_results=engine_a_results,
            engine_b_result=engine_b_result,
            evaluation_time_ms=elapsed_ms,
        )

        # Cache result for throttle gate
        _last_eval_time = time.monotonic()
        _last_eval_result = result

        # Follow-up: auto-enrich trigger IPs via curated report
        if data.follow_up == "curated_report" and engine_a_results:
            triggers, _ = engine_a_results
            if triggers:
                fu_results: list[dict] = []
                for t in triggers[:5]:  # cap at 5 to avoid rate limits
                    ip = t["srcip"]
                    try:
                        fu_filters = CuratedReportFilters(srcips=[ip])
                        fu_since = since_iso
                        fu_until = until_iso
                        fu_clauses = _build_curated_query(fu_since, fu_until, fu_filters)
                        fu_body = {
                            "size": 0,
                            "query": {"bool": {"must": fu_clauses}},
                            "aggs": {
                                "top_rules": {"terms": {"field": "rule.id.keyword", "size": 5}},
                                "total_alerts": {"value_count": {"field": "_id"}},
                            },
                        }
                        fu_raw = await _wazuh_indexer_post(fu_body, _WAZUH_INDEX_PATTERNS["alerts"])
                        if "error" not in fu_raw:
                            fu_aggs = fu_raw.get("aggregations", {})
                            fu_results.append({
                                "srcip": ip,
                                "total_alerts": fu_aggs.get("total_alerts", {}).get("value", 0),
                                "top_rules": [
                                    {"id": b["key"], "count": b["doc_count"]}
                                    for b in fu_aggs.get("top_rules", {}).get("buckets", [])
                                ],
                                "three_sum_score": t["total_score"],
                            })
                    except Exception:
                        fu_results.append({"srcip": ip, "error": "follow_up_failed"})
                result["follow_up"] = {"mode": "curated_report", "results": fu_results}

        logger.info("[3SUM-EVAL] Evaluation finished — %d ms", round(elapsed_ms))
        return json.dumps(result, indent=2)

    except httpx.HTTPStatusError as e:
        return json.dumps({
            "error": f"Wazuh Indexer error: HTTP {e.response.status_code}",
            "detail": str(e)[:500],
        }, indent=2)
    except Exception as e:
        logger.exception("[3SUM-EVAL] Unexpected error during evaluation")
        return json.dumps({
            "error": f"Correlation evaluation failed: {type(e).__name__}",
            "detail": str(e),
        }, indent=2)


# Case insensitive tool lookup transparently handles LLM casing variations.
# When an LLM generates a tool call like "CrowdSec_IP_Reputation" instead of
# "crowdsec_ip_reputation", this layer normalizes the name before the FastMCP
# dispatcher sees it — no user configuration required. The fast path (exact
# match via dict.get) adds zero overhead for correctly-cased calls.
_original_get_tool = mcp._tool_manager.get_tool

_tool_name_index: dict[str, str] = {
    name.casefold(): name
    for name in mcp._tool_manager._tools
}


def _case_insensitive_get_tool(name: str):
    """Case-insensitive tool lookup via casefold normalization.

    **Fast path** (exact match): ``dict.get(name)`` — O(1), no allocation.
    Used for every correct call; handles 99.9% of traffic with zero overhead.

    **Slow path** (case-insensitive fallback): walks the ``_tool_name_index``
    on first mismatch per session, then caches the canonical name.  Handles
    LLM casing drift (e.g. ``CrowdSecIpReputation`` → ``crowdsec_ip_reputation``).
    """
    tool = mcp._tool_manager._tools.get(name)
    if tool is not None:
        return tool
    canonical = _tool_name_index.get(name.casefold())
    if canonical is not None:
        return mcp._tool_manager._tools[canonical]
    return None


mcp._tool_manager.get_tool = _case_insensitive_get_tool

logger.info(
    "Tool router: case-insensitive matching active (%d tools indexed). "
    "LLM casing variations in tool names will be normalized automatically.",
    len(_tool_name_index),
)


# ENTRY POINT / TRANSPORT SELECTION
def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with multi-transport support."""
    parser = argparse.ArgumentParser(
        description="blue_team_mcp - Unified blue-team MCP server (TangerangKota-CSIRT)"
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable_http", "http"],
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
        help="MCP transport to use (default: stdio, or env MCP_TRANSPORT).",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("MCP_HOST", "127.0.0.1"),
        help="Bind host for streamable_http transport (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("MCP_PORT", "8000")),
        help="Port for streamable_http transport (default: 8000).",
    )
    return parser


def _validate_configuration() -> None:
    """Validate required secrets at startup and warn on missing optional credentials.
    on missing configuration. All API keys are optional (the server starts
    without them and tools that need them return actionable errors at call
    time), but we emit clear WARNINGs so operators know which tools will be
    unavailable before a request fails.
    """
    _check_key = [
        ("CROWDSEC_API_KEY", "https://docs.crowdsec.net/docs/cti_api/getting_started"),
        ("ABUSEIPDB_API_KEY", "https://docs.abuseipdb.com/"),
        ("VIRUSTOTAL_API_KEY", "https://docs.virustotal.com/reference/overview"),
        ("NETRA_API_KEY", "https://netra.tangerangkota.go.id/docs"),
        ("ARGUS_API_KEY", "https://argus.tangerangkota.go.id/docs"),
    ]
    for env_var, doc_url in _check_key:
        if not os.environ.get(env_var, "").strip():
            label = env_var.removesuffix("_API_KEY")
            logger.warning(
                "%s is not set — %s tools will be unavailable. "
                "Set the environment variable and restart. Docs: %s",
                env_var, label, doc_url
            )

    if not os.environ.get("WAZUH_API_URL", "").strip():
        logger.warning(
            "WAZUH_API_URL is not set — Wazuh Manager API tools "
            "(blueteam_wazuh_agents, blueteam_wazuh_manager_logs, etc.) "
            "will be unavailable."
        )
    if not os.environ.get("WAZUH_INDEXER_URL", "").strip():
        logger.warning(
            "WAZUH_INDEXER_URL is not set — Wazuh Indexer/OpenSearch tools "
            "(blueteam_wazuh_indexer_search, wazuh_email_lookup, etc.) "
            "will be unavailable."
        )

    # WAZUH_INDEXER_MAX_SIZE guard - warn if it exceeds OpenSearch's default max_result_window
    if _WAZUH_INDEXER_MAX_SIZE > 10000:
        logger.warning(
            "WAZUH_INDEXER_MAX_SIZE is %d — this exceeds OpenSearch's default "
            "index.max_result_window of 10,000. Indexer queries using size > 10000 "
            "will fail unless the cluster limit has been raised. "
            "Set WAZUH_INDEXER_MAX_SIZE=10000 (or lower) to stay within defaults.",
            _WAZUH_INDEXER_MAX_SIZE,
        )


def main() -> None:
    """Start the MCP server on the selected transport."""
    _validate_configuration()
    args = _build_arg_parser().parse_args()

    if args.transport == "stdio":
        logger.info("Starting %s via stdio transport", _MCP_SERVER_NAME)
        logger.info(
            "MCP server name: '%s'. Ensure your MCP client config uses "
            "an all-lowercase server name to prevent LLM casing mismatches "
            "(e.g. 'blue-team-mcp' not 'BlueTeamMCP').",
            _MCP_SERVER_NAME,
        )
        mcp.run(transport="stdio")
        return

    # FastMCP sets host/port via settings attributes before .run() is called.
    mcp.settings.host = args.host
    mcp.settings.port = args.port

    # Update transport security to allow the actual host the client connects to.
    # FastMCP auto-enables DNS rebinding protection for localhost only
    # binding to a different IP (e.g. 172.16.9.125 or 0.0.0.0) must add it
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

    if args.transport in ("streamable_http", "http"):
        logger.info(
            "Starting %s via Streamable HTTP transport on %s:%s",
            _MCP_SERVER_NAME,
            args.host,
            args.port,
        )
        mcp.run(transport="streamable-http")
    else:  # pragma: no cover - unreachable due to argparse choices
        raise ValueError(f"Unknown transport: {args.transport}")


if __name__ == "__main__":
    main()
