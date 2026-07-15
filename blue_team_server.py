#!/usr/bin/env python3
"""
Blue Team MCP Server
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
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from collections import Counter
from typing import Any, Dict, List, Optional
import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, AliasChoices, field_validator, model_validator
from pydantic import AfterValidator
from typing import Annotated

# 3-Sum Correlation Engine
from correlation.three_sum_engine import (
    evaluate_engine_a,
    evaluate_engine_b,
    format_evaluation_dict,
    normalize_srcip_to_cidr,
    DEFAULT_THRESHOLD_SCORE,
    DEFAULT_Z_THRESHOLD,
    DEFAULT_WINDOW_MINUTES,
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

# Shared HTTP / response config
HTTP_TIMEOUT = 30.0
CHARACTER_LIMIT = int(os.environ.get("BLUETEAM_CHARACTER_LIMIT", "100000"))
_WAZUH_INDEXER_MAX_SIZE = int(os.environ.get("WAZUH_INDEXER_MAX_SIZE", "10000"))
BLUETEAM_ALLOW_UNTRUNCATED = os.environ.get("BLUETEAM_ALLOW_UNTRUNCATED", "false").lower() in ("1", "true", "yes")
if BLUETEAM_ALLOW_UNTRUNCATED:
    logger.warning(
        "BLUETEAM_ALLOW_UNTRUNCATED=true — character-limit bypass and include_all_docs are ENABLED. "
        "Unbounded response payloads may exhaust LLM context windows or MCP transport buffers. "
        "Use only for forensic deep-dives with explicit scope constraints (small time windows, "
        "specific agents/IPs, conservative max_scanned values)."
    )
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
    if unit == "s":
        return timedelta(seconds=n)
    elif unit == "m":
        return timedelta(minutes=n)
    elif unit == "h":
        return timedelta(hours=n)
    elif unit == "d":
        return timedelta(days=n)
    elif unit == "w":
        return timedelta(weeks=n)
    return timedelta(days=365)  # fallback — shouldn't happen with validated regex


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
    if isinstance(e, CircuitBreakerOpenError):
        return f"{prefix}Error: Circuit breaker is open — {e}"
    if isinstance(e, RuntimeError):
        return f"{prefix}Error: {e}"
    logger.exception("Unexpected error in %s", context)
    return f"{prefix}Error: Unexpected error ({type(e).__name__})."

def _truncate_if_needed(text: str, *, bypass: bool = False) -> str:
    """Cap response at CHARACTER_LIMIT to keep MCP messages manageable.

    Args:
        text: The response text to potentially truncate.
        bypass: When True AND BLUETEAM_ALLOW_UNTRUNCATED is enabled, return the
                text without truncation. Ignored (treated as False) unless the
                environment guard is active — this prevents callers from
                accidentally bypassing the safety cap without admin approval.
    """
    if bypass and BLUETEAM_ALLOW_UNTRUNCATED:
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
# CLOSED - normal operation, calls pass through
# OPEN - fail-fast for recovery_timeout seconds after failure_threshold failures
# HALF_OPEN - single probe call allowed; success -> CLOSED, failure -> OPEN
class CircuitBreakerOpenError(Exception):
    """Raised when a call is attempted while the circuit breaker is OPEN."""

class CircuitBreaker:
    """Async-safe circuit breaker for external API calls.

    Usage:
        cb = CircuitBreaker("crowdsec", failure_threshold=5, recovery_timeout=60)
        data = await cb.call(_crowdsec_request, f"/v2/smoke/{ip}")
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failure_count = 0
        self._state: str = "CLOSED"  # CLOSED | OPEN | HALF_OPEN
        self._opened_at: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> str:
        return self._state

    async def call(self, fn, *args: Any, **kwargs: Any) -> Any:
        """Execute ``fn(*args, **kwargs)`` with circuit-breaker protection.

        Returns the callable's result on success.
        Raises ``CircuitBreakerOpenError`` if the circuit is OPEN.
        Re-raises the original exception on failure.
        """
        async with self._lock:
            now = time.monotonic()

            if self._state == "OPEN":
                if now - self._opened_at >= self.recovery_timeout:
                    self._state = "HALF_OPEN"
                    logger.info(
                        "Circuit breaker '%s' → HALF_OPEN (probing after %.0fs timeout)",
                        self.name, self.recovery_timeout,
                    )
                else:
                    remaining = self.recovery_timeout - (now - self._opened_at)
                    logger.warning(
                        "Circuit breaker '%s' is OPEN — failing fast (%.0fs remaining)",
                        self.name, remaining,
                    )
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker '{self.name}' is OPEN. "
                        f"Upstream API is unavailable. Retry in {remaining:.0f}s."
                    )

        # Execute the call outside the lock to avoid blocking concurrent callers
        try:
            result = await fn(*args, **kwargs)
        except Exception:
            async with self._lock:
                self._failure_count += 1
                if self._state == "HALF_OPEN":
                    logger.warning(
                        "Circuit breaker '%s' HALF_OPEN probe FAILED (%d/%d) → OPEN",
                        self.name, self._failure_count, self.failure_threshold,
                    )
                    self._state = "OPEN"
                    self._opened_at = time.monotonic()
                elif self._failure_count >= self.failure_threshold:
                    logger.error(
                        "Circuit breaker '%s' threshold reached (%d failures) → OPEN",
                        self.name, self._failure_count,
                    )
                    self._state = "OPEN"
                    self._opened_at = time.monotonic()
            raise

        # Success — reset
        async with self._lock:
            if self._state == "HALF_OPEN":
                logger.info(
                    "Circuit breaker '%s' HALF_OPEN probe SUCCEEDED → CLOSED", self.name,
                )
            self._failure_count = 0
            self._state = "CLOSED"

        return result


# Per-service circuit breakers - one per external API trust domain
_cb_crowdsec = CircuitBreaker("crowdsec_cti", failure_threshold=5, recovery_timeout=60)
_cb_wazuh_manager = CircuitBreaker("wazuh_manager", failure_threshold=5, recovery_timeout=60)
_cb_wazuh_indexer = CircuitBreaker("wazuh_indexer", failure_threshold=5, recovery_timeout=60)
_cb_argus = CircuitBreaker("argus_ti", failure_threshold=5, recovery_timeout=60)


# PII redaction patterns - applied to alert payloads when BLUETEAM_REDACT_PII is enabled
_REDACT_EMAIL_RE = re.compile(r"([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
_REDACT_HOSTNAME_RE = re.compile(r"(?<![a-zA-Z0-9-])([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9]+))(?![a-zA-Z0-9.])")

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
    # AWS access key IDs: "AKIA" plus secret key pattern "wJalrXUtn..."
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), '<AWS_ACCESS_KEY_REDACTED>'),
    # Stripe secret keys: sk_live_ / sk_test_
    (re.compile(r'\bsk_(?:live|test)_[a-zA-Z0-9]{24,}\b'), '<STRIPE_KEY_REDACTED>'),
    # GitHub personal access tokens: ghp_*, gho_*, ghu_*, ghs_*, ghr_*
    (re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{36,}\b'), '<GITHUB_TOKEN_REDACTED>'),
    # GitLab personal access tokens: glpat-
    (re.compile(r'\bglpat-[A-Za-z0-9_-]{20,}\b'), '<GITLAB_TOKEN_REDACTED>'),
    # OpenAI / Anthropic API keys: sk- (but NOT Stripe sk_live/sk_test which are handled above)
    (re.compile(r'\b(?:sk-(?!live|test)|sk-ant-)[a-zA-Z0-9_-]{20,}\b'), '<AI_API_KEY_REDACTED>'),
    # Generic password/secret/passwd/pwd query params or inline: "password=value" -> "password=<REDACTED>"
    (re.compile(r'(password|passwd|pwd|secret)\s*[=:]\s*\S+', re.IGNORECASE),
     r'\1=<PASSWORD_REDACTED>'),
    # Slack tokens: xoxb-, xoxp-, xoxa-, xoxr-
    (re.compile(r'\bxox[abpro]-[0-9]+-[0-9]+-[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)?\b'),
     '<SLACK_TOKEN_REDACTED>'),
    # Google API keys: AIza (35 chars)
    (re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b'), '<GOOGLE_API_KEY_REDACTED>'),
]

# Forensic email hashing — preserves domain visibility for SOC analysis while
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

        echo -n "<salt>:admin@corp.gov" | sha256sum | cut -c1-8

    and matching the result against the ``[h:xxxxxxxx]`` suffix in the output.
    """
    return hashlib.sha256(f"{_REDACT_SALT}:{email}".encode()).hexdigest()[:8]


def _redact_alert_data(data: Any, *, bypass: bool = False) -> Any:
    """Apply redacted-but-real PII and credential masking to alert payloads (PRD FR-17).

    **Three independent layers — apply in strict priority order:**

    1. **Credential stripping** (layer 1 — MANDATORY, never configurable):
       Bearer tokens, Basic auth, API keys, JWTs, PEM keys, cloud/VCS/AI/Slack/
       Stripe/Google keys, and password params are ALWAYS stripped.  There is no
       legitimate operational use case for sending credentials to an LLM.

    2. **Email redaction** (layer 2 — controlled by ``BLUETEAM_REDACT_EMAILS``):
       Masks the local part (preserving first/last char + forensic hash), keeps
       the domain FULLY visible for threat intelligence.  Set to ``false`` when
       SOC analysts need to identify specific compromised accounts.

    3. **Internal IP masking** (layer 3 — controlled by ``BLUETEAM_REDACT_PII``):
       Masks RFC1918 addresses (10.x, 172.16-31.x, 192.168.x).  **Public IPs
       (attacker IoCs) are NEVER masked** — only internal infrastructure addresses.

    The per-call ``bypass`` parameter skips layers 2 and 3 only — credential
    stripping can NEVER be bypassed because it has no legitimate use case.

    Returns the redacted copy — original is never mutated.
    """
    if isinstance(data, str):
        # Layer 1: Credential stripping (MANDATORY — no env var override) ──
        # These patterns protect against secrets in Wazuh full_log fields.
        # Bypass is NOT honored here — credentials must never reach the LLM.
        for pattern, replacement in _CREDENTIAL_STRIP_RULES:
            data = pattern.sub(replacement, data)

        # Layer 2: Email redaction (BLUETEAM_REDACT_EMAILS) ──
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

        # Layer 3: RFC1918 internal IP masking (BLUETEAM_REDACT_PII) ──
        # Public IPs (attacker IoCs) are NEVER masked — only internal infra.
        if not bypass and BLUETEAM_REDACT_PII:
            def _redact_rfc1918(m: re.Match) -> str:
                ip = m.group(0)
                octets = ip.split(".")
                if octets[0] == "10":
                    return f"10.{'***'}.{'***'}.{octets[3]}"
                elif octets[0] == "172" and 16 <= int(octets[1]) <= 31:
                    return f"172.{octets[1]}.{'***'}.{octets[3]}"
                elif octets[0] == "192" and octets[1] == "168":
                    return f"192.168.{'***'}.{octets[3]}"
                return ip

            data = re.sub(
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
                _redact_rfc1918,
            data,
        )
        return data

    if isinstance(data, dict):
        return {k: _redact_alert_data(v, bypass=bypass) for k, v in data.items()}

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

        async def _do_wazuh_auth_http() -> str:
            client = await _get_client("wazuh", verify=WAZUH_API_VERIFY_SSL, max_keepalive=10, max_connections=50)
            resp = await client.post(
                url,
                auth=(WAZUH_API_USER, WAZUH_API_PASSWORD),
            )
            resp.raise_for_status()
            return resp.text.strip().strip('"')

        _wazuh_token = await _cb_wazuh_manager.call(_do_wazuh_auth_http)
        _wazuh_token_expiry = now + _WAZUH_TOKEN_TTL
        return _wazuh_token
    except httpx.HTTPStatusError as e:
        logger.warning("Wazuh auth failed: HTTP %s — %s", e.response.status_code, e.response.text[:200])
        _wazuh_token = None
        _wazuh_token_expiry = 0.0
        return None
    except CircuitBreakerOpenError as e:
        logger.warning("Wazuh auth failed: circuit breaker open — %s", e)
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

        async def _do_wazuh_api_http() -> dict:
            client = await _get_client("wazuh", verify=WAZUH_API_VERIFY_SSL, max_keepalive=10, max_connections=50)
            resp = await client.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                params=params or {},
            )
            resp.raise_for_status()
            return resp.json()

        return await _cb_wazuh_manager.call(_do_wazuh_api_http)
    except httpx.HTTPStatusError as e:
        return {"error": f"Wazuh API error: {e.response.status_code}", "detail": e.response.text[:500]}
    except CircuitBreakerOpenError:
        return {
            "error": "Wazuh Manager API is temporarily unavailable (circuit breaker open)",
            "detail": (
                "The Wazuh Manager API has been unresponsive. The circuit breaker "
                "will retry automatically after the recovery timeout. Try again in ~60 seconds."
            ),
        }
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

    async def _do_indexer_http() -> dict[str, Any]:
        client = await _get_client("indexer", verify=WAZUH_INDEXER_VERIFY_SSL, max_keepalive=10, max_connections=50)
        resp = await client.post(
            url,
            auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
            json=body,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()

    try:
        result = await _cb_wazuh_indexer.call(_do_indexer_http)
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
        # Only fetch fields we actually need — raw full_log can be huge
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

    # Filter context (no scoring needed — filter is faster than query)
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
    # Free-text keyword filter — same query_string pattern as _wazuh_indexer_search
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
    CROWDSEC_CACHE_TTL) per PRD FR-2a / SKILLS.md §3.1. Cache entries are
    keyed by the exact path (which includes the IP). Error responses (HTTP
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

    # circuit-breaker-wrapped HTTP call — cache hits skip this entirely
    async def _do_crowdsec_http() -> dict[str, Any]:
        client = await _get_client("http")
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    data = await _cb_crowdsec.call(_do_crowdsec_http)

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
        return _validate_public_ip(v)

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
    _audit_log("crowdsec_ip_reputation", {"ip": params.ip})
    try:
        raw = await _crowdsec_request(f"/v2/smoke/{params.ip}")
    except (httpx.HTTPStatusError, httpx.TimeoutException, CircuitBreakerOpenError, RuntimeError) as e:
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
    _audit_log("crowdsec_ip_reputation_bulk", {"count": len(params.ips)})
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
        except (httpx.HTTPStatusError, httpx.TimeoutException, CircuitBreakerOpenError, RuntimeError) as e:
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
        lines.append("- **Noise**: Yes — this IP has been observed scanning the internet")
    elif noise is False:
        lines.append("- **Noise**: No — this IP has not been observed scanning")
    else:
        lines.append("- **Noise**: unknown")

    # RIOT (business service)
    riot = raw.get("riot")
    if riot is True:
        lines.append("- **RIOT**: Yes — this IP is a known business service (trusted)")
    elif riot is False:
        lines.append("- **RIOT**: No — not a known business service")
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
        return _validate_public_ip(v)

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
    _audit_log("greynoise_ip_context", {"ip": params.ip})
    try:
        raw = await _greynoise_community_request(params.ip)
    except (httpx.HTTPStatusError, httpx.TimeoutException, CircuitBreakerOpenError, RuntimeError) as e:
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


# NETRA THREAT INTELLIGENCE
# Optional: set NETRA_API_KEY to enable the netra_ip_analysis tool.
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


# Netra Threat Intelligence input model
class NetraIpAnalysisInput(BaseModel):
    """Input model for Netra Threat Intelligence IP analysis lookup."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ip: str = Field(
        ...,
        description="Public IPv4 or IPv6 address to analyze through Netra Threat Intelligence "
        "(e.g. '185.220.101.1').",
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
        return _validate_public_ip(v)


# NETRA THREAT INTELLIGENCE TOOL
@mcp.tool(
    name="netra_ip_analysis",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def netra_ip_analysis(params: NetraIpAnalysisInput) -> str:
    """Analyze a public IP address using Netra Threat Intelligence.

    This tool is READ-ONLY — it queries the Netra Threat Intelligence API to
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
    _audit_log("netra_ip_analysis", {"ip": params.ip})
    try:
        raw = await _netra_request(f"/analysis/{params.ip}")
    except (httpx.HTTPStatusError, httpx.TimeoutException, CircuitBreakerOpenError, RuntimeError) as e:
        return _handle_api_error(e, context="netra_ip_analysis")

    if params.response_format == ResponseFormat.JSON:
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
            "ip": params.ip,
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
        result = _format_netra_markdown(params.ip, raw)

    return _truncate_if_needed(result)


# ARGUS THREAT INTELLIGENCE
# Optional: set ARGUS_API_KEY and ARGUS_BASE_URL to enable the argus_ip_lookup tool.
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

    async def _do_argus_http() -> dict[str, Any]:
        client = await _get_client("argus", verify=ARGUS_VERIFY_SSL, max_keepalive=5, max_connections=20)
        resp = await client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        return resp.json()

    return await _cb_argus.call(_do_argus_http)


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


class ArgusIpLookupInput(BaseModel):
    """Input model for Argus Threat Intelligence IP lookup."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ip: str = Field(
        ...,
        description="Public IPv4 or IPv6 address to analyze through Argus Threat Intelligence.",
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
        return _validate_public_ip(v)


@mcp.tool(
    name="argus_ip_lookup",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def argus_ip_lookup(params: ArgusIpLookupInput) -> str:
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
    _audit_log("argus_ip_lookup", {"ip": params.ip})
    try:
        raw = await _argus_request("/lookup-jobs", {"observable": params.ip})
    except (httpx.HTTPStatusError, httpx.TimeoutException, CircuitBreakerOpenError, RuntimeError) as e:
        return _handle_api_error(e, context="argus_ip_lookup")

    if params.response_format == ResponseFormat.JSON:
        return _truncate_if_needed(json.dumps(raw, indent=2, ensure_ascii=False))

    result = _format_argus_markdown(params.ip, raw)
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
        params.grep (str, optional): Filter to lines containing this pattern

    Returns:
        str: Matching log lines or error JSON
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
        lines = [l for l in content.splitlines() if re.search(safe_grep, l, re.IGNORECASE)]
        return "\n".join(lines) if lines else f"No lines matched filter: {params.grep}"
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
                return _redact_alert_data("\n".join(lines, bypass=params.bypass_redaction) if lines else f"No matches for: {params.grep}")
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
        str: Log lines
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
    if log_type not in paths[server]:
        return json.dumps({"error": f"Unknown log type '{params.log_type}'. Use 'access' or 'error'."})

    path = paths[server][log_type]
    content = _tail_file(path, params.lines)
    if params.grep:
        safe_grep = _sanitize_regex(params.grep)
        lines = [l for l in content.splitlines() if re.search(safe_grep, l, re.IGNORECASE)]
        return _redact_alert_data("\n".join(lines, bypass=params.bypass_redaction) if lines else f"No matches for: {params.grep}")
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
    else:
        # Redact internal RFC1918 IPs from stdout text output (PRD FR-17, AGENTS.md §3.3).
        # Connection metadata contains internal endpoint IPs; mask them without altering
        # the packet-capture file itself (which is forensic evidence and always unredacted).
        result = _redact_alert_data(result, bypass=params.bypass_redaction)
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
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
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
    _audit_log("blueteam_wazuh_agents", {})
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

    return _truncate_if_needed(json.dumps({
        "agents": summary,
        "total": total,
        "offset": offset,
        "limit": params.limit,
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
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
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
    _audit_log("blueteam_wazuh_manager_logs", {})
    valid = ("alerts", "api", "cluster", "integrations")
    if params.log_type not in valid:
        return json.dumps({"error": f"log_type must be one of: {valid}"})

    offset = 0
    if params.cursor:
        decoded = _decode_cursor(params.cursor)
        if decoded:
            offset = decoded.get("offset", 0)

    # Wazuh Manager API hard-caps limit at 500 — values > 500 return 400.
    # Auto-cap here so LLM clients pass large values without triggering API errors.
    wazuh_safe_limit = min(params.limit, 500)
    api_params = {"offset": str(offset), "limit": str(wazuh_safe_limit), "pretty": "true"}
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

    return _truncate_if_needed(json.dumps({
        "logs": items,
        "total": total,
        "offset": offset,
        "limit": params.limit,
        "next_cursor": next_cursor,
    }, indent=2))


# Path to Wazuh alerts file (on the host where MCP runs; must be Wazuh manager or have mounts file system)
_WAZUH_ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"
_WAZUH_ALERTS_MAX_LINES = 2000  # safety cap


class WazuhAlertsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    agent_name: Optional[str] = Field(default=None, max_length=64, description="Filter by agent name (e.g. HYDRA-DC)")
    srcip: Optional[str] = Field(default=None, max_length=45, description="Source IP filter (e.g. '180.254.78.145')")
    since: Optional[str] = Field(default=None, max_length=30, description="ISO 8601 or relative time ('24h', '1h', '7d', etc.)")
    until: Optional[str] = Field(default=None, max_length=30, description="ISO 8601 or relative end time")
    limit: int = Field(default=500, description="Max alerts per page", ge=1, le=2000)
    cursor: Optional[str] = Field(
        default=None,
        description="Pagination cursor from previous response (next_cursor). Omit for first page.",
    )
    bypass_redaction: bool = Field(default=False, description="When true, return raw alert data without PII masking. Overrides BLUETEAM_REDACT_PII for this call only — use for internal audit investigations.")


@mcp.tool(
    name="blueteam_wazuh_alerts",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
)
async def blueteam_wazuh_alerts(params: WazuhAlertsInput) -> str:
    """Read Wazuh security alerts — local alerts.json first, auto-fallback to Indexer.
    When /var/ossec/logs/alerts/alerts.json is available (MCP on Wazuh Manager host),
    reads directly from the file. When the file is absent (remote Wazuh Manager),
    automatically delegates to the Wazuh Indexer (OpenSearch) — no tool switch needed.

    Args:
        params.agent_name: Optional filter by agent name (e.g. HYDRA-DC)
        params.limit: Max alerts per page (default 100, max 2000)
        params.cursor: next_cursor from previous response (omit for first page)

    Returns:
        str: JSON with alerts, count, next_cursor, and source field ("local" or "wazuh-indexer")
    """
    _audit_log("blueteam_wazuh_alerts", {})
    ok, err = _validate_path(_WAZUH_ALERTS_PATH, ALLOWED_PATH_PREFIXES)
    if not ok:
        return json.dumps({"error": err})
    p = Path(_WAZUH_ALERTS_PATH)
    if not p.exists():
        # Self-healing fallback: when alerts.json is absent (remote Wazuh Manager),
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

        # Decode cursor — handle both indexer search_after and legacy scanned formats
        search_after: Optional[list] = None
        if params.cursor:
            decoded = _decode_cursor(params.cursor)
            if decoded:
                search_after = decoded.get("search_after") or decoded.get("scanned")
                # "scanned" is a legacy integer — discard it; search_after needs an array
                if isinstance(search_after, int):
                    search_after = None

        data = await _wazuh_indexer_search(
            index_pattern="wazuh-alerts-*",
            agent_name=params.agent_name,
            size=params.limit,
            search_after=search_after,
            srcip=params.srcip,
            since=params.since,
            until=params.until,
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
        if hit_list and len(docs) >= params.limit:
            last_sort = hit_list[-1].get("sort")
            if last_sort:
                next_cursor = _encode_cursor({"search_after": last_sort})

        return _truncate_if_needed(json.dumps({
            "source": "wazuh-indexer",  # signals auto-fallback to the LLM
            "total": {"value": total_val, "relation": total_relation},
            "count": len(docs),
            "limit": params.limit,
            "next_cursor": next_cursor,
            "alerts": _redact_alert_data(docs, bypass=params.bypass_redaction),
        }, indent=2))

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
    ip_filter = (params.srcip or "").strip()
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

    next_cursor = _encode_cursor({"scanned": scanned}) if len(alerts) >= params.limit else None

    return _truncate_if_needed(json.dumps({
        "source": "local",
        "alerts": alerts,
        "count": len(alerts),
        "next_cursor": next_cursor,
    }, indent=2))


# Wazuh Indexer index patterns (OpenSearch)
_WAZUH_INDEX_PATTERNS = {
    "alerts": "wazuh-alerts-*",
    "events": "wazuh-events-*",
    "vulnerabilities": "wazuh-states-vulnerabilities-*",
}

# Agent name: alphanumeric, hyphen, underscore, dot only (prevents injection)
_AGENT_NAME_SAFE_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

# Practical email regex for extraction from log fields — covers >99% of real addresses
# Handles dots-in-local-part, plus-sign aliases, and multi-level TLDs
_EMAIL_RE = re.compile(
    r'[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}'
)

# Shared keyword search fields — used across all Wazuh Indexer query helpers.
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
        """
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
    response_format: ResponseFormat = Field(
        default=ResponseFormat.JSON,
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
        description="Start of time window — ISO 8601 ('2026-07-05T18:30:00Z') or relative "
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
            # Allow IPv4, IPv6, and CIDR notation — reject obvious non-IP strings
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
    if params.response_format == ResponseFormat.JSON:
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
    Supports filtering by agent_name, srcip/s (source IP), keyword, or all simultaneously.
    Requires WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD (port 9200).

    **Three modes**:

    - **Single-page** (default, ``max_scanned`` not set): Returns one page per call.
      Pass the returned ``next_cursor`` back as the ``cursor`` parameter to fetch
      the next page. ``next_cursor`` is null when all results are exhausted.
    - **Full-scan aggregate** (set ``max_scanned``): Auto-paginates across ALL
      matching pages and returns aggregated summary (top IPs, top rules) with 50
      sample documents.
    - **Full-scan forensic** (``max_scanned`` + ``include_all_docs=True``): Returns
      ALL scanned documents alongside aggregations. Requires
      ``BLUETEAM_ALLOW_UNTRUNCATED=true`` on the server. Pair with
      ``bypass_character_limit=True`` to avoid the 100K-character response cap.

    Args:
        params.agent_name: Optional agent name filter (e.g. HYDRA-DC)
        params.srcip: Optional single source IP filter (e.g. '180.254.78.145')
        params.srcips: Optional list of source IPs to match ANY of (max 25)
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
        str: In 'json' mode (default): JSON with documents, total, size, count, next_cursor,
             and timezone. Metadata includes ``applied_size`` when ``_WAZUH_INDEXER_MAX_SIZE``
             clamped the per-page document count.
    """
    _audit_log("blueteam_wazuh_indexer_search", {})
    if params.index_type not in _WAZUH_INDEX_PATTERNS:
        return json.dumps({"error": f"index_type must be one of: {list(_WAZUH_INDEX_PATTERNS)}"})
    index_pattern = _WAZUH_INDEX_PATTERNS[params.index_type]

    # Decode pagination cursor — search_after uses sort-key values, not numeric offsets
    search_after: Optional[list] = None
    if params.cursor:
        decoded = _decode_cursor(params.cursor)
        if decoded:
            search_after = decoded.get("search_after")

    # Auto-pagination mode — scan ALL pages internally, return aggregate
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

    if params.response_format == ResponseFormat.JSON:
        meta["documents"] = _redact_alert_data(meta["documents"], bypass=params.bypass_redaction)
        return _truncate_if_needed(
            json.dumps(meta, indent=2),
            bypass=params.bypass_character_limit,
        )

    # Markdown: compact summary table
    lines = [
        f"# Wazuh Indexer Search Results",
        f"",
        f"**Total**: {total_val} ({total_relation}) | **Returned**: {len(docs)} | **Page size**: {params.limit}",
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
            f"**Note:** Requested page size {data['requested_size']} was clamped to "
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
        ge=1000,
        le=200000,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
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
    pages through alerts using ``search_after`` cursors until either the Indexer
    is exhausted or ``max_scanned`` documents have been processed.

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
                # If we've already collected some data, return partial results
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

    except (httpx.HTTPStatusError, httpx.TimeoutException, CircuitBreakerOpenError, RuntimeError) as e:
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

    if params.response_format == ResponseFormat.JSON:
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
        description="Optional agent name filter.",
    )
    since: Optional[str] = Field(
        default=None,
        max_length=30,
        description="ISO 8601 start time in UTC. Defaults to 365 days ago.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="ISO 8601 end time in UTC. Defaults to now.",
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
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable summary, 'json' for structured data.",
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
                    "scanned pages — no need to manually iterate with next_cursor. "
                    "When None (default), returns a single page with next_cursor for "
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

    if params.response_format == ResponseFormat.JSON:
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
            f"---\n**Note:** Results are partial — scan hit the "
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
    ``full_log`` for the domain as a phrase.

    **Two modes**:

    - **Single-page** (default, ``max_scanned`` not set): Returns one page of
      results with a ``next_cursor``.  Call repeatedly with the cursor to manually
      iterate through all pages.
    - **Full-scan** (set ``max_scanned`` to an integer ≥1000): Auto-paginates
      internally across ALL matching pages and returns an aggregated summary
      (global top IPs, top rule groups, top rules).  Set ``max_scanned`` high
      enough to cover the time window — the scan stops when the indexer is
      exhausted or the ceiling is hit.

    Args:
        params.domain: Domain to search for (e.g. 'tangerangkota.go.id')
        params.agent_name: Optional agent filter
        params.since: ISO 8601 start in UTC (default: 365 days ago)
        params.until: ISO 8601 end in UTC (default: now)
        params.limit: Max alerts per page in single-page mode (1-10000, default 500)
        params.include_full_log: Include raw log lines (default false — forced false in full-scan mode)
        params.cursor: Pagination cursor from previous response
        params.response_format: 'markdown' or 'json'
        params.max_scanned: When set, run full-scan auto-pagination (see above)
        params.keyword: Free-text keyword to further narrow results

    Returns:
        str: Paged alert results (single-page) or aggregated summary (full-scan).

    Example usage:
        - "Search for all alerts involving tangerangkota.go.id"
        - "Get the complete picture for this domain over the past 12h — use full-scan"
        - "Show me who's hitting the mail server domain"
    """
    _audit_log("wazuh_domain_lookup", {"domain": params.domain, "since": params.since})
    since_str, until_str = _parse_time_window(params.since, params.until)

    search_after: Optional[list] = None
    if params.cursor:
        decoded = _decode_cursor(params.cursor)
        if decoded:
            search_after = decoded.get("search_after")

    # Auto-pagination mode — scan ALL pages internally, return aggregate
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
    except (httpx.HTTPStatusError, httpx.TimeoutException, CircuitBreakerOpenError, RuntimeError) as e:
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

    if params.response_format == ResponseFormat.JSON:
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
        lines.append(f"\n**Next cursor**: `{next_cursor}`")
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
        description="Optional agent name filter.",
    )
    since: Optional[str] = Field(
        default=None,
        max_length=30,
        description="ISO 8601 start time in UTC. Defaults to 365 days ago.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="ISO 8601 end time in UTC. Defaults to now.",
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
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for structured.",
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
    enriched regardless of ``top_ips``).

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
        breakdown.  If enrich_with_netra is true, Netra threat scores are included
        for the top 10 IPs.

    Example usage:
        - "Take the top 5 emails from the lookup and find who's attacking them"
        - "Enrich the attacker IPs for these compromised accounts through Netra"
    """
    _audit_log("wazuh_compromised_emails_analysis", {"top_ips": params.top_ips, "since": params.since})
    since_str, until_str = _parse_time_window(params.since, params.until)

    ip_counter: Counter[str] = Counter()
    ip_to_emails: dict[str, set[str]] = {}  # IP -> set of targeted emails
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

    except (httpx.HTTPStatusError, httpx.TimeoutException, CircuitBreakerOpenError, RuntimeError) as e:
        if total_scanned == 0:
            return _handle_api_error(e, context="wazuh_compromised_emails_analysis")
        logging.getLogger(__name__).warning(
            "wazuh_compromised_emails_analysis: error after %d docs: %s", total_scanned, e
        )

    top_ips = ip_counter.most_common(params.top_ips)

    # Optional Netra enrichment for top IPs (max 10)
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
                # Rate-limit courtesy: 1s delay between Netra calls
                await asyncio.sleep(1)
            except (httpx.HTTPStatusError, httpx.TimeoutException, Exception) as e:
                netra_results[ip] = {"error": str(e)}

    if params.response_format == ResponseFormat.JSON:
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


# Dynamic Time-Based Alert Analysis
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
        s = datetime.fromisoformat(since.replace("Z", "+00:00").rstrip("Z"))
        u = datetime.fromisoformat(until.replace("Z", "+00:00").rstrip("Z"))
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
        description="Optional agent name filter.",
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
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable timeline, 'json' for structured bucket data.",
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
    bucket alert counts by time interval (per minute, per 15 minutes, per hour, etc.)
    directly on the server — fast, even across millions of documents.

    Each bucket includes:
    - Total alert count
    - Count by severity band (low ≤4, medium 5-9, high ≥10)
    - Top rules, top source IPs, and top agents within that bucket

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
        str: Timeline table with per-bucket counts, severity bands, and top indicators.

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
        )
    except (httpx.HTTPStatusError, httpx.TimeoutException, CircuitBreakerOpenError, RuntimeError) as e:
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

    if params.response_format == ResponseFormat.JSON:
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

    # Per-severity totals
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
        description="Optional agent name filter.",
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
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for structured.",
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
        params.bucket: Bucket granularity within each window. 'auto' picks based on
                      window size.
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
            ),
            _wazuh_indexer_aggregate(
                bucket_interval=bucket_interval,
                since=previous_since,
                until=previous_until,
                agent_name=params.agent_name,
                rule_groups=rule_group_list,
                keyword=params.keyword,
            ),
        )
    except (httpx.HTTPStatusError, httpx.TimeoutException, CircuitBreakerOpenError, RuntimeError) as e:
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

    if params.response_format == ResponseFormat.JSON:
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
        f"**Current window**: {current_since} → {current_until}  ({total_current:,} alerts)",
        f"**Previous window**: {previous_since} → {previous_until}  ({total_previous:,} alerts)",
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

class IPInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: str = Field(..., max_length=45, description="IPv4 or IPv6 address to look up")
    max_age_days: int = Field(default=90, description="Only return reports from the last N days", ge=1, le=365)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format: 'markdown' (default) or 'json'")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        if not v or len(v) > 45:
            raise ValueError("Invalid IP format or length")
        if _IPV4_RE.match(v) or _IPV6_RE.match(v):
            return _validate_public_ip(v)
        raise ValueError("Invalid IP format")


@mcp.tool(
    name="blueteam_lookup_ip_abuseipdb",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_lookup_ip_abuseipdb(params: IPInput) -> str:
    """Check an IP address against AbuseIPDB for known malicious activity reports.
    Requires ABUSEIPDB_API_KEY environment variable.

    Args:
        params.ip: IP address to check
        params.max_age_days: Lookback window in days
        params.response_format: 'markdown' (default) or 'json'

    Returns:
        str: Markdown report (default) or JSON with abuse confidence score, report count, etc.
    """
    _audit_log("blueteam_lookup_ip_abuseipdb", {"ip": params.ip})
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
        if params.response_format == ResponseFormat.JSON:
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

class HashInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    hash_value: str = Field(..., max_length=64, description="MD5 (32), SHA1 (40), or SHA256 (64) hash hex")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format: 'markdown' (default) or 'json'")

    @field_validator("hash_value")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        if not _HASH_RE.match(v) or len(v) not in (32, 40, 64):
            raise ValueError("Hash must be 32 (MD5), 40 (SHA1), or 64 (SHA256) hex chars")
        return v


@mcp.tool(
    name="blueteam_lookup_hash_virustotal",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_lookup_hash_virustotal(params: HashInput) -> str:
    """Check a file hash against VirusTotal to see if it's known malware.
    Requires VIRUSTOTAL_API_KEY environment variable.

    Args:
        params.hash_value: MD5/SHA1/SHA256 of the file
        params.response_format: 'markdown' (default) or 'json'

    Returns:
        str: Markdown report (default) or JSON with detection ratio, malware names
    """
    _audit_log("blueteam_lookup_hash_virustotal", {"hash": params.hash_value[:8] + "..."})
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
        detections = {
            engine: r["result"]
            for engine, r in results.items()
            if r.get("category") == "malicious"
        }
        detection_ratio = f"{stats.get('malicious', 0)}/{sum(stats.values())}"
        result = {
            "hash": params.hash_value,
            "name": attrs.get("meaningful_name"),
            "type": attrs.get("type_description"),
            "size_bytes": attrs.get("size"),
            "first_seen": attrs.get("first_submission_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "detections": detection_ratio,
            "malware_names": detections,
        }
        if params.response_format == ResponseFormat.JSON:
            return json.dumps(result, indent=2)
        # markdown
        malicious = stats.get("malicious", 0)
        severity = "🔴 Malicious" if malicious > 0 else "🟢 Clean"
        lines = [
            f"# VirusTotal Hash Lookup — `{params.hash_value}`",
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


class DomainInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    domain: str = Field(..., max_length=253, description="Domain name to look up, e.g. 'example.com'")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format: 'markdown' (default) or 'json'")

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
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_lookup_domain_virustotal(params: DomainInput) -> str:
    """Check a domain against VirusTotal for malicious reputation.

    Args:
        params.domain: Domain to check
        params.response_format: 'markdown' (default) or 'json'

    Returns:
        str: Markdown report (default) or JSON with reputation score and detection details
    """
    _audit_log("blueteam_lookup_domain_virustotal", {"domain": params.domain})
    if not VIRUSTOTAL_API_KEY:
        return json.dumps({"error": "VIRUSTOTAL_API_KEY not set. See blueteam_lookup_hash_virustotal for setup."})
    try:
        data = await _http_get(
            f"https://www.virustotal.com/api/v3/domains/{params.domain}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}
        )
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        detection_ratio = f"{stats.get('malicious', 0)}/{sum(stats.values())}"
        result = {
            "domain": params.domain,
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories", {}),
            "detections": detection_ratio,
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "whois": (attrs.get("whois", "") or "")[:500],
        }
        if params.response_format == ResponseFormat.JSON:
            return json.dumps(result, indent=2)
        # markdown
        malicious = stats.get("malicious", 0)
        severity = "🔴 Malicious" if malicious > 0 else ("🟠 Suspicious" if (attrs.get("reputation") or 0) < 0 else "🟢 Clean")
        lines = [
            f"# VirusTotal Domain Lookup — `{params.domain}`",
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

    # Sort: UID 0 first, then regular users, then system accounts
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
    """Post a raw OpenSearch query body to the Wazuh Indexer.

    All aggregation tools (Tier 1 & Tier 2) funnel through this single helper,
    which wraps the HTTP call with the ``_cb_wazuh_indexer`` circuit breaker.
    """
    if index_pattern is None:
        index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return {"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set. See README for Indexer setup."}
    url = f"{WAZUH_INDEXER_URL}/{index_pattern}/_search"

    async def _do_post() -> dict[str, Any]:
        client = await _get_client("indexer", verify=WAZUH_INDEXER_VERIFY_SSL, max_keepalive=10, max_connections=50)
        resp = await client.post(
            url,
            auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
            json=body,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()

    try:
        return await _cb_wazuh_indexer.call(_do_post)
    except httpx.HTTPStatusError as e:
        return {"error": f"Indexer API error: {e.response.status_code}", "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": str(e)}


# Tier 1: wazuh_alert_aggregate_analysis — full-period statistics (size: 0 -> summarizes a whole period with no document limit)
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
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable stats, 'json' for structured data.",
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
    """Full-period statistical analysis of Wazuh alerts — NO document limits.

    All matching alerts are processed server-side by the Wazuh Indexer (OpenSearch)
    using ``size: 0`` aggregations. Only statistics and bucketed summaries are
    returned — ZERO raw alert documents. This means 1M alerts and 10K alerts
    consume roughly the same LLM context budget (~10–50 KB).

    **Analysis modes:**
    - ``topology`` — Top-N (src_ip × rule_id × agent) attack patterns + severity bands
    - ``anomaly`` — Statistical-deviation detection: which time slices are >2σ above mean?
    - ``correlation`` — Significant IP↔rule co-occurrence via significant_terms
    - ``trend`` — Multi-resolution rate-of-change (acceleration/deceleration) detection
    - ``summary`` — All four modes dispatched in parallel (recommended)

    **Typical workflow:**
    1. Call with ``mode="summary"`` to get the full statistical picture
    2. Identify hot spots from the results (specific IPs, rules, time windows)
    3. Use ``wazuh_alert_focused_crawl`` to drill into those specific slices

    Args:
        params.mode: Analysis mode (default 'summary').
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
        - Timeout/connection failures surface actionable error messages per mode
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

    if params.response_format == ResponseFormat.JSON:
        return _truncate_if_needed(json.dumps({
            "window": {"since": since_str, "until": until_str},
            "mode": params.mode,
            "results": results_by_mode,
        }, indent=2, default=str))
    return _format_aggregate_markdown(params, results_by_mode, since_str, until_str, errors)


# Tier 2: wazuh_alert_dsl_query - power user escape hatch (size: 0 enforced)
class DslQueryInput(BaseModel):
    """Input model for wazuh_alert_dsl_query — raw OpenSearch DSL, aggregation-only."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    query_json: str = Field(
        ...,
        min_length=5,
        max_length=10240,
        description=(
            "Raw OpenSearch DSL JSON payload. MUST use 'size': 0 (aggregation-only). "
            "Any query requesting document hits (size > 0) will be rejected. "
            "Docs: https://opensearch.org/docs/latest/aggregations/"
        ),
    )
    index_pattern: str = Field(
        default="wazuh-alerts-*",
        max_length=128,
        description="OpenSearch index pattern (default 'wazuh-alerts-*'). "
                    "Also accepts 'wazuh-events-*', 'wazuh-states-vulnerabilities-*'.",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.JSON,
        description="'json' (default, machine-readable) or 'markdown'.",
    )

    @field_validator("query_json")
    @classmethod
    def validate_dsl(cls, v: str) -> str:
        """Parse the JSON and enforce size: 0 — no document hits allowed."""
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

        # Reject scripted aggregations that could be expensive
        def _check_no_scripts(obj: Any, path: str = "") -> None:
            if isinstance(obj, dict):
                if "script" in obj and path:
                    raise ValueError(
                        f"Script found at '{path}' — scripted aggregations are not "
                        "supported in this tool for security and performance reasons."
                    )
                for k, val in obj.items():
                    _check_no_scripts(val, f"{path}.{k}" if path else k)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    _check_no_scripts(item, f"{path}[{i}]")

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

    Use this when you need a specific OpenSearch aggregation (percentiles,
    geo_distance, nested, reverse_nested, etc.) that the built-in tools
    do not expose.

    Args:
        params.query_json: Raw OpenSearch DSL JSON. MUST include ``"size": 0``
                          and an ``"aggs"`` (or ``"aggregations"``) block.
        params.index_pattern: Index pattern (default 'wazuh-alerts-*').
        params.response_format: 'json' (default) or 'markdown'.

    Returns:
        str: OpenSearch aggregation response (JSON by default, markdown on request).

    Example usage:
        - "Compute percentile latency distribution across all alert documents"
        - "Group alerts by geo_point and return top regions"
        - "Nested aggregation: alerts per agent, then per rule within each agent"

    Error Handling:
        - Invalid JSON → rejected at Pydantic validation
        - ``size`` > 0 → rejected with guidance to use wazuh_alert_focused_crawl
        - Scripted aggs → rejected for security
        - HTTP errors → surfaced through the circuit breaker

    Docs: https://opensearch.org/docs/latest/aggregations/
    """
    _audit_log("wazuh_alert_dsl_query", {"index": params.index_pattern})
    try:
        data = await _wazuh_indexer_post(
            json.loads(params.query_json),
            index_pattern=params.index_pattern,
        )
    except (httpx.HTTPStatusError, httpx.TimeoutException, CircuitBreakerOpenError, RuntimeError) as e:
        return _handle_api_error(e, context="wazuh_alert_dsl_query")

    if params.response_format == ResponseFormat.MARKDOWN:
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
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
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
                if not re.match(r"^[a-zA-Z0-9_.]+$", p):
                    raise ValueError(f"Invalid field name: '{p}'. Use only alphanumeric, dots, underscores.")
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
    except (httpx.HTTPStatusError, httpx.TimeoutException, CircuitBreakerOpenError, RuntimeError) as e:
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

    if params.response_format == ResponseFormat.JSON:
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
        le=20160,
        description="Sliding time window in minutes (5–20160, up to 14 days). Default: 30.",
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
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' (default, human-readable) or 'json' (machine-readable).",
    )
    category_a_groups: list[str] = Field(
        default=["web_attack", "webshell", "xss", "sqlinjection", "lfi", "rfi", "rce",
                 "command_injection", "vulnerability_scan", "encoded_payload", "evasion_attempt",
                 "injection", "suspicious_wp", "path_traversal", "dir_traversal", "suspicious_url",
                 "user_agent", "suspicious_ua", "malicious_request", "content_violation", "web_scan",
                 "gambling"],
        description="Wazuh rule.groups for Category A (Recon/Probe). TangerangKota-CSIRT production taxonomy.",
    )
    category_b_groups: list[str] = Field(
        default=["authentication_failures", "bruteforce", "malicious_login", "blocklist",
                 "blacklist", "credential_breach", "account_compromised", "zimbra"],
        description="Wazuh rule.groups for Category B (Access Anomaly). TangerangKota-CSIRT production taxonomy.",
    )
    category_c_groups: list[str] = Field(
        default=["firewall_drop", "exfiltration", "overflow", "opencti", "persistent",
                 "backdoor", "common_webshell", "react2shell", "defacement"],
        description="Wazuh rule.groups for Category C (C2/Exfil/Maintain). TangerangKota-CSIRT production taxonomy.",
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
async def three_sum_correlation(params: ThreeSumCorrelationInput) -> str:
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

    # Parse time window
    since_dt = (datetime.utcnow() - timedelta(minutes=params.time_window_minutes))
    until_dt = datetime.utcnow()
    since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    until_iso = until_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    logger.info(
        "[3SUM-EVAL] Starting evaluation window=%s -> %s (engineA=%s engineB=%s threshold=%d z=%.1f)",
        since_iso, until_iso,
        params.engine_a_enabled, params.engine_b_enabled,
        params.threshold_score, params.z_score_threshold,
    )

    try:
        engine_a_results = None
        engine_b_result = None

        # Engine A: terms aggregation per category (3 parallel queries)
        if params.engine_a_enabled:
            label_to_groups = [
                (params.category_a_label, params.category_a_groups),
                (params.category_b_label, params.category_b_groups),
                (params.category_c_label, params.category_c_groups),
            ]

            async def _fetch_srcip_terms(label: str, groups: list[str]) -> tuple[str, list[tuple[str, int]]]:
                """Fetch distinct srcips and their max rule.level per category via terms agg."""
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
                                {"terms": {"rule.groups": groups}},
                            ]
                        }
                    },
                    "aggs": {
                        "unique_srcips": {
                            "terms": {
                                "field": "data.srcip.keyword",
                                "size": 10000,
                                "min_doc_count": 1,
                            },
                            "aggs": {
                                "max_level": {
                                    "max": {"field": "rule.level"},
                                },
                            },
                        }
                    },
                }
                raw = await _wazuh_indexer_post(body, _WAZUH_INDEX_PATTERNS["alerts"])
                if "error" in raw:
                    logger.warning("[3SUM-EVAL] Engine-A query failed for %s: %s", label, raw["error"])
                    return (label, [])

                buckets = raw.get("aggregations", {}).get("unique_srcips", {}).get("buckets", [])
                return (label, [(b["key"], int(b.get("max_level", {}).get("value", 1))) for b in buckets])

            label_a, label_b, label_c = (
                params.category_a_label,
                params.category_b_label,
                params.category_c_label,
            )
            groups_a, groups_b, groups_c = (
                params.category_a_groups,
                params.category_b_groups,
                params.category_c_groups,
            )

            fetched = await asyncio.gather(
                _fetch_srcip_terms(label_a, groups_a),
                _fetch_srcip_terms(label_b, groups_b),
                _fetch_srcip_terms(label_c, groups_c),
            )

            # Map label -> srcip list; apply CIDR normalization if requested
            srcips_by_label: dict[str, list[tuple[str, int]]] = {}
            for label_ret, entries in fetched:
                if params.cidr_normalize and entries:
                    ips = [e[0] for e in entries]
                    cidr_map = normalize_srcip_to_cidr(ips)
                    cidr_scores: dict[str, int] = {}
                    for srcip, score in entries:
                        cidr = cidr_map.get(srcip, srcip)
                        cidr_scores[cidr] = cidr_scores.get(cidr, 0) + score
                    srcips_by_label[label_ret] = [(cidr, score) for cidr, score in cidr_scores.items()]
                else:
                    srcips_by_label[label_ret] = entries

            triggers_a, stats_a = evaluate_engine_a(
                srcips_by_label.get(label_a, []),
                srcips_by_label.get(label_b, []),
                srcips_by_label.get(label_c, []),
                category_a_label=label_a,
                category_b_label=label_b,
                category_c_label=label_c,
                threshold_score=params.threshold_score,
                exclude_srcips=params.exclude_srcips if params.exclude_srcips else None,
            )

            engine_a_results = (triggers_a, stats_a)
            logger.info("[3SUM-EVAL] Engine-A evaluation complete — %d triggers", len(triggers_a))


        # Engine B: date_histogram per source (3 parallel queries)
        if params.engine_b_enabled:
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
                                {"terms": {"rule.groups": groups}},
                            ]
                        }
                    },
                    "aggs": {
                        "alerts_over_time": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1m",
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
                params.category_a_label,
                params.category_b_label,
                params.category_c_label,
            )
            groups_a, groups_b, groups_c = (
                params.category_a_groups,
                params.category_b_groups,
                params.category_c_groups,
            )

            fetched_b = await asyncio.gather(
                _fetch_bucket_counts(label_a, groups_a),
                _fetch_bucket_counts(label_b, groups_b),
                _fetch_bucket_counts(label_c, groups_c),
            )

            buckets_by_label: dict[str, list[dict[str, Any]]] = {}
            for label_ret, buckets in fetched_b:
                buckets_by_label[label_ret] = buckets

            engine_b_result = evaluate_engine_b(
                buckets_by_label.get(label_a, []),
                buckets_by_label.get(label_b, []),
                buckets_by_label.get(label_c, []),
                source_1_label=label_a,
                source_2_label=label_b,
                source_3_label=label_c,
                z_score_threshold=params.z_score_threshold,
            )
            logger.info(
                "[3SUM-EVAL] Engine-B evaluation complete — %d simultaneous triggers",
                len(engine_b_result.simultaneous_triggers),
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

        logger.info("[3SUM-EVAL] Evaluation finished — %d ms", round(elapsed_ms))
        return json.dumps(result, indent=2)

    except CircuitBreakerOpenError:
        return json.dumps({
            "error": "Wazuh Indexer is temporarily unavailable (circuit breaker open)",
            "detail": "The Indexer has been unresponsive. Retry after the circuit breaker recovery timeout (~60s).",
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
        description="blue_team_mcp — Unified blue-team MCP server (TangerangKota-CSIRT)"
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
    Per CLAUDE.md Hard Rule 8 and AGENTS.md §1.4 checklist item 2: fail fast
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

    # WAZUH_INDEXER_MAX_SIZE guard — warn if it exceeds OpenSearch's default max_result_window
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
    else:  # pragma: no cover — unreachable due to argparse choices
        raise ValueError(f"Unknown transport: {args.transport}")


if __name__ == "__main__":
    main()
