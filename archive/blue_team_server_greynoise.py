#!/usr/bin/env python3
"""
blue_team_mcp — GreyNoise Community API integration for blue team / detection engineering
TangerangKota-CSIRT.

Supports three transports:
  - stdio            (default, local, subprocess)
  - sse               (remote, legacy Server-Sent Events)
  - streamable_http   (remote, modern, stateless)

The GreyNoise Community API is free and unauthenticated — no API key required.
Rate limits apply per GreyNoise's fair-use policy.
"""

from __future__ import annotations
import argparse
import asyncio
import ipaddress
import json
import logging
import os
import sys
from enum import Enum
from typing import Any, Optional
import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, field_validator


# Logging — MUST go to stderr. stdout is used by the MCP stdio protocol.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("blue_team_mcp")

# Constants
GREYNOISE_COMMUNITY_BASE_URL = "https://api.greynoise.io/v3/community"
HTTP_TIMEOUT_SECONDS = float(os.environ.get("BLUETEAM_HTTP_TIMEOUT", "30.0"))
CHARACTER_LIMIT = int(os.environ.get("BLUETEAM_CHARACTER_LIMIT", "25000"))
BLUETEAM_VERIFY_SSL = os.environ.get("BLUETEAM_VERIFY_SSL", "true").lower() in ("1", "true", "yes")

# Private / reserved IP ranges — this tool is for public-IP threat intel only.
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
    Lazily initialized; reuse across all tool invocations."""
    global _shared_http_client
    if _shared_http_client is None or _shared_http_client.is_closed:
        _shared_http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(HTTP_TIMEOUT_SECONDS),
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=50),
            verify=BLUETEAM_VERIFY_SSL,
        )
    return _shared_http_client


mcp = FastMCP("blue_team_mcp")

# Shared utilities
class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"

def _is_private_or_reserved(ip: str) -> bool:
    """Check whether an IP belongs to a private or reserved range.

    The GreyNoise Community API only has data on public, routable IPs.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETWORKS)

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

def _handle_api_error(e: Exception, context: str = "") -> str:
    """Consistent, actionable error formatting across all tools."""
    prefix = f"[{context}] " if context else ""
    if isinstance(e, httpx.HTTPStatusError):
        status = e.response.status_code
        if status == 400:
            return f"{prefix}Error: Bad request (400) — GreyNoise rejected the parameters. "
            "Verify the IP format is valid and the field values are well-formed."
        if status == 404:
            return f"{prefix}Error: No GreyNoise data found for this IP (404). The IP may not have been observed scanning."
        if status == 429:
            retry_after = e.response.headers.get("Retry-After")
            hint = f" Retry after {retry_after} seconds." if retry_after else " Retry later."
            return f"{prefix}Error: GreyNoise Community API rate limit reached (429).{hint}"
        return f"{prefix}Error: GreyNoise API request failed with status {status}."
    if isinstance(e, httpx.TimeoutException):
        return f"{prefix}Error: Request timed out after {HTTP_TIMEOUT_SECONDS}s. Try again."
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
        + f"\n\n... [truncated — response exceeds {CHARACTER_LIMIT} characters. "
        "Response may include verbose raw fields; switch to "
        "response_format='json' for structured output with tighter field selection.]"
    )

# Input models
class GreynoiseIpContextInput(BaseModel):
    """Input model for GreyNoise Community IP context lookup."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ip: str = Field(
        ...,
        description="Public IPv4 or IPv6 address to check against GreyNoise (e.g. '51.91.185.74').",
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

# Formatting helpers (GreyNoise)
def _format_greynoise_markdown(ip: str, raw: dict[str, Any]) -> str:
    """Render GreyNoise Community API response as a human-readable markdown report."""
    lines = [f"# GreyNoise Community — {ip}", ""]

    # Message field (status indicator)
    message = raw.get("message", "")
    if message and message != "Success":
        lines.append(f"> ⚠️ {message}")
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

    # Classification
    classification = raw.get("classification", "unknown")
    lines.append(f"- **Classification**: `{classification}`")

    # Organization name
    name = raw.get("name")
    if name and name != "unknown":
        lines.append(f"- **Organization**: {name}")
    else:
        lines.append("- **Organization**: unknown")

    # Last seen
    last_seen = raw.get("last_seen")
    if last_seen:
        lines.append(f"- **Last Seen**: {last_seen}")

    # GreyNoise Visualizer link
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
            "This IP is a **known business service** (e.g. CDN, cloud provider, SaaS). "
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

# Tools
@mcp.tool(
    name="greynoise_ip_context",
    annotations={
        "title": "GreyNoise Community IP Context",
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
            - ip (str): Public IPv4/IPv6 address to check (e.g. "51.91.185.74")
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
        - Use when: "I see 51.91.185.74 in my firewall logs — is it just a scanner?"
        - Use when: "Triage a list of suspicious IPs — filter out known noise first"
        - Don't use when: you need full context (actors, CVEs, tags) — the Community
          API is a lightweight subset; upgrade to the full GreyNoise API for deep dives.

    Error Handling:
        - "Error: No GreyNoise data found..." (404) — IP hasn't been observed
        - "Error: GreyNoise Community API rate limit reached (429)..." — back off
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

# Entrypoint / transport selection
def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="blue_team_mcp — GreyNoise Community (TangerangKota-CSIRT)")
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
    args = _build_arg_parser().parse_args()

    if args.transport == "stdio":
        logger.info("Starting blue_team_mcp (GreyNoise) via stdio transport")
        mcp.run(transport="stdio")
        return

    # FastMCP sets host/port via settings attributes before .run() is called.
    mcp.settings.host = args.host
    mcp.settings.port = args.port

    # Update transport security to allow the actual host the client connects.
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
        logger.info("Starting blue_team_mcp (GreyNoise) via SSE transport on %s:%s", args.host, args.port)
        mcp.run(transport="sse")
    elif args.transport in ("streamable_http", "http"):
        logger.info(
            "Starting blue_team_mcp (GreyNoise) via Streamable HTTP transport on %s:%s",
            args.host,
            args.port,
        )
        mcp.run(transport="streamable-http")
    else:  # pragma: no cover — unreachable due to argparse choices
        raise ValueError(f"Unknown transport: {args.transport}")

if __name__ == "__main__":
    main()
