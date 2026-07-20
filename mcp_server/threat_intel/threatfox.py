"""ThreatFox by abuse.ch — IP → malware family attribution for APT hunting."""
from __future__ import annotations
import json, time, os, asyncio
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict, Field, field_validator

from mcp_server import mcp
from mcp_server.core.http_client import _api_call, _handle_api_error, ValidPublicIp
from mcp_server.core.audit import _audit_log, _truncate_if_needed

THREATFOX_BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_API_KEY_ENV = "THREATFOX_API_KEY"
_threatfox_cache: dict[str, tuple[float, dict[str, Any]]] = {}
THREATFOX_CACHE_TTL = 900


def _get_threatfox_api_key() -> str:
    key = os.environ.get(THREATFOX_API_KEY_ENV, "")
    if not key:
        raise RuntimeError(f"{THREATFOX_API_KEY_ENV} not set. Register at https://threatfox.abuse.ch/api")
    return key


async def _threatfox_request(search_term: str, exact_match: bool = False) -> dict[str, Any]:
    """Query ThreatFox search_ioc endpoint with in-memory TTL cache."""
    cache_key = f"{search_term}:{exact_match}"
    now = time.monotonic()
    if cache_key in _threatfox_cache:
        expiry, data = _threatfox_cache[cache_key]
        if now < expiry:
            return data
    headers = {"Auth-Key": _get_threatfox_api_key(), "Content-Type": "application/json"}
    body = {"query": "search_ioc", "search_term": search_term, "exact_match": exact_match}
    resp = await _api_call("post", THREATFOX_BASE_URL, headers=headers, json=body)
    data = resp.json()
    if data.get("query_status") == "ok":
        _threatfox_cache[cache_key] = (now + THREATFOX_CACHE_TTL, data)
    return data


def _format_threatfox_markdown(ip: str, data: dict) -> str:
    """Render ThreatFox response as a human-readable markdown report."""
    items = data.get("data", [])
    if not items:
        return f"# ThreatFox — `{ip}`\n\nNo ThreatFox data found for this IP (clean)."

    lines = [f"# ThreatFox — `{ip}`", ""]
    for i, entry in enumerate(items[:10]):
        malware = entry.get("malware_printable") or entry.get("malware", "unknown")
        threat_type = entry.get("threat_type_desc", entry.get("threat_type", "?"))
        confidence = entry.get("confidence_level", "?")
        first = (entry.get("first_seen") or "?")[:19]
        last = (entry.get("last_seen") or "?")[:19] if entry.get("last_seen") else "still active"
        lines.append(f"## Match {i+1}: `{entry.get('ioc', ip)}`")
        lines.append(f"- **Malware**: {malware}")
        lines.append(f"- **Type**: {threat_type}")
        lines.append(f"- **Confidence**: {confidence}/100")
        lines.append(f"- **First seen**: {first}")
        lines.append(f"- **Last seen**: {last}")
        if entry.get("malware_alias"):
            lines.append(f"- **Aliases**: {entry['malware_alias']}")
        if entry.get("malware_malpedia"):
            lines.append(f"- **Malpedia**: {entry['malware_malpedia']}")
        samples = entry.get("malware_samples", [])
        if samples:
            lines.append(f"- **Samples**: {len(samples)}")
            for s in samples[:3]:
                lines.append(f"  - `{s.get('sha256_hash','?')[:16]}...`")
        lines.append("")
    return "\n".join(lines)


# ── Single lookup ──

class ThreatFoxIpLookupInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: ValidPublicIp = Field(..., min_length=3, max_length=45)
    exact_match: bool = Field(default=False, description="Exact IP match vs wildcard search.")
    response_format: str = Field(default="markdown")


@mcp.tool(
    name="threatfox_ip_lookup",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
)
async def threatfox_ip_lookup(params: ThreatFoxIpLookupInput) -> str:
    """Query ThreatFox by abuse.ch for IP → malware family attribution.

    Maps attacker IPs to specific malware families (Cobalt Strike, Emotet, etc.)
    with confidence scores. Essential for APT group attribution.

    **Required**: THREATFOX_API_KEY env var. Register at https://threatfox.abuse.ch/api

    **Worked Examples**

    1. *Check an attacker IP*:
       ``threatfox_ip_lookup(ip="139.180.203.104")``

    2. *Exact match only*:
       ``threatfox_ip_lookup(ip="139.180.203.104", exact_match=true)``
    """
    _audit_log("threatfox_ip_lookup", {"ip": params.ip})
    try:
        data = await _threatfox_request(params.ip, params.exact_match)
    except Exception as e:
        return _handle_api_error(e, context="threatfox")
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"ip": params.ip, "threatfox": data}, indent=2, ensure_ascii=False))
    return _truncate_if_needed(_format_threatfox_markdown(params.ip, data))


# ── Bulk lookup ──

class ThreatFoxIpLookupBulkInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ips: list[str] = Field(..., min_length=1, max_length=25)
    exact_match: bool = Field(default=False)
    response_format: str = Field(default="markdown")

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, v):
        import ipaddress
        for ip in v:
            try: ipaddress.ip_address(ip.strip())
            except ValueError: raise ValueError(f"Invalid IP: {ip}")
        return v


@mcp.tool(
    name="threatfox_ip_lookup_bulk",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
)
async def threatfox_ip_lookup_bulk(params: ThreatFoxIpLookupBulkInput) -> str:
    """Check multiple IPs against ThreatFox concurrently (max 25).

    Returns per-IP malware family + confidence. Fan-out via asyncio.gather.

    **Worked Examples**

    1. *Batch attribution*:
       ``threatfox_ip_lookup_bulk(ips=["139.180.203.104","101.200.193.211"])``
    """
    _audit_log("threatfox_ip_lookup_bulk", {"count": len(params.ips)})

    async def _lookup_one(ip: str) -> dict:
        try:
            data = await _threatfox_request(ip.strip(), params.exact_match)
            items = data.get("data", [])
            return {"ip": ip, "matches": len(items),
                    "malware": [e.get("malware_printable") or e.get("malware","?") for e in items[:3]],
                    "confidence": max((e.get("confidence_level",0) for e in items), default=0)}
        except Exception as e:
            return {"ip": ip, "error": _handle_api_error(e, context=ip)}

    results = await asyncio.gather(*[_lookup_one(ip) for ip in params.ips])
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(results, indent=2, ensure_ascii=False))
    lines = ["# ThreatFox Bulk Lookup", ""]
    for r in results:
        if "error" in r:
            lines.append(f"- **{r['ip']}** — ⚠️ {r['error']}")
        elif r["matches"] == 0:
            lines.append(f"- `{r['ip']}` — clean (0 matches)")
        else:
            lines.append(f"- `{r['ip']}` — {r['matches']} matches, malware: {', '.join(r['malware'][:3])}, confidence: {r['confidence']}/100")
    return _truncate_if_needed("\n".join(lines))
