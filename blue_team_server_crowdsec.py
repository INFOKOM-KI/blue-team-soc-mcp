#!/usr/bin/env python3
"""
blue_team_mcp — MCP server untuk kapabilitas blue team / detection engineering
TangerangKota-CSIRT.

Mendukung tiga transport:
  - stdio            (default, lokal, subprocess)
  - sse               (remote, legacy Server-Sent Events)
  - streamable_http   (remote, modern, stateless)

Lihat PRD.md, CLAUDE.md, AGENTS.md, SKILLS.md di root repo untuk konteks desain lengkap.
"""

from __future__ import annotations
import argparse
import ipaddress
import logging
import os
import sys
from enum import Enum
from typing import Any, Optional
import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Logging — WAJIB ke stderr. stdout dipakai protokol MCP untuk transport stdio.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("blue_team_mcp")

# Constants
CROWDSEC_BASE_URL = "https://cti.api.crowdsec.net"
CROWDSEC_API_KEY_ENV = "CROWDSEC_API_KEY"
HTTP_TIMEOUT_SECONDS = 30.0
CHARACTER_LIMIT = 25000

# Rentang IP privat/reserved — tool ini untuk threat intel IP publik, bukan internal network.
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

mcp = FastMCP("blue_team_mcp")

# Shared utilities
class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"

def _is_private_or_reserved(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETWORKS)

def _get_crowdsec_api_key() -> str:
    key = os.environ.get(CROWDSEC_API_KEY_ENV)
    if not key:
        raise RuntimeError(
            f"Environment variable {CROWDSEC_API_KEY_ENV} belum diset. "
            "Set API key CrowdSec CTI sebelum menjalankan server."
        )
    return key

async def _crowdsec_request(path: str) -> dict[str, Any]:
    """Reusable async GET request ke CrowdSec CTI API."""
    headers = {
        "x-api-key": _get_crowdsec_api_key(),
        "accept": "application/json",
        "User-Agent": "blue-team-mcp/1.0.0 (TangerangKota-CSIRT)",
    }
    url = f"{CROWDSEC_BASE_URL}{path}"
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

def _handle_api_error(e: Exception, context: str = "") -> str:
    """Consistent, actionable error formatting across all tools."""
    prefix = f"[{context}] " if context else ""
    if isinstance(e, httpx.HTTPStatusError):
        status = e.response.status_code
        if status == 401:
            return f"{prefix}Error: API key tidak valid atau belum diset (401)."
        if status == 404:
            return f"{prefix}Error: Data tidak ditemukan untuk target ini (404)."
        if status == 429:
            retry_after = e.response.headers.get("Retry-After")
            hint = f" Coba lagi setelah {retry_after} detik." if retry_after else " Coba lagi nanti."
            return f"{prefix}Error: Rate limit tercapai (429).{hint}"
        return f"{prefix}Error: API request gagal dengan status {status}."
    if isinstance(e, httpx.TimeoutException):
        return f"{prefix}Error: Request timeout setelah {HTTP_TIMEOUT_SECONDS}s. Coba lagi."
    if isinstance(e, RuntimeError):
        return f"{prefix}Error: {e}"
    logger.exception("Unexpected error in %s", context)
    return f"{prefix}Error: Terjadi kesalahan tak terduga ({type(e).__name__})."

def _truncate_if_needed(text: str) -> str:
    if len(text) <= CHARACTER_LIMIT:
        return text
    truncated = text[: CHARACTER_LIMIT]
    return (
        truncated
        + f"\n\n... [truncated - response melebihi {CHARACTER_LIMIT} karakter, "
        "gunakan filter lebih spesifik]"
    )

# Input models
class CrowdsecIpReputationInput(BaseModel):
    """Input model for single IP reputation lookup."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ip: str = Field(
        ...,
        description="Alamat IPv4 atau IPv6 publik yang akan dicek reputasinya (contoh: '1.2.3.4').",
        min_length=3,
        max_length=45,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' untuk laporan terbaca manusia, 'json' untuk data terstruktur.",
    )

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"'{v}' bukan alamat IP yang valid (IPv4/IPv6).") from exc
        return v

class CrowdsecIpReputationBulkInput(BaseModel):
    """Input model for batch IP reputation lookup."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ips: list[str] = Field(
        ...,
        description="Daftar alamat IP publik yang akan dicek reputasinya (maksimal 10 per panggilan "
        "untuk menghindari rate limit CrowdSec CTI).",
        min_length=1,
        max_length=10,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' untuk laporan terbaca manusia, 'json' untuk data terstruktur.",
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
            raise ValueError(f"IP tidak valid: {', '.join(invalid)}")
        return [ip.strip() for ip in v]

# Formatting helpers (Crowdsec)
def _format_crowdsec_markdown(ip: str, raw: dict[str, Any]) -> str:
    if "reputation" not in raw and "attack_details" not in raw:
        return f"# CrowdSec Reputation — {ip}\n\nTidak ditemukan data ancaman untuk IP ini (bersih)."

    lines = [f"# CrowdSec Reputation — {ip}", ""]
    reputation = raw.get("reputation", "unknown")
    lines.append(f"- **Reputasi**: {reputation}")

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
            lines.append(f"- **{name}**{f' — {label}' if label else ''}")

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
        lines.append("## CVE Terkait")
        for cve in cves:
            lines.append(f"- {cve}")

    return "\n".join(lines)

# Tools
@mcp.tool(
    name="crowdsec_ip_reputation",
    annotations={
        "title": "CrowdSec IP Reputation Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def crowdsec_ip_reputation(params: CrowdsecIpReputationInput) -> str:
    """
    Cek reputasi ancaman sebuah alamat IP publik menggunakan CrowdSec CTI Smoke API.

    Tool ini READ-ONLY, tidak melakukan blocking atau perubahan apa pun — hanya mengambil
    data threat intelligence (reputasi, behavior serangan, teknik MITRE ATT&CK terkait,
    CVE yang pernah dieksploitasi dari IP tersebut, dan riwayat kemunculan).

    Args:
        params (CrowdsecIpReputationInput): Parameter tervalidasi berisi:
            - ip (str): Alamat IPv4/IPv6 yang dicek (contoh: "185.220.101.1")
            - response_format ('markdown' | 'json'): Format output (default: markdown)

    Returns:
        str: Jika markdown, laporan reputasi terformat. Jika json, berisi field:
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

    Contoh pemakaian:
        - Dipakai saat: "IP 185.220.101.1 muncul di log Wazuh, cek reputasinya"
        - Jangan dipakai saat: butuh cek beberapa IP sekaligus (pakai crowdsec_ip_reputation_bulk)

    Error Handling:
        - "Error: API key tidak valid..." jika CROWDSEC_API_KEY salah/belum diset
        - "Error: Rate limit tercapai (429)..." jika kuota API habis
        - Validasi format IP ditangani otomatis oleh Pydantic sebelum request dikirim
    """
    try:
        raw = await _crowdsec_request(f"/v2/smoke/{params.ip}")
    except Exception as e:  # noqa: BLE001 - dikonversi ke pesan actionable di bawah
        return _handle_api_error(e, context="crowdsec_ip_reputation")

    if params.response_format == ResponseFormat.JSON:
        import json

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
        "title": "CrowdSec Bulk IP Reputation Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def crowdsec_ip_reputation_bulk(params: CrowdsecIpReputationBulkInput) -> str:
    """
    Cek reputasi ancaman untuk beberapa alamat IP publik sekaligus (maksimal 10 per panggilan)
    menggunakan CrowdSec CTI Smoke API.

    Tool ini READ-ONLY. Cocok dipakai saat triase daftar IP dari log/alert (mis. top talker
    di firewall) yang perlu diprioritaskan berdasarkan reputasi.

    Args:
        params (CrowdsecIpReputationBulkInput): Parameter tervalidasi berisi:
            - ips (list[str]): Daftar 1-10 alamat IP
            - response_format ('markdown' | 'json'): Format output (default: markdown)

    Returns:
        str: Ringkasan per-IP. Format markdown berupa daftar; format json berupa array objek
        dengan schema yang sama seperti crowdsec_ip_reputation per elemen, plus field "error"
        (string, optional) jika lookup untuk IP tertentu gagal.

    Contoh pemakaian:
        - Dipakai saat: "Ada 5 IP mencurigakan dari alert kemarin, cek reputasinya sekaligus"
        - Jangan dipakai saat: hanya 1 IP (pakai crowdsec_ip_reputation, lebih ringan)

    Error Handling:
        - Kegagalan pada satu IP tidak menggagalkan keseluruhan batch — error per-IP dilaporkan
          di dalam hasil, bukan menghentikan proses.
    """
    import json
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
            lines.append(f"- **{r['ip']}** — reputasi: `{r['reputation']}` | behaviors: {behaviors_str}")
        result = "\n".join(lines)

    return _truncate_if_needed(result)

# Entrypoint / transport selection
def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="blue_team_mcp — MCP server TangerangKota-CSIRT")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable_http", "http"],
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
        help="Transport MCP yang dipakai (default: stdio, atau env MCP_TRANSPORT).",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("MCP_HOST", "127.0.0.1"),
        help="Host bind untuk transport sse/streamable_http (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("MCP_PORT", "8000")),
        help="Port untuk transport sse/streamable_http (default: 8000).",
    )
    return parser

def main() -> None:
    args = _build_arg_parser().parse_args()

    if args.transport == "stdio":
        logger.info("Menjalankan blue_team_mcp via stdio transport")
        mcp.run(transport="stdio")
        return

    # FastMCP mengatur host/port lewat atribut settings sebelum .run() dipanggil.
    mcp.settings.host = args.host
    mcp.settings.port = args.port

    if args.transport == "sse":
        logger.info("Menjalankan blue_team_mcp via SSE transport di %s:%s", args.host, args.port)
        mcp.run(transport="sse")
    elif args.transport in ("streamable_http", "http"):
        logger.info(
            "Menjalankan blue_team_mcp via Streamable HTTP transport di %s:%s", args.host, args.port
        )
        mcp.run(transport="streamable-http")
    else:  # pragma: no cover - unreachable karena argparse choices
        raise ValueError(f"Transport tidak dikenal: {args.transport}")

if __name__ == "__main__":
    main()
