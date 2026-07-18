"""
© TangerangKota-CSIRT
Pure evaluation logic for 3-Sum Threat Detection.
Zero external dependencies - stdlib only. Testable without httpx/pydantic/mcp.
"""
from __future__ import annotations
import math
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("blue_team_mcp.three_sum")

DEFAULT_THRESHOLD_SCORE = 10
DEFAULT_Z_THRESHOLD = 2.5
DEFAULT_WINDOW_MINUTES = 30


def evaluate_engine_a(
    category_a_srcips: List[Tuple[str, int]],
    category_b_srcips: List[Tuple[str, int]],
    category_c_srcips: List[Tuple[str, int]],
    category_a_label: str = "recon",
    category_b_label: str = "access_anomaly",
    category_c_label: str = "c2_exfil",
    threshold_score: int = DEFAULT_THRESHOLD_SCORE,
    exclude_srcips: Optional[List[str]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    _EXCLUDE_IP_FALLBACKS: set[str] = {"0.0.0.0", "unknown", ""}
    exclude_set = set(exclude_srcips or [])
    exclude_set.update(_EXCLUDE_IP_FALLBACKS)

    def _build_map(entries, cat_label):
        result = {}
        for srcip, score in entries:
            if srcip in exclude_set:
                continue
            result[srcip] = max(result.get(srcip, 0), score)
        logger.info("[3SUM-EVAL] Engine-A: fetched %d distinct srcips in %s", len(result), cat_label)
        return result

    map_a = _build_map(category_a_srcips, category_a_label)
    map_b = _build_map(category_b_srcips, category_b_label)
    map_c = _build_map(category_c_srcips, category_c_label)
    intersection = set(map_a.keys()) & set(map_b.keys()) & set(map_c.keys())
    stats = {
        f"distinct_srcips_{category_a_label}": len(map_a),
        f"distinct_srcips_{category_b_label}": len(map_b),
        f"distinct_srcips_{category_c_label}": len(map_c),
        "intersection_count": len(intersection),
    }
    logger.info("[3SUM-EVAL] Engine-A: intersection A∩B∩C = %d srcips", len(intersection))
    triggers = []
    for srcip in sorted(intersection):
        scores = {
            category_a_label: map_a[srcip],
            category_b_label: map_b[srcip],
            category_c_label: map_c[srcip],
        }
        total = sum(scores.values())
        if total >= threshold_score:
            logger.info("[3SUM-EVAL] Engine-A: srcip=%s total=%d -> TRIGGER", srcip, total)
            triggers.append({"srcip": srcip, "scores": scores,
                             "total_score": total, "severity": "CRITICAL"})
    return triggers, stats


def _compute_mean(values):
    return sum(values) / len(values) if values else 0.0


def _compute_stddev(values, mean):
    if len(values) < 2:
        return 0.0
    return math.sqrt(sum((x - mean) ** 2 for x in values) / len(values))


def _z_score(value, mean, stddev):
    return 0.0 if stddev <= 0.0001 else (value - mean) / stddev


def evaluate_engine_b(
    source_1_buckets: List[Dict[str, Any]],
    source_2_buckets: List[Dict[str, Any]],
    source_3_buckets: List[Dict[str, Any]],
    source_1_label: str = "recon",
    source_2_label: str = "access_anomaly",
    source_3_label: str = "c2_exfil",
    z_score_threshold: float = DEFAULT_Z_THRESHOLD,
    account_lockouts_total: int = 0,
) -> Dict[str, Any]:
    source_stats = {}
    for buckets, label in [
        (source_1_buckets, source_1_label),
        (source_2_buckets, source_2_label),
        (source_3_buckets, source_3_label),
    ]:
        counts = [float(b.get("doc_count", 0)) for b in buckets]
        mean = _compute_mean(counts)
        stddev = _compute_stddev(counts, mean)
        z_scores = [_z_score(c, mean, stddev) for c in counts]
        max_z = max(z_scores) if z_scores else 0.0
        peak_at = buckets[z_scores.index(max_z)]["key_as_string"] if z_scores and max_z > 0 else None
        logger.info("[3SUM-EVAL] Engine-B: source=%s μ=%.1f σ=%.2f max_z=%.1f", label, mean, stddev, max_z)
        source_stats[label] = {
            "label": label, "bucket_count": len(buckets),
            "mean": mean, "stddev": stddev,
            "max_z": max_z, "peak_at": peak_at, "z_scores": z_scores,
        }
    simultaneous = []
    for i in range(min(len(source_1_buckets), len(source_2_buckets), len(source_3_buckets))):
        zs = {lbl: source_stats[lbl]["z_scores"][i] for lbl in
              [source_1_label, source_2_label, source_3_label]}
        if all(z >= z_score_threshold for z in zs.values()):
            ts = source_1_buckets[i].get("key_as_string", f"bucket_{i}")
            simultaneous.append({"at": ts, "z_scores": zs})
    return {"evaluated": True, "sources": source_stats,
            "simultaneous_triggers": simultaneous, "account_lockouts_total": account_lockouts_total}


def format_evaluation_dict(
    window_since: str, window_until: str,
    engine_a_results=None, engine_b_result=None,
    evaluation_time_ms: float = 0.0,
    geo_samples=None, domain_samples=None,
) -> Dict[str, Any]:
    summary_parts = []
    result = {
        "window": {"since": window_since, "until": window_until},
        "meta": {"evaluation_time_ms": round(evaluation_time_ms, 1)},
    }
    if engine_a_results is not None:
        triggers, stats = engine_a_results
        tl = list(triggers)
        for t in tl:
            if geo_samples and t["srcip"] in geo_samples:
                t["geo_hints"] = geo_samples[t["srcip"]]
            if domain_samples and t["srcip"] in domain_samples:
                t["domain_hints"] = domain_samples[t["srcip"]]
        result["engine_a"] = {"evaluated": True, "triggers": tl, "stats": stats}
        if triggers:
            summary_parts.extend(f"Engine-A CRITICAL: {t['srcip']} scored {t['total_score']}" for t in triggers)
        else:
            summary_parts.append("Engine-A: no threshold crossings")
    if engine_b_result is not None:
        result["engine_b"] = {
            "evaluated": engine_b_result["evaluated"],
            "sources": {
                lbl: {"mean": round(s["mean"], 1), "stddev": round(s["stddev"], 2),
                      "max_z": round(s["max_z"], 1), "peak_at": s["peak_at"],
                      "bucket_count": s["bucket_count"]}
                for lbl, s in engine_b_result["sources"].items()
            },
            "simultaneous_triggers": [
                {"at": st["at"], "z_scores": {k: round(v, 1) for k, v in st["z_scores"].items()}}
                for st in engine_b_result["simultaneous_triggers"]
            ],
        }
        if engine_b_result.get("account_lockouts_total", 0) > 0:
            result["engine_b"]["account_lockouts_observed"] = engine_b_result["account_lockouts_total"]
        if engine_b_result["simultaneous_triggers"]:
            for st in engine_b_result["simultaneous_triggers"]:
                z_str = ", ".join(f"{k}={v:.1f}" for k, v in st["z_scores"].items())
                summary_parts.append(f"Engine-B TRIGGER at {st['at']}: Z [{z_str}]")
        else:
            summary_parts.append("Engine-B: no simultaneous anomalies")
    result["summary"] = " | ".join(summary_parts) if summary_parts else "No evaluation data"

    # ── F-4: Unified cross-engine scoring ──
    ea_triggered = bool(engine_a_results and engine_a_results[0])
    eb_triggered = bool(engine_b_result and engine_b_result.get("simultaneous_triggers"))

    # Extract Engine A max score and Engine B max Z
    ea_max_score = 0.0
    if engine_a_results:
        triggers, _ = engine_a_results
        ea_max_score = max((t.get("total_score", 0) for t in triggers), default=0.0)
    eb_max_z = 0.0
    if engine_b_result:
        for s in engine_b_result.get("sources", {}).values():
            eb_max_z = max(eb_max_z, s.get("max_z", 0.0))

    # Overlap bonus: Engine A trigger IPs active during Engine B spike windows
    overlap_bonus = 0.0
    if ea_triggered and eb_triggered:
        overlap_bonus = 0.3  # both engines independently flagged activity

    # Compute unified score (0.0–1.3, clamped to 1.0)
    ea_component = 0.5 if ea_triggered else 0.0
    eb_component = 0.5 if eb_triggered else 0.0
    unified_score = min(1.0, round(ea_component + eb_component + overlap_bonus, 2))

    severity = (
        "CRITICAL" if unified_score >= 1.0 else
        "HIGH" if unified_score >= 0.5 else
        "MEDIUM" if unified_score >= 0.3 else
        "LOW"
    )

    result["unified"] = {
        "score": unified_score,
        "severity": severity,
        "components": {
            "engine_a_triggered": ea_triggered,
            "engine_b_triggered": eb_triggered,
            "overlap_bonus": overlap_bonus > 0,
        },
        "details": {
            "engine_a_max_score": ea_max_score,
            "engine_b_max_z": round(eb_max_z, 1),
        },
    }
    if unified_score >= 0.5:
        summary_parts.append(f"Unified: {severity} ({unified_score})")
        result["summary"] = " | ".join(summary_parts)

    return result


def normalize_srcip_to_cidr(srcips: List[str], prefix_length: int = 24) -> Dict[str, str]:
    import ipaddress
    result = {}
    for ip in srcips:
        try:
            addr = ipaddress.ip_address(ip)
            bits = prefix_length if addr.version == 4 else 64
            net = ipaddress.ip_network(f"{ip}/{bits}", strict=False)
            result[ip] = str(net.network_address) + f"/{bits}"
        except ValueError:
            result[ip] = ip
    return result
