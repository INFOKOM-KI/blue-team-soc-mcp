#!/usr/bin/env python3
"""
3-Sum Threat Detection Engine pure evaluation logic.

Engine A: Multi-IoC Risk Thresholding
    Finds srcip values appearing across 3 alert categories, sums risk scores,
    flags combinations ≥ threshold.

Engine B: 3-Source Volumetric Z-Score Anomaly Detection
    Computes rolling μ/σ over per-minute alert counts from 3 sources,
    triggers when all 3 simultaneously cross Z ≥ threshold.

Stdlib math only - no numpy dependency for 30 float ops per source.
Dict based intersection instead of pandas DataFrame for srcip grouping.
"""

from __future__ import annotations
import logging
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("blue_team_mcp.three_sum")

DEFAULT_THRESHOLD_SCORE = 10
DEFAULT_Z_THRESHOLD = 2.5
DEFAULT_WINDOW_MINUTES = 30


# Result types

@dataclass
class EngineAResult:
    """One 3-Sum trigger from Engine A."""
    srcip: str
    scores: Dict[str, int]          # category_label → score
    total_score: int
    severity: str = "CRITICAL"


@dataclass
class SourceStats:
    """Rolling statistics for one Engine B alert source."""
    label: str
    bucket_count: int = 0
    mean: float = 0.0
    stddev: float = 0.0
    max_z: float = 0.0
    peak_at: Optional[str] = None
    z_scores: List[float] = field(default_factory=list)


@dataclass
class SimultaneousTrigger:
    """A 3-source simultaneous Z-score spike."""
    at: str                         # ISO timestamp of the 1-minute bucket
    z_scores: Dict[str, float]      # source_label -> Z-score


@dataclass
class EngineBResult:
    """Full result from one Engine B evaluation."""
    evaluated: bool
    sources: Dict[str, SourceStats]
    simultaneous_triggers: List[SimultaneousTrigger]


# Engine A: Multi-IoC Risk Thresholding

def evaluate_engine_a(
    category_a_srcips: List[Tuple[str, int]],
    category_b_srcips: List[Tuple[str, int]],
    category_c_srcips: List[Tuple[str, int]],
    category_a_label: str = "recon",
    category_b_label: str = "access_anomaly",
    category_c_label: str = "c2_exfil",
    threshold_score: int = DEFAULT_THRESHOLD_SCORE,
    exclude_srcips: Optional[List[str]] = None,
) -> Tuple[List[EngineAResult], Dict[str, int]]:
    """Evaluate the 3-Sum intersection of srcips across 3 alert categories.

    Args:
        category_*_srcips: Lists of (srcip, risk_score) per category.
        category_*_label: Human-readable category names.
        threshold_score: Minimum combined score to trigger (default 10).
        exclude_srcips: IPs to suppress before intersection.

    Returns:
        Tuple of (triggered_combinations, intersection_stats).
    """
    exclude_set: set[str] = set(exclude_srcips or [])

    def _build_map(entries: List[Tuple[str, int]], cat_label: str) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for srcip, score in entries:
            if srcip in exclude_set:
                continue
            result[srcip] = max(result.get(srcip, 0), score)
        logger.info(
            "[3SUM-EVAL] Engine-A: fetched %d distinct srcips in category %s",
            len(result), cat_label,
        )
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

    logger.info(
        "[3SUM-EVAL] Engine-A: intersection A∩B∩C = %d srcips", len(intersection),
    )

    triggers: List[EngineAResult] = []
    for srcip in sorted(intersection):
        scores = {
            category_a_label: map_a[srcip],
            category_b_label: map_b[srcip],
            category_c_label: map_c[srcip],
        }
        total = sum(scores.values())
        if total >= threshold_score:
            logger.info(
                "[3SUM-EVAL] Engine-A: srcip=%s %s=%d %s=%d %s=%d total=%d THRESHOLD=%d -> TRIGGER",
                srcip,
                category_a_label, scores[category_a_label],
                category_b_label, scores[category_b_label],
                category_c_label, scores[category_c_label],
                total, threshold_score,
            )
            triggers.append(EngineAResult(
                srcip=srcip, scores=scores, total_score=total,
            ))
        else:
            logger.info(
                "[3SUM-EVAL] Engine-A: srcip=%s total=%d THRESHOLD=%d -> NO",
                srcip, total, threshold_score,
            )

    return triggers, stats


# Engine B: 3-Source Volumetric Z-Score

def _compute_mean(values: List[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _compute_stddev(values: List[float], mean: float) -> float:
    if len(values) < 2:
        return 0.0
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def _z_score(value: float, mean: float, stddev: float) -> float:
    """Z-score with σ=0 guard — returns 0.0 instead of dividing by zero."""
    if stddev <= 0.0001:
        return 0.0
    return (value - mean) / stddev


def evaluate_engine_b(
    source_1_buckets: List[Dict[str, Any]],
    source_2_buckets: List[Dict[str, Any]],
    source_3_buckets: List[Dict[str, Any]],
    source_1_label: str = "recon",
    source_2_label: str = "access_anomaly",
    source_3_label: str = "c2_exfil",
    z_score_threshold: float = DEFAULT_Z_THRESHOLD,
) -> EngineBResult:
    """Evaluate simultaneous volumetric anomalies across 3 alert sources.

    Each ``source_*_buckets`` is a list of dicts with keys:
      - ``key_as_string`` (ISO timestamp of the 1-minute bucket)
      - ``doc_count`` (alert count for that bucket)

    Returns EngineBResult with per-source statistics and simultaneous triggers.
    """
    sources_data: List[Tuple[List[Dict[str, Any]], str]] = [
        (source_1_buckets, source_1_label),
        (source_2_buckets, source_2_label),
        (source_3_buckets, source_3_label),
    ]

    source_stats: Dict[str, SourceStats] = {}

    for buckets, label in sources_data:
        counts = [float(b.get("doc_count", 0)) for b in buckets]
        mean = _compute_mean(counts)
        stddev = _compute_stddev(counts, mean)

        if stddev <= 0.0001:
            logger.info(
                "[3SUM-EVAL] Engine-B: source=%s μ=%.1f σ≈0 - treating as non-anomalous",
                label, mean,
            )

        z_scores: List[float] = []
        max_z = 0.0
        peak_at: Optional[str] = None

        for i, bucket in enumerate(buckets):
            z = _z_score(counts[i], mean, stddev)
            z_scores.append(z)
            if z > max_z:
                max_z = z
                peak_at = bucket.get("key_as_string")

        logger.info(
            "[3SUM-EVAL] Engine-B: source=%s μ=%.1f σ=%.1f max_z=%.1f peak_at=%s",
            label, mean, stddev, max_z, peak_at,
        )

        source_stats[label] = SourceStats(
            label=label,
            bucket_count=len(buckets),
            mean=mean,
            stddev=stddev,
            max_z=max_z,
            peak_at=peak_at,
            z_scores=z_scores,
        )

    # Find simultaneous triggers: buckets where ALL 3 sources cross threshold
    simultaneous: List[SimultaneousTrigger] = []
    bucket_count = min(len(source_1_buckets), len(source_2_buckets), len(source_3_buckets))

    for i in range(bucket_count):
        z1 = source_stats[source_1_label].z_scores[i]
        z2 = source_stats[source_2_label].z_scores[i]
        z3 = source_stats[source_3_label].z_scores[i]

        if z1 >= z_score_threshold and z2 >= z_score_threshold and z3 >= z_score_threshold:
            ts = source_1_buckets[i].get("key_as_string", f"bucket_{i}")
            logger.info(
                "[3SUM-EVAL] Engine-B: ALL THREE Z ≥ %.1f at %s (%s=%.1f %s=%.1f %s=%.1f) → TRIGGER",
                z_score_threshold, ts,
                source_1_label, z1, source_2_label, z2, source_3_label, z3,
            )
            simultaneous.append(SimultaneousTrigger(
                at=ts,
                z_scores={
                    source_1_label: z1,
                    source_2_label: z2,
                    source_3_label: z3,
                },
            ))

    return EngineBResult(
        evaluated=True,
        sources=source_stats,
        simultaneous_triggers=simultaneous,
    )


# Result formatting (inline dict, no wrapper class)

def format_evaluation_dict(
    window_since: str,
    window_until: str,
    engine_a_results: Optional[Tuple[List[EngineAResult], Dict[str, int]]] = None,
    engine_b_result: Optional[EngineBResult] = None,
    evaluation_time_ms: float = 0.0,
) -> Dict[str, Any]:
    """Build the unified evaluation result as a plain dict for direct JSON serialization."""
    summary_parts: List[str] = []
    result: Dict[str, Any] = {
        "window": {"since": window_since, "until": window_until},
        "meta": {"evaluation_time_ms": round(evaluation_time_ms, 1)},
    }

    if engine_a_results is not None:
        triggers, stats = engine_a_results
        result["engine_a"] = {
            "evaluated": True,
            "triggers": [
                {"srcip": t.srcip, "scores": t.scores, "total_score": t.total_score, "severity": t.severity}
                for t in triggers
            ],
            "stats": stats,
        }
        if triggers:
            for t in triggers:
                summary_parts.append(
                    f"Engine-A CRITICAL: {t.srcip} scored {t.total_score} across {len(t.scores)} categories"
                )
        else:
            summary_parts.append("Engine-A: no threshold crossings")

    if engine_b_result is not None:
        result["engine_b"] = {
            "evaluated": engine_b_result.evaluated,
            "sources": {
                label: {
                    "mean": round(s.mean, 1),
                    "stddev": round(s.stddev, 2),
                    "max_z": round(s.max_z, 1),
                    "peak_at": s.peak_at,
                    "bucket_count": s.bucket_count,
                }
                for label, s in engine_b_result.sources.items()
            },
            "simultaneous_triggers": [
                {"at": st.at, "z_scores": {k: round(v, 1) for k, v in st.z_scores.items()}}
                for st in engine_b_result.simultaneous_triggers
            ],
        }
        if engine_b_result.simultaneous_triggers:
            for st in engine_b_result.simultaneous_triggers:
                z_str = ", ".join(f"{k}={v:.1f}" for k, v in st.z_scores.items())
                summary_parts.append(f"Engine-B TRIGGER at {st.at}: Z [{z_str}]")
        else:
            summary_parts.append("Engine-B: no simultaneous anomalies")

    result["summary"] = " | ".join(summary_parts) if summary_parts else "No evaluation data"
    return result


# Utility: CIDR normalization (opt-in, called by MCP handler)

def normalize_srcip_to_cidr(
    srcips: List[str],
    prefix_length: int = 24,
) -> Dict[str, str]:
    """Group IPs by /prefix_length for opt-in CIDR normalization.
    Returns a mapping: srcip → cidr_key (e.g., '109.123.239.235' -> '109.123.239.0/24').
    IPs that fail to parse are mapped to themselves.
    """
    import ipaddress

    result: Dict[str, str] = {}
    for ip in srcips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 4:
                network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
                result[ip] = str(network.network_address) + f"/{prefix_length}"
            else:
                network = ipaddress.ip_network(f"{ip}/{64}", strict=False)
                result[ip] = str(network.network_address) + "/64"
        except ValueError:
            result[ip] = ip
    return result
