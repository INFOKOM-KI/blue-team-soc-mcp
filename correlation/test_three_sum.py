#!/usr/bin/env python3
"""
Self-contained assert-based tests for the inlined 3-Sum engine.
Run:  python3 correlation/test_three_sum.py
No test framework required - pure assert checks.
Imports directly from blue_team_server.py.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlation.three_sum_core import (
    evaluate_engine_a,
    evaluate_engine_b,
    _compute_mean,
    _compute_stddev,
    _z_score,
)


# Helper: build a trigger for comparison
def _trigger(srcip, scores, total):
    return {"srcip": srcip, "scores": scores, "total_score": total, "severity": "CRITICAL"}


# Engine A tests
def test_happy_path_3sum():
    """3 srcips, one appears in all 3 with scores summing to 11 (≥10)."""
    attacker = "109.123.239.235"
    triggers, stats = evaluate_engine_a(
        [(attacker, 3), ("1.2.3.4", 3)],            # cat A
        [(attacker, 4), ("5.6.7.8", 4)],            # cat B
        [(attacker, 4), ("9.10.11.12", 4)],          # cat C
        threshold_score=10,
    )
    assert len(triggers) == 1, f"Expected 1 trigger, got {len(triggers)}"
    assert triggers[0]["srcip"] == attacker
    assert triggers[0]["total_score"] == 11
    assert stats["intersection_count"] == 1


def test_sub_threshold():
    """srcip appears in all 3 but scores sum to 9 (< 10)."""
    triggers, stats = evaluate_engine_a(
        [("10.0.0.1", 3)],
        [("10.0.0.1", 3)],
        [("10.0.0.1", 3)],
        threshold_score=10,
    )
    assert len(triggers) == 0, f"Expected 0 triggers, got {len(triggers)}"
    assert stats["intersection_count"] == 1


def test_no_intersection():
    """No IP appears in all 3 categories."""
    triggers, stats = evaluate_engine_a(
        [("1.1.1.1", 3)],
        [("2.2.2.2", 4)],
        [("3.3.3.3", 4)],
    )
    assert len(triggers) == 0
    assert stats["intersection_count"] == 0


def test_exclude_srcips():
    """Excluded IP should be suppressed before intersection."""
    triggers, stats = evaluate_engine_a(
        [("1.2.3.4", 3), ("5.6.7.8", 3)],
        [("1.2.3.4", 4), ("5.6.7.8", 4)],
        [("1.2.3.4", 4), ("5.6.7.8", 4)],
        exclude_srcips=["1.2.3.4"],
    )
    assert len(triggers) == 1, f"Expected 1 trigger (5.6.7.8), got {len(triggers)}"
    assert triggers[0]["srcip"] == "5.6.7.8"


def test_fallback_ip_exclusion():
    """0.0.0.0 fallback from non-networked decoders must not trigger."""
    triggers, stats = evaluate_engine_a(
        [("0.0.0.0", 3)],
        [("0.0.0.0", 4)],
        [("0.0.0.0", 4)],
    )
    assert len(triggers) == 0, "0.0.0.0 must be excluded from intersection"


# Engine B tests
def test_engine_b_simultaneous_trigger():
    """All 3 sources cross Z threshold in same bucket → trigger."""
    # 10 buckets: spike at index 5
    quiet = [{"key_as_string": f"T-{i:02d}", "doc_count": 5} for i in range(10)]
    spike = [{"key_as_string": f"T-{i:02d}", "doc_count": 100 if i == 5 else 5} for i in range(10)]
    result = evaluate_engine_b(spike, spike, spike, z_score_threshold=2.5)
    assert result["evaluated"] is True
    assert len(result["simultaneous_triggers"]) >= 1, "Expected at least 1 simultaneous trigger"
    # The spike bucket should be triggered
    triggered_ts = {st["at"] for st in result["simultaneous_triggers"]}
    assert "T-05" in triggered_ts, f"Expected T-05 triggered, got {triggered_ts}"


def test_engine_b_staggered_spike_suppression():
    """Only 2 of 3 sources spike → no simultaneous trigger."""
    quiet = [{"key_as_string": f"T-{i:02d}", "doc_count": 5} for i in range(10)]
    spike = [{"key_as_string": f"T-{i:02d}", "doc_count": 100 if i == 5 else 5} for i in range(10)]
    result = evaluate_engine_b(spike, spike, quiet, z_score_threshold=2.5)
    assert len(result["simultaneous_triggers"]) == 0, "Staggered spike must not trigger"


def test_engine_b_zero_variance():
    """All buckets identical → σ=0 → Z=0 for all → no trigger."""
    flat = [{"key_as_string": f"T-{i:02d}", "doc_count": 5} for i in range(10)]
    result = evaluate_engine_b(flat, flat, flat, z_score_threshold=2.5)
    assert len(result["simultaneous_triggers"]) == 0, "Zero variance must not trigger"
    for s in result["sources"].values():
        assert s["stddev"] == 0.0, f"Expected stddev 0, got {s['stddev']}"
        assert s["max_z"] == 0.0


# Math helpers

def test_compute_mean():
    assert _compute_mean([1, 2, 3, 4, 5]) == 3.0
    assert _compute_mean([]) == 0.0

def test_compute_stddev():
    s = _compute_stddev([2, 4, 4, 4, 5, 5, 7, 9], _compute_mean([2, 4, 4, 4, 5, 5, 7, 9]))
    assert round(s, 2) == 2.0, f"Expected stddev=2.0, got {s}"


def test_z_score_zero_stddev():
    assert _z_score(5.0, 5.0, 0.0) == 0.0, "σ=0 guard must return 0.0"
    assert _z_score(5.0, 5.0, 0.00005) == 0.0, "Near-zero σ guard must return 0.0"


# Run
if __name__ == "__main__":
    tests = [
        ("happy_path_3sum", test_happy_path_3sum),
        ("sub_threshold", test_sub_threshold),
        ("no_intersection", test_no_intersection),
        ("exclude_srcips", test_exclude_srcips),
        ("fallback_ip_exclusion", test_fallback_ip_exclusion),
        ("engine_b_simultaneous_trigger", test_engine_b_simultaneous_trigger),
        ("engine_b_staggered_spike_suppression", test_engine_b_staggered_spike_suppression),
        ("engine_b_zero_variance", test_engine_b_zero_variance),
        ("compute_mean", test_compute_mean),
        ("compute_stddev", test_compute_stddev),
        ("z_score_zero_stddev", test_z_score_zero_stddev),
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f"{name}")
        except AssertionError as e:
            print(f"{name}: {e}")
            failures += 1
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(failures)
