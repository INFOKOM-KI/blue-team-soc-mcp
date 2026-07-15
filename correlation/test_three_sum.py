#!/usr/bin/env python3
"""
Self-contained assert-based tests for three_sum_engine.py.
Run:  python3 correlation/test_three_sum.py
No test framework required - pure assert checks.
"""

from __future__ import annotations
import math
import sys
import os

# Ensure the correlation package is importable from the test's location
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlation.three_sum_engine import (
    evaluate_engine_a,
    evaluate_engine_b,
    EngineAResult,
    EngineBResult,
    SimultaneousTrigger,
    _compute_mean,
    _compute_stddev,
    _z_score,
)


# Fixture generators

def _fixture_happy_path():
    """3 srcips, one appears in all 3 categories with scores summing to 11 (≥10)."""
    # srcip shared across all three
    attacker = "109.123.239.235"
    return (
        [(attacker, 3), ("45.33.32.156", 3)],          # A: recon
        [(attacker, 4), ("45.33.32.156", 4)],           # B: access_anomaly
        [(attacker, 4), ("185.220.101.42", 4)],         # C: c2_exfil
    )


def _fixture_sub_threshold():
    """Same srcip in all 3 categories but scores sum to 8 (< 10)."""
    attacker = "109.123.239.235"
    return (
        [(attacker, 2)],   # A: low recon score
        [(attacker, 3)],   # B: low access score
        [(attacker, 3)],   # C: low c2 score (total 8)
    )


def _fixture_missing_category():
    """Same srcip in only 2 of 3 categories — no match."""
    attacker = "109.123.239.235"
    return (
        [(attacker, 3)],
        [(attacker, 4)],
        [],                # C: empty - attacker absent
    )


def _fixture_many_noise():
    """Many IPs, only one matches all 3 (noise IPs are disjoint across categories)."""
    attacker = "109.123.239.235"
    # Category A: attacker + range 1-49
    a = [(attacker, 3)] + [(f"203.0.113.{i}", 3) for i in range(1, 50)]
    # Category B: attacker + range 50-99 (disjoint from A's noise)
    b = [(attacker, 4)] + [(f"203.0.113.{i}", 4) for i in range(50, 100)]
    # Category C: attacker + range 100-149 (disjoint from A and B)
    c = [(attacker, 4)] + [(f"203.0.113.{i}", 4) for i in range(100, 150)]
    return (a, b, c)


def _fixture_engine_b_simultaneous():
    """All 3 sources spike at bucket index 13 (30-bucket window, enough that μ/σ aren't distorted)."""
    ts_minutes = [f"2026-07-15T09:{m:02d}:00Z" for m in range(0, 30)]
    # Source 1: steady 2, spikes to 50 at minute 13
    s1 = [{"key_as_string": ts, "doc_count": 2} for ts in ts_minutes]
    s1[13]["doc_count"] = 50
    # Source 2: steady 5, spikes to 52 at minute 13
    s2 = [{"key_as_string": ts, "doc_count": 5} for ts in ts_minutes]
    s2[13]["doc_count"] = 52
    # Source 3: steady 1, spikes to 38 at minute 13
    s3 = [{"key_as_string": ts, "doc_count": 1} for ts in ts_minutes]
    s3[13]["doc_count"] = 38
    return s1, s2, s3


def _fixture_engine_b_staggered():
    """Source 1 spikes at minute 13, source 2 at minute 17, source 3 at minute 9 — no simultaneous."""
    ts_minutes = [f"2026-07-15T09:{m:02d}:00Z" for m in range(0, 30)]
    s1 = [{"key_as_string": ts, "doc_count": 2} for ts in ts_minutes]
    s1[13]["doc_count"] = 50  # spike at min 13
    s2 = [{"key_as_string": ts, "doc_count": 5} for ts in ts_minutes]
    s2[17]["doc_count"] = 52  # spike at min 17
    s3 = [{"key_as_string": ts, "doc_count": 1} for ts in ts_minutes]
    s3[9]["doc_count"] = 38   # spike at min 9
    return s1, s2, s3


def _fixture_engine_b_zero_variance():
    """All buckets have identical counts → σ = 0."""
    ts_minutes = [f"2026-07-15T09:{m:02d}:00Z" for m in range(0, 30)]
    s1 = [{"key_as_string": ts, "doc_count": 5} for ts in ts_minutes]
    s2 = [{"key_as_string": ts, "doc_count": 10} for ts in ts_minutes]
    s3 = [{"key_as_string": ts, "doc_count": 2} for ts in ts_minutes]
    return s1, s2, s3


def _fixture_engine_b_baseline_noise():
    """All sources at low, stable counts — no anomalies."""
    ts_base = "2026-07-15T09:2"
    s1 = [{"key_as_string": f"{ts_base}{i}:00Z", "doc_count": i % 3 + 1} for i in range(30)]
    s2 = [{"key_as_string": f"{ts_base}{i}:00Z", "doc_count": i % 4 + 2} for i in range(30)]
    s3 = [{"key_as_string": f"{ts_base}{i}:00Z", "doc_count": i % 2 + 1} for i in range(30)]
    return s1, s2, s3


# Tests

def test_engine_a_happy_path():
    """One srcip across all 3 categories, score 11 ≥ 10 → triggers."""
    a, b, c = _fixture_happy_path()
    triggers, stats = evaluate_engine_a(a, b, c, threshold_score=10)
    assert len(triggers) == 1, f"Expected 1 trigger, got {len(triggers)}"
    assert triggers[0].srcip == "109.123.239.235"
    assert triggers[0].total_score == 11
    assert stats["intersection_count"] == 1
    print("  PASS test_engine_a_happy_path")


def test_engine_a_sub_threshold():
    """Same srcip across all 3, but total score 8 < 10 → no trigger."""
    a, b, c = _fixture_sub_threshold()
    triggers, stats = evaluate_engine_a(a, b, c, threshold_score=10)
    assert len(triggers) == 0, f"Expected 0 triggers, got {len(triggers)}"
    assert stats["intersection_count"] == 1
    print("  PASS test_engine_a_sub_threshold")


def test_engine_a_missing_category():
    """Srcip in 2 of 3 categories → intersection empty → no trigger."""
    a, b, c = _fixture_missing_category()
    triggers, stats = evaluate_engine_a(a, b, c, threshold_score=10)
    assert len(triggers) == 0
    assert stats["intersection_count"] == 0
    print("  PASS test_engine_a_missing_category")


def test_engine_a_exclude_srcips():
    """Attacker IP is in exclude list → no trigger."""
    a, b, c = _fixture_happy_path()
    triggers, stats = evaluate_engine_a(a, b, c, threshold_score=10,
                                         exclude_srcips=["109.123.239.235"])
    assert len(triggers) == 0
    assert stats["intersection_count"] == 0
    print("  PASS test_engine_a_exclude_srcips")


def test_engine_a_many_noise():
    """Attacker among 50-70 noise IPs, still found."""
    a, b, c = _fixture_many_noise()
    triggers, stats = evaluate_engine_a(a, b, c, threshold_score=10)
    assert len(triggers) == 1
    assert triggers[0].srcip == "109.123.239.235"
    # Only the attacker appears in all 3
    assert stats["intersection_count"] == 1
    print("  PASS test_engine_a_many_noise")


def test_engine_b_simultaneous_spike():
    """All 3 sources spike at the same bucket → simultaneous trigger."""
    s1, s2, s3 = _fixture_engine_b_simultaneous()
    result = evaluate_engine_b(s1, s2, s3, z_score_threshold=2.5)
    assert len(result.simultaneous_triggers) > 0, "Expected at least one simultaneous trigger"
    trigger = result.simultaneous_triggers[0]
    # All 3 Z-scores should be ≥ 2.5
    for z in trigger.z_scores.values():
        assert z >= 2.5, f"Expected Z ≥ 2.5, got {z}"
    # The peak should be at minute 13
    assert "09:13" in trigger.at, f"Expected spike at minute 13, got {trigger.at}"
    print("  PASS test_engine_b_simultaneous_spike")


def test_engine_b_staggered_spikes():
    """Each source spikes at a different minute → no simultaneous trigger."""
    s1, s2, s3 = _fixture_engine_b_staggered()
    result = evaluate_engine_b(s1, s2, s3, z_score_threshold=2.5)
    assert len(result.simultaneous_triggers) == 0, (
        f"Expected 0 simultaneous triggers with staggered spikes, got {len(result.simultaneous_triggers)}"
    )
    print("  PASS test_engine_b_staggered_spikes")


def test_engine_b_zero_variance():
    """All buckets identical → σ = 0 → Z = 0 for all → no trigger, no crash."""
    s1, s2, s3 = _fixture_engine_b_zero_variance()
    result = evaluate_engine_b(s1, s2, s3, z_score_threshold=2.5)
    for label, stats in result.sources.items():
        assert stats.stddev == 0.0, f"Expected σ=0 for {label}, got {stats.stddev}"
        assert stats.max_z == 0.0, f"Expected max_z=0 for {label}, got {stats.max_z}"
    assert len(result.simultaneous_triggers) == 0
    print("  PASS test_engine_b_zero_variance")


def test_engine_b_baseline_noise():
    """Normal variation → no simultaneous spikes crossing Z=2.5."""
    s1, s2, s3 = _fixture_engine_b_baseline_noise()
    result = evaluate_engine_b(s1, s2, s3, z_score_threshold=2.5)
    # With 30 buckets of low-variance data, no individual Z should exceed ~2.5
    assert len(result.simultaneous_triggers) == 0, (
        f"Expected 0 simultaneous triggers on baseline noise, got {len(result.simultaneous_triggers)}"
    )
    print("  PASS test_engine_b_baseline_noise")


def test_math_helpers():
    """Validate the stateless math helpers."""
    # Mean
    assert _compute_mean([1.0, 2.0, 3.0]) == 2.0
    assert _compute_mean([]) == 0.0
    assert _compute_mean([5.0]) == 5.0

    # Stddev
    m = _compute_mean([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])
    s = _compute_stddev([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0], m)
    assert abs(s - 2.0) < 0.01, f"Expected stddev ~2.0, got {s}"

    # σ=0 guard
    assert _z_score(5.0, 5.0, 0.0) == 0.0
    assert _z_score(5.0, 5.0, 0.00001) == 0.0  # below epsilon

    # Normal Z-score
    assert _z_score(10.0, 5.0, 2.0) == 2.5
    assert _z_score(2.0, 5.0, 2.0) == -1.5

    print("PASS test_math_helpers")


# Main

if __name__ == "__main__":
    print("Running three_sum_engine tests...\n")
    tests = [
        test_engine_a_happy_path,
        test_engine_a_sub_threshold,
        test_engine_a_missing_category,
        test_engine_a_exclude_srcips,
        test_engine_a_many_noise,
        test_engine_b_simultaneous_spike,
        test_engine_b_staggered_spikes,
        test_engine_b_zero_variance,
        test_engine_b_baseline_noise,
        test_math_helpers,
    ]
    passed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except AssertionError as e:
            print(f"FAIL {test_fn.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {test_fn.__name__}: {type(e).__name__}: {e}")

    print(f"\n{passed}/{len(tests)} tests passed")
    if passed == len(tests):
        print("All tests passed.")
        sys.exit(0)
    else:
        print("Some tests FAILED.")
        sys.exit(1)
