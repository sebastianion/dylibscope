from __future__ import annotations

from dylibscope.security_analysis.derived_scoring import METRIC_WEIGHTS, compare_observation_scores, score_observation


def observation(cfg_edges: int, symbols: int, mach_ports: int = 0) -> dict:
    return {
        "library": "libexample.dylib",
        "ios_version": "iPhone1,1_1.0_1A000",
        "metrics": {
            "num_symbols": {"level": "high", "value": symbols},
            "imported_function_count": {"level": "high", "value": 20},
            "exported_function_count": {"level": "high", "value": 5},
            "num_sections": {"level": "high", "value": 10},
            "cfg_edge_count": {"level": "low", "value": cfg_edges},
            "internal_function_count": {"level": "low", "value": 30},
            "internal_variable_count": {"level": "low", "value": 30},
            "allocation_call_count": {"level": "low", "value": 2},
            "syscall_function_count": {"level": "low", "value": 0},
            "mach_port_function_count": {"level": "low", "value": mach_ports},
        },
    }


def test_profile_weights_are_reused_with_storage_metric_names() -> None:
    assert METRIC_WEIGHTS["num_symbols"] == 0.55
    assert METRIC_WEIGHTS["imported_function_count"] == 0.30
    assert METRIC_WEIGHTS["num_sections"] == 0.15
    assert METRIC_WEIGHTS["cfg_edge_count"] == 0.50
    assert METRIC_WEIGHTS["allocation_call_count"] == 0.25
    assert METRIC_WEIGHTS["mach_port_function_count"] == 0.15
    assert METRIC_WEIGHTS["syscall_function_count"] == 0.10


def test_score_observation_returns_band_and_profile_contributors() -> None:
    score = score_observation(observation(cfg_edges=800, symbols=300))

    assert score["score"] is not None
    assert score["band"] in {"low_static_complexity", "medium_static_complexity", "high_static_complexity"}
    assert score["confidence"] == "high"
    assert score["available_metric_count"] == 7
    assert score["profile_source"].startswith("security_analysis.profiles")
    assert score["profile_raw_risk"]["hla_raw_risk"] is not None
    assert score["profile_raw_risk"]["lla_raw_risk"] is not None
    assert score["top_contributors"]
    assert score["interpretation_note"]


def test_context_only_metrics_are_not_scored() -> None:
    score = score_observation(
        observation(cfg_edges=800, symbols=300),
        metric_filter=["internal_function_count", "exported_function_count"],
    )

    assert score["score"] is None
    assert score["band"] == "insufficient_data"
    assert score["confidence"] == "none"
    assert score["ignored_metric_filters"] == ["internal_function_count", "exported_function_count"]


def test_score_observation_flags_mach_port_usage() -> None:
    score = score_observation(observation(cfg_edges=800, symbols=300, mach_ports=2))

    assert "mach_port_related_code_present" in score["risk_points"]


def test_compare_observation_scores_reports_metric_deltas() -> None:
    before = observation(cfg_edges=800, symbols=300)
    after = observation(cfg_edges=900, symbols=350, mach_ports=1)

    comparison = compare_observation_scores(before, after)
    deltas = {item["metric"]: item for item in comparison["metric_deltas"]}

    assert comparison["score_delta"] is not None
    assert comparison["trend"] in {
        "expanded_static_surface",
        "reduced_static_surface",
        "stable_static_surface",
    }
    assert deltas["cfg_edge_count"]["absolute_delta"] == 100
    assert deltas["num_symbols"]["absolute_delta"] == 50
    assert deltas["mach_port_function_count"]["absolute_delta"] == 1
