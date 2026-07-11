"""API-facing heuristic scoring for normalized DylibScope observations.

This module adapts the existing ``security_analysis`` profile assumptions to
single-library and API responses. It intentionally works on already-extracted
static metrics. It does not detect vulnerabilities.
"""

from __future__ import annotations

import math
from statistics import median
from typing import Any, Dict, Iterable, List, Optional

try:
    from dylibscope.security_analysis.profiles import high_level_analysis as hla_profile
    from dylibscope.security_analysis.profiles import low_level_analysis as lla_profile
except Exception:  # pragma: no cover - defensive fallback for partial installs
    hla_profile = None
    lla_profile = None

INTERPRETATION_NOTE = (
    "This is a heuristic static-complexity indicator based on the existing "
    "DylibScope security-analysis profiles. It does not prove the presence or "
    "absence of vulnerabilities."
)

# Storage metric name -> profile metric name.
# The original HLA profile calls this metric ``import_count`` while the normalized
# storage layer exposes it as ``imported_function_count``.
HLA_METRIC_ALIASES: Dict[str, str] = {
    "num_symbols": "num_symbols",
    "imported_function_count": "import_count",
    "num_sections": "num_sections",
}

LLA_METRIC_ALIASES: Dict[str, str] = {
    "cfg_edge_count": "cfg_edge_count",
    "allocation_call_count": "allocation_call_count",
    "mach_port_function_count": "mach_port_function_count",
    "syscall_function_count": "syscall_function_count",
}

HLA_PROFILE_WEIGHTS: Dict[str, float] = (
    dict(hla_profile.W_RAW) if hla_profile is not None else {"num_symbols": 0.55, "import_count": 0.30, "num_sections": 0.15}
)

LLA_PROFILE_WEIGHTS: Dict[str, float] = (
    dict(lla_profile.WEIGHTS)
    if lla_profile is not None
    else {
        "cfg_edge_count": 0.50,
        "allocation_call_count": 0.25,
        "mach_port_function_count": 0.15,
        "syscall_function_count": 0.10,
    }
)

# API scoring uses the same profile weights and log scaling as the existing HLA
# and LLA reports. Caps are only used to map raw log-risk contributions to a
# 0..100 API score. They do not change the relative profile weights.
METRIC_LOG_CAPS: Dict[str, float] = {
    "num_symbols": 1000.0,
    "imported_function_count": 300.0,
    "num_sections": 30.0,
    "cfg_edge_count": 5000.0,
    "allocation_call_count": 100.0,
    "mach_port_function_count": 50.0,
    "syscall_function_count": 50.0,
}

METRIC_CATEGORIES: Dict[str, str] = {
    "num_symbols": "interface_surface",
    "imported_function_count": "interface_surface",
    "num_sections": "binary_structure",
    "cfg_edge_count": "implementation_complexity",
    "allocation_call_count": "memory_activity",
    "syscall_function_count": "privileged_interaction",
    "mach_port_function_count": "privileged_interaction",
}

# Context-only metrics are returned by the storage layer but are not part of the
# existing security-analysis risk profile. They are therefore not weighted in the
# API score.
CONTEXT_ONLY_METRICS = {"exported_function_count", "internal_function_count", "internal_variable_count"}


def _api_metric_weights() -> Dict[str, float]:
    """Return storage-level metric weights derived from existing profiles."""
    weights: Dict[str, float] = {}
    for api_name, profile_name in HLA_METRIC_ALIASES.items():
        if profile_name in HLA_PROFILE_WEIGHTS:
            weights[api_name] = float(HLA_PROFILE_WEIGHTS[profile_name])
    for api_name, profile_name in LLA_METRIC_ALIASES.items():
        if profile_name in LLA_PROFILE_WEIGHTS:
            weights[api_name] = float(LLA_PROFILE_WEIGHTS[profile_name])
    return weights


METRIC_WEIGHTS: Dict[str, float] = _api_metric_weights()


def is_number(value: Any) -> bool:
    """Return True for numeric metric values, excluding booleans."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def metric_value(observation: Dict[str, Any], metric_name: str) -> Any:
    """Extract one metric value from a repository/API observation."""
    metric = observation.get("metrics", {}).get(metric_name)
    if not metric:
        return None
    return metric.get("value")


def normalize_metric(metric_name: str, value: Any) -> Optional[float]:
    """Normalize a raw metric using the same log scale as existing profiles."""
    if not is_number(value):
        return None
    cap = METRIC_LOG_CAPS.get(metric_name)
    if cap is None or cap <= 0:
        return None
    raw = max(float(value), 0.0)
    normalized = min(math.log1p(raw) / math.log1p(cap), 1.0) * 100.0
    return round(normalized, 3)


def profile_raw_risk(observation: Dict[str, Any]) -> Dict[str, Optional[float]]:
    """Compute raw HLA/LLA risk using the existing profile functions when available."""
    symbols = metric_value(observation, "num_symbols")
    imports = metric_value(observation, "imported_function_count")
    sections = metric_value(observation, "num_sections")
    cfg = metric_value(observation, "cfg_edge_count")
    alloc = metric_value(observation, "allocation_call_count")
    mach = metric_value(observation, "mach_port_function_count")
    syscall = metric_value(observation, "syscall_function_count")

    hla_raw = None
    if all(is_number(value) for value in [symbols, imports, sections]):
        if hla_profile is not None:
            hla_raw = hla_profile.raw_risk_row(float(symbols), float(imports), float(sections))
        else:
            hla_raw = (
                HLA_PROFILE_WEIGHTS["num_symbols"] * math.log1p(max(float(symbols), 0.0))
                + HLA_PROFILE_WEIGHTS["import_count"] * math.log1p(max(float(imports), 0.0))
                + HLA_PROFILE_WEIGHTS["num_sections"] * math.log1p(max(float(sections), 0.0))
            )

    lla_raw = None
    if all(is_number(value) for value in [cfg, alloc, mach, syscall]):
        if lla_profile is not None:
            lla_raw = lla_profile.raw_risk_lib(float(cfg), float(alloc), float(mach), float(syscall))
        else:
            lla_raw = (
                LLA_PROFILE_WEIGHTS["cfg_edge_count"] * math.log1p(max(float(cfg), 0.0))
                + LLA_PROFILE_WEIGHTS["allocation_call_count"] * math.log1p(max(float(alloc), 0.0))
                + LLA_PROFILE_WEIGHTS["mach_port_function_count"] * math.log1p(max(float(mach), 0.0))
                + LLA_PROFILE_WEIGHTS["syscall_function_count"] * math.log1p(max(float(syscall), 0.0))
            )

    return {"hla_raw_risk": hla_raw, "lla_raw_risk": lla_raw}


def classify_score(score: Optional[float]) -> str:
    """Map a normalized API score to a human-readable band."""
    if score is None:
        return "insufficient_data"
    if score >= 66.0:
        return "high_static_complexity"
    if score >= 33.0:
        return "medium_static_complexity"
    return "low_static_complexity"


def classify_confidence(available_weight_ratio: float) -> str:
    """Map metric coverage to a confidence label."""
    if available_weight_ratio >= 0.75:
        return "high"
    if available_weight_ratio >= 0.45:
        return "medium"
    if available_weight_ratio > 0:
        return "low"
    return "none"


def classify_trend(score_delta: Optional[float]) -> str:
    """Classify first-to-last score movement."""
    if score_delta is None:
        return "not_comparable"
    if score_delta >= 5.0:
        return "expanded_static_surface"
    if score_delta <= -5.0:
        return "reduced_static_surface"
    return "stable_static_surface"


def _selected_metric_names(metric_filter: Optional[Iterable[str]]) -> List[str]:
    if metric_filter:
        return [name for name in dict.fromkeys(metric_filter) if name in METRIC_WEIGHTS]
    return list(METRIC_WEIGHTS)


def _ignored_scoring_metrics(metric_filter: Optional[Iterable[str]]) -> List[str]:
    if not metric_filter:
        return []
    ignored = []
    for metric_name in dict.fromkeys(metric_filter):
        if metric_name not in METRIC_WEIGHTS:
            ignored.append(metric_name)
    return ignored


def _category_summary(contributions: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    categories: Dict[str, Dict[str, Any]] = {}
    for item in contributions:
        category = item["category"]
        if category not in categories:
            categories[category] = {"weighted_points": 0.0, "available_weight": 0.0, "metrics": []}
        categories[category]["weighted_points"] += item["weighted_points"]
        categories[category]["available_weight"] += item["weight"]
        categories[category]["metrics"].append(item["metric"])

    for category_payload in categories.values():
        available_weight = category_payload["available_weight"]
        category_payload["score"] = None if available_weight == 0 else round(
            category_payload["weighted_points"] / available_weight,
            3,
        )
        category_payload["weighted_points"] = round(category_payload["weighted_points"], 3)
        category_payload["available_weight"] = round(available_weight, 3)

    return categories


def _risk_points(observation: Dict[str, Any]) -> List[str]:
    points: List[str] = []

    cfg_edges = metric_value(observation, "cfg_edge_count")
    imports = metric_value(observation, "imported_function_count")
    symbols = metric_value(observation, "num_symbols")
    alloc_calls = metric_value(observation, "allocation_call_count")
    syscall_functions = metric_value(observation, "syscall_function_count")
    mach_port_functions = metric_value(observation, "mach_port_function_count")

    if is_number(cfg_edges) and cfg_edges >= 2500:
        points.append("large_control_flow_graph")
    if is_number(imports) and imports >= 150:
        points.append("broad_import_interface")
    if is_number(symbols) and symbols >= 500:
        points.append("large_symbol_surface")
    if is_number(alloc_calls) and alloc_calls >= 20:
        points.append("allocation_heavy_code")
    if is_number(syscall_functions) and syscall_functions > 0:
        points.append("syscall_related_code_present")
    if is_number(mach_port_functions) and mach_port_functions > 0:
        points.append("mach_port_related_code_present")

    return points


def score_observation(observation: Dict[str, Any], metric_filter: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Compute a profile-based heuristic static score for one observation."""
    metric_names = _selected_metric_names(metric_filter)
    total_possible_weight = sum(METRIC_WEIGHTS[name] for name in metric_names)
    available_weight = 0.0
    weighted_points = 0.0
    contributions: List[Dict[str, Any]] = []

    for metric_name in metric_names:
        value = metric_value(observation, metric_name)
        normalized = normalize_metric(metric_name, value)
        if normalized is None:
            continue

        weight = METRIC_WEIGHTS[metric_name]
        metric_points = normalized * weight
        weighted_points += metric_points
        available_weight += weight
        contributions.append(
            {
                "metric": metric_name,
                "category": METRIC_CATEGORIES.get(metric_name, "other"),
                "raw_value": value,
                "normalized_value": normalized,
                "weight": weight,
                "weighted_points": round(metric_points, 3),
            }
        )

    score: Optional[float] = None if available_weight == 0 else round(weighted_points / available_weight, 3)
    available_weight_ratio = 0.0 if total_possible_weight == 0 else round(available_weight / total_possible_weight, 3)
    top_contributors = sorted(contributions, key=lambda item: item["weighted_points"], reverse=True)[:5]

    return {
        "score": score,
        "band": classify_score(score),
        "confidence": classify_confidence(available_weight_ratio),
        "available_metric_count": len(contributions),
        "available_weight_ratio": available_weight_ratio,
        "profile_source": "security_analysis.profiles.high_level_analysis.W_RAW + security_analysis.profiles.low_level_analysis.WEIGHTS",
        "profile_raw_risk": profile_raw_risk(observation),
        "ignored_metric_filters": _ignored_scoring_metrics(metric_filter),
        "category_scores": _category_summary(contributions),
        "top_contributors": top_contributors,
        "risk_points": _risk_points(observation),
        "interpretation_note": INTERPRETATION_NOTE,
    }


def compare_observation_scores(
    from_observation: Dict[str, Any],
    to_observation: Dict[str, Any],
    metric_filter: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Compare derived scores and numeric metric deltas between two observations."""
    from_score = score_observation(from_observation, metric_filter=metric_filter)
    to_score = score_observation(to_observation, metric_filter=metric_filter)
    score_delta = None
    if is_number(from_score["score"]) and is_number(to_score["score"]):
        score_delta = round(to_score["score"] - from_score["score"], 3)

    metric_names = _selected_metric_names(metric_filter)
    metric_deltas: List[Dict[str, Any]] = []
    for metric_name in metric_names:
        from_value = metric_value(from_observation, metric_name)
        to_value = metric_value(to_observation, metric_name)
        if not (is_number(from_value) and is_number(to_value)):
            continue
        delta = to_value - from_value
        percent_change = None if from_value == 0 else round((delta / from_value) * 100.0, 3)
        direction = "increased" if delta > 0 else "decreased" if delta < 0 else "unchanged"
        metric_deltas.append(
            {
                "metric": metric_name,
                "from_value": from_value,
                "to_value": to_value,
                "absolute_delta": delta,
                "percent_change": percent_change,
                "direction": direction,
            }
        )

    return {
        "from_version": from_observation.get("ios_version"),
        "to_version": to_observation.get("ios_version"),
        "from_score": from_score["score"],
        "to_score": to_score["score"],
        "score_delta": score_delta,
        "trend": classify_trend(score_delta),
        "from_band": from_score["band"],
        "to_band": to_score["band"],
        "metric_deltas": metric_deltas,
        "interpretation_note": INTERPRETATION_NOTE,
    }


def build_library_security_report(
    library_name: str,
    observations: List[Dict[str, Any]],
    metric_filter: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Build a snapshot or timeline report for one library."""
    scored_observations = []
    for observation in observations:
        scored_observations.append(
            {
                "ios_version": observation.get("ios_version"),
                "ios_release": observation.get("ios_release"),
                "build_number": observation.get("build_number"),
                "score": score_observation(observation, metric_filter=metric_filter),
            }
        )

    trend = None
    if len(observations) >= 2:
        trend = compare_observation_scores(observations[0], observations[-1], metric_filter=metric_filter)

    return {
        "report_type": "library_security_report",
        "library": library_name,
        "observation_count": len(observations),
        "scoring_basis": "existing_profile_weighted_log_static_metric_score",
        "interpretation_note": INTERPRETATION_NOTE,
        "observations": scored_observations,
        "first_to_last_trend": trend,
    }


def build_version_security_summary(
    ios_version: str,
    observations: List[Dict[str, Any]],
    metric_filter: Optional[Iterable[str]] = None,
    top_limit: int = 10,
) -> Dict[str, Any]:
    """Build an aggregate heuristic summary for one iOS version/filter."""
    scored = []
    for observation in observations:
        score = score_observation(observation, metric_filter=metric_filter)
        scored.append(
            {
                "library": observation.get("library"),
                "ios_version": observation.get("ios_version"),
                "ios_release": observation.get("ios_release"),
                "build_number": observation.get("build_number"),
                "score": score["score"],
                "band": score["band"],
                "confidence": score["confidence"],
                "risk_points": score["risk_points"],
                "top_contributors": score["top_contributors"],
            }
        )

    numeric_scores = [item["score"] for item in scored if is_number(item["score"])]
    band_counts: Dict[str, int] = {}
    confidence_counts: Dict[str, int] = {}
    for item in scored:
        band_counts[item["band"]] = band_counts.get(item["band"], 0) + 1
        confidence_counts[item["confidence"]] = confidence_counts.get(item["confidence"], 0) + 1

    top_libraries = sorted(scored, key=lambda item: (-1 if item["score"] is None else item["score"]), reverse=True)[:top_limit]

    return {
        "summary_type": "ios_version_security_summary",
        "ios_version_filter": ios_version,
        "observation_count": len(observations),
        "scoring_basis": "existing_profile_weighted_log_static_metric_score",
        "interpretation_note": INTERPRETATION_NOTE,
        "score_statistics": {
            "average_score": None if not numeric_scores else round(sum(numeric_scores) / len(numeric_scores), 3),
            "median_score": None if not numeric_scores else round(float(median(numeric_scores)), 3),
            "minimum_score": None if not numeric_scores else min(numeric_scores),
            "maximum_score": None if not numeric_scores else max(numeric_scores),
        },
        "band_counts": band_counts,
        "confidence_counts": confidence_counts,
        "top_libraries": top_libraries,
    }
