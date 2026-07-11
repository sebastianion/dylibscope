from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Literal, Optional, Union

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from dylibscope.api.config import resolve_db_path
from dylibscope.security_analysis.derived_scoring import (
    INTERPRETATION_NOTE,
    build_library_security_report,
    build_version_security_summary,
    compare_observation_scores,
    score_observation,
)
from dylibscope.storage.repository import (
    get_library_metrics,
    list_ios_versions,
    list_libraries,
    list_observations_for_ios_version,
)
from dylibscope.storage.schema import connect

MetricLevel = Literal["high", "low", "all"]


class CompareLibrariesRequest(BaseModel):
    """Request body for comparing two or more libraries in the same scope."""

    libraries: List[str] = Field(..., min_length=2, description="Library basenames to compare.")
    dataset_name: Optional[str] = Field(default="public-baseline")
    ios_version: Optional[str] = Field(default=None, description="Full firmware label or parsed iOS release.")
    level: Optional[MetricLevel] = Field(default=None)
    metrics: Optional[List[str]] = Field(default=None, description="Optional exact metric names to compare.")

    @field_validator("libraries")
    @classmethod
    def require_unique_non_empty_libraries(cls, value: List[str]) -> List[str]:
        cleaned = [item.strip() for item in value if item and item.strip()]
        if len(set(cleaned)) < 2:
            raise ValueError("At least two unique library names are required.")
        return cleaned


class CompareLibraryVersionsRequest(BaseModel):
    """Request body for comparing one library across two or more iOS versions."""

    ios_versions: List[str] = Field(
        ...,
        min_length=2,
        description="Full firmware labels or parsed iOS releases to compare, in the requested order.",
    )
    dataset_name: Optional[str] = Field(default="public-baseline")
    level: Optional[MetricLevel] = Field(default=None)
    metrics: Optional[List[str]] = Field(default=None, description="Optional exact metric names to compare.")

    @field_validator("ios_versions")
    @classmethod
    def require_unique_non_empty_versions(cls, value: List[str]) -> List[str]:
        cleaned = [item.strip() for item in value if item and item.strip()]
        if len(set(cleaned)) < 2:
            raise ValueError("At least two unique iOS versions are required.")
        return cleaned


class ErrorResponse(BaseModel):
    detail: str


def _parse_metric_filters(metric: Optional[List[str]], metrics: Optional[str]) -> Optional[List[str]]:
    """Accept both repeated ``metric=`` and comma-separated ``metrics=`` query styles."""
    selected: List[str] = []
    if metric:
        selected.extend(metric)
    if metrics:
        selected.extend(part.strip() for part in metrics.split(","))
    cleaned = [item for item in selected if item]
    return cleaned or None


def _connection_dependency(db_path: Path) -> Iterator[sqlite3.Connection]:
    if not db_path.exists():
        raise HTTPException(
            status_code=503,
            detail=(
                f"SQLite database not found at '{db_path}'. "
                "Run scripts/import_datasets.py before starting the API."
            ),
        )
    conn = connect(str(db_path))
    try:
        yield conn
    finally:
        conn.close()


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _metric_value(observation: Dict[str, Any], metric_name: str) -> Any:
    metric = observation.get("metrics", {}).get(metric_name)
    if metric is None:
        return None
    return metric.get("value")


def _metric_level(observations: Iterable[Dict[str, Any]], metric_name: str) -> Optional[str]:
    for observation in observations:
        metric = observation.get("metrics", {}).get(metric_name)
        if metric is not None:
            return metric.get("level")
    return None


def _select_metrics_for_comparison(
    observations: Iterable[Dict[str, Any]],
    requested_metrics: Optional[Iterable[str]],
) -> List[str]:
    """Return requested metrics, or all numeric metrics when none are requested."""
    if requested_metrics:
        return list(dict.fromkeys(metric for metric in requested_metrics if metric))

    selected: List[str] = []
    for observation in observations:
        for metric_name, metric_payload in observation.get("metrics", {}).items():
            if _is_number(metric_payload.get("value")) and metric_name not in selected:
                selected.append(metric_name)
    return sorted(selected)


def _summarize_numeric_values(values: Dict[str, Any]) -> Dict[str, Any]:
    numeric_values = {key: value for key, value in values.items() if _is_number(value)}
    if not numeric_values:
        return {
            "leader": None,
            "lowest": None,
            "absolute_difference": None,
            "ratio_high_to_low": None,
        }

    leader = max(numeric_values, key=numeric_values.get)
    lowest = min(numeric_values, key=numeric_values.get)
    high = numeric_values[leader]
    low = numeric_values[lowest]
    ratio = None if low == 0 else high / low

    return {
        "leader": leader,
        "lowest": lowest,
        "absolute_difference": high - low,
        "ratio_high_to_low": ratio,
    }


def _build_metric_comparison_results(
    entity_observations: Dict[str, Dict[str, Any]],
    requested_metrics: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Build human-readable metric comparison rows for named entities.

    ``entity_observations`` maps an entity label to one observation. For library
    comparison, the entity label is the library name.
    """
    observations = list(entity_observations.values())
    metric_names = _select_metrics_for_comparison(observations, requested_metrics)

    rows: List[Dict[str, Any]] = []
    for metric_name in metric_names:
        values = {entity: _metric_value(observation, metric_name) for entity, observation in entity_observations.items()}
        numeric_summary = _summarize_numeric_values(values)
        rows.append(
            {
                "metric": metric_name,
                "level": _metric_level(observations, metric_name),
                "values": values,
                "leader": numeric_summary["leader"],
                "lowest": numeric_summary["lowest"],
                "absolute_difference": numeric_summary["absolute_difference"],
                "ratio_high_to_low": numeric_summary["ratio_high_to_low"],
            }
        )

    return rows


def _build_version_evolution_results(
    version_observations: Dict[str, Dict[str, Any]],
    requested_metrics: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Build first-to-last evolution rows for one library across ordered versions."""
    versions = list(version_observations.keys())
    observations = list(version_observations.values())
    metric_names = _select_metrics_for_comparison(observations, requested_metrics)

    if len(versions) < 2:
        return []

    first_version = versions[0]
    last_version = versions[-1]
    first_observation = version_observations[first_version]
    last_observation = version_observations[last_version]

    rows: List[Dict[str, Any]] = []
    for metric_name in metric_names:
        values = {version: _metric_value(observation, metric_name) for version, observation in version_observations.items()}
        numeric_summary = _summarize_numeric_values(values)
        first_value = _metric_value(first_observation, metric_name)
        last_value = _metric_value(last_observation, metric_name)
        delta = None
        percent_change = None
        direction = "not_comparable"

        if _is_number(first_value) and _is_number(last_value):
            delta = last_value - first_value
            percent_change = None if first_value == 0 else round((delta / first_value) * 100, 3)
            if delta > 0:
                direction = "increased"
            elif delta < 0:
                direction = "decreased"
            else:
                direction = "unchanged"

        rows.append(
            {
                "metric": metric_name,
                "level": _metric_level(observations, metric_name),
                "values": values,
                "leader": numeric_summary["leader"],
                "from_version": first_version,
                "to_version": last_version,
                "from_value": first_value,
                "to_value": last_value,
                "absolute_delta": delta,
                "percent_change": percent_change,
                "direction": direction,
            }
        )

    return rows


def _first_observation_for_scope(observations: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Pick the first observation for a requested scope.

    If the caller filters by a full firmware label, this is exact. If the caller
    filters only by an iOS release and the DB contains multiple device/build
    labels for that release, the API still returns one representative observation
    and keeps the selected firmware label visible in the response.
    """
    return observations[0] if observations else None


def create_app(db_path: Optional[Union[str, Path]] = None) -> FastAPI:
    """Create the DylibScope FastAPI application.

    ``db_path`` is injectable so tests can run against a temporary database.
    """
    resolved_db_path = resolve_db_path(db_path)

    app = FastAPI(
        title="DylibScope API",
        version="0.2.0",
        description="HTTP API for querying and comparing normalized DylibScope static-analysis metrics.",
    )

    def get_conn() -> Iterator[sqlite3.Connection]:
        yield from _connection_dependency(resolved_db_path)

    @app.get("/health")
    def health() -> Dict[str, Any]:
        database_exists = resolved_db_path.exists()
        return {
            "status": "ok" if database_exists else "missing_database",
            "database_path": str(resolved_db_path),
            "database_exists": database_exists,
        }

    @app.get("/v1/libraries")
    def api_list_libraries(
        dataset_name: Optional[str] = Query(default=None),
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> Dict[str, Any]:
        libraries = list_libraries(conn, dataset_name=dataset_name)
        return {"count": len(libraries), "libraries": libraries}

    @app.get("/v1/ios-versions")
    def api_list_ios_versions(conn: sqlite3.Connection = Depends(get_conn)) -> Dict[str, Any]:
        versions = list_ios_versions(conn)
        return {"count": len(versions), "ios_versions": versions}

    @app.get("/v1/ios-versions/{ios_version}/security-summary", responses={404: {"model": ErrorResponse}})
    def api_get_ios_version_security_summary(
        ios_version: str,
        dataset_name: Optional[str] = Query(default="public-baseline"),
        level: Optional[MetricLevel] = Query(default=None),
        metric: Optional[List[str]] = Query(default=None, description="Repeatable exact metric filter."),
        metrics: Optional[str] = Query(default=None, description="Comma-separated exact metric filter."),
        limit: int = Query(default=10, ge=1, le=50, description="Maximum number of top libraries to return."),
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> Dict[str, Any]:
        selected_metrics = _parse_metric_filters(metric, metrics)
        observations = list_observations_for_ios_version(
            conn,
            ios_version=ios_version,
            dataset_name=dataset_name,
            level=level,
            metrics=selected_metrics,
        )
        if not observations:
            raise HTTPException(status_code=404, detail="No metrics found for the requested iOS version filter.")

        summary = build_version_security_summary(
            ios_version=ios_version,
            observations=observations,
            metric_filter=selected_metrics,
            top_limit=limit,
        )
        summary.update(
            {
                "dataset_name": dataset_name,
                "level_filter": level,
                "metric_filter": selected_metrics,
            }
        )
        return summary

    @app.get("/v1/libraries/{library_name}/metrics", responses={404: {"model": ErrorResponse}})
    def api_get_library_metrics(
        library_name: str,
        dataset_name: Optional[str] = Query(default="public-baseline"),
        ios_version: Optional[str] = Query(default=None),
        level: Optional[MetricLevel] = Query(default=None),
        metric: Optional[List[str]] = Query(default=None, description="Repeatable exact metric filter."),
        metrics: Optional[str] = Query(default=None, description="Comma-separated exact metric filter."),
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> Dict[str, Any]:
        selected_metrics = _parse_metric_filters(metric, metrics)
        observations = get_library_metrics(
            conn,
            library_name=library_name,
            dataset_name=dataset_name,
            ios_version=ios_version,
            level=level,
            metrics=selected_metrics,
        )
        if not observations:
            raise HTTPException(status_code=404, detail="No metrics found for the requested filters.")
        return {
            "library": library_name,
            "dataset_name": dataset_name,
            "ios_version_filter": ios_version,
            "level_filter": level,
            "metric_filter": selected_metrics,
            "count": len(observations),
            "observations": observations,
        }

    @app.get("/v1/libraries/{library_name}/timeline", responses={404: {"model": ErrorResponse}})
    def api_get_library_timeline(
        library_name: str,
        dataset_name: Optional[str] = Query(default="public-baseline"),
        level: Optional[MetricLevel] = Query(default=None),
        metric: Optional[List[str]] = Query(default=None),
        metrics: Optional[str] = Query(default=None),
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> Dict[str, Any]:
        selected_metrics = _parse_metric_filters(metric, metrics)
        observations = get_library_metrics(
            conn,
            library_name=library_name,
            dataset_name=dataset_name,
            ios_version=None,
            level=level,
            metrics=selected_metrics,
        )
        if not observations:
            raise HTTPException(status_code=404, detail="No timeline data found for the requested filters.")
        return {
            "library": library_name,
            "dataset_name": dataset_name,
            "level_filter": level,
            "metric_filter": selected_metrics,
            "count": len(observations),
            "timeline": observations,
        }

    @app.get("/v1/libraries/{library_name}/security-report", responses={404: {"model": ErrorResponse}})
    def api_get_library_security_report(
        library_name: str,
        dataset_name: Optional[str] = Query(default="public-baseline"),
        ios_version: Optional[str] = Query(default=None, description="Full firmware label or parsed iOS release."),
        from_ios_version: Optional[str] = Query(default=None, description="Start version for a transition report."),
        to_ios_version: Optional[str] = Query(default=None, description="End version for a transition report."),
        level: Optional[MetricLevel] = Query(default=None),
        metric: Optional[List[str]] = Query(default=None, description="Repeatable exact metric filter."),
        metrics: Optional[str] = Query(default=None, description="Comma-separated exact metric filter."),
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> Dict[str, Any]:
        selected_metrics = _parse_metric_filters(metric, metrics)

        if bool(from_ios_version) != bool(to_ios_version):
            raise HTTPException(
                status_code=400,
                detail="Both from_ios_version and to_ios_version are required for a transition report.",
            )

        if from_ios_version and to_ios_version:
            from_observations = get_library_metrics(
                conn,
                library_name=library_name,
                dataset_name=dataset_name,
                ios_version=from_ios_version,
                level=level,
                metrics=selected_metrics,
            )
            to_observations = get_library_metrics(
                conn,
                library_name=library_name,
                dataset_name=dataset_name,
                ios_version=to_ios_version,
                level=level,
                metrics=selected_metrics,
            )
            from_observation = _first_observation_for_scope(from_observations)
            to_observation = _first_observation_for_scope(to_observations)
            if not from_observation or not to_observation:
                raise HTTPException(status_code=404, detail="Metrics were not found for both requested transition endpoints.")

            return {
                "report_type": "library_transition_security_report",
                "library": library_name,
                "dataset_name": dataset_name,
                "from_ios_version_filter": from_ios_version,
                "to_ios_version_filter": to_ios_version,
                "level_filter": level,
                "metric_filter": selected_metrics,
                "scoring_basis": "weighted_static_metric_score",
                "interpretation_note": INTERPRETATION_NOTE,
                "resolved_observations": [
                    {
                        "requested_ios_version": from_ios_version,
                        "matched_observation_count": len(from_observations),
                        "selected_ios_version": from_observation.get("ios_version"),
                        "selected_ios_release": from_observation.get("ios_release"),
                        "selected_build_number": from_observation.get("build_number"),
                    },
                    {
                        "requested_ios_version": to_ios_version,
                        "matched_observation_count": len(to_observations),
                        "selected_ios_version": to_observation.get("ios_version"),
                        "selected_ios_release": to_observation.get("ios_release"),
                        "selected_build_number": to_observation.get("build_number"),
                    },
                ],
                "from_score": score_observation(from_observation, metric_filter=selected_metrics),
                "to_score": score_observation(to_observation, metric_filter=selected_metrics),
                "trend": compare_observation_scores(from_observation, to_observation, metric_filter=selected_metrics),
            }

        observations = get_library_metrics(
            conn,
            library_name=library_name,
            dataset_name=dataset_name,
            ios_version=ios_version,
            level=level,
            metrics=selected_metrics,
        )
        if not observations:
            raise HTTPException(status_code=404, detail="No metrics found for the requested security report filters.")

        report = build_library_security_report(
            library_name=library_name,
            observations=observations,
            metric_filter=selected_metrics,
        )
        report.update(
            {
                "dataset_name": dataset_name,
                "ios_version_filter": ios_version,
                "level_filter": level,
                "metric_filter": selected_metrics,
            }
        )
        return report

    @app.post("/v1/libraries/compare", responses={404: {"model": ErrorResponse}})
    def api_compare_libraries(
        request: CompareLibrariesRequest,
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> Dict[str, Any]:
        selected_observations: Dict[str, Dict[str, Any]] = {}
        resolved_observations: List[Dict[str, Any]] = []
        missing_libraries: List[str] = []

        for library in request.libraries:
            observations = get_library_metrics(
                conn,
                library_name=library,
                dataset_name=request.dataset_name,
                ios_version=request.ios_version,
                level=request.level,
                metrics=request.metrics,
            )
            selected = _first_observation_for_scope(observations)
            if selected:
                selected_observations[library] = selected
                resolved_observations.append(
                    {
                        "library": library,
                        "matched_observation_count": len(observations),
                        "selected_ios_version": selected.get("ios_version"),
                        "selected_ios_release": selected.get("ios_release"),
                        "selected_build_number": selected.get("build_number"),
                    }
                )
            else:
                missing_libraries.append(library)

        if not selected_observations:
            raise HTTPException(status_code=404, detail="No metrics found for any requested library.")

        results = _build_metric_comparison_results(selected_observations, request.metrics)
        return {
            "comparison_type": "libraries_same_scope",
            "summary": (
                f"Compared {len(selected_observations)} libraries"
                + (f" for iOS filter '{request.ios_version}'" if request.ios_version else " across the first matching observation")
                + "."
            ),
            "dataset_name": request.dataset_name,
            "ios_version_filter": request.ios_version,
            "level_filter": request.level,
            "metric_filter": request.metrics,
            "comparison_basis": "static_metric_comparison",
            "interpretation_note": "Higher static metric values may indicate larger complexity or interface surface, but they do not prove vulnerabilities.",
            "requested_count": len(request.libraries),
            "matched_count": len(selected_observations),
            "missing_libraries": missing_libraries,
            "resolved_observations": resolved_observations,
            "metric_count": len(results),
            "results": results,
        }

    @app.post("/v1/libraries/{library_name}/compare-versions", responses={404: {"model": ErrorResponse}})
    def api_compare_library_versions(
        library_name: str,
        request: CompareLibraryVersionsRequest,
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> Dict[str, Any]:
        selected_observations: Dict[str, Dict[str, Any]] = {}
        resolved_observations: List[Dict[str, Any]] = []
        missing_versions: List[str] = []

        for requested_version in request.ios_versions:
            observations = get_library_metrics(
                conn,
                library_name=library_name,
                dataset_name=request.dataset_name,
                ios_version=requested_version,
                level=request.level,
                metrics=request.metrics,
            )
            selected = _first_observation_for_scope(observations)
            if selected:
                selected_label = selected.get("ios_version") or requested_version
                selected_observations[selected_label] = selected
                resolved_observations.append(
                    {
                        "requested_ios_version": requested_version,
                        "matched_observation_count": len(observations),
                        "selected_ios_version": selected.get("ios_version"),
                        "selected_ios_release": selected.get("ios_release"),
                        "selected_build_number": selected.get("build_number"),
                    }
                )
            else:
                missing_versions.append(requested_version)

        if len(selected_observations) < 2:
            raise HTTPException(
                status_code=404,
                detail="At least two requested iOS versions must have metrics for this library.",
            )

        results = _build_version_evolution_results(selected_observations, request.metrics)
        return {
            "comparison_type": "same_library_across_ios_versions",
            "summary": f"Compared '{library_name}' across {len(selected_observations)} iOS version observations.",
            "library": library_name,
            "dataset_name": request.dataset_name,
            "requested_ios_versions": request.ios_versions,
            "level_filter": request.level,
            "metric_filter": request.metrics,
            "comparison_basis": "static_metric_evolution",
            "interpretation_note": "Metric increases indicate static growth or complexity growth, not necessarily a security regression.",
            "matched_count": len(selected_observations),
            "missing_ios_versions": missing_versions,
            "resolved_observations": resolved_observations,
            "metric_count": len(results),
            "results": results,
        }

    return app


app = create_app()
