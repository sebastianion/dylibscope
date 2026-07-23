from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Literal, Optional, Union

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import SQLAlchemyError

from dylibscope.api.auth import CurrentUser, get_optional_current_user, require_current_user
from dylibscope.api.config import resolve_database_url
from dylibscope.security_analysis.derived_scoring import (
    INTERPRETATION_NOTE,
    METRIC_WEIGHTS,
    build_library_security_report,
    build_version_security_summary,
    compare_observation_scores,
    score_observation,
)
from dylibscope.storage.repository import (
    create_user_manual_observation,
    dataset_accessible,
    get_library_metrics,
    list_datasets,
    list_ios_versions,
    list_libraries,
    list_observations_for_ios_version,
)
from dylibscope.storage.schema import connect

MetricLevel = Literal["high", "low", "all"]

PUBLIC_BASELINE_DATASET_NAME = "public-baseline"
USER_PROVIDED_WARNING = (
    "User-provided observations are not independently verified by DylibScope. Scores, summaries, "
    "comparisons, and security indicators are computed from the values supplied by the user. "
    "Incorrect or incomplete entries may produce misleading results."
)


class UserObservationRequest(BaseModel):
    """Manual user-provided observation inserted into a private dataset."""

    dataset_name: str = Field(..., description="Private user dataset to create or update. Cannot be public-baseline.")
    library: str = Field(..., description="Library basename, for example libExample.dylib.")
    ios_version: str = Field(..., description="Full firmware label or user-supplied iOS version label.")
    metrics: Dict[str, Any] = Field(..., description="Schema-valid metric names and values.")
    original_path: Optional[str] = Field(default=None, description="Optional source path for the observation.")

    @field_validator("dataset_name")
    @classmethod
    def validate_dataset_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("dataset_name is required.")
        if cleaned == PUBLIC_BASELINE_DATASET_NAME:
            raise ValueError("public-baseline is read-only and cannot receive user-provided observations.")
        return cleaned

    @field_validator("library")
    @classmethod
    def validate_library(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("library is required.")
        if not cleaned.lower().endswith(".dylib"):
            raise ValueError("library must be a dynamic-library basename ending in .dylib.")
        return cleaned

    @field_validator("ios_version")
    @classmethod
    def validate_ios_version(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("ios_version is required.")
        return cleaned

    @field_validator("metrics")
    @classmethod
    def validate_metrics(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        if not value:
            raise ValueError("at least one metric is required.")
        cleaned = {str(key).strip(): metric_value for key, metric_value in value.items() if str(key).strip()}
        if not cleaned:
            raise ValueError("at least one metric is required.")
        if not any(metric_name in METRIC_WEIGHTS for metric_name in cleaned):
            raise ValueError("at least one score-relevant weighted metric is required.")
        return cleaned


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


def _cors_origins_from_env() -> List[str]:
    origins = os.getenv("DYLIBSCOPE_CORS_ORIGINS", "*").strip()
    if origins == "*":
        return ["*"]
    return [origin.strip() for origin in origins.split(",") if origin.strip()]


def _parse_metric_filters(metric: Optional[List[str]], metrics: Optional[str]) -> Optional[List[str]]:
    """Accept both repeated ``metric=`` and comma-separated ``metrics=`` query styles."""
    selected: List[str] = []
    if metric:
        selected.extend(metric)
    if metrics:
        selected.extend(part.strip() for part in metrics.split(","))
    cleaned = [item for item in selected if item]
    return cleaned or None


def _safe_database_label(database_url: str) -> str:
    url = make_url(database_url)
    if url.drivername.startswith("sqlite"):
        return str(url.database)
    return str(url.set(password="***"))


def _sqlite_file_exists(database_url: str) -> Optional[bool]:
    url = make_url(database_url)
    if not url.drivername.startswith("sqlite"):
        return None
    if url.database in (None, "", ":memory:"):
        return True
    return Path(url.database).exists()


def _connection_dependency(database_url: str) -> Iterator[Connection]:
    sqlite_exists = _sqlite_file_exists(database_url)
    if sqlite_exists is False:
        raise HTTPException(
            status_code=503,
            detail=(
                f"SQLite database not found at '{_safe_database_label(database_url)}'. "
                "Run scripts/import_datasets.py before starting the API."
            ),
        )

    try:
        conn = connect(database_url)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail=f"Database connection failed: {exc}") from exc

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
    """Build human-readable metric comparison rows for named entities."""
    observations = list(entity_observations.values())
    metric_names = _select_metrics_for_comparison(observations, requested_metrics)

    rows: List[Dict[str, Any]] = []
    for metric_name in metric_names:
        values = {
            entity: _metric_value(observation, metric_name)
            for entity, observation in entity_observations.items()
        }
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
        values = {
            version: _metric_value(observation, metric_name)
            for version, observation in version_observations.items()
        }
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
    """Pick the first observation for a requested scope."""
    return observations[0] if observations else None


def create_app(
    db_path: Optional[Union[str, Path]] = None,
    database_url: Optional[str] = None,
) -> FastAPI:
    """Create the DylibScope FastAPI application."""
    resolved_database_url = resolve_database_url(db_path=db_path, database_url=database_url)

    app = FastAPI(
        title="DylibScope API",
        version="0.4.0",
        description="HTTP API for querying and comparing normalized DylibScope static-analysis metrics.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins_from_env(),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def get_conn() -> Iterator[Connection]:
        yield from _connection_dependency(resolved_database_url)

    def current_user_id(current_user: Optional[CurrentUser]) -> Optional[str]:
        return current_user.user_id if current_user else None

    def require_dataset_access(
        conn: Connection,
        dataset_name: Optional[str],
        current_user: Optional[CurrentUser],
    ) -> None:
        if not dataset_name:
            return
        if dataset_accessible(conn, dataset_name, owner_user_id=current_user_id(current_user)):
            return
        raise HTTPException(status_code=404, detail="Dataset was not found or is not visible to the current user.")

    @app.get("/health")
    def health() -> Dict[str, Any]:
        sqlite_exists = _sqlite_file_exists(resolved_database_url)
        try:
            conn = connect(resolved_database_url)
            try:
                metric_count = conn.execute(text("SELECT COUNT(*) FROM metric_definitions")).scalar_one()
                dataset_count = conn.execute(text("SELECT COUNT(*) FROM datasets")).scalar_one()
            finally:
                conn.close()
            return {
                "status": "ok",
                "database": _safe_database_label(resolved_database_url),
                "database_backend": make_url(resolved_database_url).drivername,
                "database_exists": True if sqlite_exists is None else sqlite_exists,
                "metric_definition_count": metric_count,
                "dataset_count": dataset_count,
            }
        except Exception as exc:  # noqa: BLE001 - readiness endpoint should report failed DB readiness
            return {
                "status": "database_unready",
                "database": _safe_database_label(resolved_database_url),
                "database_backend": make_url(resolved_database_url).drivername,
                "database_exists": False if sqlite_exists is False else sqlite_exists,
                "error": str(exc),
            }

    @app.get("/v1/auth/session")
    def api_auth_session(
        current_user: Optional[CurrentUser] = Depends(get_optional_current_user),
    ) -> Dict[str, Any]:
        return {
            "authenticated": current_user is not None,
            "user_id": current_user.user_id if current_user else None,
            "role": current_user.role if current_user else None,
            "is_anonymous": current_user.is_anonymous if current_user else False,
        }

    @app.get("/v1/datasets")
    def api_list_datasets(
        conn: Connection = Depends(get_conn),
        current_user: Optional[CurrentUser] = Depends(get_optional_current_user),
    ) -> Dict[str, Any]:
        items = list_datasets(conn, owner_user_id=current_user_id(current_user))
        return {"count": len(items), "datasets": items}

    @app.post("/v1/user-observations", status_code=201)
    def api_create_user_observation(
        request: UserObservationRequest,
        conn: Connection = Depends(get_conn),
        current_user: CurrentUser = Depends(require_current_user),
    ) -> Dict[str, Any]:
        try:
            observation = create_user_manual_observation(
                conn,
                dataset_name=request.dataset_name,
                owner_user_id=current_user.user_id,
                library_name=request.library,
                ios_version=request.ios_version,
                metrics=request.metrics,
                original_path=request.original_path,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        return {
            "operation": "upserted_user_observation",
            "dataset_name": request.dataset_name,
            "dataset_visibility": "private",
            "dataset_source_type": "user_manual",
            "dataset_trust_level": "user_provided_unverified",
            "library": request.library,
            "ios_version": request.ios_version,
            "metric_count": len(request.metrics),
            "warning": USER_PROVIDED_WARNING,
            "observation": observation,
        }

    @app.get("/v1/libraries")
    def api_list_libraries(
        dataset_name: Optional[str] = Query(default=None),
        conn: Connection = Depends(get_conn),
        current_user: Optional[CurrentUser] = Depends(get_optional_current_user),
    ) -> Dict[str, Any]:
        require_dataset_access(conn, dataset_name, current_user)
        libraries = list_libraries(conn, dataset_name=dataset_name, owner_user_id=current_user_id(current_user))
        return {"count": len(libraries), "libraries": libraries}

    @app.get("/v1/ios-versions")
    def api_list_ios_versions(
        conn: Connection = Depends(get_conn),
        current_user: Optional[CurrentUser] = Depends(get_optional_current_user),
    ) -> Dict[str, Any]:
        versions = list_ios_versions(conn, owner_user_id=current_user_id(current_user))
        return {"count": len(versions), "ios_versions": versions}

    @app.get("/v1/ios-versions/{ios_version}/security-summary", responses={404: {"model": ErrorResponse}})
    def api_get_ios_version_security_summary(
        ios_version: str,
        dataset_name: Optional[str] = Query(default="public-baseline"),
        level: Optional[MetricLevel] = Query(default=None),
        metric: Optional[List[str]] = Query(default=None, description="Repeatable exact metric filter."),
        metrics: Optional[str] = Query(default=None, description="Comma-separated exact metric filter."),
        limit: int = Query(default=10, ge=1, le=50, description="Maximum number of top libraries to return."),
        conn: Connection = Depends(get_conn),
        current_user: Optional[CurrentUser] = Depends(get_optional_current_user),
    ) -> Dict[str, Any]:
        selected_metrics = _parse_metric_filters(metric, metrics)
        require_dataset_access(conn, dataset_name, current_user)
        observations = list_observations_for_ios_version(
            conn,
            ios_version=ios_version,
            dataset_name=dataset_name,
            level=level,
            metrics=selected_metrics,
            owner_user_id=current_user_id(current_user),
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
        conn: Connection = Depends(get_conn),
        current_user: Optional[CurrentUser] = Depends(get_optional_current_user),
    ) -> Dict[str, Any]:
        selected_metrics = _parse_metric_filters(metric, metrics)
        require_dataset_access(conn, dataset_name, current_user)
        observations = get_library_metrics(
            conn,
            library_name=library_name,
            dataset_name=dataset_name,
            ios_version=ios_version,
            level=level,
            metrics=selected_metrics,
            owner_user_id=current_user_id(current_user),
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
        conn: Connection = Depends(get_conn),
        current_user: Optional[CurrentUser] = Depends(get_optional_current_user),
    ) -> Dict[str, Any]:
        selected_metrics = _parse_metric_filters(metric, metrics)
        require_dataset_access(conn, dataset_name, current_user)
        observations = get_library_metrics(
            conn,
            library_name=library_name,
            dataset_name=dataset_name,
            ios_version=None,
            level=level,
            metrics=selected_metrics,
            owner_user_id=current_user_id(current_user),
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
        conn: Connection = Depends(get_conn),
        current_user: Optional[CurrentUser] = Depends(get_optional_current_user),
    ) -> Dict[str, Any]:
        selected_metrics = _parse_metric_filters(metric, metrics)
        require_dataset_access(conn, dataset_name, current_user)

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
                owner_user_id=current_user_id(current_user),
            )
            to_observations = get_library_metrics(
                conn,
                library_name=library_name,
                dataset_name=dataset_name,
                ios_version=to_ios_version,
                level=level,
                metrics=selected_metrics,
                owner_user_id=current_user_id(current_user),
            )
            from_observation = _first_observation_for_scope(from_observations)
            to_observation = _first_observation_for_scope(to_observations)
            if not from_observation or not to_observation:
                raise HTTPException(
                    status_code=404,
                    detail="Metrics were not found for both requested transition endpoints.",
                )
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
            owner_user_id=current_user_id(current_user),
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
        conn: Connection = Depends(get_conn),
        current_user: Optional[CurrentUser] = Depends(get_optional_current_user),
    ) -> Dict[str, Any]:
        require_dataset_access(conn, request.dataset_name, current_user)
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
                owner_user_id=current_user_id(current_user),
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
                + (
                    f" for iOS filter '{request.ios_version}'"
                    if request.ios_version
                    else " across the first matching observation"
                )
                + "."
            ),
            "dataset_name": request.dataset_name,
            "ios_version_filter": request.ios_version,
            "level_filter": request.level,
            "metric_filter": request.metrics,
            "comparison_basis": "static_metric_comparison",
            "interpretation_note": (
                "Higher static metric values may indicate larger complexity or interface surface, "
                "but they do not prove vulnerabilities."
            ),
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
        conn: Connection = Depends(get_conn),
        current_user: Optional[CurrentUser] = Depends(get_optional_current_user),
    ) -> Dict[str, Any]:
        require_dataset_access(conn, request.dataset_name, current_user)
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
                owner_user_id=current_user_id(current_user),
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
            "interpretation_note": (
                "Metric increases indicate static growth or complexity growth, "
                "not necessarily a security regression."
            ),
            "matched_count": len(selected_observations),
            "missing_ios_versions": missing_versions,
            "resolved_observations": resolved_observations,
            "metric_count": len(results),
            "results": results,
        }

    return app


app = create_app()
