from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import bindparam, select, text
from sqlalchemy.engine import Connection, RowMapping

from dylibscope.storage.normalize import canonicalize_library_name
from dylibscope.storage.schema import datasets


def _as_dict(row: RowMapping) -> Dict[str, Any]:
    return dict(row)


def _coerce_metric_value(row: RowMapping) -> Any:
    if row["numeric_value"] is not None:
        numeric = float(row["numeric_value"])
        return int(numeric) if numeric.is_integer() else numeric
    if row["text_value"] is not None:
        return row["text_value"]
    if row["json_value"] is not None:
        return json.loads(row["json_value"])
    return None


def list_datasets(conn: Connection) -> List[Dict[str, Any]]:
    rows = conn.execute(
        text(
            """
            SELECT
                d.name,
                d.source,
                d.visibility,
                d.created_at,
                COUNT(o.id) AS observation_count
            FROM datasets d
            LEFT JOIN library_observations o ON o.dataset_id = d.id
            GROUP BY d.id, d.name, d.source, d.visibility, d.created_at
            ORDER BY d.name
            """
        )
    ).mappings().fetchall()
    return [_as_dict(row) for row in rows]


def dataset_exists(conn: Connection, dataset_name: str) -> bool:
    row = conn.execute(select(datasets.c.id).where(datasets.c.name == dataset_name)).first()
    return row is not None


def list_libraries(conn: Connection, dataset_name: Optional[str] = None) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {}
    dataset_filter = ""
    if dataset_name:
        dataset_filter = "WHERE d.name = :dataset_name"
        params["dataset_name"] = dataset_name

    rows = conn.execute(
        text(
            f"""
            SELECT
                l.display_name,
                l.canonical_name,
                COUNT(DISTINCT iv.version_label) AS ios_version_count
            FROM libraries l
            JOIN library_observations o ON o.library_id = l.id
            JOIN ios_versions iv ON iv.id = o.ios_version_id
            JOIN datasets d ON d.id = o.dataset_id
            {dataset_filter}
            GROUP BY l.id, l.display_name, l.canonical_name
            ORDER BY l.display_name
            """
        ),
        params,
    ).mappings().fetchall()
    return [_as_dict(row) for row in rows]


def list_ios_versions(conn: Connection) -> List[Dict[str, Any]]:
    """Return all firmware/iOS labels known to the database."""
    rows = conn.execute(
        text(
            """
            SELECT version_label, device_model, ios_release, build_number
            FROM ios_versions
            ORDER BY ios_release, build_number, device_model, version_label
            """
        )
    ).mappings().fetchall()
    return [_as_dict(row) for row in rows]


def get_library_metrics(
    conn: Connection,
    library_name: str,
    dataset_name: Optional[str] = None,
    ios_version: Optional[str] = None,
    level: Optional[str] = None,
    metrics: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Return metric observations for a library.

    Query semantics:
    - library is required;
    - dataset, iOS version, metric level, and exact metrics are optional;
    - ``ios_version`` accepts either a full firmware label or parsed release.
    """
    canonical_name = canonicalize_library_name(library_name)
    metric_list = list(metrics or [])

    conditions = ["l.canonical_name = :canonical_name"]
    params: Dict[str, Any] = {"canonical_name": canonical_name}

    if dataset_name:
        conditions.append("d.name = :dataset_name")
        params["dataset_name"] = dataset_name
    if ios_version:
        conditions.append("(iv.version_label = :ios_version OR iv.ios_release = :ios_version)")
        params["ios_version"] = ios_version
    if level and level != "all":
        conditions.append("md.level = :level")
        params["level"] = level
    if metric_list:
        conditions.append("mv.metric_name IN :metric_names")
        params["metric_names"] = metric_list

    query = text(
        f"""
        SELECT
            d.name AS dataset_name,
            l.display_name AS library,
            iv.version_label AS ios_version,
            iv.device_model,
            iv.ios_release,
            iv.build_number,
            mv.metric_name,
            md.level,
            mv.numeric_value,
            mv.text_value,
            mv.json_value
        FROM metric_values mv
        JOIN metric_definitions md ON md.name = mv.metric_name
        JOIN library_observations o ON o.id = mv.observation_id
        JOIN datasets d ON d.id = o.dataset_id
        JOIN libraries l ON l.id = o.library_id
        JOIN ios_versions iv ON iv.id = o.ios_version_id
        WHERE {' AND '.join(conditions)}
        ORDER BY iv.ios_release, iv.build_number, iv.version_label, md.level, mv.metric_name
        """
    )
    if metric_list:
        query = query.bindparams(bindparam("metric_names", expanding=True))

    rows = conn.execute(query, params).mappings().fetchall()
    return _group_metric_rows(rows)


def list_observations_for_ios_version(
    conn: Connection,
    ios_version: str,
    dataset_name: Optional[str] = None,
    level: Optional[str] = None,
    metrics: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Return all library observations for one iOS version or release."""
    metric_list = list(metrics or [])

    conditions = ["(iv.version_label = :ios_version OR iv.ios_release = :ios_version)"]
    params: Dict[str, Any] = {"ios_version": ios_version}

    if dataset_name:
        conditions.append("d.name = :dataset_name")
        params["dataset_name"] = dataset_name
    if level and level != "all":
        conditions.append("md.level = :level")
        params["level"] = level
    if metric_list:
        conditions.append("mv.metric_name IN :metric_names")
        params["metric_names"] = metric_list

    query = text(
        f"""
        SELECT
            d.name AS dataset_name,
            l.display_name AS library,
            iv.version_label AS ios_version,
            iv.device_model,
            iv.ios_release,
            iv.build_number,
            mv.metric_name,
            md.level,
            mv.numeric_value,
            mv.text_value,
            mv.json_value
        FROM metric_values mv
        JOIN metric_definitions md ON md.name = mv.metric_name
        JOIN library_observations o ON o.id = mv.observation_id
        JOIN datasets d ON d.id = o.dataset_id
        JOIN libraries l ON l.id = o.library_id
        JOIN ios_versions iv ON iv.id = o.ios_version_id
        WHERE {' AND '.join(conditions)}
        ORDER BY l.display_name, iv.ios_release, iv.build_number, iv.version_label, md.level, mv.metric_name
        """
    )
    if metric_list:
        query = query.bindparams(bindparam("metric_names", expanding=True))

    rows = conn.execute(query, params).mappings().fetchall()
    return _group_metric_rows(rows)


def _group_metric_rows(rows: Iterable[RowMapping]) -> List[Dict[str, Any]]:
    grouped: Dict[tuple[str, str, str], Dict[str, Any]] = {}

    for row in rows:
        key = (row["dataset_name"], row["library"], row["ios_version"])
        if key not in grouped:
            grouped[key] = {
                "dataset": row["dataset_name"],
                "library": row["library"],
                "ios_version": row["ios_version"],
                "device_model": row["device_model"],
                "ios_release": row["ios_release"],
                "build_number": row["build_number"],
                "metrics": {},
            }
        grouped[key]["metrics"][row["metric_name"]] = {
            "level": row["level"],
            "value": _coerce_metric_value(row),
        }

    return list(grouped.values())
