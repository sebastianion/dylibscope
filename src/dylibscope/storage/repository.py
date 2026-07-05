from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, Iterable, List, Optional

from dylibscope.storage.normalize import canonicalize_library_name


def _coerce_metric_value(row: sqlite3.Row) -> Any:
    if row["numeric_value"] is not None:
        numeric = float(row["numeric_value"])
        return int(numeric) if numeric.is_integer() else numeric
    if row["text_value"] is not None:
        return row["text_value"]
    if row["json_value"] is not None:
        return json.loads(row["json_value"])
    return None


def list_libraries(conn: sqlite3.Connection, dataset_name: Optional[str] = None) -> List[Dict[str, Any]]:
    params: list[Any] = []
    dataset_filter = ""
    if dataset_name:
        dataset_filter = "WHERE d.name = ?"
        params.append(dataset_name)

    rows = conn.execute(
        f"""
        SELECT l.display_name, l.canonical_name, COUNT(DISTINCT iv.version_label) AS ios_version_count
        FROM libraries l
        JOIN library_observations o ON o.library_id = l.id
        JOIN ios_versions iv ON iv.id = o.ios_version_id
        JOIN datasets d ON d.id = o.dataset_id
        {dataset_filter}
        GROUP BY l.id
        ORDER BY l.display_name
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def list_ios_versions(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Return all firmware/iOS labels known to the database."""
    rows = conn.execute(
        """
        SELECT version_label, device_model, ios_release, build_number
        FROM ios_versions
        ORDER BY ios_release, build_number, device_model, version_label
        """
    ).fetchall()
    return [dict(row) for row in rows]


def get_library_metrics(
    conn: sqlite3.Connection,
    library_name: str,
    dataset_name: Optional[str] = None,
    ios_version: Optional[str] = None,
    level: Optional[str] = None,
    metrics: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Return metric observations for a library.

    Query semantics for the future P0 API:
    - library is required;
    - dataset, iOS version, metric level, and exact metrics are optional;
    - ``ios_version`` accepts either the full firmware label
      ``iPhone11,8_12.0_16A366`` or the parsed release ``12.0``.
    """
    canonical_name = canonicalize_library_name(library_name)
    metric_list = list(metrics or [])

    conditions = ["l.canonical_name = ?"]
    params: list[Any] = [canonical_name]

    if dataset_name:
        conditions.append("d.name = ?")
        params.append(dataset_name)
    if ios_version:
        conditions.append("(iv.version_label = ? OR iv.ios_release = ?)")
        params.extend([ios_version, ios_version])
    if level and level != "all":
        conditions.append("md.level = ?")
        params.append(level)
    if metric_list:
        placeholders = ",".join("?" for _ in metric_list)
        conditions.append(f"mv.metric_name IN ({placeholders})")
        params.extend(metric_list)

    where_clause = " AND ".join(conditions)

    rows = conn.execute(
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
        WHERE {where_clause}
        ORDER BY iv.ios_release, iv.build_number, iv.version_label, md.level, mv.metric_name
        """,
        params,
    ).fetchall()

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
