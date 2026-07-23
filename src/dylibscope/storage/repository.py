from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy import bindparam, select, text
from sqlalchemy.engine import Connection, RowMapping

from dylibscope.storage.normalize import canonicalize_library_name, json_dumps_stable, parse_ios_version_label
from dylibscope.storage.schema import (
    datasets,
    ios_versions,
    libraries,
    library_observations,
    metric_definitions,
    metric_values,
)


PUBLIC_DATASET_VISIBILITY = "public"

USER_MANUAL_SOURCE_TYPE = "user_manual"
USER_MANUAL_TRUST_LEVEL = "user_provided_unverified"
PRIVATE_DATASET_VISIBILITY = "private"


def _scalar_id(row: Any) -> int:
    if row is None:
        raise RuntimeError("expected database row was not found")
    return int(row[0])


def _supports_returning(conn: Connection) -> bool:
    return bool(getattr(conn.dialect, "insert_returning", False))


def _insert_and_fetch_id(conn: Connection, table: Any, values: Dict[str, Any], lookup: Any) -> int:
    if _supports_returning(conn):
        row = conn.execute(table.insert().values(**values).returning(table.c.id)).first()
        return _scalar_id(row)

    conn.execute(table.insert().values(**values))
    row = conn.execute(select(table.c.id).where(lookup)).first()
    return _scalar_id(row)


def _upsert_metric_value(conn: Connection, observation_id: int, metric_name: str, values: Dict[str, Any]) -> None:
    if conn.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert

        stmt = dialect_insert(metric_values).values(observation_id=observation_id, metric_name=metric_name, **values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[metric_values.c.observation_id, metric_values.c.metric_name],
            set_=values,
        )
        conn.execute(stmt)
        return

    if conn.dialect.name == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as dialect_insert

        stmt = dialect_insert(metric_values).values(observation_id=observation_id, metric_name=metric_name, **values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[metric_values.c.observation_id, metric_values.c.metric_name],
            set_=values,
        )
        conn.execute(stmt)
        return

    existing = conn.execute(
        select(metric_values.c.observation_id).where(
            metric_values.c.observation_id == observation_id,
            metric_values.c.metric_name == metric_name,
        )
    ).first()
    if existing:
        conn.execute(
            metric_values.update()
            .where(
                metric_values.c.observation_id == observation_id,
                metric_values.c.metric_name == metric_name,
            )
            .values(**values)
        )
    else:
        conn.execute(metric_values.insert().values(observation_id=observation_id, metric_name=metric_name, **values))


def _metric_definition_map(conn: Connection) -> Dict[str, Dict[str, str]]:
    rows = conn.execute(
        select(metric_definitions.c.name, metric_definitions.c.level, metric_definitions.c.value_type)
    ).mappings().fetchall()
    return {str(row["name"]): {"level": str(row["level"]), "value_type": str(row["value_type"])} for row in rows}


def ensure_user_manual_dataset(conn: Connection, dataset_name: str, owner_user_id: str) -> int:
    """Create or update a private user-owned manual dataset."""
    row = conn.execute(
        select(datasets.c.id, datasets.c.owner_user_id, datasets.c.visibility).where(datasets.c.name == dataset_name)
    ).first()
    values = {
        "source": USER_MANUAL_SOURCE_TYPE,
        "visibility": PRIVATE_DATASET_VISIBILITY,
        "owner_user_id": owner_user_id,
        "source_type": USER_MANUAL_SOURCE_TYPE,
        "trust_level": USER_MANUAL_TRUST_LEVEL,
    }
    if row:
        if row.owner_user_id != owner_user_id or row.visibility != PRIVATE_DATASET_VISIBILITY:
            raise ValueError("dataset name is already used by another visible dataset")
        dataset_id = _scalar_id(row)
        conn.execute(datasets.update().where(datasets.c.id == dataset_id).values(**values))
        return dataset_id

    return _insert_and_fetch_id(conn, datasets, {"name": dataset_name, **values}, datasets.c.name == dataset_name)


def _get_or_create_library(conn: Connection, library_name: str) -> int:
    canonical_name = canonicalize_library_name(library_name)
    display_name = library_name.strip()
    row = conn.execute(select(libraries.c.id).where(libraries.c.canonical_name == canonical_name)).first()
    if row:
        return _scalar_id(row)
    return _insert_and_fetch_id(
        conn,
        libraries,
        {"canonical_name": canonical_name, "display_name": display_name},
        libraries.c.canonical_name == canonical_name,
    )


def _get_or_create_ios_version(conn: Connection, ios_version: str) -> int:
    parsed = parse_ios_version_label(ios_version)
    row = conn.execute(select(ios_versions.c.id).where(ios_versions.c.version_label == parsed.version_label)).first()
    values = {
        "device_model": parsed.device_model,
        "ios_release": parsed.ios_release,
        "build_number": parsed.build_number,
    }
    if row:
        ios_version_id = _scalar_id(row)
        update_values = {key: value for key, value in values.items() if value is not None}
        if update_values:
            conn.execute(ios_versions.update().where(ios_versions.c.id == ios_version_id).values(**update_values))
        return ios_version_id
    return _insert_and_fetch_id(
        conn,
        ios_versions,
        {"version_label": parsed.version_label, **values},
        ios_versions.c.version_label == parsed.version_label,
    )


def _get_or_create_manual_observation(
    conn: Connection,
    dataset_id: int,
    library_id: int,
    ios_version_id: int,
    original_path: Optional[str],
    has_hla_metrics: bool,
    has_lla_metrics: bool,
) -> int:
    row = conn.execute(
        select(
            library_observations.c.id,
            library_observations.c.hla_source_seen,
            library_observations.c.lla_source_seen,
        ).where(
            library_observations.c.dataset_id == dataset_id,
            library_observations.c.library_id == library_id,
            library_observations.c.ios_version_id == ios_version_id,
        )
    ).first()
    update_values = {
        "hla_source_seen": 1 if has_hla_metrics else 0,
        "lla_source_seen": 1 if has_lla_metrics else 0,
    }
    if original_path:
        update_values["original_path"] = original_path

    if row:
        observation_id = _scalar_id(row)
        update_values["hla_source_seen"] = max(int(row.hla_source_seen), update_values["hla_source_seen"])
        update_values["lla_source_seen"] = max(int(row.lla_source_seen), update_values["lla_source_seen"])
        conn.execute(
            library_observations.update()
            .where(library_observations.c.id == observation_id)
            .values(**update_values)
        )
        return observation_id

    return _insert_and_fetch_id(
        conn,
        library_observations,
        {
            "dataset_id": dataset_id,
            "library_id": library_id,
            "ios_version_id": ios_version_id,
            "original_path": original_path,
            "hla_source_seen": 1 if has_hla_metrics else 0,
            "lla_source_seen": 1 if has_lla_metrics else 0,
        },
        (
            (library_observations.c.dataset_id == dataset_id)
            & (library_observations.c.library_id == library_id)
            & (library_observations.c.ios_version_id == ios_version_id)
        ),
    )


def _storage_values_for_metric(metric_name: str, value_type: str, value: Any) -> Dict[str, Any]:
    if value_type == "numeric":
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ValueError(f"metric '{metric_name}' must be a non-negative number")
        return {"numeric_value": float(value), "text_value": None, "json_value": None}
    if value_type == "text":
        if not isinstance(value, str):
            raise ValueError(f"metric '{metric_name}' must be a string")
        return {"numeric_value": None, "text_value": value, "json_value": None}
    if value_type == "json":
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"metric '{metric_name}' must be a list of strings")
        return {"numeric_value": None, "text_value": None, "json_value": json_dumps_stable(value)}
    raise ValueError(f"metric '{metric_name}' has unsupported value type '{value_type}'")


def create_user_manual_observation(
    conn: Connection,
    *,
    dataset_name: str,
    owner_user_id: str,
    library_name: str,
    ios_version: str,
    metrics: Dict[str, Any],
    original_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Create or update one private manual observation and return the resolved observation."""
    definitions = _metric_definition_map(conn)
    if not definitions:
        raise ValueError("metric definitions are not initialized")

    unknown_metrics = sorted(name for name in metrics if name not in definitions)
    if unknown_metrics:
        raise ValueError(f"unknown metric(s): {', '.join(unknown_metrics)}")

    dataset_id = ensure_user_manual_dataset(conn, dataset_name=dataset_name, owner_user_id=owner_user_id)
    library_id = _get_or_create_library(conn, library_name)
    ios_version_id = _get_or_create_ios_version(conn, ios_version)
    has_hla_metrics = any(definitions[name]["level"] == "high" for name in metrics)
    has_lla_metrics = any(definitions[name]["level"] == "low" for name in metrics)
    observation_id = _get_or_create_manual_observation(
        conn,
        dataset_id=dataset_id,
        library_id=library_id,
        ios_version_id=ios_version_id,
        original_path=original_path,
        has_hla_metrics=has_hla_metrics,
        has_lla_metrics=has_lla_metrics,
    )

    for metric_name, value in metrics.items():
        value_type = definitions[metric_name]["value_type"]
        storage_values = _storage_values_for_metric(metric_name, value_type, value)
        _upsert_metric_value(conn, observation_id, metric_name, storage_values)

    conn.commit()
    observations = get_library_metrics(
        conn,
        library_name=library_name,
        dataset_name=dataset_name,
        ios_version=ios_version,
        owner_user_id=owner_user_id,
    )
    return observations[0] if observations else {}


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


def _visibility_condition(owner_user_id: Optional[str]) -> Tuple[str, Dict[str, Any]]:
    if owner_user_id:
        return "(d.visibility = 'public' OR d.owner_user_id = :owner_user_id)", {"owner_user_id": owner_user_id}
    return "d.visibility = 'public'", {}


def list_datasets(conn: Connection, owner_user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    visibility_sql, params = _visibility_condition(owner_user_id)
    rows = conn.execute(
        text(
            f"""
            SELECT
                d.name,
                d.source,
                d.visibility,
                d.owner_user_id,
                COALESCE(d.source_type, d.source) AS source_type,
                COALESCE(d.trust_level, 'unknown') AS trust_level,
                d.created_at,
                COUNT(o.id) AS observation_count
            FROM datasets d
            LEFT JOIN library_observations o ON o.dataset_id = d.id
            WHERE {visibility_sql}
            GROUP BY d.id, d.name, d.source, d.visibility, d.owner_user_id, d.source_type, d.trust_level, d.created_at
            ORDER BY CASE WHEN d.visibility = 'public' THEN 0 ELSE 1 END, d.name
            """
        ),
        params,
    ).mappings().fetchall()
    return [_as_dict(row) for row in rows]


def dataset_exists(conn: Connection, dataset_name: str) -> bool:
    row = conn.execute(select(datasets.c.id).where(datasets.c.name == dataset_name)).first()
    return row is not None


def dataset_accessible(conn: Connection, dataset_name: str, owner_user_id: Optional[str] = None) -> bool:
    visibility_sql, params = _visibility_condition(owner_user_id)
    params["dataset_name"] = dataset_name
    row = conn.execute(
        text(
            f"""
            SELECT d.id
            FROM datasets d
            WHERE d.name = :dataset_name AND {visibility_sql}
            """
        ),
        params,
    ).first()
    return row is not None


def list_libraries(
    conn: Connection,
    dataset_name: Optional[str] = None,
    owner_user_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    visibility_sql, params = _visibility_condition(owner_user_id)
    conditions = [visibility_sql]
    if dataset_name:
        conditions.append("d.name = :dataset_name")
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
            WHERE {' AND '.join(conditions)}
            GROUP BY l.id, l.display_name, l.canonical_name
            ORDER BY l.display_name
            """
        ),
        params,
    ).mappings().fetchall()
    return [_as_dict(row) for row in rows]


def list_ios_versions(conn: Connection, owner_user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return all firmware/iOS labels visible to the current user."""
    visibility_sql, params = _visibility_condition(owner_user_id)
    rows = conn.execute(
        text(
            f"""
            SELECT DISTINCT iv.version_label, iv.device_model, iv.ios_release, iv.build_number
            FROM ios_versions iv
            JOIN library_observations o ON o.ios_version_id = iv.id
            JOIN datasets d ON d.id = o.dataset_id
            WHERE {visibility_sql}
            ORDER BY iv.ios_release, iv.build_number, iv.device_model, iv.version_label
            """
        ),
        params,
    ).mappings().fetchall()
    return [_as_dict(row) for row in rows]


def get_library_metrics(
    conn: Connection,
    library_name: str,
    dataset_name: Optional[str] = None,
    ios_version: Optional[str] = None,
    level: Optional[str] = None,
    metrics: Optional[Iterable[str]] = None,
    owner_user_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return metric observations for a visible library.

    Query semantics:
    - library is required;
    - dataset, iOS version, metric level, and exact metrics are optional;
    - ``ios_version`` accepts either a full firmware label or parsed release;
    - private datasets are visible only to their owner.
    """
    canonical_name = canonicalize_library_name(library_name)
    metric_list = list(metrics or [])
    visibility_sql, visibility_params = _visibility_condition(owner_user_id)

    conditions = ["l.canonical_name = :canonical_name", visibility_sql]
    params: Dict[str, Any] = {"canonical_name": canonical_name, **visibility_params}

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
            d.visibility AS dataset_visibility,
            d.owner_user_id AS dataset_owner_user_id,
            COALESCE(d.source_type, d.source) AS dataset_source_type,
            COALESCE(d.trust_level, 'unknown') AS dataset_trust_level,
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
    owner_user_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return all visible library observations for one iOS version or release."""
    metric_list = list(metrics or [])
    visibility_sql, visibility_params = _visibility_condition(owner_user_id)

    conditions = ["(iv.version_label = :ios_version OR iv.ios_release = :ios_version)", visibility_sql]
    params: Dict[str, Any] = {"ios_version": ios_version, **visibility_params}

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
            d.visibility AS dataset_visibility,
            d.owner_user_id AS dataset_owner_user_id,
            COALESCE(d.source_type, d.source) AS dataset_source_type,
            COALESCE(d.trust_level, 'unknown') AS dataset_trust_level,
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
                "dataset_visibility": row.get("dataset_visibility"),
                "dataset_owner_user_id": row.get("dataset_owner_user_id"),
                "dataset_source_type": row.get("dataset_source_type"),
                "dataset_trust_level": row.get("dataset_trust_level"),
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
