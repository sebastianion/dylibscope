from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy import bindparam, select, text
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from dylibscope.storage.normalize import canonicalize_library_name, json_dumps_stable, parse_ios_version_label
from dylibscope.storage.schema import (
    datasets,
    ios_versions,
    libraries,
    library_observations,
    metric_definitions,
    metric_values,
    upload_job_items,
    upload_jobs,
)


PUBLIC_DATASET_VISIBILITY = "public"

USER_MANUAL_SOURCE_TYPE = "user_manual"
USER_MANUAL_TRUST_LEVEL = "user_provided_unverified"
USER_UPLOADED_HLA_SOURCE_TYPE = "user_uploaded_hla"
PLATFORM_EXTRACTED_HLA_TRUST_LEVEL = "platform_extracted_hla"
PUBLIC_BASELINE_CLONE_SOURCE_TYPE = "public_baseline_clone_with_user_manual"
MIXED_VERIFIED_MANUAL_TRUST_LEVEL = "mixed_verified_and_user_provided"
PRIVATE_DATASET_VISIBILITY = "private"
PUBLIC_BASELINE_DATASET_NAME = "public-baseline"


class DatasetConflictError(ValueError):
    """Raised when a private dataset name conflicts within the current owner scope."""


class DatasetNotFoundError(ValueError):
    """Raised when a private dataset is not found for the current owner scope."""


class ObservationConflictError(ValueError):
    """Raised when a manual observation would overwrite an existing library/iOS entry."""


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


def _dataset_select_columns() -> Any:
    return select(
        datasets.c.id,
        datasets.c.name,
        datasets.c.owner_user_id,
        datasets.c.visibility,
        datasets.c.source,
        datasets.c.source_type,
        datasets.c.trust_level,
    )


def _public_dataset_row_by_name(conn: Connection, dataset_name: str) -> Optional[RowMapping]:
    return (
        conn.execute(
            _dataset_select_columns().where(
                datasets.c.name == dataset_name,
                datasets.c.visibility == PUBLIC_DATASET_VISIBILITY,
            )
        )
        .mappings()
        .first()
    )


def _private_dataset_row_by_owner_and_name(
    conn: Connection,
    *,
    dataset_name: str,
    owner_user_id: str,
) -> Optional[RowMapping]:
    return (
        conn.execute(
            _dataset_select_columns().where(
                datasets.c.name == dataset_name,
                datasets.c.visibility == PRIVATE_DATASET_VISIBILITY,
                datasets.c.owner_user_id == owner_user_id,
            )
        )
        .mappings()
        .first()
    )


def _create_private_dataset(
    conn: Connection,
    *,
    dataset_name: str,
    owner_user_id: str,
    source: str,
    source_type: str,
    trust_level: str,
) -> int:
    try:
        return _insert_and_fetch_id(
            conn,
            datasets,
            {
                "name": dataset_name,
                "source": source,
                "visibility": PRIVATE_DATASET_VISIBILITY,
                "owner_user_id": owner_user_id,
                "source_type": source_type,
                "trust_level": trust_level,
            },
            (
                (datasets.c.name == dataset_name)
                & (datasets.c.owner_user_id == owner_user_id)
                & (datasets.c.visibility == PRIVATE_DATASET_VISIBILITY)
            ),
        )
    except IntegrityError as exc:
        raise DatasetConflictError(
            "private dataset could not be created because the name conflicts in the current scope; "
            "run the schema migration if this appears to be a cross-user collision"
        ) from exc


def _public_name_is_reserved(conn: Connection, dataset_name: str) -> bool:
    return _public_dataset_row_by_name(conn, dataset_name) is not None


def ensure_user_manual_dataset(conn: Connection, dataset_name: str, owner_user_id: str) -> int:
    """Create a private manual dataset, or reuse an existing private user-owned dataset.

    Existing private datasets keep their provenance/trust metadata. This matters for
    cloned baseline datasets, whose metadata should remain mixed rather than being
    downgraded to plain user_manual on later appends.
    """
    row = _private_dataset_row_by_owner_and_name(
        conn,
        dataset_name=dataset_name,
        owner_user_id=owner_user_id,
    )
    if row:
        return int(row["id"])
    if _public_name_is_reserved(conn, dataset_name):
        raise DatasetConflictError("dataset name is reserved by a public dataset")

    return _create_private_dataset(
        conn,
        dataset_name=dataset_name,
        owner_user_id=owner_user_id,
        source=USER_MANUAL_SOURCE_TYPE,
        source_type=USER_MANUAL_SOURCE_TYPE,
        trust_level=USER_MANUAL_TRUST_LEVEL,
    )


def create_new_user_manual_dataset(conn: Connection, dataset_name: str, owner_user_id: str) -> int:
    """Create a new private manual dataset and reject accidental appends."""
    if _private_dataset_row_by_owner_and_name(
        conn,
        dataset_name=dataset_name,
        owner_user_id=owner_user_id,
    ):
        raise DatasetConflictError(
            "a private dataset with this name already exists for your account; use append mode or choose another name"
        )
    if _public_name_is_reserved(conn, dataset_name):
        raise DatasetConflictError("dataset name is reserved by a public dataset")
    return _create_private_dataset(
        conn,
        dataset_name=dataset_name,
        owner_user_id=owner_user_id,
        source=USER_MANUAL_SOURCE_TYPE,
        source_type=USER_MANUAL_SOURCE_TYPE,
        trust_level=USER_MANUAL_TRUST_LEVEL,
    )


def ensure_existing_private_user_dataset(conn: Connection, dataset_name: str, owner_user_id: str) -> int:
    """Return an existing private dataset owned by the current user."""
    row = _private_dataset_row_by_owner_and_name(
        conn,
        dataset_name=dataset_name,
        owner_user_id=owner_user_id,
    )
    if not row:
        raise ValueError("private target dataset was not found for the current user")
    return int(row["id"])



def prepare_user_hla_upload_dataset(
    conn: Connection,
    *,
    dataset_name: str,
    owner_user_id: str,
    target_mode: str,
) -> int:
    """Create or resolve the private dataset used by a batch uploaded-HLA job."""
    cleaned_dataset_name = dataset_name.strip()
    if not cleaned_dataset_name:
        raise ValueError("dataset_name is required")
    if target_mode == "new_private_dataset":
        if _private_dataset_row_by_owner_and_name(conn, dataset_name=cleaned_dataset_name, owner_user_id=owner_user_id):
            raise DatasetConflictError(
                "a private dataset with this name already exists for your account; use append mode or choose another name"
            )
        if _public_name_is_reserved(conn, cleaned_dataset_name):
            raise DatasetConflictError("dataset name is reserved by a public dataset")
        dataset_id = _create_private_dataset(
            conn,
            dataset_name=cleaned_dataset_name,
            owner_user_id=owner_user_id,
            source=USER_UPLOADED_HLA_SOURCE_TYPE,
            source_type=USER_UPLOADED_HLA_SOURCE_TYPE,
            trust_level=PLATFORM_EXTRACTED_HLA_TRUST_LEVEL,
        )
        conn.commit()
        return dataset_id
    if target_mode == "append_private_dataset":
        return ensure_existing_private_user_dataset(
            conn,
            dataset_name=cleaned_dataset_name,
            owner_user_id=owner_user_id,
        )
    raise ValueError("target_mode must be either 'new_private_dataset' or 'append_private_dataset'")

def clone_public_dataset_for_user(
    conn: Connection,
    *,
    source_dataset_name: str,
    target_dataset_name: str,
    owner_user_id: str,
) -> int:
    """Physically clone a public dataset into a private user-owned dataset."""
    if _private_dataset_row_by_owner_and_name(
        conn,
        dataset_name=target_dataset_name,
        owner_user_id=owner_user_id,
    ):
        raise DatasetConflictError("clone target dataset already exists for your account; append to it instead of cloning again")
    if _public_name_is_reserved(conn, target_dataset_name):
        raise DatasetConflictError("clone target name is reserved by a public dataset")

    source_row = _public_dataset_row_by_name(conn, source_dataset_name)
    if not source_row:
        raise ValueError("source dataset must be an existing public dataset")

    source_dataset_id = int(source_row["id"])
    target_dataset_id = _create_private_dataset(
        conn,
        dataset_name=target_dataset_name,
        owner_user_id=owner_user_id,
        source=source_dataset_name,
        source_type=PUBLIC_BASELINE_CLONE_SOURCE_TYPE,
        trust_level=MIXED_VERIFIED_MANUAL_TRUST_LEVEL,
    )

    conn.execute(
        text(
            """
            INSERT INTO library_observations (
                dataset_id,
                library_id,
                ios_version_id,
                original_path,
                hla_source_seen,
                lla_source_seen
            )
            SELECT
                :target_dataset_id,
                library_id,
                ios_version_id,
                original_path,
                hla_source_seen,
                lla_source_seen
            FROM library_observations
            WHERE dataset_id = :source_dataset_id
            """
        ),
        {"target_dataset_id": target_dataset_id, "source_dataset_id": source_dataset_id},
    )

    conn.execute(
        text(
            """
            INSERT INTO metric_values (
                observation_id,
                metric_name,
                numeric_value,
                text_value,
                json_value
            )
            SELECT
                new_o.id,
                mv.metric_name,
                mv.numeric_value,
                mv.text_value,
                mv.json_value
            FROM metric_values mv
            JOIN library_observations old_o ON old_o.id = mv.observation_id
            JOIN library_observations new_o
              ON new_o.dataset_id = :target_dataset_id
             AND new_o.library_id = old_o.library_id
             AND new_o.ios_version_id = old_o.ios_version_id
            WHERE old_o.dataset_id = :source_dataset_id
            """
        ),
        {"target_dataset_id": target_dataset_id, "source_dataset_id": source_dataset_id},
    )

    return target_dataset_id


def resolve_user_observation_dataset(
    conn: Connection,
    *,
    target_mode: str,
    dataset_name: str,
    owner_user_id: str,
    source_dataset_name: str = PUBLIC_BASELINE_DATASET_NAME,
) -> int:
    """Resolve the target dataset for a user-provided observation."""
    if target_mode == "new_private_dataset":
        return create_new_user_manual_dataset(conn, dataset_name=dataset_name, owner_user_id=owner_user_id)
    if target_mode == "append_private_dataset":
        return ensure_existing_private_user_dataset(conn, dataset_name=dataset_name, owner_user_id=owner_user_id)
    if target_mode == "clone_public_baseline":
        return clone_public_dataset_for_user(
            conn,
            source_dataset_name=source_dataset_name,
            target_dataset_name=dataset_name,
            owner_user_id=owner_user_id,
        )
    raise ValueError(f"unsupported target_mode '{target_mode}'")


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
    conflict_mode: str,
) -> Tuple[int, str]:
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
        if conflict_mode == "reject":
            raise ObservationConflictError(
                "observation already exists for this dataset, library, and iOS version; "
                "use conflict_mode=replace to replace it explicitly"
            )
        if conflict_mode != "replace":
            raise ValueError("conflict_mode must be either 'reject' or 'replace'")
        observation_id = _scalar_id(row)
        conn.execute(
            library_observations.update()
            .where(library_observations.c.id == observation_id)
            .values(**update_values)
        )
        conn.execute(metric_values.delete().where(metric_values.c.observation_id == observation_id))
        return observation_id, "replaced"

    if conflict_mode not in {"reject", "replace"}:
        raise ValueError("conflict_mode must be either 'reject' or 'replace'")

    observation_id = _insert_and_fetch_id(
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
    return observation_id, "created"



def _get_or_create_upload_observation_by_ios_release(
    conn: Connection,
    *,
    dataset_id: int,
    library_id: int,
    ios_version: str,
    original_path: Optional[str],
    conflict_mode: str,
) -> Tuple[int, str]:
    """Create or replace one uploaded-HLA observation using iOS release as identity.

    Upload datasets accept both release-only values such as ``12.0`` and full
    firmware labels such as ``iPhone11,8_12.0_16A366``. Those two inputs should
    not create two timeline observations for the same library/release.
    """
    parsed = parse_ios_version_label(ios_version)
    ios_version_id = _get_or_create_ios_version(conn, ios_version)

    if parsed.ios_release:
        row = (
            conn.execute(
                text(
                    """
                    SELECT
                        o.id,
                        o.ios_version_id,
                        iv.version_label,
                        iv.ios_release
                    FROM library_observations o
                    JOIN ios_versions iv ON iv.id = o.ios_version_id
                    WHERE o.dataset_id = :dataset_id
                      AND o.library_id = :library_id
                      AND iv.ios_release = :ios_release
                    ORDER BY
                        CASE
                            WHEN iv.version_label = :ios_version THEN 0
                            WHEN iv.version_label = :ios_release THEN 1
                            ELSE 2
                        END,
                        iv.version_label
                    LIMIT 1
                    """
                ),
                {
                    "dataset_id": dataset_id,
                    "library_id": library_id,
                    "ios_release": parsed.ios_release,
                    "ios_version": parsed.version_label,
                },
            )
            .mappings()
            .first()
        )
        if row:
            if conflict_mode == "reject":
                raise ObservationConflictError(
                    "observation already exists for this dataset, library, and iOS release; "
                    "use conflict_mode=replace to replace it explicitly"
                )
            if conflict_mode != "replace":
                raise ValueError("conflict_mode must be either 'reject' or 'replace'")
            observation_id = int(row["id"])
            update_values = {
                "ios_version_id": ios_version_id,
                "hla_source_seen": 1,
                "lla_source_seen": 0,
            }
            if original_path:
                update_values["original_path"] = original_path
            conn.execute(
                library_observations.update()
                .where(library_observations.c.id == observation_id)
                .values(**update_values)
            )
            conn.execute(metric_values.delete().where(metric_values.c.observation_id == observation_id))
            return observation_id, "replaced"

    return _get_or_create_manual_observation(
        conn,
        dataset_id=dataset_id,
        library_id=library_id,
        ios_version_id=ios_version_id,
        original_path=original_path,
        has_hla_metrics=True,
        has_lla_metrics=False,
        conflict_mode=conflict_mode,
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



def delete_user_dataset(conn: Connection, *, dataset_name: str, owner_user_id: str) -> Dict[str, Any]:
    """Delete one private dataset owned by the current user.

    Public datasets are immutable through this endpoint. Libraries and iOS-version
    rows are intentionally preserved because they can be shared by other datasets.
    """
    cleaned_name = dataset_name.strip()
    if not cleaned_name:
        raise ValueError("dataset_name is required")
    if cleaned_name == PUBLIC_BASELINE_DATASET_NAME or _public_name_is_reserved(conn, cleaned_name):
        raise DatasetConflictError("public datasets cannot be deleted")

    dataset_row = _private_dataset_row_by_owner_and_name(
        conn,
        dataset_name=cleaned_name,
        owner_user_id=owner_user_id,
    )
    if not dataset_row:
        raise DatasetNotFoundError("private dataset was not found for the current user")

    dataset_id = int(dataset_row["id"])
    deleted_observations = int(
        conn.execute(
            text("SELECT COUNT(*) FROM library_observations WHERE dataset_id = :dataset_id"),
            {"dataset_id": dataset_id},
        ).scalar_one()
    )
    deleted_metric_values = int(
        conn.execute(
            text(
                """
                SELECT COUNT(*)
                FROM metric_values mv
                JOIN library_observations o ON o.id = mv.observation_id
                WHERE o.dataset_id = :dataset_id
                """
            ),
            {"dataset_id": dataset_id},
        ).scalar_one()
    )

    observation_ids = select(library_observations.c.id).where(library_observations.c.dataset_id == dataset_id)
    conn.execute(metric_values.delete().where(metric_values.c.observation_id.in_(observation_ids)))
    conn.execute(library_observations.delete().where(library_observations.c.dataset_id == dataset_id))
    conn.execute(datasets.delete().where(datasets.c.id == dataset_id))
    conn.commit()

    return {
        "deleted": True,
        "dataset_name": cleaned_name,
        "dataset_visibility": PRIVATE_DATASET_VISIBILITY,
        "deleted_observations": deleted_observations,
        "deleted_metric_values": deleted_metric_values,
    }


def list_user_observations(conn: Connection, *, dataset_name: str, owner_user_id: str) -> List[Dict[str, Any]]:
    """List observations stored in one private dataset owned by the current user."""
    cleaned_name = dataset_name.strip()
    if not cleaned_name:
        raise ValueError("dataset_name is required")
    if cleaned_name == PUBLIC_BASELINE_DATASET_NAME or _public_name_is_reserved(conn, cleaned_name):
        raise DatasetConflictError("public datasets cannot be managed through user observation endpoints")

    dataset_row = _private_dataset_row_by_owner_and_name(
        conn,
        dataset_name=cleaned_name,
        owner_user_id=owner_user_id,
    )
    if not dataset_row:
        raise DatasetNotFoundError("private dataset was not found for the current user")

    rows = conn.execute(
        text(
            """
            SELECT
                o.id AS observation_id,
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
                o.original_path,
                o.hla_source_seen,
                o.lla_source_seen,
                mv.metric_name,
                md.level,
                mv.numeric_value,
                mv.text_value,
                mv.json_value
            FROM library_observations o
            JOIN datasets d ON d.id = o.dataset_id
            JOIN libraries l ON l.id = o.library_id
            JOIN ios_versions iv ON iv.id = o.ios_version_id
            LEFT JOIN metric_values mv ON mv.observation_id = o.id
            LEFT JOIN metric_definitions md ON md.name = mv.metric_name
            WHERE d.id = :dataset_id
            ORDER BY l.display_name, iv.ios_release, iv.build_number, iv.version_label, mv.metric_name
            """
        ),
        {"dataset_id": int(dataset_row["id"])},
    ).mappings().fetchall()

    grouped: Dict[int, Dict[str, Any]] = {}
    for row in rows:
        observation_id = int(row["observation_id"])
        if observation_id not in grouped:
            grouped[observation_id] = {
                "observation_id": observation_id,
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
                "original_path": row["original_path"],
                "hla_source_seen": bool(row["hla_source_seen"]),
                "lla_source_seen": bool(row["lla_source_seen"]),
                "metrics": {},
            }
        if row["metric_name"] is not None:
            grouped[observation_id]["metrics"][row["metric_name"]] = {
                "level": row["level"],
                "value": _coerce_metric_value(row),
            }

    observations = list(grouped.values())
    for observation in observations:
        observation["metric_count"] = len(observation["metrics"])
    return observations


def delete_user_observation(
    conn: Connection,
    *,
    dataset_name: str,
    owner_user_id: str,
    library_name: str,
    ios_version: str,
) -> Dict[str, Any]:
    """Delete one observation from a private dataset owned by the current user."""
    cleaned_name = dataset_name.strip()
    cleaned_library = library_name.strip()
    cleaned_ios_version = ios_version.strip()
    if not cleaned_name:
        raise ValueError("dataset_name is required")
    if not cleaned_library:
        raise ValueError("library is required")
    if not cleaned_ios_version:
        raise ValueError("ios_version is required")
    if cleaned_name == PUBLIC_BASELINE_DATASET_NAME or _public_name_is_reserved(conn, cleaned_name):
        raise DatasetConflictError("public datasets cannot be modified through user observation endpoints")

    dataset_row = _private_dataset_row_by_owner_and_name(
        conn,
        dataset_name=cleaned_name,
        owner_user_id=owner_user_id,
    )
    if not dataset_row:
        raise DatasetNotFoundError("private dataset was not found for the current user")

    rows = conn.execute(
        text(
            """
            SELECT o.id, iv.version_label, iv.ios_release
            FROM library_observations o
            JOIN libraries l ON l.id = o.library_id
            JOIN ios_versions iv ON iv.id = o.ios_version_id
            WHERE o.dataset_id = :dataset_id
              AND l.canonical_name = :canonical_name
              AND (iv.version_label = :ios_version OR iv.ios_release = :ios_version)
            ORDER BY iv.version_label
            """
        ),
        {
            "dataset_id": int(dataset_row["id"]),
            "canonical_name": canonicalize_library_name(cleaned_library),
            "ios_version": cleaned_ios_version,
        },
    ).mappings().fetchall()

    if not rows:
        raise DatasetNotFoundError("observation was not found for this private dataset, library, and iOS version")
    if len(rows) > 1:
        raise ValueError("multiple observations match this iOS release; use the full firmware label to delete one observation")

    observation_id = int(rows[0]["id"])
    deleted_metric_values = int(
        conn.execute(
            text("SELECT COUNT(*) FROM metric_values WHERE observation_id = :observation_id"),
            {"observation_id": observation_id},
        ).scalar_one()
    )
    conn.execute(metric_values.delete().where(metric_values.c.observation_id == observation_id))
    conn.execute(library_observations.delete().where(library_observations.c.id == observation_id))
    conn.commit()

    return {
        "deleted": True,
        "dataset_name": cleaned_name,
        "library": cleaned_library,
        "ios_version": rows[0]["version_label"],
        "deleted_observations": 1,
        "deleted_metric_values": deleted_metric_values,
    }

def create_user_manual_observation(
    conn: Connection,
    *,
    dataset_name: str,
    owner_user_id: str,
    library_name: str,
    ios_version: str,
    metrics: Dict[str, Any],
    original_path: Optional[str] = None,
    target_mode: str,
    source_dataset_name: str = PUBLIC_BASELINE_DATASET_NAME,
    conflict_mode: str = "reject",
) -> Dict[str, Any]:
    """Create one private manual observation or explicitly replace an existing one."""
    definitions = _metric_definition_map(conn)
    if not definitions:
        raise ValueError("metric definitions are not initialized")

    unknown_metrics = sorted(name for name in metrics if name not in definitions)
    if unknown_metrics:
        raise ValueError(f"unknown metric(s): {', '.join(unknown_metrics)}")

    dataset_id = resolve_user_observation_dataset(
        conn,
        target_mode=target_mode,
        dataset_name=dataset_name,
        owner_user_id=owner_user_id,
        source_dataset_name=source_dataset_name,
    )
    library_id = _get_or_create_library(conn, library_name)
    ios_version_id = _get_or_create_ios_version(conn, ios_version)
    has_hla_metrics = any(definitions[name]["level"] == "high" for name in metrics)
    has_lla_metrics = any(definitions[name]["level"] == "low" for name in metrics)
    observation_id, write_operation = _get_or_create_manual_observation(
        conn,
        dataset_id=dataset_id,
        library_id=library_id,
        ios_version_id=ios_version_id,
        original_path=original_path,
        has_hla_metrics=has_hla_metrics,
        has_lla_metrics=has_lla_metrics,
        conflict_mode=conflict_mode,
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
    if not observations:
        return {}
    observation = observations[0]
    observation["manual_write_operation"] = write_operation
    return observation


def create_user_hla_upload_observation(
    conn: Connection,
    *,
    dataset_name: str,
    owner_user_id: str,
    library_name: str,
    ios_version: str,
    metrics: Dict[str, Any],
    original_path: Optional[str] = None,
    target_mode: str,
    conflict_mode: str = "reject",
) -> Dict[str, Any]:
    """Create one private observation from a platform-extracted uploaded .dylib HLA result."""
    definitions = _metric_definition_map(conn)
    if not definitions:
        raise ValueError("metric definitions are not initialized")
    unknown_metrics = sorted(name for name in metrics if name not in definitions)
    if unknown_metrics:
        raise ValueError(f"unknown metric(s): {', '.join(unknown_metrics)}")
    unsupported_levels = sorted(name for name in metrics if definitions[name]["level"] != "high")
    if unsupported_levels:
        raise ValueError(f"uploaded HLA observations cannot include low-level metric(s): {', '.join(unsupported_levels)}")

    cleaned_dataset_name = dataset_name.strip()
    if not cleaned_dataset_name:
        raise ValueError("dataset_name is required")

    if target_mode == "new_private_dataset":
        if _private_dataset_row_by_owner_and_name(conn, dataset_name=cleaned_dataset_name, owner_user_id=owner_user_id):
            raise DatasetConflictError(
                "a private dataset with this name already exists for your account; use append mode or choose another name"
            )
        if _public_name_is_reserved(conn, cleaned_dataset_name):
            raise DatasetConflictError("dataset name is reserved by a public dataset")
        dataset_id = _create_private_dataset(
            conn,
            dataset_name=cleaned_dataset_name,
            owner_user_id=owner_user_id,
            source=USER_UPLOADED_HLA_SOURCE_TYPE,
            source_type=USER_UPLOADED_HLA_SOURCE_TYPE,
            trust_level=PLATFORM_EXTRACTED_HLA_TRUST_LEVEL,
        )
    elif target_mode == "append_private_dataset":
        dataset_id = ensure_existing_private_user_dataset(
            conn,
            dataset_name=cleaned_dataset_name,
            owner_user_id=owner_user_id,
        )
    else:
        raise ValueError("target_mode must be either 'new_private_dataset' or 'append_private_dataset'")

    library_id = _get_or_create_library(conn, library_name)
    observation_id, write_operation = _get_or_create_upload_observation_by_ios_release(
        conn,
        dataset_id=dataset_id,
        library_id=library_id,
        ios_version=ios_version,
        original_path=original_path,
        conflict_mode=conflict_mode,
    )
    for metric_name, value in metrics.items():
        value_type = definitions[metric_name]["value_type"]
        storage_values = _storage_values_for_metric(metric_name, value_type, value)
        _upsert_metric_value(conn, observation_id, metric_name, storage_values)
    conn.commit()

    observations = get_library_metrics(
        conn,
        library_name=library_name,
        dataset_name=cleaned_dataset_name,
        ios_version=ios_version,
        owner_user_id=owner_user_id,
    )
    if not observations:
        return {}
    observation = observations[0]
    observation["upload_write_operation"] = write_operation
    return observation



def create_upload_job(
    conn: Connection,
    *,
    job_id: str,
    owner_user_id: str,
    dataset_name: str,
    ios_version: str,
    target_mode: str,
    conflict_mode: str,
    zip_filename: str,
    zip_byte_count: int,
    total_files: int,
    ignored_count: int,
) -> Dict[str, Any]:
    conn.execute(
        upload_jobs.insert().values(
            id=job_id,
            owner_user_id=owner_user_id,
            dataset_name=dataset_name,
            ios_version=ios_version,
            target_mode=target_mode,
            conflict_mode=conflict_mode,
            status="queued",
            zip_filename=zip_filename,
            zip_byte_count=zip_byte_count,
            total_files=total_files,
            processed_count=0,
            failed_count=0,
            ignored_count=ignored_count,
        )
    )
    conn.commit()
    return get_upload_job(conn, job_id=job_id, owner_user_id=owner_user_id)


def create_upload_job_item(
    conn: Connection,
    *,
    item_id: str,
    job_id: str,
    filename: str,
    library_name: str,
) -> None:
    conn.execute(
        upload_job_items.insert().values(
            id=item_id,
            job_id=job_id,
            filename=filename,
            library_name=library_name,
            status="queued",
        )
    )


def update_upload_job_status(
    conn: Connection,
    *,
    job_id: str,
    owner_user_id: str,
    status: str,
    error_message: Optional[str] = None,
) -> None:
    completed_sql = ", completed_at = CURRENT_TIMESTAMP" if status in {"completed", "failed"} else ""
    conn.execute(
        text(
            f"""
            UPDATE upload_jobs
            SET status = :status,
                error_message = :error_message,
                updated_at = CURRENT_TIMESTAMP
                {completed_sql}
            WHERE id = :job_id AND owner_user_id = :owner_user_id
            """
        ),
        {
            "job_id": job_id,
            "owner_user_id": owner_user_id,
            "status": status,
            "error_message": error_message,
        },
    )
    conn.commit()


def update_upload_job_item_status(
    conn: Connection,
    *,
    item_id: str,
    status: str,
    error_message: Optional[str] = None,
    observation_id: Optional[int] = None,
) -> None:
    completed_sql = ", completed_at = CURRENT_TIMESTAMP" if status in {"processed", "failed"} else ""
    conn.execute(
        text(
            f"""
            UPDATE upload_job_items
            SET status = :status,
                error_message = :error_message,
                observation_id = :observation_id,
                updated_at = CURRENT_TIMESTAMP
                {completed_sql}
            WHERE id = :item_id
            """
        ),
        {
            "item_id": item_id,
            "status": status,
            "error_message": error_message,
            "observation_id": observation_id,
        },
    )
    conn.commit()


def refresh_upload_job_counts(conn: Connection, *, job_id: str, owner_user_id: str) -> None:
    conn.execute(
        text(
            """
            UPDATE upload_jobs
            SET processed_count = (
                    SELECT COUNT(*) FROM upload_job_items WHERE job_id = :job_id AND status = 'processed'
                ),
                failed_count = (
                    SELECT COUNT(*) FROM upload_job_items WHERE job_id = :job_id AND status = 'failed'
                ),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :job_id AND owner_user_id = :owner_user_id
            """
        ),
        {"job_id": job_id, "owner_user_id": owner_user_id},
    )
    conn.commit()


def get_upload_job(conn: Connection, *, job_id: str, owner_user_id: str) -> Dict[str, Any]:
    job = (
        conn.execute(
            text(
                """
                SELECT *
                FROM upload_jobs
                WHERE id = :job_id AND owner_user_id = :owner_user_id
                """
            ),
            {"job_id": job_id, "owner_user_id": owner_user_id},
        )
        .mappings()
        .first()
    )
    if not job:
        raise DatasetNotFoundError("upload job was not found for the current user")
    items = (
        conn.execute(
            text(
                """
                SELECT *
                FROM upload_job_items
                WHERE job_id = :job_id
                ORDER BY filename
                """
            ),
            {"job_id": job_id},
        )
        .mappings()
        .fetchall()
    )
    job_payload = _as_dict(job)
    total_files = int(job_payload.get("total_files") or 0)
    processed_count = int(job_payload.get("processed_count") or 0)
    failed_count = int(job_payload.get("failed_count") or 0)
    completed_count = processed_count + failed_count
    job_payload["progress_percent"] = round((completed_count / total_files) * 100, 2) if total_files else 0
    item_payloads = [_as_dict(item) for item in items]
    job_payload["items"] = item_payloads
    job_payload["results"] = [item for item in item_payloads if item.get("status") == "processed"]
    job_payload["failures"] = [item for item in item_payloads if item.get("status") == "failed"]
    job_payload["pending_count"] = max(total_files - completed_count, 0)
    return job_payload

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


def dataset_exists(conn: Connection, dataset_name: str, owner_user_id: Optional[str] = None) -> bool:
    if _public_dataset_row_by_name(conn, dataset_name):
        return True
    if owner_user_id and _private_dataset_row_by_owner_and_name(
        conn,
        dataset_name=dataset_name,
        owner_user_id=owner_user_id,
    ):
        return True
    return False


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


def list_ios_versions(
    conn: Connection,
    dataset_name: Optional[str] = None,
    owner_user_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return firmware/iOS labels visible in the requested dataset scope."""
    visibility_sql, params = _visibility_condition(owner_user_id)
    conditions = [visibility_sql]
    if dataset_name:
        conditions.append("d.name = :dataset_name")
        params["dataset_name"] = dataset_name
    rows = conn.execute(
        text(
            f"""
            SELECT DISTINCT iv.version_label, iv.device_model, iv.ios_release, iv.build_number
            FROM ios_versions iv
            JOIN library_observations o ON o.ios_version_id = iv.id
            JOIN datasets d ON d.id = o.dataset_id
            WHERE {' AND '.join(conditions)}
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
