from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, Optional

from dylibscope.storage.normalize import (
    canonical_library_name,
    display_library_name,
    ios_version_label,
    parse_ios_version_label,
    json_dumps_stable,
    normalize_hla_metrics,
    normalize_lla_metrics,
    original_path,
)
from dylibscope.storage.schema import initialize_database


@dataclass(frozen=True)
class ImportSummary:
    dataset_name: str
    hla_records: int = 0
    lla_records: int = 0
    errors: int = 0

    @property
    def total_records(self) -> int:
        return self.hla_records + self.lla_records


def get_or_create_dataset(conn: sqlite3.Connection, name: str, source: str = "public_baseline") -> int:
    conn.execute(
        "INSERT OR IGNORE INTO datasets(name, source, visibility) VALUES (?, ?, 'public')",
        (name, source),
    )
    row = conn.execute("SELECT id FROM datasets WHERE name = ?", (name,)).fetchone()
    return int(row["id"])


def get_or_create_ios_version(conn: sqlite3.Connection, version_label: str) -> int:
    parsed = parse_ios_version_label(version_label)
    conn.execute(
        """
        INSERT INTO ios_versions(version_label, device_model, ios_release, build_number)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(version_label) DO UPDATE SET
            device_model = COALESCE(excluded.device_model, ios_versions.device_model),
            ios_release = COALESCE(excluded.ios_release, ios_versions.ios_release),
            build_number = COALESCE(excluded.build_number, ios_versions.build_number)
        """,
        (
            parsed.version_label,
            parsed.device_model,
            parsed.ios_release,
            parsed.build_number,
        ),
    )
    row = conn.execute("SELECT id FROM ios_versions WHERE version_label = ?", (version_label,)).fetchone()
    return int(row["id"])


def get_or_create_library(conn: sqlite3.Connection, canonical_name: str, display_name: str) -> int:
    conn.execute(
        "INSERT OR IGNORE INTO libraries(canonical_name, display_name) VALUES (?, ?)",
        (canonical_name, display_name),
    )
    row = conn.execute("SELECT id FROM libraries WHERE canonical_name = ?", (canonical_name,)).fetchone()
    return int(row["id"])


def get_or_create_observation(
    conn: sqlite3.Connection,
    dataset_id: int,
    library_id: int,
    ios_version_id: int,
    path: Optional[str],
    source_level: str,
) -> int:
    hla_seen = 1 if source_level == "high" else 0
    lla_seen = 1 if source_level == "low" else 0
    conn.execute(
        """
        INSERT INTO library_observations(
            dataset_id,
            library_id,
            ios_version_id,
            original_path,
            hla_source_seen,
            lla_source_seen
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(dataset_id, library_id, ios_version_id)
        DO UPDATE SET
            original_path = COALESCE(excluded.original_path, library_observations.original_path),
            hla_source_seen = MAX(library_observations.hla_source_seen, excluded.hla_source_seen),
            lla_source_seen = MAX(library_observations.lla_source_seen, excluded.lla_source_seen),
            updated_at = CURRENT_TIMESTAMP
        """,
        (dataset_id, library_id, ios_version_id, path, hla_seen, lla_seen),
    )
    row = conn.execute(
        """
        SELECT id FROM library_observations
        WHERE dataset_id = ? AND library_id = ? AND ios_version_id = ?
        """,
        (dataset_id, library_id, ios_version_id),
    ).fetchone()
    return int(row["id"])


def upsert_metric(conn: sqlite3.Connection, observation_id: int, metric_name: str, value: Any) -> None:
    definition = conn.execute(
        "SELECT value_type FROM metric_definitions WHERE name = ?",
        (metric_name,),
    ).fetchone()
    if definition is None:
        raise ValueError(f"unknown metric: {metric_name}")

    value_type = str(definition["value_type"])
    numeric_value = None
    text_value = None
    json_value = None

    if value_type == "numeric":
        numeric_value = float(value)
    elif value_type == "text":
        text_value = str(value)
    elif value_type == "json":
        json_value = json_dumps_stable(value)
    else:
        raise ValueError(f"unsupported metric value type: {value_type}")

    conn.execute(
        """
        INSERT INTO metric_values(observation_id, metric_name, numeric_value, text_value, json_value)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(observation_id, metric_name)
        DO UPDATE SET
            numeric_value = excluded.numeric_value,
            text_value = excluded.text_value,
            json_value = excluded.json_value
        """,
        (observation_id, metric_name, numeric_value, text_value, json_value),
    )


def import_record(
    conn: sqlite3.Connection,
    dataset_id: int,
    record: Dict[str, Any],
    source_level: str,
) -> None:
    canonical_name = canonical_library_name(record)
    display_name = display_library_name(record)
    version_label = ios_version_label(record)

    library_id = get_or_create_library(conn, canonical_name, display_name)
    ios_version_id = get_or_create_ios_version(conn, version_label)
    observation_id = get_or_create_observation(
        conn=conn,
        dataset_id=dataset_id,
        library_id=library_id,
        ios_version_id=ios_version_id,
        path=original_path(record),
        source_level=source_level,
    )

    if source_level == "high":
        metrics = normalize_hla_metrics(record)
    elif source_level == "low":
        metrics = normalize_lla_metrics(record)
    else:
        raise ValueError(f"unsupported source level: {source_level}")

    for metric_name, value in metrics.items():
        upsert_metric(conn, observation_id, metric_name, value)


def log_import_error(
    conn: sqlite3.Connection,
    dataset_id: int,
    source_level: str,
    source_path: str,
    line_number: Optional[int],
    error: Exception,
) -> None:
    conn.execute(
        """
        INSERT INTO import_errors(dataset_id, source_level, source_path, line_number, error_message)
        VALUES (?, ?, ?, ?, ?)
        """,
        (dataset_id, source_level, source_path, line_number, str(error)),
    )


def import_jsonl_file(
    conn: sqlite3.Connection,
    dataset_id: int,
    path: str,
    source_level: str,
) -> tuple[int, int]:
    imported = 0
    errors = 0
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
                import_record(conn, dataset_id, record, source_level)
                imported += 1
            except Exception as exc:  # noqa: BLE001 - importer should continue collecting bad records
                log_import_error(conn, dataset_id, source_level, path, line_number, exc)
                errors += 1
    return imported, errors


def import_datasets(
    conn: sqlite3.Connection,
    dataset_name: str,
    hla_path: Optional[str] = None,
    lla_path: Optional[str] = None,
    source: str = "public_baseline",
) -> ImportSummary:
    initialize_database(conn)
    dataset_id = get_or_create_dataset(conn, dataset_name, source=source)

    hla_records = 0
    lla_records = 0
    errors = 0

    with conn:
        if hla_path:
            hla_records, hla_errors = import_jsonl_file(conn, dataset_id, hla_path, "high")
            errors += hla_errors
        if lla_path:
            lla_records, lla_errors = import_jsonl_file(conn, dataset_id, lla_path, "low")
            errors += lla_errors

    return ImportSummary(
        dataset_name=dataset_name,
        hla_records=hla_records,
        lla_records=lla_records,
        errors=errors,
    )
