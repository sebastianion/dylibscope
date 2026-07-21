from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.engine import Connection

from dylibscope.storage.normalize import (
    canonical_library_name,
    display_library_name,
    ios_version_label,
    json_dumps_stable,
    normalize_hla_metrics,
    normalize_lla_metrics,
    original_path,
    parse_ios_version_label,
)
from dylibscope.storage.schema import (
    datasets,
    import_errors,
    initialize_database,
    ios_versions,
    libraries,
    library_observations,
    metric_definitions,
    metric_values,
)


@dataclass(frozen=True)
class ImportSummary:
    dataset_name: str
    hla_records: int = 0
    lla_records: int = 0
    errors: int = 0

    @property
    def total_records(self) -> int:
        return self.hla_records + self.lla_records


@dataclass
class ImportOptions:
    """Runtime controls for JSONL imports.

    Remote databases such as Supabase/Postgres are much slower when the importer is
    completely silent and commits only once at the end. These options keep the
    existing SQLite behavior simple while making production imports observable.
    """

    progress_every: int = 100
    commit_every: int = 500
    quiet: bool = False


@dataclass
class ImportState:
    conn: Connection
    options: ImportOptions = field(default_factory=ImportOptions)
    dataset_ids: Dict[str, int] = field(default_factory=dict)
    library_ids: Dict[str, int] = field(default_factory=dict)
    ios_version_ids: Dict[str, int] = field(default_factory=dict)
    observation_ids: Dict[Tuple[int, int, int], int] = field(default_factory=dict)
    metric_value_types: Dict[str, str] = field(default_factory=dict)
    processed_since_commit: int = 0
    started_at: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        self.metric_value_types = {
            str(row.name): str(row.value_type)
            for row in self.conn.execute(select(metric_definitions.c.name, metric_definitions.c.value_type))
        }

    def note_processed(self) -> None:
        self.processed_since_commit += 1
        if self.options.commit_every > 0 and self.processed_since_commit >= self.options.commit_every:
            self.conn.commit()
            self.processed_since_commit = 0

    def maybe_log_progress(self, source_level: str, imported: int, errors: int, path: str) -> None:
        if self.options.quiet or self.options.progress_every <= 0:
            return
        if imported == 0 or imported % self.options.progress_every != 0:
            return
        elapsed = max(time.monotonic() - self.started_at, 0.001)
        rate = imported / elapsed
        label = "HLA" if source_level == "high" else "LLA"
        print(
            f"[{label}] Imported {imported} records from {path} "
            f"({errors} errors, {rate:.1f} records/s)",
            file=sys.stderr,
            flush=True,
        )


def _scalar_id(row: Any) -> int:
    if row is None:
        raise RuntimeError("expected database row was not found")
    return int(row[0])


def _supports_returning(conn: Connection) -> bool:
    return bool(getattr(conn.dialect, "insert_returning", False))


def _insert_and_fetch_id(conn: Connection, table: Any, values: Dict[str, Any], lookup: Any) -> int:
    """Insert a row and return its integer id, supporting SQLite and Postgres."""
    if _supports_returning(conn):
        row = conn.execute(table.insert().values(**values).returning(table.c.id)).first()
        return _scalar_id(row)

    conn.execute(table.insert().values(**values))
    row = conn.execute(select(table.c.id).where(lookup)).first()
    return _scalar_id(row)


def _upsert_metric_value(conn: Connection, observation_id: int, metric_name: str, values: Dict[str, Any]) -> None:
    """Upsert a metric value using the current SQL dialect when possible.

    This avoids one SELECT per metric value, which is the main reason full imports
    feel like they hang against a remote Postgres database.
    """
    if conn.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert

        stmt = dialect_insert(metric_values).values(
            observation_id=observation_id,
            metric_name=metric_name,
            **values,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[metric_values.c.observation_id, metric_values.c.metric_name],
            set_=values,
        )
        conn.execute(stmt)
        return

    if conn.dialect.name == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as dialect_insert

        stmt = dialect_insert(metric_values).values(
            observation_id=observation_id,
            metric_name=metric_name,
            **values,
        )
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
        conn.execute(
            metric_values.insert().values(
                observation_id=observation_id,
                metric_name=metric_name,
                **values,
            )
        )


def get_or_create_dataset(state: ImportState, name: str, source: str = "public_baseline") -> int:
    if name in state.dataset_ids:
        return state.dataset_ids[name]

    conn = state.conn
    row = conn.execute(select(datasets.c.id).where(datasets.c.name == name)).first()
    if row:
        dataset_id = _scalar_id(row)
    else:
        dataset_id = _insert_and_fetch_id(
            conn,
            datasets,
            {"name": name, "source": source, "visibility": "public"},
            datasets.c.name == name,
        )
    state.dataset_ids[name] = dataset_id
    return dataset_id


def get_or_create_ios_version(state: ImportState, version_label: str) -> int:
    parsed = parse_ios_version_label(version_label)
    cache_key = parsed.version_label
    if cache_key in state.ios_version_ids:
        return state.ios_version_ids[cache_key]

    conn = state.conn
    row = conn.execute(select(ios_versions.c.id).where(ios_versions.c.version_label == parsed.version_label)).first()
    if row:
        ios_version_id = _scalar_id(row)
        update_values = {}
        if parsed.device_model is not None:
            update_values["device_model"] = parsed.device_model
        if parsed.ios_release is not None:
            update_values["ios_release"] = parsed.ios_release
        if parsed.build_number is not None:
            update_values["build_number"] = parsed.build_number
        if update_values:
            conn.execute(ios_versions.update().where(ios_versions.c.id == ios_version_id).values(**update_values))
    else:
        ios_version_id = _insert_and_fetch_id(
            conn,
            ios_versions,
            {
                "version_label": parsed.version_label,
                "device_model": parsed.device_model,
                "ios_release": parsed.ios_release,
                "build_number": parsed.build_number,
            },
            ios_versions.c.version_label == parsed.version_label,
        )
    state.ios_version_ids[cache_key] = ios_version_id
    return ios_version_id


def get_or_create_library(state: ImportState, canonical_name: str, display_name: str) -> int:
    if canonical_name in state.library_ids:
        return state.library_ids[canonical_name]

    conn = state.conn
    row = conn.execute(select(libraries.c.id).where(libraries.c.canonical_name == canonical_name)).first()
    if row:
        library_id = _scalar_id(row)
    else:
        library_id = _insert_and_fetch_id(
            conn,
            libraries,
            {"canonical_name": canonical_name, "display_name": display_name},
            libraries.c.canonical_name == canonical_name,
        )
    state.library_ids[canonical_name] = library_id
    return library_id


def get_or_create_observation(
    state: ImportState,
    dataset_id: int,
    library_id: int,
    ios_version_id: int,
    path: Optional[str],
    source_level: str,
) -> int:
    cache_key = (dataset_id, library_id, ios_version_id)
    hla_seen = 1 if source_level == "high" else 0
    lla_seen = 1 if source_level == "low" else 0

    conn = state.conn
    if cache_key in state.observation_ids:
        observation_id = state.observation_ids[cache_key]
        update_values = {
            "hla_source_seen": hla_seen if source_level == "high" else 0,
            "lla_source_seen": lla_seen if source_level == "low" else 0,
        }
        # Preserve previously seen source flags by setting only the active source flag.
        active_values = {k: v for k, v in update_values.items() if v == 1}
        if path:
            active_values["original_path"] = path
        if active_values:
            conn.execute(library_observations.update().where(library_observations.c.id == observation_id).values(**active_values))
        return observation_id

    row = conn.execute(
        select(library_observations.c.id, library_observations.c.hla_source_seen, library_observations.c.lla_source_seen).where(
            library_observations.c.dataset_id == dataset_id,
            library_observations.c.library_id == library_id,
            library_observations.c.ios_version_id == ios_version_id,
        )
    ).first()

    if row:
        observation_id = _scalar_id(row)
        update_values = {
            "hla_source_seen": max(int(row.hla_source_seen), hla_seen),
            "lla_source_seen": max(int(row.lla_source_seen), lla_seen),
        }
        if path:
            update_values["original_path"] = path
        conn.execute(library_observations.update().where(library_observations.c.id == observation_id).values(**update_values))
    else:
        observation_id = _insert_and_fetch_id(
            conn,
            library_observations,
            {
                "dataset_id": dataset_id,
                "library_id": library_id,
                "ios_version_id": ios_version_id,
                "original_path": path,
                "hla_source_seen": hla_seen,
                "lla_source_seen": lla_seen,
            },
            (
                (library_observations.c.dataset_id == dataset_id)
                & (library_observations.c.library_id == library_id)
                & (library_observations.c.ios_version_id == ios_version_id)
            ),
        )
    state.observation_ids[cache_key] = observation_id
    return observation_id


def upsert_metric(state: ImportState, observation_id: int, metric_name: str, value: Any) -> None:
    value_type = state.metric_value_types.get(metric_name)
    if value_type is None:
        raise ValueError(f"unknown metric: {metric_name}")

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

    _upsert_metric_value(
        state.conn,
        observation_id,
        metric_name,
        {
            "numeric_value": numeric_value,
            "text_value": text_value,
            "json_value": json_value,
        },
    )


def import_record(state: ImportState, dataset_id: int, record: Dict[str, Any], source_level: str) -> None:
    canonical_name = canonical_library_name(record)
    display_name = display_library_name(record)
    version_label = ios_version_label(record)

    library_id = get_or_create_library(state, canonical_name, display_name)
    ios_version_id = get_or_create_ios_version(state, version_label)
    observation_id = get_or_create_observation(
        state=state,
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
        upsert_metric(state, observation_id, metric_name, value)


def log_import_error(
    conn: Connection,
    dataset_id: int,
    source_level: str,
    source_path: str,
    line_number: Optional[int],
    error: Exception,
) -> None:
    conn.execute(
        import_errors.insert().values(
            dataset_id=dataset_id,
            source_level=source_level,
            source_path=source_path,
            line_number=line_number,
            error_message=str(error),
        )
    )


def import_jsonl_file(state: ImportState, dataset_id: int, path: str, source_level: str) -> tuple[int, int]:
    imported = 0
    errors = 0

    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
                import_record(state, dataset_id, record, source_level)
                imported += 1
                state.note_processed()
                state.maybe_log_progress(source_level, imported, errors, path)
            except Exception as exc:  # noqa: BLE001 - importer should continue collecting bad records
                log_import_error(state.conn, dataset_id, source_level, path, line_number, exc)
                errors += 1
                state.note_processed()

    return imported, errors


def import_datasets(
    conn: Connection,
    dataset_name: str,
    hla_path: Optional[str] = None,
    lla_path: Optional[str] = None,
    source: str = "public_baseline",
    progress_every: int = 100,
    commit_every: int = 500,
    quiet: bool = False,
) -> ImportSummary:
    initialize_database(conn)
    state = ImportState(
        conn=conn,
        options=ImportOptions(progress_every=progress_every, commit_every=commit_every, quiet=quiet),
    )
    dataset_id = get_or_create_dataset(state, dataset_name, source=source)

    hla_records = 0
    lla_records = 0
    errors = 0

    if hla_path:
        hla_records, hla_errors = import_jsonl_file(state, dataset_id, hla_path, "high")
        errors += hla_errors
    if lla_path:
        lla_records, lla_errors = import_jsonl_file(state, dataset_id, lla_path, "low")
        errors += lla_errors

    conn.commit()

    return ImportSummary(
        dataset_name=dataset_name,
        hla_records=hla_records,
        lla_records=lla_records,
        errors=errors,
    )
