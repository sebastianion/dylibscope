from __future__ import annotations

import os
from pathlib import Path
from threading import RLock
from typing import Dict, Optional, Union

from sqlalchemy import (
    Column,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    func,
    inspect,
    select,
)
from sqlalchemy.engine import Connection, Engine, make_url
from sqlalchemy.exc import IntegrityError

SCHEMA_VERSION = 4
DEFAULT_SQLITE_PATH = Path("data/dylibscope.sqlite")

metadata = MetaData()

schema_metadata = Table(
    "schema_metadata",
    metadata,
    Column("key", String, primary_key=True),
    Column("value", Text, nullable=False),
)

datasets = Table(
    "datasets",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False, unique=True),
    Column("source", String, nullable=False),
    Column("visibility", String, nullable=False, server_default="public"),
    Column("owner_user_id", String),
    Column("source_type", String, nullable=False, server_default="public_baseline"),
    Column("trust_level", String, nullable=False, server_default="verified_pipeline_output"),
    Column("created_at", String, nullable=False, server_default=func.current_timestamp()),
)

ios_versions = Table(
    "ios_versions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("version_label", String, nullable=False, unique=True),
    Column("device_model", String),
    Column("ios_release", String),
    Column("build_number", String),
    Column("created_at", String, nullable=False, server_default=func.current_timestamp()),
)

libraries = Table(
    "libraries",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("canonical_name", String, nullable=False, unique=True),
    Column("display_name", String, nullable=False),
    Column("created_at", String, nullable=False, server_default=func.current_timestamp()),
)

library_observations = Table(
    "library_observations",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("dataset_id", Integer, ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False),
    Column("library_id", Integer, ForeignKey("libraries.id", ondelete="CASCADE"), nullable=False),
    Column("ios_version_id", Integer, ForeignKey("ios_versions.id", ondelete="CASCADE"), nullable=False),
    Column("original_path", Text),
    Column("hla_source_seen", Integer, nullable=False, server_default="0"),
    Column("lla_source_seen", Integer, nullable=False, server_default="0"),
    Column("created_at", String, nullable=False, server_default=func.current_timestamp()),
    Column("updated_at", String, nullable=False, server_default=func.current_timestamp()),
    UniqueConstraint("dataset_id", "library_id", "ios_version_id", name="uq_observation_identity"),
)

metric_definitions = Table(
    "metric_definitions",
    metadata,
    Column("name", String, primary_key=True),
    Column("level", String, nullable=False),
    Column("value_type", String, nullable=False),
    Column("description", Text, nullable=False),
)

metric_values = Table(
    "metric_values",
    metadata,
    Column(
        "observation_id",
        Integer,
        ForeignKey("library_observations.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("metric_name", String, ForeignKey("metric_definitions.name", ondelete="CASCADE"), primary_key=True),
    Column("numeric_value", Float),
    Column("text_value", Text),
    Column("json_value", Text),
)

import_errors = Table(
    "import_errors",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("dataset_id", Integer, ForeignKey("datasets.id", ondelete="CASCADE")),
    Column("source_level", String, nullable=False),
    Column("source_path", Text, nullable=False),
    Column("line_number", Integer),
    Column("error_message", Text, nullable=False),
    Column("created_at", String, nullable=False, server_default=func.current_timestamp()),
)

METRIC_DEFINITIONS = [
    ("deployment_target", "high", "text", "Minimum deployment target extracted from Mach-O load commands."),
    ("num_sections", "high", "numeric", "Number of Mach-O sections."),
    ("num_symbols", "high", "numeric", "Number of Mach-O symbols."),
    ("exported_function_count", "high", "numeric", "Number of exported function symbols."),
    ("imported_function_count", "high", "numeric", "Number of imported function symbols."),
    ("exported_functions", "high", "json", "Exported function names."),
    ("imported_functions", "high", "json", "Imported function names."),
    ("cfg_edge_count", "low", "numeric", "Total control-flow graph edge count."),
    ("internal_function_count", "low", "numeric", "Number of internal functions found by Ghidra."),
    ("internal_variable_count", "low", "numeric", "Number of internal variables found by Ghidra."),
    ("allocation_call_count", "low", "numeric", "Number of allocation-related calls."),
    ("syscall_function_count", "low", "numeric", "Number of functions containing syscall-like SVC instructions."),
    ("mach_port_function_count", "low", "numeric", "Number of functions calling Mach message or Mach port APIs."),
]


def is_database_url(value: str) -> bool:
    return "://" in value


def sqlite_url_from_path(db_path: Union[str, Path]) -> str:
    path = Path(db_path)
    if str(path) == ":memory:":
        return "sqlite+pysqlite:///:memory:"
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+pysqlite:///{path.as_posix()}"


def default_database_url() -> str:
    return sqlite_url_from_path(DEFAULT_SQLITE_PATH)


def normalize_database_url(database_url: str) -> str:
    """Normalize common Postgres URLs to the installed psycopg v3 driver."""
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+psycopg://", 1)
    return database_url


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return int(value)


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return float(value)


_ENGINE_CACHE: Dict[str, Engine] = {}
_ENGINE_CACHE_LOCK = RLock()


def _new_db_engine(resolved_url: str) -> Engine:
    url = make_url(resolved_url)

    if url.drivername.startswith("sqlite"):
        return create_engine(
            resolved_url,
            future=True,
            connect_args={"check_same_thread": False},
        )

    return create_engine(
        resolved_url,
        future=True,
        pool_pre_ping=True,
        pool_size=_int_env("DYLIBSCOPE_DB_POOL_SIZE", 3),
        max_overflow=_int_env("DYLIBSCOPE_DB_MAX_OVERFLOW", 0),
        pool_timeout=_float_env("DYLIBSCOPE_DB_POOL_TIMEOUT", 10.0),
        pool_recycle=_int_env("DYLIBSCOPE_DB_POOL_RECYCLE", 300),
    )


def create_db_engine(database_url: Optional[str] = None) -> Engine:
    resolved_url = normalize_database_url(database_url or default_database_url())
    with _ENGINE_CACHE_LOCK:
        engine = _ENGINE_CACHE.get(resolved_url)
        if engine is None:
            engine = _new_db_engine(resolved_url)
            _ENGINE_CACHE[resolved_url] = engine
        return engine


def dispose_cached_engines() -> None:
    """Dispose all cached engines. Mostly useful for tests and local diagnostics."""
    with _ENGINE_CACHE_LOCK:
        engines = list(_ENGINE_CACHE.values())
        _ENGINE_CACHE.clear()
    for engine in engines:
        engine.dispose()


def connect(database: Optional[Union[str, Path]] = None) -> Connection:
    """Open a database connection.

    Backward compatibility:
    - ``connect("data/dylibscope.sqlite")`` still opens a SQLite database.
    - ``connect("postgresql+psycopg://...")`` opens an external database.
    - ``connect()`` uses ``DATABASE_URL`` when set, otherwise local SQLite.
    """
    if database is None:
        database_url = os.getenv("DATABASE_URL") or os.getenv("DYLIBSCOPE_DATABASE_URL") or default_database_url()
    else:
        text_value = str(database)
        database_url = text_value if is_database_url(text_value) else sqlite_url_from_path(text_value)

    database_url = normalize_database_url(database_url)
    engine = create_db_engine(database_url)
    conn = engine.connect()
    if conn.dialect.name == "sqlite":
        conn.exec_driver_sql("PRAGMA foreign_keys = ON")
    return conn


def initialize_database(conn: Connection) -> None:
    """Create schema tables, migrate additive columns, and insert metric definitions."""
    metadata.create_all(conn)
    _ensure_dataset_provenance_columns(conn)

    _upsert_schema_metadata(conn, "schema_version", str(SCHEMA_VERSION))
    for name, level, value_type, description in METRIC_DEFINITIONS:
        _upsert_metric_definition(conn, name, level, value_type, description)
    conn.commit()


def _quote_identifier(conn: Connection, name: str) -> str:
    return conn.dialect.identifier_preparer.quote(name)


def _column_exists(conn: Connection, table_name: str, column_name: str) -> bool:
    return any(column["name"] == column_name for column in inspect(conn).get_columns(table_name))


def _add_column_if_missing(conn: Connection, table_name: str, column_name: str, definition: str) -> None:
    if _column_exists(conn, table_name, column_name):
        return
    conn.exec_driver_sql(
        f"ALTER TABLE {_quote_identifier(conn, table_name)} "
        f"ADD COLUMN {_quote_identifier(conn, column_name)} {definition}"
    )


def _ensure_dataset_provenance_columns(conn: Connection) -> None:
    """Apply additive dataset ownership/provenance columns to existing databases."""
    _add_column_if_missing(conn, "datasets", "owner_user_id", "VARCHAR")
    _add_column_if_missing(conn, "datasets", "source_type", "VARCHAR")
    _add_column_if_missing(conn, "datasets", "trust_level", "VARCHAR")

    conn.execute(
        datasets.update()
        .where(datasets.c.source_type.is_(None))
        .values(source_type="public_baseline")
    )
    conn.execute(
        datasets.update()
        .where(datasets.c.trust_level.is_(None))
        .values(trust_level="verified_pipeline_output")
    )


def _upsert_schema_metadata(conn: Connection, key: str, value: str) -> None:
    existing = conn.execute(select(schema_metadata.c.key).where(schema_metadata.c.key == key)).first()
    if existing:
        conn.execute(schema_metadata.update().where(schema_metadata.c.key == key).values(value=value))
    else:
        conn.execute(schema_metadata.insert().values(key=key, value=value))


def _upsert_metric_definition(
    conn: Connection,
    name: str,
    level: str,
    value_type: str,
    description: str,
) -> None:
    existing = conn.execute(select(metric_definitions.c.name).where(metric_definitions.c.name == name)).first()
    values = {"level": level, "value_type": value_type, "description": description}
    if existing:
        conn.execute(metric_definitions.update().where(metric_definitions.c.name == name).values(**values))
    else:
        try:
            conn.execute(metric_definitions.insert().values(name=name, **values))
        except IntegrityError:
            conn.rollback()
            conn.execute(metric_definitions.update().where(metric_definitions.c.name == name).values(**values))
