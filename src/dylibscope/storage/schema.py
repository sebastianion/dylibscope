from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 2

CREATE_TABLES_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS datasets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'public',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ios_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_label TEXT NOT NULL UNIQUE,
    device_model TEXT,
    ios_release TEXT,
    build_number TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS libraries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS library_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id INTEGER NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    library_id INTEGER NOT NULL REFERENCES libraries(id) ON DELETE CASCADE,
    ios_version_id INTEGER NOT NULL REFERENCES ios_versions(id) ON DELETE CASCADE,
    original_path TEXT,
    hla_source_seen INTEGER NOT NULL DEFAULT 0,
    lla_source_seen INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(dataset_id, library_id, ios_version_id)
);

CREATE TABLE IF NOT EXISTS metric_definitions (
    name TEXT PRIMARY KEY,
    level TEXT NOT NULL,
    value_type TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metric_values (
    observation_id INTEGER NOT NULL REFERENCES library_observations(id) ON DELETE CASCADE,
    metric_name TEXT NOT NULL REFERENCES metric_definitions(name) ON DELETE CASCADE,
    numeric_value REAL,
    text_value TEXT,
    json_value TEXT,
    PRIMARY KEY (observation_id, metric_name)
);

CREATE TABLE IF NOT EXISTS import_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id INTEGER REFERENCES datasets(id) ON DELETE CASCADE,
    source_level TEXT NOT NULL,
    source_path TEXT NOT NULL,
    line_number INTEGER,
    error_message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ios_versions_label ON ios_versions(version_label);
CREATE INDEX IF NOT EXISTS idx_ios_versions_release ON ios_versions(ios_release);
CREATE INDEX IF NOT EXISTS idx_ios_versions_build ON ios_versions(build_number);
CREATE INDEX IF NOT EXISTS idx_observations_dataset ON library_observations(dataset_id);
CREATE INDEX IF NOT EXISTS idx_observations_library ON library_observations(library_id);
CREATE INDEX IF NOT EXISTS idx_observations_ios_version ON library_observations(ios_version_id);
CREATE INDEX IF NOT EXISTS idx_metric_values_metric ON metric_values(metric_name);
CREATE INDEX IF NOT EXISTS idx_metric_values_numeric ON metric_values(metric_name, numeric_value);
"""

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


def connect(db_path: str) -> sqlite3.Connection:
    """Open a SQLite connection with foreign keys enabled."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database(conn: sqlite3.Connection) -> None:
    """Create schema tables and insert metric definitions."""
    conn.executescript(CREATE_TABLES_SQL)
    conn.execute(
        "INSERT OR REPLACE INTO schema_metadata(key, value) VALUES (?, ?)",
        ("schema_version", str(SCHEMA_VERSION)),
    )
    conn.executemany(
        """
        INSERT OR REPLACE INTO metric_definitions(name, level, value_type, description)
        VALUES (?, ?, ?, ?)
        """,
        METRIC_DEFINITIONS,
    )
    conn.commit()
