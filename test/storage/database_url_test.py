from __future__ import annotations

from pathlib import Path

from dylibscope.api.config import resolve_database_url
from dylibscope.storage.schema import connect, initialize_database


def test_resolve_database_url_from_sqlite_path(tmp_path: Path) -> None:
    db_path = tmp_path / "dylibscope.sqlite"
    assert resolve_database_url(db_path=db_path).startswith("sqlite+pysqlite:///")


def test_initialize_database_with_sqlalchemy_connection(tmp_path: Path) -> None:
    db_path = tmp_path / "dylibscope.sqlite"
    conn = connect(str(db_path))
    try:
        initialize_database(conn)
        count = conn.exec_driver_sql("SELECT COUNT(*) FROM metric_definitions").scalar_one()
    finally:
        conn.close()

    assert count >= 1
