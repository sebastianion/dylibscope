from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

from dylibscope.storage.schema import default_database_url, normalize_database_url, sqlite_url_from_path

DEFAULT_DB_PATH = Path("data/dylibscope.sqlite")
ENV_DATABASE_URL = "DATABASE_URL"
ENV_ALT_DATABASE_URL = "DYLIBSCOPE_DATABASE_URL"
ENV_DB_PATH = "DYLIBSCOPE_DB_PATH"


def resolve_db_path(db_path: Optional[Union[str, Path]] = None) -> Path:
    """Resolve the local SQLite database path used by older callers/tests."""
    if db_path is not None:
        return Path(db_path)
    env_value = os.getenv(ENV_DB_PATH)
    if env_value:
        return Path(env_value)
    return DEFAULT_DB_PATH


def resolve_database_url(
    db_path: Optional[Union[str, Path]] = None,
    database_url: Optional[str] = None,
) -> str:
    """Resolve the database URL used by the API/importer.

    Priority:
    1. explicit ``database_url`` argument;
    2. explicit ``db_path`` argument, converted to a SQLite URL;
    3. ``DATABASE_URL`` environment variable, used by Supabase/Render/Postgres;
    4. ``DYLIBSCOPE_DATABASE_URL`` environment variable;
    5. ``DYLIBSCOPE_DB_PATH`` environment variable, converted to a SQLite URL;
    6. local ``data/dylibscope.sqlite`` fallback.
    """
    if database_url:
        return normalize_database_url(database_url)
    if db_path is not None:
        return sqlite_url_from_path(db_path)

    env_database_url = os.getenv(ENV_DATABASE_URL) or os.getenv(ENV_ALT_DATABASE_URL)
    if env_database_url:
        return normalize_database_url(env_database_url)

    env_db_path = os.getenv(ENV_DB_PATH)
    if env_db_path:
        return sqlite_url_from_path(env_db_path)

    return default_database_url()
