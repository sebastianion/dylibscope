from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

DEFAULT_DB_PATH = Path("data/dylibscope.sqlite")
ENV_DB_PATH = "DYLIBSCOPE_DB_PATH"


def resolve_db_path(db_path: Optional[Union[str, Path]] = None) -> Path:
    """Resolve the SQLite database path used by the API.

    Priority:
    1. explicit ``db_path`` argument, useful for tests;
    2. ``DYLIBSCOPE_DB_PATH`` environment variable;
    3. ``data/dylibscope.sqlite`` from the repository root.
    """
    if db_path is not None:
        return Path(db_path)
    env_value = os.getenv(ENV_DB_PATH)
    if env_value:
        return Path(env_value)
    return DEFAULT_DB_PATH
