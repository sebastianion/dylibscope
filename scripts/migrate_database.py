from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from dylibscope.storage.schema import connect, initialize_database


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply additive DylibScope database migrations.")
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help="SQLite database path. Omit when using DATABASE_URL or DYLIBSCOPE_DATABASE_URL.",
    )
    args = parser.parse_args()

    database: Optional[str]
    database = str(args.db) if args.db is not None else None

    conn = connect(database)
    try:
        initialize_database(conn)
    finally:
        conn.close()

    print("DylibScope database schema is up to date.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
