from __future__ import annotations

import argparse
from pathlib import Path

from dylibscope.api.config import resolve_database_url
from dylibscope.storage.importer import import_datasets
from dylibscope.storage.schema import connect


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import DylibScope JSONL datasets into SQLite or Postgres.")
    parser.add_argument(
        "--db",
        default=None,
        help="Local SQLite database path. Ignored when --database-url or DATABASE_URL is provided.",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="SQLAlchemy database URL, for example postgresql+psycopg://... or sqlite+pysqlite:///data/dylibscope.sqlite.",
    )
    parser.add_argument("--dataset-name", default="public-baseline", help="Logical dataset name.")
    parser.add_argument("--hla-input", help="Path to high-level JSONL dataset.")
    parser.add_argument("--lla-input", help="Path to low-level JSONL dataset.")
    parser.add_argument(
        "--progress-every",
        type=int,
        default=100,
        help="Print import progress every N successfully imported records per source file. Use 0 to disable.",
    )
    parser.add_argument(
        "--commit-every",
        type=int,
        default=500,
        help="Commit every N processed records. Use 0 to commit only once at the end.",
    )
    parser.add_argument("--quiet", action="store_true", help="Disable progress logging.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.hla_input and not args.lla_input:
        raise SystemExit("Provide at least --hla-input or --lla-input.")

    if args.db:
        db_path = Path(args.db)
        db_path.parent.mkdir(parents=True, exist_ok=True)

    database_url = resolve_database_url(db_path=args.db, database_url=args.database_url)
    conn = connect(database_url)
    try:
        summary = import_datasets(
            conn=conn,
            dataset_name=args.dataset_name,
            hla_path=args.hla_input,
            lla_path=args.lla_input,
            progress_every=args.progress_every,
            commit_every=args.commit_every,
            quiet=args.quiet,
        )
    finally:
        conn.close()

    print(
        "Imported dataset '{name}': {hla} HLA records, {lla} LLA records, {errors} errors.".format(
            name=summary.dataset_name,
            hla=summary.hla_records,
            lla=summary.lla_records,
            errors=summary.errors,
        )
    )


if __name__ == "__main__":
    main()
