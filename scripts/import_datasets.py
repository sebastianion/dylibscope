from __future__ import annotations

import argparse
from pathlib import Path

from dylibscope.storage.importer import import_datasets
from dylibscope.storage.schema import connect


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import DylibScope JSONL datasets into SQLite.")
    parser.add_argument("--db", default="dylibscope.sqlite", help="Output SQLite database path.")
    parser.add_argument("--dataset-name", default="public-baseline", help="Logical dataset name.")
    parser.add_argument("--hla-input", help="Path to high-level JSONL dataset.")
    parser.add_argument("--lla-input", help="Path to low-level JSONL dataset.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.hla_input and not args.lla_input:
        raise SystemExit("Provide at least --hla-input or --lla-input.")

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = connect(str(db_path))
    try:
        summary = import_datasets(
            conn=conn,
            dataset_name=args.dataset_name,
            hla_path=args.hla_input,
            lla_path=args.lla_input,
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
