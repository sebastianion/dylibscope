from __future__ import annotations

import argparse
import json

from dylibscope.storage.repository import get_library_metrics
from dylibscope.storage.schema import connect


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Query normalized DylibScope metrics.")
    parser.add_argument("library", help="Library name or path, e.g. libsqlite3.0.dylib")
    parser.add_argument("--db", default="data/dylibscope.sqlite", help="SQLite database path.")
    parser.add_argument("--dataset-name", default="public-baseline", help="Logical dataset name.")
    parser.add_argument("--ios-version", help="Full firmware label or release, e.g. iPhone11,8_12.0_16A366 or 12.0.")
    parser.add_argument("--level", choices=["high", "low", "all"], help="Metric level filter.")
    parser.add_argument(
        "--metric",
        action="append",
        dest="metrics",
        help="Metric name to return. Can be passed multiple times.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    conn = connect(args.db)
    try:
        result = get_library_metrics(
            conn=conn,
            library_name=args.library,
            dataset_name=args.dataset_name,
            ios_version=args.ios_version,
            level=args.level,
            metrics=args.metrics,
        )
    finally:
        conn.close()

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
