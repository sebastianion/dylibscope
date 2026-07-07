from __future__ import annotations

import argparse

import uvicorn

from dylibscope.api.app import create_app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the DylibScope API.")
    parser.add_argument("--db", default=None, help="Path to the normalized SQLite database.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind.")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind.")
    parser.add_argument("--reload", action="store_true", help="Enable uvicorn reload mode.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.reload:
        if args.db:
            raise SystemExit("--reload with --db is not supported. Use DYLIBSCOPE_DB_PATH instead.")
        uvicorn.run("dylibscope.api.app:app", host=args.host, port=args.port, reload=True)
        return

    uvicorn.run(create_app(db_path=args.db), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
