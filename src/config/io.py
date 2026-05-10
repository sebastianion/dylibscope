from __future__ import annotations

import json
from pathlib import Path

import pandas as pd


def load_jsonl(path: str | Path) -> pd.DataFrame:
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Input JSONL file not found: {path}")

    rows = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number} in {path}") from exc

    return pd.DataFrame(rows)