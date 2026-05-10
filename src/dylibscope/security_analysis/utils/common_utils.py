from __future__ import annotations

import json
from typing import List
import pandas as pd


def pick_col(df: pd.DataFrame, candidates: List[str]) -> str:
    cols = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in cols:
            return cols[cand.lower()]
    raise ValueError(f"Missing expected column. Tried {candidates}. Available: {list(df.columns)}")


def lib_base(name: str) -> str:
    s = str(name)
    return s.split("/")[-1].strip()


def to_int(x) -> int:
    try:
        return int(x)
    except Exception:
        try:
            return int(float(x))
        except Exception:
            return 0


def count_semicolon_list(s: str) -> int:
    if s is None:
        return 0
    s = str(s).strip()
    if not s:
        return 0
    return len([p for p in s.split(";") if p.strip() != ""])


def norm01(series: pd.Series) -> pd.Series:
    mn, mx = series.min(), series.max()
    if mx == mn:
        return pd.Series([0.0] * len(series), index=series.index)
    return (series - mn) / (mx - mn)


def pct_change(prev: float, cur: float) -> float:
    if prev == 0:
        return 0.0 if cur == 0 else 1.0
    return (cur - prev) / abs(prev)


def table_print(header: str, rows: List[str]) -> None:
    print(header)
    print("-" * len(header))
    for line in rows:
        print(line)
