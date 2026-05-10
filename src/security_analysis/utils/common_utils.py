from __future__ import annotations

import json
from typing import List

import pandas as pd


VERSION_MAP = {
    "iPhone11,8_12.0_16A366": "iOS 12.0",
    "iPhone_4.0_64bit_10.0.1_14A403": "iOS 10.0.1",
    "iPhone_4.0_64bit_10.1_14B72": "iOS 10.1",
    "iPhone_4.0_64bit_10.2_14C92": "iOS 10.2",
    "iPhone_4.0_64bit_10.3.3_14G60": "iOS 10.3.3",
    "iPhone_4.0_64bit_10.3_14E277": "iOS 10.3",
    "iPhone_4.0_64bit_11.1.2_15B202": "iOS 11.1.2",
    "iPhone_4.0_64bit_11.2.5_15D60": "iOS 11.2.5",
    "iPhone5,1_6.0_10A405": "iOS 6.0",
    "iPhone5,1_7.0_11A465": "iOS 7.0",
    "iPhone5,1_8.0_12A365": "iOS 8.0",
    "iPhone5,1_8.1_12B411": "iOS 8.1",
    "iPhone5,1_8.3_12F70": "iOS 8.3",
    "iPhone5,1_8.4_12H143": "iOS 8.4",
    "iPhone5,1_9.0_13A344": "iOS 9.0",
    "iPhone5,1_9.1_13B143": "iOS 9.1",
    "iPhone5,1_9.2_13C75": "iOS 9.2",
    "iPhone5,1_9.3_13E237": "iOS 9.3",
    "iPhone6,2_11.0.0_15A372": "iOS 11.0",
}

VERSION_ORDER = [
    "iOS 6.0", "iOS 7.0", "iOS 8.0", "iOS 8.1",
    "iOS 8.3", "iOS 8.4", "iOS 9.0", "iOS 9.1",
    "iOS 9.2", "iOS 9.3", "iOS 10.0.1",
    "iOS 10.1", "iOS 10.2", "iOS 10.3", "iOS 10.3.3",
    "iOS 11.0", "iOS 11.1.2", "iOS 11.2.5", "iOS 12.0"
]


def load_jsonl(path: str) -> pd.DataFrame:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return pd.DataFrame(rows)


def pick_col(df: pd.DataFrame, candidates: List[str]) -> str:
    cols = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in cols:
            return cols[cand.lower()]
    raise ValueError(f"Missing expected column. Tried {candidates}. Available: {list(df.columns)}")


def normalize_version_label(raw: str) -> str:
    raw = str(raw).strip()
    return VERSION_MAP.get(raw, raw).strip()


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
