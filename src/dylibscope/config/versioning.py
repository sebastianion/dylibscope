from __future__ import annotations

import pandas as pd
from pandas import DataFrame
from dylibscope.config.ios_versions import VERSION_MAP, VERSION_ORDER, IOS_VERSION


def normalize_version_label(raw: str) -> str:
    raw = str(raw).strip()
    return VERSION_MAP.get(raw, raw).strip()


def normalize_ios_versions(df: DataFrame) -> DataFrame:
    df = df.copy()
    df[IOS_VERSION] = df[IOS_VERSION].map(normalize_version_label)
    df[IOS_VERSION] = pd.Categorical(df[IOS_VERSION], categories=VERSION_ORDER, ordered=True)
    return df