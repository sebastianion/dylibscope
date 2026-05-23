from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from pandas import DataFrame


@dataclass(frozen=True)
class AnalysisConfig:
    metrics: dict[str, str]
    default_metric_label: str
    library_label: str
    title: str
    preprocess: Callable[[DataFrame], DataFrame] | None = None
