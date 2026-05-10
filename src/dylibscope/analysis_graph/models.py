from dataclasses import dataclass
from typing import Callable, Dict, Optional
from pandas import DataFrame

@dataclass(frozen=True)
class AnalysisConfig:
    metrics: Dict[str, str]
    default_metric_label: str
    library_label: str
    title: str
    preprocess: Optional[Callable[[DataFrame], DataFrame]] = None

@dataclass(frozen=True)
class SecurityProfile:
    name: str
    weights: Dict[str, float]
    security_lens: Dict[str, str]