from __future__ import annotations

import math
from dataclasses import dataclass

from dylibscope.config.paths import PACKAGE_DIR

HL_METRICS = ["num_symbols", "import_count", "num_sections"]

W_RAW = {
    "num_symbols": 0.55,
    "import_count": 0.30,
    "num_sections": 0.15,
}

W_TRIAGE = W_RAW.copy()

MIN_LIBS_FOR_VERSION = 150
MIN_COMMON = 150
MIN_OVERLAP = 0.60

THR_RAW_RISK = 0.01
THR_SYMS = 0.07
THR_IMPS = 0.07
THR_SECS = 0.07

DEFAULT_HLA_INPUT = PACKAGE_DIR / "high_level_analysis" / "dylibs_analysis_local.json"


@dataclass
class HlaTrendReportRow:
    ios_version: str
    version_risk: float
    data_quality: str
    release_label: str
    common: int | None
    overlap: float | None
    delta_raw: float | None
    delta_symbols: float | None
    delta_imports: float | None
    delta_sections: float | None
    libs: int


def raw_risk_row(num_symbols: float, import_count: float, num_sections: float) -> float:
    return (
        W_RAW["num_symbols"] * math.log1p(max(num_symbols, 0.0))
        + W_RAW["import_count"] * math.log1p(max(import_count, 0.0))
        + W_RAW["num_sections"] * math.log1p(max(num_sections, 0.0))
    )


def classify(d_raw: float, d_syms: float, d_imps: float, d_secs: float) -> str:
    up = sum([d_syms >= THR_SYMS, d_imps >= THR_IMPS, d_secs >= THR_SECS])
    down = sum([d_syms <= -THR_SYMS, d_imps <= -THR_IMPS, d_secs <= -THR_SECS])

    expanding_a = (d_raw >= THR_RAW_RISK) and (up >= 1)
    hardening_a = (d_raw <= -THR_RAW_RISK) and (down >= 1)

    expanding_b = up >= 2
    hardening_b = down >= 2

    if hardening_a or hardening_b:
        return "hardening"
    if expanding_a or expanding_b:
        return "expanding"
    return "stable"


def format_optional_int(value: int | None) -> str:
    return "-" if value is None else f"{value:>6}"


def format_optional_float(value: float | None, width: int = 7, precision: int = 3) -> str:
    return "-" if value is None else f"{value:>{width}.{precision}f}"


def format_optional_percent(value: float | None, width: int = 6) -> str:
    return "-" if value is None else f"{value * 100:>{width}.2f}"


def format_hla_row(row: HlaTrendReportRow) -> str:
    return (
        f"{row.ios_version:<12} "
        f"{row.version_risk:>12.6f}  "
        f"{row.data_quality:<12}  "
        f"{row.release_label:<20} "
        f"{format_optional_int(row.common):>6}  "
        f"{format_optional_float(row.overlap):>7}  "
        f"{format_optional_percent(row.delta_raw):>6}  "
        f"{format_optional_percent(row.delta_symbols):>6}  "
        f"{format_optional_percent(row.delta_imports):>6}  "
        f"{format_optional_percent(row.delta_sections):>6}  "
        f"{row.libs:>4}"
    )


def format_hla_report(rows: list[HlaTrendReportRow]) -> str:
    header = (
        "iOS_VERSION   VERSION_RISK  DATA_QUALITY  RELEASE_LABEL        "
        "COMMON  OVERLAP  ΔRAW%   ΔSYMS%  ΔIMPS%  ΔSECS%  LIBS"
    )

    lines = [header, "-" * len(header)]
    lines.extend(format_hla_row(row) for row in rows)

    return "\n".join(lines)
