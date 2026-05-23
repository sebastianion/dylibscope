from __future__ import annotations

import math
from dataclasses import dataclass

RISK_METRICS = ["cfg_edge_count", "allocation_call_count", "mach_port_function_count", "syscall_function_count"]
ALL_METRICS = RISK_METRICS + ["internal_function_count", "internal_variable_count"]

WEIGHTS = {
    "cfg_edge_count": 0.50,
    "allocation_call_count": 0.25,
    "mach_port_function_count": 0.15,
    "syscall_function_count": 0.10,
}

MIN_LIBS_FOR_VERSION = 150
MIN_COMMON = 150
MIN_OVERLAP = 0.60

THR_RAW_RISK = 0.03
THR_CFG = 0.05
THR_ALLOC = 0.05
THR_BOUNDARY = 0.05


@dataclass
class TrendReportRow:
    ios_version: str
    version_risk: float
    data_quality: str
    release_label: str
    common: int | None
    overlap: float | None
    delta_raw: float | None
    delta_cfg: float | None
    delta_alloc: float | None
    delta_boundary: float | None
    libs: int
    boundary_total: int


def raw_risk_lib(cfg: float, alloc: float, mach: float, syscall: float) -> float:
    return (
        WEIGHTS["cfg_edge_count"] * math.log1p(max(cfg, 0.0))
        + WEIGHTS["allocation_call_count"] * math.log1p(max(alloc, 0.0))
        + WEIGHTS["mach_port_function_count"] * math.log1p(max(mach, 0.0))
        + WEIGHTS["syscall_function_count"] * math.log1p(max(syscall, 0.0))
    )


def classify(
    delta_raw_risk: float,
    delta_cfg: float,
    delta_alloc: float,
    delta_boundary: float,
) -> str:
    hardening = (delta_raw_risk <= -THR_RAW_RISK) and (
        delta_boundary <= -THR_BOUNDARY or delta_alloc <= -THR_ALLOC or delta_cfg <= -THR_CFG
    )

    expanding = (delta_raw_risk >= THR_RAW_RISK) and (
        delta_boundary >= THR_BOUNDARY or delta_alloc >= THR_ALLOC or delta_cfg >= THR_CFG
    )

    if hardening:
        return "hardening"
    if expanding:
        return "expanding"
    return "stable"


def format_optional_int(value: int | None) -> str:
    return "-" if value is None else f"{value:>6}"


def format_optional_float(value: float | None, width: int = 7, precision: int = 3) -> str:
    return "-" if value is None else f"{value:>{width}.{precision}f}"


def format_optional_percent(value: float | None, width: int = 7) -> str:
    return "-" if value is None else f"{value * 100:>{width}.2f}"


def format_lla_row(row: TrendReportRow) -> str:
    return (
        f"{row.ios_version:<12} "
        f"{row.version_risk:>12.6f}  "
        f"{row.data_quality:<12}  "
        f"{row.release_label:<20} "
        f"{format_optional_int(row.common):>6}  "
        f"{format_optional_float(row.overlap):>7}  "
        f"{format_optional_percent(row.delta_raw, width=6):>6}  "
        f"{format_optional_percent(row.delta_cfg, width=6):>6}  "
        f"{format_optional_percent(row.delta_alloc, width=7):>7}  "
        f"{format_optional_percent(row.delta_boundary, width=7):>7}  "
        f"{row.libs:>5}  "
        f"{row.boundary_total:>8}"
    )


def format_lla_report(rows: list[TrendReportRow]) -> str:
    header = (
        "iOS_VERSION   VERSION_RISK  DATA_QUALITY  RELEASE_LABEL        "
        "COMMON  OVERLAP  ΔRAW%   ΔCFG%   ΔALLOC%  ΔBOUND%  LIBS  BOUNDARY"
    )

    lines = [header, "-" * len(header)]
    lines.extend(format_lla_row(row) for row in rows)

    return "\n".join(lines)
