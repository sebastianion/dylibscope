from __future__ import annotations

import math

from dylibscope.security_analysis.profiles.low_level_analysis import (
    ALL_METRICS,
    MIN_COMMON,
    MIN_LIBS_FOR_VERSION,
    MIN_OVERLAP,
    RISK_METRICS,
    THR_ALLOC,
    THR_BOUNDARY,
    THR_CFG,
    THR_RAW_RISK,
    WEIGHTS,
    TrendReportRow,
    classify,
    format_lla_report,
    format_lla_row,
    format_optional_float,
    format_optional_int,
    format_optional_percent,
    raw_risk_lib,
)
from dylibscope.config.datasets import LLA_INPUT


def test_lla_constants_preserve_expected_values():
    assert RISK_METRICS == [
        "cfg_edge_count",
        "allocation_call_count",
        "mach_port_function_count",
        "syscall_function_count",
    ]
    assert ALL_METRICS == RISK_METRICS + [
        "internal_function_count",
        "internal_variable_count",
    ]
    assert WEIGHTS == {
        "cfg_edge_count": 0.50,
        "allocation_call_count": 0.25,
        "mach_port_function_count": 0.15,
        "syscall_function_count": 0.10,
    }
    assert MIN_LIBS_FOR_VERSION == 150
    assert MIN_COMMON == 150
    assert MIN_OVERLAP == 0.60
    assert THR_RAW_RISK == 0.03
    assert THR_CFG == 0.05
    assert THR_ALLOC == 0.05
    assert THR_BOUNDARY == 0.05
    assert LLA_INPUT.name == "merged.json"


def test_raw_risk_lib_uses_expected_weighted_log_formula():
    result = raw_risk_lib(cfg=100, alloc=20, mach=5, syscall=2)

    expected = (
        WEIGHTS["cfg_edge_count"] * math.log1p(100)
        + WEIGHTS["allocation_call_count"] * math.log1p(20)
        + WEIGHTS["mach_port_function_count"] * math.log1p(5)
        + WEIGHTS["syscall_function_count"] * math.log1p(2)
    )

    assert result == expected


def test_raw_risk_lib_clamps_negative_values_to_zero():
    assert raw_risk_lib(cfg=-100, alloc=-20, mach=-5, syscall=-2) == 0.0


def test_classify_returns_stable_when_no_threshold_is_reached():
    assert classify(0.0, 0.0, 0.0, 0.0) == "stable"


def test_classify_returns_expanding_when_raw_risk_and_cfg_increase():
    assert classify(0.04, 0.06, 0.0, 0.0) == "expanding"


def test_classify_returns_expanding_when_raw_risk_and_alloc_increase():
    assert classify(0.04, 0.0, 0.06, 0.0) == "expanding"


def test_classify_returns_expanding_when_raw_risk_and_boundary_increase():
    assert classify(0.04, 0.0, 0.0, 0.06) == "expanding"


def test_classify_returns_hardening_when_raw_risk_and_cfg_decrease():
    assert classify(-0.04, -0.06, 0.0, 0.0) == "hardening"


def test_classify_returns_hardening_when_raw_risk_and_alloc_decrease():
    assert classify(-0.04, 0.0, -0.06, 0.0) == "hardening"


def test_classify_returns_hardening_when_raw_risk_and_boundary_decrease():
    assert classify(-0.04, 0.0, 0.0, -0.06) == "hardening"


def test_classify_does_not_expand_without_raw_risk_threshold():
    assert classify(0.0, 0.06, 0.06, 0.06) == "stable"


def test_classify_does_not_harden_without_raw_risk_threshold():
    assert classify(0.0, -0.06, -0.06, -0.06) == "stable"


def test_format_optional_int_formats_none_as_dash():
    assert format_optional_int(None) == "-"


def test_format_optional_int_formats_value_with_width():
    assert format_optional_int(12) == "    12"


def test_format_optional_float_formats_none_as_dash():
    assert format_optional_float(None) == "-"


def test_format_optional_float_formats_value_with_default_precision():
    assert format_optional_float(0.12345) == "  0.123"


def test_format_optional_percent_formats_none_as_dash():
    assert format_optional_percent(None) == "-"


def test_format_optional_percent_formats_value_as_percentage():
    assert format_optional_percent(0.12345) == "  12.35"


def test_format_lla_row_formats_complete_row():
    row = TrendReportRow(
        ios_version="iOS 9.0",
        version_risk=0.123456,
        data_quality="ok",
        release_label="expanding",
        common=200,
        overlap=0.75,
        delta_raw=0.10,
        delta_cfg=0.20,
        delta_alloc=-0.05,
        delta_boundary=0.0,
        libs=250,
        boundary_total=500,
    )

    formatted = format_lla_row(row)

    assert "iOS 9.0" in formatted
    assert "0.123456" in formatted
    assert "ok" in formatted
    assert "expanding" in formatted
    assert "200" in formatted
    assert "0.750" in formatted
    assert "10.00" in formatted
    assert "20.00" in formatted
    assert "-5.00" in formatted
    assert "250" in formatted
    assert "500" in formatted


def test_format_lla_row_formats_missing_transition_values_as_dashes():
    row = TrendReportRow(
        ios_version="iOS 6.0",
        version_risk=0.111111,
        data_quality="ok",
        release_label="n/a",
        common=None,
        overlap=None,
        delta_raw=None,
        delta_cfg=None,
        delta_alloc=None,
        delta_boundary=None,
        libs=194,
        boundary_total=519,
    )

    formatted = format_lla_row(row)

    assert "iOS 6.0" in formatted
    assert "n/a" in formatted
    assert "-" in formatted
    assert "194" in formatted
    assert "519" in formatted


def test_format_lla_report_contains_header_separator_and_rows():
    rows = [
        TrendReportRow(
            ios_version="iOS 6.0",
            version_risk=0.111111,
            data_quality="ok",
            release_label="n/a",
            common=None,
            overlap=None,
            delta_raw=None,
            delta_cfg=None,
            delta_alloc=None,
            delta_boundary=None,
            libs=194,
            boundary_total=519,
        ),
        TrendReportRow(
            ios_version="iOS 9.0",
            version_risk=0.222222,
            data_quality="ok",
            release_label="expanding",
            common=180,
            overlap=0.8,
            delta_raw=0.1,
            delta_cfg=0.2,
            delta_alloc=0.3,
            delta_boundary=0.4,
            libs=250,
            boundary_total=600,
        ),
    ]

    report = format_lla_report(rows)

    assert "iOS_VERSION" in report
    assert "VERSION_RISK" in report
    assert "RELEASE_LABEL" in report
    assert "BOUNDARY" in report
    assert "iOS 6.0" in report
    assert "iOS 9.0" in report
    assert "expanding" in report
    assert report.count("\n") >= 3