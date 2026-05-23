from __future__ import annotations

import math

from dylibscope.security_analysis.profiles.high_level_analysis import (
    HL_METRICS,
    MIN_COMMON,
    MIN_LIBS_FOR_VERSION,
    MIN_OVERLAP,
    THR_IMPS,
    THR_RAW_RISK,
    THR_SECS,
    THR_SYMS,
    W_RAW,
    W_TRIAGE,
    HlaTrendReportRow,
    classify,
    format_hla_report,
    format_hla_row,
    format_optional_float,
    format_optional_int,
    format_optional_percent,
    raw_risk_row,
)
from dylibscope.config.datasets import HLA_INPUT

def test_hla_constants_preserve_expected_values():
    assert HL_METRICS == ["num_symbols", "import_count", "num_sections"]
    assert W_RAW == {
        "num_symbols": 0.55,
        "import_count": 0.30,
        "num_sections": 0.15,
    }
    assert W_TRIAGE == W_RAW
    assert MIN_LIBS_FOR_VERSION == 150
    assert MIN_COMMON == 150
    assert MIN_OVERLAP == 0.60
    assert THR_RAW_RISK == 0.01
    assert THR_SYMS == 0.07
    assert THR_IMPS == 0.07
    assert THR_SECS == 0.07
    assert HLA_INPUT.name == "dylibs_analysis_local.json"


def test_raw_risk_row_uses_expected_weighted_log_formula():
    result = raw_risk_row(num_symbols=100, import_count=20, num_sections=5)

    expected = (
        W_RAW["num_symbols"] * math.log1p(100)
        + W_RAW["import_count"] * math.log1p(20)
        + W_RAW["num_sections"] * math.log1p(5)
    )

    assert result == expected


def test_raw_risk_row_clamps_negative_values_to_zero():
    assert raw_risk_row(-100, -20, -5) == 0.0


def test_classify_returns_stable_when_no_threshold_is_reached():
    assert classify(0.0, 0.0, 0.0, 0.0) == "stable"


def test_classify_returns_expanding_when_raw_risk_and_one_metric_increase():
    assert classify(0.02, 0.08, 0.0, 0.0) == "expanding"


def test_classify_returns_expanding_when_two_metrics_increase():
    assert classify(0.0, 0.08, 0.08, 0.0) == "expanding"


def test_classify_returns_hardening_when_raw_risk_and_one_metric_decrease():
    assert classify(-0.02, -0.08, 0.0, 0.0) == "hardening"


def test_classify_returns_hardening_when_two_metrics_decrease():
    assert classify(0.0, -0.08, -0.08, 0.0) == "hardening"


def test_classify_prioritizes_hardening_when_both_conditions_are_true():
    assert classify(0.02, -0.08, -0.08, 0.08) == "hardening"


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
    assert format_optional_percent(0.12345) == " 12.35"


def test_format_hla_row_formats_complete_row():
    row = HlaTrendReportRow(
        ios_version="iOS 9.0",
        version_risk=0.123456,
        data_quality="ok",
        release_label="expanding",
        common=200,
        overlap=0.75,
        delta_raw=0.10,
        delta_symbols=0.20,
        delta_imports=-0.05,
        delta_sections=0.0,
        libs=250,
    )

    formatted = format_hla_row(row)

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


def test_format_hla_row_formats_missing_transition_values_as_dashes():
    row = HlaTrendReportRow(
        ios_version="iOS 6.0",
        version_risk=0.111111,
        data_quality="ok",
        release_label="n/a",
        common=None,
        overlap=None,
        delta_raw=None,
        delta_symbols=None,
        delta_imports=None,
        delta_sections=None,
        libs=194,
    )

    formatted = format_hla_row(row)

    assert "iOS 6.0" in formatted
    assert "n/a" in formatted
    assert "-" in formatted
    assert "194" in formatted


def test_format_hla_report_contains_header_separator_and_rows():
    rows = [
        HlaTrendReportRow(
            ios_version="iOS 6.0",
            version_risk=0.111111,
            data_quality="ok",
            release_label="n/a",
            common=None,
            overlap=None,
            delta_raw=None,
            delta_symbols=None,
            delta_imports=None,
            delta_sections=None,
            libs=194,
        ),
        HlaTrendReportRow(
            ios_version="iOS 9.0",
            version_risk=0.222222,
            data_quality="ok",
            release_label="expanding",
            common=180,
            overlap=0.8,
            delta_raw=0.1,
            delta_symbols=0.2,
            delta_imports=0.3,
            delta_sections=0.4,
            libs=250,
        ),
    ]

    report = format_hla_report(rows)

    assert "iOS_VERSION" in report
    assert "VERSION_RISK" in report
    assert "RELEASE_LABEL" in report
    assert "iOS 6.0" in report
    assert "iOS 9.0" in report
    assert "expanding" in report
    assert report.count("\n") >= 3