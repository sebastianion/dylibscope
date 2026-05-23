from __future__ import annotations

import pandas as pd
import pytest

from dylibscope.security_analysis.utils.common_utils import (
    count_semicolon_list,
    lib_base,
    norm01,
    pct_change,
    pick_col,
    table_print,
    to_int,
)


def test_pick_col_finds_exact_column_name():
    df = pd.DataFrame(columns=["ios_version", "library"])

    assert pick_col(df, ["ios_version", "version"]) == "ios_version"


def test_pick_col_is_case_insensitive_and_returns_original_column_name():
    df = pd.DataFrame(columns=["IOS_VERSION", "Library"])

    assert pick_col(df, ["ios_version"]) == "IOS_VERSION"
    assert pick_col(df, ["library"]) == "Library"


def test_pick_col_uses_first_matching_candidate():
    df = pd.DataFrame(columns=["version", "ios_version"])

    assert pick_col(df, ["ios_version", "version"]) == "ios_version"


def test_pick_col_raises_when_no_candidate_matches():
    df = pd.DataFrame(columns=["library", "metric"])

    with pytest.raises(ValueError, match="Missing expected column"):
        pick_col(df, ["ios_version", "version"])


def test_lib_base_extracts_last_unix_path_component():
    assert lib_base("/usr/lib/libsqlite3.dylib") == "libsqlite3.dylib"


def test_lib_base_strips_whitespace():
    assert lib_base("  /usr/lib/libA.dylib  ") == "libA.dylib"


def test_lib_base_converts_non_string_input():
    assert lib_base(123) == "123"


def test_to_int_converts_integer_string():
    assert to_int("10") == 10


def test_to_int_converts_float_string_by_truncating():
    assert to_int("10.9") == 10


def test_to_int_converts_numeric_values():
    assert to_int(7) == 7
    assert to_int(7.8) == 7


def test_to_int_returns_zero_for_invalid_values():
    assert to_int("invalid") == 0
    assert to_int(None) == 0


def test_count_semicolon_list_counts_items():
    assert count_semicolon_list("a;b;c") == 3


def test_count_semicolon_list_ignores_empty_items():
    assert count_semicolon_list("a;;c;") == 2


def test_count_semicolon_list_handles_empty_and_none():
    assert count_semicolon_list("") == 0
    assert count_semicolon_list("   ") == 0
    assert count_semicolon_list(None) == 0


def test_count_semicolon_list_converts_non_string_input():
    assert count_semicolon_list(123) == 1


def test_norm01_scales_values_between_zero_and_one():
    result = norm01(pd.Series([10, 20, 30]))

    assert result.tolist() == [0.0, 0.5, 1.0]


def test_norm01_preserves_index():
    series = pd.Series([10, 20, 30], index=["a", "b", "c"])

    result = norm01(series)

    assert result.index.tolist() == ["a", "b", "c"]


def test_norm01_handles_constant_series():
    result = norm01(pd.Series([5, 5, 5]))

    assert result.tolist() == [0.0, 0.0, 0.0]


def test_pct_change_regular_increase_and_decrease():
    assert pct_change(100, 120) == 0.2
    assert pct_change(100, 80) == -0.2


def test_pct_change_uses_absolute_previous_value():
    assert pct_change(-100, -80) == 0.2
    assert pct_change(-100, -120) == -0.2


def test_pct_change_handles_zero_previous_value():
    assert pct_change(0, 0) == 0.0
    assert pct_change(0, 5) == 1.0


def test_table_print_outputs_header_separator_and_rows(capsys):
    table_print("Header", ["row 1", "row 2"])

    captured = capsys.readouterr()

    assert captured.out == "Header\n------\nrow 1\nrow 2\n"