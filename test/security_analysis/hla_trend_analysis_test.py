from __future__ import annotations

import json

import pytest

from dylibscope.config.ios_versions import IOS_VERSION
from dylibscope.security_analysis import hla_trend_analysis
from dylibscope.security_analysis.hla_trend_analysis import (
    build_hla_trend_rows,
    compute_version_tables,
    load_and_prepare_hla_data,
    run_hla_trend_analysis,
)


def write_jsonl(path, rows):
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n",
        encoding="utf-8",
    )


def make_hla_rows(version: str, count: int, symbol_base: int = 100, import_count: int = 3):
    return [
        {
            "file": f"lib{i}.dylib",
            "ios_version": version,
            "num_sections": 5,
            "num_symbols": symbol_base + i,
            "imported_functions": ";".join(f"_import_{j}" for j in range(import_count)),
        }
        for i in range(count)
    ]


def test_load_and_prepare_hla_data_normalizes_and_aggregates(tmp_path):
    input_file = tmp_path / "hla.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "file": "/usr/lib/libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "num_sections": "5",
                "num_symbols": "100",
                "imported_functions": "_a;_b",
            },
            {
                "file": "/usr/lib/libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "num_sections": "7",
                "num_symbols": "120",
                "imported_functions": "_a;_b;_c",
            },
        ],
    )

    df = load_and_prepare_hla_data(input_file)

    assert len(df) == 1
    assert df.loc[0, IOS_VERSION] == "iOS 8.0"
    assert df.loc[0, "library"] == "libA.dylib"
    assert df.loc[0, "num_sections"] == 7
    assert df.loc[0, "num_symbols"] == 120
    assert df.loc[0, "import_count"] == 3


def test_load_and_prepare_hla_data_accepts_alternative_column_names(tmp_path):
    input_file = tmp_path / "hla.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "name": "libA.dylib",
                "version": "iPhone5,1_8.0_12A365",
                "num_sections": 5,
                "num_symbols": 100,
                "imported_functions": "_a;_b",
            }
        ],
    )

    df = load_and_prepare_hla_data(input_file)

    assert len(df) == 1
    assert df.loc[0, "library"] == "libA.dylib"
    assert df.loc[0, IOS_VERSION] == "iOS 8.0"


def test_load_and_prepare_hla_data_raises_when_required_column_missing(tmp_path):
    input_file = tmp_path / "hla.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "file": "libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "num_sections": 5,
                "num_symbols": 100,
            }
        ],
    )

    with pytest.raises(ValueError, match="Missing expected column"):
        load_and_prepare_hla_data(input_file)


def test_compute_version_tables_builds_summary_and_per_version_tables(tmp_path):
    input_file = tmp_path / "hla.jsonl"

    rows = []
    rows.extend(make_hla_rows("iPhone5,1_8.0_12A365", count=3, symbol_base=100))
    rows.extend(make_hla_rows("iPhone5,1_9.0_13A344", count=3, symbol_base=200))

    write_jsonl(input_file, rows)

    df = load_and_prepare_hla_data(input_file)
    versions, per_version, summary = compute_version_tables(df, topk=2)

    assert versions == ["iOS 8.0", "iOS 9.0"]
    assert set(per_version.keys()) == {"iOS 8.0", "iOS 9.0"}
    assert summary["iOS 8.0"]["libs"] == 3
    assert summary["iOS 8.0"]["data_quality"] == "partial"
    assert "version_risk" in summary["iOS 8.0"]
    assert list(per_version["iOS 8.0"].columns) == [
        "library",
        "raw_risk",
        "num_symbols",
        "import_count",
        "num_sections",
    ]


def test_build_hla_trend_rows_marks_first_version_as_na(tmp_path):
    input_file = tmp_path / "hla.jsonl"

    write_jsonl(
        input_file,
        make_hla_rows("iPhone5,1_8.0_12A365", count=3),
    )

    df = load_and_prepare_hla_data(input_file)
    versions, per_version, summary = compute_version_tables(df, topk=2)
    rows = build_hla_trend_rows(versions, per_version, summary)

    assert len(rows) == 1
    assert rows[0].ios_version == "iOS 8.0"
    assert rows[0].release_label == "n/a"
    assert rows[0].common is None
    assert rows[0].overlap is None


def test_build_hla_trend_rows_marks_partial_snapshot(tmp_path, monkeypatch):
    input_file = tmp_path / "hla.jsonl"

    rows = []
    rows.extend(make_hla_rows("iPhone5,1_8.0_12A365", count=2, symbol_base=100))
    rows.extend(make_hla_rows("iPhone5,1_9.0_13A344", count=2, symbol_base=120))

    write_jsonl(input_file, rows)

    df = load_and_prepare_hla_data(input_file)
    versions, per_version, summary = compute_version_tables(df, topk=2)

    trend_rows = build_hla_trend_rows(versions, per_version, summary)

    assert trend_rows[1].release_label == "partial_snapshot"
    assert trend_rows[1].common is None


def test_build_hla_trend_rows_marks_insufficient_overlap(tmp_path, monkeypatch):
    monkeypatch.setattr(hla_trend_analysis, "MIN_LIBS_FOR_VERSION", 1)
    monkeypatch.setattr(hla_trend_analysis, "MIN_COMMON", 2)
    monkeypatch.setattr(hla_trend_analysis, "MIN_OVERLAP", 0.60)

    input_file = tmp_path / "hla.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "file": "libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "num_sections": 5,
                "num_symbols": 100,
                "imported_functions": "_a",
            },
            {
                "file": "libB.dylib",
                "ios_version": "iPhone5,1_9.0_13A344",
                "num_sections": 5,
                "num_symbols": 200,
                "imported_functions": "_a",
            },
        ],
    )

    df = load_and_prepare_hla_data(input_file)
    versions, per_version, summary = compute_version_tables(df, topk=1)
    rows = build_hla_trend_rows(versions, per_version, summary)

    assert rows[1].release_label == "insufficient_overlap"
    assert rows[1].common == 0
    assert rows[1].overlap == 0.0


def test_build_hla_trend_rows_classifies_valid_transition(tmp_path, monkeypatch):
    monkeypatch.setattr(hla_trend_analysis, "MIN_LIBS_FOR_VERSION", 1)
    monkeypatch.setattr(hla_trend_analysis, "MIN_COMMON", 1)
    monkeypatch.setattr(hla_trend_analysis, "MIN_OVERLAP", 0.50)

    input_file = tmp_path / "hla.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "file": "libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "num_sections": 5,
                "num_symbols": 100,
                "imported_functions": "_a",
            },
            {
                "file": "libA.dylib",
                "ios_version": "iPhone5,1_9.0_13A344",
                "num_sections": 8,
                "num_symbols": 250,
                "imported_functions": "_a;_b;_c;_d",
            },
        ],
    )

    df = load_and_prepare_hla_data(input_file)
    versions, per_version, summary = compute_version_tables(df, topk=1)
    rows = build_hla_trend_rows(versions, per_version, summary)

    assert rows[1].release_label == "expanding"
    assert rows[1].common == 1
    assert rows[1].overlap == 1.0
    assert rows[1].delta_raw is not None
    assert rows[1].delta_symbols is not None
    assert rows[1].delta_imports is not None
    assert rows[1].delta_sections is not None


def test_run_hla_trend_analysis_returns_rows_without_printing(tmp_path, capsys):
    input_file = tmp_path / "hla.jsonl"

    write_jsonl(
        input_file,
        make_hla_rows("iPhone5,1_8.0_12A365", count=2),
    )

    rows = run_hla_trend_analysis(input_file, topk=1, print_report=False)

    captured = capsys.readouterr()

    assert len(rows) == 1
    assert captured.out == ""


def test_run_hla_trend_analysis_prints_report(tmp_path, capsys):
    input_file = tmp_path / "hla.jsonl"

    write_jsonl(
        input_file,
        make_hla_rows("iPhone5,1_8.0_12A365", count=2),
    )

    run_hla_trend_analysis(input_file, topk=1, print_report=True)

    captured = capsys.readouterr()

    assert "iOS_VERSION" in captured.out
    assert "iOS 8.0" in captured.out