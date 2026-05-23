from __future__ import annotations

import json

import pytest

from dylibscope.config.ios_versions import IOS_VERSION
from dylibscope.security_analysis import lla_trend_analysis
from dylibscope.security_analysis.lla_trend_analysis import (
    build_lla_trend_rows,
    compute_version_tables,
    load_and_prepare_lla_data,
    run_lla_trend_analysis,
)


def write_jsonl(path, rows):
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n",
        encoding="utf-8",
    )


def make_lla_rows(
    version: str,
    count: int,
    cfg_base: int = 100,
    alloc_base: int = 10,
    mach_base: int = 2,
    syscall_base: int = 1,
):
    return [
        {
            "library": f"lib{i}.dylib",
            "ios_version": version,
            "cfg_edge_count": cfg_base + i,
            "internal_variable_count": 20 + i,
            "internal_function_count": 30 + i,
            "allocation_call_count": alloc_base,
            "syscall_function_count": syscall_base,
            "mach_port_function_count": mach_base,
        }
        for i in range(count)
    ]


def test_load_and_prepare_lla_data_normalizes_and_aggregates(tmp_path):
    input_file = tmp_path / "lla.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "library": "/usr/lib/libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "cfg_edge_count": "100",
                "internal_variable_count": "20",
                "internal_function_count": "30",
                "allocation_call_count": "4",
                "syscall_function_count": "1",
                "mach_port_function_count": "2",
            },
            {
                "library": "/usr/lib/libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "cfg_edge_count": "120",
                "internal_variable_count": "25",
                "internal_function_count": "35",
                "allocation_call_count": "5",
                "syscall_function_count": "2",
                "mach_port_function_count": "3",
            },
        ],
    )

    df = load_and_prepare_lla_data(input_file)

    assert len(df) == 1
    assert df.loc[0, IOS_VERSION] == "iOS 8.0"
    assert df.loc[0, "library"] == "libA.dylib"
    assert df.loc[0, "cfg_edge_count"] == 120
    assert df.loc[0, "internal_variable_count"] == 25
    assert df.loc[0, "internal_function_count"] == 35
    assert df.loc[0, "allocation_call_count"] == 5
    assert df.loc[0, "syscall_function_count"] == 2
    assert df.loc[0, "mach_port_function_count"] == 3


def test_load_and_prepare_lla_data_accepts_alternative_column_names(tmp_path):
    input_file = tmp_path / "lla.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "name": "libA.dylib",
                "version": "iPhone5,1_8.0_12A365",
                "cfg_edge_count": 100,
            }
        ],
    )

    df = load_and_prepare_lla_data(input_file)

    assert len(df) == 1
    assert df.loc[0, "library"] == "libA.dylib"
    assert df.loc[0, IOS_VERSION] == "iOS 8.0"
    assert df.loc[0, "cfg_edge_count"] == 100
    assert df.loc[0, "allocation_call_count"] == 0
    assert df.loc[0, "syscall_function_count"] == 0
    assert df.loc[0, "mach_port_function_count"] == 0
    assert df.loc[0, "internal_function_count"] == 0
    assert df.loc[0, "internal_variable_count"] == 0


def test_load_and_prepare_lla_data_raises_when_required_column_missing(tmp_path):
    input_file = tmp_path / "lla.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "ios_version": "iPhone5,1_8.0_12A365",
                "cfg_edge_count": 100,
            }
        ],
    )

    with pytest.raises(ValueError, match="Missing expected column"):
        load_and_prepare_lla_data(input_file)


def test_compute_version_tables_builds_summary_and_per_version_tables(tmp_path):
    input_file = tmp_path / "lla.jsonl"

    rows = []
    rows.extend(make_lla_rows("iPhone5,1_8.0_12A365", count=3, cfg_base=100))
    rows.extend(make_lla_rows("iPhone5,1_9.0_13A344", count=3, cfg_base=200))

    write_jsonl(input_file, rows)

    df = load_and_prepare_lla_data(input_file)
    versions, per_version, summary = compute_version_tables(df, topk=2)

    assert versions == ["iOS 8.0", "iOS 9.0"]
    assert set(per_version.keys()) == {"iOS 8.0", "iOS 9.0"}
    assert summary["iOS 8.0"]["libs"] == 3
    assert summary["iOS 8.0"]["data_quality"] == "partial"
    assert summary["iOS 8.0"]["boundary_total"] == 9
    assert "version_risk" in summary["iOS 8.0"]
    assert list(per_version["iOS 8.0"].columns) == [
        "library",
        "raw_risk",
        "cfg_edge_count",
        "allocation_call_count",
        "mach_port_function_count",
        "syscall_function_count",
        "internal_function_count",
        "internal_variable_count",
    ]


def test_build_lla_trend_rows_marks_first_version_as_na(tmp_path):
    input_file = tmp_path / "lla.jsonl"

    write_jsonl(
        input_file,
        make_lla_rows("iPhone5,1_8.0_12A365", count=3),
    )

    df = load_and_prepare_lla_data(input_file)
    versions, per_version, summary = compute_version_tables(df, topk=2)
    rows = build_lla_trend_rows(versions, per_version, summary)

    assert len(rows) == 1
    assert rows[0].ios_version == "iOS 8.0"
    assert rows[0].release_label == "n/a"
    assert rows[0].common is None
    assert rows[0].overlap is None
    assert rows[0].boundary_total == 9


def test_build_lla_trend_rows_marks_partial_snapshot(tmp_path):
    input_file = tmp_path / "lla.jsonl"

    rows = []
    rows.extend(make_lla_rows("iPhone5,1_8.0_12A365", count=2, cfg_base=100))
    rows.extend(make_lla_rows("iPhone5,1_9.0_13A344", count=2, cfg_base=120))

    write_jsonl(input_file, rows)

    df = load_and_prepare_lla_data(input_file)
    versions, per_version, summary = compute_version_tables(df, topk=2)

    trend_rows = build_lla_trend_rows(versions, per_version, summary)

    assert trend_rows[1].release_label == "partial_snapshot"
    assert trend_rows[1].common is None


def test_build_lla_trend_rows_marks_insufficient_overlap(tmp_path, monkeypatch):
    monkeypatch.setattr(lla_trend_analysis, "MIN_LIBS_FOR_VERSION", 1)
    monkeypatch.setattr(lla_trend_analysis, "MIN_COMMON", 2)
    monkeypatch.setattr(lla_trend_analysis, "MIN_OVERLAP", 0.60)

    input_file = tmp_path / "lla.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "library": "libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "cfg_edge_count": 100,
                "allocation_call_count": 1,
                "mach_port_function_count": 1,
                "syscall_function_count": 1,
                "internal_function_count": 10,
                "internal_variable_count": 20,
            },
            {
                "library": "libB.dylib",
                "ios_version": "iPhone5,1_9.0_13A344",
                "cfg_edge_count": 200,
                "allocation_call_count": 1,
                "mach_port_function_count": 1,
                "syscall_function_count": 1,
                "internal_function_count": 10,
                "internal_variable_count": 20,
            },
        ],
    )

    df = load_and_prepare_lla_data(input_file)
    versions, per_version, summary = compute_version_tables(df, topk=1)
    rows = build_lla_trend_rows(versions, per_version, summary)

    assert rows[1].release_label == "insufficient_overlap"
    assert rows[1].common == 0
    assert rows[1].overlap == 0.0


def test_build_lla_trend_rows_classifies_valid_transition(tmp_path, monkeypatch):
    monkeypatch.setattr(lla_trend_analysis, "MIN_LIBS_FOR_VERSION", 1)
    monkeypatch.setattr(lla_trend_analysis, "MIN_COMMON", 1)
    monkeypatch.setattr(lla_trend_analysis, "MIN_OVERLAP", 0.50)

    input_file = tmp_path / "lla.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "library": "libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "cfg_edge_count": 100,
                "allocation_call_count": 1,
                "mach_port_function_count": 1,
                "syscall_function_count": 1,
                "internal_function_count": 10,
                "internal_variable_count": 20,
            },
            {
                "library": "libA.dylib",
                "ios_version": "iPhone5,1_9.0_13A344",
                "cfg_edge_count": 300,
                "allocation_call_count": 5,
                "mach_port_function_count": 3,
                "syscall_function_count": 2,
                "internal_function_count": 20,
                "internal_variable_count": 40,
            },
        ],
    )

    df = load_and_prepare_lla_data(input_file)
    versions, per_version, summary = compute_version_tables(df, topk=1)
    rows = build_lla_trend_rows(versions, per_version, summary)

    assert rows[1].release_label == "expanding"
    assert rows[1].common == 1
    assert rows[1].overlap == 1.0
    assert rows[1].delta_raw is not None
    assert rows[1].delta_cfg is not None
    assert rows[1].delta_alloc is not None
    assert rows[1].delta_boundary is not None


def test_run_lla_trend_analysis_returns_rows_without_printing(tmp_path, capsys):
    input_file = tmp_path / "lla.jsonl"

    write_jsonl(
        input_file,
        make_lla_rows("iPhone5,1_8.0_12A365", count=2),
    )

    rows = run_lla_trend_analysis(input_file, topk=1, print_report=False)

    captured = capsys.readouterr()

    assert len(rows) == 1
    assert captured.out == ""


def test_run_lla_trend_analysis_prints_report(tmp_path, capsys):
    input_file = tmp_path / "lla.jsonl"

    write_jsonl(
        input_file,
        make_lla_rows("iPhone5,1_8.0_12A365", count=2),
    )

    run_lla_trend_analysis(input_file, topk=1, print_report=True)

    captured = capsys.readouterr()

    assert "iOS_VERSION" in captured.out
    assert "iOS 8.0" in captured.out