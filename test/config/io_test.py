from __future__ import annotations

import pytest

from dylibscope.config.io import load_jsonl


def test_load_jsonl_reads_valid_json_lines(tmp_path):
    input_file = tmp_path / "sample.jsonl"
    input_file.write_text(
        '{"library": "libA.dylib", "ios_version": "iOS 8.0", "metric": 10}\n'
        '{"library": "libB.dylib", "ios_version": "iOS 9.0", "metric": 20}\n',
        encoding="utf-8",
    )

    df = load_jsonl(input_file)

    assert len(df) == 2
    assert list(df["library"]) == ["libA.dylib", "libB.dylib"]
    assert list(df["ios_version"]) == ["iOS 8.0", "iOS 9.0"]
    assert list(df["metric"]) == [10, 20]


def test_load_jsonl_accepts_string_path(tmp_path):
    input_file = tmp_path / "sample.jsonl"
    input_file.write_text(
        '{"library": "libA.dylib"}\n',
        encoding="utf-8",
    )

    df = load_jsonl(str(input_file))

    assert len(df) == 1
    assert df.loc[0, "library"] == "libA.dylib"


def test_load_jsonl_ignores_blank_lines(tmp_path):
    input_file = tmp_path / "sample.jsonl"
    input_file.write_text(
        '\n{"library": "libA.dylib"}\n\n{"library": "libB.dylib"}\n\n',
        encoding="utf-8",
    )

    df = load_jsonl(input_file)

    assert len(df) == 2
    assert list(df["library"]) == ["libA.dylib", "libB.dylib"]


def test_load_jsonl_returns_empty_dataframe_for_empty_file(tmp_path):
    input_file = tmp_path / "empty.jsonl"
    input_file.write_text("", encoding="utf-8")

    df = load_jsonl(input_file)

    assert df.empty


def test_load_jsonl_raises_file_not_found_for_missing_file(tmp_path):
    input_file = tmp_path / "missing.jsonl"

    with pytest.raises(FileNotFoundError, match="Input JSONL file not found"):
        load_jsonl(input_file)


def test_load_jsonl_raises_value_error_for_invalid_json(tmp_path):
    input_file = tmp_path / "invalid.jsonl"
    input_file.write_text(
        '{"library": "libA.dylib"}\n'
        "invalid-json\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid JSON on line 2"):
        load_jsonl(input_file)