from __future__ import annotations

import json
from types import SimpleNamespace

from dylibscope.high_level_analysis import extract_high_level


class FakeMachOBinary:
    pass


def make_fake_binary(
    commands=None,
    sections=None,
    symbols=None,
    exported_symbols=None,
    imported_symbols=None,
):
    binary = FakeMachOBinary()
    binary.commands = commands or []
    binary.sections = sections or []
    binary.symbols = symbols or []
    binary.exported_symbols = exported_symbols or []
    binary.imported_symbols = imported_symbols or []
    return binary


def test_extract_ios_deployment_reads_version_min(monkeypatch):
    command = SimpleNamespace(version=(10, 3, 0))
    binary = make_fake_binary(commands=[command])

    fake_version_min = type(command)
    fake_build_version = type("FakeBuildVersion", (), {})

    monkeypatch.setattr(extract_high_level.lief.MachO, "VersionMin", fake_version_min)
    monkeypatch.setattr(extract_high_level.lief.MachO, "BuildVersion", fake_build_version)

    assert extract_high_level.extract_ios_deployment(binary) == "10.3.0"


def test_extract_ios_deployment_reads_build_version(monkeypatch):
    command = SimpleNamespace(minos=(12, 0, 0))
    binary = make_fake_binary(commands=[command])

    fake_version_min = type("FakeVersionMin", (), {})
    fake_build_version = type(command)

    monkeypatch.setattr(extract_high_level.lief.MachO, "VersionMin", fake_version_min)
    monkeypatch.setattr(extract_high_level.lief.MachO, "BuildVersion", fake_build_version)

    assert extract_high_level.extract_ios_deployment(binary) == "12.0.0"


def test_extract_ios_deployment_returns_none_when_no_version_command():
    binary = make_fake_binary(commands=[])

    assert extract_high_level.extract_ios_deployment(binary) is None


def test_analyze_dylib_returns_expected_record(monkeypatch, tmp_path):
    dylib_path = tmp_path / "libExample.dylib"
    dylib_path.write_text("fake binary", encoding="utf-8")

    monkeypatch.setattr(extract_high_level.lief.MachO, "Binary", FakeMachOBinary)

    binary = make_fake_binary(
        commands=[],
        sections=[object(), object()],
        symbols=[object(), object(), object()],
        exported_symbols=[
            SimpleNamespace(name="_exportedA"),
            SimpleNamespace(name=""),
            SimpleNamespace(name="_exportedB"),
        ],
        imported_symbols=[
            SimpleNamespace(name="_importedA"),
            SimpleNamespace(name=None),
            SimpleNamespace(name="_importedB"),
        ],
    )

    monkeypatch.setattr(extract_high_level.lief, "parse", lambda path: binary)

    result = extract_high_level.analyze_dylib(str(dylib_path), "iOS_TEST")

    assert result == {
        "file": "libExample.dylib",
        "deployment_target": None,
        "ios_version": "iOS_TEST",
        "path": str(dylib_path),
        "num_sections": 2,
        "num_symbols": 3,
        "exported_functions": "_exportedA;_exportedB",
        "imported_functions": "_importedA;_importedB",
    }


def test_analyze_dylib_returns_none_for_non_macho_binary(monkeypatch, tmp_path):
    dylib_path = tmp_path / "libInvalid.dylib"
    dylib_path.write_text("fake binary", encoding="utf-8")

    monkeypatch.setattr(extract_high_level.lief.MachO, "Binary", FakeMachOBinary)
    monkeypatch.setattr(extract_high_level.lief, "parse", lambda path: object())

    result = extract_high_level.analyze_dylib(str(dylib_path), "iOS_TEST")

    assert result is None


def test_analyze_dylib_returns_none_when_lief_parse_fails(monkeypatch, tmp_path):
    dylib_path = tmp_path / "libBroken.dylib"
    dylib_path.write_text("fake binary", encoding="utf-8")

    def raise_parse_error(path):
        raise RuntimeError("parse failed")

    monkeypatch.setattr(extract_high_level.lief, "parse", raise_parse_error)

    result = extract_high_level.analyze_dylib(str(dylib_path), "iOS_TEST")

    assert result is None


def test_analyze_directory_non_recursive(tmp_path, monkeypatch):
    root = tmp_path / "iPhone_TEST"
    nested = root / "nested"
    nested.mkdir(parents=True)

    top_level_dylib = root / "libTop.dylib"
    nested_dylib = nested / "libNested.dylib"
    ignored_file = root / "readme.txt"

    top_level_dylib.write_text("fake", encoding="utf-8")
    nested_dylib.write_text("fake", encoding="utf-8")
    ignored_file.write_text("ignore", encoding="utf-8")

    def fake_analyze_dylib(path, ios_root_label):
        return {
            "file": path.split("/")[-1],
            "ios_version": ios_root_label,
        }

    monkeypatch.setattr(extract_high_level, "analyze_dylib", fake_analyze_dylib)

    result = extract_high_level.analyze_directory(
        str(root),
        recursive=False,
        return_data=True,
    )

    assert result == [
        {
            "file": "libTop.dylib",
            "ios_version": "iPhone_TEST",
        }
    ]


def test_analyze_directory_recursive(tmp_path, monkeypatch):
    root = tmp_path / "iPhone_TEST"
    nested = root / "nested"
    nested.mkdir(parents=True)

    (root / "libTop.dylib").write_text("fake", encoding="utf-8")
    (nested / "libNested.dylib").write_text("fake", encoding="utf-8")

    def fake_analyze_dylib(path, ios_root_label):
        return {
            "file": path.split("/")[-1],
            "ios_version": ios_root_label,
        }

    monkeypatch.setattr(extract_high_level, "analyze_dylib", fake_analyze_dylib)

    result = extract_high_level.analyze_directory(
        str(root),
        recursive=True,
        return_data=True,
    )

    assert result == [
        {
            "file": "libTop.dylib",
            "ios_version": "iPhone_TEST",
        },
        {
            "file": "libNested.dylib",
            "ios_version": "iPhone_TEST",
        },
    ]


def test_analyze_from_filelist_writes_jsonl(tmp_path, monkeypatch):
    parent = tmp_path / "parent"
    version_dir = parent / "iPhone_TEST"
    version_dir.mkdir(parents=True)

    filelist = tmp_path / "dylib_list.txt"
    output_file = tmp_path / "output.jsonl"

    filelist.write_text(f"{parent}\n", encoding="utf-8")

    def fake_analyze_directory(dir_path, recursive=False, return_data=False):
        return [
            {
                "file": "libA.dylib",
                "ios_version": "iPhone_TEST",
            },
            {
                "file": "libB.dylib",
                "ios_version": "iPhone_TEST",
            },
        ]

    monkeypatch.setattr(extract_high_level, "analyze_directory", fake_analyze_directory)

    extract_high_level.analyze_from_filelist(
        str(filelist),
        output_path=str(output_file),
        recursive=True,
    )

    lines = output_file.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]

    assert records == [
        {
            "file": "libA.dylib",
            "ios_version": "iPhone_TEST",
        },
        {
            "file": "libB.dylib",
            "ios_version": "iPhone_TEST",
        },
    ]


def test_analyze_from_filelist_skips_empty_and_commented_lines(tmp_path, monkeypatch):
    parent = tmp_path / "parent"
    version_dir = parent / "iPhone_TEST"
    version_dir.mkdir(parents=True)

    filelist = tmp_path / "dylib_list.txt"
    output_file = tmp_path / "output.jsonl"

    filelist.write_text(
        "\n"
        "# ignored comment\n"
        f"{parent}\n",
        encoding="utf-8",
    )

    calls = []

    def fake_analyze_directory(dir_path, recursive=False, return_data=False):
        calls.append(dir_path)
        return []

    monkeypatch.setattr(extract_high_level, "analyze_directory", fake_analyze_directory)

    extract_high_level.analyze_from_filelist(
        str(filelist),
        output_path=str(output_file),
        recursive=True,
    )

    assert calls == [str(version_dir)]