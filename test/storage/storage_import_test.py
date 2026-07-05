from __future__ import annotations

import json

from dylibscope.storage.importer import import_datasets
from dylibscope.storage.repository import get_library_metrics, list_ios_versions, list_libraries
from dylibscope.storage.schema import connect


def write_jsonl(path, records):
    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def test_import_merges_hla_and_lla_records(tmp_path):
    hla_path = tmp_path / "hla.jsonl"
    lla_path = tmp_path / "lla.jsonl"
    db_path = tmp_path / "dylibscope.sqlite"

    write_jsonl(
        hla_path,
        [
            {
                "file": "libxpc.dylib",
                "deployment_target": "12.0",
                "ios_version": "iPhone11,8_12.0_16A366",
                "path": "/System/Library/libxpc.dylib",
                "num_sections": 12,
                "num_symbols": 100,
                "exported_functions": "_xpc_main;_xpc_connection_create",
                "imported_functions": "_malloc;_mach_msg",
            }
        ],
    )
    write_jsonl(
        lla_path,
        [
            {
                "ios_version": "iPhone11,8_12.0_16A366",
                "library": "libxpc.dylib",
                "cfg_edge_count": 50,
                "internal_variable_count": 5,
                "internal_function_count": 10,
                "allocation_call_count": 2,
                "syscall_function_count": 1,
                "mach_port_function_count": 3,
            }
        ],
    )

    conn = connect(str(db_path))
    summary = import_datasets(
        conn,
        dataset_name="test-baseline",
        hla_path=str(hla_path),
        lla_path=str(lla_path),
    )

    assert summary.hla_records == 1
    assert summary.lla_records == 1
    assert summary.errors == 0

    libraries = list_libraries(conn, dataset_name="test-baseline")
    assert libraries == [
        {
            "display_name": "libxpc.dylib",
            "canonical_name": "libxpc.dylib",
            "ios_version_count": 1,
        }
    ]

    versions = list_ios_versions(conn)
    assert versions == [
        {
            "version_label": "iPhone11,8_12.0_16A366",
            "device_model": "iPhone11,8",
            "ios_release": "12.0",
            "build_number": "16A366",
        }
    ]

    result = get_library_metrics(conn, "libxpc.dylib", dataset_name="test-baseline")
    assert len(result) == 1
    assert result[0]["ios_release"] == "12.0"
    metrics = result[0]["metrics"]
    assert metrics["num_sections"]["value"] == 12
    assert metrics["imported_function_count"]["value"] == 2
    assert metrics["cfg_edge_count"]["value"] == 50
    assert metrics["mach_port_function_count"]["value"] == 3


def test_metric_level_exact_metric_and_release_filters(tmp_path):
    hla_path = tmp_path / "hla.jsonl"
    db_path = tmp_path / "dylibscope.sqlite"

    write_jsonl(
        hla_path,
        [
            {
                "file": "libsystem_kernel.dylib",
                "deployment_target": "13.0",
                "ios_version": "iPhone11,8_17.0_21A000",
                "path": "/usr/lib/system/libsystem_kernel.dylib",
                "num_sections": 8,
                "num_symbols": 42,
                "exported_functions": "_open;_close",
                "imported_functions": "",
            }
        ],
    )

    conn = connect(str(db_path))
    import_datasets(conn, dataset_name="test-baseline", hla_path=str(hla_path))

    high_only = get_library_metrics(
        conn,
        "libsystem_kernel.dylib",
        dataset_name="test-baseline",
        level="high",
    )
    assert "num_symbols" in high_only[0]["metrics"]

    exact = get_library_metrics(
        conn,
        "/usr/lib/system/libsystem_kernel.dylib",
        dataset_name="test-baseline",
        metrics=["num_symbols"],
    )
    assert list(exact[0]["metrics"].keys()) == ["num_symbols"]

    by_release = get_library_metrics(
        conn,
        "libsystem_kernel.dylib",
        dataset_name="test-baseline",
        ios_version="17.0",
    )
    by_full_label = get_library_metrics(
        conn,
        "libsystem_kernel.dylib",
        dataset_name="test-baseline",
        ios_version="iPhone11,8_17.0_21A000",
    )
    assert len(by_release) == 1
    assert by_release == by_full_label


def test_imports_real_sample_shape_with_empty_exports(tmp_path):
    hla_path = tmp_path / "hla.jsonl"
    lla_path = tmp_path / "lla.jsonl"
    db_path = tmp_path / "dylibscope.sqlite"

    write_jsonl(
        hla_path,
        [
            {
                "file": "libsqlite3.0.dylib",
                "deployment_target": "6.0.0",
                "ios_version": "iPhone5,1_6.0_10A405",
                "path": "/Volumes/T7 Shield/iextractor/out/iPhone5,1_6.0_10A405/dyld_shared_cache/usr/lib/libsqlite3.0.dylib",
                "num_sections": 11,
                "num_symbols": 313,
                "exported_functions": "",
                "imported_functions": "_malloc;_free;dyld_stub_binder",
            }
        ],
    )
    write_jsonl(
        lla_path,
        [
            {
                "ios_version": "iPhone11,8_12.0_16A366",
                "internal_function_count": 16,
                "mach_port_function_count": 0,
                "internal_variable_count": 48,
                "cfg_edge_count": 828,
                "library": "libSimplifiedChineseConverter.dylib",
                "syscall_function_count": 0,
                "allocation_call_count": 0,
            }
        ],
    )

    conn = connect(str(db_path))
    summary = import_datasets(
        conn,
        dataset_name="sample-baseline",
        hla_path=str(hla_path),
        lla_path=str(lla_path),
    )
    assert summary.errors == 0

    hla = get_library_metrics(conn, "libsqlite3.0.dylib", dataset_name="sample-baseline")
    assert hla[0]["ios_release"] == "6.0"
    assert hla[0]["metrics"]["exported_function_count"]["value"] == 0
    assert hla[0]["metrics"]["imported_function_count"]["value"] == 3
    assert hla[0]["metrics"]["deployment_target"]["value"] == "6.0.0"

    lla = get_library_metrics(
        conn,
        "libSimplifiedChineseConverter.dylib",
        dataset_name="sample-baseline",
        ios_version="12.0",
        level="low",
    )
    assert lla[0]["metrics"]["cfg_edge_count"]["value"] == 828
