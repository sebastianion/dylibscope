from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from fastapi.testclient import TestClient

from dylibscope.api.app import create_app
from dylibscope.storage.importer import import_datasets
from dylibscope.storage.schema import connect


def write_jsonl(path: Path, records: List[Dict]) -> None:
    path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")


def build_test_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "dylibscope.sqlite"
    hla_path = tmp_path / "hla.jsonl"
    lla_path = tmp_path / "lla.jsonl"

    write_jsonl(
        hla_path,
        [
            {
                "file": "libsqlite3.0.dylib",
                "deployment_target": "6.0.0",
                "ios_version": "iPhone5,1_6.0_10A405",
                "path": "/x/y/usr/lib/libsqlite3.0.dylib",
                "num_sections": 11,
                "num_symbols": 313,
                "exported_functions": "",
                "imported_functions": "_malloc;_free;dyld_stub_binder",
            },
            {
                "file": "libsqlite3.0.dylib",
                "deployment_target": "7.0.0",
                "ios_version": "iPhone5,1_7.0_11A465",
                "path": "/x/y/usr/lib/libsqlite3.0.dylib",
                "num_sections": 12,
                "num_symbols": 350,
                "exported_functions": "",
                "imported_functions": "_malloc;_free;_mmap;dyld_stub_binder",
            },
            {
                "file": "libresolv.dylib",
                "deployment_target": "6.0.0",
                "ios_version": "iPhone5,1_6.0_10A405",
                "path": "/x/y/usr/lib/libresolv.dylib",
                "num_sections": 11,
                "num_symbols": 416,
                "exported_functions": "",
                "imported_functions": "_socket;_sendto;_recvmsg;dyld_stub_binder",
            },
        ],
    )
    write_jsonl(
        lla_path,
        [
            {
                "ios_version": "iPhone5,1_6.0_10A405",
                "library": "libsqlite3.0.dylib",
                "internal_function_count": 16,
                "mach_port_function_count": 0,
                "internal_variable_count": 48,
                "cfg_edge_count": 828,
                "syscall_function_count": 0,
                "allocation_call_count": 2,
            },
            {
                "ios_version": "iPhone5,1_7.0_11A465",
                "library": "libsqlite3.0.dylib",
                "internal_function_count": 18,
                "mach_port_function_count": 1,
                "internal_variable_count": 50,
                "cfg_edge_count": 900,
                "syscall_function_count": 0,
                "allocation_call_count": 3,
            },
            {
                "ios_version": "iPhone5,1_6.0_10A405",
                "library": "libresolv.dylib",
                "internal_function_count": 13,
                "mach_port_function_count": 0,
                "internal_variable_count": 25,
                "cfg_edge_count": 308,
                "syscall_function_count": 0,
                "allocation_call_count": 0,
            },
        ],
    )

    conn = connect(str(db_path))
    try:
        import_datasets(conn, dataset_name="public-baseline", hla_path=hla_path, lla_path=lla_path)
    finally:
        conn.close()
    return db_path


def test_health_reports_database_status(tmp_path: Path) -> None:
    db_path = build_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["database_exists"] is True


def test_list_libraries_and_ios_versions(tmp_path: Path) -> None:
    db_path = build_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    libraries = client.get("/v1/libraries?dataset_name=public-baseline")
    versions = client.get("/v1/ios-versions")

    assert libraries.status_code == 200
    assert libraries.json()["count"] == 2
    assert {item["display_name"] for item in libraries.json()["libraries"]} == {
        "libsqlite3.0.dylib",
        "libresolv.dylib",
    }

    assert versions.status_code == 200
    assert {item["ios_release"] for item in versions.json()["ios_versions"]} == {"6.0", "7.0"}


def test_query_metrics_by_release_level_and_exact_metric(tmp_path: Path) -> None:
    db_path = build_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    high_response = client.get(
        "/v1/libraries/libsqlite3.0.dylib/metrics",
        params={"dataset_name": "public-baseline", "ios_version": "6.0", "level": "high"},
    )
    assert high_response.status_code == 200
    high_metrics = high_response.json()["observations"][0]["metrics"]
    assert "num_symbols" in high_metrics
    assert "cfg_edge_count" not in high_metrics

    exact_response = client.get(
        "/v1/libraries/libsqlite3.0.dylib/metrics",
        params={"dataset_name": "public-baseline", "metrics": "imported_function_count,cfg_edge_count"},
    )
    assert exact_response.status_code == 200
    exact_metrics = exact_response.json()["observations"][0]["metrics"]
    assert set(exact_metrics) == {"imported_function_count", "cfg_edge_count"}


def test_query_metrics_by_full_firmware_label(tmp_path: Path) -> None:
    db_path = build_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    response = client.get(
        "/v1/libraries/libsqlite3.0.dylib/metrics",
        params={
            "dataset_name": "public-baseline",
            "ios_version": "iPhone5,1_6.0_10A405",
            "level": "low",
        },
    )

    assert response.status_code == 200
    metrics = response.json()["observations"][0]["metrics"]
    assert metrics["cfg_edge_count"]["value"] == 828
    assert "num_symbols" not in metrics


def test_compare_libraries_returns_human_readable_static_metric_results(tmp_path: Path) -> None:
    db_path = build_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    response = client.post(
        "/v1/libraries/compare",
        json={
            "libraries": ["libsqlite3.0.dylib", "libresolv.dylib"],
            "dataset_name": "public-baseline",
            "ios_version": "6.0",
            "metrics": ["num_symbols", "cfg_edge_count"],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["comparison_basis"] == "static_metric_comparison"
    assert payload["matched_count"] == 2
    assert payload["missing_libraries"] == []
    assert payload["resolved_observations"] == [
        {
            "library": "libsqlite3.0.dylib",
            "matched_observation_count": 1,
            "selected_ios_version": "iPhone5,1_6.0_10A405",
            "selected_ios_release": "6.0",
            "selected_build_number": "10A405",
        },
        {
            "library": "libresolv.dylib",
            "matched_observation_count": 1,
            "selected_ios_version": "iPhone5,1_6.0_10A405",
            "selected_ios_release": "6.0",
            "selected_build_number": "10A405",
        },
    ]

    rows_by_metric = {row["metric"]: row for row in payload["results"]}
    assert rows_by_metric["num_symbols"]["values"] == {
        "libsqlite3.0.dylib": 313,
        "libresolv.dylib": 416,
    }
    assert rows_by_metric["num_symbols"]["leader"] == "libresolv.dylib"
    assert rows_by_metric["num_symbols"]["absolute_difference"] == 103

    assert rows_by_metric["cfg_edge_count"]["values"] == {
        "libsqlite3.0.dylib": 828,
        "libresolv.dylib": 308,
    }
    assert rows_by_metric["cfg_edge_count"]["leader"] == "libsqlite3.0.dylib"


def test_compare_same_library_across_ios_versions(tmp_path: Path) -> None:
    db_path = build_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    response = client.post(
        "/v1/libraries/libsqlite3.0.dylib/compare-versions",
        json={
            "dataset_name": "public-baseline",
            "ios_versions": ["6.0", "7.0"],
            "metrics": ["num_symbols", "cfg_edge_count", "mach_port_function_count"],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["comparison_type"] == "same_library_across_ios_versions"
    assert payload["matched_count"] == 2
    assert payload["missing_ios_versions"] == []
    assert payload["resolved_observations"] == [
        {
            "requested_ios_version": "6.0",
            "matched_observation_count": 1,
            "selected_ios_version": "iPhone5,1_6.0_10A405",
            "selected_ios_release": "6.0",
            "selected_build_number": "10A405",
        },
        {
            "requested_ios_version": "7.0",
            "matched_observation_count": 1,
            "selected_ios_version": "iPhone5,1_7.0_11A465",
            "selected_ios_release": "7.0",
            "selected_build_number": "11A465",
        },
    ]

    rows_by_metric = {row["metric"]: row for row in payload["results"]}
    assert rows_by_metric["num_symbols"]["values"] == {
        "iPhone5,1_6.0_10A405": 313,
        "iPhone5,1_7.0_11A465": 350,
    }
    assert rows_by_metric["num_symbols"]["leader"] == "iPhone5,1_7.0_11A465"
    assert rows_by_metric["num_symbols"]["from_version"] == "iPhone5,1_6.0_10A405"
    assert rows_by_metric["num_symbols"]["to_version"] == "iPhone5,1_7.0_11A465"
    assert rows_by_metric["num_symbols"]["from_value"] == 313
    assert rows_by_metric["num_symbols"]["to_value"] == 350
    assert rows_by_metric["num_symbols"]["absolute_delta"] == 37
    assert rows_by_metric["num_symbols"]["direction"] == "increased"
    assert rows_by_metric["cfg_edge_count"]["absolute_delta"] == 72
    assert rows_by_metric["mach_port_function_count"]["absolute_delta"] == 1
