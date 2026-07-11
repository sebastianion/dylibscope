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


def test_library_security_report_snapshot(tmp_path: Path) -> None:
    db_path = build_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    response = client.get(
        "/v1/libraries/libsqlite3.0.dylib/security-report",
        params={"dataset_name": "public-baseline", "ios_version": "6.0"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["report_type"] == "library_security_report"
    assert payload["library"] == "libsqlite3.0.dylib"
    assert payload["observation_count"] == 1
    score = payload["observations"][0]["score"]
    assert score["score"] is not None
    assert score["band"] in {"low_static_complexity", "medium_static_complexity", "high_static_complexity"}
    assert score["interpretation_note"]


def test_library_security_report_transition(tmp_path: Path) -> None:
    db_path = build_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    response = client.get(
        "/v1/libraries/libsqlite3.0.dylib/security-report",
        params={
            "dataset_name": "public-baseline",
            "from_ios_version": "6.0",
            "to_ios_version": "7.0",
            "metrics": "num_symbols,cfg_edge_count,mach_port_function_count",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["report_type"] == "library_transition_security_report"
    assert payload["resolved_observations"][0]["selected_ios_version"] == "iPhone5,1_6.0_10A405"
    assert payload["resolved_observations"][1]["selected_ios_version"] == "iPhone5,1_7.0_11A465"
    assert payload["from_score"]["score"] is not None
    assert payload["to_score"]["score"] is not None
    assert payload["trend"]["from_version"] == "iPhone5,1_6.0_10A405"
    assert payload["trend"]["to_version"] == "iPhone5,1_7.0_11A465"
    metric_deltas = {item["metric"]: item for item in payload["trend"]["metric_deltas"]}
    assert metric_deltas["num_symbols"]["absolute_delta"] == 37
    assert metric_deltas["cfg_edge_count"]["absolute_delta"] == 72
    assert metric_deltas["mach_port_function_count"]["absolute_delta"] == 1


def test_ios_version_security_summary(tmp_path: Path) -> None:
    db_path = build_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    response = client.get(
        "/v1/ios-versions/6.0/security-summary",
        params={"dataset_name": "public-baseline", "limit": 5},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary_type"] == "ios_version_security_summary"
    assert payload["ios_version_filter"] == "6.0"
    assert payload["observation_count"] == 2
    assert payload["score_statistics"]["average_score"] is not None
    assert len(payload["top_libraries"]) == 2
    assert {item["library"] for item in payload["top_libraries"]} == {
        "libsqlite3.0.dylib",
        "libresolv.dylib",
    }
