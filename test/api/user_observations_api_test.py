from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi.testclient import TestClient

from dylibscope.api.app import create_app
from dylibscope.api.auth import CurrentUser, get_optional_current_user, require_current_user
from dylibscope.storage.schema import connect, initialize_database


def build_empty_test_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "dylibscope.sqlite"
    conn = connect(str(db_path))
    try:
        initialize_database(conn)
    finally:
        conn.close()
    return db_path


def fake_user() -> CurrentUser:
    return CurrentUser(user_id="alice", role="authenticated", is_anonymous=True)


def fake_optional_user() -> Optional[CurrentUser]:
    return fake_user()


def test_create_user_observation_requires_authentication(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    response = client.post(
        "/v1/user-observations",
        json={
            "dataset_name": "alice-manual",
            "library": "libManual.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 10},
        },
    )

    assert response.status_code == 401


def test_create_user_observation_creates_private_dataset_and_metrics(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user
    client = TestClient(app)

    response = client.post(
        "/v1/user-observations",
        json={
            "dataset_name": "alice-manual",
            "library": "libManual.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {
                "num_symbols": 10,
                "imported_function_count": 2,
                "num_sections": 4,
                "cfg_edge_count": 20,
                "deployment_target": "17.0.0",
                "imported_functions": ["_malloc", "_free"],
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["operation"] == "upserted_user_observation"
    assert payload["dataset_visibility"] == "private"
    assert payload["dataset_source_type"] == "user_manual"
    assert payload["dataset_trust_level"] == "user_provided_unverified"
    assert payload["observation"]["dataset"] == "alice-manual"
    assert payload["observation"]["dataset_owner_user_id"] == "alice"
    assert payload["observation"]["metrics"]["num_symbols"]["value"] == 10
    assert payload["observation"]["metrics"]["imported_functions"]["value"] == ["_malloc", "_free"]

    datasets = client.get("/v1/datasets").json()["datasets"]
    assert [item["name"] for item in datasets] == ["alice-manual"]
    assert datasets[0]["source_type"] == "user_manual"
    assert datasets[0]["trust_level"] == "user_provided_unverified"

    libraries = client.get("/v1/libraries", params={"dataset_name": "alice-manual"}).json()
    assert libraries["count"] == 1
    assert libraries["libraries"][0]["display_name"] == "libManual.dylib"

    metrics = client.get(
        "/v1/libraries/libManual.dylib/metrics",
        params={"dataset_name": "alice-manual", "ios_version": "17.0"},
    ).json()
    assert metrics["count"] == 1
    assert metrics["observations"][0]["metrics"]["cfg_edge_count"]["value"] == 20


def test_user_observation_rejects_public_baseline_and_context_only_metrics(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    client = TestClient(app)

    public_response = client.post(
        "/v1/user-observations",
        json={
            "dataset_name": "public-baseline",
            "library": "libManual.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 10},
        },
    )
    assert public_response.status_code == 422

    context_only_response = client.post(
        "/v1/user-observations",
        json={
            "dataset_name": "alice-manual",
            "library": "libManual.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"exported_function_count": 3},
        },
    )
    assert context_only_response.status_code == 422
