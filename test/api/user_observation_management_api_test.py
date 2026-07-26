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


def fake_user_bob() -> CurrentUser:
    return CurrentUser(user_id="bob", role="authenticated", is_anonymous=True)


def fake_optional_user() -> Optional[CurrentUser]:
    return fake_user()


def fake_optional_user_bob() -> Optional[CurrentUser]:
    return fake_user_bob()


def create_manual_observation(client: TestClient, *, library: str, ios_version: str = "iPhone15,2_17.0_21A329") -> None:
    response = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "append_private_dataset",
            "dataset_name": "alice-manual",
            "library": library,
            "ios_version": ios_version,
            "metrics": {"num_symbols": 10, "cfg_edge_count": 20},
        },
    )
    assert response.status_code == 201


def test_list_user_observations_requires_authentication(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    response = client.get("/v1/user-observations", params={"dataset_name": "alice-manual"})

    assert response.status_code == 401


def test_delete_user_observation_requires_authentication(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    response = client.delete(
        "/v1/user-observations",
        params={"dataset_name": "alice-manual", "library": "libManual.dylib", "ios_version": "17.0"},
    )

    assert response.status_code == 401


def test_list_user_observations_returns_private_dataset_entries(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user
    client = TestClient(app)

    create_dataset = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "new_private_dataset",
            "dataset_name": "alice-manual",
            "library": "libManualOne.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 10, "deployment_target": "17.0.0"},
        },
    )
    assert create_dataset.status_code == 201
    create_manual_observation(client, library="libManualTwo.dylib")

    response = client.get("/v1/user-observations", params={"dataset_name": "alice-manual"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["dataset_name"] == "alice-manual"
    assert payload["count"] == 2
    assert {item["library"] for item in payload["observations"]} == {"libManualOne.dylib", "libManualTwo.dylib"}
    first = next(item for item in payload["observations"] if item["library"] == "libManualOne.dylib")
    assert first["dataset_visibility"] == "private"
    assert first["metric_count"] == 2
    assert first["metrics"]["num_symbols"]["value"] == 10
    assert first["metrics"]["deployment_target"]["value"] == "17.0.0"


def test_delete_user_observation_removes_only_one_entry(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user
    client = TestClient(app)

    create_dataset = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "new_private_dataset",
            "dataset_name": "alice-manual",
            "library": "libManualOne.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 10, "cfg_edge_count": 20},
        },
    )
    assert create_dataset.status_code == 201
    create_manual_observation(client, library="libManualTwo.dylib")

    delete_response = client.delete(
        "/v1/user-observations",
        params={
            "dataset_name": "alice-manual",
            "library": "libManualOne.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
        },
    )

    assert delete_response.status_code == 200
    payload = delete_response.json()
    assert payload["deleted"] is True
    assert payload["deleted_observations"] == 1
    assert payload["deleted_metric_values"] == 2

    remaining = client.get("/v1/user-observations", params={"dataset_name": "alice-manual"}).json()
    assert remaining["count"] == 1
    assert remaining["observations"][0]["library"] == "libManualTwo.dylib"

    datasets = client.get("/v1/datasets").json()["datasets"]
    assert [item["name"] for item in datasets] == ["alice-manual"]
    assert datasets[0]["observation_count"] == 1


def test_user_observation_management_does_not_cross_user_boundaries(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user
    client = TestClient(app)

    create_dataset = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "new_private_dataset",
            "dataset_name": "alice-manual",
            "library": "libAliceOnly.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 10},
        },
    )
    assert create_dataset.status_code == 201

    app.dependency_overrides[require_current_user] = fake_user_bob
    app.dependency_overrides[get_optional_current_user] = fake_optional_user_bob

    list_response = client.get("/v1/user-observations", params={"dataset_name": "alice-manual"})
    assert list_response.status_code == 404

    delete_response = client.delete(
        "/v1/user-observations",
        params={"dataset_name": "alice-manual", "library": "libAliceOnly.dylib", "ios_version": "17.0"},
    )
    assert delete_response.status_code == 404


def test_user_observation_management_rejects_public_baseline(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user
    client = TestClient(app)

    list_response = client.get("/v1/user-observations", params={"dataset_name": "public-baseline"})
    assert list_response.status_code == 403

    delete_response = client.delete(
        "/v1/user-observations",
        params={"dataset_name": "public-baseline", "library": "libManual.dylib", "ios_version": "17.0"},
    )
    assert delete_response.status_code == 403
