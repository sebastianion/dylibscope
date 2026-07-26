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


def test_delete_user_dataset_requires_authentication(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    response = client.delete("/v1/user-datasets/alice-manual")

    assert response.status_code == 401


def test_delete_user_dataset_removes_private_dataset_observations_and_metrics(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user
    client = TestClient(app)

    create_response = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "new_private_dataset",
            "dataset_name": "delete-me",
            "library": "libDeleteMe.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 10, "cfg_edge_count": 20},
        },
    )
    assert create_response.status_code == 201

    delete_response = client.delete("/v1/user-datasets/delete-me")

    assert delete_response.status_code == 200
    payload = delete_response.json()
    assert payload["deleted"] is True
    assert payload["dataset_name"] == "delete-me"
    assert payload["deleted_observations"] == 1
    assert payload["deleted_metric_values"] == 2

    datasets = client.get("/v1/datasets").json()["datasets"]
    assert "delete-me" not in [item["name"] for item in datasets]

    libraries = client.get("/v1/libraries", params={"dataset_name": "delete-me"})
    assert libraries.status_code == 404


def test_delete_user_dataset_does_not_delete_other_users_private_dataset(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user
    client = TestClient(app)

    create_response = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "new_private_dataset",
            "dataset_name": "alice-only",
            "library": "libAliceOnly.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 10},
        },
    )
    assert create_response.status_code == 201

    app.dependency_overrides[require_current_user] = fake_user_bob
    app.dependency_overrides[get_optional_current_user] = fake_optional_user_bob

    delete_response = client.delete("/v1/user-datasets/alice-only")
    assert delete_response.status_code == 404

    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user

    datasets = client.get("/v1/datasets").json()["datasets"]
    assert "alice-only" in [item["name"] for item in datasets]


def test_delete_user_dataset_rejects_public_baseline_name(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user
    client = TestClient(app)

    response = client.delete("/v1/user-datasets/public-baseline")

    assert response.status_code == 403
