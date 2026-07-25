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


def test_create_user_observation_requires_authentication(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    client = TestClient(create_app(db_path=db_path))

    response = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "new_private_dataset",
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
            "target_mode": "new_private_dataset",
            "conflict_mode": "reject",
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
    assert payload["operation"] == "saved_user_observation"
    assert payload["target_mode"] == "new_private_dataset"
    assert payload["conflict_mode"] == "reject"
    assert payload["manual_write_operation"] == "created"
    assert payload["source_dataset_name"] is None
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


def test_user_observation_appends_to_existing_private_dataset(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user
    client = TestClient(app)

    create_response = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "new_private_dataset",
            "dataset_name": "alice-manual",
            "library": "libManualOne.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 10},
        },
    )
    assert create_response.status_code == 201

    append_response = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "append_private_dataset",
            "dataset_name": "alice-manual",
            "library": "libManualTwo.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 12, "cfg_edge_count": 24},
        },
    )

    assert append_response.status_code == 201
    payload = append_response.json()
    assert payload["target_mode"] == "append_private_dataset"
    assert payload["dataset_name"] == "alice-manual"
    assert payload["manual_write_operation"] == "created"
    assert payload["dataset_source_type"] == "user_manual"

    datasets = client.get("/v1/datasets").json()["datasets"]
    assert [item["name"] for item in datasets] == ["alice-manual"]

    libraries = client.get("/v1/libraries", params={"dataset_name": "alice-manual"}).json()
    assert libraries["count"] == 2
    assert {item["display_name"] for item in libraries["libraries"]} == {
        "libManualOne.dylib",
        "libManualTwo.dylib",
    }


def test_private_dataset_names_are_scoped_per_owner(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user
    client = TestClient(app)

    alice_response = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "new_private_dataset",
            "dataset_name": "shared-name",
            "library": "libAlice.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 10},
        },
    )
    assert alice_response.status_code == 201

    duplicate_for_same_user = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "new_private_dataset",
            "dataset_name": "shared-name",
            "library": "libAliceTwo.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 11},
        },
    )
    assert duplicate_for_same_user.status_code == 409

    app.dependency_overrides[require_current_user] = fake_user_bob
    app.dependency_overrides[get_optional_current_user] = fake_optional_user_bob

    bob_response = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "new_private_dataset",
            "dataset_name": "shared-name",
            "library": "libBob.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 12},
        },
    )
    assert bob_response.status_code == 201
    assert bob_response.json()["observation"]["dataset_owner_user_id"] == "bob"

    bob_libraries = client.get("/v1/libraries", params={"dataset_name": "shared-name"}).json()
    assert {item["display_name"] for item in bob_libraries["libraries"]} == {"libBob.dylib"}

    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user

    alice_libraries = client.get("/v1/libraries", params={"dataset_name": "shared-name"}).json()
    assert {item["display_name"] for item in alice_libraries["libraries"]} == {"libAlice.dylib"}


def test_user_observation_rejects_duplicate_observation_by_default_and_allows_replace(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    app.dependency_overrides[get_optional_current_user] = fake_optional_user
    client = TestClient(app)

    create_response = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "new_private_dataset",
            "dataset_name": "alice-manual",
            "library": "libManual.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 10, "cfg_edge_count": 20},
        },
    )
    assert create_response.status_code == 201

    duplicate_response = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "append_private_dataset",
            "conflict_mode": "reject",
            "dataset_name": "alice-manual",
            "library": "libManual.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 99},
        },
    )
    assert duplicate_response.status_code == 409

    replace_response = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "append_private_dataset",
            "conflict_mode": "replace",
            "dataset_name": "alice-manual",
            "library": "libManual.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 99},
        },
    )
    assert replace_response.status_code == 201
    payload = replace_response.json()
    assert payload["manual_write_operation"] == "replaced"
    assert payload["observation"]["metrics"]["num_symbols"]["value"] == 99
    assert "cfg_edge_count" not in payload["observation"]["metrics"]


def test_user_observation_rejects_public_baseline_and_context_only_metrics(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    client = TestClient(app)

    public_response = client.post(
        "/v1/user-observations",
        json={
            "target_mode": "new_private_dataset",
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
            "target_mode": "new_private_dataset",
            "dataset_name": "alice-manual",
            "library": "libManual.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"exported_function_count": 3},
        },
    )
    assert context_only_response.status_code == 422


def test_user_observation_requires_target_mode(tmp_path: Path) -> None:
    db_path = build_empty_test_db(tmp_path)
    app = create_app(db_path=db_path)
    app.dependency_overrides[require_current_user] = fake_user
    client = TestClient(app)

    response = client.post(
        "/v1/user-observations",
        json={
            "dataset_name": "alice-manual",
            "library": "libManual.dylib",
            "ios_version": "iPhone15,2_17.0_21A329",
            "metrics": {"num_symbols": 10},
        },
    )

    assert response.status_code == 422
