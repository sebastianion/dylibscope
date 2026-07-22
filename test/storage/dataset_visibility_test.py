from __future__ import annotations

from dylibscope.storage.repository import dataset_accessible, list_datasets
from dylibscope.storage.schema import connect, datasets, initialize_database


def test_dataset_visibility_filters_private_rows_by_owner() -> None:
    conn = connect(":memory:")
    try:
        initialize_database(conn)
        conn.execute(
            datasets.insert(),
            [
                {
                    "name": "public-baseline",
                    "source": "public_baseline",
                    "visibility": "public",
                    "owner_user_id": None,
                    "source_type": "public_baseline",
                    "trust_level": "verified_pipeline_output",
                },
                {
                    "name": "alice-manual",
                    "source": "user_manual",
                    "visibility": "private",
                    "owner_user_id": "alice",
                    "source_type": "user_manual",
                    "trust_level": "user_provided_unverified",
                },
                {
                    "name": "bob-manual",
                    "source": "user_manual",
                    "visibility": "private",
                    "owner_user_id": "bob",
                    "source_type": "user_manual",
                    "trust_level": "user_provided_unverified",
                },
            ],
        )
        conn.commit()

        public_names = [item["name"] for item in list_datasets(conn)]
        alice_names = [item["name"] for item in list_datasets(conn, owner_user_id="alice")]

        assert public_names == ["public-baseline"]
        assert alice_names == ["public-baseline", "alice-manual"]
        assert dataset_accessible(conn, "public-baseline")
        assert not dataset_accessible(conn, "alice-manual")
        assert dataset_accessible(conn, "alice-manual", owner_user_id="alice")
        assert not dataset_accessible(conn, "bob-manual", owner_user_id="alice")
    finally:
        conn.close()
