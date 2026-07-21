from dylibscope.storage.schema import create_db_engine, dispose_cached_engines


def test_create_db_engine_reuses_engine_for_same_url(monkeypatch):
    dispose_cached_engines()
    monkeypatch.setenv("DYLIBSCOPE_DB_POOL_SIZE", "2")
    monkeypatch.setenv("DYLIBSCOPE_DB_MAX_OVERFLOW", "0")

    url = "postgresql+psycopg://user:password@localhost:5432/dylibscope_test"
    first = create_db_engine(url)
    second = create_db_engine(url)

    assert first is second
    assert first.pool.size() == 2

    dispose_cached_engines()
