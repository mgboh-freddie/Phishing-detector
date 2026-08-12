import pytest

from api import store


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "test.db")
    store.init_db(path)
    return path


def test_init_db_is_idempotent(db):
    store.init_db(db)
    store.init_db(db)


def test_ids_are_prefixed_and_strictly_increasing():
    """Two ids created in the same millisecond must still sort correctly,
    or 'newest first' ordering is unreliable."""
    ids = [store.new_id("scn") for _ in range(50)]

    assert all(i.startswith("scn_") for i in ids)
    assert len(set(ids)) == 50
    assert ids == sorted(ids)


def test_create_key_returns_plaintext_once_and_stores_only_a_hash(db):
    key_id, plaintext = store.create_key(db, "sam")

    assert plaintext.startswith("sk_live_")
    assert len(plaintext) > 20

    with store.connect(db) as conn:
        row = conn.execute(
            "SELECT key_hash FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()

    assert plaintext not in row["key_hash"]
    assert row["key_hash"] == store.hash_key(plaintext)


def test_find_key_by_hash_round_trips(db):
    key_id, plaintext = store.create_key(db, "sam", threshold=0.5, rate_limit=10)

    row = store.find_key_by_hash(db, store.hash_key(plaintext))

    assert row["id"] == key_id
    assert row["name"] == "sam"
    assert row["threshold"] == 0.5
    assert row["rate_limit"] == 10
    assert row["revoked_at"] is None


def test_unknown_hash_returns_none(db):
    assert store.find_key_by_hash(db, "deadbeef") is None


def test_revoke_marks_the_key(db):
    key_id, plaintext = store.create_key(db, "sam")

    assert store.revoke_key(db, key_id) is True

    row = store.find_key_by_hash(db, store.hash_key(plaintext))
    assert row["revoked_at"] is not None


def test_revoking_an_unknown_key_returns_false(db):
    assert store.revoke_key(db, "key_nope") is False


def make_record(key_id, **overrides):
    record = {
        "id": store.new_id("scn"),
        "key_id": key_id,
        "source": "url",
        "target": "https://example.com/",
        "content_sha256": "a" * 64,
        "score": 0.69,
        "verdict": "phishing",
        "threshold": 0.30,
        "features": {"tag_count": 91},
        "warnings": ["small_simple_site"],
        "tls_verified": True,
        "model_version": "abc123",
        "elapsed_ms": 412,
        "raw_html": "<html></html>",
    }
    record.update(overrides)
    return record


def test_save_and_read_back_a_scan(db):
    key_id, _ = store.create_key(db, "sam")
    record = make_record(key_id)

    store.save_scan(db, record, store_raw_html=False)
    fetched = store.get_scan(db, key_id, record["id"])

    assert fetched["score"] == 0.69
    assert fetched["verdict"] == "phishing"
    assert fetched["features"] == {"tag_count": 91}
    assert fetched["warnings"] == ["small_simple_site"]
    assert fetched["tls_verified"] is True


def test_raw_html_is_not_stored_by_default(db):
    key_id, _ = store.create_key(db, "sam")
    record = make_record(key_id)

    store.save_scan(db, record, store_raw_html=False)

    with store.connect(db) as conn:
        row = conn.execute(
            "SELECT raw_html FROM scans WHERE id = ?", (record["id"],)
        ).fetchone()
    assert row["raw_html"] is None


def test_raw_html_is_stored_when_enabled(db):
    key_id, _ = store.create_key(db, "sam")
    record = make_record(key_id)

    store.save_scan(db, record, store_raw_html=True)

    with store.connect(db) as conn:
        row = conn.execute(
            "SELECT raw_html FROM scans WHERE id = ?", (record["id"],)
        ).fetchone()
    assert row["raw_html"] == "<html></html>"


def test_history_is_scoped_to_the_calling_key(db):
    mine, _ = store.create_key(db, "mine")
    theirs, _ = store.create_key(db, "theirs")

    store.save_scan(db, make_record(mine), store_raw_html=False)
    store.save_scan(db, make_record(theirs), store_raw_html=False)

    assert len(store.list_scans(db, mine)) == 1
    assert len(store.list_scans(db, theirs)) == 1


def test_another_keys_scan_is_not_readable(db):
    mine, _ = store.create_key(db, "mine")
    theirs, _ = store.create_key(db, "theirs")
    record = make_record(theirs)
    store.save_scan(db, record, store_raw_html=False)

    assert store.get_scan(db, mine, record["id"]) is None


def test_history_is_newest_first_and_paginates(db):
    key_id, _ = store.create_key(db, "sam")
    ids = []
    for _ in range(5):
        record = make_record(key_id)
        store.save_scan(db, record, store_raw_html=False)
        ids.append(record["id"])

    rows = store.list_scans(db, key_id, limit=2, offset=0)
    assert [r["id"] for r in rows] == [ids[4], ids[3]]

    rows = store.list_scans(db, key_id, limit=2, offset=2)
    assert [r["id"] for r in rows] == [ids[2], ids[1]]
