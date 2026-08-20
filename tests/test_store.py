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


def test_ids_remain_strictly_increasing_after_backward_clock_step(monkeypatch):
    """If the system clock steps backward, ids must still sort strictly
    increasing. The timestamp is clamped to the highest seen value, so the
    counter increments instead of the timestamp moving backward."""
    # Start with a baseline time: 1000ms since epoch
    clock_ms = [1000]

    def mock_time():
        return clock_ms[0] / 1000.0

    monkeypatch.setattr("api.store.time.time", mock_time)

    # Issue several ids with advancing time
    ids_phase1 = [store.new_id("scn") for _ in range(5)]
    clock_ms[0] += 100  # advance to 1100ms
    ids_phase2 = [store.new_id("scn") for _ in range(5)]

    # Step the clock backward from 1100ms to 800ms (simulate an NTP correction)
    clock_ms[0] = 800
    # Issue more ids despite the backward step
    ids_phase3 = [store.new_id("scn") for _ in range(5)]

    all_ids = ids_phase1 + ids_phase2 + ids_phase3
    assert len(set(all_ids)) == 15, "All ids must be unique"
    assert all_ids == sorted(all_ids), "Ids must remain strictly increasing despite clock step backward"


def test_counter_overflow_borrows_a_millisecond_instead_of_wrapping(monkeypatch):
    """A sustained backward clock step pins the timestamp while the counter
    keeps incrementing. If the counter were allowed to run past its width,
    _encode would wrap it back to 0 and produce a duplicate, out-of-order
    id. It must instead borrow a millisecond and restart the counter there.

    The clock is frozen so it cannot advance on its own, and the module's
    counter state is parked one step below its limit so only a handful of
    ids are needed to cross the boundary -- generating a million ids here
    would make the suite crawl.
    """
    frozen_ms = 5_000_000

    def mock_time():
        return frozen_ms / 1000.0

    monkeypatch.setattr("api.store.time.time", mock_time)

    original_stamp = list(store._last_stamp)
    store._last_stamp[0] = frozen_ms
    store._last_stamp[1] = store.COUNTER_LIMIT - 3
    try:
        ids = [store.new_id("scn") for _ in range(6)]
    finally:
        store._last_stamp[0] = original_stamp[0]
        store._last_stamp[1] = original_stamp[1]

    assert len(set(ids)) == 6, "Ids must stay unique across a counter overflow"
    assert ids == sorted(ids), "Ids must stay strictly increasing across a counter overflow"


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
