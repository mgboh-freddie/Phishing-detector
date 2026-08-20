import pytest

from api import store
from api.auth import AuthError, authenticate, check_rate_limit


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "auth.db")
    store.init_db(path)
    return path


def test_missing_header_is_rejected(db):
    with pytest.raises(AuthError) as exc:
        authenticate(db, None)
    assert exc.value.status == 401


@pytest.mark.parametrize(
    "header", ["", "sk_live_abc", "Basic abc", "Bearer", "Bearer  "]
)
def test_malformed_header_is_rejected(db, header):
    with pytest.raises(AuthError):
        authenticate(db, header)


def test_unknown_key_is_rejected(db):
    with pytest.raises(AuthError):
        authenticate(db, "Bearer sk_live_doesnotexist")


def test_valid_key_authenticates(db):
    key_id, plaintext = store.create_key(db, "sam")
    row = authenticate(db, f"Bearer {plaintext}")
    assert row["id"] == key_id


def test_revoked_key_is_rejected(db):
    key_id, plaintext = store.create_key(db, "sam")
    store.revoke_key(db, key_id)
    with pytest.raises(AuthError):
        authenticate(db, f"Bearer {plaintext}")


def test_rate_limit_allows_up_to_the_cap(db):
    key_id, _ = store.create_key(db, "sam", rate_limit=3)
    for _ in range(3):
        check_rate_limit(db, key_id, 3)


def test_rate_limit_rejects_past_the_cap(db):
    key_id, _ = store.create_key(db, "sam", rate_limit=2)
    check_rate_limit(db, key_id, 2)
    check_rate_limit(db, key_id, 2)

    with pytest.raises(AuthError) as exc:
        check_rate_limit(db, key_id, 2)

    assert exc.value.status == 429
    assert exc.value.retry_after > 0
