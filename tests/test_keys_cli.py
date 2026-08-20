import pytest

from api import keys, store


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "cli.db"))
    monkeypatch.setenv("DASHBOARD_PASSWORD", "pw")
    monkeypatch.setenv("SECRET_KEY", "sk")
    from api.config import get_settings

    get_settings.cache_clear()
    yield str(tmp_path / "cli.db")
    get_settings.cache_clear()


def test_create_prints_the_key_once(env, capsys):
    exit_code = keys.main(["create", "--name", "sam"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "sk_live_" in output
    assert "shown once" in output.lower()


def test_created_key_authenticates(env, capsys):
    keys.main(["create", "--name", "sam"])
    printed = [
        line for line in capsys.readouterr().out.splitlines() if "sk_live_" in line
    ][0]
    plaintext = printed.split()[-1]

    from api.auth import authenticate

    row = authenticate(env, f"Bearer {plaintext}")
    assert row["name"] == "sam"


def test_create_accepts_threshold_and_rate_limit(env, capsys):
    keys.main(
        ["create", "--name", "sam", "--threshold", "0.5", "--rate-limit", "10"]
    )
    rows = store.list_keys(env)
    created = [r for r in rows if r["name"] == "sam"][0]

    assert created["threshold"] == 0.5
    assert created["rate_limit"] == 10


def test_list_shows_created_keys(env, capsys):
    keys.main(["create", "--name", "sam"])
    capsys.readouterr()

    keys.main(["list"])

    assert "sam" in capsys.readouterr().out


def test_revoke_marks_the_key_and_reports(env, capsys):
    keys.main(["create", "--name", "sam"])
    capsys.readouterr()
    key_id = [r for r in store.list_keys(env) if r["name"] == "sam"][0]["id"]

    assert keys.main(["revoke", key_id]) == 0
    assert "revoked" in capsys.readouterr().out.lower()


def test_revoking_an_unknown_key_exits_nonzero(env, capsys):
    assert keys.main(["revoke", "key_nope"]) == 1


def test_invalid_threshold_is_refused(env):
    assert keys.main(["create", "--name", "sam", "--threshold", "3"]) == 1
