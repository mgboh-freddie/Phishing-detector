"""API key management.

    python -m api.keys create --name "sam"
    python -m api.keys list
    python -m api.keys revoke key_xxx

Deliberately a CLI and not an HTTP endpoint. An admin endpoint would
need an admin credential to protect it, which is a chicken-and-egg not
worth solving for a handful of users.
"""

import argparse
import sys

from api import store
from api.config import get_settings


def _create(settings, args) -> int:
    if args.threshold is not None and not 0.0 <= args.threshold <= 1.0:
        print("threshold must be between 0 and 1.", file=sys.stderr)
        return 1

    store.init_db(settings.db_path)
    key_id, plaintext = store.create_key(
        settings.db_path,
        name=args.name,
        threshold=args.threshold,
        rate_limit=args.rate_limit,
    )

    print(f"Created key {key_id} for {args.name!r}.")
    print("Store it now. It is shown once and cannot be recovered:")
    print(f"  {plaintext}")
    return 0


def _list(settings, args) -> int:
    store.init_db(settings.db_path)
    rows = store.list_keys(settings.db_path)

    if not rows:
        print("No keys yet. Create one with: python -m api.keys create --name NAME")
        return 0

    print(f"{'ID':<32} {'NAME':<16} {'THRESH':>7} {'RATE':>6}  STATUS")
    for row in rows:
        status = "revoked" if row["revoked_at"] else "active"
        print(
            f"{row['id']:<32} {row['name']:<16} {row['threshold']:>7.2f}"
            f" {row['rate_limit']:>6}  {status}"
        )
    return 0


def _revoke(settings, args) -> int:
    store.init_db(settings.db_path)
    if store.revoke_key(settings.db_path, args.key_id):
        print(f"Key {args.key_id} revoked.")
        return 0
    print(f"No active key with id {args.key_id}.", file=sys.stderr)
    return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m api.keys")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Create a new API key")
    create.add_argument("--name", required=True)
    create.add_argument("--threshold", type=float, default=None)
    create.add_argument("--rate-limit", type=int, default=60)

    sub.add_parser("list", help="List keys")

    revoke = sub.add_parser("revoke", help="Revoke a key")
    revoke.add_argument("key_id")

    args = parser.parse_args(argv)
    settings = get_settings()

    return {"create": _create, "list": _list, "revoke": _revoke}[args.command](
        settings, args
    )


if __name__ == "__main__":
    raise SystemExit(main())
