"""Create and administer local web users and API keys without exposing secrets.

Examples (password is requested securely, never supplied on the command line):
  python scripts/auth/manage_auth.py create-user --username operator --role admin
  python scripts/auth/manage_auth.py create-api-key --label integration --role viewer
  python scripts/auth/manage_auth.py revoke-api-key --id 7
"""
from __future__ import annotations

import argparse
import getpass
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.access.auth import create_user, issue_api_key, revoke_api_key  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Security Log Intelligence local authentication.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    user = subcommands.add_parser("create-user")
    user.add_argument("--username", required=True)
    user.add_argument("--role", choices=("viewer", "operator", "admin"), default="admin")
    key = subcommands.add_parser("create-api-key")
    key.add_argument("--label", required=True)
    key.add_argument("--role", choices=("viewer", "operator", "admin"), default="viewer")
    revoke = subcommands.add_parser("revoke-api-key")
    revoke.add_argument("--id", type=int, required=True)
    recovery = subcommands.add_parser("owner-recovery", help="Root console only: issue a single-use owner code (10 minutes)")
    recovery.add_argument("--username", required=True)
    args = parser.parse_args()

    if args.command == "owner-recovery":
        if not sys.stdout.isatty():
            raise SystemExit("terminal_required")
        from server.sli.access.owner_recovery import issue_owner_recovery_code

        try:
            code = issue_owner_recovery_code(args.username)
        except (PermissionError, ValueError) as exc:
            raise SystemExit(str(exc)) from None
        except Exception:
            # Driver errors can carry bound parameters. Never print them.
            raise SystemExit("owner_recovery_issue_failed") from None
        print("Single-use owner recovery code (expires in 10 minutes; password also required):")
        print(code)
        return 0
    if args.command == "create-user":
        password = getpass.getpass("Password (at least 12 characters): ")
        confirmation = getpass.getpass("Repeat password: ")
        if password != confirmation:
            raise SystemExit("Passwords do not match.")
        result = create_user(username=args.username, password=password, role=args.role)
        print(f"Created user id={result['id']} username={result['username']} role={result['role']}")
        return 0
    if args.command == "create-api-key":
        result, secret = issue_api_key(label=args.label, role=args.role)
        print(f"Created API key id={result['id']} label={result['label']} role={result['role']}")
        print("Copy this key now; it cannot be shown again:")
        print(secret)
        return 0
    if revoke_api_key(args.id):
        print(f"Revoked API key id={args.id}")
        return 0
    print(f"Active API key id={args.id} was not found.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
