"""Interactive local DPAPI provisioning; never starts a collector or contacts AD."""
from __future__ import annotations

import argparse
import getpass
import hmac
import json
import os
from pathlib import Path
import re
import sys
import warnings

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's normal error can echo an accidentally supplied password value.
        self.exit(2, "Invalid arguments. Use --help; passwords are accepted only in the local hidden prompt.\n")


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=SafeArgumentParser)
    provision = commands.add_parser("provision", help="Prompt locally and encrypt for the current Windows user.")
    provision.add_argument("--username", required=True, help="Exact DOMAIN\\login or UPN; no normalization.")
    provision.add_argument("--replace", action="store_true", help="Explicitly replace only this credential store.")
    provision.add_argument("--single-entry", action="store_true", help="Explicitly request one hidden entry without confirmation.")
    check = commands.add_parser("check", help="Verify decryption without printing credential values.")
    check.add_argument("--username", help="Optionally require an exact account match.")
    from server.sli.sources.ad_source_credentials import CredentialProfile
    for command in (provision, check):
        command.add_argument("--profile", choices=[item.value for item in CredentialProfile], default="ad",
                             help="Separate local credential profile; defaults to the existing AD store.")
        command.add_argument("--pause", action="store_true", help="Keep the local console open after the outcome; never retries password entry.")
    return parser


def validate_username(value: str) -> str:
    from server.sli.sources.ad_source_credentials import AdCredentialStoreError, validate_username as validate

    try:
        return validate(value)
    except AdCredentialStoreError:
        raise ValueError("invalid_username") from None


def _print_metadata(result: dict[str, object]) -> None:
    allowed = {"status", "dpapi_scope", "owner_matches", "account_matches", "error_code", "path", "stored", "replaced"}
    safe = {name: value for name, value in result.items() if name in allowed}
    print(json.dumps(safe, ensure_ascii=True), flush=True)


def _error(code: str) -> int:
    safe_code = code if re.fullmatch(r"[a-z0-9_]+", code) else "credential_operation_failed"
    _print_metadata({"status": "error", "error_code": safe_code})
    return 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _execute(args)
    finally:
        if args.pause and sys.stdin.isatty():
            try:
                input("Press Enter to close. ")
            except (KeyboardInterrupt, EOFError, OSError):
                pass


def _execute(args: argparse.Namespace) -> int:
    if os.name != "nt":
        return _error("windows_dpapi_required")
    if args.username is not None:
        try:
            validate_username(args.username)
        except ValueError:
            return _error("invalid_username")
    from server.sli.sources import ad_source_credentials as store

    try:
        if args.command == "check":
            result = store.credentials_status(expected_username=args.username, profile=args.profile)
            _print_metadata(result)
            return 0 if result.get("status") == "ready" and result.get("account_matches") is not False else 1
        existing = store.credentials_status(profile=args.profile)
        if existing.get("status") != "missing" and not args.replace:
            return _error("credential_already_exists")
        if not sys.stdin.isatty():
            return _error("interactive_console_required")
        print(f"SLI: save the {args.profile} profile password for this local Windows user.", flush=True)
        print(f"Domain account: {args.username}", flush=True)
        print("No domain connection, collector start or service change will be performed.", flush=True)
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Password (hidden): ")
            if not password:
                return _error("empty_password")
            confirmation = password if args.single_entry else getpass.getpass("Repeat password (hidden): ")
        if not hmac.compare_digest(password.encode("utf-8"), confirmation.encode("utf-8")):
            return _error("password_confirmation_mismatch")
        store.store_credentials(args.username, password, replace=args.replace, profile=args.profile)
        password = confirmation = ""
        result = store.credentials_status(expected_username=args.username, profile=args.profile)
        _print_metadata(result)
        return 0 if result.get("status") == "ready" and result.get("account_matches") is True else 1
    except store.AdCredentialStoreError as exc:
        return _error(exc.code)
    except (KeyboardInterrupt, EOFError):
        return _error("cancelled")
    except getpass.GetPassWarning:
        return _error("secure_console_required")
    except Exception:
        # Never print a raw exception: secret payloads must not reach diagnostics.
        return _error("credential_operation_failed")


if __name__ == "__main__":
    raise SystemExit(main())
