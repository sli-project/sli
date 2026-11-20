"""Verify a restored owner's secret and fresh login; never reset credentials."""

from __future__ import annotations

import argparse
from http.cookiejar import CookieJar
import json
from pathlib import Path
import ssl
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from argon2.exceptions import InvalidHashError, VerificationError

from deploy.linux import backup
from server.sli.access.auth import PASSWORD_HASHER, SESSION_COOKIE


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_login(password_file: Path, base_url: str, ca_file: str | None) -> None:
    """Use only the supplied restored secret, checked against the restored DB."""
    url = urlsplit(base_url)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.path not in {"", "/"} or url.query or url.fragment):
        raise ValueError("linux_restore_invalid_login_url")
    password = password_file.read_text(encoding="utf-8").rstrip("\r\n")
    with backup.pg_passfile() as passfile, backup.pg_connect(passfile) as connection:
        row = connection.execute(
            "SELECT id, password_hash, is_active FROM public.auth_users WHERE lower(username)=lower(%s)",
            ("platform-owner",),
        ).fetchone()
    try:
        valid = bool(row and row[2] and PASSWORD_HASHER.verify(row[1], password))
    except (VerificationError, InvalidHashError):
        valid = False
    if not valid:
        raise RuntimeError("linux_restore_owner_credentials_mismatch")
    # No browser session, API token, proxy environment or redirect can substitute
    # for the password login being verified here.
    cookies = CookieJar()
    opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPCookieProcessor(cookies),
                          HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
    origin = base_url.rstrip("/")
    request = Request(origin + "/api/auth/login", data=json.dumps({
        "username": "platform-owner", "password": password,
    }).encode("utf-8"), headers={"Content-Type": "application/json", "Origin": origin})
    try:
        with opener.open(request, timeout=30) as response:
            if response.code != 200:
                raise RuntimeError("linux_restore_fresh_login_failed")
        if not any(cookie.name == SESSION_COOKIE and cookie.value for cookie in cookies):
            raise RuntimeError("linux_restore_fresh_login_failed")
        with opener.open(Request(origin + "/api/auth/me"), timeout=30) as response:
            document = json.loads(response.read(1024 * 1024))
            principal = document.get("principal", {})
            if (response.code != 200 or document.get("authenticated") is not True
                    or principal.get("type") != "session" or principal.get("id") != row[0]):
                raise RuntimeError("linux_restore_fresh_login_failed")
    except HTTPError:
        raise RuntimeError("linux_restore_fresh_login_failed") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--password-file", type=Path, required=True,
                        help="Protected owner secret belonging to the restored backup")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--ca-file")
    args = parser.parse_args(argv)
    try:
        if args.project.lower() == "sli":
            raise ValueError("linux_restore_production_project_refused")
        check_login(args.password_file, args.base_url, args.ca_file)
    except Exception:  # noqa: BLE001 - never expose credentials, hashes or HTTP bodies
        print("linux_restore_login_check_failed", file=sys.stderr)
        return 1
    print("linux_restore_fresh_login_verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
