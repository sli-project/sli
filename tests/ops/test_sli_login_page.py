from __future__ import annotations

from pathlib import Path

import pytest

from server.api import http_server
from server.api.routes import static as routes_static

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web" / "app"
LOGIN_ASSETS = {
    "feature-brain.svg",
    "feature-eye.svg",
    "feature-shield.svg",
    "sli-logo.svg",
}
# The scene is one flat illustration. The assembled version it replaced — rays,
# collector, four badges, background map — is in archive/obsolete-repository-20260728.
SCENE_ASSET = "collector-server.svg"


def test_login_page_uses_real_auth_contract_and_accessible_controls() -> None:
    html = (WEB / "login.html").read_text(encoding="utf-8")
    script = (WEB / "sli-login.js").read_text(encoding="utf-8")

    # Versioned, not bare: an unversioned stylesheet URL was served from a stale
    # tab cache and the page rendered unstyled while every other asset loaded.
    assert 'href="/sli-login.css?v=' in html
    assert 'src="/sli-login.js"' in html
    assert 'id="sli-login-form"' in html
    assert 'for="username"' in html and 'name="username"' in html
    assert 'for="password"' in html and 'name="password"' in html
    assert 'name="remember"' in html
    assert 'aria-label="Показать пароль"' in html
    assert 'role="alert"' in html and 'aria-live="polite"' in html
    assert 'fetch("/api/auth/login"' in script
    assert "username: cleanUsername" in script
    assert "password: password.value" in script
    assert "remember: remember.checked" in script
    # Only language is persisted; the application's theme and credentials are untouched.
    assert 'readPreference("sli.locale")' in script
    assert 'localStorage.setItem("sli.locale", locale)' in script
    assert "sli.theme" not in script
    assert 'id="sli-theme"' not in html and 'for="sli-theme"' not in html
    assert 'id="sli-locale"' in html and 'for="sli-locale"' in html
    assert "sessionStorage" not in script


def test_login_redirect_is_same_origin_and_transport_copy_is_truthful() -> None:
    script = (WEB / "sli-login.js").read_text(encoding="utf-8")

    assert "new URL(rawValue, window.location.origin)" in script
    assert "target.origin !== window.location.origin" in script
    assert 'target.pathname === "/login"' in script
    assert "window.location.assign(safeDestination(requested))" in script
    assert 'window.location.protocol !== "https:"' in script
    assert "Локальная HTTP-копия предназначена только для проверки" in script
    assert "secure_transport_required" in script
    assert "login_temporarily_locked" in script


def test_login_layout_contains_approved_desktop_and_mobile_composition() -> None:
    html = (WEB / "login.html").read_text(encoding="utf-8")
    css = (WEB / "sli-login.css").read_text(encoding="utf-8")

    for name in LOGIN_ASSETS:
        assert f'/assets/sli-login/{name}' in html
        asset = WEB / "assets" / "sli-login" / name
        assert asset.is_file()
        assert asset.read_text(encoding="utf-8").lstrip().startswith("<svg")
    assert f'/assets/sli-login/{SCENE_ASSET}' in html
    scene = WEB / "assets" / "sli-login" / SCENE_ASSET
    assert scene.is_file()
    assert scene.read_text(encoding="utf-8").lstrip().startswith("<svg")
    # The retired scene must not creep back: a hidden <img> is still downloaded,
    # which cost about 1.3 MB per page load while the parts lingered behind
    # display:none.
    assert "sli-login-clean" not in html
    assert not (WEB / "assets" / "sli-login-clean").exists()
    assert "grid-template-columns: minmax(0, 1fr) 462px" in css
    assert "@media (max-width: 900px)" in css
    assert ".sli-features," in css and ".sli-scene {" in css
    # Both axes must scale together, otherwise percentages of width and of height
    # drift apart and anything placed inside the scene lands off its mark.
    assert "aspect-ratio: 1672 / 941" in css
    assert "display: none" in css
    assert "min-height: 58px" in css
    assert "@media (prefers-reduced-motion: reduce)" in css


@pytest.mark.parametrize(
    ("request_path", "content_type"),
    [
        ("/sli-login.css", "text/css; charset=utf-8"),
        ("/sli-login.js", "application/javascript; charset=utf-8"),
        ("/assets/sli-login/sli-logo.svg", "image/svg+xml"),
        ("/assets/sli-login/collector-server.svg", "image/svg+xml"),
    ],
)
def test_login_static_asset_allowlist_is_exact(
    request_path: str, content_type: str,
) -> None:
    resolved = routes_static._login_static_asset(request_path)

    assert resolved is not None
    path, actual_content_type = resolved
    assert path.is_file()
    assert actual_content_type == content_type


@pytest.mark.parametrize(
    "request_path",
    [
        "/assets/sli-login/../secret.svg",
        "/assets/sli-login/%2e%2e/secret.svg",
        "/assets/sli-login/unapproved.svg",
        "/assets/sli-login/sli-logo.svg/extra",
        "/sli-login.css.map",
    ],
)
def test_login_static_asset_allowlist_rejects_unknown_paths(request_path: str) -> None:
    assert routes_static._login_static_asset(request_path) is None


def test_login_assets_are_served_before_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = object.__new__(http_server.RequestHandler)
    handler.path = "/assets/sli-login/feature-shield.svg"
    sent: list[tuple[Path, str]] = []
    handler._send_file = lambda path, content_type: sent.append((path, content_type))
    monkeypatch.setattr(http_server, "auth_required", lambda: True)
    monkeypatch.setattr(
        http_server,
        "principal_from_headers",
        lambda _headers: pytest.fail("public login asset must not request a session"),
    )

    handler._do_GET()

    assert sent == [
        (
            WEB / "assets" / "sli-login" / "feature-shield.svg",
            "image/svg+xml",
        )
    ]
