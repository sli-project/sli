"""Auth domain: login/logout, users, API keys.

Owns everything under /api/auth/* plus the test-only session fixture route.
Shared ambient auth/authz machinery (``_require_access``,
``_authorize_mutation``, ``_require_capability``, ``_public_principal``,
``_read_json_body``, response helpers) stays on ``RequestHandler`` in
``server.api.http_server`` and is reached through the ``handler`` instance
passed to every function here — this module never imports
``server.api.http_server``.
"""
from __future__ import annotations

import logging
import os
import sys
from http import HTTPStatus

from server.api.net_utils import is_loopback_bind_host
from server.sli.access.login_throttle import LoginThrottled
from server.sli.access.auth import (
    SESSION_COOKIE,
    InitialOwnerPasswordError,
    auth_required,
    authenticate_password,
    claim_initial_owner,
    create_user,
    initial_owner_setup_pending,
    issue_api_key,
    issue_session,
    list_api_keys,
    list_users,
    principal_from_headers,
    record_auth_audit,
    reset_user_password,
    revoke_api_key,
    revoke_session,
    session_token_from_cookie,
    update_user,
)
from server.sli.ops.logging_config import log_event

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("POST", "/api/auth/bootstrap"),
    ("POST", "/api/auth/api-keys"),
    ("POST", "/api/auth/api-keys/{}/revoke"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/users"),
    ("POST", "/api/auth/users/*"),
    ("POST", "/api/auth/users/{}/password"),
    ("POST", "/api/test/sli-v4/session"),
)


def try_handle_account_get(handler, path: str) -> bool:
    """Pre-gate entry point: /api/auth/me, /users, /api-keys all decide their
    own auth (principal check / _require_access) and must keep running
    before the shared ambient gate, exactly like health/static's pre-gate
    routes (see interfaces.md, ratified in ticket 01)."""
    if path == "/api/auth/bootstrap":
        if initial_owner_setup_pending():
            handler._send_html(OWNER_SETUP_HTML)
        else:
            handler._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        return True
    if path == "/api/auth/me":
        principal = principal_from_headers(handler.headers)
        if not principal:
            handler._send_json({"error": "authentication_required"}, HTTPStatus.UNAUTHORIZED)
        else:
            handler._send_json({"authenticated": True, "principal": handler._public_principal(principal)})
        return True
    if path == "/api/auth/users":
        if not handler._require_access("admin") or not handler._require_capability("access.manage"):
            return True
        handler._send_json({"items": list_users(), "roles": [
            {"id": "viewer", "label": "ИБ", "description": "Расследования, события и отчёты ИБ"},
            {"id": "operator", "label": "ИТ", "description": "Отчёты ИБ и эксплуатационные отчёты"},
            {"id": "admin", "label": "Администратор", "description": "Полный доступ и управление пользователями"},
        ]})
        return True
    if path == "/api/auth/api-keys":
        if not handler._require_access("admin") or not handler._require_capability("access.manage"):
            return True
        handler._send_json({"items": list_api_keys()})
        return True
    return False


def try_handle_post(handler, path: str) -> bool:
    """Body is read lazily inside each handler (matching the original code's
    order — e.g. login checks the brute-force limiter before ever reading
    the request body), so this contract does not take a pre-parsed body."""
    if path == "/api/auth/bootstrap":
        _handle_owner_setup(handler)
        return True
    if path == "/api/test/sli-v4/session":
        enabled = os.environ.get("ADLOG_SLI_V4_FIXTURE", "0").strip().lower() in {"1", "true", "yes", "on"}
        if not enabled or not is_loopback_bind_host(handler.server.server_address[0]):
            handler._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
            return True
        from server.sli.reporting.sli_v4_fixture import evaluate_fixture_actor
        try:
            decision = evaluate_fixture_actor(handler._read_json_body())
        except ValueError as exc:
            handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return True
        handler._send_json_with_cookie(
            {"status": "ok", "decision": decision},
            f"sli_v4_fixture_actor={decision['actor']}; Path=/; SameSite=Strict",
        )
        return True
    if path == "/api/auth/login":
        _handle_login(handler)
        return True
    if path == "/api/auth/logout":
        _handle_logout(handler)
        return True
    if path == "/api/auth/users":
        _handle_user_create(handler)
        return True
    if path.startswith("/api/auth/users/") and path.endswith("/password"):
        _handle_user_password_reset(handler, path)
        return True
    if path == "/api/auth/api-keys":
        _handle_api_key_create(handler)
        return True
    if path.startswith("/api/auth/api-keys/") and path.endswith("/revoke"):
        _handle_api_key_revoke(handler, path)
        return True
    if path.startswith("/api/auth/users/"):
        _handle_user_update(handler, path)
        return True
    return False


OWNER_SETUP_HTML = '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="referrer" content="no-referrer"><title>SLI — Create owner / Создание владельца</title>
<body><main><h1>SLI — Create owner / Создание владельца</h1>
<p>Account / Учётная запись: <strong>platform-owner</strong></p>
<p>Enter the one-time code from sli-setup and choose your password.<br>
Введите одноразовый код из sli-setup и задайте свой пароль.</p>
<form><label>Code / Код <input id="code" type="password" required autocomplete="off"></label><br>
<label>New password / Новый пароль <input id="password" type="password" minlength="12" maxlength="4096"
required autocomplete="new-password"></label><br>
<label>Repeat / Повтор <input id="repeat" type="password" required autocomplete="new-password"></label><br>
<button>Create owner / Создать владельца</button></form><p id="message" role="status"></p></main>
<script>document.querySelector("form").addEventListener("submit", async (event) => {
event.preventDefault(); const code=document.getElementById("code"), password=document.getElementById("password");
const message=document.getElementById("message"), button=document.querySelector("button");
if(password.value!==document.getElementById("repeat").value){message.textContent="Passwords differ / Пароли не совпадают";return;}
button.disabled=true;
try {const response=await fetch("/api/auth/bootstrap", {method:"POST", headers:{"Content-Type":"application/json"},
body:JSON.stringify({code:code.value,password:password.value})});
if(response.ok){location.replace("/app");}else{message.textContent="Cannot create owner: check code, password (12+ characters), or sign in if already created. / Проверьте код и пароль (от 12 символов); если владелец уже создан — войдите.";}
}catch{message.textContent="Connection failed / Нет соединения";}finally{code.value="";button.disabled=false;}
});</script></body></html>'''


def _handle_owner_setup(handler) -> None:
    if os.getenv("SLI_OWNER_SETUP") != "1" or not auth_required():
        handler._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        return
    if not handler._secure_transport():
        handler._send_json({"error": "secure_transport_required"}, HTTPStatus.FORBIDDEN)
        return
    if not handler._check_request_origin():
        return
    allowed, retry_after = handler.server.login_allowed(handler.client_address[0])
    if not allowed:
        handler._send_json({"error": "login_temporarily_locked"}, HTTPStatus.TOO_MANY_REQUESTS,
                           headers={"Retry-After": str(retry_after)})
        return
    payload = handler._read_json_body(max_bytes=16384)
    stage = 'claim'
    try:
        principal = claim_initial_owner(payload.get('code'), payload.get('password'),
                                        remote_address=handler.client_address[0])
        if not principal:
            stage = 'failed_audit'
            record_auth_audit(actor_type="anonymous", actor_id=None, action="initial_owner_claimed",
                              outcome="failed", remote_address=handler.client_address[0])
            handler._send_json({"error": "invalid_or_used_setup_code"}, HTTPStatus.UNAUTHORIZED)
            return
        stage = 'session'
        token = issue_session(principal)
        stage = 'response'
        _send_login_success(handler, principal, token)
    except InitialOwnerPasswordError:
        handler._send_json({"error": "new_password_required"}, HTTPStatus.BAD_REQUEST)
    except Exception as error:
        if getattr(handler, '_response_started', False):
            raise
        # Exceptions from DB/crypto can carry credentials or bind values.
        # Log a stable service event without exception text, traceback or payload.
        kind = type(error).__name__
        log_event("api.auth", "initial_owner_setup_failed", "Initial owner setup failed.",
                  level=logging.ERROR, stage=stage, error_type=kind)
        print(f'initial_owner_setup_failed: {stage} {kind}', file=sys.stderr, flush=True)
        handler._send_json({"error": "internal_server_error"}, HTTPStatus.INTERNAL_SERVER_ERROR)


def _handle_login(handler) -> None:
    if not auth_required():
        handler._send_json({"error": "authentication_not_enabled"}, HTTPStatus.CONFLICT)
        return
    if not handler._check_request_origin():
        return
    if not handler._secure_transport() and os.environ.get("ADLOG_AUTH_ALLOW_INSECURE_HTTP", "0").strip().lower() not in {"1", "true", "yes", "on"}:
        handler._send_json({"error": "secure_transport_required"}, HTTPStatus.FORBIDDEN)
        return
    allowed, retry_after = handler.server.login_allowed(handler.client_address[0])
    if not allowed:
        record_auth_audit(actor_type="anonymous", actor_id=None, action="login", outcome="throttled", remote_address=handler.client_address[0])
        handler._send_json({"error": "login_temporarily_locked", "retry_after_seconds": retry_after}, HTTPStatus.TOO_MANY_REQUESTS, headers={"Retry-After": str(retry_after)})
        return
    payload = handler._read_json_body()
    try:
        recovery = ({"recovery_code": str(payload.get("recovery_code") or ""),
                     "remote_address": handler.client_address[0]} if "recovery_code" in payload else {})
        if recovery:
            from server.sli.access.owner_recovery import recovery_budget

            principal = recovery_budget.verify(
                handler.client_address[0],
                lambda: authenticate_password(str(payload.get("username") or ""), str(payload.get("password") or ""), **recovery),
            )
        else:
            principal = authenticate_password(str(payload.get("username") or ""), str(payload.get("password") or ""))
    except LoginThrottled as exc:
        record_auth_audit(actor_type="anonymous", actor_id=None, action="owner_recovery_login" if recovery else "login", outcome="throttled", remote_address=handler.client_address[0])
        handler._send_json({"error": "login_temporarily_locked", "retry_after_seconds": exc.retry_after}, HTTPStatus.TOO_MANY_REQUESTS, headers={"Retry-After": str(exc.retry_after)})
        return
    if not principal:
        record_auth_audit(actor_type="anonymous", actor_id=None, action="login", outcome="failed", remote_address=handler.client_address[0])
        handler._send_json({"error": "invalid_credentials"}, HTTPStatus.UNAUTHORIZED)
        return
    remember = bool(payload.get("remember"))
    record_auth_audit(actor_type="session", actor_id=int(principal["id"]), action="login", remote_address=handler.client_address[0])
    _send_login_success(handler, principal, issue_session(principal, remember=remember), remember=remember)


def _handle_logout(handler) -> None:
    if not handler._check_request_origin():
        return
    revoke_session(session_token_from_cookie(handler.headers.get("Cookie")))
    handler._send_json_with_cookie({"status": "ok"}, _session_cookie(handler, "", max_age=0))


def _handle_user_create(handler) -> None:
    if not handler._authorize_mutation() or not handler._require_access("admin") or not handler._require_capability("access.manage"):
        return
    payload = handler._read_json_body()
    actor_type, actor_id = handler._audit_actor()
    try:
        created = create_user(
            username=str(payload.get("username") or ""),
            password=str(payload.get("password") or ""),
            role=str(payload.get("role") or "viewer"),
            actor_id=actor_id, actor_type=actor_type,
            remote_address=handler.client_address[0],
        )
    except ValueError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json({"item": created}, HTTPStatus.CREATED)


def _handle_user_update(handler, path: str) -> None:
    if not handler._authorize_mutation() or not handler._require_access("admin") or not handler._require_capability("access.manage"):
        return
    try:
        user_id = int(path.rsplit("/", 1)[-1])
    except ValueError:
        handler._send_json({"error": "invalid_user_id"}, HTTPStatus.BAD_REQUEST)
        return
    payload = handler._read_json_body()
    actor_type, actor_id = handler._audit_actor()
    role = payload.get("role") if "role" in payload else None
    active = payload.get("is_active") if "is_active" in payload else None
    if active is not None and not isinstance(active, bool):
        handler._send_json({"error": "is_active_must_be_boolean"}, HTTPStatus.BAD_REQUEST)
        return
    try:
        updated = update_user(user_id=user_id, role=role, is_active=active, actor_id=actor_id, actor_type=actor_type, remote_address=handler.client_address[0])
    except ValueError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json({"item": updated})


def _handle_user_password_reset(handler, path: str) -> None:
    if not handler._authorize_mutation() or not handler._require_access("admin") or not handler._require_capability("access.manage"):
        return
    try:
        user_id = int(path.rsplit("/", 2)[-2])
    except ValueError:
        handler._send_json({"error": "invalid_user_id"}, HTTPStatus.BAD_REQUEST)
        return
    payload = handler._read_json_body()
    actor_type, actor_id = handler._audit_actor()
    try:
        item = reset_user_password(
            user_id=user_id,
            password=str(payload.get("password") or ""),
            actor_id=actor_id, actor_type=actor_type,
            remote_address=handler.client_address[0],
        )
    except ValueError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json({"item": item})


def _handle_api_key_create(handler) -> None:
    if not handler._authorize_mutation() or not handler._require_access("admin") or not handler._require_capability("access.manage"):
        return
    payload = handler._read_json_body()
    actor_type, actor_id = handler._audit_actor()
    try:
        item, token = issue_api_key(
            label=str(payload.get("label") or ""), role=str(payload.get("role") or "viewer"),
            actor_id=actor_id, actor_type=actor_type, remote_address=handler.client_address[0],
        )
    except ValueError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    # This is the one and only response which contains the secret token.
    handler._send_json({"item": item, "token": token}, HTTPStatus.CREATED)


def _handle_api_key_revoke(handler, path: str) -> None:
    if not handler._authorize_mutation() or not handler._require_access("admin") or not handler._require_capability("access.manage"):
        return
    try:
        key_id = int(path.rsplit("/", 2)[-2])
    except ValueError:
        handler._send_json({"error": "invalid_api_key_id"}, HTTPStatus.BAD_REQUEST)
        return
    actor_type, actor_id = handler._audit_actor()
    revoked = revoke_api_key(key_id, actor_id=actor_id, actor_type=actor_type, remote_address=handler.client_address[0])
    if not revoked:
        handler._send_json({"error": "api_key_not_found_or_already_revoked"}, HTTPStatus.NOT_FOUND)
        return
    handler._send_json({"status": "revoked"})


def _session_cookie(handler, token: str, *, max_age: int) -> str:
    secure = "; Secure" if handler._secure_transport() or os.environ.get("ADLOG_AUTH_COOKIE_SECURE", "0").strip().lower() in {"1", "true", "yes", "on"} else ""
    return f"{SESSION_COOKIE}={token}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict{secure}"


def _send_login_success(handler, principal: dict, token: str, *, remember: bool = False) -> None:
    max_age = 1_209_600 if remember else 43_200
    cookie = _session_cookie(handler, token, max_age=max_age)
    handler._send_json_with_cookie({"authenticated": True, "principal": handler._public_principal(principal)}, cookie)
