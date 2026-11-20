"""Owner administration and independently authenticated agent endpoints."""
from http import HTTPStatus

from server.sli.agents import (
    sequence_recovery, ad_credentials, deployment_scope, gpo_plan_credentials, gpo_plans, group_deployment, group_enrollment, onboarding, policies, registry, removal, update_waves, updates, windows_audit,
)
from server.sli.agents.ca import AgentError, IssuingCA
from server.sli.agents.transport import peer_certificate, require_enrollment_tls
from server.sli.agents import runtime_switch
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.plugins.registry import plugin_hook

ROUTES = (
    ("POST", "/api/v1/admin/agents/replace"),
    ("GET", "/api/v1/admin/agents/sequence-recovery"),
    ("POST", "/api/v1/admin/agents/sequence-recovery"),
    ("GET", "/api/v1/workstations/agents"),
    ("GET", "/api/v1/ad-operation-credentials"),
    ("POST", "/api/v1/ad-operation-credentials"),
    ("POST", "/api/v1/ad-operation-credentials/replace-password"),
    ("POST", "/api/v1/ad-operation-credentials/delete"),
    ("POST", "/api/v1/ad-operation-credentials/check"),
    ("POST", "/api/v1/agent-deployment/gpo/credentials"),
    ("POST", "/api/v1/agent-deployment/gpo/preview"),
    ("POST", "/api/v1/agent-deployment/gpo/confirm"),
    ("POST", "/api/v1/agent-deployment/gpo/cancel"),
    ("POST", "/api/v1/admin/agent-deployment-directory"),
    ("POST", "/api/v1/admin/agent-group-requests"),
    ("POST", "/api/v1/admin/agent-group-requests/approve"),
    ("GET", "/api/v1/admin/agent-templates"),
    ("POST", "/api/v1/admin/agent-templates"),
    ("GET", "/api/v1/admin/agent-onboarding"),
    ("POST", "/api/v1/admin/agent-onboarding/approve"),
    ("POST", "/api/v1/admin/agents/remove"),
    ("POST", "/api/v1/agent/uninstall"),
    ("POST", "/api/v1/agent/removal-result"),
    ("GET", "/api/v1/admin/agent-group-tokens"),
    ("POST", "/api/v1/admin/agent-group-tokens"),
    ("POST", "/api/v1/admin/agent-group-tokens/revoke"),
    ("POST", "/api/v1/agent/group-enroll"),
    ("GET", "/api/v1/admin/agent-packages"),
    ("POST", "/api/v1/admin/agent-packages"),
    ("POST", "/api/v1/admin/agents/update-policy"),
    ("GET", "/api/v1/admin/agent-update-waves"),
    ("POST", "/api/v1/admin/agent-update-waves"),
    ("POST", "/api/v1/admin/agent-update-waves/stop"),
    ("GET", "/api/v1/agent/package"),
    ("POST", "/api/v1/agent/update-result"),
    ("GET", "/api/v1/admin/agents"),
    ("GET", "/api/v1/admin/agent-tokens"),
    ("GET", "/api/v1/agent/revocations"),
    ("GET", "/api/v1/agent/identity"),
    ("POST", "/api/v1/admin/agent-tokens"),
    ("POST", "/api/v1/admin/agent-tokens/revoke"),
    ("POST", "/api/v1/admin/agents/revoke"),
    ("POST", "/api/v1/admin/agents/disable"),
    ("POST", "/api/v1/admin/agents/modules"),
    ("POST", "/api/v1/admin/agents/rights-probe"),
    ("POST", "/api/v1/admin/agents/policy"),
    ("POST", "/api/v1/agent/policy-report"),
    ("POST", "/api/v1/agent/windows-audit-report"),
    ("POST", "/api/v1/admin/agents/file-audit"),
    ("GET", "/api/v1/admin/agents/file-audit"),
    ("POST", "/api/v1/agent/file-audit-report"),
    ("POST", "/api/v1/agent/enroll"),
    ("POST", "/api/v1/agent/renew"),
)


def _owner(handler, *, mutation=False):
    if mutation and not handler._authorize_mutation(required_role="viewer"):
        return False
    # Require a real authenticated administrator even on an auth-disabled copy.
    if not handler._require_access("viewer"):
        return False
    decision = handler._access_decision()
    if decision.get("platform_owner"):
        return True
    return handler._require_capability("access.manage")


def _recovery_owner(handler, *, mutation=False):
    if not _owner(handler, mutation=mutation):
        return False
    if handler._access_decision().get("platform_owner") is not True:
        handler._send_json({"error": "platform_owner_required"}, HTTPStatus.FORBIDDEN,
                           headers={"Cache-Control": "no-store"})
        return False
    return True


def _actor(handler):
    principal = handler._principal
    return str(principal["type"]) + ":" + str(principal["id"])


def _execute(handler, operation, *, transport=None, binary=False):
    rejection = None
    try:
        peer = transport(handler) if transport else None
        with connect() as conn, conn.cursor() as cur:
            try:
                result = operation(cur, peer) if transport else operation(cur)
            except group_enrollment.AuditedRejection as exc:
                # Group admission denials write only a safe audit. Preserve it
                # through commit, while ordinary enrollment failures roll back.
                rejection = exc
            conn.commit()
    except AgentError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus(exc.status), headers={"Cache-Control": "no-store"})
        return
    except Exception:
        # DB/crypto exception diagnostics can contain bind values (token hashes,
        # host metadata). Do not pass them to ambient traceback logging.
        handler._send_json({"error": "agent_service_unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE,
            headers={"Cache-Control": "no-store"})
        return
    if rejection is not None:
        handler._send_json({"error": str(rejection)}, HTTPStatus(rejection.status), headers={"Cache-Control": "no-store"})
    elif binary:
        handler.send_response(HTTPStatus.OK)
        handler.send_header("Content-Type", "application/zip")
        handler.send_header("Content-Length", str(len(result)))
        handler.send_header("Cache-Control", "no-store")
        handler.end_headers()
        handler.wfile.write(result)
    else:
        handler._send_json(result, headers={"Cache-Control": "no-store"})


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/v1/admin/agents/sequence-recovery":
        if _recovery_owner(handler):
            def read_recovery(cur):
                if set(query) != {"agent_id"} or len(query["agent_id"]) != 1:
                    raise AgentError("agent_sequence_recovery_invalid")
                return sequence_recovery.list_gaps(cur, query["agent_id"][0], access=handler._access_decision())
            _execute(handler, read_recovery)
        return True
    if path == "/api/v1/workstations/agents":
        if not handler._require_access("viewer"):
            return True
        headers = {"Cache-Control": "no-store"}
        try:
            reader = plugin_hook("sli.workstations", "agent_read")
            if reader is None:
                raise AgentError("workstation_plugin_unavailable", 409)
            access = handler._access_decision()
            with connect() as conn, conn.cursor() as cur:
                payload = reader(cur, access, query)
            handler._send_json(payload, headers=headers)
        except PermissionError:
            handler._send_json({"error": "workstation_access_denied"}, HTTPStatus.FORBIDDEN, headers=headers)
        except AgentError as exc:
            code = "workstation_request_invalid" if exc.status == 400 else str(exc)
            handler._send_json({"error": code}, HTTPStatus(exc.status), headers=headers)
        except ValueError:
            handler._send_json({"error": "workstation_request_invalid"}, HTTPStatus.BAD_REQUEST, headers=headers)
        except Exception:
            handler._send_json({"error": "workstation_source_unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE, headers=headers)
        return True
    if path == "/api/v1/ad-operation-credentials":
        if handler._require_access("viewer"):
            principal = handler._principal
            if not principal or principal.get("type") != "session":
                handler._send_json({"error": "ad_operations_denied"}, HTTPStatus.FORBIDDEN,
                    headers={"Cache-Control": "no-store"})
            elif query:
                handler._send_json({"error": "ad_credential_request_invalid"}, HTTPStatus.BAD_REQUEST,
                    headers={"Cache-Control": "no-store"})
            else:
                _execute(handler, lambda cur: ad_credentials.list_credentials(cur, actor=_actor(handler)))
        return True
    if path == "/api/v1/admin/agents/file-audit":
        if _owner(handler):
            def read(cur):
                if set(query) != {"agent_id"} or len(query["agent_id"]) != 1:
                    raise AgentError("file_audit_request_invalid")
                hook = plugin_hook("sli.file-audit", "audit_status")
                if hook is None:
                    raise AgentError("file_audit_plugin_unavailable", 409)
                return hook(cur, query["agent_id"][0], principal=handler._principal, access=handler._access_decision())
            _execute(handler, read)
        return True
    if path == "/api/v1/admin/agent-update-waves":
        if _owner(handler):
            def waves(cur):
                if set(query) - {"wave_id"} or ("wave_id" in query and len(query["wave_id"]) != 1):
                    raise AgentError("agent_update_wave_invalid")
                return update_waves.list_waves(cur, actor=_actor(handler), wave_id=(query.get("wave_id") or [None])[0])
            _execute(handler, waves)
        return True
    if path == "/api/v1/admin/agent-templates":
        if _owner(handler):
            _execute(handler, lambda cur: onboarding.list_templates(cur, actor=_actor(handler)))
        return True
    if path == "/api/v1/admin/agent-onboarding":
        if _owner(handler):
            def pending(cur):
                if set(query) != {"token_id"} or len(query["token_id"]) != 1:
                    raise AgentError("invalid_agent_batch_approval")
                return onboarding.list_requests(cur, query["token_id"][0], actor=_actor(handler))
            _execute(handler, pending)
        return True
    if path == "/api/v1/admin/agent-group-tokens":
        if _owner(handler):
            _execute(handler, lambda cur: group_enrollment.list_tokens(cur, actor=_actor(handler)))
        return True
    if path == "/api/v1/admin/agent-packages":
        if _owner(handler):
            _execute(handler, lambda cur: updates.list_packages(cur, actor=_actor(handler)))
        return True
    if path == "/api/v1/agent/package":
        def package(cur, der):
            update_waves.lock(cur)
            agent = registry.authenticate(cur, IssuingCA.from_environment(), der)
            if set(query) != {"sha256"} or len(query["sha256"]) != 1:
                raise AgentError("agent_package_invalid")
            return updates.download(cur, agent, query["sha256"][0])
        _execute(handler, package, transport=peer_certificate, binary=True)
        return True
    if path == "/api/v1/admin/agents":
        if _owner(handler):
            _execute(handler, lambda cur: registry.list_agents(cur, actor=_actor(handler), agent_id=(query.get("agent_id") or [None])[0]))
        return True
    if path == "/api/v1/admin/agent-tokens":
        if _owner(handler):
            _execute(handler, lambda cur: registry.list_tokens(cur, actor=_actor(handler)))
        return True
    if path == "/api/v1/agent/revocations":
        def read(cur):
            if set(query) - {"after"} or len(query.get("after", ["0"])) != 1:
                raise AgentError("invalid_revocation_cursor")
            try:
                after = int(query.get("after", ["0"])[0])
            except (ValueError, TypeError):
                raise AgentError("invalid_revocation_cursor") from None
            return registry.revocations(cur, after)
        _execute(handler, read)
        return True
    if path == "/api/v1/agent/identity":
        def identity(cur, der):
            update_waves.lock(cur)
            ca = IssuingCA.from_environment()
            try:
                agent = registry.authenticate(cur, ca, der)
            except AgentError:
                agent = registry.authenticate(cur, ca, der, removal_only=True)
                return removal.command(cur, agent)
            return {**policies.check_in(agent), "agent_update": updates.advertisement(cur, agent)}
        _execute(handler, identity, transport=peer_certificate)
        return True
    return False


def try_handle_post(handler, path: str) -> bool:
    if path == "/api/v1/admin/agents/replace":
        if _owner(handler, mutation=True):
            body = handler._read_json_body()
            _execute(handler, lambda cur: runtime_switch.replace(
                cur, body, actor=_actor(handler), access=handler._access_decision()))
        return True
    if path == "/api/v1/admin/agents/sequence-recovery":
        if _recovery_owner(handler, mutation=True):
            body = handler._read_json_body()
            _execute(handler, lambda cur: sequence_recovery.authorize_all(
                cur, body, actor=_actor(handler), access=handler._access_decision()))
        return True
    credential_actions = {
        "/api/v1/ad-operation-credentials": ad_credentials.create,
        "/api/v1/ad-operation-credentials/replace-password": ad_credentials.replace_password,
        "/api/v1/ad-operation-credentials/delete": ad_credentials.delete,
        "/api/v1/ad-operation-credentials/check": ad_credentials.check_read_only,
    }
    if path in ("/api/v1/ad-operation-credentials", "/api/v1/ad-operation-credentials/replace-password",
                "/api/v1/ad-operation-credentials/delete", "/api/v1/ad-operation-credentials/check"):
        if handler._authorize_mutation(required_role="viewer") and handler._require_access("viewer"):
            principal = handler._principal
            if not principal or principal.get("type") != "session":
                handler._send_json({"error": "ad_operations_denied"}, HTTPStatus.FORBIDDEN,
                    headers={"Cache-Control": "no-store"})
            else:
                body = handler._read_json_body()
                _execute(handler, lambda cur, _peer: credential_actions[path](cur, body, actor=_actor(handler)),
                    transport=require_enrollment_tls)
        return True
    if path in {"/api/v1/agent-deployment/gpo/credentials", "/api/v1/agent-deployment/gpo/preview",
            "/api/v1/agent-deployment/gpo/confirm", "/api/v1/agent-deployment/gpo/cancel"}:
        if handler._authorize_mutation(required_role="viewer") and handler._require_access("viewer"):
            principal = handler._principal
            if not principal or principal.get("type") != "session":
                handler._send_json({"error": "gpo_session_required"}, HTTPStatus.FORBIDDEN,
                    headers={"Cache-Control": "no-store"})
                return True
            body = handler._read_json_body()
            if path.endswith("/credentials"):
                _execute(handler, lambda cur: gpo_plan_credentials.options(cur, body, actor=_actor(handler)))
            elif path.endswith("/preview"):
                _execute(handler, lambda cur: gpo_plans.preview(cur, body, actor=_actor(handler)))
            else:
                _execute(handler, lambda cur: gpo_plans.finish(cur, body, actor=_actor(handler), cancel=path.endswith("/cancel")))
        return True
    if path == "/api/v1/admin/agent-deployment-directory":
        if _owner(handler, mutation=True):
            body = handler._read_json_body()
            _execute(handler, lambda cur: deployment_scope.directory(cur, body))
        return True
    if path in ("/api/v1/admin/agent-group-requests", "/api/v1/admin/agent-group-requests/approve"):
        if _owner(handler, mutation=True):
            # A 1000-key deployment attestation exceeds the normal 64 KiB cap.
            # The larger bound applies only after administrative authorization.
            body = handler._read_json_body(max_bytes=512 * 1024) if path.endswith("/approve") else handler._read_json_body()
            operation = group_deployment.approve if path.endswith("/approve") else group_deployment.list_pending
            _execute(handler, lambda cur: operation(cur, body, actor=_actor(handler)))
        return True
    if path == "/api/v1/admin/agents/file-audit":
        if _owner(handler, mutation=True):
            body = handler._read_json_body()
            def enqueue(cur):
                hook = plugin_hook("sli.file-audit", "enqueue_audit_batch" if isinstance(body, dict) and "agents" in body else "enqueue_audit")
                if hook is None:
                    raise AgentError("file_audit_plugin_unavailable", 409)
                return hook(cur, body, principal=handler._principal, access=handler._access_decision())
            _execute(handler, enqueue)
        return True
    if path == "/api/v1/agent/file-audit-report":
        body = handler._read_json_body()
        def ingest(cur, der):
            agent = registry.authenticate(cur, IssuingCA.from_environment(), der)
            hook = plugin_hook("sli.file-audit", "ingest_audit")
            if hook is None:
                raise AgentError("file_audit_plugin_unavailable", 409)
            return hook(cur, agent, body)
        _execute(handler, ingest, transport=peer_certificate)
        return True
    if path in ("/api/v1/admin/agent-update-waves", "/api/v1/admin/agent-update-waves/stop"):
        if _owner(handler, mutation=True):
            # A fleet-wide selection requires explicit platform-owner scope.
            if not handler._access_decision().get("platform_owner"):
                handler._send_json({"error": "platform_owner_required"}, HTTPStatus.FORBIDDEN)
                return True
            body = handler._read_json_body()
            operation = update_waves.stop if path.endswith("/stop") else update_waves.create
            _execute(handler, lambda cur: operation(cur, body, actor=_actor(handler)))
        return True
    if path in ("/api/v1/admin/agent-templates", "/api/v1/admin/agent-onboarding/approve"):
        if _owner(handler, mutation=True):
            body = handler._read_json_body()
            operation = onboarding.save_template if path.endswith("agent-templates") else onboarding.approve
            _execute(handler, lambda cur: operation(cur, body, actor=_actor(handler)))
        return True
    if path == "/api/v1/admin/agents/remove":
        if _owner(handler, mutation=True):
            # access.manage alone has no authority over the entire agent fleet.
            if not handler._access_decision().get("platform_owner"):
                handler._send_json({"error": "platform_owner_required"}, HTTPStatus.FORBIDDEN)
                return True
            body = handler._read_json_body()
            _execute(handler, lambda cur: removal.request(cur, body, actor=_actor(handler)))
        return True
    if path in ("/api/v1/agent/uninstall", "/api/v1/agent/removal-result"):
        body = handler._read_json_body()
        def uninstall(cur, der):
            ca = IssuingCA.from_environment()
            if path.endswith("/removal-result"):
                agent = registry.authenticate(cur, ca, der, removal_only=True)
                return removal.report(cur, agent, body)
            if body != {}:
                raise AgentError("agent_removal_invalid")
            try:
                agent = registry.authenticate(cur, ca, der)
            except AgentError:
                agent = registry.authenticate(cur, ca, der, removal_only=True)
            return removal.local_uninstall(cur, agent)
        _execute(handler, uninstall, transport=peer_certificate)
        return True
    if path in ("/api/v1/admin/agent-group-tokens", "/api/v1/admin/agent-group-tokens/revoke"):
        if _owner(handler, mutation=True):
            body = handler._read_json_body(max_bytes=512 * 1024)
            if path.endswith("/revoke"):
                _execute(handler, lambda cur: group_enrollment.revoke_token(cur, body.get("id"), actor=_actor(handler)))
            else:
                _execute(handler, lambda cur: group_enrollment.create_token(cur, body, actor=_actor(handler)))
        return True
    if path == "/api/v1/agent/group-enroll":
        body = handler._read_json_body()
        _execute(handler, lambda cur, _peer: group_enrollment.submit(cur, body), transport=require_enrollment_tls)
        return True
    if path == "/api/v1/admin/agent-packages":
        if _owner(handler, mutation=True):
            def upload(cur):
                try:
                    length = int(handler.headers.get("Content-Length", "0"))
                except (ValueError, TypeError):
                    raise AgentError("agent_package_invalid") from None
                if (not 0 < length <= updates.MAX_PACKAGE_BYTES or handler.headers.get("Transfer-Encoding")
                        or handler.headers.get("Content-Type") != "application/zip"):
                    raise AgentError("agent_package_invalid")
                raw = handler.rfile.read(length)
                if len(raw) != length:
                    raise AgentError("agent_package_invalid")
                return updates.upload(cur, raw, actor=_actor(handler))
            _execute(handler, upload)
        return True
    if path == "/api/v1/admin/agents/update-policy":
        if _owner(handler, mutation=True):
            body = handler._read_json_body()
            _execute(handler, lambda cur: updates.assign(cur, body, actor=_actor(handler)))
        return True
    if path == "/api/v1/agent/update-result":
        body = handler._read_json_body()
        def report(cur, der):
            update_waves.lock(cur)
            agent = registry.authenticate(cur, IssuingCA.from_environment(), der)
            return updates.report(cur, agent, body)
        _execute(handler, report, transport=peer_certificate)
        return True
    if path in ("/api/v1/admin/agents/modules", "/api/v1/admin/agents/rights-probe", "/api/v1/admin/agents/policy"):
        if _owner(handler, mutation=True):
            body = handler._read_json_body()
            operation = {"modules": registry.assign_module, "rights-probe": policies.request_probe,
                         "policy": policies.update_control}[path.rsplit("/", 1)[-1]]
            _execute(handler, lambda cur: operation(cur, body, actor=_actor(handler)))
        return True
    if path == "/api/v1/agent/policy-report":
        body = handler._read_json_body()
        def report(cur, der):
            agent = registry.authenticate(cur, IssuingCA.from_environment(), der)
            return policies.report(cur, agent, body)
        _execute(handler, report, transport=peer_certificate)
        return True
    if path == "/api/v1/agent/windows-audit-report":
        body = handler._read_json_body()
        def report(cur, der):
            agent = registry.authenticate(cur, IssuingCA.from_environment(), der)
            return windows_audit.report(cur, agent, body)
        _execute(handler, report, transport=peer_certificate)
        return True
    if path == "/api/v1/admin/agent-tokens":
        if _owner(handler, mutation=True):
            body = handler._read_json_body()
            _execute(handler, lambda cur: registry.create_token(cur, body, actor=_actor(handler)))
        return True
    if path == "/api/v1/admin/agent-tokens/revoke":
        if _owner(handler, mutation=True):
            body = handler._read_json_body()
            _execute(handler, lambda cur: registry.revoke_token(cur, body.get("id"), actor=_actor(handler)))
        return True
    if path in ("/api/v1/admin/agents/revoke", "/api/v1/admin/agents/disable"):
        if _owner(handler, mutation=True):
            body = handler._read_json_body()
            _execute(handler, lambda cur: registry.revoke(cur, body, actor=_actor(handler), disable=path.endswith("/disable")))
        return True
    if path == "/api/v1/agent/enroll":
        body = handler._read_json_body()
        def enroll(cur, _peer):
            return registry.enroll(cur, IssuingCA.from_environment(), body)
        _execute(handler, enroll, transport=require_enrollment_tls)
        return True
    if path == "/api/v1/agent/renew":
        body = handler._read_json_body()
        _execute(handler, lambda cur, der: registry.renew(cur, IssuingCA.from_environment(), der, body), transport=peer_certificate)
        return True
    return False
