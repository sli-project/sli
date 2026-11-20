"""Agent packets use Part-A verified TLS identity, independently of UI login."""
from http import HTTPStatus

from server.sli.agent_ingest import PostgresLedger, receive_packet
from server.sli.agents.delivery_diagnostics import log_rejection
from server.sli.core.postgres_runtime_pipeline import connect
from sli_agent.envelope import EnvelopeError

ROUTES = (("POST", "/api/v1/agent/packets"),)


def _peer(handler):
    # Part A is a merge/runtime prerequisite, not copied into this branch.
    from server.sli.agents.transport import peer_certificate
    return peer_certificate(handler)


def _authenticate(cur, der):
    from server.sli.agents import registry
    from server.sli.agents.ca import IssuingCA
    ca = IssuingCA.from_environment()
    identity = registry.authenticate(cur, ca, der)
    return identity, ca.verify_client(der).public_key()


def try_handle_post(handler, path):
    if path == "/api/v1/agent/packets":
        try:
            der = _peer(handler)
            body = handler._read_json_body()
            with connect() as conn, conn.cursor() as cur:
                identity, public_key = _authenticate(cur, der)
                result = receive_packet(PostgresLedger(cur), identity=identity, public_key=public_key, value=body)
                conn.commit()
        except EnvelopeError as exc:
            handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST, headers={"Cache-Control": "no-store"})
            return True
        except Exception as exc:
            if type(exc).__module__ == "server.sli.agents.ca" and type(exc).__name__ == "AgentError":
                status = HTTPStatus(getattr(exc, "status", 401))
                code = "agent_authentication_failed"
            elif type(exc).__name__ == "RequestInputError":
                # Keep the HTTP server's bounded-body/content-type errors.
                raise
            else:
                status, code = HTTPStatus.SERVICE_UNAVAILABLE, "agent_service_unavailable"
            handler._send_json({"error": code}, status, headers={"Cache-Control": "no-store"})
            return True
        try:
            log_rejection(identity, body, result)
        except Exception:
            # Diagnostics must not turn an already committed receipt into a retry.
            pass
        handler._send_json(result, headers={"Cache-Control": "no-store"})
        return True
    return False
