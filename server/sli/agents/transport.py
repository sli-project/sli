"""Use only a peer certificate verified by the existing TLS listener."""
import ssl

from server.sli.agents.ca import AgentError


def peer_certificate(handler) -> bytes:
    connection = handler.connection
    if not isinstance(connection, ssl.SSLSocket) or connection.context.verify_mode not in (ssl.CERT_OPTIONAL, ssl.CERT_REQUIRED):
        raise AgentError("agent_mtls_required", 401)
    der = connection.getpeercert(binary_form=True)
    if not der:
        raise AgentError("agent_mtls_required", 401)
    return der


def require_enrollment_tls(handler):
    if not isinstance(handler.connection, ssl.SSLSocket):
        raise AgentError("agent_tls_required", 401)
