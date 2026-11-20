"""Owner CLI over the same HTTPS admin routes; credentials use hidden input."""
import argparse
import getpass
import http.client
import json
import ssl
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID


def assign(*, server_url, ca_bundle, session_token, agent_id, enabled, config):
    url = urlsplit(server_url)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in ("", "/")):
        raise ValueError("agent_admin_url_invalid")
    if not session_token or any(c in session_token for c in "\r\n;"):
        raise ValueError("agent_admin_session_invalid")
    body = json.dumps({"agent_id": str(UUID(agent_id)), "module_id": "sli.workstations",
                       "enabled": enabled, "config": config}).encode()
    connection = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=30,
                                             context=ssl.create_default_context(cafile=str(ca_bundle)))
    try:
        connection.request("POST", "/api/v1/admin/agents/modules", body=body,
                           headers={"Content-Type": "application/json", "Cookie": "adlog_session=" + session_token})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("agent_admin_request_rejected")
        result = json.loads(response.read(65537))
        if result.get("agent_id") != str(UUID(agent_id)):
            raise ValueError("agent_admin_response_invalid")
    finally:
        connection.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="SLI owner agent administration")
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--ca-bundle", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    assignment = commands.add_parser("assign-workstations")
    assignment.add_argument("--agent-id", required=True)
    assignment.add_argument("--disable", action="store_true")
    assignment.add_argument("--policy", type=Path)
    args = parser.parse_args(argv)
    try:
        policy = json.loads(args.policy.read_text("utf-8")) if args.policy else {}
        assign(server_url=args.server_url, ca_bundle=args.ca_bundle,
               session_token=getpass.getpass("Owner session token (adlog_session): "),
               agent_id=args.agent_id, enabled=not args.disable, config=policy)
    except Exception:  # noqa: BLE001 - never expose credentials, paths or response data
        parser.exit(1, "agent_admin_operation_failed\n")
    print("agent_module_assigned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
