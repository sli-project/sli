"""One real loopback request through the unchanged Python HTTP handler.

The caller owns the fresh PostgreSQL cluster and snapshots it around this process.
No run_server/bootstrap/scheduler, handler replacement or DB exception injection.
"""
from __future__ import annotations

import base64
from contextlib import closing
import hashlib
import http.client
import json
from pathlib import Path
import sys
import threading


def main():
    root = Path(__file__).resolve().parents[4]
    sys.path.insert(0, str(root))
    from server.api.http_server import ProtectedHTTPServer, RequestHandler

    request = json.loads(sys.stdin.readline())
    with ProtectedHTTPServer(("127.0.0.1", 0), RequestHandler) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            with closing(http.client.HTTPConnection(*server.server_address)) as client:
                client.request("GET", "/api/v1/domains", headers={
                    "Cookie": "adlog_session=" + request["token"],
                    "Accept-Language": "en",
                })
                response = client.getresponse()
                payload = {
                    "status": response.status,
                    "reason": response.reason,
                    "version": response.version,
                    "headers": response.getheaders(),
                    "body_base64": base64.b64encode(response.read()).decode("ascii"),
                }
        finally:
            server.shutdown()
            thread.join()
    # Bind this observation to actual local source bytes, without claiming that
    # they establish the historical ddce909d Git identity (Git is out of scope).
    files = {}
    for module in tuple(sys.modules.values()):
        name = getattr(module, "__file__", None)
        if name:
            path = Path(name).resolve()
            if path.is_relative_to(root / "server") and path.suffix == ".py":
                files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    payload["python_source_sha256"] = hashlib.sha256(
        json.dumps(files, sort_keys=True).encode("utf-8")
    ).hexdigest()
    payload["python_source_files"] = len(files)
    print(json.dumps(payload))


if __name__ == "__main__":
    main()
