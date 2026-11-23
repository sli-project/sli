"""Perform a certificate-verified TLS exchange over memory BIOs."""
import argparse
import hashlib
import json
from pathlib import Path
import ssl
import sys


def transfer(output, incoming):
    data = output.read()
    if data:
        incoming.write(data)


def exchange(certificate, private_key):
    host = "sli-abi.invalid"
    client_context = ssl.create_default_context(cafile=certificate)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, private_key)
    for context in (client_context, server_context):
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    assert client_context.check_hostname and client_context.verify_mode == ssl.CERT_REQUIRED
    client_rx, client_tx, server_rx, server_tx = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(client_rx, client_tx, server_hostname=host)
    server = server_context.wrap_bio(server_rx, server_tx, server_side=True)
    ready = set()
    for _ in range(32):
        for side in (client, server):
            if side not in ready:
                try:
                    side.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                else:
                    ready.add(side)
        transfer(client_tx, server_rx)
        transfer(server_tx, client_rx)
        if len(ready) == 2:
            break
    assert ready == {client, server} and client.version() == server.version() == "TLSv1.3"
    request, reply = b"sli-n03-abi-client", b"sli-n03-abi-server"
    assert client.write(request) == len(request)
    transfer(client_tx, server_rx)
    assert server.read(len(request)) == request
    assert server.write(reply) == len(reply)
    transfer(server_tx, client_rx)
    assert client.read(len(reply)) == reply
    return {"tls": client.version(), "cipher": client.cipher()[0], "hostname_verified": host}


def mapped_system_libraries():
    names = {"libssl.so.3", "libcrypto.so.3"}
    mapped = set()
    for line in Path("/proc/self/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and fields[-1].startswith("/"):
            path = Path(fields[-1])
            if path.name in names:
                mapped.add(path.resolve(strict=True))
    assert mapped == {Path("/usr/lib/x86_64-linux-gnu") / name for name in names}, mapped
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(mapped)}


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("certificate")
    cli.add_argument("private_key")
    cli.add_argument("--openssl-release")
    args = cli.parse_args()
    result = exchange(args.certificate, args.private_key)
    result.update(openssl=ssl.OPENSSL_VERSION, python_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest())
    if args.openssl_release is not None:
        assert ssl.OPENSSL_VERSION.split()[1] == args.openssl_release
        result["mapped_libraries"] = mapped_system_libraries()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
