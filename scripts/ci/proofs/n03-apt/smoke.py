"""Exercise Debian's mapped libraries with the installed, sealed runtime."""
import hashlib
import os
from pathlib import Path
import ssl
import sys
import zlib


def tls_exchange(certificate, key, payload):
    hostname = "sli-apt.invalid"
    client_context = ssl.create_default_context(cafile=certificate)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, key)
    for context in (client_context, server_context):
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    client_rx, client_tx, server_rx, server_tx = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(client_rx, client_tx, server_hostname=hostname)
    server = server_context.wrap_bio(server_rx, server_tx, server_side=True)
    complete = set()
    for _ in range(32):
        for side in (client, server):
            if side not in complete:
                try:
                    side.do_handshake()
                except ssl.SSLWantReadError:
                    continue
                complete.add(side)
        if client_tx.pending:
            server_rx.write(client_tx.read())
        if server_tx.pending:
            client_rx.write(server_tx.read())
        if len(complete) == 2:
            break
    assert complete == {client, server}
    assert client.version() == server.version() == "TLSv1.3"
    assert client.write(payload) == len(payload)
    server_rx.write(client_tx.read())
    assert server.read(len(payload)) == payload


expected_ssl, certificate, key = sys.argv[1:]
payload = b"offline-n03-three-libraries"
assert ssl.OPENSSL_VERSION.split()[1] == expected_ssl
assert os.confstr("CS_GNU_LIBC_VERSION") == "glibc 2.41"
assert zlib.decompress(zlib.compress(payload)) == payload
tls_exchange(certificate, key, hashlib.sha256(payload).digest())

system_lib = Path("/usr/lib/x86_64-linux-gnu")
required = {
    (system_lib / name).resolve(strict=True)
    for name in ("libc.so.6", "libz.so.1", "libssl.so.3", "libcrypto.so.3")
}
mapped = set()
for line in Path("/proc/self/maps").read_text().splitlines():
    fields = line.split(maxsplit=5)
    if len(fields) == 6 and fields[-1].startswith("/"):
        mapped.add(Path(fields[-1]).resolve())
assert required <= mapped, required - mapped
print(f"Python {sys.version.split()[0]}, {ssl.OPENSSL_VERSION}, zlib {zlib.ZLIB_RUNTIME_VERSION}, glibc 2.41, TLSv1.3")
