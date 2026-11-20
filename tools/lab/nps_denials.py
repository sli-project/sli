"""One-shot loopback RADIUS denial attempts for an administrator-owned NPS LAB.

No client/policy/service is configured. The PAP shared secret is read from the
protected LAB file and never accepted in arguments or printed. A RADIUS reject
alone does not prove that NPS emitted 6273 or that SLI collected/delivered it.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import struct
import time

ACCOUNT = b"labsim-nps-denied"


def request(secret, *, identifier, authenticator):
    if not 1 <= len(secret) <= 128 or len(authenticator) != 16:
        raise ValueError("nps_lab_request_invalid")
    # An intentionally invalid synthetic password, unrelated to any account.
    password = b"labsim-invalid-password"
    password += b"\0" * (-len(password) % 16)
    encrypted, previous = b"", authenticator
    for offset in range(0, len(password), 16):
        mask = hashlib.md5(secret + previous).digest()  # RFC 2865 PAP, not credential storage.
        previous = bytes(a ^ b for a, b in zip(password[offset:offset + 16], mask))
        encrypted += previous
    attributes = (bytes((1, len(ACCOUNT) + 2)) + ACCOUNT + bytes((2, len(encrypted) + 2)) + encrypted
                  + bytes((4, 6, 127, 0, 0, 1)) + bytes((80, 18)) + b"\0" * 16)
    packet = struct.pack("!BBH", 1, identifier, 20 + len(attributes)) + authenticator + attributes
    # Message-Authenticator is required by hardened NPS installations too.
    return packet[:-16] + hmac.new(secret, packet, hashlib.md5).digest()


def send_denials(secret, count, *, socket_factory=socket.socket, random_bytes=os.urandom, pause=time.sleep):
    if type(count) is not int or count not in {1, 19, 20, 60}:
        raise ValueError("nps_lab_count_invalid")
    rejected = 0
    with socket_factory(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        # Connected UDP fixes the peer; never contact an external RADIUS source.
        client.connect(("127.0.0.1", 1812))
        for _ in range(count):
            identifier = random_bytes(1)[0]
            authenticator = random_bytes(16)
            packet = request(secret, identifier=identifier, authenticator=authenticator)
            client.send(packet)
            response = client.recv(4097)
            if len(response) < 20 or len(response) > 4096:
                return {"state": "not_proven", "code": "nps_lab_response_invalid", "rejected": rejected}
            code, response_id, length = struct.unpack("!BBH", response[:4])
            expected = hashlib.md5(response[:4] + authenticator + response[20:] + secret).digest()
            if (code != 3 or response_id != identifier or length != len(response)
                    or not hmac.compare_digest(expected, response[4:20])):
                return {"state": "not_proven", "code": "nps_lab_reject_unverified", "rejected": rejected}
            rejected += 1
            pause(0.1)
    return {"state": "radius_reject_verified", "rejected": rejected, "event_6273": "not_proven",
            "sli_queue": "not_proven", "smtp": "not_proven", "telegram": "not_proven"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, required=True, choices=(1, 19, 20, 60))
    args = parser.parse_args()
    try:
        root = Path("C:/SLI-Lab")
        if os.name != "nt" or not (root / "domain-owned").is_file() or not (root / "nps-owned").is_file():
            raise ValueError("nps_lab_not_owned")
        # Provision with the existing Write-LabSecret helper, never in a repo.
        secret = (root / "credentials/nps-radius.secret").read_bytes().strip()
        result = send_denials(secret, args.count)
    except Exception:
        result = {"state": "not_proven", "code": "nps_lab_unavailable"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["state"] == "radius_reject_verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
