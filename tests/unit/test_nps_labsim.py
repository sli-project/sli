"""Loopback-only real-protocol request generation with a fake UDP peer."""
import hashlib
import struct

import pytest

from tools.lab import nps_denials as lab


SECRET = b"synthetic-radius-secret"


def test_radius_request_pap_and_response_authentication_without_network():
    calls = []
    class Client:
        def __init__(self, *args):
            calls.append(args)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, timeout):
            assert timeout == 3
        def connect(self, address):
            assert address == ("127.0.0.1", 1812)
        def send(self, packet):
            assert SECRET not in packet and b"labsim-invalid-password" not in packet
            assert packet[20:22] == bytes((1, len(lab.ACCOUNT) + 2))
            self.packet = packet
        def recv(self, maximum):
            assert maximum == 4097
            header = struct.pack("!BBH", 3, self.packet[1], 20)
            return header + hashlib.md5(header + self.packet[4:20] + SECRET).digest()
    result = lab.send_denials(SECRET, 19, socket_factory=Client, pause=lambda _: None)
    assert result["rejected"] == 19 and result["state"] == "radius_reject_verified"
    assert result["event_6273"] == result["smtp"] == result["telegram"] == "not_proven"


@pytest.mark.parametrize("response", [b"", b"x" * 4097, struct.pack("!BBH", 3, 1, 20) + b"x" * 16])
def test_bad_radius_reply_cannot_be_claimed_as_nps_evidence(response):
    class Client:
        def __init__(self, *args):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, *args):
            pass
        def connect(self, address):
            assert address == ("127.0.0.1", 1812)
        def send(self, *args):
            pass
        def recv(self, *args):
            return response
    assert lab.send_denials(SECRET, 1, socket_factory=Client, pause=lambda _: None)["state"] == "not_proven"


def test_lab_requires_explicit_windows_ownership_and_redacts_errors(monkeypatch, capsys):
    monkeypatch.setattr(lab.os, "name", "posix")
    monkeypatch.setattr(lab, "Path", lambda _: None)
    monkeypatch.setattr("sys.argv", ["nps_denials", "--count", "20"])
    assert lab.main() == 1
    assert capsys.readouterr().out == '{"code": "nps_lab_unavailable", "state": "not_proven"}\n'


@pytest.mark.parametrize("count", [0, 21, 10000, True])
def test_bounded_lab_counts(count):
    with pytest.raises(ValueError, match="nps_lab_count_invalid"):
        lab.send_denials(SECRET, count)
