"""Exercise real stdlib SMTP TLS wrapping over fake sockets, never a network."""
import io
import ssl
import time
import unittest
from unittest.mock import patch

from server.sli.core import notification_smtp as smtp


class Socket:
    def __init__(self, reply):
        self.reply = reply

    def makefile(self, mode):
        return io.BytesIO(self.reply)

    def settimeout(self, timeout):
        pass

    def sendall(self, data):
        pass

    def close(self):
        pass


class HostnameTests(unittest.TestCase):
    def test_real_stdlib_tls_and_starttls_use_configured_hostname(self):
        for mode in ("tls", "starttls"):
            with self.subTest(mode=mode):
                context = ssl.create_default_context()
                sock = Socket(b"220 fixture\r\n" if mode == "tls" else b"220 fixture\r\n250-fixture\r\n250 STARTTLS\r\n220 ready\r\n")
                def wrap(raw, *, server_hostname):
                    self.assertIs(raw, sock)
                    self.assertEqual(server_hostname, "smtp.example.invalid")
                    self.assertTrue(context.check_hostname)
                    self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                    return sock
                with patch("smtplib.socket.create_connection", return_value=sock), patch.object(context, "wrap_socket", side_effect=wrap) as wrapped:
                    client = smtp._SMTPSSL(context=context, timeout=5, local_hostname="example.invalid") if mode == "tls" else smtp._SMTP(timeout=5, local_hostname="example.invalid")
                    client.deadline = time.monotonic() + 30
                    client.connect("smtp.example.invalid", 465 if mode == "tls" else 587)
                    if mode == "starttls":
                        client.ehlo()
                        client.starttls(context=context)
                    wrapped.assert_called_once()
                    client.close()


if __name__ == "__main__":
    unittest.main()
