"""Bound HTTP header reads without timers or changing body read semantics."""
from __future__ import annotations

import io
import time


class _DeadlineReader(io.RawIOBase):
    def __init__(self, raw, connection):
        self.raw = raw
        self.connection = connection
        self.deadline = None
        self.previous_timeout = None

    def readable(self):
        return True

    def arm(self, seconds):
        self.previous_timeout = self.connection.gettimeout()
        if self.previous_timeout is not None:
            seconds = min(seconds, self.previous_timeout)
        self.deadline = time.monotonic() + seconds

    def disarm(self):
        if self.deadline is not None:
            self.deadline = None
            self.connection.settimeout(self.previous_timeout)

    def readinto(self, target):
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP header deadline exceeded")
            self.connection.settimeout(remaining)
        # SocketIO.readinto performs one recv, unlike BufferedReader.readline,
        # which may perform arbitrarily many reads as a client trickles bytes.
        count = self.raw.readinto(target)
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError("HTTP header deadline exceeded")
        return count

    def close(self):
        try:
            self.raw.close()
        finally:
            super().close()


class HeaderDeadlineMixin:
    # Allow browser preconnects a grace period, but never an indefinite slot.
    header_timeout_seconds = 30

    def setup(self):
        buffer_size = self.rbufsize
        self.rbufsize = 0
        try:
            super().setup()
        finally:
            self.rbufsize = buffer_size
        self._header_reader = _DeadlineReader(self.rfile, self.connection)
        self.rfile = (
            io.BufferedReader(self._header_reader, buffer_size if buffer_size > 0 else io.DEFAULT_BUFFER_SIZE)
            if buffer_size != 0 else self._header_reader
        )

    def handle_one_request(self):
        self._header_reader.arm(self.header_timeout_seconds)
        try:
            super().handle_one_request()
        finally:
            # Includes EOF, invalid/oversized request lines and read timeouts.
            self._header_reader.disarm()

    def parse_request(self):
        try:
            return super().parse_request()
        finally:
            # Headers are complete: body, route and response use their existing
            # timeout policies. Keep any read-ahead body bytes in rfile.
            self._header_reader.disarm()
