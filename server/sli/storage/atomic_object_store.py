"""Same-volume atomic publication for immutable filesystem objects.

This is the shared filesystem half of evidence-first persistence.  It does not
own a database manifest or decide retention.  Callers prepare and verify bytes,
commit their own durable manifest at the appropriate boundary, and publish the
prepared object with an atomic same-volume rename.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path


class AtomicObjectError(RuntimeError):
    """Fail-closed immutable object publication error."""


class AtomicObjectIntegrityError(AtomicObjectError):
    """Existing or staged bytes disagree with the requested object identity."""


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _same_volume(left: Path, right: Path) -> bool:
    if os.name == "nt":
        return left.drive.casefold() == right.drive.casefold()
    return left.stat().st_dev == right.stat().st_dev


@dataclass(frozen=True)
class PreparedAtomicObject:
    relative_name: str
    sha256: str
    size_bytes: int
    partial_path: Path = field(repr=False)
    final_path: Path = field(repr=False)
    already_published: bool = False

    @property
    def readable_path(self) -> Path:
        return self.final_path if self.already_published else self.partial_path


class AtomicObjectStore:
    """Prepare, verify and atomically publish immutable objects under one root."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        if not self.root.is_absolute():
            raise AtomicObjectError("atomic object root must be absolute")
        self.staging = self.root / "staging"
        self.published = self.root / "published"
        self.quarantine = self.root / "quarantine"
        for path in (self.staging, self.published, self.quarantine):
            path.mkdir(parents=True, exist_ok=True)
        if not _same_volume(self.staging, self.published):
            raise AtomicObjectError(
                "staging and published object paths must be on the same volume"
            )

    def prepare(
        self,
        relative_name: str,
        payload: bytes,
        *,
        expected_sha256: str | None = None,
    ) -> PreparedAtomicObject:
        if not isinstance(payload, bytes) or not payload:
            raise AtomicObjectError("immutable object payload must be non-empty bytes")
        relative = self._relative_path(relative_name)
        digest = sha256_hex(payload)
        if expected_sha256 is not None and digest != expected_sha256.casefold():
            raise AtomicObjectIntegrityError(
                "immutable object payload SHA-256 does not match the contract"
            )
        partial = self.staging / Path(str(relative) + ".partial")
        final = self.published / relative
        quarantine = self.quarantine / Path(str(relative) + ".hash-mismatch")
        for parent in (partial.parent, final.parent, quarantine.parent):
            parent.mkdir(parents=True, exist_ok=True)

        if final.exists():
            self._verify_path(final, digest, len(payload))
            return PreparedAtomicObject(
                relative_name=relative.as_posix(),
                sha256=digest,
                size_bytes=len(payload),
                partial_path=partial,
                final_path=final,
                already_published=True,
            )

        if partial.exists():
            try:
                self._verify_path(partial, digest, len(payload))
            except AtomicObjectIntegrityError:
                if quarantine.exists():
                    raise AtomicObjectIntegrityError(
                        "quarantine target already exists for mismatched partial object"
                    )
                os.replace(partial, quarantine)
                _fsync_directory(quarantine.parent)
                raise
        else:
            with partial.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _fsync_directory(partial.parent)
            self._verify_path(partial, digest, len(payload))

        return PreparedAtomicObject(
            relative_name=relative.as_posix(),
            sha256=digest,
            size_bytes=len(payload),
            partial_path=partial,
            final_path=final,
        )

    def publish(self, prepared: PreparedAtomicObject) -> Path:
        if prepared.already_published:
            self.verify(prepared)
            return prepared.final_path
        self._require_store_path(prepared.partial_path, self.staging)
        self._require_store_path(prepared.final_path, self.published)
        self._verify_path(
            prepared.partial_path,
            prepared.sha256,
            prepared.size_bytes,
        )
        if prepared.final_path.exists():
            self._verify_path(
                prepared.final_path,
                prepared.sha256,
                prepared.size_bytes,
            )
            prepared.partial_path.unlink()
            _fsync_directory(prepared.partial_path.parent)
        else:
            os.replace(prepared.partial_path, prepared.final_path)
            _fsync_directory(prepared.final_path.parent)
        self._verify_path(
            prepared.final_path,
            prepared.sha256,
            prepared.size_bytes,
        )
        return prepared.final_path

    def verify(self, prepared: PreparedAtomicObject) -> None:
        self._require_store_path(prepared.final_path, self.published)
        self._verify_path(
            prepared.final_path,
            prepared.sha256,
            prepared.size_bytes,
        )

    def read_verified(
        self,
        relative_name: str,
        *,
        expected_sha256: str,
        expected_size_bytes: int,
    ) -> bytes:
        relative = self._relative_path(relative_name)
        final = self.published / relative
        digest = str(expected_sha256 or "").casefold()
        self._require_store_path(final, self.published)
        self._verify_path(final, digest, int(expected_size_bytes))
        return final.read_bytes()

    def _relative_path(self, value: str) -> Path:
        text = str(value or "").replace("\\", "/")
        relative = Path(text)
        if (
            not text
            or relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise AtomicObjectError("immutable object name must be a safe relative path")
        self._require_store_path(self.published / relative, self.published)
        return relative

    @staticmethod
    def _verify_path(path: Path, digest: str, size_bytes: int) -> None:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise AtomicObjectIntegrityError("immutable object SHA-256 is invalid")
        if not path.is_file():
            raise AtomicObjectIntegrityError("immutable object file is missing")
        payload = path.read_bytes()
        if len(payload) != int(size_bytes) or sha256_hex(payload) != digest:
            raise AtomicObjectIntegrityError("immutable object SHA-256 mismatch")

    @staticmethod
    def _require_store_path(path: Path, root: Path) -> None:
        try:
            path.resolve().relative_to(root.resolve())
        except ValueError as exc:
            raise AtomicObjectError("immutable object path escapes its store root") from exc
