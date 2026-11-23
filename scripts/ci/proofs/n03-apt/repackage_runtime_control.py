"""Create a control-only compatibility package from the attested n03 runtime."""

import argparse
from copy import copy
import gzip
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile
import zlib


PACKAGE = "sli-runtime-cp3146-n03-20261026"
ORIGINAL_VERSION = "3.14.6-1~deb13"
COMPATIBILITY_VERSION = "3.14.6-3~deb13"
ARCHITECTURE = "amd64"
ORIGINAL_SHA256 = "46986d230f363f3af7e2fd4c4f25ee3da9ae3964982812f404f24b6d654a44d9"
ORIGINAL_SIZE = 27_727_168
ORIGINAL_LIBSSL = "libssl3t64 (= 3.5.7-1~deb13u3)"
REHEARSAL_ALTERNATIVES = {
    "libc6 (= 2.41-12+deb13u4)": "libc6 (= 2.41-12+deb13u5)",
    "zlib1g (= 1:1.3.dfsg+really1.3.1-1+b1)": "zlib1g (= 1:1.3.dfsg+really1.3.1-1+deb13u1)",
}
CONTROL_FIELDS = (
    "Package", "Version", "Architecture", "Maintainer", "Section",
    "Priority", "Depends", "Description", "Installed-Size",
)
DEBIAN_VERSION = re.compile(r"(?:[0-9]+:)?[0-9][a-zA-Z0-9.+~]*(?:-[a-zA-Z0-9.+~]+)?")
EXACT_DEPENDENCY = re.compile(r"([a-z0-9][a-z0-9+.-]*) \(= [0-9a-zA-Z:.+~_-]+\)")
AR_MAGIC = b"!<arch>\n"
AR_TRAILER = b"\x60\n"
MAX_CONTROL_TAR_SIZE = 64 * 1024


def read_ar_member(package, offset, expected_name):
    header = package[offset:offset + 60]
    if (len(header) != 60 or header[58:] != AR_TRAILER
            or header[:16].rstrip(b" ").removesuffix(b"/") != expected_name):
        raise ValueError("Invalid Debian package member: " + expected_name.decode("ascii"))
    size_field = header[48:58].strip()
    if not size_field.isdigit():
        raise ValueError("Invalid Debian package member size")
    start = offset + 60
    end = start + int(size_field)
    padded_end = end + (end - start) % 2
    if padded_end > len(package) or package[end:padded_end] not in (b"", b"\n"):
        raise ValueError("Invalid Debian package member padding or truncated member")
    return package[start:end], padded_end


def control_fields(control):
    text = control.decode("utf-8")
    rows = [line.partition(": ") for line in text.removesuffix("\n").split("\n")]
    if (not text.endswith("\n") or tuple(name for name, _, _ in rows) != CONTROL_FIELDS
            or any(not separator or not value or re.search(r"[\x00-\x1f\x7f]", value)
                   for _, separator, value in rows)):
        raise ValueError("Unexpected runtime control fields")
    fields = {name: value for name, _, value in rows}
    if ((fields["Package"], fields["Version"], fields["Architecture"])
            != (PACKAGE, ORIGINAL_VERSION, ARCHITECTURE)):
        raise ValueError("Unexpected runtime control package identity")
    if not re.fullmatch(r"[0-9]+", fields["Installed-Size"]):
        raise ValueError("Unexpected runtime control installed size")
    return fields


def rewrite_control(compressed, libssl_floor):
    try:
        with gzip.GzipFile(fileobj=BytesIO(compressed)) as stream:
            original_tar = stream.read(MAX_CONTROL_TAR_SIZE + 1)
        if len(original_tar) > MAX_CONTROL_TAR_SIZE:
            raise ValueError("Unexpected runtime control archive size")
        with tarfile.open(fileobj=BytesIO(original_tar), mode="r:") as archive:
            members = archive.getmembers()
            if ([member.name for member in members] != [".", "./control"]
                    or not members[0].isdir() or not members[1].isfile()):
                raise ValueError("Unexpected runtime control archive members")
            fields = control_fields(archive.extractfile(members[1]).read())
    except (OSError, EOFError, UnicodeDecodeError, tarfile.TarError, zlib.error) as error:
        raise ValueError("Invalid runtime control archive") from error

    dependencies = fields["Depends"].split(", ")
    matches = [EXACT_DEPENDENCY.fullmatch(dependency) for dependency in dependencies]
    if (len(matches) != 16 or any(match is None for match in matches)
            or len({match[1] for match in matches}) != 16
            or not ({ORIGINAL_LIBSSL} | REHEARSAL_ALTERNATIVES.keys()) <= set(dependencies)):
        raise ValueError("Unexpected runtime control dependencies")

    dependencies[dependencies.index(ORIGINAL_LIBSSL)] = f"libssl3t64 (>= {libssl_floor})"
    for historical, current in REHEARSAL_ALTERNATIVES.items():
        dependencies[dependencies.index(historical)] = f"{historical} | {current}"
    fields["Depends"] = ", ".join(dependencies)
    fields["Version"] = COMPATIBILITY_VERSION
    fields["Provides"] = f"{PACKAGE} (= {ORIGINAL_VERSION})"
    body = "".join(f"{name}: {value}\n" for name, value in fields.items()).encode("utf-8")

    control_member = copy(members[1])
    control_member.size = len(body)
    result = BytesIO()
    with gzip.GzipFile(filename="", fileobj=result, mode="wb", mtime=0) as stream:
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            archive.addfile(members[0])
            archive.addfile(control_member, BytesIO(body))
    return result.getvalue()


def repack_runtime(original, *, original_sha256, libssl_floor):
    """Use a caller's trusted artifact digest and independently qualified library floor."""
    source_digest = sha256(original).hexdigest()
    if source_digest != original_sha256:
        raise ValueError("Incorrect source package SHA-256")
    if not DEBIAN_VERSION.fullmatch(libssl_floor):
        raise ValueError("Invalid Debian libssl3t64 floor")
    if not original.startswith(AR_MAGIC):
        raise ValueError("Invalid Debian package header")

    format_version, control_offset = read_ar_member(original, len(AR_MAGIC), b"debian-binary")
    control, data_offset = read_ar_member(original, control_offset, b"control.tar.gz")
    data, end = read_ar_member(original, data_offset, b"data.tar.gz")
    if format_version != b"2.0\n" or end != len(original) or not data.startswith(b"\x1f\x8b\x08"):
        raise ValueError("Unexpected Debian package format or data member")
    new_control = rewrite_control(control, libssl_floor)

    control_header = original[control_offset:control_offset + 60]
    size_field = str(len(new_control)).encode("ascii").ljust(10)
    padding = b"\n" if len(new_control) % 2 else b""
    # Keep the other ar members, including their headers and padding, byte-for-byte.
    output = (original[:control_offset] + control_header[:48] + size_field + AR_TRAILER
              + new_control + padding + original[data_offset:])
    return output, {
        "package": PACKAGE,
        "architecture": ARCHITECTURE,
        "source_version": ORIGINAL_VERSION,
        "source_sha256": source_digest,
        "version": COMPATIBILITY_VERSION,
        "sha256": sha256(output).hexdigest(),
        "data_tar_gz_sha256": sha256(data).hexdigest(),
        "provides": f"{PACKAGE} (= {ORIGINAL_VERSION})",
        "libssl3t64_minimum": libssl_floor,
        "rehearsal_alternatives": REHEARSAL_ALTERNATIVES,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="original pinned n03 .deb")
    parser.add_argument("--output", required=True, type=Path, help="new .deb path")
    parser.add_argument("--libssl-floor", required=True, help="independently qualified Debian package version")
    args = parser.parse_args(argv)

    try:
        if not args.source.is_file():
            raise ValueError("Source package must be a regular file")
        with args.source.open("rb") as stream:
            original = stream.read(ORIGINAL_SIZE + 1)
        if len(original) != ORIGINAL_SIZE:
            raise ValueError("Incorrect source package size")
        output, provenance = repack_runtime(original, original_sha256=ORIGINAL_SHA256, libssl_floor=args.libssl_floor)
        with tempfile.TemporaryDirectory(dir=args.output.parent) as temporary:
            staged = Path(temporary) / "runtime.deb"
            staged.write_bytes(output)
            os.link(staged, args.output)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(json.dumps(provenance, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
