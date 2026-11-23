"""Verify the exact local inputs or stage an unregistered disposable APT fixture."""
import argparse
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
from urllib.request import urlopen


PRODUCER_SHA = "ffe460080197c0442736e417e974221ceea77737d1626e966cdcfccc1e679e69"
PREVIOUS_PRODUCER_SHA = "9da76035db648abb7ca766177cdfd64954d9be2e504301a280c02984e5052758"
PREVIOUS_WRAPPER_SHA = "c36ed9b1170fd83120144711d81e91f333f0e5a49975316bc1226ba794dacdd8"
PINS_SHA = "bc98cdacefbed6e400c96fc8b885877df1cc71ed204f0f9cdfcc320fb7b602a7"
CURRENT_LOCK_SHA = "4fe73ca3ea4f61e2383cc8812d08f460bc923ec3302790cb21261493bf79af7c"
RUNTIME_SHA = "46986d230f363f3af7e2fd4c4f25ee3da9ae3964982812f404f24b6d654a44d9"
DATA_SHA = "6510d97a1a18f7c0f18e5182627fe8bf3d56b00d2f4cd4232a7fd43d1f0adad2"
ORIGINAL = "sli-runtime-cp3146-n03-20261026_3.14.6-1~deb13_amd64.deb"
FLOOR_VERSION = "3.5.7-1~deb13u3"
CURRENT_VERSION = "3.5.9-1~deb13u1"
OPENSSL = {"libssl3t64", "openssl", "openssl-provider-legacy"}
GLIBC_FLOOR = "2.41-12+deb13u4"
ZLIB_FLOOR = "1:1.3.dfsg+really1.3.1-1+b1"
CURRENT = {
    **dict.fromkeys(OPENSSL, CURRENT_VERSION),
    "libc6": "2.41-12+deb13u5",
    "libc-bin": "2.41-12+deb13u5",
    "zlib1g": "1:1.3.dfsg+really1.3.1-1+deb13u1",
}


def verified(path, expected, size=None):
    assert path.is_file() and not path.is_symlink(), path.name
    body = path.read_bytes()
    assert size is None or len(body) == size, path.name
    assert sha256(body).hexdigest() == expected, path.name
    return body


def original_packages(pins):
    spec = pins["runtime_build"]
    rows = {row["name"]: row for row in spec["debian_artifacts"]}
    rows.update((row["name"], row) for row in pins["packages"])
    pinned = {row["name"]: row["version"] for row in spec["debian_runtime"]}
    assert len(pinned) == 16 and pinned["libssl3t64"] == FLOOR_VERSION
    assert pinned["libc6"] == rows["libc-bin"]["version"] == GLIBC_FLOOR
    assert pinned["zlib1g"] == ZLIB_FLOOR
    assert all(rows[name]["version"] == version for name, version in pinned.items())
    # Extra dependencies of ca-certificates, libgcc and libreadline.
    names = pinned.keys() | CURRENT.keys() | {"debconf", "gcc-14-base", "readline-common"}
    assert len(names) == 22
    return pinned, {name: rows[name] for name in sorted(names)}


def current_file(row, directory):
    name = PurePosixPath(row["Filename"]).name
    if directory is not None:
        return verified(directory / name, row["SHA256"], int(row["Size"]))
    # Paths and hashes were read from the Debian archive's verified InRelease index.
    origin = "https://deb.debian.org/debian/"
    assert row["Filename"].startswith(("pool/main/o/openssl/", "pool/main/g/glibc/", "pool/main/z/zlib/"))
    with urlopen(origin + row["Filename"], timeout=30) as connection:
        assert connection.geturl().startswith(origin)
        body = connection.read(int(row["Size"]) + 1)
    assert len(body) == int(row["Size"]) and sha256(body).hexdigest() == row["SHA256"], name
    return body


def stage_inputs(directory, original, previous, wrapper, old_debs, current):
    # The private parent stays closed; APT's _apt reader needs the mounted child.
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    entries = {
        "runtime-old.deb": original, "runtime-ssl-only.deb": previous,
        "runtime-wrapper.deb": wrapper, **old_debs, **current,
    }
    for group in ("common", "floor", "current"):
        (directory / group).mkdir(mode=0o755)
        (directory / group).chmod(0o755)
    manifest = []
    for path, data in sorted(entries.items()):
        staged = directory / path
        staged.write_bytes(data)
        staged.chmod(0o644)
        manifest.append(f"{sha256(data).hexdigest()}  {path}\n")
    (directory / "sha256sums.txt").write_text("".join(manifest), encoding="ascii", newline="\n")


def main():
    if not __debug__:
        raise SystemExit("Run with assertions enabled.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--previous-producer", type=Path, required=True)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--kit", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, help="Optional separately fetched public original")
    parser.add_argument("--current-cache", type=Path, help="Use only previously downloaded current packages")
    parser.add_argument("--stage", type=Path, help="Optional new, private disposable-test input directory")
    args = parser.parse_args()
    producer_bytes = verified(args.producer, PRODUCER_SHA)
    producer = {"__name__": "verified_n03_repack"}
    exec(compile(producer_bytes, str(args.producer), "exec"), producer)
    previous_bytes = verified(args.previous_producer, PREVIOUS_PRODUCER_SHA)
    previous_producer = {"__name__": "verified_n03_ssl_repack"}
    exec(compile(previous_bytes, str(args.previous_producer), "exec"), previous_producer)
    pins = json.loads(verified(args.pins, PINS_SHA))
    current_lock = Path(__file__).with_name("current-system-family-lock.json")
    lock = json.loads(verified(current_lock, CURRENT_LOCK_SHA))["packages"]
    assert {name: row["Version"] for name, row in lock.items()} == CURRENT
    assert all(row["Architecture"] == "amd64" for row in lock.values())

    original = verified(args.runtime or args.kit / ORIGINAL, RUNTIME_SHA, 27_727_168)
    pinned, packages = original_packages(pins)
    fixture = {}
    for name, row in packages.items():
        filename = PurePosixPath(row["filename"]).name
        group = "floor" if name in CURRENT else "common"
        fixture[f"{group}/{filename}"] = verified(args.kit / filename, row["sha256"], int(row["size"]))

    wrapper, provenance = producer["repack_runtime"](
        original, original_sha256=RUNTIME_SHA, libssl_floor=FLOOR_VERSION)
    previous, previous_provenance = previous_producer["repack_runtime"](
        original, original_sha256=RUNTIME_SHA, libssl_floor=FLOOR_VERSION)
    assert provenance["data_tar_gz_sha256"] == DATA_SHA
    assert sha256(previous).hexdigest() == previous_provenance["sha256"] == PREVIOUS_WRAPPER_SHA
    for blob in (original, previous, wrapper):
        _, position = producer["read_ar_member"](blob, 8, b"debian-binary")
        _, position = producer["read_ar_member"](blob, position, b"control.tar.gz")
        data, end = producer["read_ar_member"](blob, position, b"data.tar.gz")
        assert end == len(blob) and sha256(data).hexdigest() == DATA_SHA

    if args.stage is not None:
        current = {f"current/{PurePosixPath(row['Filename']).name}": current_file(row, args.current_cache)
                   for row in lock.values()}
        stage_inputs(args.stage, original, previous, wrapper, fixture, current)
    print(json.dumps({"control": provenance, "previous_wrapper_sha256": PREVIOUS_WRAPPER_SHA,
                      "old_exact_dependencies": pinned,
                      "verified_historical_packages": len(fixture), "stage_written": args.stage is not None},
                     sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
