import hashlib
import json
from pathlib import Path

from scripts.maintenance.verify_independent_corpus_copy import verify_copy


def _write_fixture(root: Path) -> None:
    events = root / "events"
    events.mkdir(parents=True)
    payload = b"bounded-corpus-copy"
    (events / "0000.jsonl.gz").write_bytes(payload)
    manifest = {
        "backup": {
            "rows": 1,
            "identity_sha256": "identity",
            "full_payload_sequence_sha256": "payload-sequence",
        },
        "files": [
            {
                "name": "0000.jsonl.gz",
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        ],
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )


def test_copy_verification_requires_distinct_disk_and_exact_hashes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    copy = tmp_path / "copy"
    _write_fixture(source)
    _write_fixture(copy)

    valid = verify_copy(
        source,
        copy,
        source_disk_number=1,
        copy_disk_number=0,
    )
    assert valid["status"] == "ok"
    assert valid["copy"]["separate_physical_disk"] is True
    assert valid["files"]["sha256_mismatches"] == []

    same_disk = verify_copy(
        source,
        copy,
        source_disk_number=1,
        copy_disk_number=1,
    )
    assert same_disk["status"] == "blocked"
    assert "copy_is_not_on_a_separate_physical_disk" in same_disk["blockers"]

    (copy / "events" / "0000.jsonl.gz").write_bytes(b"corrupt")
    corrupt = verify_copy(
        source,
        copy,
        source_disk_number=1,
        copy_disk_number=0,
    )
    assert corrupt["status"] == "blocked"
    assert "file_size_mismatch" in corrupt["blockers"]
