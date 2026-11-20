"""Frozen Python suffix rebuild hashes for the real-schema delayed DC packet test."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path.cwd()))
from server.sli.storage.storage_v2_link_blocks import (
    build_link_blocks,
    rebuild_link_block_suffix,
    validate_link_blocks,
)

vectors = []
for role in (1, 2):
    rows = [
        {"event_id": event, "entity_id": 1001, "role_id": role}
        for event in [*range(2, 770), *range(771, 1539)]
    ]
    blocks = build_link_blocks(rows)
    stages = {}
    for name, event in (("baseline", None), ("middle", 770), ("first", 1)):
        if event is not None:
            incoming = [{"event_id": event, "entity_id": 1001, "role_id": role}]
            start = next(i for i, block in enumerate(blocks) if block.last_event_id >= event)
            blocks = blocks[:start] + rebuild_link_block_suffix(blocks[start:], incoming)
            rows += incoming
            assert blocks == build_link_blocks(rows)
        validate_link_blocks(blocks)
        stages[name] = [
            {"number": block.block_no, "count": len(block.event_ids),
             "first": block.first_event_id, "last": block.last_event_id,
             "hash": block.identity_sha256.hex()}
            for block in blocks
        ]
    vectors.append({"entity": 1001, "role": role, "stages": stages})

Path(__file__).with_name("link-suffix-source.json").write_text(
    json.dumps(vectors, indent=2) + "\n", encoding="utf-8"
)
