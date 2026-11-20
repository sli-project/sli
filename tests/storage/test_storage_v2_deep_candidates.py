"""Synthetic-only exact deep search regression; also runnable with unittest."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

from server.sli.storage.storage_v2_archive import (
    ArchiveIntegrityError, ArchivePublisher, ArchiveReader, InMemoryArchiveManifestStore,
)
from server.sli.storage.storage_v2_runtime import StorageV2RuntimeReader


def row(event_id, second, **changes):
    return dict(id=event_id, server_id=1, domain_id=1, log_source_id=1,
                event_id=4624, event_record_id=event_id,
                time_created_utc=f"2026-10-20T00:00:{second:02d}Z",
                message_text="needle", **changes)


class DeepCandidatesTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.manifest = InMemoryArchiveManifestStore()
        self.publisher = ArchivePublisher(Path(self.directory.name), self.manifest)
        self.archive = ArchiveReader(self.manifest)
        self.store = Mock()
        self.reader = StorageV2RuntimeReader(self.store, self.archive)

    def publish(self, rows):
        return self.publisher.publish_rows(archive_set_id=str(uuid4()), archive_kind="event",
                                           block_index=0, rows=rows)

    def search(self, candidates, limit=2):
        return self.reader.deep_search_candidates(term="needle", candidates=candidates,
                                                  max_results=limit, max_blocks=8)

    def test_exact_candidates_before_limit_and_metadata_order(self):
        a, excluded, b = row(100, 50), row(101, 30), row(102, 10)
        self.publish([a, excluded, b])
        self.assertEqual([r["id"] for r in self.search([a, b], 1)], [100])
        self.assertEqual([r["id"] for r in self.search([b, a])], [102, 100])
        self.store.get_event_summary.assert_not_called()

    def test_missing_hot_and_mixed_payloads_are_not_complete(self):
        a, b = row(100, 50), row(102, 10)
        with self.assertRaises(KeyError):
            self.search([a])
        self.publish([a])
        with self.assertRaises(KeyError):
            self.search([a, b])
        self.assertEqual(self.search([]), [])

    def test_identity_and_hash_guards_survive(self):
        a = row(100, 50)
        block = self.publish([a])
        with self.assertRaises(ArchiveIntegrityError):
            self.search([{**a, "server_id": 2}])
        Path(block.object_location).write_bytes(b"bad hash")
        with self.assertRaises(ArchiveIntegrityError):
            self.search([a])

    def test_nonmatching_corrupt_candidate_is_verified_before_limit(self):
        a, b = row(100, 50), row(102, 10)
        b["message_text"] = "different"
        self.publish([a, b])
        with self.assertRaises(ArchiveIntegrityError):
            self.search([a, {**b, "server_id": 2}], 1)

    def test_account_match_precedes_limit_and_preserves_exact_case(self):
        a, b, c = row(100, 50), row(101, 30), row(102, 10)
        a["subject_user_name"] = "Alice"
        b["subject_user_name"] = "alice-prefix"
        c["target_user_name"] = "alice"
        self.publish([a, b, c])
        result = self.reader.deep_search_candidates(
            term="needle", candidates=[a, b, c], max_results=1, account_values=["alice"],
        )
        self.assertEqual([r["id"] for r in result], [102])

    def test_candidate_limit_and_canonical_record_keys(self):
        with self.assertRaisesRegex(ValueError, "candidate limit; narrow"):
            self.search([row(100, 50)] * 10001)
        a = row(100, 50)
        self.publish([a])
        self.assertEqual(self.search([{**a, "event_record_id": 0}])[0]["event_record_id"], 0)
        self.assertIsNone(self.search([{**a, "event_record_id": None}])[0]["event_record_id"])

    def test_no_match_and_single_verified_block_read(self):
        a, b = row(100, 50), row(102, 10)
        a["message_text"] = "other"
        self.publish([a, b])
        with unittest.mock.patch.object(self.archive, "_read_verified_block", wraps=self.archive._read_verified_block) as read:
            self.assertEqual([r["id"] for r in self.search([a, b], 1)], [102])
            self.assertEqual(read.call_count, 1)
        self.assertEqual(self.search([a]), [])

    def test_one_archive_read_and_block_budget(self):
        rows = [row(i, i) for i in range(9)]
        for item in rows:
            self.publish([item])
        with self.assertRaises(ArchiveIntegrityError):
            self.search(rows)


if __name__ == "__main__":
    unittest.main()
