import gzip
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from server.sli.storage import history_source_diagnostics as diagnostic


class ArchiveDetailsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'archive.gz'
        self.row = {'event_id': 41, 'entity_id': 3, 'link_role': 'subject', 'role_id': 2}

    def block(self, rows):
        raw = b''.join(json.dumps({'kind': 'link_detail', 'row': row}).encode() + b'\n' for row in rows)
        compressed = gzip.compress(raw)
        self.path.write_bytes(compressed)
        return {'state': 'published', 'archive_kind': 'link_detail', 'object_location': str(self.path),
                'first_event_id': 40, 'last_event_id': 50, 'row_count': len(rows),
                'raw_bytes': len(raw), 'compressed_bytes': len(compressed),
                'raw_sha256': hashlib.sha256(raw).hexdigest(),
                'archive_sha256': hashlib.sha256(compressed).hexdigest()}

    def test_verified_archive_detects_present_and_missing_keys_without_payload(self):
        block = self.block([self.row])
        links = [dict(self.row), {'event_id': 42, 'entity_id': 4, 'role_id': 2, 'link_role': 'subject'}]
        result = diagnostic.inspect_archive_details(links, [block], no_archive_ids=set())
        self.assertEqual(result['missing_detail_links'], 1)
        self.assertEqual(result['missing_detail_events'], 1)
        self.assertEqual(result['sample_missing_detail_event_ids'], [42])
        self.assertNotIn('entity_id', json.dumps(result))

    def test_corruption_and_wrong_row_count_do_not_report_absence(self):
        block = self.block([self.row])
        block['raw_sha256'] = '0' * 64
        with self.assertRaises(diagnostic.DetailDiagnosticError):
            diagnostic.inspect_archive_details([self.row], [block], no_archive_ids=set())
        block = self.block([self.row])
        block['row_count'] = 2
        with self.assertRaises(diagnostic.DetailDiagnosticError):
            diagnostic.inspect_archive_details([self.row], [block], no_archive_ids=set())

    def test_actual_compressed_and_expanded_byte_limits_are_enforced(self):
        block = self.block([self.row])
        with patch_limit('MAX_ARCHIVE_COMPRESSED_BYTES', 1):
            block['compressed_bytes'] = 1  # forged metadata must not bypass actual read limit
            with self.assertRaises(diagnostic.DetailDiagnosticError):
                diagnostic.inspect_archive_details([self.row], [block], no_archive_ids=set())
        block = self.block([self.row])
        with patch_limit('MAX_ARCHIVE_RAW_BYTES', 1):
            block['raw_bytes'] = 1  # compressed stream expands beyond its declared size
            with self.assertRaises(diagnostic.DetailDiagnosticError):
                diagnostic.inspect_archive_details([self.row], [block], no_archive_ids=set())

    def test_no_archive_uses_compact_fallback(self):
        result = diagnostic.inspect_archive_details([self.row], [], no_archive_ids={41})
        self.assertEqual(result['missing_detail_links'], 0)

    def test_large_nested_row_is_rejected_before_json_decoding(self):
        from unittest.mock import patch
        row = {**self.row, 'evidence_json': list(range(300))}
        block = self.block([row])
        with (patch.object(diagnostic, 'MAX_ARCHIVE_ROW_BYTES', 256, create=True),
              patch.object(diagnostic.json, 'loads', side_effect=AssertionError('decoded oversized row'))):
            with self.assertRaisesRegex(diagnostic.DetailDiagnosticError, 'archive_budget'):
                diagnostic.inspect_archive_details([self.row], [block], no_archive_ids=set())

    def test_repeated_archive_identity_is_inconclusive(self):
        block = self.block([self.row, self.row])
        with self.assertRaisesRegex(diagnostic.DetailDiagnosticError, 'archive_duplicate'):
            diagnostic.inspect_archive_details([self.row], [block], no_archive_ids=set())

    def test_postgres_bytea_hashes_are_verified(self):
        block = self.block([self.row])
        for key in ('raw_sha256', 'archive_sha256'):
            block[key] = bytes.fromhex(block[key])
        result = diagnostic.inspect_archive_details([self.row], [block], no_archive_ids=set())
        self.assertEqual(result['missing_detail_links'], 0)

    def test_changed_frontier_discards_detail_counts(self):
        block = self.block([self.row])
        class Connection:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def cursor(self): return self
            def execute(self, sql, params=()): self.sql = sql
            def fetchone(self): return {'role': 'adlog_storage_worker'}
            def fetchall(inner):
                if 'from events_v2_core' in inner.sql:
                    from datetime import datetime, timezone
                    return [{'id': 41, 'time_created_utc': datetime(2026, 10, 1, tzinfo=timezone.utc)}]
                if 'from event_entity_link_blocks_v2' in inner.sql: return [self.row]
                return [block]
        frontier = iter((40, 41))
        result = diagnostic.inspect_batch(connect=Connection, read_frontier=lambda: next(frontier),
                                          catalog=lambda *args: {}, check_archive=True)
        self.assertFalse(result['detail_presence_checked'])
        self.assertNotIn('missing_detail_links', result)
        self.assertEqual(result['reason'], 'history_frontier_changed_during_diagnostic')

    def test_extra_detail_for_event_without_source_links_is_inconclusive(self):
        block = self.block([self.row])
        with self.assertRaises(diagnostic.DetailDiagnosticError):
            diagnostic.inspect_archive_details([], [block], no_archive_ids=set(), archive_ids={41})


def patch_limit(name, value):
    from unittest.mock import patch
    return patch.object(diagnostic, name, value)
