"""Sequence replay remains distinct from a recoverable forward gap."""
import unittest
from sli_agent.delivery_diagnostics import safe_code


class SequenceReasonCodesTests(unittest.TestCase):
    def test_gap_and_replay_are_retained(self):
        self.assertEqual(safe_code('agent_sequence_gap'),'agent_sequence_gap')
        self.assertEqual(safe_code('agent_sequence_replayed'),'agent_sequence_replayed')

    def test_unknown_or_freeform_reason_is_still_redacted(self):
        self.assertEqual(safe_code('unknown private detail'),'agent_delivery_rejected')
