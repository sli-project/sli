"""The public event DTO must accept authorized partial projections."""
import unittest

from pydantic import ValidationError

from server.sli.reporting.ui_api_models import EntityWorkspaceEvent


class EntityEventProjectionContractTests(unittest.TestCase):
    def test_projected_events_serialize_without_inventing_withheld_values(self):
        from server.sli.reporting.ui_workspace_entity import _entity_detail_event_item

        source = {"event_db_id": 101, "event_id": 4624, "link_role": "actor",
                  "confidence": 0.0, "server": "synthetic", "channel": "Security",
                  "provider_name": "synthetic", "subject_user_name": "synthetic-actor",
                  "target_user_name": "synthetic-target", "time_created_utc": "2026-10-21T00:00:00Z"}
        for projection in ["metadata", "technical", "security_metadata", "full"]:
            with self.subTest(projection=projection):
                projected = _entity_detail_event_item({**source, "_field_projection": projection})
                serialized = EntityWorkspaceEvent.model_validate(projected).model_dump(mode="json")
                for field in ["event_id", "link_role", "confidence", "actor", "target", "provider_name"]:
                    self.assertEqual(serialized[field], projected.get(field))
                self.assertEqual(serialized["event_db_id"], 101)
                if projection == "full":
                    self.assertEqual(serialized, projected)

    def test_missing_and_null_are_not_fabricated_zero_or_context(self):
        for data in [{"event_db_id": 101}, {"event_db_id": 101, "event_id": None,
                                             "confidence": None, "link_role": None}]:
            result = EntityWorkspaceEvent.model_validate(data).model_dump(mode="json")
            for field in ["event_id", "link_role", "confidence"]:
                self.assertIsNone(result[field])

    def test_exact_event_id_remains_required_positive(self):
        for value in [None, 0, -1]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                EntityWorkspaceEvent(event_db_id=value)
        with self.assertRaises(ValidationError):
            EntityWorkspaceEvent()

    def test_workspace_filters_denied_candidates_before_hydration_and_serialization(self):
        from contextlib import ExitStack
        from unittest.mock import patch

        from server.sli.reporting import ui_workspace_entity as workspace
        from server.sli.reporting.ui_api_models import EntityWorkspaceDetailResponse

        candidates = [
            {"event_db_id": 101, "domain_id": 1, "server_id": 1},
            {"event_db_id": 102, "domain_id": 2, "server_id": 2},
        ]
        entity = {"id": 7, "type": "user", "natural_key": "synthetic"}
        for projection in ["metadata", "technical", "security_metadata", "full"]:
            for denial in ["scoped", "evidence.exact", "all"]:
                with self.subTest(projection=projection, denial=denial), ExitStack() as stack:
                    reads = []

                    def read_rows(**kwargs):
                        if kwargs.get("id_only"):
                            return candidates
                        reads.append(kwargs)
                        self.assertEqual(kwargs["event_db_ids"], [101])
                        return [{"event_db_id": 101, "event_id": 4624, "link_role": "actor",
                                 "confidence": 0.0, "time_created_utc": "2026-10-21T00:00:00Z"}]

                    patches = {
                        "is_postgres_runtime_db": lambda: True,
                        "query_rows": lambda *args: [{"id": 7}],
                        "_get_current_entity_states": lambda **kwargs: [],
                        "_get_entity_evidence_event_rows": read_rows,
                        "_exact_event_db_id": lambda row: row.get("event_db_id"),
                        "_entity_item": lambda row: entity,
                        "_entity_detail_event_item": workspace._entity_detail_event_item,
                        "_EVENT_EVIDENCE_FIELD_PROJECTIONS": ("full", "technical", "security_metadata", "metadata"),
                        "ENTITY_DETAIL_EVENT_MAX": 200,
                        "ENTITY_CURRENT_STATE_LIMIT": 50,
                    }
                    for name, value in patches.items():
                        stack.enter_context(patch.object(workspace._src, name, value, create=True))
                    stack.enter_context(patch("server.sli.plugins.registry.plugin_hook", return_value=lambda *args, **kwargs: {
                        "entity_id": 7, "resolution": "not_found", "items": [], "returned_count": 0, "bounded": True,
                    }))
                    # Exercise the existing callback boundary without changing its
                    # authorization policy: scoped denial and exact-evidence denial
                    # must both exclude candidates before the selected-field read.
                    allowed = (lambda row: False) if denial == "all" else (
                        (lambda row: row["domain_id"] == 1) if denial == "scoped" else None
                    )
                    project = lambda row: projection if denial != "evidence.exact" or row["event_db_id"] == 101 else None
                    result = workspace.get_entity_workspace_detail_data(
                        entity_id=7, event_evidence_allowed=allowed, event_evidence_projection=project,
                    )
                    serialized = EntityWorkspaceDetailResponse.model_validate(result).model_dump(mode="json")
                    self.assertTrue(serialized["events_scope_filtered"])
                    if denial == "all":
                        self.assertEqual(serialized["events"], [])
                        self.assertEqual(serialized["events_state"], "forbidden")
                        self.assertEqual(reads, [])
                    else:
                        self.assertEqual(len(reads), 1)
                        self.assertEqual(reads[0]["field_projection"], projection)
                        self.assertEqual([event["event_db_id"] for event in serialized["events"]], [101])
                        self.assertEqual(serialized["events"][0]["event_id"], 4624 if projection in {"full", "security_metadata"} else None)
                        self.assertEqual(serialized["events"][0]["confidence"], 0.0 if projection in {"full", "technical"} else None)
