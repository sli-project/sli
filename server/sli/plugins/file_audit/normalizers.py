"""Source-native file facts; successful access checks never imply data reads."""
from functools import lru_cache
import json
from types import SimpleNamespace

from server.source_packs.contracts import EventEntitySemantics
from server.source_packs.normalizer_types import SourceNormalizer
from sli_agent.file_audit_policy import EVENT_IDS, OPTIONAL_EVENT_IDS, PROVIDER
from sli_agent.file_audit_events import number, outcome


def _matches(row):
    return (str(row.get("channel") or "").casefold() == "security"
            and str(row.get("provider_name") or "").casefold() == PROVIDER.casefold()
            and str(row.get("event_id")) in {str(item) for item in (*EVENT_IDS, *OPTIONAL_EVENT_IDS)})


def native_facts(*, row, event_data):
    if not _matches(row):
        return {}
    fields = {"subject_user_sid": ("SubjectUserSid", 184), "logon_id": ("SubjectLogonId", 128),
              "object_name": ("ObjectName", 4096), "ip_address": ("IpAddress", 128),
              "process_name": ("ProcessName", 512), "share_name": ("ShareName", 256),
              "share_local_path": ("ShareLocalPath", 4096), "relative_target_name": ("RelativeTargetName", 4096),
              "object_type": ("ObjectType", 128), "access_list": ("AccessList", 4096),
              "access_reason": ("AccessReason", 8192), "old_sd": ("OldSd", 65536), "new_sd": ("NewSd", 65536)}
    # Do not truncate identity/path fields or copy arbitrary payload keys.
    facts = {key: value for key, (name, limit) in fields.items()
             if isinstance(value := event_data.get(name), str) and 0 < len(value) <= limit and value != "-"}
    for key, name in (("access_mask", "AccessMask"), ("server_process_id", "ProcessId"),
                      ("handle_id", "HandleId"), ("logon_id_numeric", "SubjectLogonId")):
        value = number(event_data.get(name), 0xffffffff if key == "access_mask" else 0xffffffffffffffff)
        if value is not None:
            facts[key] = value
    facts["outcome"] = outcome(row)
    return facts


def event_facts(*, row, event_data):
    native = native_facts(row=row, event_data=event_data)
    if not native:
        return {}
    from server.sli.storage.storage_v2_repository_columns import EVENT_FACTS_V2_WRITE_COLUMNS
    # The core persists a fixed facts row. Plugin-only fields travel together
    # in a versioned bounded column, including into permanent CH fact history.
    facts = dict.fromkeys(EVENT_FACTS_V2_WRITE_COLUMNS - {"event_id", "source_facts_sha256"})
    for key in ("object_name", "share_name", "process_name"):
        facts[key] = native.get(key)
    facts["process_id"] = str(native["server_process_id"]) if "server_process_id" in native else None
    facts["file_audit_facts_json"] = json.dumps({"contract_id": "file-audit.facts.v1", **native},
                                               sort_keys=True, separators=(",", ":"))
    return facts


normalizer_namespace = SimpleNamespace(
    event_facts=event_facts,
    entity_semantics=lambda **_kwargs: EventEntitySemantics(),
    event_label=lambda _event_id, _lang: None,
)


@lru_cache(maxsize=1)
def normalizer():
    # The reviewed registry supplies the implementation; manifests contain no
    # executable names and cannot replace this bundled normalizer identity.
    return SourceNormalizer(
        normalizer_id="windows-file-audit-v1",
        event_facts=event_facts,
        entity_semantics=normalizer_namespace.entity_semantics,
        event_label=normalizer_namespace.event_label,
        correlation_id=lambda **_kwargs: None,
        state_semantics=lambda **_kwargs: None,
        contextual_classification=lambda _row: {},
        account_event=lambda _event_id: None,
        event_ids_for_search_family=lambda _family: (),
        event_ids_for_analysis_family=lambda _family: (),
        important_account_event_ids=lambda: (),
        finding_rules=dict,
        investigation_event_ids=lambda _family: (),
        investigation_category=lambda _event_id: "other",
        investigation_check=lambda _category: None,
        security_monitor_groups=lambda: (),
        monitor_privileged_event_ids=lambda: (),
        semantic_projection=lambda **_kwargs: {},
        semantic_event_identities=lambda _types: (),
        semantic_core_role_filters=lambda _type, _roles, _triggers: None,
    )
