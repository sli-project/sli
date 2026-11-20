"""Disabled-only registration contract for the Stage 9 RADIUS pilot.

The module does not connect to PostgreSQL or RADIUS by itself.  A caller may
provide a PostgreSQL connection and a cursor position obtained by a separately
authorized bounded bootstrap.  Registration remains disabled and cannot start
or schedule a worker.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping
from uuid import UUID

from server.source_packs.radius.collection_routes import (
    load_radius_collection_routes,
)


ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "config" / "stage9_radius_registration_v1.json"
CONTRACT_ID = "sli.radius-accounting-registration.v1"
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FQDN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


class RadiusRegistrationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RadiusCursorBootstrap:
    cursor_epoch: UUID
    file_generation: str
    byte_offset: int
    last_record_sha256: str | None = None


@dataclass(frozen=True)
class RadiusRegistrationReceipt:
    source_instance_id: str
    stream_id: str
    transport_binding: str
    subscription_id: str
    desired_activation: str
    cursor_revision: int
    created_source: bool
    created_cursor: bool
    created_subscription: bool


def load_registration_contract(
    path: Path | None = None,
) -> dict[str, Any]:
    use_template = path is None and not os.environ.get("ADLOG_RADIUS_REGISTRATION_CONTRACT_PATH")
    path = path or Path(os.environ.get("ADLOG_RADIUS_REGISTRATION_CONTRACT_PATH") or CONTRACT_PATH)
    try:
        contract = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusRegistrationError("registration_contract_invalid") from exc
    if use_template:
        routes = load_radius_collection_routes()
        host = str(routes["source_name"])
        organization = host.partition(".")[2]
        label = host.partition(".")[0]
        contract["source"].update(
            source_instance_id=routes["source_instance_id"],
            organization_scope=organization,
            endpoint_identity=f"fqdn:{host}|ipv4:{routes['owner_confirmed_ip']}",
            display_name=f"VPN/RADIUS — {host}",
        )
        contract["subscription"].update(
            subscription_id=f"vpn-radius-session-observations-{label}-v1",
            partition_key=f"{organization}:{label}:radius-accounting",
        )
    return validate_registration_contract(contract)


def validate_registration_contract(
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    value = dict(contract)
    if value.get("schema_version") != 1:
        raise RadiusRegistrationError("registration_schema_unsupported")
    if value.get("contract_id") != CONTRACT_ID:
        raise RadiusRegistrationError("registration_contract_id_unexpected")
    if value.get("status") != "prepared_disabled_only":
        raise RadiusRegistrationError("registration_disabled_status_required")
    if value.get("required_migration") != 58:
        raise RadiusRegistrationError("registration_migration_invalid")
    if value.get("desired_activation") != "disabled":
        raise RadiusRegistrationError("registration_must_be_disabled")
    if value.get("observed_health") != "unknown":
        raise RadiusRegistrationError("registration_health_must_be_unknown")
    source = _validate_source_identity(value.get("source"))
    if source is None:
        raise RadiusRegistrationError("registration_source_identity_mismatch")
    stream = dict(value.get("stream") or {})
    if stream != {
        "stream_id": "radius-accounting",
        "transport_binding": "windows-rpc-smb-readonly-tail-v1",
        "initial_cursor_policy": "requires_bounded_live_bootstrap",
        "rotation_policy": (
            "previous_generation_eof_then_new_generation_offset_zero"
        ),
    }:
        raise RadiusRegistrationError("registration_stream_contract_mismatch")
    subscription = dict(value.get("subscription") or {})
    required_subscription = {
        "subscription_id",
        "consumer_id",
        "consumer_component_id",
        "consumer_component_version",
        "routing_contract_id",
        "consumer_contract_version",
        "replay_policy",
        "resource_profile_id",
        "selector",
        "authority_mode",
        "partition_key",
    }
    if set(subscription) != required_subscription:
        raise RadiusRegistrationError(
            "registration_subscription_contract_mismatch"
        )
    if subscription["routing_contract_id"] != (
        "sli.radius-accounting-runtime.v1"
    ):
        raise RadiusRegistrationError("registration_routing_contract_mismatch")
    if subscription["authority_mode"] != "authoritative":
        raise RadiusRegistrationError("registration_authority_mode_invalid")
    if subscription["replay_policy"] != "bounded_replay":
        raise RadiusRegistrationError("registration_replay_policy_invalid")
    source_host = str(source["endpoint_identity"]).split("|", 1)[0].removeprefix("fqdn:")
    source_label = source_host.partition(".")[0]
    expected_subscription_id = (
        f"vpn-radius-session-observations-{source_label}-v1"
    )
    if subscription["subscription_id"] != expected_subscription_id:
        raise RadiusRegistrationError("registration_subscription_scope_invalid")
    if subscription["partition_key"] != (
        f"{source['organization_scope']}:{source_label}:radius-accounting"
    ):
        raise RadiusRegistrationError("registration_partition_scope_invalid")
    if value.get("evidence_root_policy") != (
        "explicit_absolute_protected_acl_readback_required"
    ):
        raise RadiusRegistrationError("registration_evidence_policy_invalid")
    prohibited = set(value.get("prohibited_actions") or [])
    if prohibited != {
        "production_apply",
        "source_contact",
        "cursor_bootstrap",
        "worker_activation",
        "autostart",
    }:
        raise RadiusRegistrationError("registration_prohibition_mismatch")
    return value


def _validate_source_identity(value: Any) -> dict[str, Any] | None:
    source = dict(value or {})
    if set(source) != {
        "source_instance_id",
        "organization_scope",
        "source_kind",
        "endpoint_identity",
        "adapter_binding",
        "credential_handle",
        "display_name",
    }:
        return None
    source_instance_id = str(source["source_instance_id"] or "")
    routes = load_radius_collection_routes()
    host = str(routes["source_name"])
    if (
        not source_instance_id
        or not host
        or _FQDN.fullmatch(host) is None
        or source_instance_id != routes["source_instance_id"]
    ):
        return None
    organization_scope = host.partition(".")[2]
    try:
        endpoint_prefix, endpoint_ip = str(
            source["endpoint_identity"]
        ).split("|ipv4:", 1)
        ipaddress.IPv4Address(endpoint_ip)
    except ValueError:
        return None
    if not (
        endpoint_prefix == f"fqdn:{host}"
        and host == routes["source_name"]
        and endpoint_ip == routes["owner_confirmed_ip"]
        and source["organization_scope"] == organization_scope
        and source["source_kind"] == "windows.nps.radius"
        and source["adapter_binding"]
        == "radius-accounting-database-compatible-v1"
        and source["credential_handle"] is None
        and source["display_name"] == f"VPN/RADIUS — {host}"
    ):
        return None
    return source


def register_disabled_radius_source(
    conn: Any,
    *,
    bootstrap: RadiusCursorBootstrap,
    contract: Mapping[str, Any] | None = None,
) -> RadiusRegistrationReceipt:
    value = validate_registration_contract(
        contract or load_registration_contract()
    )
    generation = _token(bootstrap.file_generation, "file_generation")
    offset = int(bootstrap.byte_offset)
    if offset < 0:
        raise RadiusRegistrationError("bootstrap_byte_offset_invalid")
    last_hash = (
        str(bootstrap.last_record_sha256).casefold()
        if bootstrap.last_record_sha256 is not None
        else None
    )
    if last_hash is not None and _SHA256.fullmatch(last_hash) is None:
        raise RadiusRegistrationError("bootstrap_last_hash_invalid")
    if not isinstance(bootstrap.cursor_epoch, UUID):
        raise RadiusRegistrationError("bootstrap_cursor_epoch_invalid")

    source = dict(value["source"])
    stream = dict(value["stream"])
    subscription = dict(value["subscription"])
    selector_json = json.dumps(
        subscription["selector"],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    selector_sha = sha256(selector_json.encode("utf-8")).hexdigest()
    configuration_sha = _configuration_sha(value)

    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute("set local lock_timeout='5s'")
            cur.execute("set local statement_timeout='15s'")
            cur.execute("set local role adlog_storage_owner")
            cur.execute(
                """
                select exists(
                  select 1 from schema_migrations
                  where version=58
                    and name='radius_accounting_transaction_foundation'
                )
                """
            )
            if not bool(cur.fetchone()[0]):
                raise RadiusRegistrationError(
                    "registration_migration_58_required"
                )
            created_source = _insert_source(
                cur,
                source=source,
                configuration_sha=configuration_sha,
            )
            created_cursor = _insert_cursor(
                cur,
                source_instance_id=source["source_instance_id"],
                stream=stream,
                bootstrap=bootstrap,
                generation=generation,
                offset=offset,
                last_hash=last_hash,
            )
            created_subscription = _insert_subscription(
                cur,
                source_instance_id=source["source_instance_id"],
                stream=stream,
                subscription=subscription,
                selector_json=selector_json,
                selector_sha=selector_sha,
            )
    return RadiusRegistrationReceipt(
        source_instance_id=source["source_instance_id"],
        stream_id=stream["stream_id"],
        transport_binding=stream["transport_binding"],
        subscription_id=subscription["subscription_id"],
        desired_activation="disabled",
        cursor_revision=0,
        created_source=created_source,
        created_cursor=created_cursor,
        created_subscription=created_subscription,
    )


def _insert_source(
    cur: Any,
    *,
    source: Mapping[str, Any],
    configuration_sha: str,
) -> bool:
    cur.execute(
        """
        insert into acquisition_source_instances(
          source_instance_id,organization_scope,source_kind,
          endpoint_identity,adapter_binding,credential_handle,
          display_name,desired_activation,observed_health,
          configuration_sha256
        ) values(%s,%s,%s,%s,%s,%s,%s,'disabled','unknown',%s)
        on conflict(source_instance_id) do nothing
        returning source_instance_id
        """,
        (
            source["source_instance_id"],
            source["organization_scope"],
            source["source_kind"],
            source["endpoint_identity"],
            source["adapter_binding"],
            source["credential_handle"],
            source["display_name"],
            configuration_sha,
        ),
    )
    created = cur.fetchone() is not None
    cur.execute(
        """
        select organization_scope,source_kind,endpoint_identity,
               adapter_binding,credential_handle,display_name,
               desired_activation,observed_health,configuration_sha256
        from acquisition_source_instances
        where source_instance_id=%s
        """,
        (source["source_instance_id"],),
    )
    actual = cur.fetchone()
    expected = (
        source["organization_scope"],
        source["source_kind"],
        source["endpoint_identity"],
        source["adapter_binding"],
        source["credential_handle"],
        source["display_name"],
        "disabled",
        "unknown",
        configuration_sha,
    )
    if actual != expected:
        raise RadiusRegistrationError("registration_source_conflict")
    return created


def _insert_cursor(
    cur: Any,
    *,
    source_instance_id: str,
    stream: Mapping[str, Any],
    bootstrap: RadiusCursorBootstrap,
    generation: str,
    offset: int,
    last_hash: str | None,
) -> bool:
    cur.execute(
        """
        insert into acquisition_stream_cursors(
          source_instance_id,stream_id,transport_binding,cursor_epoch,
          file_generation,byte_offset,last_record_sha256,revision
        ) values(%s,%s,%s,%s,%s,%s,%s,0)
        on conflict(source_instance_id,stream_id,transport_binding) do nothing
        returning source_instance_id
        """,
        (
            source_instance_id,
            stream["stream_id"],
            stream["transport_binding"],
            bootstrap.cursor_epoch,
            generation,
            offset,
            last_hash,
        ),
    )
    created = cur.fetchone() is not None
    cur.execute(
        """
        select cursor_epoch,file_generation,byte_offset,last_record_sha256,
               revision
        from acquisition_stream_cursors
        where source_instance_id=%s and stream_id=%s
          and transport_binding=%s
        """,
        (
            source_instance_id,
            stream["stream_id"],
            stream["transport_binding"],
        ),
    )
    actual = cur.fetchone()
    expected = (
        bootstrap.cursor_epoch,
        generation,
        offset,
        last_hash,
        0,
    )
    if actual != expected:
        raise RadiusRegistrationError("registration_cursor_conflict")
    return created


def _insert_subscription(
    cur: Any,
    *,
    source_instance_id: str,
    stream: Mapping[str, Any],
    subscription: Mapping[str, Any],
    selector_json: str,
    selector_sha: str,
) -> bool:
    cur.execute(
        """
        insert into acquisition_consumer_subscriptions(
          subscription_id,source_instance_id,stream_id,transport_binding,
          consumer_id,consumer_component_id,consumer_component_version,
          routing_contract_id,consumer_contract_version,replay_policy,
          resource_profile_id,selector_json,selector_sha256,
          authority_mode,desired_activation,partition_key
        ) values(
          %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,'disabled',%s
        )
        on conflict(subscription_id) do nothing
        returning subscription_id
        """,
        (
            subscription["subscription_id"],
            source_instance_id,
            stream["stream_id"],
            stream["transport_binding"],
            subscription["consumer_id"],
            subscription["consumer_component_id"],
            subscription["consumer_component_version"],
            subscription["routing_contract_id"],
            subscription["consumer_contract_version"],
            subscription["replay_policy"],
            subscription["resource_profile_id"],
            selector_json,
            selector_sha,
            subscription["authority_mode"],
            subscription["partition_key"],
        ),
    )
    created = cur.fetchone() is not None
    cur.execute(
        """
        select source_instance_id,stream_id,transport_binding,consumer_id,
               consumer_component_id,consumer_component_version,
               routing_contract_id,consumer_contract_version,replay_policy,
               resource_profile_id,selector_json,selector_sha256,
               authority_mode,desired_activation,partition_key
        from acquisition_consumer_subscriptions
        where subscription_id=%s
        """,
        (subscription["subscription_id"],),
    )
    actual = cur.fetchone()
    expected = (
        source_instance_id,
        stream["stream_id"],
        stream["transport_binding"],
        subscription["consumer_id"],
        subscription["consumer_component_id"],
        subscription["consumer_component_version"],
        subscription["routing_contract_id"],
        subscription["consumer_contract_version"],
        subscription["replay_policy"],
        subscription["resource_profile_id"],
        subscription["selector"],
        selector_sha,
        subscription["authority_mode"],
        "disabled",
        subscription["partition_key"],
    )
    if actual != expected:
        raise RadiusRegistrationError("registration_subscription_conflict")
    return created


def _configuration_sha(contract: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        contract,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def _token(value: str, name: str) -> str:
    text = str(value or "").strip()
    if _TOKEN.fullmatch(text) is None:
        raise RadiusRegistrationError(f"{name}_invalid")
    return text
