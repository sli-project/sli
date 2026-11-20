"""Generate a synthetic AD Context bundle that matches the demo event batches.

Offline and deterministic (plan 9.4, second chunk). The bundle uses the same
synthetic world as ``generate_demo_events.py`` -- domain ``example.test``, the
same user and admin accounts and SIDs, and the groups the demo events change
(Staff, Ops-Universal, Domain Admins) plus a VPN group -- so a demo database
loaded with both shows consistent accounts, memberships and events.  Computer
accounts (the two DCs, a file server and the workstations the demo events name)
are ``ad_computer`` entities of the ``directory_accounts`` section.

It writes ``ad-context-bundle.json`` and its ``.sha256`` sidecar; the
product's own ``server.ad_context.contracts.load_bundle`` accepts the result.
Importing it into a database is a separate, explicit step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.demo.generate_demo_events import (
    DEFAULT_END,
    DOMAIN_DN,
    DOMAIN_FQDN,
    DOMAIN_NETBIOS,
    SID_PREFIX,
    _iso,
    _sid,
    _utc,
    _World,
    resolve_out_dir,
)
from server.ad_context.contracts import (
    COMPUTER_REFERENCE_ATTRIBUTE_SOURCES,
    PACK_ID,
    SCHEMA_VERSION,
    canonical_sha256,
)

SOURCE_PACK_VERSION = "0.9.0"
BUNDLE_NAME = "ad-context-bundle.json"
_GUID_NAMESPACE = uuid.UUID("6f0a6b62-5d2e-4b2c-9a43-2d1f0c8e7a11")

GROUPS = (
    # (name, rid or SID, privileged, vpn)
    ("Domain Admins", f"{SID_PREFIX}-512", True, False),
    ("Staff", _sid(1500), False, False),
    ("Ops-Universal", _sid(1501), False, False),
    ("VPN Users", _sid(1502), False, True),
)


MAX_DEMO_WORKSTATIONS = 6
FILE_SERVER = "FS01"


def computer_accounts(users: int) -> list[dict[str, Any]]:
    """Computers consistent with the demo events: DCs, a file server, admin and user workstations."""
    world = _World(users)
    items: list[dict[str, Any]] = [
        {"name": "DC01", "sid": _sid(3001), "kind": "dc", "os": "Windows Server 2022 Standard",
         "version": "10.0 (20348)", "location": None},
        {"name": "DC02", "sid": _sid(3002), "kind": "dc", "os": "Windows Server 2022 Standard",
         "version": "10.0 (20348)", "location": None},
        {"name": FILE_SERVER, "sid": _sid(3010), "kind": "server",
         "os": "Windows Server 2019 Standard", "version": "10.0 (17763)", "location": None},
    ]
    hosts = [account["host"] for account in world.admins]
    hosts += [account["host"] for account in world.users[:MAX_DEMO_WORKSTATIONS]]
    for host in hosts:
        number = int(host[2:])
        items.append({"name": host, "sid": _sid(3000 + number if number >= 900 else 3100 + number),
                      "kind": "workstation", "os": "Windows 11 Enterprise",
                      "version": "10.0 (22631)", "location": None})
    return items


def _guid(sid: str) -> str:
    return str(uuid.uuid5(_GUID_NAMESPACE, sid))


def _entity(kind: str, sid: str, observed: str, attributes: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_type": "entity",
        "record_key": f"entity:{sid}",
        "section": "directory_accounts",
        "observed_at_utc": observed,
        "identity": {"kind": kind, "domain_sid": SID_PREFIX, "object_guid": _guid(sid), "object_sid": sid},
        "attributes": attributes,
    }


def _member_of(section: str, member_sid: str, group_sid: str, observed: str) -> dict[str, Any]:
    return {
        "record_type": "relation",
        "record_key": f"{section}:{member_sid}:{group_sid}",
        "section": section,
        "observed_at_utc": observed,
        "relation_kind": "member_of",
        "source_record_key": f"entity:{member_sid}",
        "target_record_key": f"entity:{group_sid}",
        "attributes": {"membership_type": "direct", "source_section": section},
    }


def build_bundle(*, users: int = 25, end: str = DEFAULT_END) -> dict[str, Any]:
    world = _World(users)
    observed_at = _utc(end)
    observed = _iso(observed_at)
    created = _iso(observed_at - timedelta(days=400))
    records: list[dict[str, Any]] = []

    def user(account: dict[str, str], *, admin: bool) -> dict[str, Any]:
        name = account["name"]
        return _entity("ad_user", account["sid"], observed, {
            "display_name": f"Demo {'Admin' if admin else 'User'} {name[-3:]}",
            "sam_account_name": name,
            "user_principal_name": f"{name}@{DOMAIN_FQDN}",
            "distinguished_name": f"CN={name},OU={'Admins' if admin else 'Staff'},{DOMAIN_DN}",
            "object_class": "user",
            "enabled": True,
            "department": "IT" if admin else "Operations",
            "when_created_utc": created,
            "admin_count": 1 if admin else 0,
        })

    for account in world.admins:
        records.append(user(account, admin=True))
    for account in world.users:
        records.append(user(account, admin=False))
    for name, sid, _privileged, _vpn in GROUPS:
        records.append(_entity("ad_group", sid, observed, {
            "display_name": name,
            "sam_account_name": name,
            "distinguished_name": f"CN={name},OU=Groups,{DOMAIN_DN}",
            "object_class": "group",
            "group_category": "Security",
            "group_scope": "Universal" if name == "Ops-Universal" else "Global",
        }))

    for item in computer_accounts(users):
        name = item["name"]
        controller = item["kind"] == "dc"
        ou = "Domain Controllers" if controller else ("Servers" if item["kind"] == "server" else "Workstations")
        attributes: dict[str, Any] = {
            "display_name": name,
            "sam_account_name": f"{name}$",
            "distinguished_name": f"CN={name},OU={ou},{DOMAIN_DN}",
            "canonical_name": f"{DOMAIN_FQDN}/{ou}/{name}",
            "object_class": "computer",
            "enabled": True,
            "dns_host_name": f"{name.lower()}.{DOMAIN_FQDN}",
            "operating_system": item["os"],
            "operating_system_version": item["version"],
            "description": f"Demo {item['kind']} account",
            "last_logon_utc": _iso(observed_at - timedelta(hours=3)),
            "password_last_set_utc": _iso(observed_at - timedelta(days=12)),
            "created_utc": created,
            "when_changed_utc": _iso(observed_at - timedelta(days=12)),
            "service_principal_names": [f"HOST/{name.lower()}.{DOMAIN_FQDN}", f"HOST/{name}"],
            "trusted_for_delegation": controller,
            "trusted_to_auth_for_delegation": False,
            "user_account_control": 532480 if controller else 4096,
        }
        attributes["computer_reference_attribute_states"] = {
            key: {"state": "present" if key in attributes else "absent_in_source", "source_attribute": source}
            for key, source in COMPUTER_REFERENCE_ATTRIBUTE_SOURCES.items()
        }
        records.append(_entity("ad_computer", item["sid"], observed, attributes))

    privileged = [sid for _name, sid, is_privileged, _vpn in GROUPS if is_privileged]
    vpn = [sid for _name, sid, _privileged, is_vpn in GROUPS if is_vpn]
    for account in world.admins:
        records.append(_member_of("privileged_membership", account["sid"], privileged[0], observed))
    for index, account in enumerate(world.users):
        if index % 2 == 0:
            records.append(_member_of("vpn_membership", account["sid"], vpn[0], observed))

    counts: dict[str, int] = {}
    for record in records:
        counts[record["section"]] = counts.get(record["section"], 0) + 1
    sections = [
        {"name": name, "status": "complete", "record_count": counts.get(name, 0), "duration_ms": 0}
        for name in ("directory_accounts", "privileged_membership", "vpn_membership")
    ]
    bundle: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source_pack_id": PACK_ID,
        "source_pack_version": SOURCE_PACK_VERSION,
        "run_id": str(uuid.uuid5(_GUID_NAMESPACE, f"run:{users}:{observed}")),
        "mode": "full",
        "domain": {"sid": SID_PREFIX, "dns_name": DOMAIN_FQDN},
        "scope": {"search_base": DOMAIN_DN, "privileged_group_sids": privileged, "vpn_group_sids": vpn},
        "observed_at_utc": observed,
        "sections": sections,
        "records": sorted(records, key=lambda item: item["record_key"]),
    }
    return bundle


def write_bundle(out: str | Path, *, users: int = 25, end: str = DEFAULT_END) -> Path:
    out_dir = resolve_out_dir(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    from server.ad_context.contracts import validate_bundle

    bundle = build_bundle(users=users, end=end)
    bundle["bundle_sha256"] = validate_bundle(json.loads(json.dumps(bundle)))["bundle_sha256"]
    path = out_dir / BUNDLE_NAME
    raw = (json.dumps(bundle, ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode("utf-8")
    path.write_bytes(raw)
    path.with_name(path.name + ".sha256").write_text(f"{hashlib.sha256(raw).hexdigest()}  {BUNDLE_NAME}\n", encoding="ascii")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic AD Context bundle for the demo (offline).")
    parser.add_argument("--out", required=True, help="output directory (must not be inside data/)")
    parser.add_argument("--users", type=int, default=25)
    parser.add_argument("--end", default=DEFAULT_END, help="observation time, ISO UTC (default: fixed)")
    args = parser.parse_args(argv)
    try:
        path = write_bundle(args.out, users=args.users, end=args.end)
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"bundle": str(path), "domain": DOMAIN_FQDN, "netbios": DOMAIN_NETBIOS,
                      "canonical_sha256": canonical_sha256(json.loads(path.read_text(encoding="utf-8")))}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
