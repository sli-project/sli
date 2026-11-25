"""Provision one synthetic 406 source in the disposable Debian guest only."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

TARGET = "fa8baf797ca0f0bcd62574aebf551e3aef1e6638"
ROUTE = json.loads(r'''{"schema_version":1,"contract_id":"sli.radius-collection-routes.v1","source_name":"nps.example.test","connect_address":"nps.example.test","source_instance_id":"radius-instance","runtime_enabled":false,"autostart_enabled":false,"event_log_route":{"pack_id":"sli.windows.vpn-radius","channel":"Security","provider_name":"Microsoft-Windows-Security-Auditing","event_ids":[6272,6273],"transport":"windows_event_log_rpc","collection_entrypoint":"scripts/run_dc_log_pilot.py","primary_adapter":"windows-eventlog-pywin32","fallback_adapter":"windows-eventlog-powershell"},"accounting_route":{"transport":"dedicated_read_only_smb_share","share_unc":"\\\\nps.example.test\\Accounting","administrative_shares_forbidden":["c$","admin$","ipc$"],"default_windows_logfiles_path_forbidden":true,"timezone_descriptor":{"source":"static_accepted_evidence","timezone_id":"N. Central Asia Standard Time","utc_offset_minutes":420,"remote_registry_allowed":false,"drift_check_required_before_activation":false,"drift_check_accepted":false,"owner_assumption_active":true,"owner_assumption_recorded_on":"2026-08-02"}},"owner_confirmed_ip":"192.0.2.12"}''')
SOURCE = "radius-instance"
SUBSCRIPTION = "vpn-radius-session-observations-nps-v1"
TRANSPORT = "windows-rpc-smb-readonly-tail-v1"
ENDPOINT = "fqdn:nps.example.test|ipv4:192.0.2.12"
CREDENTIALS = Path("/etc/sli/radius-accounting")


def assert_fixture(required, reason):
    if not required:
        raise RuntimeError(reason)


def psql(sql):
    process = subprocess.run(
        ["runuser", "-u", "postgres", "--", "psql", "-XqAtw", "-h", "/var/run/postgresql", "-d", "sli",
         "-v", "ON_ERROR_STOP=1", "--single-transaction", "-f", "-"],
        text=True, input="\\set VERBOSITY sqlstate\n" + sql, capture_output=True, check=False,
    )
    if process.returncode:
        code = re.search(r"(?m)(?:^|: )ERROR:\s+([0-9A-Z]{5})(?:\s|$)", process.stderr)
        raise RuntimeError("postgres_sqlstate_" + code.group(1) if code else "postgres_fixture_command_failed")
    return process.stdout.strip()


def write_private(name, value):
    with (CREDENTIALS / name).open("x", encoding="utf-8") as stream:
        stream.write(value + "\n")


def prepare():
    os.umask(0o077)
    assert_fixture(os.geteuid() == 0 and os.uname().nodename == "sli-clean-beta", "disposable_guest_identity")
    directory = Path("/opt/sli/current")
    provenance = json.loads((directory / "native-runtime.json").read_text())["provenance"]
    assert_fixture(provenance["source_commit"] == TARGET, "unexpected_installed_source")
    assert_fixture(not CREDENTIALS.exists() and not CREDENTIALS.is_symlink(), "radius_credentials_already_present")
    assert_fixture(psql("""
        SELECT CASE WHEN
            to_regrole('sli_radius_accounting_login') IS NULL
            AND to_regprocedure('public.radius_accounting_source_ready406(text,text,text,text,boolean)') IS NOT NULL
            AND EXISTS (
                SELECT 1 FROM plugin_installations_v1
                WHERE plugin_id = 'sli.remote-access' AND package_lifecycle = 'registered'
                  AND desired_activation = 'disabled' AND component_runtime = 'stopped')
            AND NOT EXISTS (SELECT 1 FROM acquisition_source_instances WHERE source_kind = 'windows.nps.radius')
            AND NOT EXISTS (SELECT 1 FROM sli_agents)
            AND NOT EXISTS (SELECT 1 FROM sli_agent_receipts)
            AND NOT EXISTS (SELECT 1 FROM event_hot)
            AND NOT EXISTS (SELECT 1 FROM findings)
        THEN 'clean' ELSE 'unexpected' END;
    """) == "clean", "unexpected_database_predecessor")
    print("vpn_fixture_clean=yes", flush=True)

    password = secrets.token_hex(32)
    route = json.dumps(ROUTE, sort_keys=True, separators=(",", ":"))
    selector = json.dumps({"packet_type": 4, "lifecycle": ["start", "interim_update", "stop"]},
                          sort_keys=True, separators=(",", ":"))
    route_digest = hashlib.sha256(route.encode()).hexdigest()
    selector_digest = hashlib.sha256(selector.encode()).hexdigest()
    psql(f"""
        SET LOCAL log_statement = 'none';
        SET LOCAL log_min_error_statement = 'panic';
        SET LOCAL password_encryption = 'scram-sha-256';
        CREATE ROLE sli_radius_accounting_login LOGIN NOINHERIT PASSWORD '{password}';
        GRANT adlog_nps_agent_import_worker TO sli_radius_accounting_login WITH INHERIT FALSE, SET TRUE;
        GRANT CONNECT ON DATABASE sli TO sli_radius_accounting_login;
        INSERT INTO acquisition_source_instances (
            source_instance_id, organization_scope, source_kind, endpoint_identity, adapter_binding,
            display_name, desired_activation, configuration_sha256)
        VALUES ('{SOURCE}', 'example.test', 'windows.nps.radius', '{ENDPOINT}',
            'radius-accounting-database-compatible-v1', 'Synthetic local Accounting', 'manual_enabled', '{route_digest}');
        INSERT INTO acquisition_stream_cursors (
            source_instance_id, stream_id, transport_binding, cursor_epoch, file_generation, byte_offset, revision)
        VALUES ('{SOURCE}', 'radius-accounting', '{TRANSPORT}', gen_random_uuid(), 'fixture-generation', 0, 1);
        INSERT INTO acquisition_consumer_subscriptions (
            subscription_id, source_instance_id, stream_id, transport_binding, consumer_id,
            consumer_component_id, consumer_component_version, routing_contract_id, consumer_contract_version,
            replay_policy, resource_profile_id, selector_json, selector_sha256, authority_mode, desired_activation, partition_key)
        VALUES ('{SUBSCRIPTION}', '{SOURCE}', 'radius-accounting', '{TRANSPORT}',
            'sli.windows.vpn-radius', 'radius-session-observation', '1.0.0', 'sli.radius-accounting-runtime.v1', '1',
            'bounded_replay', 'stage9-radius-manual-bounded-v1', '{selector}', '{selector_digest}',
            'authoritative', 'manual_enabled', 'example.test:nps:radius-accounting');
    """)
    ready = psql(f"SELECT public.radius_accounting_source_ready406('{SOURCE}', '{SUBSCRIPTION}', '{TRANSPORT}', '{ENDPOINT}', false);")
    assert_fixture(ready == "t", "radius_registration_406_rejected")
    print("vpn_fixture_registration_406=passed", flush=True)

    CREDENTIALS.mkdir(mode=0o700)
    write_private("radius-agent-route", route)
    write_private("radius-agent-dsn", "Host=127.0.0.1;Port=5432;Database=sli;Username=sli_radius_accounting_login;SSL Mode=Disable")
    write_private("radius-agent-password", password)
    # Run the real packaged helper. Its output is filtered below and never includes inputs.
    command = ["/usr/bin/python3", "-I", "-B", "/usr/lib/sli/native_runtime.py", "prepare-radius-accounting"]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode:
        reason = re.search(r"(?m)^native_runtime_failed reason=([A-Za-z0-9_]{1,100})$", result.stderr)
        raise RuntimeError("native_prepare_" + reason.group(1) if reason else "native_prepare_failed")
    marker = json.loads((CREDENTIALS / "prepared.json").read_text())
    inputs = {name: hashlib.sha256((CREDENTIALS / name).read_bytes()).hexdigest()
              for name in ("radius-agent-route", "radius-agent-dsn", "radius-agent-password")}
    assert_fixture(marker == {"schema_version": 1, "inputs": inputs}, "native_prepare_receipt_mismatch")
    print("vpn_fixture_native_prepare=verified", flush=True)


if __name__ == "__main__":
    try:
        prepare()
    except Exception as error:
        message = str(error)
        if not re.fullmatch(r"[A-Za-z0-9_]{1,105}", message):
            message = type(error).__name__
        print("vpn_fixture_failure=" + message, flush=True)
        sys.exit(1)
