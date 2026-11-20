"""Synthetic GPO capture, privacy and source limits; no directory or DB."""
from __future__ import annotations

import base64
import io
import json
import re
import shutil
import subprocess
import threading
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from sli_agent.envelope import canonical
from sli_agent.gpo_snapshot import GPOSnapshotModule, PowerShellGPOReader, confined_gpt_path, normalize_capture
from sli_agent.modules import configured_modules
from sli_agent.snapshot_stream import SnapshotStream, policy
from test_agent_snapshot_stream import NOW, SOURCE

SID = "S-1-5-21-1-2-3"
DNS = "directory.invalid"
DN = "DC=directory,DC=invalid"
GUID = str(UUID(int=123))


def config(**changes):
    return policy("sli.gpo-snapshot", {"source_instance_id": SOURCE, "domain_sid": SID,
        "domain_dns": DNS, "scope": "fixture-scope", "dc": ["dc.directory.invalid"], **changes})


def capture():
    stamp = NOW.isoformat().replace("+00:00", "Z")
    state = {"status": "observed", "source": "synthetic", "observed_at": stamp}
    gpo_id = "gpo-" + GUID
    snapshot = {
        "schema_version": "sli.ad-gpo.snapshot/1.0", "collector_version": "sli-agent/gpo-snapshot/1",
        "demo": False, "collection_status": "complete",
        **dict.fromkeys(("started_at", "completed_at", "observed_at"), stamp),
        "domain": {"sid": SID, "dns_name": DNS, "distinguished_name": DN, "query_dc": "dc.directory.invalid"},
        "scope": {"domain": DNS, "include_sites": True, "settings_mode": "Full", "permissions": True, "sysvol": True},
        "source_states": {name: deepcopy(state) for name in ("gpo_list", "gpo_reports", "gpc_directory",
            "sysvol_gpt", "links", "permissions", "wmi_filters")},
        "gpos": [{"id": gpo_id, "guid": GUID, "display_name": "Synthetic policy", "source_states": {"acl": state},
            "gpc": {"gpc_file_sys_path": rf"\\{DNS}\SYSVOL\{DNS}\Policies\{{{GUID}}}", "version_number": 65538},
            "gpt": {"ini_version": 65538, "status": "observed"},
            "computer": {"enabled": True, "directory_version": 2, "sysvol_version": 2},
            "user": {"enabled": True, "directory_version": 1, "sysvol_version": 1},
            "owner": {"sid": SID + "-512"}, "setting_ids": ["setting-test"], "permission_ids": ["perm-test"],
            "link_ids": ["link-test"]}],
        "scopes": [{"id": "scope-test", "scope_type": "ou", "distinguished_name": "OU=Synthetic," + DN,
            "gpo_inheritance_blocked": True}],
        "links": [{"id": "link-test", "gpo_id": gpo_id, "scope_id": "scope-test", "order": 1,
            "enabled": True, "enforced": True, "raw_options": 2}],
        "settings": [{"id": "setting-test", "gpo_id": gpo_id, "side": "computer", "path": "Registry/Properties",
            "setting_name": "Registry", "value_display": "action=U; key=Software\\Synthetic; value=1"}],
        "permissions": [{"id": "perm-test", "gpo_id": gpo_id, "trustee_sid": SID + "-512", "permission": "GpoApply",
            "denied": False, "inherited": False}],
        "acl": [{"id": "ace-test", "gpo_id": gpo_id, "ace_index": 0, "trustee_sid": SID + "-512",
            "access_mask": 256, "access_control_type": "Allow", "object_type": "edacfd8f-ffb3-11d1-b41d-00a0c968f939",
            "inherited": False, "propagation_flags": 0}],
        **{name: [] for name in ("wmi_filters", "unresolved_links", "collection_errors")},
    }
    record = {"record_type": "entity", "record_key": f"ad:{SID.lower()}:{GUID}", "section": "gpo_governance",
        "observed_at_utc": stamp, "identity": {"kind": "gpo", "domain_sid": SID, "object_guid": GUID, "object_sid": None},
        "attributes": {"display_name": "Synthetic policy", "gpo_security_filtering_effective_evaluated": False,
            "gpo_security_filtering_collected": True, "gpo_security_filtering_sids": [SID + "-512"],
            "gpo_settings": [{"scope": "computer", "kind": "Registry", "path": "Registry/Properties",
                "properties": {"key": "Software\\Synthetic", "value": "1"}, "redacted_fields": [],
                "truncated_fields": [], "sensitive_value_present": False, "sha256": "a" * 64}]}}
    return {"domain": {"sid": SID, "dns_name": DNS, "default_nc": DN}, "snapshot": snapshot, "records": [record]}


def test_fake_powershell_capture_keeps_existing_gpo_contract_and_acl():
    cfg, raw = config(), capture()
    module = GPOSnapshotModule(cfg, reader=lambda *args, **kw: json.dumps(raw))
    families = module.capture(cfg, deadline=time.monotonic() + 30, stop=threading.Event())
    snapshot, count = families["gpo_v2"]
    assert count == 1 and snapshot["acl"] == raw["snapshot"]["acl"]
    assert snapshot["links"][0]["enforced"] and snapshot["scopes"][0]["gpo_inheritance_blocked"]
    assert snapshot["gpos"][0]["owner"]["sid"] == SID + "-512"
    assert families["ad_gpo_governance"][0]["records"][0]["attributes"]["gpo_security_filtering_effective_evaluated"] is False
    assert "gpo_v2_snapshot" not in families["ad_gpo_governance"][0]


@pytest.mark.parametrize("representation", ["field", "named", "inline", "raw", "script", "key"])
def test_privacy_before_capture_file_and_spool(tmp_path, representation):
    cfg, raw = config(), capture()
    marker = "synthetic-redaction-marker"
    setting = raw["snapshot"]["settings"][0]
    props = raw["records"][0]["attributes"]["gpo_settings"][0]["properties"]
    if representation == "field":
        setting.update(setting_name="cpassword", value_display=marker)
        props["cpassword"] = marker
    elif representation == "named":
        setting.update(setting_name="apiKey", value_display=marker)
        props.update(name="apiKey", value=marker)
    elif representation == "inline":
        setting["value_display"] = "password=" + marker
        props["data"] = "password=" + marker
    elif representation == "raw":
        raw["snapshot"]["raw_xml"] = "<GPO>" + marker + "</GPO>"
        props["raw_sysvol"] = marker
    elif representation == "script":
        setting.update(path="Scripts/Script/Command", value_display=marker)
        props["script_content"] = marker
    else:
        label = "PRIVATE KEY"
        setting["value_display"] = "-----" + "BEGIN " + label + "-----\n" + marker
    original = deepcopy(raw)
    families = normalize_capture(raw, cfg)
    assert raw == original
    assert marker not in canonical(families).decode()
    assert families["gpo_v2"][0]["privacy"]["masked"] is True
    stream = SnapshotStream(tmp_path, "sli.gpo-snapshot")
    stream.freeze(stream.begin(cfg, now=NOW), families)
    state = stream.read()
    for info in state["families"].values():
        decoded = base64.b64decode(info["data_b64"])
        assert marker.encode() not in decoded
        assert b"raw_xml" not in decoded and b"raw_sysvol" not in decoded
    governance = json.loads(base64.b64decode(state["families"]["ad_gpo_governance"]["data_b64"]))
    assert governance["records"][0]["attributes"]["gpo_settings"][0]["properties"]["key"] == "Software\\Synthetic"
    from server.sli.plugins.gpo.snapshot_import import prepare_gpo_cycle
    prepare_gpo_cycle({"domain_sid": SID, "policy": cfg}, {name: data for name, (data, _) in families.items()})


@pytest.mark.parametrize("limit", ["objects", "bytes", "source"])
def test_overflow_is_bounded_explicit_partial_without_deleted_objects(tmp_path, limit):
    cfg, raw = config(max_objects=1, max_bytes=4096), capture()
    if limit == "objects":
        raw["snapshot"]["gpos"] *= 2
    elif limit == "bytes":
        raw["snapshot"]["settings"][0]["value_display"] = "x" * 5000
    else:
        raw["overflow"] = True
    families = normalize_capture(raw, cfg)
    assert families["gpo_v2"][0]["collection_status"] == "partial"
    assert families["gpo_v2"][0]["gpos"] == []
    assert families["ad_gpo_governance"][0]["mode"] == "targeted"
    assert families["ad_gpo_governance"][0]["sections"][0]["status"] == "partial"
    assert all(count == 0 for _, count in families.values())
    stream = SnapshotStream(tmp_path, "sli.gpo-snapshot")
    stream.freeze(stream.begin(cfg, now=NOW), families)


def test_two_families_count_the_same_gpo_population_once(tmp_path):
    cfg = config(max_objects=1)
    families = normalize_capture(capture(), cfg)
    stream = SnapshotStream(tmp_path, "sli.gpo-snapshot")
    stream.freeze(stream.begin(cfg, now=NOW), families)
    assert all(info["total_objects"] == 1 for info in stream.read()["families"].values())


@pytest.mark.parametrize("change", ["sid", "dns", "dc", "base"])
def test_capture_requires_bound_domain_dc_and_scope(change):
    cfg, raw = config(), capture()
    if change == "sid":
        raw["domain"]["sid"] = "S-1-5-21-9-9-9"
    elif change == "dns":
        raw["snapshot"]["domain"]["dns_name"] = "other.invalid"
    elif change == "dc":
        raw["snapshot"]["domain"]["query_dc"] = "other.directory.invalid"
    else:
        cfg["search_bases"] = ["OU=Synthetic," + DN]
    with pytest.raises(ValueError, match="agent_gpo_.*mismatch"):
        normalize_capture(raw, cfg)


@pytest.mark.parametrize("tail", ["..\\Policies", "{00000000-0000-0000-0000-000000000000}\\..", "Policies2", "Policies\\x:stream", "Policies/../x"])
def test_sysvol_rejects_escape_paths(tail):
    with pytest.raises(ValueError, match="agent_gpo_sysvol_path_invalid"):
        confined_gpt_path(rf"\\{DNS}\SYSVOL\{DNS}\{tail}", config())


def test_sysvol_rewrites_only_exact_domain_policy_root_to_chosen_dc():
    path = rf"\\{DNS}\SYSVOL\{DNS}\Policies\{{{GUID}}}"
    assert confined_gpt_path(path, config()) == rf"\\dc.directory.invalid\SYSVOL\{DNS}\Policies\{{{GUID}}}\GPT.INI"
    with pytest.raises(ValueError):
        confined_gpt_path(path.replace("SYSVOL", "OTHER"), config())
    with pytest.raises(ValueError):
        confined_gpt_path(path.replace(DNS, "other.invalid"), config())


def test_dependency_failure_and_cancellation_are_fixed_codes_only():
    def missing(*args, **kw):
        return {"error_code": "agent_gpo_group_policy_unavailable"}
    module = GPOSnapshotModule(config(), reader=missing)
    with pytest.raises(ValueError, match="^agent_gpo_group_policy_unavailable$"):
        module.capture(module.policy, deadline=time.monotonic() + 30, stop=threading.Event())
    stop = threading.Event()
    stop.set()
    with pytest.raises(ValueError, match="^agent_gpo_capture_cancelled$"):
        module.capture(module.policy, deadline=time.monotonic() + 30, stop=stop)


def test_gpo_module_disabled_and_dependencies_shipped():
    modules = configured_modules(SimpleNamespace(collection_enabled=False), SOURCE)
    assert not any(module.module_id == "sli.gpo-snapshot" for module in modules)
    modules = configured_modules(SimpleNamespace(collection_enabled=False), SOURCE,
        [{"module_id": "sli.gpo-snapshot", "enabled": False, "config": config()}])
    assert not any(module.module_id == "sli.gpo-snapshot" for module in modules)
    root = Path(__file__).resolve().parents[2]
    source = (root / "sli_agent/gpo_snapshot.ps1").read_text("utf-8-sig")
    assert "GroupPolicy" in source and "agent_gpo_group_policy_unavailable" in source
    assert "AuthenticationTypes]::Signing" in source and "AuthenticationTypes]::Sealing" in source
    assert "PageSize = 500" in source and "ReferralChasingOption]::None" in source
    assert "ConvertFrom-SLIGpoReportXml" in source
    assert "ConvertTo-SLIGpoV2Settings" in source
    assert "Within-Budget $setting" in source and "Within-Budget $linkRow" in source
    assert "WriteAllText" not in source
    # Split-Path and Join-Path resolve input paths; only report output is forbidden.
    report_calls = re.findall(r"\bGet-GPOReport\b[^\r\n`]*(?:`[ \t]*\r?\n[^\r\n`]*)*", source)
    assert report_calls
    assert not any(re.search(r"(?i)(?:^|\s)-Path\b", call) for call in report_calls)
    assert "Get-ADObject" not in source and "Import-Module ActiveDirectory" not in source
    from sli_agent.updates import REQUIRED_FILES, validate_payload
    assert {"sli_agent/gpo_snapshot.ps1", "sli_agent/gpo_privacy.py", "scripts/ad_context/GpoReportContract.psm1"} <= REQUIRED_FILES
    validate_payload(REQUIRED_FILES)
    installer = (root / "tools/build-sli-agent-msi.ps1").read_text("utf-8-sig")
    assert "'sli_agent/gpo_snapshot.ps1'" in installer
    assert "'scripts/ad_context/GpoReportContract.psm1'" in installer


def test_powershell_reader_uses_gpo_script_stdin_and_suppresses_diagnostics(monkeypatch):
    from sli_agent import ad_snapshot
    class Input(io.BytesIO):
        def close(self):
            self.sent = self.getvalue()
            super().close()
    class Process:
        pid = 42
        returncode = 0
        stdin = Input()
        stdout = io.BytesIO(json.dumps(capture()).encode())
        def poll(self):
            return self.returncode
        def wait(self, timeout=None):
            return self.returncode
    calls = []
    process = Process()
    def start(args, **kwargs):
        calls.append((args, kwargs))
        return process
    monkeypatch.setattr(ad_snapshot.subprocess, "Popen", start)
    assert PowerShellGPOReader()(config(), deadline=time.monotonic() + 30, stop=threading.Event()) == capture()
    assert calls[0][0][-1].endswith("gpo_snapshot.ps1")
    assert calls[0][1]["stderr"] == subprocess.DEVNULL
    assert json.loads(process.stdin.sent)["domain_sid"] == SID


@pytest.mark.parametrize("field", ["apiKey", "encryption_key", "cpassword", "raw_xml", "script_content"])
def test_governance_masks_secret_and_raw_properties_before_import(field):
    from server.sli.plugins.gpo.snapshot_import import prepare_gpo_cycle
    raw, cfg = capture(), config()
    raw["records"][0]["attributes"]["gpo_settings"][0]["properties"][field] = "synthetic-redaction-marker"
    families = normalize_capture(raw, cfg)
    bundle = prepare_gpo_cycle({"domain_sid": SID, "policy": cfg}, {name: data for name, (data, _) in families.items()})
    assert "synthetic-redaction-marker" not in canonical(bundle).decode()
    setting = bundle["records"][0]["attributes"]["gpo_settings"][0]
    assert field not in setting["properties"] and setting["sensitive_value_present"] is True


@pytest.mark.parametrize("key", ["Console", "Control Panel\\Desktop", "Software\\Synthetic"])
def test_registry_paths_are_metadata_preserved_by_gpo_spool(tmp_path, key):
    cfg, raw = config(), capture()
    raw["records"][0]["attributes"]["gpo_settings"][0]["properties"]["key"] = key
    families = normalize_capture(raw, cfg)
    stream = SnapshotStream(tmp_path, "sli.gpo-snapshot")
    stream.freeze(stream.begin(cfg, now=NOW), families)
    stored = json.loads(base64.b64decode(stream.read()["families"]["ad_gpo_governance"]["data_b64"]))
    assert stored["records"][0]["attributes"]["gpo_settings"][0]["properties"]["key"] == key


def test_missing_powershell_does_not_expose_os_diagnostics(monkeypatch):
    from sli_agent import ad_snapshot
    def missing(*args, **kwargs):
        raise OSError("synthetic-private-diagnostic")
    monkeypatch.setattr(ad_snapshot.subprocess, "Popen", missing)
    with pytest.raises(ValueError, match="^agent_gpo_capture_failed$"):
        PowerShellGPOReader()(config(), deadline=time.monotonic() + 30, stop=threading.Event())


def test_normalized_script_filename_is_preserved_while_body_is_masked():
    from sli_agent.gpo_privacy import HIDDEN, mask_gpo
    setting = {"setting_name": "Command", "path": "Scripts/Script/Command", "value_display": "synthetic.ps1"}
    assert mask_gpo(setting) == setting
    setting["value_display"] = "synthetic-script-body"
    assert mask_gpo(setting)["value_display"] == HIDDEN


def test_capture_domain_sid_is_retained_for_existing_rights_classification():
    cfg = config()
    snapshot = normalize_capture(capture(), cfg)["gpo_v2"][0]
    assert snapshot["domain"]["sid"] == SID


def test_thousands_of_gpos_do_not_halve_the_object_ceiling(tmp_path):
    cfg, raw = config(), capture()
    example, record = raw["snapshot"]["gpos"][0], raw["records"][0]
    raw["snapshot"]["gpos"], raw["records"] = [], []
    for index in range(5001):
        guid = str(UUID(int=index + 1))
        gpo, entity = deepcopy(example), deepcopy(record)
        gpo.update(id="gpo-" + guid, guid=guid, display_name=f"Synthetic policy {index}", link_ids=[], setting_ids=[], permission_ids=[])
        gpo["gpc"]["gpc_file_sys_path"] = rf"\\{DNS}\SYSVOL\{DNS}\Policies\{{{guid}}}"
        entity.update(record_key=f"ad:{SID.lower()}:{guid}")
        entity["identity"]["object_guid"] = guid
        entity["attributes"]["display_name"] = gpo["display_name"]
        raw["snapshot"]["gpos"].append(gpo)
        raw["records"].append(entity)
    for name in ("settings", "permissions", "acl", "links"):
        raw["snapshot"][name] = []
    families = normalize_capture(raw, cfg)
    assert families["gpo_v2"][0]["collection_status"] == "complete"
    stream = SnapshotStream(tmp_path, "sli.gpo-snapshot")
    stream.freeze(stream.begin(cfg, now=NOW), families)
    assert {info["total_objects"] for info in stream.read()["families"].values()} == {5001}


def test_shared_powershell_normalizer_matches_retained_legacy_on_synthetic_xml(tmp_path):
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if powershell is None:
        pytest.skip("PowerShell pure normalizer is unavailable in this container")
    root = Path(__file__).resolve().parents[2]
    runner = tmp_path / "normalizer.ps1"
    runner.write_text(r'''
param($ModulePath, $ExporterPath, $AgentPath)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Import-Module $ModulePath -Force -ErrorAction Stop
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($ExporterPath,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'legacy_parse_failed' }
foreach ($name in @('Convert-GpoReportSettings','Get-XmlNodePath','Get-Sha256Hex','New-StableId','New-SourceState','ConvertFrom-WmiDateText')) {
    $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    . ([scriptblock]::Create($definition.Extent.Text))
}
$agentAst=[Management.Automation.Language.Parser]::ParseFile($AgentPath,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'agent_parse_failed' }
foreach ($name in @('Within-Budget','Wmi-Date','Get-ConfinedGptPath')) {
    $definition=$agentAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    . ([scriptblock]::Create($definition.Extent.Text))
}
$script:ObservedAt='2026-10-08T12:00:00Z'
[xml]$xml='<GPO><Computer><Enabled>true</Enabled><ExtensionData><Extension><Name>Preferences</Name><Registry key="Software\Synthetic" value="1"/><Task><Properties action="U" cpassword="synthetic-redaction-marker"/></Task></Extension></ExtensionData></Computer><User><Enabled>false</Enabled><ExtensionData><Extension><Name>Security</Name><Policy><Name>Synthetic policy</Name><Value>1</Value></Policy></Extension></ExtensionData></User></GPO>'
$output=@{}
foreach ($side in @('computer','user')) {
    $old=Convert-GpoReportSettings -Xml $xml -GpoId 'gpo-test' -GpoName 'Synthetic policy' -Side $side -Maximum 5000
    $new=ConvertTo-SLIGpoV2Settings -Xml $xml -GpoId 'gpo-test' -GpoName 'Synthetic policy' -Side $side -Maximum 5000 -ObservedAt $script:ObservedAt
    $output[$side]=@{legacy=$old; agent=$new}
}
$output.facts=ConvertFrom-SLIGpoReportXml -XmlText $xml.OuterXml
$policy=@{max_bytes=128}; $script:CapturedBytes=0; $script:overflow=$false
$output.budget=@{small=(Within-Budget @{name='synthetic'}); large=(Within-Budget @{name=('x' * 200)}); overflow=$script:overflow}
$output.wmiDate=@{legacy=(ConvertFrom-WmiDateText '20261008120000.000000+000'); agent=(Wmi-Date '20261008120000.000000+000')}
$domainDns='directory.invalid'; $server='dc.directory.invalid'; $rejected=0
foreach ($path in @('\\directory.invalid\SYSVOL\directory.invalid\Policies\..','\\other.invalid\SYSVOL\directory.invalid\Policies\{00000000-0000-0000-0000-000000000001}')) {
    try { $null=Get-ConfinedGptPath $path '00000000-0000-0000-0000-000000000001' } catch {
        if ($_.Exception.Message -eq 'agent_gpo_sysvol_path_invalid') { $rejected++ }
    }
}
$output.rejectedPaths=$rejected
$output | ConvertTo-Json -Depth 30 -Compress
''', encoding="utf-8-sig")
    completed = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-File", str(runner),
        str(root / "scripts/ad_context/GpoReportContract.psm1"), str(root / "scripts/ad_context/Export-AdGpoV2Snapshot.ps1"),
        str(root / "sli_agent/gpo_snapshot.ps1")], capture_output=True, timeout=30, check=True)
    result = json.loads(completed.stdout.decode("utf-8-sig"))
    assert result["computer"]["legacy"] == result["computer"]["agent"]
    assert result["user"]["legacy"] == result["user"]["agent"]
    assert "synthetic-redaction-marker" not in json.dumps(result)
    assert result["facts"]["attributes"]["gpo_computer_enabled"] is True
    assert result["facts"]["attributes"]["gpo_user_enabled"] is False
    assert result["budget"] == {"small": True, "large": False, "overflow": True}
    assert result["wmiDate"]["agent"] == result["wmiDate"]["legacy"]
    assert result["rejectedPaths"] == 2
