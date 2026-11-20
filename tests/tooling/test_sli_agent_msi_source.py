"""WiX and offline build boundaries, checked on Linux without WiX."""
import json
import re
import shutil
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]


def test_staged_powershell_payload_has_utf8_bom_and_is_parsed_before_packaging():
    script = (ROOT / 'tools/build-sli-agent-msi.ps1').read_text('utf-8')
    assert "[Text.UTF8Encoding]::new($true)" in script
    assert "[Management.Automation.Language.Parser]::ParseFile($scriptFile.FullName" in script
    assert "agent_msi_powershell_payload_invalid" in script
    assert script.index('agent_msi_powershell_payload_invalid') < script.index('candle.exe')


def test_dedicated_gpo_diagnostics_script_is_in_the_offline_payload():
    script = (ROOT / 'tools/build-sli-agent-msi.ps1').read_text('utf-8')
    assert "'sli_agent/gpo_writer.ps1'" in script
    assert (ROOT / 'sli_agent/gpo_writer.ps1').is_file()


NS = {"w": "http://schemas.microsoft.com/wix/2006/wi"}


def test_embedded_rights_probe_reads_only_shipped_source_packs(tmp_path, monkeypatch):
    from sli_agent import probe as rights
    from sli_agent.config import AgentConfig
    from sli_agent.modules import RIGHTS_REGISTRY

    script = (ROOT / "tools/build-sli-agent-msi.ps1").read_text()
    shipped = set(re.findall(r"'config/source_packs/([^']+\.json)'", script))
    pack_root = tmp_path / "config/source_packs"
    pack_root.mkdir(parents=True)
    for name in shipped:
        shutil.copyfile(ROOT / "config/source_packs" / name, pack_root / name)
    monkeypatch.setattr(rights, "PACK_ROOT", pack_root)
    for profile in RIGHTS_REGISTRY.values():
        if profile.source_pack:
            assert isinstance(json.loads((pack_root / profile.source_pack).read_text())["channels"], list)

    channels = []
    reader = SimpleNamespace(current_sid=lambda: "S-1-5-18", event_channel=channels.append)
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path,
                         service_identity_sid="S-1-5-18")
    report = rights.probe(config, reader=reader, planned=False,
                         assigned_modules=[{"module_id": "sli.file-audit", "enabled": True, "config": {}}])
    assert report["ready"] is True
    assert channels == ["Security"]


def test_per_machine_x64_service_and_deferred_actions():
    tree = ET.parse(ROOT / "tools/msi/SLIAgent.wxs")
    package = tree.find(".//w:Package", NS)
    assert package.get("InstallScope") == "perMachine"
    assert package.get("Platform") == "x64"
    service = tree.find(".//w:ServiceInstall", NS)
    assert service.get("Account") == "[SERVICE_ACCOUNT]"
    assert service.get("Arguments") == "-I -B -m sli_agent.service"
    assert service.get("Start") == "auto"
    control = tree.find(".//w:ServiceControl", NS)
    assert control.get("Start") == "install"
    assert control.get("Stop") == "both" and control.get("Remove") == "uninstall"
    assert control.get("Wait") == "yes"
    actions = {a.get("Id"): a for a in tree.findall(".//w:CustomAction", NS)}
    for name in ("ConfigureAgent", "RemoveAgent", "RollbackAgent", "CommitAgent"):
        assert actions[name].get("Impersonate") == "no"
        assert actions[name].get("Return") == "check"
    assert actions["RollbackAgent"].get("Execute") == "rollback"
    sequence = {a.get("Action"): a for a in tree.findall(".//w:InstallExecuteSequence/w:Custom", NS)}
    assert sequence["RemoveAgent"].get("After") == "DeleteServices"
    product = tree.find(".//w:RegistryValue[@Name='ProductCode']", NS)
    assert product.get("Value") == "[ProductCode]" and product.get("Root") == "HKLM"
    assert sequence["ConfigureAgent"].get("After") == "RollbackAgent"
    assert sequence["RollbackAgent"].get("After") == "InstallFiles"
    assert sequence["ConfigureAgent"].text == "NOT Installed AND NOT RESTORE_STATE AND NOT WIX_UPGRADE_DETECTED"


def test_no_secret_property_or_network_install_action():
    tree = ET.parse(ROOT / "tools/msi/SLIAgent.wxs")
    props = {p.get("Id") for p in tree.findall(".//w:Property", NS)}
    assert {"SERVER_URL", "CA_FILE", "CA_FINGERPRINT", "TOKEN_FILE", "SERVICE_ACCOUNT"} <= props
    assert not {"TOKEN", "ENROLLMENT_TOKEN", "PASSWORD", "SERVICE_PASSWORD"} & props
    native = (ROOT / "tools/msi/custom_action.cpp").read_text()
    assert "CreateProcessW" in native and "WaitForSingleObject" in native
    assert "TRUE, CREATE_NO_WINDOW" in native
    assert "120000" in native and "TerminateProcess" in native
    assert "cmd.exe" not in native and "tempfile" not in native


def test_build_uses_locked_hashes_offline_wheels_and_explicit_payload():
    lock = json.loads((ROOT / "tools/msi/toolchain.lock.json").read_text())
    for entry in [lock["python"], lock["wix"], *lock["wheels"]]:
        assert len(entry["sha256"]) == 64
        assert int(entry["sha256"], 16) != 0
    script = (ROOT / "tools/build-sli-agent-msi.ps1").read_text(encoding="utf-8-sig")
    assert script.isascii()
    assert "Get-FileHash" in script and "SHA256" in script
    assert "pip install" not in script and "venv" not in script
    assert "--startup" not in script
    assert "xml_safety.py" in script and "event_catalog.json" in script
    assert "python313._pth" in script and "pywin32_system32" in script
    assert "Import smoke check failed" in script


def test_repair_restores_account_without_provisioning_or_zip_update():
    tree = ET.parse(ROOT / "tools/msi/SLIAgent.wxs")
    assert tree.find(".//w:Property[@Id='STORED_SERVICE_ACCOUNT']/w:RegistrySearch", NS) is not None
    native = (ROOT / "tools/msi/custom_action.cpp").read_text()
    assert 'property(session, L"STORED_SERVICE_ACCOUNT")' in native
    assert "MsiSetTargetPathW" in native
    assert "ERROR_SERVICE_DOES_NOT_EXIST" in native
    major = tree.find(".//w:MajorUpgrade", NS)
    assert major.get("Schedule") == "afterInstallInitialize"
    assert major.get("AllowSameVersionUpgrades") == "no"


def test_major_upgrade_restores_state_before_start_without_cleanup_or_provisioning():
    tree = ET.parse(ROOT / "tools/msi/SLIAgent.wxs")
    assert tree.find(".//w:Product", NS).get("Id") == "*"
    assert tree.find(".//w:Product", NS).get("UpgradeCode") == "D6836D37-49FA-4AB6-BDFD-10B07ED51973"
    sequence = {a.get("Action"): a for a in tree.findall(".//w:InstallExecuteSequence/w:Custom", NS)}
    assert sequence["RestoreAgent"].get("After") == "ConfigureAgent"
    assert sequence["RestoreAgent"].text == "NOT Installed AND RESTORE_STATE"
    for name in ("RollbackAgent", "ConfigureAgent", "CommitAgent"):
        assert "NOT RESTORE_STATE" in sequence[name].text
        assert "NOT WIX_UPGRADE_DETECTED" in sequence[name].text
    assert 'NOT UPGRADINGPRODUCTCODE AND NOT PRESERVE_STATE' in sequence["RemoveAgent"].text
    restore = tree.find(".//w:CustomAction[@Id='RestoreAgent']", NS)
    assert restore.get("Execute") == "deferred" and restore.get("Impersonate") == "no"
    conditions = [c.text for c in tree.findall(".//w:Condition", NS)]
    assert "NOT WIX_UPGRADE_DETECTED OR RESTORE_STATE" not in conditions
    assert any("Installed OR WIX_UPGRADE_DETECTED OR RESTORE_STATE" in c for c in conditions)
    preserve = tree.find(".//w:CustomAction[@Id='PreserveAgent']", NS)
    assert preserve.get("Execute") == "deferred" and preserve.get("Impersonate") == "no"
    assert preserve.get("Return") == "check"
    assert sequence["PreserveAgent"].get("After") == "RestoreAgent"
    assert sequence["PreserveAgent"].text == "NOT Installed AND WIX_UPGRADE_DETECTED AND NOT RESTORE_STATE"
    assert sequence["CommitAgent"].get("After") == "PreserveAgent"
    native = (ROOT / "tools/msi/custom_action.cpp").read_text()
    assert 'property(session, L"WIX_UPGRADE_DETECTED").empty()' in native
    assert 'command + L"restore " + hex(property(session, L"RESTORE_STATE"))' in native
    assert 'command + L"preserve"' in native


def test_msi_and_embedded_agent_versions_come_from_build_version():
    source = (ROOT / "tools/build-sli-agent-msi.ps1").read_text()
    assert "Join-Path $repo 'VERSION'" in source
    assert "$ProductVersion = $derivedVersion" in source
    assert "msi_build_version_mismatch" in source
    assert "$parts[0] -= 2000" in source and "$parts[2] -gt 65535" in source
    assert "__version__" in source and "$buildVersion" in source


def test_install_docs_have_path_only_unattended_examples_and_revocation_boundary():
    for language in ("en", "ru"):
        source = (ROOT / f"docs/install/AGENT_INSTALL.{language}.md").read_text()
        assert '/qn /norestart' in source
        assert 'TOKEN_FILE="C:\\ProgramData\\SLI-Bootstrap\\enrollment.token"' in source
        assert "CA_FINGERPRINT" in source and "SERVICE_ACCOUNT" in source
        assert "GPO" in source and "SCCM" in source and "Intune" in source
        assert "#444" in source
