"""Progress diagnostics are local aggregate metadata, never source payloads."""
import json
from pathlib import Path
import subprocess
import os

import pytest


def test_timeout_contains_only_bounded_allowlisted_progress(monkeypatch):
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as worker
    monkeypatch.setattr(worker, "_collector_request", lambda **kwargs: kwargs)
    script = worker.ROOT / "scripts/ad_context/Export-AdAuditContextBundle.ps1"
    monkeypatch.setattr(worker, "build_ad_context_command", lambda request: ["powershell.exe", "-File", str(script)])
    def runner(command, **kwargs):
        assert "-ProgressPath" in command
        progress = Path(command[command.index("-ProgressPath") + 1])
        progress.write_text(json.dumps({"phase": "exact_logon_queries", "elapsed_sec": 897,
            "exact_queries_completed": 1200, "username": "secret-name", "password": "secret-password"}))
        raise RuntimeError("ad_source_process_timeout")
    monkeypatch.setattr(worker, "_run_collector_process", runner)
    with pytest.raises(RuntimeError) as result:
        worker._collect("ad_context_base")
    message = str(result.value)
    assert '"phase":"exact_logon_queries"' in message
    assert '"exact_queries_completed":1200' in message
    assert "secret-" not in message


@pytest.mark.parametrize("payload", [b"x" * 4097, b"{broken", b'{"phase":"secret-name","elapsed_sec":"secret-password"}'], ids=["oversized", "malformed", "untrusted"])
def test_untrusted_or_oversized_progress_does_not_escape_timeout(monkeypatch, payload):
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as worker
    monkeypatch.setattr(worker, "_collector_request", lambda **kwargs: kwargs)
    script = worker.ROOT / "scripts/ad_context/Export-AdAuditContextBundle.ps1"
    monkeypatch.setattr(worker, "build_ad_context_command", lambda request: ["powershell.exe", "-File", str(script)])
    def runner(command, **kwargs):
        assert "-ProgressPath" in command
        Path(command[command.index("-ProgressPath") + 1]).write_bytes(payload)
        raise RuntimeError("ad_source_process_timeout")
    monkeypatch.setattr(worker, "_run_collector_process", runner)
    with pytest.raises(RuntimeError) as result:
        worker._collect("ad_context_base")
    assert "ad_source_process_timeout" in str(result.value)
    assert "secret-" not in str(result.value)
    assert len(str(result.value)) < 200


def test_privileged_collector_does_not_receive_unknown_progress_parameter(monkeypatch):
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as worker
    monkeypatch.setattr(worker, "_collector_request", lambda **kwargs: kwargs)
    script = worker.ROOT / "scripts/ad_context/Export-AdContextBundle.ps1"
    monkeypatch.setattr(worker, "build_ad_context_command", lambda request: ["powershell.exe", "-File", str(script)])
    def runner(command, **kwargs):
        assert "-ProgressPath" not in command
        raise RuntimeError("ad_source_process_timeout")
    monkeypatch.setattr(worker, "_run_collector_process", runner)
    with pytest.raises(RuntimeError, match="ad_source_process_timeout"):
        worker._collect("ad_privileged_membership")


@pytest.mark.windows_only
@pytest.mark.parametrize("path_mode", ["normal", "same", "partial_collision"])
def test_powershell_progress_function_and_full_script_parameter_parse(tmp_path, path_mode):
    root = Path(__file__).resolve().parents[2]
    script = root / "scripts/ad_context/Export-AdAuditContextBundle.ps1"
    harness = tmp_path / "progress-fixture.ps1"
    harness.write_text("""param($SourcePath, $ProgressPath, $OutputPath)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($SourcePath,[ref]$tokens,[ref]$errors)
if (@($errors).Count) { throw 'collector_parse_failed' }
if ('ProgressPath' -notin @($ast.ParamBlock.Parameters | ForEach-Object {$_.Name.VariablePath.UserPath})) { throw 'progress_parameter_missing' }
$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Write-SLICollectorProgress'},$true)
if ($null -eq $function) { throw 'progress_function_missing' }
. ([scriptblock]::Create($function.Extent.Text))
$script:ProgressClock=[Diagnostics.Stopwatch]::StartNew()
Write-SLICollectorProgress -Phase base_users_start
Write-SLICollectorProgress -Phase exact_logon_queries -UserCount 400 -ExactQueries 100 -DcCount 2
""", encoding="utf-8")
    powershell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    progress = tmp_path / "p.json"
    output = tmp_path / "bundle.json"
    if path_mode == "same":
        progress = Path(str(output).upper())
    elif path_mode == "partial_collision":
        output = Path(str(progress) + ".partial")
        progress = Path(str(progress).upper())
    output.write_text("original-bundle", encoding="utf-8")
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-File", str(harness), str(script), str(progress), str(output)], capture_output=True, text=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert output.read_text(encoding="utf-8") == "original-bundle"
    if path_mode != "normal":
        return
    payload = json.loads(progress.read_text())
    assert payload == {"phase": "exact_logon_queries", "elapsed_sec": payload["elapsed_sec"], "user_count": 400, "exact_queries_completed": 100, "dc_count": 2}
    assert isinstance(payload["elapsed_sec"], int) and payload["elapsed_sec"] >= 0
    assert progress.stat().st_size < 4096 and not progress.with_suffix(".json.partial").exists()
