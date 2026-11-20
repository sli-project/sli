from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]






def test_windows_identity_probe_no_longer_requires_child_process() -> None:
    identity_source = (
        ROOT / "server" / "sli" / "sources" / "radius_plugin_runtime.py"
    ).read_text(encoding="utf-8")
    function_source = identity_source.split(
        "def current_windows_account()", 1
    )[1].split("# --- radius-acquisition", 1)[0]
    assert "GetUserNameExW" in function_source
    assert 'subprocess.run(["whoami"]' not in function_source


