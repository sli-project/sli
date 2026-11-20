"""Source contract only; native Windows behavior requires PowerShell validation."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_windows_cleanup_never_changes_acl_or_owner():
    source = (ROOT / 'scripts/maintenance/clean_tmp_sid.ps1').read_text(encoding='utf-8').lower()
    assert 'takeown' not in source
    assert 'icacls' not in source
    assert 's-1-1-0' not in source
    assert 'remove-item -literalpath' in source
    assert 'exit 1' in source
    assert "test-path -literalpath $d.fullname -erroraction stop" in source
    assert "[заблокировано процессом]" not in source
