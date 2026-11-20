from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "maintenance" / "Invoke-SLIClaudeTester.ps1"


def test_claude_team_runner_is_bounded_read_only_and_measures_usage() -> None:
    text = RUNNER.read_text(encoding="utf-8")

    assert '[ValidateSet("haiku", "sonnet")]' in text
    assert '[string]$Model = "haiku"' in text
    assert '[ValidateRange(1, 5)]' in text
    assert "$TaskText.Length -gt 12000" in text
    assert "Get-ClaudeUsage" in text
    work = text.rindex("Invoke-SLIClaudeProcess -Arguments")
    assert text.index("$before = Get-ClaudeUsage") < work
    assert work < text.index("$after = Get-ClaudeUsage")
    assert "session_used_percent -ge 85" in text
    assert '"Read,Glob,Grep"' in text
    assert '"Edit,Write,NotebookEdit,Bash"' in text
    assert '"--no-session-persistence"' in text
    assert '"--json-schema"' in text
    assert "minItems = $ExpectedItems" in text
    assert "$structuredFindings.Count -eq $ExpectedItems" in text
    assert "$null -ne $taskResult.structured_output.findings" in text
    assert "$startInfo.Arguments = (" in text
    assert "ConvertTo-SLIProcessArgument -Value" in text
    assert "project_mutation_allowed = $false" in text
    assert "cost_per_item_usd" in text
    assert "output_tokens_per_item" in text
