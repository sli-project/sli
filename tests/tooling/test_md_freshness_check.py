from __future__ import annotations

from pathlib import Path

import pytest

import scripts.maintenance.md_freshness_check as freshness


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_absent_folder_indexes_are_not_required(tmp_path: Path) -> None:
    (tmp_path / "frontend" / "src" / "components").mkdir(parents=True)
    _write(tmp_path / "frontend" / "README.md", "Existing documentation\n")
    items, warnings = freshness.folder_index_items(tmp_path)
    assert warnings == []
    assert [item["path"] for item in items] == ["frontend/README.md"]


def test_instruction_walk_prunes_dependencies_and_generated_trees(tmp_path: Path) -> None:
    _write(tmp_path / "frontend/AGENTS.md", "current rules")
    for rel in ("frontend/node_modules/a/AGENTS.md", "frontend/artifacts/CLAUDE.md", "server/__pycache__/AGENTS.md"):
        _write(tmp_path / rel, "not project rules")
    assert freshness.instruction_markdown_paths(tmp_path) == ["frontend/AGENTS.md"]


def test_broken_historical_link_is_reported_without_promoting_authority(tmp_path: Path) -> None:
    _write(tmp_path / "docs/DOCUMENTATION_INDEX.md", "| missing-reference.md | historical | context |\n")
    items, warnings = freshness.documentation_index_items(tmp_path)
    assert items[0]["current_authority"] is False
    assert warnings == ["broken historical documentation path: docs/missing-reference.md"]


def test_historical_status_marker_cannot_satisfy_current_contract(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write(tmp_path / "docs" / "CURRENT_ROADMAP.md", "МЫ ЗДЕСЬ\n")
    monkeypatch.setattr(freshness, "REQUIRED_MD", ["docs/CURRENT_ROADMAP.md"])
    monkeypatch.setattr(
        freshness,
        "CONTRACT_MARKERS",
        {"docs/CURRENT_ROADMAP.md": ["# SLI дорожная карта владельца/архитектора"]},
    )

    result = freshness.check_markdown_freshness(tmp_path)

    assert result["status"] == "failed"
    assert result["items"][0]["missing_contract_markers"] == [
        "# SLI дорожная карта владельца/архитектора"
    ]


def test_instruction_surface_coverage_includes_root_nearest_and_scoped_docs(
    tmp_path: Path,
) -> None:
    expected = {
        ".github/PULL_REQUEST_TEMPLATE.md",
        "AGENTS.md",
        "CLAUDE.md",
        "docs/agents/CLAUDE_CODE_ROLE.md",
        "frontend/AGENTS.md",
        "server/feature/AGENTS.md",
    }
    for rel in expected:
        _write(tmp_path / rel, "instruction surface\n")
    _write(tmp_path / "docs" / "ordinary-reference.md", "not an instruction\n")

    assert set(freshness.instruction_markdown_paths(tmp_path)) == expected
    result = freshness.check_markdown_freshness(tmp_path)
    assert result["instruction_surface_count"] == len(expected)
    assert "total_markdown_count" not in result


@pytest.mark.parametrize("signature", freshness.STALE_INSTRUCTION_SIGNATURES)
def test_stale_instruction_surface_fails(
    tmp_path: Path,
    monkeypatch,
    signature: str,
) -> None:
    _write(
        tmp_path / "AGENTS.md",
        f"{signature}\n",
    )
    monkeypatch.setattr(freshness, "REQUIRED_MD", [])

    result = freshness.check_markdown_freshness(tmp_path)

    assert result["status"] == "failed"
    assert result["instruction_items"] == [{
        "path": "AGENTS.md",
        "exists": True,
        "status": "warn",
        "size_bytes": (tmp_path / "AGENTS.md").stat().st_size,
        "stale_contamination_signatures": [signature],
    }]
    assert (
        f"stale instruction contamination: AGENTS.md: {signature}"
    ) in result["warnings"]


def test_empty_active_instruction_fails(tmp_path: Path, monkeypatch) -> None:
    _write(tmp_path / "docs" / "agents" / "CODEX_ROLE.md", "")
    monkeypatch.setattr(freshness, "REQUIRED_MD", [])

    result = freshness.check_markdown_freshness(tmp_path)

    assert result["status"] == "failed"
    assert "empty active instruction: docs/agents/CODEX_ROLE.md" in result["warnings"]


def test_claude_code_role_is_an_instruction_surface(tmp_path: Path) -> None:
    role = "docs/agents/CLAUDE_CODE_ROLE.md"
    _write(tmp_path / role, "# Claude Code role\n")

    assert role in freshness.instruction_markdown_paths(tmp_path)


def test_empty_mandatory_canonical_document_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write(tmp_path / "docs" / "forgtp.md", "")
    monkeypatch.setattr(freshness, "REQUIRED_MD", ["docs/forgtp.md"])
    monkeypatch.setattr(freshness, "CONTRACT_MARKERS", {"docs/forgtp.md": []})

    result = freshness.check_markdown_freshness(tmp_path)

    assert result["status"] == "failed"
    assert "empty mandatory markdown: docs/forgtp.md" in result["warnings"]


def test_broken_current_authority_path_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write(
        tmp_path / "docs" / "DOCUMENTATION_INDEX.md",
        "| Path | Label | Use |\n"
        "| --- | --- | --- |\n"
        "| missing-current.md | active | Current execution authority. |\n",
    )
    monkeypatch.setattr(
        freshness,
        "REQUIRED_MD",
        ["docs/DOCUMENTATION_INDEX.md"],
    )
    monkeypatch.setattr(
        freshness,
        "CONTRACT_MARKERS",
        {"docs/DOCUMENTATION_INDEX.md": ["| Path | Label | Use |"]},
    )

    result = freshness.check_markdown_freshness(tmp_path)

    assert result["status"] == "failed"
    assert "broken current authority path: docs/missing-current.md" in result["warnings"]


def test_fresh_reference_is_not_promoted_to_current_authority(tmp_path: Path) -> None:
    _write(tmp_path / "docs" / "fresh-reference.md", "fresh supporting material\n")
    _write(
        tmp_path / "docs" / "DOCUMENTATION_INDEX.md",
        "| Path | Label | Use |\n"
        "| --- | --- | --- |\n"
        "| fresh-reference.md | reference | Supporting evidence. |\n",
    )

    items, warnings = freshness.documentation_index_items(tmp_path)

    assert warnings == []
    assert items == [
        {
            "path": "docs/fresh-reference.md",
            "label": "reference",
            "exists": True,
            "current_authority": False,
        }
    ]
