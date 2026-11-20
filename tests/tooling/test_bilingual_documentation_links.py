"""Offline link checks for repository entry points and operator guides."""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCUMENTS = (
    "README.md",
    "README.ru.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "agent-dotnet/INSTALL.md",
    "agent-dotnet/PROTOCOL.md",
    "docs/ADMIN_GUIDE.md",
    "docs/USER_GUIDE.md",
    "docs/agent-enrollment.md",
    "docs/install/REPORT_PRODUCER.md",
    ".github/ISSUE_TEMPLATE/bug_report.md",
    ".github/ISSUE_TEMPLATE/feature_request.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    "docs/install/SERVER_INSTALL.en.md",
    "docs/install/SERVER_INSTALL.ru.md",
    "docs/install/AGENT_INSTALL.en.md",
    "docs/install/AGENT_INSTALL.ru.md",
)
INLINE_LINK = re.compile(
    r"!?\[[^\]\n]*\]\(\s*(?:<([^>\n]+)>|([^\s)]+))"
    r"(?:\s+['\"][^)\n]*['\"])?\s*\)"
)
REFERENCE_LINK = re.compile(r"(?m)^ {0,3}\[[^\]\n]+\]:\s*(?:<([^>\n]+)>|(\S+))")


def _without_fences(text: str) -> str:
    text = re.sub(r"(?ms)^```[^\n]*\n.*?^```[ \t]*$", "", text)
    return re.sub(r"(?ms)^~~~[^\n]*\n.*?^~~~[ \t]*$", "", text)


def _anchors(text: str) -> set[str]:
    anchors = set()
    counts: dict[str, int] = {}
    for heading in re.findall(r"(?m)^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", _without_fences(text)):
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        count = counts.get(slug, 0)
        anchors.add(f"{slug}-{count}" if count else slug)
        counts[slug] = count + 1
    return anchors


def _check_links(document: Path, root: Path) -> None:
    prose = _without_fences(document.read_text(encoding="utf-8"))
    prose = re.sub(r"`+[^`\n]*`+", "", prose)
    destinations = [
        match.group(1) or match.group(2)
        for pattern in (INLINE_LINK, REFERENCE_LINK)
        for match in pattern.finditer(prose)
    ]
    for destination in destinations:
        url = urlsplit(destination)
        if url.scheme or url.netloc:
            continue  # External links are not fetched by this offline check.
        target = (document.parent / unquote(url.path)).resolve() if url.path else document.resolve()
        assert target.is_relative_to(root.resolve()), f"Link escapes repository: {destination}"
        assert target.exists(), f"Missing link in {document.relative_to(root)}: {destination}"
        if url.fragment and target.suffix == ".md":
            assert unquote(url.fragment) in _anchors(target.read_text(encoding="utf-8")), (
                f"Missing heading in {document.relative_to(root)}: {destination}"
            )


@pytest.mark.parametrize("relative", DOCUMENTS)
def test_public_documentation_links(relative: str) -> None:
    _check_links(ROOT / relative, ROOT)


def test_checker_accepts_relative_references_images_and_unicode_anchors(tmp_path: Path) -> None:
    guide = tmp_path / "guide file.md"
    guide.write_text("# Установка\n# Установка\n", encoding="utf-8")
    (tmp_path / "image.png").write_bytes(b"synthetic image")
    document = tmp_path / "index.md"
    document.write_text(
        "[Guide](guide%20file.md#%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0-1)\n"
        "![Image](image.png)\n[Reference][guide]\n[guide]: <guide file.md>\n"
        "[External](https://example.invalid/)\n"
        "`[Ignored inline](missing.md)`\n"
        "```md\n[Ignored](missing.md)\n```\n",
        encoding="utf-8",
    )
    _check_links(document, tmp_path)


@pytest.mark.parametrize(
    ("destination", "error"),
    [
        ("missing.md", "Missing link"),
        ("guide.md#missing", "Missing heading"),
        ("../outside.md", "Link escapes repository"),
    ],
)
def test_checker_rejects_broken_links(tmp_path: Path, destination: str, error: str) -> None:
    (tmp_path / "guide.md").write_text("# Guide\n", encoding="utf-8")
    document = tmp_path / "index.md"
    document.write_text(f"[Guide]({destination})\n", encoding="utf-8")
    with pytest.raises(AssertionError, match=error):
        _check_links(document, tmp_path)
