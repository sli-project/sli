"""WiX and offline build boundaries, checked on Linux without WiX."""
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[2]






NS = {"w": "http://schemas.microsoft.com/wix/2006/wi"}














@pytest.mark.parametrize("language", ["en", "ru"])
def test_unattended_install_examples_pass_enrollment_by_local_file(language):
    markdown = (ROOT / f"docs/install/AGENT_INSTALL.{language}.md").read_text(encoding="utf-8")
    commands = re.sub(r"`[ \t]*\n", " ", markdown)
    examples = re.findall(r"^[ \t]*msiexec(?:\.exe)?[ \t]+([^\n]+)", commands, re.I | re.M)
    forbidden = {"TOKEN", "ENROLLMENT_TOKEN", "PASSWORD", "SERVICE_PASSWORD"}

    has_unattended_enrollment = False
    for arguments in examples:
        lexer = shlex.shlex(arguments, posix=True)
        lexer.whitespace_split = True
        lexer.escape = ""  # Backslashes in Windows paths are literal.
        args = list(lexer)
        options = {arg.lower() for arg in args if arg.startswith("/")}
        for argument in args:
            name, sep, value = argument.partition("=")
            if not sep:
                continue
            assert name.upper() not in forbidden
            if name.upper() == "TOKEN_FILE":
                path = PureWindowsPath(value)
                assert path.is_absolute() and path.drive.endswith(":") and path.name
                has_unattended_enrollment |= {"/i", "/qn", "/norestart"} <= options

    assert has_unattended_enrollment
