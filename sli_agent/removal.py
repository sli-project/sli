# SPDX-License-Identifier: Apache-2.0
"""Fixed MSI uninstall command; no server-supplied paths or process arguments."""
from __future__ import annotations

import os
import re
import subprocess
from uuid import UUID

from sli_agent.config import machine_config_path
from sli_agent.msi import owned_tree


def validate_command(value, agent_id):
    try:
        if (not isinstance(value, dict) or set(value) != {"agent_id", "agent_removal"}
                or value["agent_id"] != agent_id or
                set(value["agent_removal"]) != {"command_id", "action"} or
                value["agent_removal"]["action"] != "uninstall"):
            raise ValueError()
        return str(UUID(value["agent_removal"]["command_id"]))
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("agent_removal_invalid") from None


def msi_command(config):
    if os.name != "nt":
        raise ValueError("agent_removal_requires_admin")
    # MSI currently owns only the default instance. Do not remove a sibling or
    # a manually installed service with this machine-wide product code.
    root = machine_config_path().parent
    if config.instance_name is not None or config.state_dir != root / "state":
        raise ValueError("agent_removal_unmanaged")
    try:
        if not owned_tree(root):
            raise ValueError()
    except (OSError, ValueError):
        raise ValueError("agent_removal_unmanaged") from None
    import ctypes
    import winreg
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("agent_removal_requires_admin")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SLI\Agent", 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        product, kind = winreg.QueryValueEx(key, "ProductCode")
    if kind != winreg.REG_SZ or not re.fullmatch(r"\{[0-9A-Fa-f-]{36}\}", product):
        raise ValueError("agent_removal_unmanaged")
    UUID(product)
    directory = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(directory, len(directory))
    if not 0 < length < len(directory):
        raise ValueError("agent_removal_unmanaged")
    return [directory.value + r"\msiexec.exe", "/x", product, "/qn", "/norestart"]


def launch(config, value, transport, identity, *, command=msi_command, spawn=subprocess.Popen):
    command_id = validate_command(value, identity.agent_id)
    try:
        args = command(config)
        spawn(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, ValueError) as exc:
        # Native error text can contain local identity/path details.
        reason = str(exc) if str(exc) in {"agent_removal_requires_admin", "agent_removal_unmanaged"} else "agent_removal_cleanup_failed"
        transport.post("/api/v1/agent/removal-result", {"command_id": command_id,
                       "state": "cleanup_failed", "reason": reason}, identity=identity)
        return False
    return True
