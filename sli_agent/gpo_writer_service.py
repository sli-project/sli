# SPDX-License-Identifier: Apache-2.0
"""Separate SCM host for GPO diagnostics. Administrative provisioning is external.

No installer, password prompt, command receiver or AD mutation is exposed here.
The dedicated gMSA must already exist and have service logon configured by AD's
administrator. The collector's LocalSystem/DC$ context is never reused.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from sli_agent.gpo_writer import WriterConfig, preflight


SERVICE_NAME = "SLIGpoWriter"
# TrustedInstaller, SYSTEM and built-in Administrators may maintain binaries.
TRUSTED_OWNERS = frozenset({"S-1-5-18", "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"})


def _restricted_descriptor(owner, aces, *, ancestor=False):
    """Conservative allow-list, not an implementation of Windows AccessCheck."""
    if owner not in TRUSTED_OWNERS or aces is None:
        return False
    # Ancestors must prevent replacement; the file itself must also be immutable
    # to the writer. A null DACL or an unknown ACE type fails closed.
    dangerous = 0x10000000 | 0x40000000 | 0x000D0040  # generic all/write, delete, DACL/owner, delete child
    if not ancestor:
        dangerous |= 0x00000116  # write/append data, write EA/attributes
    for kind, flags, mask, sid in aces:
        if kind not in (0, 1):
            return False
        if kind == 0 and not flags & 0x08 and mask & dangerous and sid not in TRUSTED_OWNERS:
            return False
    return True


def protected_installation(config_path):
    import win32security
    files = (Path(config_path), Path(__file__), Path(__file__).with_name("gpo_writer.py"),
        Path(__file__).with_name("gpo_writer.ps1"), Path(__file__).with_name("__init__.py"))
    seen = set()
    for file in files:
        if not file.is_file():
            raise ValueError("gpo_writer_local_protection_failed")
        for path in (file, *file.parents):
            marker = (str(path), path != file)
            if marker in seen:
                continue
            seen.add(marker)
            if path.is_symlink() or path.is_junction():
                raise ValueError("gpo_writer_local_protection_failed")
            descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
            owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
            acl = descriptor.GetSecurityDescriptorDacl()
            aces = None
            if acl is not None:
                aces = []
                for index in range(acl.GetAceCount()):
                    ace = acl.GetAce(index)
                    if len(ace) != 3:
                        raise ValueError("gpo_writer_local_protection_failed")
                    aces.append((*ace[0], ace[1], win32security.ConvertSidToStringSid(ace[2])))
            if not _restricted_descriptor(owner, aces, ancestor=path != file):
                raise ValueError("gpo_writer_local_protection_failed")


def run_diagnostics(config_path, stop, *, check_installation=protected_installation, inspect=preflight, save=None):
    if save is None:
        from sli_agent.protection import atomic_write
        save = atomic_write
    while not stop.is_set():
        # Recheck on every cycle, before trusting a changed local OU map.
        check_installation(config_path)
        config = WriterConfig.load(config_path)
        report = inspect(config)
        save(Path(config_path).parent / "state" / "preflight.json", json.dumps(report).encode("ascii"))
        stop.wait(300)


def service_class():
    if os.name != "nt":
        raise RuntimeError("gpo_writer_windows_required")
    import servicemanager
    import win32service
    import win32serviceutil

    class SliGpoWriterService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = "SLI GPO Writer"
        _svc_description_ = "Dedicated GPO identity; stage 1 read-only diagnostics, no AD writes."

        def __init__(self, args):
            super().__init__(args)
            self.stop = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop.set()

        def SvcDoRun(self):
            try:
                config = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "SLI" / "GpoWriter" / "writer.json"
                run_diagnostics(config, self.stop)
            except Exception:
                servicemanager.LogErrorMsg("SLI GPO writer stopped: gpo_writer_diagnostics_failed")
                raise RuntimeError("gpo_writer_diagnostics_failed") from None

    SliGpoWriterService.__module__ = "sli_agent.gpo_writer_service"
    SliGpoWriterService.__qualname__ = "SliGpoWriterService"
    return SliGpoWriterService


if os.name == "nt":
    SliGpoWriterService = service_class()


def main():
    if os.name != "nt":
        raise RuntimeError("gpo_writer_windows_required")
    import servicemanager
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(SliGpoWriterService)
    servicemanager.StartServiceCtrlDispatcher()


if __name__ == "__main__":
    main()
