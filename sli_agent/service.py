# SPDX-License-Identifier: Apache-2.0
"""Windows SCM wrapper. Importing this module on Linux has no OS side effects."""
from __future__ import annotations

import os
import threading

from sli_agent.config import AgentConfig, machine_config_path, service_name, validate_instance_name
from sli_agent.runtime import run


def grant_restart_access(sid_text, instance=None):
    """Installer-only service control grant to the selected service identity."""
    import win32service
    import win32security
    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    service = None
    try:
        service = win32service.OpenService(manager, service_name(instance), win32service.READ_CONTROL | win32service.WRITE_DAC)
        descriptor = win32service.QueryServiceObjectSecurity(service, win32security.DACL_SECURITY_INFORMATION)
        acl = descriptor.GetSecurityDescriptorDacl()
        acl.AddAccessAllowedAce(win32security.ACL_REVISION,
            win32service.SERVICE_START | win32service.SERVICE_STOP | win32service.SERVICE_QUERY_STATUS,
            win32security.ConvertStringSidToSid(sid_text))
        descriptor.SetSecurityDescriptorDacl(1, acl, 0)
        win32service.SetServiceObjectSecurity(service, win32security.DACL_SECURITY_INFORMATION, descriptor)
    finally:
        if service is not None:
            win32service.CloseServiceHandle(service)
        win32service.CloseServiceHandle(manager)


def service_class(instance=None):
    if os.name != "nt":
        raise RuntimeError("agent_windows_required")
    import servicemanager
    import win32service
    import win32serviceutil

    class SliAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = service_name(instance)
        _svc_display_name_ = "SLI Agent" if instance is None else "SLI Agent (" + instance + ")"
        _svc_description_ = "Outbound SLI agent; collection disabled unless explicitly configured."

        def __init__(self, args):
            # pythonservice.exe imports this same stable class for every service.
            # SCM supplies the registered name, independent of CLI/environment.
            name = args[0]
            if name == service_name():
                self.instance_name = None
            elif name.startswith("SLI-Agent-"):
                self.instance_name = validate_instance_name(name[len("SLI-Agent-"):])
            else:
                raise ValueError("agent_service_name_invalid")
            self._svc_name_ = service_name(self.instance_name)
            super().__init__(args)
            self.stop = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop.set()

        def SvcDoRun(self):
            try:
                path = machine_config_path(self.instance_name)
                config = AgentConfig.load(path)
                if config.instance_name != self.instance_name:
                    raise ValueError("agent_service_instance_mismatch")
                if config.update_root is not None:
                    from sli_agent.launcher import request_service_restart, supervise
                    supervise(config, path, self.stop,
                        restart_service=lambda: request_service_restart(config.service_python, config.instance_name))
                else:
                    if (path.parent / ".msi-owned").exists():
                        from sli_agent.msi import run_managed
                        run_managed(config, self.stop)
                    else:
                        run(config, self.stop)
            except Exception:
                servicemanager.LogErrorMsg("SLI agent stopped: agent_service_failed")
                raise RuntimeError("agent_service_failed") from None

    # SCM imports the fully qualified module/class, never a factory-local name
    # or the interactive -m __main__ module.
    SliAgentService.__module__ = "sli_agent.service"
    SliAgentService.__qualname__ = "SliAgentService"
    return SliAgentService


if os.name == "nt":
    SliAgentService = service_class()


def main():
    if os.name != "nt":
        raise RuntimeError("agent_windows_required")
    import sys
    import argparse
    import servicemanager
    import win32serviceutil
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--instance")
    args, command = parser.parse_known_args(sys.argv[1:])
    cls = service_class(args.instance)
    if not command:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(cls)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Factory classes are not pickle-identical to the module's default
        # class. Store the explicit import path in each service's registry entry.
        return win32serviceutil.HandleCommandLine(cls,
            serviceClassString="sli_agent.service.SliAgentService", argv=[sys.argv[0], *command])


if __name__ == "__main__":
    raise SystemExit(main())
