# SPDX-License-Identifier: Apache-2.0
"""Read-only rights diagnostics; no source rows, account names or paths escape."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sli_agent.modules import RIGHTS_REGISTRY
from sli_agent.protection import restrict_path, sync_directory

STATUSES = frozenset({"available", "denied", "not_present", "not_applicable"})
PACK_ROOT = Path(__file__).resolve().parents[1] / "config" / "source_packs"
REMEDIES = {
    "event_channel": "Предоставьте учётке службы чтение канала (Event Log Readers и ACL канала); войдите заново или перезапустите службу.",
    "ad": "Проверьте доступность AD и разрешение чтения объекта домена для учётки службы; LocalSystem использует учётку компьютера.",
    "sysvol": "Предоставьте учётке службы чтение SYSVOL/Policies в разрешениях общего ресурса и NTFS; проверьте доступность домена.",
    "accounting": "Проверьте каталог Accounting и предоставьте учётке службы чтение каталога и файлов (NTFS и общий ресурс, если используется).",
    "identity": "Запустите проверку от имени выбранной учётки службы; настройте её в Windows Services и повторите проверку.",
    "module": "Зарегистрируйте требования чтения модуля в RIGHTS_REGISTRY и повторите проверку.",
    "state": "Запустите probe от имени службы и проверьте право записи в её каталог состояния.",
}

# Constant scripts use integrated Windows credentials, never input credentials or
# operator-supplied code. Only one of the four safe status literals is returned.
_PS_ERRORS = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices
function FailureStatus($failure) {
    $exception = $failure.Exception
    while ($exception.InnerException) { $exception = $exception.InnerException }
    $code = $exception.HResult -band 0xffff
    if ($exception -is [IO.FileNotFoundException] -or
        $exception -is [IO.DirectoryNotFoundException] -or
        $exception -is [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException] -or
        $code -in @(2, 3, 8240, 8250, 1355)) { return 'not_present' }
    return 'denied'
}
"""
_LDAP_SCRIPT = _PS_ERRORS + r"""
$root = $null
$object = $null
try {
    $auth = [DirectoryServices.AuthenticationTypes]::Secure -bor
        [DirectoryServices.AuthenticationTypes]::Signing -bor [DirectoryServices.AuthenticationTypes]::Sealing
    $root = [DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE')
    $root.AuthenticationType = $auth
    $root.RefreshCache(@('defaultNamingContext'))
    $dn = [string]$root.Properties['defaultNamingContext'][0]
    if (-not $dn) { 'not_present' } else {
        $object = [DirectoryServices.DirectoryEntry]::new(('LDAP://' + $dn))
        $object.AuthenticationType = $auth
        $object.RefreshCache(@('distinguishedName'))
        if ($object.Properties['distinguishedName'].Count -eq 1) { 'available' } else { 'denied' }
    }
} catch { FailureStatus $_ }
finally {
    if ($object) { $object.Dispose() }
    if ($root) { $root.Dispose() }
}
"""
_SYSVOL_SCRIPT = _PS_ERRORS + r"""
$domain = $null
$iterator = $null
$stream = $null
try {
    $domain = [DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
    $path = '\\' + $domain.Name + '\SYSVOL\' + $domain.Name + '\Policies'
    $iterator = [IO.Directory]::EnumerateDirectories($path).GetEnumerator()
    if ($iterator.MoveNext()) {
        $gpt = [IO.Path]::Combine($iterator.Current, 'gpt.ini')
        $stream = [IO.File]::Open($gpt, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        [void]$stream.ReadByte()
    }
    'available'
} catch { FailureStatus $_ }
finally {
    if ($stream) { $stream.Dispose() }
    if ($iterator -is [IDisposable]) { $iterator.Dispose() }
    if ($domain) { $domain.Dispose() }
}
"""


def _failure(exc):
    code = getattr(exc, "winerror", None)
    if isinstance(exc, (FileNotFoundError, ModuleNotFoundError)) or code in (2, 3, 15007):
        return "not_present", "source_missing"
    if isinstance(exc, PermissionError) or code in (5, 1314, 1326):
        return "denied", "access_denied"
    # Unrecognized failures are not evidence of absence or successful access.
    return "denied", "read_failed"


class WindowsRightsReader:
    def current_sid(self):
        if os.name != "nt":
            return None
        import win32api
        import win32con
        import win32security
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            return win32security.ConvertSidToStringSid(sid)
        finally:
            token.Close()

    def event_channel(self, channel):
        import win32evtlog
        query = None
        events = []
        try:
            query = win32evtlog.EvtQuery(channel,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection, "*", None)
            try:
                events = win32evtlog.EvtNext(query, 1, 1000, 0)
            except win32evtlog.error as exc:
                if exc.winerror != 259:  # An empty readable channel is available.
                    raise
            # Reading the XML confirms access, but it is discarded immediately.
            for event in events:
                win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
        finally:
            for event in events:
                event.Close()
            if query is not None:
                query.Close()

    def _powershell(self, script):
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        # Use the installed Windows binary, not an executable from the source path.
        executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        status = result.stdout.strip()
        if result.returncode != 0 or status not in STATUSES:
            raise RuntimeError("agent_probe_read_failed")
        return status

    def ad(self):
        return self._powershell(_LDAP_SCRIPT)

    def sysvol(self):
        return self._powershell(_SYSVOL_SCRIPT)

    def accounting(self, directory):
        # Enumerate the directory and open one existing log without disclosing
        # names/content. An empty directory still proves directory read access.
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.name.casefold().endswith(".log") and entry.is_file(follow_symlinks=False):
                    with open(entry.path, "rb") as stream:
                        stream.read(1)
                    break


def _check(module, kind, label, required, *, status, reason):
    text = {"available": "Чтение доступно.", "denied": "Доступ запрещён или чтение не подтверждено.",
            "not_present": "Источник или компонент не найден.", "not_applicable": "Не применяется."}[status]
    if reason == "run_as_service_identity":
        text = "Запустите проверку от имени службы для подтверждения прав."
    return {"module_id": module, "kind": kind, "label": label, "required": required,
            "status": status, "reason": reason, "text_ru": text,
            "remedy_ru": "" if status == "available" or not required else REMEDIES[kind]}


def service_identity_verified(config, *, reader=None):
    reader = reader or WindowsRightsReader()
    try:
        sid = reader.current_sid()
    except Exception:
        sid = None
    return bool(config.service_identity_sid and sid == config.service_identity_sid)


def probe(config, *, reader=None, assigned_modules=None, planned=True, now=None):
    """Probe a local install preview or live assignments, without enabling modules."""
    reader = reader or WindowsRightsReader()
    verified = service_identity_verified(config, reader=reader)
    checks = [_check("service", "identity", "Учётка службы", True,
        status="available" if verified else "not_applicable",
        reason="read_ok" if verified else "run_as_service_identity")]

    def read(module, kind, label, *args, required=True):
        if not required:
            status, reason = "not_applicable", "not_configured"
        elif not verified:
            status, reason = "not_applicable", "run_as_service_identity"
        else:
            try:
                status = getattr(reader, kind)(*args) or "available"
                if status not in STATUSES:
                    raise ValueError("agent_probe_status_invalid")
                reason = "read_ok" if status == "available" else "read_failed"
            except Exception as exc:
                status, reason = _failure(exc)
        checks.append(_check(module, kind, label, required, status=status, reason=reason))

    if planned or config.collection_enabled:
        for index, item in enumerate(config.event_channels):
            if not isinstance(item, dict) or not isinstance(item.get("channel"), str) or not item["channel"]:
                raise ValueError("agent_probe_config_invalid")
            # Arbitrary configured channel names may contain private identifiers.
            channel = item["channel"]
            label = channel if channel in ("Security", "System", "Directory Service", "DNS Server") else f"Настроенный канал {index + 1}"
            read("sli.windows-eventlog", "event_channel", label, channel)
    assignments = config.probe_modules if assigned_modules is None else assigned_modules
    if not isinstance(assignments, (list, tuple)) or len(assignments) > 64:
        raise ValueError("agent_probe_config_invalid")
    seen = set()
    for item in assignments:
        if not isinstance(item, dict):
            # Legacy string assignments do not enable capture.
            if isinstance(item, str):
                continue
            raise ValueError("agent_probe_config_invalid")
        module = item.get("module_id")
        if not isinstance(module, str) or module in seen or type(item.get("enabled", False)) is not bool:
            raise ValueError("agent_probe_config_invalid")
        seen.add(module)
        if not item.get("enabled", False) or module in ("sli.heartbeat", "sli.windows-eventlog"):
            continue
        profile = RIGHTS_REGISTRY.get(module)
        if profile is None:
            # No untrusted assignment strings in operator output.
            checks.append(_check("unregistered", "module", "Неизвестный модуль", True,
                status="not_present", reason="module_unregistered"))
            continue
        settings = item.get("config", {})
        if not isinstance(settings, dict):
            raise ValueError("agent_probe_config_invalid")
        if module in ("sli.vpn-nps", "sli.radius-accounting"):
            if type(settings.get("paused", False)) is not bool:
                raise ValueError("agent_probe_config_invalid")
            if settings.get("paused", False):
                continue
            from sli_agent.nps import FAMILIES

            families = settings.get("families", {})
            if (not isinstance(families, dict) or set(families) - {FAMILIES[module]}
                    or any(type(value) is not bool for value in families.values())):
                raise ValueError("agent_probe_config_invalid")
            if not families.get(FAMILIES[module], True):
                continue
        pack = json.loads((PACK_ROOT / profile.source_pack).read_text(encoding="utf-8")) if profile.source_pack else {"channels": []}
        channels = tuple(dict.fromkeys((*pack["channels"], *profile.extra_channels)))
        if module == "sli.radius-accounting":
            channels = ()
        elif module == "sli.workstations":
            from sli_agent.workstations import WorkstationsModule
            channels = WorkstationsModule("probe", settings).enabled_channels()
        elif module in ("sli.windows.ad-dc", "sli.windows.ad-dc-history"):
            from sli_agent.ad_dc import ADDCModule, CHANNELS, DCHistoryModule
            factory = DCHistoryModule if module == "sli.windows.ad-dc-history" else ADDCModule
            policy = factory("probe", settings).config
            channels = tuple(channel for channel in CHANNELS if policy["channels"][channel])
        for channel in channels:
            read(module, "event_channel", channel, channel)
        if profile.ad:
            read(module, "ad", "AD: LDAP bind и чтение объекта домена")
        if profile.sysvol:
            read(module, "sysvol", "SYSVOL/Policies: каталог и один существующий GPO")
        if profile.accounting:
            directory = settings.get("accounting_directory")
            if directory is not None and (not isinstance(directory, str) or not directory.strip()):
                raise ValueError("agent_probe_config_invalid")
            read(module, "accounting", "Accounting: каталог и один существующий log", directory,
                 required=directory is not None)
    return {"contract": "sli.agent-rights-probe.v1", "observed_at_utc": (now or datetime.now(timezone.utc)).isoformat(),
            "scope": "installation_preview" if planned else "assigned_modules",
            "identity_verified": verified, "ready": all(not c["required"] or c["status"] == "available" for c in checks),
            "checks": checks}


def save_report(config, report):
    # Preserve the existing state-directory ACL, especially when an administrator
    # invokes the CLI for a different service account. No enrollment/key creation.
    fd, name = tempfile.mkstemp(prefix=".rights-probe-", dir=config.storage_dir)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            restrict_path(temporary)
            stream.write(json.dumps(report, ensure_ascii=True, sort_keys=True).encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        # An administrator's unverified file has a different ACL/owner from the
        # selected service account. Do not make the service replace that file.
        target = "rights-probe.json" if report["identity_verified"] else "rights-probe-unverified.json"
        os.replace(temporary, config.storage_dir / target)
        sync_directory(config.storage_dir)
    finally:
        temporary.unlink(missing_ok=True)


def format_table(report):
    rows = ["Модуль | Проверка | Статус | Результат / Как исправить"]
    for check in report["checks"]:
        rows.append(" | ".join((check["module_id"], check["label"], check["status"],
                                check["text_ru"] + " " + check["remedy_ru"])))
    return "\n".join(rows)


def report_write_failed(report):
    report["ready"] = False
    report["checks"].append(_check("service", "state", "Сохранение локального JSON", True,
        status="denied", reason="report_write_failed"))
