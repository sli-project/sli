"""Bounded native PowerShell acquisition; credentials are injected locally."""
from __future__ import annotations

import ctypes
import os
import subprocess
import time
from ctypes import wintypes
from pathlib import Path


def _source_environment() -> dict[str, str]:
    # Let Windows PowerShell build its own module path. A PS7 parent's path can
    # shadow PS5 built-ins and omit installed Windows/RSAT modules.
    return {key: os.environ[key] for key in (
        "SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "PATHEXT",
        "USERPROFILE", "LOCALAPPDATA", "APPDATA", "SystemDrive", "ComSpec",
    ) if os.environ.get(key)}


class _StartupInfo(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        *[(name, wintypes.DWORD) for name in ("dwX", "dwY", "dwXSize", "dwYSize",
          "dwXCountChars", "dwYCountChars", "dwFillAttribute", "dwFlags")],
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)), ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]


class _ProcessInfo(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


def _run_netonly(command: list[str], *, login: tuple, cwd: Path,
                 timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    """Create suspended, assign kill-on-close job, then resume and drain pipes.

    STARTF_USESTDHANDLES requires real inheritable standard handles; handles are
    kept alive through creation and closed on every exit path. The password is
    supplied only to the Win32 API, never to the child command/environment.
    """
    if os.name != "nt" or not command or not 0 < timeout_seconds <= 3600:
        raise RuntimeError("ad_source_process_command_invalid")
    executable = Path(command[0])
    if not executable.is_absolute() or executable.name.lower() != "powershell.exe":
        raise RuntimeError("ad_source_process_command_invalid")
    command_line = subprocess.list2cmdline(command)
    if len(command_line.encode("utf-16le")) // 2 >= 1024:
        raise RuntimeError("ad_source_process_command_too_long")
    import msvcrt

    import win32api
    import win32event
    import win32job
    import win32pipe
    import win32process

    create = ctypes.WinDLL("advapi32", use_last_error=True).CreateProcessWithLogonW
    create.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
        ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(_StartupInfo), ctypes.POINTER(_ProcessInfo)]
    create.restype = wintypes.BOOL
    process = _ProcessInfo()
    job = None
    assigned = False
    descriptors: list[int] = []
    password = ctypes.create_unicode_buffer(login[3])
    deadline = time.monotonic() + timeout_seconds
    outputs = [bytearray(), bytearray()]
    try:
        pairs = []
        for _ in range(2):
            pair = os.pipe()
            pairs.append(pair)
            descriptors.extend(pair)
        null, input_writer = os.pipe()
        descriptors.extend((null, input_writer))
        for fd in (null, pairs[0][1], pairs[1][1]):
            os.set_handle_inheritable(msvcrt.get_osfhandle(fd), True)
        startup = _StartupInfo()
        startup.cb = ctypes.sizeof(startup)
        startup.dwFlags = 0x100 | 0x1  # USESTDHANDLES, USESHOWWINDOW
        startup.wShowWindow = 0
        startup.hStdInput = msvcrt.get_osfhandle(null)
        startup.hStdOutput = msvcrt.get_osfhandle(pairs[0][1])
        startup.hStdError = msvcrt.get_osfhandle(pairs[1][1])
        environment = ctypes.create_unicode_buffer("\0".join(
            f"{key}={value}" for key, value in sorted(_source_environment().items())) + "\0\0")
        job = win32job.CreateJobObject(None, "")
        limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        limits["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
        if not create(login[1], login[2], password, 2, str(executable),
                      ctypes.create_unicode_buffer(command_line), 0x4 | 0x400 | 0x08000000,
                      environment, str(cwd), ctypes.byref(startup), ctypes.byref(process)):
            raise ctypes.WinError(ctypes.get_last_error())
        win32job.AssignProcessToJobObject(job, process.hProcess)
        assigned = True
        win32process.ResumeThread(process.hThread)
        for fd in (null, input_writer, pairs[0][1], pairs[1][1]):
            os.close(fd)
            descriptors.remove(fd)
        while True:
            exited = win32event.WaitForSingleObject(process.hProcess, 0) == win32event.WAIT_OBJECT_0
            if exited:
                win32job.TerminateJobObject(job, 1)
            pending = False
            for index, (reader, _) in enumerate(pairs):
                try:
                    _, available, _ = win32pipe.PeekNamedPipe(msvcrt.get_osfhandle(reader), 0)
                except Exception as exc:
                    if getattr(exc, "winerror", exc.args[0]) == 109:
                        continue
                    raise
                if available:
                    pending = True
                    chunk = os.read(reader, min(available, 65536))
                    outputs[index].extend(chunk)
                    if len(outputs[index]) > 1024 * 1024:
                        raise RuntimeError("ad_source_process_output_limit")
            if exited and not pending:
                return subprocess.CompletedProcess(command, win32process.GetExitCodeProcess(process.hProcess),
                    outputs[0].decode("utf-8", errors="replace"), outputs[1].decode("utf-8", errors="replace"))
            if time.monotonic() >= deadline:
                raise RuntimeError("ad_source_process_timeout")
            time.sleep(0.02)
    finally:
        ctypes.memset(ctypes.addressof(password), 0, ctypes.sizeof(password))
        try:
            if process.hProcess:
                if assigned:
                    win32job.TerminateJobObject(job, 1)
                elif win32event.WaitForSingleObject(process.hProcess, 0) != win32event.WAIT_OBJECT_0:
                    win32process.TerminateProcess(process.hProcess, 1)
                win32event.WaitForSingleObject(process.hProcess, 5000)
        finally:
            if job is not None:
                job.Close()
            for handle in (process.hThread, process.hProcess):
                if handle:
                    win32api.CloseHandle(handle)
            for fd in descriptors:
                os.close(fd)
