"""Bounded Windows Job Object primitive for isolated plugin child processes."""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
from typing import Mapping, Sequence


class WindowsPluginJobError(RuntimeError):
    """The Job Object boundary could not be established fail-closed."""


@dataclass(frozen=True)
class WindowsPluginJobLimits:
    active_processes: int
    process_memory_bytes: int
    kill_on_job_close: bool
    cpu_hard_limit: int | None = None

    def validate(self) -> None:
        if not 1 <= self.active_processes <= 8:
            raise WindowsPluginJobError("job_active_process_limit_invalid")
        if not 16 * 1024 * 1024 <= self.process_memory_bytes <= 4 * 1024**3:
            raise WindowsPluginJobError("job_process_memory_limit_invalid")
        if self.kill_on_job_close is not True:
            raise WindowsPluginJobError("job_kill_on_close_required")
        if self.cpu_hard_limit is not None and not 1 <= self.cpu_hard_limit <= 100:
            raise WindowsPluginJobError("job_cpu_hard_limit_invalid")


class WindowsPluginChild:
    def __init__(self, process_handle, pid: int):
        self._process_handle = process_handle
        self.pid = int(pid)
        self._closed = False

    def wait(self, timeout_ms: int) -> bool:
        import win32event

        if self._closed:
            raise WindowsPluginJobError("child_handle_closed")
        result = win32event.WaitForSingleObject(self._process_handle, int(timeout_ms))
        return result == win32event.WAIT_OBJECT_0

    def exit_code(self) -> int:
        import win32process

        if self._closed:
            raise WindowsPluginJobError("child_handle_closed")
        return int(win32process.GetExitCodeProcess(self._process_handle))

    def cpu_time_seconds(self) -> float:
        import win32process

        if self._closed:
            raise WindowsPluginJobError("child_handle_closed")
        times = win32process.GetProcessTimes(self._process_handle)
        return (
            int(times["KernelTime"]) + int(times["UserTime"])
        ) / 10_000_000.0

    def close(self) -> None:
        if not self._closed:
            self._process_handle.Close()
            self._closed = True


class WindowsPluginJob:
    """Create-before-run Job Object assignment with a minimal child environment."""

    def __init__(self, limits: WindowsPluginJobLimits):
        if os.name != "nt":
            raise WindowsPluginJobError("windows_job_requires_windows")
        limits.validate()
        import win32job

        self._win32job = win32job
        self._job = win32job.CreateJobObject(None, "")
        self._closed = False
        self._children: list[WindowsPluginChild] = []
        try:
            info = win32job.QueryInformationJobObject(
                self._job, win32job.JobObjectExtendedLimitInformation
            )
            basic = info["BasicLimitInformation"]
            basic["LimitFlags"] |= (
                win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | win32job.JOB_OBJECT_LIMIT_PROCESS_MEMORY
            )
            basic["ActiveProcessLimit"] = limits.active_processes
            info["ProcessMemoryLimit"] = limits.process_memory_bytes
            win32job.SetInformationJobObject(
                self._job,
                win32job.JobObjectExtendedLimitInformation,
                info,
            )
            if limits.cpu_hard_limit is not None:
                self._set_cpu_hard_cap(limits.cpu_hard_limit)
        except Exception:
            self._job.Close()
            self._closed = True
            raise

    def _set_cpu_hard_cap(self, percent: int) -> None:
        class CpuRateControlInformation(ctypes.Structure):
            _fields_ = [
                ("ControlFlags", wintypes.DWORD),
                ("CpuRate", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        set_information = kernel32.SetInformationJobObject
        set_information.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        set_information.restype = wintypes.BOOL
        value = CpuRateControlInformation(0x1 | 0x4, int(percent) * 100)
        if not set_information(
            wintypes.HANDLE(int(self._job)),
            15,
            ctypes.byref(value),
            ctypes.sizeof(value),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

    def _query_cpu_hard_cap(self) -> int | None:
        class CpuRateControlInformation(ctypes.Structure):
            _fields_ = [
                ("ControlFlags", wintypes.DWORD),
                ("CpuRate", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        query_information = kernel32.QueryInformationJobObject
        query_information.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        query_information.restype = wintypes.BOOL
        value = CpuRateControlInformation()
        returned = wintypes.DWORD()
        if not query_information(
            wintypes.HANDLE(int(self._job)),
            15,
            ctypes.byref(value),
            ctypes.sizeof(value),
            ctypes.byref(returned),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if value.ControlFlags & 0x1 and value.ControlFlags & 0x4:
            return int(value.CpuRate) // 100
        return None

    @staticmethod
    def _minimal_environment(extra: Mapping[str, str] | None) -> dict[str, str]:
        allowed = ("SystemRoot", "WINDIR", "TEMP", "TMP")
        result = {
            key: os.environ[key]
            for key in allowed
            if key in os.environ and os.environ[key]
        }
        for key, value in dict(extra or {}).items():
            if (
                not isinstance(key, str)
                or not key
                or "=" in key
                or not isinstance(value, str)
            ):
                raise WindowsPluginJobError("child_environment_invalid")
            result[key] = value
        return result

    def start(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str] | None = None,
    ) -> WindowsPluginChild:
        if self._closed:
            raise WindowsPluginJobError("job_closed")
        if (
            not argv
            or any(not isinstance(item, str) or not item for item in argv)
        ):
            raise WindowsPluginJobError("child_argv_invalid")
        clean_cwd = Path(cwd).resolve(strict=True)
        if not clean_cwd.is_dir():
            raise WindowsPluginJobError("child_cwd_invalid")
        import win32api
        import win32con
        import win32process

        command_line = subprocess.list2cmdline(list(argv))
        creation_flags = win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW
        process_handle = thread_handle = None
        try:
            process_handle, thread_handle, pid, _tid = win32process.CreateProcess(
                argv[0],
                command_line,
                None,
                None,
                False,
                creation_flags,
                self._minimal_environment(environment),
                str(clean_cwd),
                win32process.STARTUPINFO(),
            )
            self._win32job.AssignProcessToJobObject(self._job, process_handle)
            win32process.ResumeThread(thread_handle)
            child = WindowsPluginChild(process_handle, pid)
            self._children.append(child)
            process_handle = None
            return child
        except Exception as exc:
            if process_handle is not None:
                try:
                    win32process.TerminateProcess(process_handle, 1)
                except Exception:
                    pass
            raise WindowsPluginJobError("child_job_assignment_failed") from exc
        finally:
            if thread_handle is not None:
                win32api.CloseHandle(thread_handle)
            if process_handle is not None:
                win32api.CloseHandle(process_handle)

    def status(self) -> dict[str, int | bool | None]:
        if self._closed:
            raise WindowsPluginJobError("job_closed")
        info = self._win32job.QueryInformationJobObject(
            self._job, self._win32job.JobObjectExtendedLimitInformation
        )
        process_ids = self._win32job.QueryInformationJobObject(
            self._job, self._win32job.JobObjectBasicProcessIdList
        )
        flags = int(info["BasicLimitInformation"]["LimitFlags"])
        return {
            "active_process_limit": int(
                info["BasicLimitInformation"]["ActiveProcessLimit"]
            ),
            "process_memory_bytes": int(info["ProcessMemoryLimit"]),
            "kill_on_job_close": bool(
                flags & self._win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            ),
            "assigned_process_count": len(process_ids),
            "cpu_hard_limit": self._query_cpu_hard_cap(),
            "peak_process_memory_bytes": int(
                info.get("PeakProcessMemoryUsed") or 0
            ),
            "peak_job_memory_bytes": int(info.get("PeakJobMemoryUsed") or 0),
        }

    def close_job(self) -> None:
        if not self._closed:
            self._job.Close()
            self._closed = True

    def close_child_handles(self) -> None:
        for child in self._children:
            child.close()
        self._children.clear()

    def close(self) -> None:
        self.close_job()
        self.close_child_handles()

    def __enter__(self) -> "WindowsPluginJob":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()
