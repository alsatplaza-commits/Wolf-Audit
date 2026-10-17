"""Opt-in, read-only Windows process query.

The default scan does not call this module. ``enabled`` must be the boolean
True. The only access right requested is PROCESS_QUERY_LIMITED_INFORMATION.
Memory is not read, dumps are not written, and the result is never PASS,
REVIEWED, or APPROVED.
"""
from __future__ import annotations

import sys
from typing import Any, Protocol

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_STILL_ACTIVE = 259
_ERROR_ACCESS_DENIED = 5
_ERROR_INVALID_PARAMETER = 87
_FORBIDDEN_STATUS = {"PASS", "REVIEWED", "APPROVED"}
_LIMITATION = (
    "Exit state only. Memory contents, command line, environment, and image path are not collected."
)


class _ProcessQuery(Protocol):
    def open_process(self, rights: int, pid: int) -> int: ...

    def exit_code(self, handle: int) -> tuple[bool, int]: ...

    def close(self, handle: int) -> None: ...

    def last_error(self) -> int: ...


def inspect_process(pid: object = None, *, enabled: object = False) -> dict[str, Any]:
    """Query one process identity, or refuse.

    A disabled or non-Windows call does not open a process. The returned
    object has no memory, dump, command line, environment, or image path.
    """
    if enabled is not True:
        return _result("NOT_EXECUTED", "sensor_disabled", False, None)
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 or pid > 0xFFFFFFFF:
        return _result("INCOMPLETE", "invalid_pid", False, None)
    if sys.platform != "win32":
        return _result("NOT_EXECUTED", "windows_sensor_unsupported_platform", False, None)
    return _query_windows(pid, _Win32())


def _query_windows(pid: int, api: _ProcessQuery) -> dict[str, Any]:
    handle = api.open_process(PROCESS_QUERY_LIMITED_INFORMATION, pid)
    if not handle:
        code = api.last_error()
        if code == _ERROR_ACCESS_DENIED:
            return _result("NOT_EXECUTED", "access_denied", False, None)
        if code == _ERROR_INVALID_PARAMETER:
            return _result("NOT_EXECUTED", "process_not_found", False, None)
        return _result("INCOMPLETE", "open_process_failed", False, None)
    try:
        ok, code = api.exit_code(handle)
    finally:
        api.close(handle)
    if not ok:
        return _result("INCOMPLETE", "process_exit_race", True, None)
    state = "running" if code == _STILL_ACTIVE else "exited"
    return _result("QUERY_LIMITED", "query_limited_information", True, state)


def _result(status: str, reason: str, process_access: bool, state: str | None) -> dict[str, Any]:
    if status in _FORBIDDEN_STATUS:
        status = "INCOMPLETE"
        reason = "false_pass_rejected"
    row: dict[str, Any] = {
        "status": status,
        "coverage_claim": False,
        "process_access": process_access,
        "memory_read": False,
        "dump_collected": False,
        "access_rights": ["PROCESS_QUERY_LIMITED_INFORMATION"] if process_access else [],
        "reason": reason,
        "host_platform": sys.platform,
        "limitation": _LIMITATION,
    }
    if state is not None:
        row["process_state"] = state
    if row["coverage_claim"] or row["status"] in _FORBIDDEN_STATUS:
        row["status"] = "INCOMPLETE"
        row["reason"] = "false_pass_rejected"
        row["coverage_claim"] = False
    return row


class _Win32:
    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        self._kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self._kernel.OpenProcess.restype = wintypes.HANDLE
        self._kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self._kernel.GetExitCodeProcess.restype = wintypes.BOOL
        self._kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel.CloseHandle.restype = wintypes.BOOL
        self._dword = wintypes.DWORD

    def open_process(self, rights: int, pid: int) -> int:
        if rights != PROCESS_QUERY_LIMITED_INFORMATION:
            return 0
        return int(self._kernel.OpenProcess(rights, False, pid) or 0)

    def exit_code(self, handle: int) -> tuple[bool, int]:
        code = self._dword()
        ok = bool(self._kernel.GetExitCodeProcess(handle, self._ctypes.byref(code)))
        return ok, int(code.value)

    def close(self, handle: int) -> None:
        self._kernel.CloseHandle(handle)

    def last_error(self) -> int:
        return int(self._ctypes.get_last_error())
