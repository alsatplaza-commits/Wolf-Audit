"""Read-only Windows native and FFI source inventory.

API names are classified from source text. This module does not open processes,
allocate remote memory, or load libraries. A host that did not perform that
runtime inspection is never reported as PASS.
"""
from __future__ import annotations

import sys
from typing import Any

from .analysis import finding

NATIVE_SUFFIXES = {".c", ".h", ".hh", ".hpp", ".hxx", ".cpp", ".cc", ".cxx", ".idl"}

_RULES: dict[str, tuple[str, str]] = {
    "WriteProcessMemory": ("WIN_PROCESS_MEMORY", "high"),
    "ReadProcessMemory": ("WIN_PROCESS_MEMORY", "high"),
    "NtWriteVirtualMemory": ("WIN_PROCESS_MEMORY", "high"),
    "NtReadVirtualMemory": ("WIN_PROCESS_MEMORY", "high"),
    "VirtualAllocEx": ("WIN_PROCESS_MEMORY", "high"),
    "VirtualProtectEx": ("WIN_PROCESS_MEMORY", "high"),
    "CreateRemoteThread": ("WIN_PROCESS_MEMORY", "high"),
    "CreateRemoteThreadEx": ("WIN_PROCESS_MEMORY", "high"),
    "QueueUserAPC": ("WIN_PROCESS_MEMORY", "high"),
    "OpenProcess": ("WIN_PROCESS_MEMORY", "high"),
    "MapViewOfFile": ("WIN_PROCESS_MEMORY", "medium"),
    "VirtualAlloc": ("WIN_PROCESS_MEMORY", "medium"),
    "VirtualProtect": ("WIN_PROCESS_MEMORY", "medium"),
    "AdjustTokenPrivileges": ("WIN_PRIVILEGE_OPERATION", "medium"),
    "OpenProcessToken": ("WIN_PRIVILEGE_OPERATION", "medium"),
    "ImpersonateLoggedOnUser": ("WIN_PRIVILEGE_OPERATION", "medium"),
    "LookupPrivilegeValue": ("WIN_PRIVILEGE_OPERATION", "medium"),
    "LookupPrivilegeValueA": ("WIN_PRIVILEGE_OPERATION", "medium"),
    "LookupPrivilegeValueW": ("WIN_PRIVILEGE_OPERATION", "medium"),
    "LoadLibraryA": ("WIN_FFI_DYNAMIC_LOAD", "review"),
    "LoadLibraryW": ("WIN_FFI_DYNAMIC_LOAD", "review"),
    "LoadLibraryExA": ("WIN_FFI_DYNAMIC_LOAD", "review"),
    "LoadLibraryExW": ("WIN_FFI_DYNAMIC_LOAD", "review"),
    "GetProcAddress": ("WIN_FFI_DYNAMIC_LOAD", "review"),
}


def runtime_inspection() -> dict[str, Any]:
    """Report that live process inspection was not performed.

    The result is the same on Linux and Windows: this prototype does not
    attach to processes. ``status`` is never PASS.
    """
    return {
        "status": "NOT_EXECUTED",
        "coverage_claim": False,
        "process_access": False,
        "reason": "windows_native_runtime_not_executed",
        "host_platform": sys.platform,
        "limitation": "Static name inventory only. No process, memory, or loader call is made.",
    }


def analyze_windows_source(path: str, content: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    gaps = [{"path": path, "reason": "windows_native_runtime_not_executed"}]
    names, scan_gaps = _identifiers(content)
    gaps.extend({"path": path, "reason": reason} for reason in scan_gaps)
    for line, name in names:
        classified = _RULES.get(name)
        if classified is None:
            continue
        rule, severity = classified
        key = (rule, line)
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding(rule, severity, path, line))
    findings.sort(key=lambda item: (item["line"], item["rule"]))
    probe = runtime_inspection()
    if probe["status"] == "PASS" or probe["coverage_claim"]:
        gaps.append({"path": path, "reason": "windows_native_false_pass_rejected"})
    return findings, gaps


def _identifiers(content: str) -> tuple[list[tuple[int, str]], list[str]]:
    found: list[tuple[int, str]] = []
    gaps: list[str] = []
    chars = content
    limit = len(chars)
    index = 0
    line = 1
    while index < limit:
        ch = chars[index]
        if ch == "\n":
            line += 1
            index += 1
            continue
        if ch == "\r":
            index += 1
            continue
        if chars.startswith("//", index):
            index += 2
            while index < limit and chars[index] not in "\n\r":
                index += 1
            continue
        if chars.startswith("/*", index):
            end = chars.find("*/", index + 2)
            if end < 0:
                gaps.append("windows_native_unclosed_comment")
                break
            line += chars.count("\n", index, end + 2)
            index = end + 2
            continue
        if ch == '"':
            index += 1
            while index < limit and chars[index] not in "\n\r":
                if chars[index] == "\\":
                    index += 2
                    continue
                if chars[index] == '"':
                    index += 1
                    break
                index += 1
            continue
        if ch.isalpha() or ch == "_":
            start = index
            index += 1
            while index < limit and (chars[index].isalnum() or chars[index] == "_"):
                index += 1
            found.append((line, chars[start:index]))
            continue
        index += 1
    return found, gaps
