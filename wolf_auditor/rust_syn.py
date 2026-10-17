"""Explicit syn syntax inventory.

The default repository scan does not call this module. A caller that does
invokes only the trusted ``wolf_syn`` binary and sends source on stdin. The
binary parses with syn. It does not expand macros, evaluate ``cfg``, resolve
names, read other files, or run the scanned repository.

A missing backend, a rejected executable, or an unusable result is a coverage
gap. ``coverage_claim`` is always false.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .analysis import finding

_MAX_INPUT = 1_000_000
_MAX_OUTPUT = 65_536
_MAX_TIMEOUT = 5.0
_ALLOWED_RULES = {"RUST_UNSAFE_INVENTORY", "RUST_FFI_BOUNDARY", "RUST_FFI_SYMBOL"}
_ALLOWED_GAPS = {
    "rust_cfg_unresolved",
    "rust_macro_not_expanded",
    "rust_name_resolution_unresolved",
    "rust_module_file_not_read",
    "rust_proc_macro_not_executed",
    "rust_attribute_body_unclassified",
    "rust_static_mut_not_inventoried",
    "rust_raw_pointer_not_inventoried",
    "rust_syn_parse_failed",
    "rust_syn_input_limit",
}
_FALSE_CLAIMS = ("coverage_claim", "macros_expanded", "cfg_evaluated", "names_resolved")


def analyze_rust_syntax(
    path: str,
    content: str,
    *,
    timeout_seconds: float = 2.0,
) -> dict[str, Any]:
    """Parse one Rust source buffer with the syn backend, or refuse."""
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        return _closed(path, "rust_syn_backend_unavailable")
    if not 0 < float(timeout_seconds) <= _MAX_TIMEOUT:
        return _closed(path, "rust_syn_backend_unavailable")
    if not isinstance(content, str):
        return _closed(path, "rust_syn_parse_failed")
    try:
        payload = content.encode("utf-8")
    except UnicodeError:
        return _closed(path, "rust_syn_parse_failed")
    if len(payload) > _MAX_INPUT:
        return _closed(path, "rust_syn_input_limit")
    executable = _backend_path()
    if executable is None:
        return _closed(path, "rust_syn_backend_unavailable")
    try:
        workspace = Path(tempfile.mkdtemp(prefix="wolf-syn-"))
    except OSError:
        return _closed(path, "rust_syn_backend_failed")
    try:
        try:
            completed = subprocess.run(
                [os.fspath(executable)],
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=float(timeout_seconds),
                check=False,
                cwd=workspace,
                env=_child_env(),
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return _closed(path, "rust_syn_timeout")
        except OSError:
            return _closed(path, "rust_syn_backend_failed")
        if completed.returncode != 0 or len(completed.stdout) > _MAX_OUTPUT:
            return _closed(path, "rust_syn_backend_failed")
        return _accept(path, completed.stdout)
    finally:
        try:
            workspace.rmdir()
        except OSError:
            pass


def _accept(path: str, stdout: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return _closed(path, "rust_syn_backend_failed")
    if not isinstance(parsed, dict):
        return _closed(path, "rust_syn_backend_failed")
    if any(parsed.get(key) is not False for key in _FALSE_CLAIMS):
        return _closed(path, "rust_syn_false_claim")
    raw_findings = parsed.get("findings")
    raw_gaps = parsed.get("gaps")
    if not isinstance(raw_findings, list) or not isinstance(raw_gaps, list):
        return _closed(path, "rust_syn_backend_failed")
    findings: list[dict[str, Any]] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            return _closed(path, "rust_syn_backend_failed")
        rule = item.get("rule")
        line = item.get("line")
        if rule not in _ALLOWED_RULES or isinstance(line, bool) or not isinstance(line, int) or line < 1:
            return _closed(path, "rust_syn_backend_failed")
        findings.append(finding(rule, "review", path, line))
    gaps: list[dict[str, Any]] = []
    for item in raw_gaps:
        if not isinstance(item, dict):
            return _closed(path, "rust_syn_backend_failed")
        reason = item.get("reason")
        if reason not in _ALLOWED_GAPS:
            return _closed(path, "rust_syn_backend_failed")
        row: dict[str, Any] = {"path": path, "reason": reason}
        if "line" in item:
            line = item.get("line")
            if isinstance(line, bool) or not isinstance(line, int) or line < 1:
                return _closed(path, "rust_syn_backend_failed")
            row["line"] = line
        if row not in gaps:
            gaps.append(row)
    findings.sort(key=lambda item: (item["line"], item["rule"]))
    gaps.sort(key=lambda item: (item["path"], item["reason"], item.get("line", 0)))
    return _result(findings, gaps, "syn")


def _closed(path: str, reason: str) -> dict[str, Any]:
    return _result([], [{"path": path, "reason": reason}], "unavailable")


def _result(findings: list[dict[str, Any]], gaps: list[dict[str, Any]], backend: str) -> dict[str, Any]:
    return {
        "backend": backend,
        "coverage_claim": False,
        "macros_expanded": False,
        "cfg_evaluated": False,
        "names_resolved": False,
        "findings": findings,
        "gaps": gaps,
    }


def _child_env() -> dict[str, str]:
    env = {"PATH": os.defpath}
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR"):
            value = os.environ.get(key)
            if value:
                env[key] = value
    return env


def _backend_path() -> Path | None:
    override = os.environ.get("WOLF_SYN_BIN")
    if override:
        return _safe_executable(Path(override))
    root = Path(__file__).resolve().parents[1] / "tools" / "wolf_syn" / "target"
    names = ("wolf_syn.exe", "wolf_syn") if os.name == "nt" else ("wolf_syn",)
    for folder in ("debug", "release"):
        for name in names:
            found = _safe_executable(root / folder / name)
            if found is not None:
                return found
    return None


def _safe_executable(candidate: Path) -> Path | None:
    if not candidate.is_absolute() or any(part == ".." for part in candidate.parts):
        return None
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            return None
        if not cursor.exists():
            return None
    if not cursor.is_file() or cursor.stat().st_size > 50_000_000:
        return None
    return cursor
