"""Read-only, heuristic audit engine. A baseline, NOT comprehensive SAST/DAST."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from .analysis import docker_sast, python_sast, workflow_sast
from .osv import cve_coverage_contract
from .iac import is_kubernetes_manifest, kubernetes_sast, terraform_sast
from .rust_safety import analyze_rust
from .rust_syn import analyze_rust_syntax
from .supply_chain import inventory, is_manifest
from .windows_native import NATIVE_SUFFIXES, analyze_windows_source

VERSION = "0.4.0-dev"
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 10_000
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "target", "dist", "build", "__pycache__", ".mypy_cache"}
TEXT_EXT = {".rs", ".py", ".toml", ".yml", ".yaml"}
SECRET_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|[A-Za-z0-9_]*password)\s*[:=]\s*[\"']?([^\"'\s]{12,})"
)
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|ENCRYPTED)?\s*PRIVATE KEY-----")
GITHUB_TOKEN_PATTERN = re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}")
USES_PATTERN = re.compile(r"^\s*-\s*uses\s*:\s*([^\s#]+)")
PINNED_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


def _sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def scan(root: Path, *, rust_syntax: str = "heuristic") -> dict[str, Any]:
    """Scan a directory. ``rust_syntax="syn"`` is an explicit opt-in.

    The default remains the token heuristic and does not spawn ``wolf_syn``.
    The syn opt-in still runs that heuristic, then adds a stdin-only syntax
    inventory. It does not expand macros, evaluate ``cfg``, resolve names, or
    read other module files.
    """
    if type(rust_syntax) is not str or rust_syntax not in {"heuristic", "syn"}:
        raise ValueError("rust_syntax must be heuristic or syn")
    use_syn = rust_syntax == "syn"
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("target must be an existing directory")
    findings: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    manifest: list[dict[str, str]] = []
    dependencies: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    scanned = 0
    stopped = False
    syn_backends: list[str] = []

    def walk_error(error: OSError) -> None:
        gaps.append({"path": "<directory>", "reason": type(error).__name__})

    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        for directory_name in dirnames:
            candidate = Path(directory) / directory_name
            if candidate.is_symlink():
                gaps.append({
                    "path": candidate.relative_to(root).as_posix(),
                    "reason": "directory_symlink_not_followed",
                })
        for ignored in sorted(d for d in dirnames if d in SKIP_DIRS):
            excluded.append({"path": (Path(directory) / ignored).relative_to(root).as_posix(),
                             "reason": "excluded_generated_or_repository_metadata"})
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not (Path(directory) / d).is_symlink()
        )
        for name in sorted(filenames):
            file = Path(directory) / name
            relative = file.relative_to(root).as_posix()
            name_lower = file.name.lower()
            if not (
                file.suffix.lower() in TEXT_EXT
                or is_manifest(relative)
                or name_lower == "dockerfile"
                or name_lower.startswith("dockerfile.")
                or name_lower.startswith(".env")
                or file.suffix.lower() in {".tf", ".tfvars"}
                or file.suffix.lower() in NATIVE_SUFFIXES
            ):
                continue
            if file.is_symlink():
                gaps.append({"path": relative, "reason": "symlink_not_followed"})
                continue
            if scanned >= MAX_FILES:
                gaps.append({"path": relative, "reason": "scan_file_budget_exceeded"})
                stopped = True
                break
            try:
                if file.stat().st_size > MAX_FILE_BYTES:
                    gaps.append({"path": relative, "reason": "file_size_limit"})
                    continue
                blob = file.read_bytes()
                if len(blob) > MAX_FILE_BYTES:
                    gaps.append({"path": relative, "reason": "file_size_limit"})
                    continue
                content = blob.decode("utf-8")
            except (OSError, UnicodeError) as error:
                gaps.append({"path": relative, "reason": type(error).__name__})
                continue
            scanned += 1
            manifest.append({"path": relative, "sha256": _sha256(blob)})
            for line_number, line in enumerate(content.splitlines(), 1):
                trimmed = line.lstrip()
                if trimmed.startswith(("//", "#")):
                    continue
                matched_rules: list[tuple[str, str]] = []
                if file.suffix.lower() in {".yaml", ".yml"} and ".github/workflows/" in f"/{relative}":
                    use = USES_PATTERN.search(line)
                    if use and not use.group(1).startswith("./"):
                        action = use.group(1)
                        if "@" not in action or not PINNED_PATTERN.fullmatch(action.rsplit("@", 1)[1]):
                            matched_rules.append(("ACTIONS_REF_NOT_SHA_PINNED", "medium"))
                if SECRET_PATTERN.search(line):
                    matched_rules.append(("POTENTIAL_HARDCODED_SECRET", "high"))
                if PRIVATE_KEY_PATTERN.search(line):
                    matched_rules.append(("PRIVATE_KEY_MATERIAL", "high"))
                if GITHUB_TOKEN_PATTERN.search(line):
                    matched_rules.append(("GITHUB_TOKEN_LIKE_STRING", "high"))
                for rule, severity in matched_rules:
                    # Never expose the matching line or secret value in the report.
                    findings.append({
                        "rule": rule,
                        "severity": severity,
                        "path": relative,
                        "line": line_number,
                        "evidence": "heuristic_match_redacted",
                        "verified_exploit": False,
                    })
            if file.suffix.lower() == ".rs":
                extra, problems = analyze_rust(relative, content)
                findings.extend(extra)
                gaps.extend(problems)
                if use_syn:
                    syntax = analyze_rust_syntax(relative, content)
                    syn_backends.append(str(syntax["backend"]))
                    seen_findings = {(item["path"], item["line"], item["rule"]) for item in findings}
                    for item in syntax["findings"]:
                        key = (item["path"], item["line"], item["rule"])
                        if key not in seen_findings:
                            findings.append(item)
                            seen_findings.add(key)
                    seen_gaps = {(item["path"], item["reason"], item.get("line")) for item in gaps}
                    for item in syntax["gaps"]:
                        key = (item["path"], item["reason"], item.get("line"))
                        if key not in seen_gaps:
                            gaps.append(item)
                            seen_gaps.add(key)
            if file.suffix.lower() in NATIVE_SUFFIXES:
                extra, problems = analyze_windows_source(relative, content)
                findings.extend(extra)
                gaps.extend(problems)
            if file.suffix.lower() == ".py":
                extra, problems = python_sast(relative, content)
                findings.extend(extra)
                gaps.extend(problems)
            if file.suffix.lower() in {".yaml", ".yml"} and "/.github/workflows/" in f"/{relative}":
                findings.extend(workflow_sast(relative, content))
            if name_lower == "dockerfile" or name_lower.startswith("dockerfile."):
                findings.extend(docker_sast(relative, content))
            if file.suffix.lower() in {".tf", ".tfvars"}:
                findings.extend(terraform_sast(relative, content))
            if is_kubernetes_manifest(relative):
                findings.extend(kubernetes_sast(relative, content))
            if is_manifest(relative):
                deps, extra, problems = inventory(relative, content)
                dependencies.extend(deps)
                findings.extend(extra)
                gaps.extend(problems)
        if stopped:
            break

    if use_syn and not syn_backends:
        gaps.append({"path": "<rust>", "reason": "rust_syn_no_rust_sources"})
    findings.sort(key=lambda f: (f["path"], f["line"], f["rule"]))
    gaps.sort(key=lambda g: (g["path"], g.get("line", 0), g["reason"]))
    excluded.sort(key=lambda g: (g["path"], g["reason"]))
    dependencies.sort(key=lambda c: (c["source_file"], c["purl"]))
    evidence = {
        "schema": "wolf-auditor.evidence.v1",
        "version": VERSION,
        "scope": "read_only_explicit_syn_plus_heuristic" if use_syn else "read_only_heuristic_source_scan",
        "target_directory_name": root.name,
        "scanned_files": scanned,
        "file_manifest": manifest,
        "excluded_paths": excluded,
        "dependency_components": dependencies,
        "dependency_inventory_scope": "offline manifests only; no CVE lookup or transitive verification",
        "analysis_limits": {
            "rust_syntax": "token_heuristic_not_a_rust_parser",
            "rust_cfg": "unresolved_not_evaluated",
            "rust_macros": "not_expanded",
            "rust_names": "not_resolved",
            "parser_stage": "token_heuristic",
            "rust_syn_backend": "not_invoked_default_scan_does_not_spawn",
            "windows_native_runtime": "not_executed_read_only_no_process_access",
            "fuzz_on_target": "not_executed_untrusted_target_not_run",
            "coverage_claim": False,
        },
        "cve_coverage": cve_coverage_contract(mode="offline"),
        "findings": findings,
        "coverage_gaps": gaps,
        "status": "INCOMPLETE" if gaps else ("REVIEW_REQUIRED" if findings else "NO_HEURISTIC_FINDINGS"),
        "claim": "No security certification; passing is not proof of absence of vulnerabilities.",
    }
    if use_syn:
        failed = (not syn_backends) or any(item != "syn" for item in syn_backends)
        evidence["analysis_limits"]["rust_syntax"] = "explicit_syn_plus_token_heuristic"
        evidence["analysis_limits"]["parser_stage"] = "explicit_syn_plus_token_heuristic"
        evidence["analysis_limits"]["rust_syn_backend"] = (
            "explicit_request_incomplete" if failed else "invoked_stdin_only_no_macro_expansion"
        )
    canonical = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    evidence["report_sha256"] = _sha256(canonical)
    return evidence
