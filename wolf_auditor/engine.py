"""Read-only, heuristic audit engine. A baseline, NOT comprehensive SAST/DAST."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .analysis import docker_sast, python_sast, workflow_sast
from .authorization import (
    FileTooLarge,
    OutsideHardlink,
    RejectedSymlink,
    assess_commit_claim,
    confine_target,
    inode_name_counts,
    is_unfollowed_link,
    read_regular_file,
)
from .iac import is_kubernetes_manifest, kubernetes_sast, terraform_sast
from .supply_chain import inventory, is_manifest

VERSION = "0.3.0-dev"
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 10_000
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "target", "dist", "build", "__pycache__", ".mypy_cache"}
TEXT_EXT = {".rs", ".py", ".toml", ".yml", ".yaml"}
UNSAFE_PATTERN = re.compile(r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b|extern\b)")
SECRET_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|[A-Za-z0-9_]*password)\s*[:=]\s*[\"']?([^\"'\s]{12,})"
)
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|ENCRYPTED)?\s*PRIVATE KEY-----")
GITHUB_TOKEN_PATTERN = re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}")
USES_PATTERN = re.compile(r"^\s*-\s*uses\s*:\s*([^\s#]+)")
PINNED_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


def _sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def scan(
    root: Path,
    *,
    customer_id: str | None = None,
    authorized_root: Path | None = None,
    commit_claim: str | None = None,
) -> dict[str, Any]:
    root, _boundary, scope = confine_target(root, authorized_root, customer_id)
    inside_links = inode_name_counts(root)
    findings: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    manifest: list[dict[str, str]] = []
    dependencies: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    scanned = 0
    stopped = False

    def walk_error(error: OSError) -> None:
        gaps.append({"path": "<directory>", "reason": type(error).__name__})

    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        for directory_name in dirnames:
            candidate = Path(directory) / directory_name
            if is_unfollowed_link(candidate):
                relative_dir = candidate.relative_to(root).as_posix()
                gaps.append({
                    "path": relative_dir,
                    "reason": "directory_symlink_not_followed",
                })
                gaps.append({
                    "path": relative_dir,
                    "reason": "symlink_target_rejected",
                })
        for ignored in sorted(d for d in dirnames if d in SKIP_DIRS):
            excluded.append({"path": (Path(directory) / ignored).relative_to(root).as_posix(),
                             "reason": "excluded_generated_or_repository_metadata"})
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not is_unfollowed_link(Path(directory) / d)
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
            ):
                continue
            if is_unfollowed_link(file):
                gaps.append({"path": relative, "reason": "symlink_not_followed"})
                gaps.append({"path": relative, "reason": "symlink_target_rejected"})
                continue
            try:
                file_info = file.lstat()
            except OSError as error:
                gaps.append({"path": relative, "reason": type(error).__name__})
                continue
            inside = inside_links.get((file_info.st_dev, file_info.st_ino), 0)
            if stat.S_ISREG(file_info.st_mode) and file_info.st_nlink > 1 and (
                file_info.st_ino == 0 or file_info.st_nlink > inside
            ):
                gaps.append({"path": relative, "reason": "hardlink_outside_root_rejected"})
                continue
            if scanned >= MAX_FILES:
                gaps.append({"path": relative, "reason": "scan_file_budget_exceeded"})
                stopped = True
                break
            try:
                blob = read_regular_file(file, MAX_FILE_BYTES, max_nlink=inside or None)
                content = blob.decode("utf-8")
            except FileTooLarge:
                gaps.append({"path": relative, "reason": "file_size_limit"})
                continue
            except OutsideHardlink:
                gaps.append({"path": relative, "reason": "hardlink_outside_root_rejected"})
                continue
            except RejectedSymlink:
                gaps.append({"path": relative, "reason": "symlink_not_followed"})
                gaps.append({"path": relative, "reason": "symlink_target_rejected"})
                continue
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
                if file.suffix.lower() == ".rs" and UNSAFE_PATTERN.search(line):
                    matched_rules.append(("RUST_UNSAFE_INVENTORY", "review"))
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

    commit_record, commit_rejected = assess_commit_claim(root, commit_claim)
    if commit_rejected:
        gaps.append({"path": "<commit>", "reason": "unverified_commit_claim_rejected"})

    findings.sort(key=lambda f: (f["path"], f["line"], f["rule"]))
    gaps.sort(key=lambda g: (g["path"], g["reason"]))
    excluded.sort(key=lambda g: (g["path"], g["reason"]))
    dependencies.sort(key=lambda c: (c["source_file"], c["purl"]))
    evidence = {
        "schema": "wolf-auditor.evidence.v1",
        "version": VERSION,
        "scope": "read_only_heuristic_source_scan",
        "customer_scope": scope,
        "commit_claim": commit_record,
        "target_directory_name": root.name,
        "scanned_files": scanned,
        "file_manifest": manifest,
        "excluded_paths": excluded,
        "dependency_components": dependencies,
        "dependency_inventory_scope": "offline manifests only; no CVE lookup or transitive verification",
        "findings": findings,
        "coverage_gaps": gaps,
        "status": "INCOMPLETE" if gaps else ("REVIEW_REQUIRED" if findings else "NO_HEURISTIC_FINDINGS"),
        "claim": "No security certification; passing is not proof of absence of vulnerabilities.",
    }
    canonical = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    evidence["report_sha256"] = _sha256(canonical)
    return evidence
