"""Offline component inventory from Cargo, npm and pip lock/requirement files.

This is NOT an online CVE scanner or vulnerability determination.
"""
from __future__ import annotations
import json
import re
import tomllib
from typing import Any
from urllib.parse import quote

REQUIREMENTS = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(==|===|~=|!=|<=|>=|<|>)?\s*([^;\s]+)?")
MAX_DEPENDENCIES = 10_000

def is_manifest(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return name in {"cargo.lock", "package-lock.json"} or (name.startswith("requirements") and name.endswith(".txt"))

def _component(ecosystem: str, name: str, version: str | None, path: str) -> dict[str, Any]:
    purl = f"pkg:{ecosystem}/{quote(name.lower(), safe='@/')}"
    if version:
        purl += "@" + quote(str(version), safe="")
    return {"type": "library", "name": name, "version": str(version) if version else None,
            "purl": purl, "source_file": path, "ecosystem": ecosystem}

def _finding(path: str, line: int) -> dict[str, Any]:
    return {"rule": "PYTHON_DEPENDENCY_NOT_EXACTLY_PINNED", "severity": "medium",
            "path": path, "line": line, "evidence": "dependency_inventory_heuristic_redacted",
            "verified_exploit": False}

def inventory(path: str, content: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]]]:
    name = path.rsplit("/", 1)[-1].lower()
    components: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    try:
        if name == "cargo.lock":
            data = tomllib.loads(content)
            packages = data.get("package")
            if not isinstance(packages, list):
                raise ValueError("missing cargo packages")
            for pkg in packages:
                if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str) or not isinstance(pkg.get("version"), str):
                    raise ValueError("invalid cargo package")
                components.append(_component("cargo", pkg["name"], pkg["version"], path))
        elif name == "package-lock.json":
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("invalid npm lock")
            packages = data.get("packages")
            if isinstance(packages, dict):
                for key, pkg in sorted(packages.items()):
                    if not key or not isinstance(pkg, dict) or "node_modules/" not in key:
                        continue
                    dependency_name = pkg.get("name") or key.rsplit("node_modules/", 1)[-1]
                    version = pkg.get("version")
                    if not isinstance(dependency_name, str) or not isinstance(version, str):
                        gaps.append({"path": path, "reason": "npm_package_unresolved"})
                        continue
                    components.append(_component("npm", dependency_name, version, path))
            elif isinstance(data.get("dependencies"), dict):
                def walk(dependencies: dict[str, Any], depth: int = 0) -> None:
                    if depth > 100:
                        raise ValueError("npm nesting bound")
                    for dep_name, pkg in sorted(dependencies.items()):
                        if not isinstance(pkg, dict) or not isinstance(pkg.get("version"), str):
                            gaps.append({"path": path, "reason": "npm_package_unresolved"})
                            continue
                        components.append(_component("npm", dep_name, pkg["version"], path))
                        nested = pkg.get("dependencies", {})
                        if isinstance(nested, dict):
                            walk(nested, depth + 1)
                walk(data["dependencies"])
            else:
                raise ValueError("unsupported npm lock structure")
        elif name.startswith("requirements") and name.endswith(".txt"):
            for line_no, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.startswith(("-", "git+", "http:", "https:")):
                    gaps.append({"path": path, "reason": "requirements_directive_or_url_unresolved"})
                    continue
                match = REQUIREMENTS.match(stripped)
                if not match:
                    gaps.append({"path": path, "reason": "requirements_parse_failed"})
                    continue
                pkg_name, operator, version = match.groups()
                pinned = operator in {"==", "==="} and bool(version) and "*" not in version
                if not pinned:
                    findings.append(_finding(path, line_no))
                components.append(_component("pypi", pkg_name, version if pinned else None, path))
    except (ValueError, TypeError, RecursionError):
        gaps.append({"path": path, "reason": "dependency_manifest_parse_failed"})
        components = []
    if len(components) > MAX_DEPENDENCIES:
        gaps.append({"path": path, "reason": "dependency_inventory_limit"})
        components = components[:MAX_DEPENDENCIES]
    return components, findings, gaps
