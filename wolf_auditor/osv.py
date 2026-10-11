"""Opt-in OSV vulnerability intelligence for locked dependency versions.

No external requests occur unless explicitly requested. This never proves an
exploit, and a failed or partial response never becomes a clean result.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import quote

OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 100
MAX_QUERIES = 2000
MAX_RESPONSE_BYTES = 4_000_000
ECOSYSTEMS = {"cargo": "crates.io", "npm": "npm", "pypi": "PyPI"}
IDENTIFIER = re.compile(r"^[A-Za-z0-9._-]{3,128}$")
Fetch = Callable[[list[dict[str, Any]]], dict[str, Any]]


def _http_query(queries: list[dict[str, Any]]) -> dict[str, Any]:
    body = json.dumps({"queries": queries}, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        OSV_ENDPOINT, body,
        headers={"Content-Type": "application/json", "User-Agent": "wolf-auditor/0.3"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=12) as response:
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValueError("OSV response exceeds size limit")
    result = json.loads(payload)
    if not isinstance(result, dict):
        raise ValueError("OSV response must be an object")
    return result


def _status(report: dict[str, Any]) -> str:
    if report.get("coverage_gaps"):
        return "INCOMPLETE"
    if report.get("findings"):
        return "REVIEW_REQUIRED"
    return "NO_HEURISTIC_FINDINGS"


def _seal(report: dict[str, Any]) -> dict[str, Any]:
    without_hash = {k: v for k, v in report.items() if k != "report_sha256"}
    canonical = json.dumps(without_hash, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return report


def enrich_with_osv(report: dict[str, Any], *, fetcher: Fetch | None = None) -> dict[str, Any]:
    """Return a separately hashed report; the original report is never modified.

    The caller must have explicit authorization to disclose package names and
    exact versions to OSV, including transitive/private package identifiers.
    """
    enriched = copy.deepcopy(report)
    checks = enriched.setdefault("external_checks", {})
    problems = enriched.setdefault("coverage_gaps", [])
    findings = enriched.setdefault("findings", [])
    unique: dict[tuple[str, str, str], list[str]] = {}
    for component in enriched.get("dependency_components", []):
        ecosystem = ECOSYSTEMS.get(component.get("ecosystem"))
        version = component.get("version")
        name = component.get("name")
        path = component.get("source_file")
        if not ecosystem:
            problems.append({"path": str(path), "reason": "osv_unsupported_ecosystem"})
            continue
        if not isinstance(name, str) or not name or len(name) > 300:
            problems.append({"path": str(path), "reason": "osv_invalid_package_name"})
            continue
        if not isinstance(version, str) or not version or len(version) > 150:
            problems.append({"path": str(path), "reason": "osv_version_unresolved"})
            continue
        key = (ecosystem, name, version)
        unique.setdefault(key, []).append(str(path))

    checked = 0
    failed = False
    keys = sorted(unique)
    if len(keys) > MAX_QUERIES:
        problems.append({"path": "<dependency-inventory>", "reason": "osv_query_budget_exceeded"})
        keys = keys[:MAX_QUERIES]
        failed = True
    fetch = fetcher or _http_query
    for offset in range(0, len(keys), BATCH_SIZE):
        batch = keys[offset:offset + BATCH_SIZE]
        queries = [
            {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
            for ecosystem, name, version in batch
        ]
        try:
            data = fetch(queries)
            if not isinstance(data, dict):
                raise ValueError("OSV provider returned a non-object")
            results = data.get("results")
            if not isinstance(results, list) or len(results) != len(batch):
                raise ValueError("OSV response/query count mismatch")
            candidate_findings: list[dict[str, Any]] = []
            for (ecosystem, name, version), item in zip(batch, results):
                if not isinstance(item, dict) or not isinstance(item.get("vulns", []), list):
                    raise ValueError("OSV result missing vulnerability array")
                for vuln in item.get("vulns", []):
                    if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
                        raise ValueError("OSV vulnerability lacks an id")
                    advisory = vuln["id"]
                    if not IDENTIFIER.fullmatch(advisory):
                        raise ValueError("invalid OSV advisory identifier")
                    for path in sorted(set(unique[(ecosystem, name, version)])):
                        candidate_findings.append({
                            "rule": "OSV_MATCHED_ADVISORY",
                            "severity": "review",
                            "path": path,
                            "line": 1,
                            "evidence": "OSV version-to-package match; unverified exploitability",
                            "advisory_id": advisory,
                            "advisory_url": "https://osv.dev/vulnerability/" + quote(advisory, safe=""),
                            "package": {"ecosystem": ecosystem, "name": name, "version": version},
                            "verified_exploit": False,
                        })
            findings.extend(candidate_findings)
            checked += len(batch)
        except (ValueError, TypeError, KeyError, OSError, urllib.error.URLError, json.JSONDecodeError):
            problems.append({"path": "<dependency-inventory>", "reason": "osv_request_or_schema_failed"})
            failed = True

    problems.sort(key=lambda row: (row["path"], row["reason"]))
    findings.sort(key=lambda row: (row["path"], row["line"], row["rule"], row.get("advisory_id", "")))
    all_done = not failed and not any(g["reason"].startswith("osv_") for g in problems)
    state = "COMPLETE" if all_done and checked else ("NO_DEPENDENCIES" if all_done else "INCOMPLETE")
    checks["osv"] = {
        "state": state, "queried_versions": checked,
        "provider": "OSV querybatch", "network_disclosure": "package names and exact versions",
        "fetched_utc": None, "disclaimer": "OSV match is not an exploit proof or complete security guarantee",
    }
    enriched["status"] = _status(enriched)
    return _seal(enriched)
