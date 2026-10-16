"""Standard-format outputs derived from a bounded evidence report; not certification."""
from __future__ import annotations
import hashlib
import json
from typing import Any

def _digest(data: object) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(canonical).hexdigest()

def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """SARIF 2.1.0 for security triage (source text / secret values excluded)."""
    findings = report.get("findings", [])
    rules = sorted(set(f["rule"] for f in findings))
    severity = {"high": "error", "medium": "warning", "review": "note", "low": "note"}
    results = [
        {
            "ruleId": f["rule"],
            "level": severity.get(f["severity"], "note"),
            "message": {"text": "Potential issue flagged for manual review; unverified heuristic."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["path"].replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, int(f["line"]))},
                }
            }],
            "properties": {
                "verified_exploit": False,
                "evidence": "redacted",
                **({"osv_advisory_id": f["advisory_id"]}
                   if f.get("rule") == "OSV_MATCHED_ADVISORY" and f.get("advisory_id") else {}),
            },
        }
        for f in findings
    ]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "WOLF AUDITOR",
                "version": report["version"],
                "informationUri": "https://github.com/alsatplaza-commits/Wolf-Audit",
                "rules": [{"id": rule, "shortDescription": {"text": rule}} for rule in rules],
            }},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
            "artifacts": [
                {
                    "location": {"uri": item["path"].replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                    "hashes": {"sha-256": item["sha256"]},
                }
                for item in sorted(report.get("file_manifest", []), key=lambda item: item["path"])
                if isinstance(item, dict) and isinstance(item.get("path"), str)
                and isinstance(item.get("sha256"), str)
            ],
            "results": results,
            "properties": {
                "audit_status": report["status"],
                "audit_report_sha256": report["report_sha256"],
                "coverage_gaps": report["coverage_gaps"],
                "limitations": "Heuristic triage only. No independent review or certification.",
            },
        }],
    }

def to_sbom(report: dict[str, Any]) -> dict[str, Any]:
    """CycloneDX 1.6 component inventory; NOT CVE analysis or complete transitive SBOM."""
    components = []
    seen: set[str] = set()
    references: dict[tuple[str, str, str, str], str] = {}
    for item in report.get("dependency_components", []):
        ref = _digest([item["purl"], item["source_file"]])[:32]
        if ref in seen:
            continue
        seen.add(ref)
        references[(
            item["source_file"],
            {"cargo": "crates.io", "pypi": "PyPI", "npm": "npm"}.get(
                item["ecosystem"], item["ecosystem"]
            ),
            item["name"], str(item.get("version") or "")
        )] = ref
        obj: dict[str, Any] = {
            "bom-ref": ref,
            "type": "library",
            "name": item["name"],
            "purl": item["purl"],
            "properties": [{"name": "wolf:source_file", "value": item["source_file"]}],
        }
        if item.get("version"):
            obj["version"] = item["version"]
        components.append(obj)
    vulnerabilities = []
    for f in report.get("findings", []):
        if f.get("rule") != "OSV_MATCHED_ADVISORY":
            continue
        package = f.get("package", {})
        key = (
            f["path"], package.get("ecosystem"), package.get("name"), str(package.get("version") or "")
        )
        ref = references.get(key)
        if ref:
            vulnerabilities.append({
                "id": f["advisory_id"],
                "source": {"name": "OSV", "url": f["advisory_url"]},
                "affects": [{"ref": ref}],
                "properties": [
                    {"name": "wolf:exploit_verified", "value": "false"},
                    {"name": "wolf:matching_method", "value": "OSV version-to-package query"},
                ],
            })
    vulnerabilities.sort(key=lambda v: (v["id"], v["affects"][0]["ref"]))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"tools": {"components": [
            {"type": "application", "name": "WOLF AUDITOR", "version": report["version"]}
        ]}},
        "components": components,
        "vulnerabilities": vulnerabilities,
        "properties": [
            {"name": "wolf:coverage", "value": report["status"]},
            {"name": "wolf:evidence_sha256", "value": report["report_sha256"]},
            {"name": "wolf:limitations", "value": "Manifest inventory, not vulnerability analysis or complete transitive SBOM"},
        ],
    }
