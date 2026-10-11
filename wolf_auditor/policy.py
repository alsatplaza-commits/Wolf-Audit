"""Deterministic fail-closed release gate. Not independent human attestation."""
from __future__ import annotations

import hashlib
import json
from typing import Any

LEVELS = {"critical": 5, "high": 4, "medium": 3, "low": 2, "review": 1}
ALLOWED_KEYS = {"schema", "block_at_or_above", "require_osv", "max_findings"}

def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Forbid unknown settings rather than silently accepting typo-based bypasses."""
    if not isinstance(policy, dict) or set(policy) - ALLOWED_KEYS:
        raise ValueError("unknown security policy keys")
    if policy.get("schema") != "wolf-auditor.policy.v1":
        raise ValueError("unsupported security policy schema")
    threshold = policy.get("block_at_or_above", "high")
    if threshold not in LEVELS:
        raise ValueError("unsupported security policy threshold")
    require_osv = policy.get("require_osv", False)
    if not isinstance(require_osv, bool):
        raise ValueError("require_osv must be boolean")
    max_findings = policy.get("max_findings")
    if max_findings is not None and (type(max_findings) is not int or not 0 <= max_findings <= 100000):
        raise ValueError("max_findings must be nonnegative integer")
    return {"schema": "wolf-auditor.policy.v1", "block_at_or_above": threshold,
            "require_osv": require_osv, "max_findings": max_findings}


def evaluate(report: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    policy = validate_policy(policy)
    failures: list[str] = []
    findings = report.get("findings")
    gaps = report.get("coverage_gaps")
    if not isinstance(findings, list) or not isinstance(gaps, list):
        raise ValueError("invalid audit evidence format")
    if gaps or report.get("status") == "INCOMPLETE":
        failures.append("INCOMPLETE_COVERAGE")
    if report.get("status") not in {"NO_HEURISTIC_FINDINGS", "REVIEW_REQUIRED", "INCOMPLETE"}:
        failures.append("UNRECOGNIZED_AUDIT_STATUS")
    threshold = LEVELS[policy["block_at_or_above"]]
    blocked = 0
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("severity") not in LEVELS:
            failures.append("INVALID_FINDING_SEVERITY")
            continue
        if LEVELS[finding["severity"]] >= threshold:
            blocked += 1
    if blocked:
        failures.append("SEVERITY_THRESHOLD_EXCEEDED")
    maximum = policy["max_findings"]
    if maximum is not None and len(findings) > maximum:
        failures.append("FINDING_COUNT_EXCEEDED")
    if policy["require_osv"] and report.get("external_checks", {}).get("osv", {}).get("state") != "COMPLETE":
        failures.append("OSV_EVIDENCE_NOT_COMPLETE")
    verdict = {
        "schema": "wolf-auditor.gate.v1",
        "status": "BLOCK" if failures else "PASS",
        "reasons": sorted(set(failures)),
        "threshold": policy["block_at_or_above"],
        "total_findings": len(findings),
        "threshold_findings": blocked,
        "coverage_gaps": len(gaps),
        "report_sha256": report.get("report_sha256"),
        "disclaimer": "Automated policy gate only; NOT independent expert approval.",
    }
    digest = json.dumps(verdict, sort_keys=True, separators=(",", ":")).encode()
    verdict["verdict_sha256"] = hashlib.sha256(digest).hexdigest()
    return verdict
