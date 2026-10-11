"""Compare two deterministic audit reports without disclosing source excerpts.

The SHA256 report hash detects accidental alteration, not adversarial
authenticity. Signed attestations require a separate trusted signing service.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

def _hash(data: Any) -> str:
    return hashlib.sha256(json.dumps(
        data, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")).hexdigest()

def verify_report(report: dict[str, Any]) -> bool:
    if not isinstance(report, dict) or report.get("schema") != "wolf-auditor.evidence.v1":
        return False
    stored = report.get("report_sha256")
    if not isinstance(stored, str) or len(stored) != 64:
        return False
    unsigned = {k: v for k, v in report.items() if k != "report_sha256"}
    return stored == _hash(unsigned)

def finding_key(f: dict[str, Any]) -> str:
    if not isinstance(f, dict):
        raise ValueError("invalid finding")
    fields = (f.get("rule"), f.get("path"), f.get("line"), f.get("advisory_id", ""))
    if not isinstance(fields[0], str) or not isinstance(fields[1], str) or type(fields[2]) is not int:
        raise ValueError("malformed finding identity")
    return _hash(list(fields))

def compare_reports(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    if not verify_report(previous) or not verify_report(current):
        raise ValueError("invalid or hash-mismatched evidence; comparison refused")
    if previous.get("target_directory_name") != current.get("target_directory_name"):
        raise ValueError("cannot compare reports from different targets")
    before = {finding_key(f) for f in previous.get("findings", [])}
    after = {finding_key(f) for f in current.get("findings", [])}
    changed = {
        "schema": "wolf-auditor.delta.v1",
        "previous_report_sha256": previous["report_sha256"],
        "current_report_sha256": current["report_sha256"],
        "new_findings": sorted(after - before),
        "resolved_findings": sorted(before - after),
        "unchanged_count": len(before & after),
        "previous_status": previous["status"],
        "current_status": current["status"],
        "scope_warning": "Line-based keys can change after code movement; not independent security certification.",
    }
    changed["delta_sha256"] = _hash(changed)
    return changed
