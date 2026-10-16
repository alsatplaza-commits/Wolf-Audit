"""Read-only intake for an operator-supplied review packet.

The function does not fetch a repository, workflow, registry, or diff.
A missing packet is INCOMPLETE. A complete packet stays NEEDS_REVIEW.
Nothing in this module grants PASS or a product-specific privilege.
"""

from __future__ import annotations

import re
from typing import Any

_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_CODE = re.compile(r"^[a-z0-9_]{1,64}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_URL = re.compile(r"^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~/-]*)?$")
_RESULTS = {"success", "failure", "cancelled", "skipped", "timed_out", "neutral"}
_ALLOWED = {
    "schema",
    "subject",
    "commit_sha",
    "workflow_run_url",
    "workflow_result",
    "registry_counts",
    "missing_review_evidence",
    "release_gate_reasons",
    "diff_ref",
    "evidence_refs",
}
_CLAIM = "External review intake is not a PASS and does not close human review records."


def assess_external_review(packet: Any) -> dict[str, Any]:
    if not isinstance(packet, dict) or not packet:
        return _report(gaps=["packet"])
    if any(key not in _ALLOWED for key in packet):
        raise ValueError("external review packet rejected")
    if packet.get("schema") not in (None, "wolf-auditor.external-review-input.v1"):
        raise ValueError("external review packet rejected")
    subject = packet.get("subject")
    if subject is not None and (
        not isinstance(subject, str) or not subject or len(subject) > 64 or any(c.isspace() for c in subject)
    ):
        raise ValueError("external review packet rejected")

    gaps: list[str] = []
    commit = _commit(packet.get("commit_sha"), gaps)
    url = _url(packet.get("workflow_run_url"), gaps)
    result = _choice(packet.get("workflow_result"), _RESULTS, "workflow_result", gaps)
    counts = _counts(packet.get("registry_counts"), gaps)
    missing = _codes(packet.get("missing_review_evidence"), "missing_review_evidence", gaps)
    reasons = _codes(packet.get("release_gate_reasons"), "release_gate_reasons", gaps)
    diff_ref = _ref(packet.get("diff_ref"), gaps)
    refs = _refs(packet.get("evidence_refs"), gaps)
    if missing:
        gaps.append("missing_review_evidence")
    if counts is not None and missing is not None and (counts["needs_review"] > 0) == (len(missing) == 0):
        gaps.append("registry_review_mismatch")
    return _report(
        commit_sha=commit,
        workflow_run_url=url,
        workflow_result=result,
        registry_counts=counts,
        missing_review_evidence=missing or [],
        release_gate_reasons=reasons or [],
        diff_ref=diff_ref,
        evidence_refs=refs or [],
        gaps=gaps,
    )


def _report(**fields: Any) -> dict[str, Any]:
    gaps = sorted(set(fields["gaps"])) if "gaps" in fields else ["packet"]
    body = {
        "schema": "wolf-auditor.external-review.v1",
        "status": "INCOMPLETE" if gaps else "NEEDS_REVIEW",
        "certification": False,
        "pass_granted": False,
        "product_privilege": False,
        "records_closed": False,
        "commit_sha": fields.get("commit_sha"),
        "workflow_run_url": fields.get("workflow_run_url"),
        "workflow_result": fields.get("workflow_result"),
        "registry_counts": fields.get("registry_counts"),
        "missing_review_evidence": fields.get("missing_review_evidence") or [],
        "release_gate_reasons": fields.get("release_gate_reasons") or [],
        "diff_ref": fields.get("diff_ref"),
        "evidence_refs": fields.get("evidence_refs") or [],
        "gaps": gaps,
        "claim": _CLAIM,
    }
    return body


def _commit(value: Any, gaps: list[str]) -> str | None:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        gaps.append("commit_sha")
        return None
    return value.lower()


def _url(value: Any, gaps: list[str]) -> str | None:
    if not isinstance(value, str) or _URL.fullmatch(value) is None or "?" in value or "@" in value:
        gaps.append("workflow_run_url")
        return None
    return value


def _choice(value: Any, allowed: set[str], name: str, gaps: list[str]) -> str | None:
    if not isinstance(value, str) or value not in allowed:
        gaps.append(name)
        return None
    return value


def _counts(value: Any, gaps: list[str]) -> dict[str, int] | None:
    if not isinstance(value, dict) or set(value) != {"total", "needs_review"}:
        gaps.append("registry_counts")
        return None
    total = value.get("total")
    pending = value.get("needs_review")
    if type(total) is not int or type(pending) is not int or total < 0 or pending < 0 or pending > total:
        gaps.append("registry_counts")
        return None
    return {"total": total, "needs_review": pending}


def _codes(value: Any, name: str, gaps: list[str]) -> list[str] | None:
    if not isinstance(value, list) or len(value) > 32:
        gaps.append(name)
        return None
    if any(not isinstance(item, str) or _CODE.fullmatch(item) is None for item in value):
        gaps.append(name)
        return None
    return sorted(set(value))


def _ref(value: Any, gaps: list[str]) -> str | None:
    if not isinstance(value, str) or _REF.fullmatch(value) is None or ".." in value:
        gaps.append("diff_ref")
        return None
    return value


def _refs(value: Any, gaps: list[str]) -> list[str] | None:
    if not isinstance(value, list) or not value or len(value) > 32:
        gaps.append("evidence_refs")
        return None
    if any(not isinstance(item, str) or _SHA256.fullmatch(item) is None for item in value):
        gaps.append("evidence_refs")
        return None
    return sorted({item.lower() for item in value})
