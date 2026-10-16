"""Read-only external review intake. No network and no automatic PASS."""

import json
import unittest

from wolf_auditor.external_review import assess_external_review


def packet(**overrides):
    base = {
        "schema": "wolf-auditor.external-review-input.v1",
        "subject": "reviewed-product",
        "commit_sha": "a" * 40,
        "workflow_run_url": "https://github.com/example/repo/actions/runs/1",
        "workflow_result": "success",
        "registry_counts": {"total": 29, "needs_review": 29},
        "missing_review_evidence": ["ffi_expert_signoff"],
        "release_gate_reasons": ["human_review_open"],
        "diff_ref": "refs/pull/14/head",
        "evidence_refs": ["b" * 64],
    }
    base.update(overrides)
    return base


class ExternalReviewTests(unittest.TestCase):
    def test_missing_packet_is_incomplete_and_not_pass(self):
        for value in (None, {}, []):
            report = assess_external_review(value)
            self.assertEqual(report["status"], "INCOMPLETE")
            self.assertFalse(report["pass_granted"])
            self.assertFalse(report["certification"])
            self.assertFalse(report["records_closed"])
            self.assertNotEqual(report["status"], "PASS")

    def test_product_name_does_not_grant_privilege_or_pass(self):
        named = assess_external_review(packet(subject="sentinel"))
        other = assess_external_review(packet(subject="other-product"))
        self.assertEqual(named["status"], other["status"])
        self.assertEqual(named["status"], "INCOMPLETE")
        self.assertFalse(named["product_privilege"])
        self.assertFalse(named["pass_granted"])
        self.assertFalse(named["records_closed"])
        self.assertEqual(named["registry_counts"]["needs_review"], 29)
        self.assertIn("ffi_expert_signoff", named["missing_review_evidence"])

    def test_workflow_success_alone_is_not_pass(self):
        report = assess_external_review(packet(
            registry_counts={"total": 0, "needs_review": 0},
            missing_review_evidence=[],
            release_gate_reasons=[],
        ))
        self.assertEqual(report["workflow_result"], "success")
        self.assertEqual(report["status"], "NEEDS_REVIEW")
        self.assertFalse(report["pass_granted"])
        self.assertFalse(report["certification"])
        self.assertFalse(report["records_closed"])

    def test_open_records_are_not_closed_by_a_count(self):
        report = assess_external_review(packet())
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertFalse(report["records_closed"])
        self.assertEqual(report["registry_counts"], {"total": 29, "needs_review": 29})

    def test_signed_workflow_url_is_not_copied(self):
        signature = "SYNTHETIC" + ("B" * 24)
        report = assess_external_review(packet(
            workflow_run_url="https://example.invalid/raw?sig=" + signature,
        ))
        encoded = json.dumps(report)
        self.assertIn("workflow_run_url", report["gaps"])
        self.assertIsNone(report["workflow_run_url"])
        self.assertNotIn(signature, encoded)
        self.assertNotIn("sig=", encoded)

    def test_private_body_is_rejected_and_not_echoed(self):
        secret = "PRIVATE_BODY_" + ("C" * 24)
        with self.assertRaisesRegex(ValueError, "external review packet rejected") as caught:
            assess_external_review(packet(source=secret, privilege="sentinel", auto_pass=True))
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn("sentinel", str(caught.exception))

    def test_patch_text_is_not_stored_as_diff_ref(self):
        patch = "diff --git a/secret.py b/secret.py\n+token = hidden"
        report = assess_external_review(packet(diff_ref=patch))
        self.assertIn("diff_ref", report["gaps"])
        self.assertIsNone(report["diff_ref"])
        self.assertNotIn("secret.py", json.dumps(report))
        self.assertNotIn("token", json.dumps(report))

    def test_zero_count_with_open_note_stays_incomplete(self):
        report = assess_external_review(packet(
            registry_counts={"total": 4, "needs_review": 0},
            missing_review_evidence=["ffi_expert_signoff"],
        ))
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertIn("registry_review_mismatch", report["gaps"])
        self.assertFalse(report["records_closed"])
