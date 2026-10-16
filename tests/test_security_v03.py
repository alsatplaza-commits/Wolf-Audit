"""No-network contract tests for OSV advisory matching, policy gates and IaC."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolf_auditor.engine import scan
from wolf_auditor.reporting import to_sbom
from wolf_auditor.__main__ import main
from contextlib import redirect_stderr, redirect_stdout
import io
from wolf_auditor.osv import enrich_with_osv
from wolf_auditor.policy import evaluate, validate_policy
from wolf_auditor.reporting import to_sarif
from wolf_auditor.delta import compare_reports, verify_report

POLICY = {"schema": "wolf-auditor.policy.v1", "block_at_or_above": "high", "require_osv": False}


class SecurityV03Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make(self, name, content):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf8")

    def with_deps(self):
        self.make("requirements.txt", "requests==2.1.0\n")
        return scan(self.root)

    def test_osv_off_by_default(self):
        self.with_deps()
        with patch("wolf_auditor.osv._http_query", side_effect=AssertionError("unexpected network")):
            report = scan(self.root)
        self.assertNotIn("external_checks", report)

    def test_osv_real_advisory_shape_with_mock_no_network(self):
        report = self.with_deps()
        calls = []
        def stub(queries):
            calls.extend(queries)
            return {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}]}
        enriched = enrich_with_osv(report, fetcher=stub)
        self.assertEqual(enriched["external_checks"]["osv"]["state"], "COMPLETE")
        self.assertEqual(calls[0]["package"], {"name": "requests", "ecosystem": "PyPI"})
        self.assertEqual(enriched["findings"][0]["advisory_id"], "GHSA-aaaa-bbbb-cccc")
        self.assertFalse(enriched["findings"][0]["verified_exploit"])
        self.assertNotEqual(enriched["report_sha256"], report["report_sha256"])
        self.assertNotIn("external_checks", report)

    def test_osv_clean_response_is_not_security_certification(self):
        enriched = enrich_with_osv(self.with_deps(), fetcher=lambda qs: {"results": [{"vulns": []} for _ in qs]})
        self.assertEqual(enriched["status"], "NO_HEURISTIC_FINDINGS")
        self.assertIn("not an exploit proof", enriched["external_checks"]["osv"]["disclaimer"])

    def test_osv_network_failure_incomplete_not_pass(self):
        def fail(queries):
            raise OSError("connection dropped")
        report = enrich_with_osv(self.with_deps(), fetcher=fail)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["external_checks"]["osv"]["state"], "INCOMPLETE")
        self.assertEqual(evaluate(report, POLICY)["status"], "BLOCK")

    def test_osv_malformed_response_incomplete(self):
        report = enrich_with_osv(self.with_deps(), fetcher=lambda qs: {"results": []})
        self.assertEqual(report["status"], "INCOMPLETE")

    def test_osv_bad_advisory_id_rejected(self):
        report = enrich_with_osv(self.with_deps(),
                                 fetcher=lambda qs: {"results": [{"vulns": [{"id": "../secret"}]}]})
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["findings"], [])

    def test_osv_unpinned_dependency_cannot_be_looked_up(self):
        self.make("requirements.txt", "requests>=2.0\n")
        report = enrich_with_osv(scan(self.root), fetcher=lambda qs: {"results": []})
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["external_checks"]["osv"]["state"], "INCOMPLETE")

    def test_osv_reproducible_for_fixed_fake_response(self):
        src = self.with_deps()
        stub = lambda qs: {"results": [{"vulns": [{"id": "GHSA-1234-5678-9abc"}]} for _ in qs]}
        self.assertEqual(enrich_with_osv(src, fetcher=stub), enrich_with_osv(src, fetcher=stub))

    def test_osv_sorted_deduplicated_queries_for_lockfiles(self):
        self.make("requirements.txt", "requests==2.1.0\n")
        self.make("requirements-dev.txt", "requests==2.1.0\n")
        source = scan(self.root)
        batches = []
        def stub(qs):
            batches.append(qs)
            return {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]} for _ in qs]}
        report = enrich_with_osv(source, fetcher=stub)
        self.assertEqual(sum(len(q) for q in batches), 1)
        self.assertEqual(len(report["findings"]), 2)

    def test_osv_malformed_non_object_is_incomplete(self):
        report = enrich_with_osv(self.with_deps(), fetcher=lambda qs: [])
        self.assertEqual(report["status"], "INCOMPLETE")

    def test_default_policy_blocks_matched_advisory_even_if_review_level(self):
        report = enrich_with_osv(self.with_deps(),
                                 fetcher=lambda qs: {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}]})
        verdict = evaluate(report, POLICY)
        self.assertEqual(verdict["status"], "BLOCK")
        self.assertIn("OSV_ADVISORY_MATCHED", verdict["reasons"])

    def test_invalid_advisory_policy_option_rejected(self):
        with self.assertRaises(ValueError):
            validate_policy({**POLICY, "block_on_advisories": "false"})

    def test_delta_reports_new_and_resolved_findings(self):
        self.make("safe.py", "print('ok')\n")
        before = scan(self.root)
        self.make("bad.py", "eval('something')\n")
        after = scan(self.root)
        delta = compare_reports(before, after)
        self.assertEqual(len(delta["new_findings"]), 1)
        self.assertEqual(delta["resolved_findings"], [])
        self.assertTrue(verify_report(after))
        (self.root / "bad.py").unlink()
        final = scan(self.root)
        restored = compare_reports(after, final)
        self.assertEqual(len(restored["resolved_findings"]), 1)

    def test_delta_rejects_modified_evidence(self):
        report = self.with_deps()
        tampered = copy.deepcopy(report)
        tampered["status"] = "INCOMPLETE"
        self.assertFalse(verify_report(tampered))
        with self.assertRaises(ValueError):
            compare_reports(tampered, report)

    def test_delta_rejects_other_target(self):
        current = self.with_deps()
        different = copy.deepcopy(current)
        different["target_directory_name"] = "not-same"
        from wolf_auditor.delta import _hash
        different["report_sha256"] = _hash({
            k: v for k, v in different.items() if k != "report_sha256"
        })
        with self.assertRaises(ValueError):
            compare_reports(current, different)

    def test_sbom_contains_linked_osv_vulnerability(self):
        source = self.with_deps()
        report = enrich_with_osv(source, fetcher=lambda qs: {
            "results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}]
        })
        bom = to_sbom(report)
        self.assertEqual(len(bom["vulnerabilities"]), 1)
        self.assertEqual(bom["vulnerabilities"][0]["id"], "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(bom["vulnerabilities"][0]["affects"][0]["ref"],
                         bom["components"][0]["bom-ref"])
        sarif = to_sarif(report)
        self.assertEqual(sarif["runs"][0]["results"][0]["properties"]["osv_advisory_id"],
                         "GHSA-aaaa-bbbb-cccc")

    def test_cli_policy_block_and_gate_report(self):
        self.make("danger.py", 'eval("1+1")\n')
        policy_path = self.root / "audit-policy.json"
        policy_path.write_text(json.dumps(POLICY), encoding="utf8")
        gate_path = self.root / "gate.json"
        args = ["wolf-auditor", str(self.root), "--policy", str(policy_path),
                "--gate-output", str(gate_path), "--output", str(self.root / "audit.json")]
        with patch("sys.argv", args), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main()
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(gate_path.read_text())["status"], "BLOCK")

    def test_cli_requires_policy_for_gate_report(self):
        self.make("safe.py", "print('hello')\n")
        args = ["wolf-auditor", str(self.root), "--gate-output", str(self.root / "gate.json")]
        with patch("sys.argv", args), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main()
        self.assertEqual(code, 2)
        self.assertFalse((self.root / "gate.json").exists())

    def test_policy_blocks_high(self):
        self.make("danger.py", 'eval("1+1")\n')
        verdict = evaluate(scan(self.root), POLICY)
        self.assertEqual(verdict["status"], "BLOCK")
        self.assertIn("SEVERITY_THRESHOLD_EXCEEDED", verdict["reasons"])

    def test_policy_allows_review_but_not_claims_security(self):
        self.make("x.rs", "unsafe { do_something(); }\n")
        verdict = evaluate(scan(self.root), POLICY)
        self.assertEqual(verdict["status"], "PASS")
        self.assertIn("NOT independent", verdict["disclaimer"])

    def test_policy_blocks_incomplete_even_for_review_threshold(self):
        self.make("broken.py", "def x(:\n")
        verdict = evaluate(scan(self.root), {**POLICY, "block_at_or_above": "review"})
        self.assertEqual(verdict["status"], "BLOCK")
        self.assertIn("INCOMPLETE_COVERAGE", verdict["reasons"])

    def test_policy_require_osv_without_check_blocks(self):
        report = self.with_deps()
        verdict = evaluate(report, {**POLICY, "require_osv": True})
        self.assertIn("OSV_EVIDENCE_NOT_COMPLETE", verdict["reasons"])

    def test_policy_require_osv_matched_check(self):
        report = enrich_with_osv(self.with_deps(), fetcher=lambda qs: {"results": [{"vulns": []} for _ in qs]})
        verdict = evaluate(report, {**POLICY, "require_osv": True})
        self.assertEqual(verdict["status"], "PASS")

    def test_policy_typo_fails_configuration(self):
        with self.assertRaises(ValueError):
            validate_policy({**POLICY, "block_at_or_abov": "review"})

    def test_policy_boolean_max_findings_rejected(self):
        with self.assertRaises(ValueError):
            validate_policy({**POLICY, "max_findings": True})

    def test_policy_count_limit(self):
        self.make("x.rs", "unsafe { do(); }\n")
        verdict = evaluate(scan(self.root), {**POLICY, "max_findings": 0})
        self.assertEqual(verdict["status"], "BLOCK")
        self.assertIn("FINDING_COUNT_EXCEEDED", verdict["reasons"])

    def test_terraform_public_acl_and_ingress(self):
        self.make("main.tf", 'acl = "public-read"\ncidr_blocks = ["0.0.0.0/0"]\n')
        self.assertEqual({f["rule"] for f in scan(self.root)["findings"]},
                         {"IAC_PUBLIC_OBJECT_ACL", "IAC_OPEN_IPV4_INGRESS_REVIEW"})

    def test_kubernetes_privilege_escalation(self):
        self.make("k8s/deployment.yaml", "privileged: true\nallowPrivilegeEscalation: true\nhostNetwork: true\n")
        self.assertEqual({f["rule"] for f in scan(self.root)["findings"]},
                         {"K8S_PRIVILEGED_CONTAINER", "K8S_PRIVILEGE_ESCALATION", "K8S_HOST_NETWORK"})

    def test_kubernetes_detection_not_applied_to_github_workflows(self):
        self.make(".github/workflows/check.yaml", "privileged: true\n")
        self.assertNotIn("K8S_PRIVILEGED_CONTAINER", [f["rule"] for f in scan(self.root)["findings"]])

    def test_private_key_redaction(self):
        secret = "-----BEGIN OPENSSH PRIVATE KEY-----"
        self.make(".env", secret + "\n")
        report = scan(self.root)
        self.assertIn("PRIVATE_KEY_MATERIAL", [f["rule"] for f in report["findings"]])
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn(secret, json.dumps(to_sarif(report)))

    def test_fake_github_token_not_exposed(self):
        secret = "ghp_" + ("A" * 36)
        self.make(".env.test", "TOKEN=" + secret + "\n")
        report = scan(self.root)
        self.assertIn("GITHUB_TOKEN_LIKE_STRING", [f["rule"] for f in report["findings"]])
        self.assertNotIn(secret, json.dumps(report))

    def test_signed_url_query_is_flagged_and_not_copied(self):
        signature = "SYNTHETIC" + ("A" * 24)
        self.make("fetch.yml", 'DOWNLOAD: "https://example.invalid/file?se=2020-01-01&sig=' + signature + '"\n')
        report = scan(self.root)
        self.assertIn("CREDENTIAL_URL_QUERY", [item["rule"] for item in report["findings"]])
        encoded = json.dumps(report)
        self.assertNotIn(signature, encoded)
        self.assertNotIn("sig=", encoded)
        self.assertNotIn("example.invalid", encoded)

    def test_ignored_generated_paths_have_explicit_inventory(self):
        self.make("node_modules/vendor/evil.py", 'eval("danger")\n')
        report = scan(self.root)
        self.assertEqual(report["status"], "NO_HEURISTIC_FINDINGS")
        self.assertEqual(report["excluded_paths"][0]["path"], "node_modules")


if __name__ == "__main__":
    unittest.main()
