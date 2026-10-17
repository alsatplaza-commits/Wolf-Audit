"""False negatives for unresolved Rust attributes, and CVE freshness limits."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from wolf_auditor.engine import scan
from wolf_auditor.osv import cve_coverage_contract, enrich_with_osv
from wolf_auditor.rust_safety import analyze_rust


class AttributeLimitTests(unittest.TestCase):
    def test_attribute_macros_are_not_a_clean_result(self) -> None:
        derived, derived_gaps = analyze_rust("a.rs", "#[derive(HiddenUnsafe)]\nfn safe() {}\n")
        self.assertEqual(derived, [])
        self.assertIn("rust_macro_not_expanded", [item["reason"] for item in derived_gaps])
        conditional, conditional_gaps = analyze_rust(
            "c.rs", "#[cfg_attr(not(test), inline)]\nfn safe() {}\n",
        )
        self.assertEqual(conditional, [])
        self.assertIn("rust_cfg_unresolved", [item["reason"] for item in conditional_gaps])
        self.assertNotIn("rust_macro_not_expanded", [item["reason"] for item in conditional_gaps])
        unknown, unknown_gaps = analyze_rust("u.rs", "#[project_macro]\nfn safe() {}\n")
        self.assertEqual(unknown, [])
        self.assertIn("rust_macro_not_expanded", [item["reason"] for item in unknown_gaps])
        commented, commented_gaps = analyze_rust(
            "s.rs", '// #[derive(HiddenUnsafe)]\nlet s = "#[derive(HiddenUnsafe)]";\nfn safe() {}\n',
        )
        self.assertEqual(commented, [])
        self.assertEqual(commented_gaps, [])
        target = Path(tempfile.mkdtemp())
        try:
            (target / "lib.rs").write_text("#[derive(HiddenUnsafe)]\nfn safe() {}\n", encoding="utf-8")
            report = scan(target)
        finally:
            shutil.rmtree(target, ignore_errors=True)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertNotEqual(report["status"], "NO_HEURISTIC_FINDINGS")
        self.assertNotIn(report["status"], {"PASS", "REVIEWED", "APPROVED"})

    def test_known_attributes_are_not_relabelled_as_macros(self) -> None:
        findings, gaps = analyze_rust("a.rs", '#[unsafe(no_mangle)]\nfn exported() {}\n')
        self.assertEqual(gaps, [])
        rules = {item["rule"] for item in findings}
        self.assertIn("RUST_UNSAFE_INVENTORY", rules)
        self.assertIn("RUST_FFI_SYMBOL", rules)
        exported, exported_gaps = analyze_rust("b.rs", '#[export_name = "marker"]\nfn x() {}\n')
        self.assertEqual(exported_gaps, [])
        self.assertTrue(exported)
        self.assertNotIn("marker", json.dumps(exported))

    def test_advisory_modified_time_is_freshness_not_completeness(self) -> None:
        secret = "modified-must-not-be-copied"
        target = Path(tempfile.mkdtemp())
        try:
            (target / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
            report = scan(target)
        finally:
            shutil.rmtree(target, ignore_errors=True)

        def fetch(_queries: list[dict]) -> dict:
            return {"results": [{"vulns": [
                {"id": "OSV-2024-0001", "modified": "2024-01-01T00:00:00Z"},
                {"id": "OSV-2024-0002", "modified": "2024-06-01T12:30:00.5Z", "summary": secret},
                {"id": "OSV-2024-0003", "modified": secret},
            ]}]}

        enriched = enrich_with_osv(report, fetcher=fetch)
        coverage = enriched["cve_coverage"]
        self.assertEqual(coverage["freshness"], "2024-06-01T12:30:00.5Z")
        self.assertIsNone(coverage["queried_at"])
        self.assertFalse(coverage["completeness"])
        self.assertEqual(coverage["source"], "OSV querybatch")
        self.assertEqual(coverage["mode"], "online")
        encoded = json.dumps(enriched)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("CVE complete", encoded)
        self.assertEqual(report["cve_coverage"]["freshness"], "not recorded")
        empty = enrich_with_osv(report, fetcher=lambda _queries: {"results": [{"vulns": []}]})
        self.assertEqual(empty["cve_coverage"]["freshness"], "not recorded")
        self.assertFalse(empty["cve_coverage"]["completeness"])
        rejected = cve_coverage_contract(mode="online", freshness=secret)
        self.assertEqual(rejected["freshness"], "not recorded")
        self.assertFalse(rejected["completeness"])
