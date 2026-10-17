"""P2.3 parser boundary and CVE coverage contract."""
from __future__ import annotations

import ast
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolf_auditor.analysis import python_sast
from wolf_auditor.engine import scan
from wolf_auditor.language import PARSER_PLAN, analyze_registered, registered_suffixes
from wolf_auditor.osv import cve_coverage_contract, enrich_with_osv
from wolf_auditor.rust_safety import analyze_rust

ROOT = Path(__file__).resolve().parents[1]


class ParserContractTests(unittest.TestCase):
    def test_hidden_macro_cfg_and_path_are_incomplete(self) -> None:
        hidden, hidden_gaps = analyze_rust("a.rs", "fn safe() { hidden_unsafe!(); }\n")
        self.assertNotIn("RUST_UNSAFE_INVENTORY", [item["rule"] for item in hidden])
        self.assertIn("rust_macro_not_expanded", [item["reason"] for item in hidden_gaps])
        cfg_source = "#[cfg(not(test))]\nfn go() { unsafe { foreign(); } }\n"
        cfg_findings, cfg_gaps = analyze_rust("c.rs", cfg_source)
        self.assertIn("RUST_UNSAFE_INVENTORY", [item["rule"] for item in cfg_findings])
        self.assertIn("rust_cfg_unresolved", [item["reason"] for item in cfg_gaps])
        named, named_gaps = analyze_rust("n.rs", "fn go() { crate::missing::item(); }\n")
        self.assertEqual(named, [])
        self.assertIn("rust_name_resolution_unresolved", [item["reason"] for item in named_gaps])
        target = Path(tempfile.mkdtemp())
        try:
            (target / "lib.rs").write_text("fn safe() { hidden_unsafe!(); }\n", encoding="utf-8")
            report = scan(target)
        finally:
            shutil.rmtree(target, ignore_errors=True)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertNotEqual(report["status"], "NO_HEURISTIC_FINDINGS")
        self.assertNotIn(report["status"], {"PASS", "REVIEWED", "APPROVED"})

    def test_comments_and_strings_do_not_create_resolution_gaps(self) -> None:
        source = '// cfg! hidden_unsafe!(); crate::nope\nlet s = "cfg! crate::nope";\nfn safe() {}\n'
        findings, gaps = analyze_rust("a.rs", source)
        self.assertEqual(findings, [])
        self.assertEqual(gaps, [])

    def test_registry_is_not_rust_only_and_does_not_compile(self) -> None:
        suffixes = registered_suffixes()
        self.assertIn(".rs", suffixes)
        self.assertIn(".py", suffixes)
        self.assertIn(".c", suffixes)
        self.assertGreater(len(suffixes), 3)
        source = "fn safe() { hidden_unsafe!(); }\n"
        self.assertEqual(analyze_registered("a.rs", source), analyze_rust("a.rs", source))
        python = "import os\nos.system('true')\n"
        self.assertEqual(analyze_registered("a.py", python), python_sast("a.py", python))
        unknown, gaps = analyze_registered("a.go", "package main\n")
        self.assertEqual(unknown, [])
        self.assertEqual(gaps[0]["reason"], "language_analyzer_not_registered")
        stages = {item["stage"]: item for item in PARSER_PLAN}
        self.assertTrue(stages["token_heuristic"]["implemented"])
        self.assertFalse(stages["token_heuristic"]["compiles_source"])
        self.assertFalse(stages["token_heuristic"]["runs_build_scripts"])
        self.assertFalse(stages["token_heuristic"]["expands_macros"])
        self.assertFalse(stages["syntax_parser_no_expansion"]["implemented"])
        self.assertIn("syn", stages["syntax_parser_no_expansion"]["candidates"])
        self.assertIn("rust-analyzer", stages["syntax_parser_no_expansion"]["candidates"])
        with patch("subprocess.run", side_effect=AssertionError("compiler executed")):
            analyze_registered("a.rs", "fn safe() {}\n")
            ast.parse((ROOT / "wolf_auditor" / "language.py").read_text(encoding="utf-8"))
        self.assertNotIn("subprocess", (ROOT / "wolf_auditor" / "language.py").read_text(encoding="utf-8"))

    def test_cve_contract_is_never_complete(self) -> None:
        offline = cve_coverage_contract(mode="offline")
        online = cve_coverage_contract(mode="online")
        for contract, mode, source in (
            (offline, "offline", None),
            (online, "online", "OSV querybatch"),
        ):
            self.assertFalse(contract["completeness"])
            self.assertEqual(contract["mode"], mode)
            self.assertEqual(contract["source"], source)
            self.assertIsNone(contract["queried_at"])
            self.assertEqual(contract["freshness"], "not recorded")
            self.assertNotIn("CVE complete", contract["statement"])
            self.assertIn("match", contract)
        with self.assertRaises(ValueError):
            cve_coverage_contract(mode="complete")
        target = Path(tempfile.mkdtemp())
        try:
            (target / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
            report = scan(target)
        finally:
            shutil.rmtree(target, ignore_errors=True)
        self.assertEqual(report["cve_coverage"]["mode"], "offline")
        self.assertFalse(report["cve_coverage"]["completeness"])
        self.assertEqual(report["analysis_limits"]["parser_stage"], "token_heuristic")
        enriched = enrich_with_osv(report, fetcher=lambda queries: {"results": [{"vulns": []} for _ in queries]})
        self.assertEqual(enriched["cve_coverage"]["mode"], "online")
        self.assertEqual(enriched["external_checks"]["osv"]["coverage"]["source"], "OSV querybatch")
        self.assertFalse(enriched["cve_coverage"]["completeness"])
        self.assertIsNone(enriched["cve_coverage"]["queried_at"])
        self.assertNotIn("CVE complete", json.dumps(enriched["cve_coverage"]))
        self.assertEqual(report["cve_coverage"]["mode"], "offline")
