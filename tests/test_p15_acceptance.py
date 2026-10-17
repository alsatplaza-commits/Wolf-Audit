"""P1.5 acceptance contracts that were not already locked by the v0.3 suite.

OSV results are mocked. These tests do not claim CVE completeness or certification.
"""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from wolf_auditor.__main__ import main
from wolf_auditor.engine import scan
from wolf_auditor.osv import enrich_with_osv
from wolf_auditor.policy import evaluate
from wolf_auditor.reporting import to_sarif

POLICY = {"schema": "wolf-auditor.policy.v1", "block_at_or_above": "high", "require_osv": False}


class P15AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def make(self, name: str, text: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_cli_without_osv_online_does_not_disclose(self):
        self.make("requirements.txt", "requests==2.1.0\n")
        with patch("wolf_auditor.osv._http_query", side_effect=AssertionError("network")):
            with patch("sys.argv", ["wolf-auditor", str(self.root)]), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
                code = main()
        self.assertEqual(code, 0)
        self.assertNotIn("OSV disclosure", err.getvalue())

    def test_cli_osv_online_is_explicit_and_sends_only_package_identity(self):
        marker = "MARKERVALUE123456789"
        self.make("requirements.txt", f"# {marker}\nrequests==2.1.0\n")
        seen: list[dict] = []

        def stub(queries):
            seen.extend(queries)
            return {"results": [{"vulns": []} for _ in queries]}

        argv = ["wolf-auditor", str(self.root), "--osv-online"]
        with patch("wolf_auditor.osv._http_query", side_effect=stub):
            with patch("sys.argv", argv), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
                code = main()
        self.assertEqual(code, 0)
        self.assertIn("OSV disclosure opted in", err.getvalue())
        self.assertEqual(seen, [{"version": "2.1.0", "package": {"name": "requests", "ecosystem": "PyPI"}}])
        self.assertNotIn(marker, json.dumps(seen))

    def test_osv_timeout_is_incomplete(self):
        self.make("requirements.txt", "requests==2.1.0\n")

        def timed_out(_queries):
            raise TimeoutError("timed out")

        report = enrich_with_osv(scan(self.root), fetcher=timed_out)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["external_checks"]["osv"]["state"], "INCOMPLETE")
        self.assertEqual(report["findings"], [])
        self.assertEqual(evaluate(report, POLICY)["status"], "BLOCK")
        self.assertIn("not an exploit proof", report["external_checks"]["osv"]["disclaimer"])

    def test_osv_partial_batch_stays_incomplete(self):
        self.make("requirements.txt", "".join(f"pkg{i}==1.0.{i}\n" for i in range(101)))
        calls = {"n": 0}

        def stub(queries):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]} for _ in queries]}
            raise TimeoutError("second batch timed out")

        report = enrich_with_osv(scan(self.root), fetcher=stub)
        self.assertGreaterEqual(calls["n"], 2)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["external_checks"]["osv"]["state"], "INCOMPLETE")
        self.assertTrue(any(item["rule"] == "OSV_MATCHED_ADVISORY" for item in report["findings"]))
        self.assertTrue(all(item["verified_exploit"] is False for item in report["findings"]))
        verdict = evaluate(report, POLICY)
        self.assertEqual(verdict["status"], "BLOCK")
        self.assertIn("INCOMPLETE_COVERAGE", verdict["reasons"])
        sarif = json.dumps(to_sarif(report))
        self.assertIn("GHSA-aaaa-bbbb-cccc", sarif)
        self.assertNotIn("pkg0==1.0.0", sarif)

    def test_invalid_policy_file_fails_closed(self):
        self.make("app.py", "print('ok')\n")
        policy = self.root / "policy.json"
        policy.write_text("{", encoding="utf-8")
        argv = ["wolf-auditor", str(self.root), "--policy", str(policy), "--gate-output", str(self.root / "gate.json")]
        with patch("sys.argv", argv), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main()
        self.assertEqual(code, 2)
        self.assertFalse((self.root / "gate.json").exists())


if __name__ == "__main__":
    unittest.main()
