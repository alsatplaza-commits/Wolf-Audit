"""Contract tests: detection, secrecy, coverage, and deterministic evidence."""

import json
import tempfile
import unittest
from pathlib import Path

from wolf_auditor.engine import MAX_FILE_BYTES, scan


class AuditEngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def make(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def test_unsafe_is_review_not_proven_vulnerability(self):
        self.make("src/native.rs", "fn go() { unsafe { foo(); } }\n")
        r = scan(self.root)
        self.assertEqual(r["status"], "REVIEW_REQUIRED")
        self.assertEqual(r["findings"][0]["rule"], "RUST_UNSAFE_INVENTORY")
        self.assertFalse(r["findings"][0]["verified_exploit"])

    def test_unpinned_action_flags_and_sha_pin_is_accepted(self):
        self.make(".github/workflows/ci.yml", "steps:\n  - uses: actions/checkout@v4\n"
                  "  - uses: actions/setup-python@" + ("a" * 40) + "\n")
        r = scan(self.root)
        self.assertEqual([f["rule"] for f in r["findings"]], ["ACTIONS_REF_NOT_SHA_PINNED"])

    def test_potential_secret_is_never_in_report(self):
        secret = "SUPER_SECRET_VALUE_123456789"
        self.make("config.py", f'api_key = "{secret}"\n')
        report = json.dumps(scan(self.root))
        self.assertIn("POTENTIAL_HARDCODED_SECRET", report)
        self.assertNotIn(secret, report)

    def test_same_content_reproducible_evidence_digest(self):
        self.make("a.rs", "fn safe() {}\n")
        self.assertEqual(scan(self.root), scan(self.root))
        self.assertEqual(scan(self.root)["status"], "NO_HEURISTIC_FINDINGS")

    def test_too_large_is_coverage_gap_not_pass(self):
        self.make("oversized.rs", "x" * (MAX_FILE_BYTES + 1))
        result = scan(self.root)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["scanned_files"], 0)

    def test_no_external_execution_or_network(self):
        self.make("untrusted.py", "raise SystemExit('should never run')\n")
        self.assertEqual(scan(self.root)["status"], "NO_HEURISTIC_FINDINGS")

    def test_directory_symlink_is_not_silently_accepted_as_full_coverage(self):
        (self.root / "safe").mkdir()
        self.make("safe/test.rs", "fn safe() {}\n")
        try:
            (self.root / "outside.rs").symlink_to(self.root / "safe", target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        result = scan(self.root)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn("directory_symlink_not_followed", [g["reason"] for g in result["coverage_gaps"]])

    def test_skipped_symlink_reports_gap(self):
        self.make("a.rs", "fn a() {}\n")
        target = self.root / "a.rs"
        try:
            (self.root / "link.rs").symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.assertEqual(scan(self.root)["status"], "INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
