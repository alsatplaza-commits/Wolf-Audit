"""Regression tests for single-customer scope and rejected untrusted inputs."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from wolf_auditor.authorization import load_customer_authorization
from wolf_auditor.engine import scan
from wolf_auditor.__main__ import main


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.outside = tempfile.TemporaryDirectory()
        self.addCleanup(self.outside.cleanup)

    def make(self, name, text, root=None):
        base = self.root if root is None else root
        path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_unbound_scan_is_not_a_certification(self):
        self.make("a.rs", "fn safe() {}\n")
        report = scan(self.root)
        scope = report["customer_scope"]
        self.assertFalse(scope["bound"])
        self.assertEqual(scope["customer_count"], 0)
        self.assertFalse(scope["certification"])
        self.assertIn("not a security certification", scope["disclaimer"])
        self.assertFalse(report["commit_claim"]["certification"])
        self.assertEqual(report["commit_claim"]["status"], "not_claimed")

    def test_single_customer_binding_is_not_a_certification(self):
        self.make("a.rs", "fn safe() {}\n")
        report = scan(self.root, customer_id="acme", authorized_root=self.root)
        scope = report["customer_scope"]
        self.assertTrue(scope["bound"])
        self.assertEqual(scope["customer_id"], "acme")
        self.assertEqual(scope["customer_count"], 1)
        self.assertFalse(scope["certification"])
        self.assertIn("not a security certification", scope["disclaimer"])
        self.assertEqual(report["status"], "NO_HEURISTIC_FINDINGS")

    def test_multiple_customers_are_rejected(self):
        for value in ("acme,beta", "acme beta", "acme/beta", "../acme", "", "acme\nbeta"):
            with self.assertRaisesRegex(ValueError, "customer id rejected"):
                scan(self.root, customer_id=value)
        with self.assertRaisesRegex(ValueError, "customer id rejected"):
            scan(self.root, customer_id=["acme", "beta"])

    def test_target_outside_authorized_root_is_rejected(self):
        other = Path(self.outside.name)
        self.make("a.rs", "fn safe() {}\n", root=other)
        with self.assertRaisesRegex(ValueError, "outside the authorized customer root"):
            scan(other, customer_id="acme", authorized_root=self.root)

    def test_authorized_root_without_customer_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "authorized root requires one customer id"):
            scan(self.root, authorized_root=self.root)

    def test_symlink_scan_root_is_rejected_without_reading_target(self):
        secret = "ROOT_LINK_SECRET_VALUE_123456789"
        real = Path(self.outside.name) / "real"
        real.mkdir()
        (real / "leak.py").write_text(f'api_key = "{secret}"\n', encoding="utf-8")
        link = self.root / "customer-link"
        try:
            link.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(ValueError, "symlink path component rejected"):
            scan(link, customer_id="acme")
        with self.assertRaisesRegex(ValueError, "symlink path component rejected"):
            scan(link)

    def test_file_symlink_target_is_not_read(self):
        secret = "FILE_LINK_SECRET_VALUE_123456789"
        outside = self.make("leak.py", f'api_key = "{secret}"\n', root=Path(self.outside.name))
        self.make("a.rs", "fn safe() {}\n")
        try:
            (self.root / "leak.py").symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        report = scan(self.root, customer_id="acme")
        encoded = json.dumps(report)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("POTENTIAL_HARDCODED_SECRET", encoded)
        reasons = [gap["reason"] for gap in report["coverage_gaps"]]
        self.assertIn("symlink_not_followed", reasons)
        self.assertIn("symlink_target_rejected", reasons)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertFalse(report["customer_scope"]["certification"])

    def test_directory_symlink_target_is_not_walked(self):
        secret = "DIR_LINK_SECRET_VALUE_123456789"
        outside = Path(self.outside.name)
        self.make("hidden.py", f'api_key = "{secret}"\n', root=outside)
        try:
            (self.root / "linked").symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        report = scan(self.root, customer_id="acme")
        self.assertNotIn(secret, json.dumps(report))
        reasons = [gap["reason"] for gap in report["coverage_gaps"]]
        self.assertIn("directory_symlink_not_followed", reasons)
        self.assertIn("symlink_target_rejected", reasons)

    def test_malformed_commit_claim_is_rejected_and_not_echoed(self):
        secret = "CLAIM_SECRET_VALUE_SHOULD_NOT_LEAK"
        self.make("a.rs", "fn safe() {}\n")
        report = scan(self.root, customer_id="acme", commit_claim=secret)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["commit_claim"]["status"], "rejected")
        self.assertFalse(report["commit_claim"]["accepted"])
        self.assertFalse(report["commit_claim"]["verified"])
        self.assertFalse(report["commit_claim"]["certification"])
        self.assertIn("Unverified commit claims are rejected", report["commit_claim"]["disclaimer"])
        self.assertNotIn(secret, json.dumps(report))
        self.assertIn("unverified_commit_claim_rejected", [gap["reason"] for gap in report["coverage_gaps"]])

    def test_unverified_sha_is_rejected(self):
        self.make("a.rs", "fn safe() {}\n")
        report = scan(self.root, commit_claim="a" * 40)
        self.assertEqual(report["commit_claim"]["status"], "rejected")
        self.assertNotIn("commit", report["commit_claim"])
        self.assertFalse(report["commit_claim"]["certification"])
        self.assertEqual(report["status"], "INCOMPLETE")

    def test_clean_local_head_matches_without_certification(self):
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        self.make("a.rs", "fn safe() {}\n")
        self.git("init", "-b", "main")
        self.git("config", "core.autocrlf", "false")
        self.git("add", "a.rs")
        self.git("-c", "user.email=wolf-auditor@example.com", "-c", "user.name=WOLF AUDITOR Test",
                 "commit", "-m", "test")
        sha = self.git("rev-parse", "HEAD").stdout.strip()
        report = scan(self.root, customer_id="acme", commit_claim=sha)
        self.assertEqual(report["commit_claim"]["status"], "local_head_match")
        self.assertTrue(report["commit_claim"]["verified"])
        self.assertEqual(report["commit_claim"]["commit"], sha)
        self.assertFalse(report["commit_claim"]["certification"])
        self.assertIn("not a security certification", report["commit_claim"]["disclaimer"])
        self.assertNotIn("unverified_commit_claim_rejected", [gap["reason"] for gap in report["coverage_gaps"]])

    def test_dirty_tree_commit_claim_is_rejected(self):
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        self.make("a.rs", "fn safe() {}\n")
        self.git("init", "-b", "main")
        self.git("config", "core.autocrlf", "false")
        self.git("add", "a.rs")
        self.git("-c", "user.email=wolf-auditor@example.com", "-c", "user.name=WOLF AUDITOR Test",
                 "commit", "-m", "test")
        sha = self.git("rev-parse", "HEAD").stdout.strip()
        self.make("a.rs", "fn safe() { /* dirty */ }\n")
        report = scan(self.root, customer_id="acme", commit_claim=sha)
        self.assertEqual(report["commit_claim"]["status"], "rejected")
        self.assertFalse(report["commit_claim"]["certification"])
        self.assertNotIn(sha, json.dumps(report["commit_claim"]))

    def test_authorization_file_accepts_one_customer_only(self):
        path = self.root / "auth.json"
        path.write_text(json.dumps({
            "schema": "wolf-auditor.customer-authorization.v1",
            "customer_id": "acme",
        }), encoding="utf-8")
        self.assertEqual(load_customer_authorization(path), "acme")
        path.write_text(json.dumps({
            "schema": "wolf-auditor.customer-authorization.v1",
            "customer_id": "acme",
            "customers": ["acme", "beta"],
        }), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "customer authorization rejected"):
            load_customer_authorization(path)

    def test_symlink_authorization_file_is_rejected(self):
        real = self.make("auth.json", json.dumps({
            "schema": "wolf-auditor.customer-authorization.v1",
            "customer_id": "acme",
        }), root=Path(self.outside.name))
        link = self.root / "auth.json"
        try:
            link.symlink_to(real)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(ValueError, "symlink authorization file rejected"):
            load_customer_authorization(link)

    def test_duplicate_customer_key_is_rejected(self):
        path = self.root / "auth.json"
        path.write_text(
            '{"schema":"wolf-auditor.customer-authorization.v1",'
            '"customer_id":"acme","customer_id":"beta"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "customer authorization rejected"):
            load_customer_authorization(path)

    def test_parent_traversal_cannot_leave_customer_root(self):
        secret = "TRAVERSAL_SECRET_VALUE_123456789"
        customer = self.root / "acme"
        other = self.root / "beta"
        customer.mkdir()
        self.make("leak.py", f'api_key = "{secret}"\n', root=other)
        self.make("ok.rs", "fn safe() {}\n", root=customer)
        with self.assertRaisesRegex(ValueError, "outside the authorized customer root"):
            scan(customer / ".." / "beta", customer_id="acme", authorized_root=customer)

    def test_bound_output_outside_customer_root_is_not_written(self):
        self.make("a.rs", "fn safe() {}\n")
        stolen = Path(self.outside.name) / "stolen.json"
        args = ["wolf-auditor", str(self.root), "--customer-id", "acme",
                "--authorized-root", str(self.root), "--output", str(stolen)]
        with patch("sys.argv", args), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            code = main()
        self.assertEqual(code, 2)
        self.assertFalse(stolen.exists())

    def test_symlink_output_does_not_overwrite_another_file(self):
        self.make("a.rs", "fn safe() {}\n")
        victim = Path(self.outside.name) / "victim.txt"
        original = "VICTIM_FILE_CONTENTS_SHOULD_STAY"
        victim.write_text(original, encoding="utf-8")
        link = self.root / "report.json"
        try:
            link.symlink_to(victim)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        args = ["wolf-auditor", str(self.root), "--customer-id", "acme", "--output", str(link)]
        with patch("sys.argv", args), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            code = main()
        self.assertEqual(code, 2)
        self.assertEqual(victim.read_text(encoding="utf-8"), original)

    def test_symlink_policy_file_is_not_read(self):
        self.make("a.rs", "fn safe() {}\n")
        policy = Path(self.outside.name) / "policy.json"
        policy.write_text(json.dumps({
            "schema": "wolf-auditor.policy.v1",
            "block_at_or_above": "high",
            "require_osv": False,
        }), encoding="utf-8")
        link = self.root / "policy.json"
        gate = self.root / "gate.json"
        try:
            link.symlink_to(policy)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        args = ["wolf-auditor", str(self.root), "--policy", str(link), "--gate-output", str(gate)]
        with patch("sys.argv", args), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            code = main()
        self.assertEqual(code, 2)
        self.assertFalse(gate.exists())

    def test_ignored_file_rejects_commit_claim(self):
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        secret = "IGNORED_SECRET_VALUE_123456789"
        self.make("a.rs", "fn safe() {}\n")
        self.make(".gitignore", "*.py\n")
        self._commit_head()
        self.make("hidden.py", f'api_key = "{secret}"\n')
        sha = self.git("rev-parse", "HEAD").stdout.strip()
        report = scan(self.root, customer_id="acme", commit_claim=sha)
        self.assertEqual(report["commit_claim"]["status"], "rejected")
        self.assertFalse(report["commit_claim"]["accepted"])
        self.assertFalse(report["commit_claim"]["certification"])
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn(sha, json.dumps(report["commit_claim"]))

    def test_assume_unchanged_rejects_commit_claim(self):
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        self.make("a.rs", "fn safe() {}\n")
        self._commit_head()
        sha = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("update-index", "--assume-unchanged", "a.rs")
        self.make("a.rs", "fn safe() { /* hidden */ }\n")
        report = scan(self.root, customer_id="acme", commit_claim=sha)
        self.assertEqual(report["commit_claim"]["status"], "rejected")
        self.assertFalse(report["commit_claim"]["certification"])

    def test_skip_worktree_rejects_commit_claim(self):
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        self.make("a.rs", "fn safe() {}\n")
        self._commit_head()
        sha = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("update-index", "--skip-worktree", "a.rs")
        self.make("a.rs", "fn safe() { /* skipped */ }\n")
        report = scan(self.root, customer_id="acme", commit_claim=sha)
        self.assertEqual(report["commit_claim"]["status"], "rejected")
        self.assertFalse(report["commit_claim"]["certification"])

    def test_sparse_checkout_flag_rejects_commit_claim(self):
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        self.make("a.rs", "fn safe() {}\n")
        self._commit_head()
        sha = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("config", "core.sparseCheckout", "true")
        report = scan(self.root, customer_id="acme", commit_claim=sha)
        self.assertEqual(report["commit_claim"]["status"], "rejected")
        self.assertFalse(report["commit_claim"]["verified"])
        self.assertFalse(report["commit_claim"]["certification"])

    def test_cli_rejects_mismatched_customer_and_does_not_write_report(self):
        self.make("a.rs", "fn safe() {}\n")
        auth = self.root / "auth.json"
        auth.write_text(json.dumps({
            "schema": "wolf-auditor.customer-authorization.v1",
            "customer_id": "acme",
        }), encoding="utf-8")
        output = self.root / "report.json"
        args = ["wolf-auditor", str(self.root), "--customer-id", "beta",
                "--customer-authorization", str(auth), "--output", str(output)]
        with patch("sys.argv", args), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            code = main()
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())

    def _commit_head(self):
        self.git("init", "-b", "main")
        self.git("config", "core.autocrlf", "false")
        self.git("add", "-A")
        self.git("-c", "user.email=wolf-auditor@example.com", "-c", "user.name=WOLF AUDITOR Test",
                 "commit", "-m", "test")

    def git(self, *args):
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )


if __name__ == "__main__":
    unittest.main()
