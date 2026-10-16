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

from wolf_auditor.authorization import has_reparse_attribute, load_customer_authorization
from wolf_auditor.delta import _hash, compare_reports
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

    def test_hardlink_outside_root_is_not_scanned(self):
        secret = "HARDLINK_SECRET_VALUE_123456789"
        outside = self.make("leak.py", f'api_key = "{secret}"\n', root=Path(self.outside.name))
        inside = self.root / "leak.py"
        try:
            os.link(outside, inside)
        except OSError:
            self.skipTest("hard links unavailable")
        report = scan(self.root, customer_id="acme")
        encoded = json.dumps(report)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("POTENTIAL_HARDCODED_SECRET", encoded)
        self.assertNotIn("leak.py", [item["path"] for item in report["file_manifest"]])
        self.assertIn("hardlink_outside_root_rejected", [gap["reason"] for gap in report["coverage_gaps"]])
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertFalse(report["customer_scope"]["certification"])

    def test_hardlink_inside_root_is_still_scanned(self):
        first = self.make("a.rs", "fn safe() {}\n")
        second = self.root / "b.rs"
        try:
            os.link(first, second)
        except OSError:
            self.skipTest("hard links unavailable")
        report = scan(self.root, customer_id="acme")
        self.assertEqual(report["status"], "NO_HEURISTIC_FINDINGS")
        self.assertEqual(report["scanned_files"], 2)
        self.assertNotIn("hardlink_outside_root_rejected", [gap["reason"] for gap in report["coverage_gaps"]])
        self.assertFalse(report["customer_scope"]["certification"])

    def test_reparse_point_attribute_is_a_link(self):
        self.assertTrue(has_reparse_attribute(0x400))
        self.assertTrue(has_reparse_attribute(0x400 | 0x10))
        self.assertFalse(has_reparse_attribute(0x10))
        self.assertFalse(has_reparse_attribute(0))

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

    def test_repository_fsmonitor_is_not_executed(self):
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        self.make("a.py", "print('ok')\n")
        self._commit_head()
        sha = self.git("rev-parse", "HEAD").stdout.strip()
        marker = Path(self.outside.name) / "fsmonitor-marker"
        if os.name == "nt":
            script = Path(self.outside.name) / "fsmon.cmd"
            script.write_text(f'@echo pwned> "{marker}"\r\n', encoding="utf-8")
            command = str(script)
        else:
            script = Path(self.outside.name) / "fsmon.sh"
            script.write_text("#!/bin/sh\ntouch " + str(marker) + "\nexit 0\n", encoding="utf-8")
            script.chmod(0o755)
            command = str(script)
        self.git("config", "core.fsmonitor", command)
        report = scan(self.root, customer_id="acme", commit_claim=sha)
        self.assertFalse(marker.exists())
        self.assertEqual(report["commit_claim"]["status"], "local_head_match")
        self.assertFalse(report["commit_claim"]["certification"])

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

    def test_delta_rejects_same_directory_name_across_customers(self):
        secret = "CROSS_TENANT_SECRET_123456"
        acme = self.root / "app"
        beta = self.root / "other" / "app"
        self.make("danger.py", f'api_key = "{secret}"\n', root=acme)
        self.make("ok.py", "print('ok')\n", root=beta)
        previous = scan(acme, customer_id="acme")
        current = scan(beta, customer_id="beta")
        self.assertEqual(previous["target_directory_name"], current["target_directory_name"])
        self.assertEqual(previous["customer_scope"]["customer_id"], "acme")
        self.assertEqual(current["customer_scope"]["customer_id"], "beta")
        self.assertIn("POTENTIAL_HARDCODED_SECRET", [item["rule"] for item in previous["findings"]])
        with self.assertRaisesRegex(ValueError, "cannot compare reports from different customers"):
            compare_reports(previous, current)
        self.assertNotIn(secret, json.dumps(current))

    def test_delta_rejects_bound_report_against_unbound_report(self):
        self.make("app/ok.py", "print('ok')\n")
        bound = scan(self.root / "app", customer_id="acme")
        unbound = scan(self.root / "app")
        self.assertEqual(bound["target_directory_name"], unbound["target_directory_name"])
        self.assertFalse(unbound["customer_scope"]["bound"])
        with self.assertRaisesRegex(ValueError, "cannot compare reports from different customers"):
            compare_reports(bound, unbound)

    def test_delta_same_customer_same_directory_still_compares(self):
        app = self.root / "app"
        self.make("ok.py", "print('ok')\n", root=app)
        previous = scan(app, customer_id="acme")
        self.make("bad.py", "eval('something')\n", root=app)
        current = scan(app, customer_id="acme")
        delta = compare_reports(previous, current)
        self.assertEqual(len(delta["new_findings"]), 1)
        self.assertEqual(delta["resolved_findings"], [])
        self.assertEqual(previous["customer_scope"]["customer_id"], "acme")

    def test_delta_bound_scope_without_customer_id_is_rejected(self):
        self.make("app/ok.py", "print('ok')\n")
        previous = scan(self.root / "app", customer_id="acme")
        current = scan(self.root / "app", customer_id="acme")
        broken = json.loads(json.dumps(current))
        del broken["customer_scope"]["customer_id"]
        broken["report_sha256"] = _hash({k: v for k, v in broken.items() if k != "report_sha256"})
        with self.assertRaisesRegex(ValueError, "cannot compare reports from different customers"):
            compare_reports(previous, broken)

    def test_cli_cross_customer_delta_is_not_written(self):
        secret = "CROSS_TENANT_SECRET_123456"
        acme = self.root / "acme" / "app"
        beta = self.root / "beta" / "app"
        self.make("danger.py", f'api_key = "{secret}"\n', root=acme)
        self.make("ok.py", "print('ok')\n", root=beta)
        baseline = self.root / "baseline.json"
        baseline.write_text(json.dumps(scan(acme, customer_id="acme")), encoding="utf-8")
        output = self.root / "out" / "report.json"
        delta_path = self.root / "out" / "delta.json"
        args = [
            "wolf-auditor", str(beta), "--customer-id", "beta",
            "--baseline", str(baseline), "--output", str(output),
            "--delta-output", str(delta_path),
        ]
        stderr = StringIO()
        with patch("sys.argv", args), redirect_stdout(StringIO()), redirect_stderr(stderr):
            code = main()
        self.assertEqual(code, 2)
        self.assertIn("cannot compare reports from different customers", stderr.getvalue())
        self.assertFalse(output.exists())
        self.assertFalse(delta_path.exists())
        self.assertNotIn(secret, stderr.getvalue())

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
