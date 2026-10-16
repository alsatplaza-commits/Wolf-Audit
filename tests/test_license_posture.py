"""License posture checks. These results are not a legal clearance."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from wolf_auditor.engine import scan

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL = ROOT / "docs" / "licensing" / "APACHE-2.0.OFFICIAL.txt"
OFFICIAL_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
FORBIDDEN_CLAIMS = ("PASS", "REVIEWED", "VERIFIED")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dependency_signal(license_id: str) -> str:
    """Label a declared dependency id. This is not a legal ruling."""
    if license_id in {"GPL-2.0-only", "GPL-2.0"}:
        return "LICENSE_CONFLICT_CANDIDATE"
    if license_id in {"", "UNKNOWN"}:
        return "OWNERSHIP_UNKNOWN"
    if license_id == "MIT":
        return "METADATA_ONLY"
    return "HUMAN_REVIEW_REQUIRED"


class LicensePostureTests(unittest.TestCase):
    def test_official_apache_text_matches_published_bytes(self):
        self.assertTrue(OFFICIAL.is_file())
        self.assertEqual(sha256(OFFICIAL), OFFICIAL_SHA256)
        text = OFFICIAL.read_text(encoding="utf-8")
        self.assertIn("Apache License", text)
        self.assertIn("Version 2.0, January 2004", text)
        self.assertNotIn("Copyright holder:", text)

    def test_wrong_license_bytes_do_not_match(self):
        altered = bytearray(OFFICIAL.read_bytes())
        altered[-2] = (altered[-2] + 1) % 256
        self.assertNotEqual(hashlib.sha256(altered).hexdigest(), OFFICIAL_SHA256)

    def test_root_license_grant_is_absent(self):
        for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "NOTICE"):
            self.assertFalse((ROOT / name).exists(), name)
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertNotIn("Apache-2.0", project)
        self.assertNotIn("license", project.lower())
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("No open-source license has been selected yet.", readme)

    def test_source_files_have_no_spdx_grant(self):
        for path in (ROOT / "wolf_auditor").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("SPDX-License-Identifier", text)
            self.assertNotIn("Apache License", text)

    def test_drafts_stay_blocked_and_do_not_claim_clearance(self):
        status = (ROOT / "docs" / "licensing" / "STATUS.md").read_text(encoding="utf-8")
        notice = (ROOT / "docs" / "licensing" / "NOTICE.DRAFT.txt").read_text(encoding="utf-8")
        third = (ROOT / "docs" / "licensing" / "THIRD_PARTY_NOTICES.DRAFT.txt").read_text(encoding="utf-8")
        for document in (status, notice, third):
            self.assertIn("NOT IN FORCE", document)
            self.assertIn("UNKNOWN", document)
            for claim in FORBIDDEN_CLAIMS:
                self.assertNotIn(claim, document)

    def test_missing_holder_and_gpl2_dependency_are_not_clearance(self):
        self.assertEqual(dependency_signal(""), "OWNERSHIP_UNKNOWN")
        self.assertEqual(dependency_signal("GPL-2.0-only"), "LICENSE_CONFLICT_CANDIDATE")
        self.assertEqual(dependency_signal("MIT"), "METADATA_ONLY")
        for label in (
            dependency_signal(""),
            dependency_signal("GPL-2.0-only"),
            dependency_signal("MIT"),
        ):
            for claim in FORBIDDEN_CLAIMS:
                self.assertNotIn(claim, label)

    def test_scan_behavior_is_unchanged_by_license_drafts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.py").write_text("print('ok')\n", encoding="utf-8")
            report = scan(root)
        self.assertEqual(report["schema"], "wolf-auditor.evidence.v1")
        self.assertNotIn("license_grant", report)
        self.assertNotIn(report["status"], FORBIDDEN_CLAIMS)
