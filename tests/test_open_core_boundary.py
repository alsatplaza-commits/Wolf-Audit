"""The public engine must run without the private Enterprise product."""

import ast
import importlib.util
import tempfile
import unittest
from pathlib import Path

from wolf_auditor.engine import scan

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "wolf_auditor"
ALLOWED_IMPORTS = {
    "__future__",
    "argparse",
    "ast",
    "copy",
    "errno",
    "hashlib",
    "json",
    "os",
    "pathlib",
    "re",
    "stat",
    "subprocess",
    "sys",
    "tomllib",
    "typing",
    "urllib",
}
FORBIDDEN_MODULES = {
    "billing",
    "consent",
    "enterprise",
    "licensing",
    "panel",
    "wolf_audit_enterprise",
}


class OpenCoreBoundaryTests(unittest.TestCase):
    def test_core_imports_are_stdlib_or_local(self):
        modules = sorted(PACKAGE.glob("*.py"))
        self.assertGreaterEqual(len(modules), 1)
        for path in modules:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module or ""]
                else:
                    continue
                for name in names:
                    top = name.split(".", 1)[0]
                    self.assertIn(top, ALLOWED_IMPORTS, f"{path.name} imports {name}")
                    self.assertNotIn(top, FORBIDDEN_MODULES)

    def test_enterprise_product_is_not_importable_or_vendored(self):
        self.assertIsNone(importlib.util.find_spec("wolf_audit_enterprise"))
        present = {path.name for path in PACKAGE.glob("*.py")}
        for banned in ("billing.py", "consent.py", "licensing.py", "panel.py", "workers.py"):
            self.assertNotIn(banned, present)
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
        self.assertNotIn("wolf-audit-enterprise", project)
        self.assertNotIn("wolf_audit_enterprise", project)

    def test_scan_completes_without_an_enterprise_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.py").write_text("print('ok')\n", encoding="utf-8")
            report = scan(root)
        self.assertEqual(report["schema"], "wolf-auditor.evidence.v1")
        self.assertFalse(report["customer_scope"]["certification"])
        self.assertIsNone(importlib.util.find_spec("wolf_audit_enterprise"))
