"""Adversarial fixtures for SAST, dependency inventory, SBOM, SARIF and fail-closed."""
import json
import tempfile
import unittest
from pathlib import Path
from wolf_auditor.engine import scan
from wolf_auditor.reporting import to_sarif, to_sbom

class ExtendedAuditTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory()
        self.addCleanup(self.context.cleanup)
        self.root = Path(self.context.name)

    def put(self, name, data):
        file = self.root / name
        file.parent.mkdir(exist_ok=True, parents=True)
        file.write_text(data, encoding="utf-8")
        return file

    def test_ast_not_comments_and_strings(self):
        self.put("foo.py", 'print("eval(1)")\n# eval("fake")\neval("1+1")\n'
                 'import subprocess\nsubprocess.run("echo hi", shell=True)\n')
        self.assertEqual([f["rule"] for f in scan(self.root)["findings"]],
                         ["PY_DYNAMIC_EXECUTION", "PY_SHELL_TRUE"])

    def test_ast_syntax_error_fails_closed(self):
        self.put("broken.py", "def x(:\n")
        report = scan(self.root)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["coverage_gaps"][0]["reason"], "python_parse_failed")

    def test_unsafe_deserialization(self):
        self.put("unsafe.py", 'import pickle\npickle.loads(b"xxx")\n')
        self.assertIn("PY_UNSAFE_DESERIALIZATION",
                      [f["rule"] for f in scan(self.root)["findings"]])

    def test_safe_subprocess_configuration(self):
        self.put("safe.py", 'import subprocess\nsubprocess.run(["echo"], shell=False)\n')
        self.assertNotIn("PY_SHELL_TRUE", [f["rule"] for f in scan(self.root)["findings"]])

    def test_workflow_event_expression_in_run(self):
        self.put(".github/workflows/ci.yml",
                 'name: Test\non: pull_request_target\njobs:\n  build:\n    permissions: write-all\n'
                 '    steps:\n      - run: |\n          echo "GITHUB_EXPR"\n'.replace(
                     "GITHUB_EXPR", "$" + "{{ github.event.pull_request.title }}"))
        rules = [f["rule"] for f in scan(self.root)["findings"]]
        self.assertIn("ACTIONS_EVENT_EXPRESSION_IN_RUN", rules)
        self.assertIn("ACTIONS_WRITE_ALL_PERMISSIONS", rules)

    def test_dockerfile_rules(self):
        self.put("Dockerfile", "FROM python:latest\nUSER root\n")
        self.assertEqual({f["rule"] for f in scan(self.root)["findings"]},
                         {"DOCKER_MUTABLE_LATEST", "DOCKER_ROOT_USER"})

    def test_cargo_lock_inventory(self):
        self.put("Cargo.lock", 'version = 3\n[[package]]\nname = "serde"\nversion = "1.0.1"\n')
        report = scan(self.root)
        self.assertEqual(report["status"], "NO_HEURISTIC_FINDINGS")
        self.assertEqual(report["dependency_components"][0]["purl"], "pkg:cargo/serde@1.0.1")
        self.assertEqual(to_sbom(report)["components"][0]["name"], "serde")

    def test_npm_lock_inventory(self):
        self.put("package-lock.json", json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {}, "node_modules/@types/node": {"version": "20.1.0"}},
        }))
        items = scan(self.root)["dependency_components"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["purl"], "pkg:npm/@types/node@20.1.0")

    def test_unpinned_requirements_warns(self):
        self.put("requirements.txt", "requests>=2.0\nflask==3.0.0\n")
        report = scan(self.root)
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertEqual(len(report["dependency_components"]), 2)
        self.assertEqual([f["rule"] for f in report["findings"]],
                         ["PYTHON_DEPENDENCY_NOT_EXACTLY_PINNED"])

    def test_nested_requirements_fails_closed(self):
        self.put("requirements-dev.txt", "-r requirements.txt\n")
        report = scan(self.root)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["coverage_gaps"][0]["reason"],
                         "requirements_directive_or_url_unresolved")

    def test_malformed_lock_fails_closed(self):
        self.put("package-lock.json", "{bad-json")
        report = scan(self.root)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["coverage_gaps"][0]["reason"],
                         "dependency_manifest_parse_failed")

    def test_sarif_and_sbom_redact_secrets(self):
        secret = "FAKE_SECRET_VALUE_FOR_TESTS_888888"
        self.put("secrets.py", f'secret_key = "{secret}"\n')
        self.put("requirements.txt", "requests==2.1.0\n")
        report = scan(self.root)
        self.assertNotIn(secret, json.dumps(to_sarif(report)))
        self.assertNotIn(secret, json.dumps(to_sbom(report)))
        sarif = to_sarif(report)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"],
                         "POTENTIAL_HARDCODED_SECRET")
        self.assertEqual(to_sbom(report)["specVersion"], "1.6")

    def test_reproducible_reports(self):
        self.put("Cargo.lock", 'version = 3\n[[package]]\nname = "serde"\nversion = "1.0.1"\n')
        report = scan(self.root)
        again = scan(self.root)
        self.assertEqual(report, again)
        self.assertEqual(to_sarif(report), to_sarif(again))
        self.assertEqual(to_sbom(report), to_sbom(again))

    def test_no_source_line_in_evidence(self):
        self.put("source.py", 'import os\nos.system("danger-should-not-appear")\n')
        self.assertNotIn("danger-should-not-appear", json.dumps(scan(self.root)))

if __name__ == "__main__":
    unittest.main()
