"""P1 scope, false-positive, inventory and schema checks.

A schema match is not a security certification and not a vulnerability proof.
"""
import hashlib
import json
import unittest
from importlib.metadata import version
from pathlib import Path

from jsonschema.validators import validator_for

import wolf_auditor.engine as engine
from wolf_auditor.delta import verify_report
from wolf_auditor.engine import scan
from wolf_auditor.reporting import to_sarif, to_sbom

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "tests" / "fixtures" / "schemas"
SARIF_SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
CDX_SCHEMA_SHA256 = "efc54d749e32a6e16abd19394b80b4c67d846e12c782e04505130375f94ea541"
SARIF_SCHEMA_URL = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
CDX_SCHEMA_URL = (
    "https://raw.githubusercontent.com/CycloneDX/specification/1.6.1/schema/bom-1.6.schema.json"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validator(schema: dict):
    validator = validator_for(schema)
    validator.check_schema(schema)
    return validator(schema, format_checker=validator.FORMAT_CHECKER)


class P1CompletionTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.context = tempfile.TemporaryDirectory()
        self.addCleanup(self.context.cleanup)
        self.root = Path(self.context.name)

    def put(self, name, data):
        file = self.root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(data, encoding="utf-8")
        return file

    def rules(self):
        return [item["rule"] for item in scan(self.root)["findings"]]

    def test_alias_and_safe_loader_controls(self):
        self.put("alias.py", "import os as operating_system\noperating_system.system('x')\n"
                 "from os import system as run_cmd\nrun_cmd('y')\n"
                 "import subprocess as sp\nsp.run(['echo'], shell=True)\n"
                 "import builtins\nbuiltins.eval('1')\n"
                 "import marshal\nmarshal.load(None)\n")
        self.put("safe.py", "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n"
                 "yaml.safe_load(data)\n"
                 "from yaml import CSafeLoader\nyaml.load(data, Loader=CSafeLoader)\n")
        self.put("review.py", "import yaml\nyaml.load(data)\n"
                 "yaml.load(data, Loader=yaml.FullLoader)\n")
        self.put("shadow.py", "from os import system\n"
                 "def f(system):\n"
                 "    system('x')\n"
                 "system = print\n"
                 "system('z')\n")
        report = scan(self.root)
        by_path = {}
        for finding in report["findings"]:
            by_path.setdefault(finding["path"], []).append(finding["rule"])
        self.assertEqual(by_path["alias.py"], [
            "PY_OS_SYSTEM", "PY_OS_SYSTEM", "PY_SHELL_TRUE",
            "PY_DYNAMIC_EXECUTION", "PY_UNSAFE_DESERIALIZATION",
        ])
        self.assertNotIn("safe.py", by_path)
        self.assertEqual(by_path["review.py"], ["PY_YAML_LOAD_REVIEW", "PY_YAML_LOAD_REVIEW"])
        self.assertNotIn("shadow.py", by_path)

    def test_supported_calls_keep_existing_spellings(self):
        self.put("calls.py", 'eval("1")\nexec("x=1")\nimport os\nos.system("x")\n'
                 "import pickle\npickle.loads(b'a')\n"
                 "import subprocess\nsubprocess.run(['echo'], shell=False)\n"
                 "def f():\n"
                 "    import os\n"
                 "    os.system('y')\n")
        rules = self.rules()
        self.assertEqual(rules.count("PY_DYNAMIC_EXECUTION"), 2)
        self.assertEqual(rules.count("PY_OS_SYSTEM"), 2)
        self.assertIn("PY_UNSAFE_DESERIALIZATION", rules)
        self.assertNotIn("PY_SHELL_TRUE", rules)

    def test_unsupported_classes_are_not_reported_as_findings(self):
        self.put("app.py", "cursor.execute('SELECT ' + user)\n"
                 "open(path).read()\n"
                 "requests.get(url)\n"
                 "subprocess_run = None\n")
        self.put("app.js", "eval('1')\n")
        self.put("positional.py", "import subprocess\n"
                 "subprocess.run('echo x', None, None, None, True)\n")
        report = scan(self.root)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["status"], "NO_HEURISTIC_FINDINGS")
        self.assertEqual(report["scanned_files"], 2)
        self.assertEqual(report["coverage_gaps"], [])

    def test_dependency_inventory_edges(self):
        self.put("requirements.txt", "requests[security]==2.31.0\n")
        self.put("requirements-dev.txt", "-r requirements.txt\n")
        pinned = scan(self.root)
        purls = {item["purl"] for item in pinned["dependency_components"]}
        self.assertIn("pkg:pypi/requests@2.31.0", purls)
        self.assertEqual(pinned["status"], "INCOMPLETE")
        (self.root / "requirements.txt").unlink()
        (self.root / "requirements-dev.txt").unlink()

        (self.root / "Cargo.lock").write_text("not = [toml\n", encoding="utf-8")
        broken = scan(self.root)
        self.assertEqual(broken["status"], "INCOMPLETE")
        self.assertIn("dependency_manifest_parse_failed",
                      [gap["reason"] for gap in broken["coverage_gaps"]])
        self.assertEqual(broken["dependency_components"], [])

    def test_npm_lock_v1_nested_inventory(self):
        self.put("package-lock.json", json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "left-pad": {"version": "1.3.0", "dependencies": {"minimist": {"version": "1.2.5"}}},
            },
        }))
        report = scan(self.root)
        self.assertEqual(
            sorted(item["purl"] for item in report["dependency_components"]),
            ["pkg:npm/left-pad@1.3.0", "pkg:npm/minimist@1.2.5"],
        )
        self.assertEqual(report["coverage_gaps"], [])
        self.assertEqual(to_sbom(report)["specVersion"], "1.6")

    def test_evidence_joins_path_line_rule_and_source_hash(self):
        source = "import os\nos.system('x')\n"
        self.put("src/a.py", source)
        report = scan(self.root)
        self.assertTrue(verify_report(report))
        manifest = {item["path"]: item["sha256"] for item in report["file_manifest"]}
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual(finding["path"], "src/a.py")
        self.assertEqual(finding["line"], 2)
        self.assertEqual(finding["rule"], "PY_OS_SYSTEM")
        self.assertGreaterEqual(finding["line"], 1)
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        self.assertEqual(manifest[finding["path"]], digest)
        sarif = to_sarif(report)
        artifact = sarif["runs"][0]["artifacts"][0]
        self.assertEqual(artifact["location"]["uri"], "src/a.py")
        self.assertEqual(artifact["hashes"]["sha-256"], digest)
        self.assertNotIn("os.system('x')", json.dumps(sarif))
        again = scan(self.root)
        self.assertEqual(report, again)
        self.assertEqual(to_sarif(report), to_sarif(again))
        self.assertEqual(to_sbom(report), to_sbom(again))

    def test_file_budget_records_that_the_walk_stopped(self):
        original = engine.MAX_FILES
        engine.MAX_FILES = 1
        self.addCleanup(setattr, engine, "MAX_FILES", original)
        self.put("a.py", "x = 1\n")
        self.put("b.py", "y = 2\n")
        report = scan(self.root)
        reasons = [gap["reason"] for gap in report["coverage_gaps"]]
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["scanned_files"], 1)
        self.assertIn("scan_file_budget_exceeded", reasons)
        self.assertIn("scan_stopped_before_remaining_files", reasons)

    def test_published_schemas_match_pinned_bytes_and_accept_output(self):
        self.assertEqual(version("jsonschema"), "4.23.0")
        sarif_path = SCHEMA_DIR / "sarif-schema-2.1.0.json"
        cdx_path = SCHEMA_DIR / "bom-1.6.schema.json"
        self.assertEqual(_sha256(sarif_path), SARIF_SCHEMA_SHA256)
        self.assertEqual(_sha256(cdx_path), CDX_SCHEMA_SHA256)
        sarif_schema = json.loads(sarif_path.read_text(encoding="utf-8"))
        cdx_schema = json.loads(cdx_path.read_text(encoding="utf-8"))
        self.put("a.py", "import os\nos.system('x')\n")
        self.put("broken.py", "def (:\n")
        self.put("Cargo.lock", 'version = 3\n[[package]]\nname = "serde"\nversion = "1.0.1"\n')
        self.put("package-lock.json", json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {}, "node_modules/@types/node": {"version": "20.1.0"}},
        }))
        self.put("requirements.txt", "flask==3.0.0\n")
        report = scan(self.root)
        sarif = to_sarif(report)
        sbom = to_sbom(report)
        sarif_errors = list(_validator(sarif_schema).iter_errors(sarif))
        sbom_errors = list(_validator(cdx_schema).iter_errors(sbom))
        self.assertEqual(sarif_errors, [], msg=[error.message for error in sarif_errors[:5]])
        self.assertEqual(sbom_errors, [], msg=[error.message for error in sbom_errors[:5]])
        self.assertEqual(sarif["$schema"], "https://json.schemastore.org/sarif-2.1.0.json")
        self.assertTrue(SARIF_SCHEMA_URL.endswith("sarif-schema-2.1.0.json"))
        self.assertTrue(CDX_SCHEMA_URL.endswith("bom-1.6.schema.json"))

    def test_wrong_schema_version_is_rejected(self):
        sarif_schema = json.loads((SCHEMA_DIR / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
        cdx_schema = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text(encoding="utf-8"))
        self.put("a.py", "x = 1\n")
        report = scan(self.root)
        sarif = to_sarif(report)
        sarif["version"] = "0.0.0"
        self.assertTrue(list(_validator(sarif_schema).iter_errors(sarif)))
        sbom = to_sbom(report)
        sbom["bomFormat"] = "not-a-bom"
        self.assertTrue(list(_validator(cdx_schema).iter_errors(sbom)))


if __name__ == "__main__":
    unittest.main()
