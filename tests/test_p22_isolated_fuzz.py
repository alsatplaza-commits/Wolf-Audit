"""P2.2 allowlisted static-ELF fuzzing. The default scan does not call it."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolf_auditor.engine import scan
from wolf_auditor.isolated_fuzz import planned_payloads, probe_isolation, run_authorized_target

_SEED = b"wolf-p22-seed"
_KW = {
    "seed": _SEED,
    "iterations": 1,
    "timeout_seconds": 2,
    "max_input_bytes": 8,
    "max_memory_bytes": 64 * 1024 * 1024,
}


class IsolatedFuzzTests(unittest.TestCase):
    def test_default_scan_and_disabled_runner_do_not_execute(self) -> None:
        target = Path(tempfile.mkdtemp())
        try:
            (target / "app.py").write_text("print('ok')\n", encoding="utf-8")
            report = scan(target)
            self.assertNotIn("isolated_fuzz", json.dumps(report["analysis_limits"]))
            self.assertEqual(report["analysis_limits"]["fuzz_on_target"], "not_executed_untrusted_target_not_run")
            self.assertFalse(report["analysis_limits"]["coverage_claim"])
        finally:
            shutil.rmtree(target)
        engine = (Path(__file__).resolve().parents[1] / "wolf_auditor" / "engine.py").read_text(encoding="utf-8")
        self.assertNotIn("isolated_fuzz", engine)
        with patch("wolf_auditor.isolated_fuzz.subprocess.run", side_effect=AssertionError("executed")):
            result = run_authorized_target(enabled=False, target="/tmp/tool", allowlist=["/tmp"], **_KW)
        self.assertEqual(result["status"], "NOT_EXECUTED")
        self.assertFalse(result["executed"])
        self.assertFalse(result["coverage_claim"])
        self.assertNotEqual(result["status"], "PASS")

    def test_network_unlisted_symlink_and_traversal_are_refused(self) -> None:
        root = Path(tempfile.mkdtemp())
        outside = Path(tempfile.mkdtemp())
        try:
            tool = root / "tool"
            tool.write_bytes(b"not an elf")
            escaped = outside / "escaped"
            link = root / "link"
            link.symlink_to(escaped)
            with patch("wolf_auditor.isolated_fuzz.subprocess.run", side_effect=AssertionError("executed")):
                networked = run_authorized_target(
                    enabled=True, target=tool, allowlist=[root], network=True, **_KW,
                )
                outsider = run_authorized_target(
                    enabled=True, target=outside / "missing", allowlist=[root], network=False, **_KW,
                )
                linked = run_authorized_target(
                    enabled=True, target=link, allowlist=[root], network=False, **_KW,
                )
                climbed = run_authorized_target(
                    enabled=True, target=root / ".." / outside.name / "escaped",
                    allowlist=[root], network=False, **_KW,
                )
                quoted = run_authorized_target(
                    enabled=True, target=str(root / "tool;touch"), allowlist=[root], network=False, **_KW,
                )
            self.assertEqual(networked["status"], "BLOCK")
            self.assertEqual(networked["reason"], "network_not_permitted")
            for refused in (outsider, linked, climbed, quoted):
                self.assertIn(refused["status"], {"BLOCK", "INCOMPLETE"})
                self.assertFalse(refused["executed"])
                self.assertFalse(refused["coverage_claim"])
                self.assertNotIn(refused["status"], {"PASS", "REVIEWED", "APPROVED"})
            self.assertFalse(escaped.exists())
        finally:
            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(outside, ignore_errors=True)

    def test_invalid_budget_and_script_do_not_run(self) -> None:
        root = Path(tempfile.mkdtemp())
        try:
            script = root / "run.sh"
            marker = root / "marker"
            script.write_text("#!/bin/sh\ntouch '%s'\n" % marker, encoding="utf-8")
            os.chmod(script, 0o755)
            with patch("wolf_auditor.isolated_fuzz.subprocess.run", side_effect=AssertionError("executed")):
                bad_seed = run_authorized_target(
                    enabled=True, target=script, allowlist=[root], network=False,
                    seed="seed", iterations=1, timeout_seconds=1, max_input_bytes=4, max_memory_bytes=_KW["max_memory_bytes"],
                )
                tiny = run_authorized_target(
                    enabled=True, target=script, allowlist=[root], network=False,
                    seed=_SEED, iterations=1, timeout_seconds=1, max_input_bytes=4, max_memory_bytes=1024,
                )
                text = run_authorized_target(
                    enabled=True, target=script, allowlist=[root], network=False, **_KW,
                )
            self.assertEqual(bad_seed["reason"], "invalid_seed")
            self.assertEqual(tiny["status"], "RESOURCE_LIMIT")
            self.assertEqual(text["reason"], "dynamic_or_non_elf_target_not_isolated")
            self.assertFalse(text["executed"])
            self.assertFalse(marker.exists())
            self.assertNotIn("SENTINEL", json.dumps(text))
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_unavailable_isolation_does_not_start_a_static_target(self) -> None:
        binary = _static_binary("int main(void){return 0;}\n")
        if binary is None:
            probe = probe_isolation()
            self.assertFalse(probe["available"] and shutil.which("gcc"))
            refused = run_authorized_target(
                enabled=True, target=__file__, allowlist=[Path(__file__).resolve().parent], network=False, **_KW,
            )
            self.assertFalse(refused["executed"])
            self.assertNotEqual(refused["status"], "PASS")
            return
        try:
            with patch("wolf_auditor.isolated_fuzz.probe_isolation", return_value={
                "available": False, "network_isolated": False, "filesystem_isolated": False,
                "mechanism": None, "reason": "namespace_probe_failed",
            }):
                result = run_authorized_target(
                    enabled=True, target=binary, allowlist=[binary.parent], network=False, **_KW,
                )
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertEqual(result["reason"], "namespace_probe_failed")
            self.assertFalse(result["executed"])
            self.assertFalse(result["coverage_claim"])
        finally:
            shutil.rmtree(binary.parent, ignore_errors=True)

    def test_payload_plan_is_deterministic_and_redacted(self) -> None:
        left = planned_payloads(_SEED, 3, 8)
        right = planned_payloads(_SEED, 3, 8)
        self.assertEqual(left, right)
        self.assertNotEqual(left, planned_payloads(b"other-seed", 3, 8))

    def test_live_static_target_is_jailed_redacted_and_replayable(self) -> None:
        probe = probe_isolation()
        if _linux_toolchain():
            self.assertTrue(probe["available"], probe)
        if not probe["available"]:
            result = run_authorized_target(
                enabled=True, target=__file__, allowlist=[Path(__file__).resolve().parent], network=False, **_KW,
            )
            self.assertFalse(result["executed"])
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertFalse(result["coverage_claim"])
            return
        marker_dir = Path(tempfile.mkdtemp())
        marker = marker_dir / "host-marker"
        root = Path(tempfile.mkdtemp())
        try:
            os.environ["WOLF_P22_SENTINEL_ENV"] = "SENTINEL_ENV_VALUE"
            code = (
                "#include <stdio.h>\n"
                "int main(void){FILE *h=fopen(\"%s\",\"w\");"
                "if(h){fputs(\"x\",h);fclose(h);}fputs(\"SENTINEL_LEAK_VALUE\\n\",stdout);return 0;}\n"
            ) % marker
            binary = _static_binary(code, directory=root)
            self.assertIsNotNone(binary)
            corpus = root / "corpus"
            corpus.mkdir()
            result = run_authorized_target(
                enabled=True, target=binary, allowlist=[root], corpus_dir=corpus, network=False, **_KW,
            )
            again = run_authorized_target(
                enabled=True, target=binary, allowlist=[root], network=False, **_KW,
            )
            encoded = json.dumps(result)
            self.assertEqual(result["status"], "COMPLETE")
            self.assertTrue(result["executed"])
            self.assertFalse(result["coverage_claim"])
            self.assertNotIn(result["status"], {"PASS", "REVIEWED", "APPROVED"})
            self.assertNotIn("SENTINEL_LEAK_VALUE", encoded)
            self.assertNotIn("SENTINEL_ENV_VALUE", encoded)
            self.assertNotIn("stdout", result)
            self.assertFalse(marker.exists())
            self.assertEqual(result["replay"], again["replay"])
            self.assertTrue(result["replay"][0]["payload_sha256"])
            payload = planned_payloads(_SEED, 1, 8)[0]
            self.assertNotIn(payload.hex(), encoded)
            stored = (corpus / "0.payload").read_text(encoding="ascii")
            self.assertEqual(stored, payload.hex())
            self.assertNotIn(stored, encoded)
        finally:
            os.environ.pop("WOLF_P22_SENTINEL_ENV", None)
            shutil.rmtree(marker_dir, ignore_errors=True)
            shutil.rmtree(root, ignore_errors=True)

    def test_crash_and_timeout_are_distinct(self) -> None:
        probe = probe_isolation()
        if _linux_toolchain():
            self.assertTrue(probe["available"], probe)
        if not probe["available"]:
            self.assertIn(probe["reason"], {"posix_namespace_unavailable", "namespace_probe_failed", "unshare_missing"})
            return
        root = Path(tempfile.mkdtemp())
        try:
            crash = _static_binary("int main(void){return 9;}\n", directory=root, name="crash")
            hang = _static_binary("#include <unistd.h>\nint main(void){for(;;)pause();}\n", directory=root, name="hang")
            self.assertIsNotNone(crash)
            self.assertIsNotNone(hang)
            crashed = run_authorized_target(
                enabled=True, target=crash, allowlist=[root], network=False,
                seed=_SEED, iterations=1, timeout_seconds=2, max_input_bytes=4,
                max_memory_bytes=_KW["max_memory_bytes"],
            )
            timed = run_authorized_target(
                enabled=True, target=hang, allowlist=[root], network=False,
                seed=_SEED, iterations=1, timeout_seconds=1, max_input_bytes=4,
                max_memory_bytes=_KW["max_memory_bytes"],
            )
            self.assertEqual(crashed["status"], "CRASH")
            self.assertEqual(crashed["replay"][0]["classification"], "CRASH")
            self.assertEqual(timed["status"], "TIMEOUT")
            self.assertEqual(timed["replay"][0]["classification"], "TIMEOUT")
            self.assertFalse(crashed["coverage_claim"])
            self.assertFalse(timed["coverage_claim"])
            self.assertNotEqual(crashed["status"], timed["status"])
        finally:
            shutil.rmtree(root, ignore_errors=True)


def _linux_toolchain() -> bool:
    return sys.platform.startswith("linux") and shutil.which("unshare") is not None and shutil.which("gcc") is not None


def _static_binary(code: str, directory: Path | None = None, name: str = "tool") -> Path | None:
    compiler = shutil.which("gcc")
    if compiler is None:
        return None
    own_dir = directory is None
    root = Path(tempfile.mkdtemp()) if directory is None else directory
    source = root / f"{name}.c"
    binary = root / name
    source.write_text(code, encoding="utf-8")
    compiled = subprocess.run(
        [compiler, "-static", "-O2", "-o", str(binary), str(source)],
        capture_output=True, check=False,
    )
    if compiled.returncode != 0 or not binary.is_file():
        if own_dir:
            shutil.rmtree(root, ignore_errors=True)
        return None
    return binary
