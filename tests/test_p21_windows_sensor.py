"""P2.1 read-only Windows sensor. Default scan behavior stays unchanged."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolf_auditor.engine import scan
from wolf_auditor.windows_native import analyze_windows_source, runtime_inspection
from wolf_auditor.windows_sensor import PROCESS_QUERY_LIMITED_INFORMATION, inspect_process

ROOT = Path(__file__).resolve().parents[1]
_FORBIDDEN_KEYS = {
    "memory", "dump", "command_line", "environment", "image_path", "image_name",
    "stdout", "stderr", "bytes",
}
_FORBIDDEN_STATUS = {"PASS", "REVIEWED", "APPROVED"}


class _Api:
    def __init__(self, handle: int, error: int = 0, ok: bool = True, code: int = 259) -> None:
        self.handle = handle
        self.error = error
        self.ok = ok
        self.code = code
        self.rights: int | None = None
        self.closed = False

    def open_process(self, rights: int, pid: int) -> int:
        self.rights = rights
        self.pid = pid
        return self.handle

    def exit_code(self, handle: int) -> tuple[bool, int]:
        return self.ok, self.code

    def close(self, handle: int) -> None:
        self.closed = True

    def last_error(self) -> int:
        return self.error


class WindowsSensorTests(unittest.TestCase):
    def tearDown(self) -> None:
        fixture = getattr(self, "_child", None)
        if fixture is not None and fixture.poll() is None:
            fixture.kill()
            fixture.wait(timeout=5)

    def test_default_is_off_and_default_scan_is_unchanged(self) -> None:
        with patch("wolf_auditor.windows_sensor._query_windows", side_effect=AssertionError("opened")):
            result = inspect_process(1, enabled=False)
        self.assertEqual(result["status"], "NOT_EXECUTED")
        self.assertEqual(result["reason"], "sensor_disabled")
        self.assertFalse(result["process_access"])
        self.assertFalse(result["memory_read"])
        self.assertFalse(result["coverage_claim"])
        self.assertNotIn(result["status"], _FORBIDDEN_STATUS)
        info = runtime_inspection()
        self.assertEqual(info["status"], "NOT_EXECUTED")
        self.assertFalse(info["coverage_claim"])
        findings, gaps = analyze_windows_source("a.c", "int main(){ OpenProcess(0,0,0); }\n")
        self.assertEqual(gaps[0]["reason"], "windows_native_runtime_not_executed")
        self.assertEqual(findings[0]["rule"], "WIN_PROCESS_MEMORY")

    def test_non_windows_opt_in_cannot_pass(self) -> None:
        if sys.platform == "win32":
            self.skipTest("unsupported-platform contract is enforced on other hosts")
        with patch("wolf_auditor.windows_sensor._query_windows", side_effect=AssertionError("opened")):
            result = inspect_process(1, enabled=True)
        self.assertEqual(result["status"], "NOT_EXECUTED")
        self.assertEqual(result["reason"], "windows_sensor_unsupported_platform")
        self.assertFalse(result["process_access"])
        self.assertFalse(result["memory_read"])
        self.assertFalse(result["dump_collected"])
        self.assertEqual(result["access_rights"], [])
        self._assert_minimized(result)

    def test_invalid_pid_and_non_boolean_opt_in_fail_closed(self) -> None:
        for pid in (0, -1, True, "4", 0x100000000):
            result = inspect_process(pid, enabled=True)
            self.assertIn(result["status"], {"NOT_EXECUTED", "INCOMPLETE"})
            self.assertFalse(result["process_access"])
            self.assertNotIn(result["status"], _FORBIDDEN_STATUS)
        for enabled in (1, "true", None):
            result = inspect_process(4, enabled=enabled)
            self.assertEqual(result["reason"], "sensor_disabled")
            self.assertFalse(result["process_access"])

    def test_query_uses_limited_rights_and_hides_exit_code(self) -> None:
        from wolf_auditor.windows_sensor import _query_windows

        running = _Api(7, code=259)
        queried = _query_windows(42, running)
        self.assertEqual(running.rights, PROCESS_QUERY_LIMITED_INFORMATION)
        self.assertEqual(PROCESS_QUERY_LIMITED_INFORMATION, 0x1000)
        self.assertTrue(running.closed)
        self.assertEqual(queried["status"], "QUERY_LIMITED")
        self.assertEqual(queried["process_state"], "running")
        self.assertNotIn("259", json.dumps(queried))
        self.assertFalse(queried["coverage_claim"])
        self._assert_minimized(queried)
        exited = _query_windows(42, _Api(7, code=1))
        self.assertEqual(exited["process_state"], "exited")
        self.assertNotIn(exited["status"], _FORBIDDEN_STATUS)

    def test_access_denied_missing_process_and_exit_race(self) -> None:
        from wolf_auditor.windows_sensor import _query_windows

        denied = _query_windows(9, _Api(0, error=5))
        self.assertEqual(denied["status"], "NOT_EXECUTED")
        self.assertEqual(denied["reason"], "access_denied")
        self.assertFalse(denied["process_access"])
        missing = _query_windows(9, _Api(0, error=87))
        self.assertEqual(missing["reason"], "process_not_found")
        self.assertEqual(missing["status"], "NOT_EXECUTED")
        other = _query_windows(9, _Api(0, error=6))
        self.assertEqual(other["status"], "INCOMPLETE")
        self.assertEqual(other["reason"], "open_process_failed")
        race = _query_windows(9, _Api(7, ok=False))
        self.assertEqual(race["status"], "INCOMPLETE")
        self.assertEqual(race["reason"], "process_exit_race")
        self.assertTrue(race["process_access"])
        self.assertFalse(race["memory_read"])
        self._assert_minimized(denied)
        self._assert_minimized(race)

    def test_module_does_not_name_memory_read_apis(self) -> None:
        source = (ROOT / "wolf_auditor" / "windows_sensor.py").read_text(encoding="utf-8")
        for banned in ("ReadProcessMemory", "WriteProcessMemory", "MiniDump", "PROCESS_VM_READ", "PROCESS_ALL_ACCESS"):
            self.assertNotIn(banned, source)

    def test_repository_scan_does_not_open_a_process(self) -> None:
        target = Path(tempfile.mkdtemp())
        try:
            (target / "a.c").write_text("void f(){ OpenProcess(0,0,0); }\n", encoding="utf-8")
            with patch("wolf_auditor.windows_sensor.inspect_process", side_effect=AssertionError("sensor called")):
                report = scan(target)
            self.assertEqual(report["status"], "INCOMPLETE")
            self.assertEqual(report["analysis_limits"]["windows_native_runtime"], "not_executed_read_only_no_process_access")
            self.assertNotIn(report["status"], _FORBIDDEN_STATUS)
        finally:
            shutil.rmtree(target, ignore_errors=True)

    @unittest.skipUnless(sys.platform == "win32", "controlled fixture runs only on the Windows runner")
    def test_owned_fixture_is_query_limited(self) -> None:
        self._child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        result = inspect_process(self._child.pid, enabled=True)
        self.assertEqual(result["status"], "QUERY_LIMITED")
        self.assertEqual(result["process_state"], "running")
        self.assertEqual(result["access_rights"], ["PROCESS_QUERY_LIMITED_INFORMATION"])
        self.assertFalse(result["memory_read"])
        self.assertFalse(result["dump_collected"])
        self.assertFalse(result["coverage_claim"])
        self.assertNotIn(result["status"], _FORBIDDEN_STATUS)
        self._assert_minimized(result)
        self._child.kill()
        self._child.wait(timeout=5)
        raced = inspect_process(self._child.pid, enabled=True)
        self.assertIn(raced["status"], {"QUERY_LIMITED", "NOT_EXECUTED", "INCOMPLETE"})
        self.assertNotIn(raced["status"], _FORBIDDEN_STATUS)
        if raced["status"] == "QUERY_LIMITED":
            self.assertEqual(raced["process_state"], "exited")
        self.assertFalse(raced["memory_read"])
        self._assert_minimized(raced)

    def _assert_minimized(self, result: dict) -> None:
        self.assertTrue(_FORBIDDEN_KEYS.isdisjoint(result))
        encoded = json.dumps(result)
        self.assertNotIn("SENTINEL", encoded)
        self.assertLessEqual(len(encoded), 800)
