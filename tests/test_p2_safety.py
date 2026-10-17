"""P2 heuristic contracts: Rust FFI inventory, Windows source inventory, fuzz limits.

These tests do not certify a target. Policy PASS is not independent approval.
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from wolf_auditor.engine import scan
from wolf_auditor.fuzz_control import run_controlled_fuzz
from wolf_auditor.policy import evaluate
from wolf_auditor.rust_safety import analyze_rust
from wolf_auditor.windows_native import analyze_windows_source, runtime_inspection

HIGH = {"schema": "wolf-auditor.policy.v1", "block_at_or_above": "high", "require_osv": False}


class P2SafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def make(self, name: str, text: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_rust_comment_unsafe_is_not_code(self):
        findings, gaps = analyze_rust("a.rs", "// unsafe { hack(); }\n/* unsafe fn hidden() {} */\nfn safe() {}\n")
        self.assertEqual(findings, [])
        self.assertEqual(gaps, [])

    def test_rust_string_ffi_text_is_not_code(self):
        source = 'fn main() {\n    let s = "extern \\"system\\" #[unsafe(no_mangle)]";\n    let raw = r#"unsafe { *mut u8 static mut X: i32 }"#;\n}\n'
        findings, gaps = analyze_rust("a.rs", source)
        self.assertEqual(findings, [])
        self.assertEqual(gaps, [])
        report = json.dumps(analyze_rust("a.rs", source))
        self.assertNotIn("no_mangle", report)

    def test_real_unsafe_block_is_review_not_exploit(self):
        self.make("lib.rs", "fn go() { unsafe { foreign(); } }\n")
        report = scan(self.root)
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        finding = report["findings"][0]
        self.assertEqual(finding["rule"], "RUST_UNSAFE_INVENTORY")
        self.assertEqual(finding["severity"], "review")
        self.assertEqual(finding["line"], 1)
        self.assertFalse(finding["verified_exploit"])
        self.assertNotIn("foreign", json.dumps(finding))

    def test_unsafe_attribute_no_mangle(self):
        findings, gaps = analyze_rust("a.rs", '#[unsafe(no_mangle)]\nfn exported() {}\n')
        self.assertEqual(gaps, [])
        rules = {item["rule"] for item in findings}
        self.assertIn("RUST_FFI_SYMBOL", rules)
        self.assertIn("RUST_UNSAFE_INVENTORY", rules)
        self.assertTrue(all(item["verified_exploit"] is False for item in findings))

    def test_extern_system_boundary(self):
        findings, gaps = analyze_rust("a.rs", 'extern "system" {\n    fn OpenProcess();\n}\nextern crate serde;\n')
        self.assertEqual(gaps, [])
        self.assertEqual(findings[0]["rule"], "RUST_FFI_BOUNDARY")
        self.assertEqual(findings[0]["line"], 1)
        self.assertEqual(len(findings), 1)

    def test_ffi_symbol_link_and_export_names_are_redacted(self):
        marker = "export_symbol_marker_value"
        source = f'#[export_name = "{marker}"]\n#[link_name = "{marker}"]\nfn x() {{}}\n'
        findings, gaps = analyze_rust("a.rs", source)
        self.assertEqual(gaps, [])
        self.assertGreaterEqual(len(findings), 2)
        self.assertTrue(all(item["rule"] == "RUST_FFI_SYMBOL" for item in findings))
        self.assertNotIn(marker, json.dumps(findings))

    def test_broken_rust_is_incomplete_not_pass(self):
        findings, gaps = analyze_rust("a.rs", 'let s = "unsafe { extern \\"system\\";\n')
        self.assertEqual(findings, [])
        self.assertEqual(gaps[0]["reason"], "rust_heuristic_unclosed_string")
        self.make("broken.rs", 'let s = "unsafe {\n')
        report = scan(self.root)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertNotEqual(report["status"], "NO_HEURISTIC_FINDINGS")
        self.assertNotIn("RUST_UNSAFE_INVENTORY", [item["rule"] for item in report["findings"]])

    def test_raw_pointer_and_static_mut_and_risky_call(self):
        source = 'static mut FLAG: i32 = 0;\nfn f(p: *mut u8) { std::mem::transmute::<u8, u8>(1); let _ = "transmute(1)"; }\n'
        findings, _gaps = analyze_rust("a.rs", source)
        rules = {item["rule"] for item in findings}
        self.assertIn("RUST_STATIC_MUT", rules)
        self.assertIn("RUST_RAW_POINTER", rules)
        self.assertIn("RUST_FFI_RISKY_CALL", rules)
        self.assertEqual(sum(1 for item in findings if item["rule"] == "RUST_FFI_RISKY_CALL"), 1)

    def test_deterministic_fuzz_repeats_and_does_not_claim_coverage(self):
        def capture(box):
            def target(payload: bytes) -> None:
                box.append(payload)
            return target

        first: list[bytes] = []
        second: list[bytes] = []
        kwargs = dict(seed=b"seed-1", iterations=6, timeout_seconds=1, max_input_bytes=8)
        left = run_controlled_fuzz(capture(first), **kwargs)
        right = run_controlled_fuzz(capture(second), **kwargs)
        self.assertEqual(first, second)
        self.assertEqual(left["status"], "COMPLETE")
        self.assertFalse(left["coverage_claim"])
        self.assertFalse(right["coverage_claim"])
        self.assertTrue(left["callable_invoked"])
        other: list[bytes] = []
        run_controlled_fuzz(capture(other), seed=b"seed-2", iterations=6, timeout_seconds=1, max_input_bytes=8)
        self.assertNotEqual(first, other)

    def test_non_bytes_seed_is_rejected(self):
        calls = []
        for seed in ("seed", 7, None, bytearray()):
            result = run_controlled_fuzz(lambda _payload: calls.append(1), seed=seed, iterations=1, timeout_seconds=1, max_input_bytes=4)
            self.assertEqual(result["status"], "INVALID_SEED")
            self.assertFalse(result["coverage_claim"])
            self.assertFalse(result["callable_invoked"])
        self.assertEqual(calls, [])
        empty = run_controlled_fuzz(lambda _payload: calls.append(1), seed=b"", iterations=1, timeout_seconds=1, max_input_bytes=4)
        self.assertEqual(empty["status"], "INVALID_SEED")
        self.assertEqual(calls, [])

    def test_zero_and_negative_iterations_are_rejected(self):
        def fail(_payload: bytes) -> None:
            raise AssertionError("target must not run")

        for iterations in (0, -1, True):
            result = run_controlled_fuzz(fail, seed=b"abc", iterations=iterations, timeout_seconds=1, max_input_bytes=4)
            self.assertEqual(result["status"], "INVALID_LIMIT")
            self.assertFalse(result["coverage_claim"])
            self.assertEqual(result["iterations_run"], 0)
        negative_timeout = run_controlled_fuzz(fail, seed=b"abc", iterations=1, timeout_seconds=-1, max_input_bytes=4)
        self.assertEqual(negative_timeout["status"], "INVALID_LIMIT")
        zero_bytes = run_controlled_fuzz(fail, seed=b"abc", iterations=1, timeout_seconds=1, max_input_bytes=0)
        self.assertEqual(zero_bytes["status"], "INVALID_LIMIT")

    def test_timeout_crash_and_memory_limit_are_distinct_and_replayable(self):
        def slow(_payload: bytes) -> None:
            time.sleep(0.6)

        timed = run_controlled_fuzz(slow, seed=b"t", iterations=3, timeout_seconds=0.1, max_input_bytes=4)
        self.assertEqual(timed["status"], "TIMEOUT")
        self.assertEqual(timed["failures"][0]["kind"], "TIMEOUT")
        self.assertEqual(timed["iterations_run"], 1)
        self.assertFalse(timed["coverage_claim"])
        replay = bytes.fromhex(timed["failures"][0]["input_hex"])
        self.assertLessEqual(len(replay), 4)

        def boom(_payload: bytes) -> None:
            raise RuntimeError("boom")

        crashed = run_controlled_fuzz(boom, seed=b"c", iterations=2, timeout_seconds=1, max_input_bytes=4)
        self.assertEqual(crashed["status"], "CRASH")
        self.assertEqual(crashed["failures"][0]["exception_type"], "RuntimeError")
        self.assertNotIn("boom", json.dumps(crashed))

        def hog(_payload: bytes) -> None:
            bytearray(200_000)

        limited = run_controlled_fuzz(
            hog, seed=b"m", iterations=1, timeout_seconds=2, max_input_bytes=4, max_memory_bytes=1024,
        )
        self.assertEqual(limited["status"], "RESOURCE_LIMIT")
        self.assertEqual(limited["failures"][0]["kind"], "RESOURCE_LIMIT")
        untouched = run_controlled_fuzz(None, seed=b"m", iterations=1, timeout_seconds=1, max_input_bytes=4)
        self.assertEqual(untouched["status"], "NOT_EXECUTED")
        self.assertFalse(untouched["coverage_claim"])

    def test_windows_native_api_detection_ignores_comments_and_strings(self):
        source = '\n'.join([
            "/* WriteProcessMemory(not, code); */",
            '// LoadLibraryA("nope")',
            'const char *text = "VirtualAllocEx";',
            "int main() {",
            "  WriteProcessMemory(0, 0, 0, 0, 0);",
            "  LoadLibraryA(0);",
            "  AdjustTokenPrivileges(0, 0, 0, 0, 0, 0);",
            "}",
            "",
        ])
        findings, gaps = analyze_windows_source("demo.c", source)
        rules = {(item["rule"], item["line"], item["severity"]) for item in findings}
        self.assertIn(("WIN_PROCESS_MEMORY", 5, "high"), rules)
        self.assertIn(("WIN_FFI_DYNAMIC_LOAD", 6, "review"), rules)
        self.assertIn(("WIN_PRIVILEGE_OPERATION", 7, "medium"), rules)
        self.assertEqual(len(findings), 3)
        self.assertIn("windows_native_runtime_not_executed", [item["reason"] for item in gaps])
        self.assertNotIn("VirtualAllocEx", json.dumps(findings))

    def test_windows_runtime_is_not_pass_on_host(self):
        info = runtime_inspection()
        self.assertNotEqual(info["status"], "PASS")
        self.assertFalse(info["coverage_claim"])
        self.assertFalse(info["process_access"])
        self.assertEqual(info["reason"], "windows_native_runtime_not_executed")
        with patch("subprocess.Popen", side_effect=AssertionError("process access")):
            again = runtime_inspection()
        self.assertEqual(again["status"], "NOT_EXECUTED")
        self.make("native.c", "int main(){ WriteProcessMemory(0,0,0,0,0); return 0; }\n")
        report = scan(self.root)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertIn("WIN_PROCESS_MEMORY", [item["rule"] for item in report["findings"]])
        self.assertIn("windows_native_runtime_not_executed", [item["reason"] for item in report["coverage_gaps"]])
        self.assertFalse(report["analysis_limits"]["coverage_claim"])
        self.assertEqual(report["analysis_limits"]["fuzz_on_target"], "not_executed_untrusted_target_not_run")
        if sys.platform == "win32":
            self.assertEqual(info["host_platform"], "win32")
        else:
            self.assertNotEqual(info["host_platform"], "win32")

    def test_policy_separates_block_review_and_pass(self):
        self.make("clean.py", "print('hello')\n")
        clean = scan(self.root)
        self.assertEqual(clean["status"], "NO_HEURISTIC_FINDINGS")
        self.assertEqual(evaluate(clean, HIGH)["status"], "PASS")
        self.assertIn("NOT independent", evaluate(clean, HIGH)["disclaimer"])

        review_root = self.root / "review"
        review_root.mkdir()
        (review_root / "x.rs").write_text("unsafe { do_something(); }\n", encoding="utf-8")
        review = scan(review_root)
        self.assertEqual(review["status"], "REVIEW_REQUIRED")
        self.assertEqual(evaluate(review, HIGH)["status"], "PASS")

        block_root = self.root / "block"
        block_root.mkdir()
        (block_root / "danger.py").write_text('eval("1+1")\n', encoding="utf-8")
        blocked = scan(block_root)
        verdict = evaluate(blocked, HIGH)
        self.assertEqual(verdict["status"], "BLOCK")
        self.assertIn("SEVERITY_THRESHOLD_EXCEEDED", verdict["reasons"])

        gap_root = self.root / "gap"
        gap_root.mkdir()
        (gap_root / "broken.rs").write_text('let s = "unsafe {\n', encoding="utf-8")
        incomplete = scan(gap_root)
        self.assertEqual(incomplete["status"], "INCOMPLETE")
        gap_verdict = evaluate(incomplete, HIGH)
        self.assertEqual(gap_verdict["status"], "BLOCK")
        self.assertIn("INCOMPLETE_COVERAGE", gap_verdict["reasons"])
        self.assertNotIn("APPROVED", json.dumps(gap_verdict))
        self.assertNotIn("REVIEWED", json.dumps(incomplete))

    def test_p0_p1_regressions_still_hold(self):
        self.make("safe.rs", "fn safe() {}\n")
        self.assertEqual(scan(self.root)["status"], "NO_HEURISTIC_FINDINGS")
        self.make("danger.py", 'eval("1+1")\n')
        report = scan(self.root)
        self.assertIn("PY_DYNAMIC_EXECUTION", [item["rule"] for item in report["findings"]])
        self.make("broken.py", "def x(:\n")
        incomplete = scan(self.root)
        self.assertEqual(incomplete["status"], "INCOMPLETE")
        self.assertIn("python_parse_failed", [item["reason"] for item in incomplete["coverage_gaps"]])


if __name__ == "__main__":
    unittest.main()
