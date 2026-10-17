"""Explicit syn syntax inventory. The default scan does not spawn this backend."""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from wolf_auditor.__main__ import main
from wolf_auditor.engine import MAX_FILE_BYTES, scan
from wolf_auditor.rust_safety import analyze_rust
from wolf_auditor.rust_syn import analyze_rust_syntax

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools" / "wolf_syn" / "src" / "main.rs"


def _backend() -> Path:
    override = os.environ.get("WOLF_SYN_BIN")
    if override:
        candidate = Path(override)
        if candidate.is_file():
            return candidate
    root = ROOT / "tools" / "wolf_syn" / "target"
    names = ("wolf_syn.exe", "wolf_syn") if os.name == "nt" else ("wolf_syn",)
    for folder in ("debug", "release"):
        for name in names:
            candidate = root / folder / name
            if candidate.is_file():
                return candidate
    raise AssertionError("wolf_syn is not built")


def _reasons(result: dict) -> list[str]:
    return [item["reason"] for item in result["gaps"]]


def _scan_reasons(report: dict) -> list[str]:
    return [item["reason"] for item in report["coverage_gaps"]]


def _rules(result: dict) -> list[str]:
    return [item["rule"] for item in result["findings"]]


def _line_of(source: str, needle: str) -> int:
    matches = [index for index, line in enumerate(source.splitlines(), 1) if needle in line]
    if len(matches) != 1:
        raise AssertionError((needle, matches))
    return matches[0]


class SynInventoryTests(unittest.TestCase):
    def test_syn_inventory_matches_syntax(self) -> None:
        source = "\n".join((
            "fn safe() {}",
            "unsafe fn marked() { unsafe { let _inner = 1; } }",
            "unsafe impl Send for Local {}",
            "unsafe trait Marker {}",
            "extern \"system\" { fn OpenProcess(); }",
            "extern \"C\" fn exported() {}",
            "#[unsafe(export_name = \"SECRET_SYMBOL_VALUE\")]",
            "fn renamed() {}",
            "#[link(name = \"SECRET_LIB_NAME\")]",
            "extern \"C\" {}",
            "extern crate serde;",
            "mod outer { mod inner { unsafe fn buried() {} } }",
            "fn go() { crate::missing::item(); }",
            "type Callback = unsafe extern \"C\" fn();",
            "",
        ))
        result = analyze_rust_syntax("crate.rs", source)
        self.assertEqual(result["backend"], "syn")
        for flag in ("coverage_claim", "macros_expanded", "cfg_evaluated", "names_resolved"):
            self.assertIs(result[flag], False)
        self.assertNotIn("status", result)
        self.assertNotIn("SECRET_SYMBOL_VALUE", json.dumps(result))
        self.assertNotIn("SECRET_LIB_NAME", json.dumps(result))
        self.assertEqual(analyze_rust_syntax("crate.rs", source), result)
        findings = {(item["rule"], item["line"]) for item in result["findings"]}
        self.assertIn(("RUST_UNSAFE_INVENTORY", _line_of(source, "unsafe fn marked")), findings)
        self.assertIn(("RUST_UNSAFE_INVENTORY", _line_of(source, "unsafe { let _inner")), findings)
        self.assertIn(("RUST_UNSAFE_INVENTORY", _line_of(source, "unsafe impl Send")), findings)
        self.assertIn(("RUST_UNSAFE_INVENTORY", _line_of(source, "unsafe trait Marker")), findings)
        self.assertIn(("RUST_UNSAFE_INVENTORY", _line_of(source, "unsafe fn buried")), findings)
        self.assertIn(("RUST_FFI_BOUNDARY", _line_of(source, "extern \"system\"")), findings)
        self.assertIn(("RUST_FFI_BOUNDARY", _line_of(source, "extern \"C\" fn exported")), findings)
        self.assertIn(("RUST_FFI_BOUNDARY", _line_of(source, "extern \"C\" {}")), findings)
        self.assertIn(("RUST_FFI_SYMBOL", _line_of(source, "export_name")), findings)
        self.assertIn(("RUST_FFI_BOUNDARY", _line_of(source, "SECRET_LIB_NAME")), findings)
        self.assertIn(("RUST_UNSAFE_INVENTORY", _line_of(source, "type Callback")), findings)
        self.assertIn(("RUST_FFI_BOUNDARY", _line_of(source, "type Callback")), findings)
        for item in result["findings"]:
            self.assertEqual(item["severity"], "review")
            self.assertEqual(item["evidence"], "heuristic_match_redacted")
            self.assertIs(item["verified_exploit"], False)
            self.assertEqual(item["path"], "crate.rs")
        gaps = {(item["reason"], item["line"]) for item in result["gaps"]}
        self.assertIn(("rust_name_resolution_unresolved", _line_of(source, "crate::missing")), gaps)
        self.assertNotIn("RUST_FFI_BOUNDARY", [
            rule for rule, _line in (
                (item["rule"], item["line"]) for item in result["findings"]
                if item["line"] == _line_of(source, "extern crate serde")
            )
        ])
        safe = analyze_rust_syntax("safe.rs", "fn safe() {}\n")
        self.assertEqual(safe["findings"], [])
        self.assertEqual(safe["gaps"], [])
        self.assertFalse(safe["names_resolved"])

    def test_nested_macros_and_attributes_are_not_expanded(self) -> None:
        source = "\n".join((
            "fn safe() { foo!(bar!(unsafe { let _hidden = 1; })); }",
            "hidden_unsafe!(unsafe { let _top = 1; });",
            "#[project_macro(inner(unsafe))]",
            "fn wrapped() {}",
            "#[derive(Debug)]",
            "struct Item;",
            "#[proc_macro_derive(Widget)]",
            "pub fn widget(input: TokenStream) -> TokenStream { input }",
            "macro_rules! make { () => { unsafe { let _inside = 1; } }; }",
            "",
        ))
        result = analyze_rust_syntax("macros.rs", source)
        self.assertEqual(result["backend"], "syn")
        self.assertNotIn("RUST_UNSAFE_INVENTORY", _rules(result))
        self.assertIn("rust_macro_not_expanded", _reasons(result))
        self.assertIn("rust_proc_macro_not_executed", _reasons(result))
        self.assertFalse(result["macros_expanded"])
        self.assertNotIn("status", result)

    def test_conditional_compilation_stays_unresolved(self) -> None:
        source = "\n".join((
            "#![cfg(test)]",
            "#[cfg(not(test))]",
            "fn go() { unsafe { let _seen = 1; } }",
            "#[cfg_attr(feature = \"off\", derive(Debug), unsafe(no_mangle))]",
            "fn maybe() {}",
            "#[cfg_attr(unix, cfg_attr(target_os = \"linux\", project_macro))]",
            "fn nested() {}",
            "",
        ))
        result = analyze_rust_syntax("cfg.rs", source)
        self.assertEqual(result["backend"], "syn")
        self.assertFalse(result["cfg_evaluated"])
        self.assertIn(("RUST_UNSAFE_INVENTORY", _line_of(source, "unsafe { let _seen")), {
            (item["rule"], item["line"]) for item in result["findings"]
        })
        self.assertIn(("RUST_UNSAFE_INVENTORY", _line_of(source, "unsafe(no_mangle)")), {
            (item["rule"], item["line"]) for item in result["findings"]
        })
        self.assertIn(("RUST_FFI_SYMBOL", _line_of(source, "unsafe(no_mangle)")), {
            (item["rule"], item["line"]) for item in result["findings"]
        })
        gaps = {(item["reason"], item["line"]) for item in result["gaps"]}
        self.assertIn(("rust_cfg_unresolved", _line_of(source, "#![cfg(test)]")), gaps)
        self.assertIn(("rust_cfg_unresolved", _line_of(source, "#[cfg(not(test))]")), gaps)
        self.assertIn(("rust_cfg_unresolved", _line_of(source, "cfg_attr(feature")), gaps)
        self.assertIn(("rust_macro_not_expanded", _line_of(source, "cfg_attr(feature")), gaps)
        self.assertIn(("rust_cfg_unresolved", _line_of(source, "cfg_attr(unix")), gaps)
        self.assertIn(("rust_macro_not_expanded", _line_of(source, "cfg_attr(unix")), gaps)

    def test_comments_strings_and_malformed_syntax_are_not_a_pass(self) -> None:
        decoy = "\n".join((
            "// unsafe extern \"C\" { fn system(); }",
            "/* unsafe impl Drop for T {} */",
            "fn safe() {",
            "    let _text = \"unsafe fn hidden() { extern \\\"C\\\" { fn Open(); } }\";",
            "    let _raw = r#\"crate::missing::item()\"#;",
            "}",
            "",
        ))
        clean = analyze_rust_syntax("decoy.rs", decoy)
        self.assertEqual(clean["findings"], [])
        self.assertEqual(clean["gaps"], [])
        broken = "fn broken( { let _ = \"SECRET_PARSE_TEXT\";\n"
        failed = analyze_rust_syntax("broken.rs", broken)
        self.assertEqual(failed["backend"], "syn")
        self.assertEqual(failed["findings"], [])
        self.assertEqual(_reasons(failed), ["rust_syn_parse_failed"])
        self.assertGreaterEqual(failed["gaps"][0]["line"], 1)
        self.assertNotIn("SECRET_PARSE_TEXT", json.dumps(failed))
        windows = analyze_rust_syntax("crlf.rs", "fn safe() {}\r\nunsafe fn marked() {}\r\n")
        self.assertIn(("RUST_UNSAFE_INVENTORY", 2), {
            (item["rule"], item["line"]) for item in windows["findings"]
        })

    def test_parse_failure_keeps_earlier_valid_items(self) -> None:
        source = "\n".join((
            "#![cfg(test)]",
            "unsafe fn marked() {}",
            "extern \"C\" { fn open(); }",
            "#[link(name = \"c\")]",
            "extern \"C\" {}",
            "#[unsafe]",
            "fn flagged() {}",
            "fn { let _ = \"SECRET_PARSE_TEXT\";",
            "",
        ))
        result = analyze_rust_syntax("partial.rs", source)
        self.assertEqual(result["backend"], "syn")
        for flag in ("coverage_claim", "macros_expanded", "cfg_evaluated", "names_resolved"):
            self.assertIs(result[flag], False)
        findings = {(item["rule"], item["line"]) for item in result["findings"]}
        self.assertIn(("RUST_UNSAFE_INVENTORY", _line_of(source, "unsafe fn marked")), findings)
        self.assertIn(("RUST_FFI_BOUNDARY", _line_of(source, "extern \"C\" { fn open")), findings)
        self.assertIn(("RUST_FFI_BOUNDARY", _line_of(source, "#[link(name = \"c\")]")), findings)
        self.assertIn(("RUST_FFI_BOUNDARY", _line_of(source, "extern \"C\" {}")), findings)
        self.assertIn(("RUST_UNSAFE_INVENTORY", _line_of(source, "#[unsafe]")), findings)
        broken_line = _line_of(source, "fn {")
        self.assertNotIn(broken_line, [item["line"] for item in result["findings"]])
        gaps = {(item["reason"], item["line"]) for item in result["gaps"]}
        self.assertIn(("rust_cfg_unresolved", _line_of(source, "#![cfg(test)]")), gaps)
        self.assertIn(("rust_syn_parse_failed", broken_line), gaps)
        self.assertNotIn("SECRET_PARSE_TEXT", json.dumps(result))
        only = analyze_rust_syntax("broken.rs", "fn {\n")
        self.assertEqual(only["findings"], [])
        self.assertEqual(_reasons(only), ["rust_syn_parse_failed"])
        self.assertGreaterEqual(only["gaps"][0]["line"], 1)
        balanced = analyze_rust_syntax("balanced.rs", "unsafe fn marked() {}\nfn {}\n")
        self.assertIn(("RUST_UNSAFE_INVENTORY", 1), {
            (item["rule"], item["line"]) for item in balanced["findings"]
        })
        self.assertNotIn(2, [item["line"] for item in balanced["findings"]])
        self.assertIn(("rust_syn_parse_failed", 2), {
            (item["reason"], item["line"]) for item in balanced["gaps"]
        })
        crlf_broken = analyze_rust_syntax("crlf-broken.rs", "unsafe fn marked() {}\r\nfn {\r\n")
        self.assertIn(("RUST_UNSAFE_INVENTORY", 1), {
            (item["rule"], item["line"]) for item in crlf_broken["findings"]
        })
        self.assertIn(("rust_syn_parse_failed", 2), {
            (item["reason"], item["line"]) for item in crlf_broken["gaps"]
        })
        self.assertNotIn(2, [item["line"] for item in crlf_broken["findings"]])
        valid = analyze_rust_syntax("ok.rs", "unsafe fn marked() {}\n")
        self.assertNotIn("rust_syn_parse_failed", _reasons(valid))
        self.assertIn(("RUST_UNSAFE_INVENTORY", 1), {
            (item["rule"], item["line"]) for item in valid["findings"]
        })
        shebang = "#!/usr/bin/env rustx\nunsafe fn marked() {}\nfn {\n"
        shebang_result = analyze_rust_syntax("shebang.rs", shebang)
        self.assertIn(("RUST_UNSAFE_INVENTORY", 2), {
            (item["rule"], item["line"]) for item in shebang_result["findings"]
        })
        self.assertIn(("rust_syn_parse_failed", 3), {
            (item["reason"], item["line"]) for item in shebang_result["gaps"]
        })
        self.assertNotIn(3, [item["line"] for item in shebang_result["findings"]])
        bom = "\ufeffunsafe fn marked() {}\nfn {\n"
        bom_result = analyze_rust_syntax("bom.rs", bom)
        self.assertIn(("RUST_UNSAFE_INVENTORY", 1), {
            (item["rule"], item["line"]) for item in bom_result["findings"]
        })
        self.assertIn(("rust_syn_parse_failed", 2), {
            (item["reason"], item["line"]) for item in bom_result["gaps"]
        })
        inner = analyze_rust_syntax("inner.rs", "#![cfg(test)]\nunsafe fn marked() {}\n")
        self.assertNotIn("rust_syn_parse_failed", _reasons(inner))
        self.assertIn(("rust_cfg_unresolved", 1), {
            (item["reason"], item["line"]) for item in inner["gaps"]
        })
        self.assertIn(("RUST_UNSAFE_INVENTORY", 2), {
            (item["rule"], item["line"]) for item in inner["findings"]
        })

    def test_external_module_and_include_are_not_read(self) -> None:
        directory = Path(tempfile.mkdtemp())
        try:
            (directory / "secret.rs").write_text(
                "SECRET_FILE_MARKER\nunsafe fn from_disk() {}\n",
                encoding="utf-8",
            )
            source = "\n".join((
                "#[path = \"secret.rs\"]",
                "mod hidden;",
                "fn safe() { include!(\"secret.rs\"); }",
                "",
            ))
            result = analyze_rust_syntax((directory / "lib.rs").as_posix(), source)
        finally:
            shutil.rmtree(directory, ignore_errors=True)
        self.assertNotIn("SECRET_FILE_MARKER", json.dumps(result))
        self.assertNotIn("RUST_UNSAFE_INVENTORY", _rules(result))
        self.assertIn("rust_module_file_not_read", _reasons(result))
        self.assertIn("rust_macro_not_expanded", _reasons(result))
        self.assertIn(
            ("rust_module_file_not_read", _line_of(source, "mod hidden;")),
            {(item["reason"], item["line"]) for item in result["gaps"]},
        )

    def test_unclassified_pointers_and_static_mut_are_gaps(self) -> None:
        source = "\n".join((
            "static mut COUNTER: i32 = 0;",
            "fn reader(value: *const u8) -> *mut u8 { value as *mut u8 }",
            "",
        ))
        result = analyze_rust_syntax("ptrs.rs", source)
        gaps = {(item["reason"], item["line"]) for item in result["gaps"]}
        self.assertIn(("rust_static_mut_not_inventoried", 1), gaps)
        self.assertIn(("rust_raw_pointer_not_inventoried", 2), gaps)
        self.assertEqual(result["findings"], [])
        self.assertFalse(result["coverage_claim"])

    def test_default_scan_does_not_spawn_syn(self) -> None:
        target = Path(tempfile.mkdtemp())
        try:
            (target / "lib.rs").write_text("fn safe() { unsafe { let _x = 1; } }\n", encoding="utf-8")
            with patch("subprocess.run", side_effect=AssertionError("spawned")), patch(
                "subprocess.Popen", side_effect=AssertionError("spawned")
            ):
                report = scan(target)
        finally:
            shutil.rmtree(target, ignore_errors=True)
        self.assertEqual(report["analysis_limits"]["parser_stage"], "token_heuristic")
        self.assertEqual(
            report["analysis_limits"]["rust_syn_backend"],
            "not_invoked_default_scan_does_not_spawn",
        )
        self.assertIn("RUST_UNSAFE_INVENTORY", [item["rule"] for item in report["findings"]])
        self.assertNotIn(report["status"], {"PASS", "REVIEWED", "APPROVED"})
        heuristic, heuristic_gaps = analyze_rust("lib.rs", "fn safe() { crate::missing::item(); }\n")
        self.assertEqual(heuristic, [])
        self.assertIn("rust_name_resolution_unresolved", [item["reason"] for item in heuristic_gaps])

    def test_spawn_is_read_only_and_rejects_untrusted_executables(self) -> None:
        binary = _backend()
        calls: list[tuple] = []
        observed: dict[str, object] = {}
        real_run = subprocess.run

        def spy(*args, **kwargs):
            calls.append((args, kwargs))
            cwd = Path(kwargs["cwd"])
            observed["name"] = cwd.name
            observed["entries"] = list(cwd.iterdir())
            return real_run(*args, **kwargs)

        source = "fn safe() {}\n"
        with patch.dict(os.environ, {"WOLF_SYN_BIN": str(binary)}), patch(
            "wolf_auditor.rust_syn.subprocess.run", side_effect=spy
        ):
            result = analyze_rust_syntax("safe.rs", source, timeout_seconds=5)
        self.assertEqual(result["backend"], "syn")
        self.assertEqual(len(calls), 1)
        argv, kwargs = calls[0]
        self.assertEqual(argv, ([os.fspath(binary)],))
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(kwargs["input"], source.encode("utf-8"))
        self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
        allowed_env = {"PATH", "SYSTEMROOT", "WINDIR"} if os.name == "nt" else {"PATH"}
        self.assertTrue(set(kwargs["env"]) <= allowed_env)
        self.assertIn("PATH", kwargs["env"])
        self.assertEqual(observed["name"].startswith("wolf-syn-"), True)
        self.assertEqual(observed["entries"], [])
        self.assertFalse(Path(kwargs["cwd"]).exists())
        helper = HELPER.read_text(encoding="utf-8")
        for banned in (
            "std::process::Command",
            "Command::new",
            "TcpStream",
            "std::net",
            "File::open",
            "std::fs::",
            "include_str!",
            "include_bytes!",
        ):
            self.assertNotIn(banned, helper)
        wrapper = (ROOT / "wolf_auditor" / "rust_syn.py").read_text(encoding="utf-8")
        self.assertIn("shell=False", wrapper)
        self.assertNotIn("shell=True", wrapper)
        with patch.dict(os.environ, {"WOLF_SYN_BIN": "wolf_syn"}):
            relative = analyze_rust_syntax("safe.rs", source)
        self.assertEqual(_reasons(relative), ["rust_syn_backend_unavailable"])
        with patch.dict(os.environ, {"WOLF_SYN_BIN": str(ROOT / "missing-wolf-syn")}):
            missing = analyze_rust_syntax("safe.rs", source)
        self.assertEqual(_reasons(missing), ["rust_syn_backend_unavailable"])
        with patch.dict(os.environ, {"WOLF_SYN_BIN": str(ROOT / ".." / "wolf_syn")}):
            traversed = analyze_rust_syntax("safe.rs", source)
        self.assertEqual(_reasons(traversed), ["rust_syn_backend_unavailable"])
        link = binary.with_name(binary.name + "-link")
        try:
            link.symlink_to(binary)
        except OSError:
            link = None
        if link is not None:
            try:
                with patch.dict(os.environ, {"WOLF_SYN_BIN": str(link)}):
                    aliased = analyze_rust_syntax("safe.rs", source)
                self.assertEqual(_reasons(aliased), ["rust_syn_backend_unavailable"])
            finally:
                link.unlink(missing_ok=True)

    def test_limits_and_false_claims_fail_closed(self) -> None:
        binary = _backend()
        with patch("wolf_auditor.rust_syn.subprocess.run", side_effect=AssertionError("spawned")):
            oversized = analyze_rust_syntax("big.rs", "a" * 1_000_001)
            bad_text = analyze_rust_syntax("bad.rs", "\ud800")
            for timeout in (True, False, 0, -1, 5.1, "1"):
                rejected = analyze_rust_syntax("safe.rs", "fn safe() {}\n", timeout_seconds=timeout)
                self.assertEqual(_reasons(rejected), ["rust_syn_backend_unavailable"])
        self.assertEqual(_reasons(oversized), ["rust_syn_input_limit"])
        self.assertEqual(oversized["findings"], [])
        self.assertEqual(oversized["backend"], "unavailable")
        self.assertEqual(_reasons(bad_text), ["rust_syn_parse_failed"])
        completed = subprocess.run(
            [os.fspath(binary)],
            input=b"A" * 1_000_001,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        direct = json.loads(completed.stdout)
        self.assertEqual(direct["gaps"], [{"reason": "rust_syn_input_limit"}])
        self.assertFalse(direct["coverage_claim"])
        self.assertLess(len(completed.stdout), 500)
        medium = "fn safe() {}\n" * 2000
        parsed = analyze_rust_syntax("medium.rs", medium, timeout_seconds=5)
        self.assertEqual(parsed["backend"], "syn")
        self.assertEqual(parsed["findings"], [])
        self.assertEqual(parsed["gaps"], [])
        claimed = json.dumps({
            "coverage_claim": True,
            "macros_expanded": False,
            "cfg_evaluated": False,
            "names_resolved": False,
            "findings": [{"rule": "RUST_UNSAFE_INVENTORY", "line": 1}],
            "gaps": [],
        }).encode("utf-8")

        def fake_run(*_args, **_kwargs):
            return subprocess.CompletedProcess(args=["wolf_syn"], returncode=0, stdout=claimed)

        with patch.dict(os.environ, {"WOLF_SYN_BIN": str(binary)}), patch(
            "wolf_auditor.rust_syn.subprocess.run", side_effect=fake_run
        ):
            false_claim = analyze_rust_syntax("safe.rs", "fn safe() {}\n")
        self.assertEqual(_reasons(false_claim), ["rust_syn_false_claim"])
        self.assertEqual(false_claim["findings"], [])
        self.assertEqual(false_claim["backend"], "unavailable")
        unknown = json.dumps({
            "coverage_claim": False,
            "macros_expanded": False,
            "cfg_evaluated": False,
            "names_resolved": False,
            "findings": [{"rule": "RUST_EXPLOIT", "line": 1}],
            "gaps": [],
        }).encode("utf-8")

        def unknown_run(*_args, **_kwargs):
            return subprocess.CompletedProcess(args=["wolf_syn"], returncode=0, stdout=unknown)

        with patch.dict(os.environ, {"WOLF_SYN_BIN": str(binary)}), patch(
            "wolf_auditor.rust_syn.subprocess.run", side_effect=unknown_run
        ):
            rejected_rule = analyze_rust_syntax("safe.rs", "fn safe() {}\n")
        self.assertEqual(_reasons(rejected_rule), ["rust_syn_backend_failed"])
        self.assertEqual(rejected_rule["findings"], [])
        with patch.dict(os.environ, {"WOLF_SYN_BIN": str(binary)}), patch(
            "wolf_auditor.rust_syn.subprocess.run",
            side_effect=subprocess.TimeoutExpired("wolf_syn", 1),
        ):
            timed_out = analyze_rust_syntax("safe.rs", "fn safe() {}\n", timeout_seconds=1)
        self.assertEqual(_reasons(timed_out), ["rust_syn_timeout"])
        self.assertEqual(timed_out["findings"], [])
        with patch.dict(os.environ, {"WOLF_SYN_BIN": str(binary)}), patch(
            "wolf_auditor.rust_syn.subprocess.run",
            return_value=subprocess.CompletedProcess(args=["wolf_syn"], returncode=0, stdout=b"x" * 70_000),
        ):
            huge = analyze_rust_syntax("safe.rs", "fn safe() {}\n")
        self.assertEqual(_reasons(huge), ["rust_syn_backend_failed"])
        with patch.dict(os.environ, {"WOLF_SYN_BIN": str(binary)}), patch(
            "pathlib.Path.rmdir", side_effect=OSError("busy")
        ):
            kept = analyze_rust_syntax("safe.rs", "fn safe() {}\n")
        self.assertEqual(kept["backend"], "syn")
        self.assertEqual(kept["findings"], [])

    def test_helper_source_is_not_a_clean_heuristic_pass(self) -> None:
        _findings, gaps = analyze_rust(HELPER.as_posix(), HELPER.read_text(encoding="utf-8"))
        reasons = {item["reason"] for item in gaps}
        self.assertIn("rust_name_resolution_unresolved", reasons)
        self.assertIn("rust_macro_not_expanded", reasons)


class ExplicitSynScanTests(unittest.TestCase):
    def test_explicit_syn_scan_reports_syntax_and_its_limits(self) -> None:
        source = "\n".join((
            "#[unsafe(export_name = \"SECRET_SYMBOL_VALUE\")]",
            "fn renamed() {}",
            "extern \"system\" { fn OpenProcess(); }",
            "#[derive(Debug)]",
            "struct Item;",
            "#[cfg(not(test))]",
            "fn go() { crate::missing::item(); }",
            "mod hidden;",
            "fn body() { hidden_unsafe!(unsafe { let _x = 1; }); }",
            "",
        ))
        directory = Path(tempfile.mkdtemp())
        try:
            (directory / "lib.rs").write_text(source, encoding="utf-8")
            default = scan(directory)
            with patch("wolf_auditor.rust_syn.subprocess.run", side_effect=AssertionError("spawned")):
                self.assertEqual(scan(directory)["analysis_limits"]["parser_stage"], "token_heuristic")
            report = scan(directory, rust_syntax="syn")
            again = scan(directory, rust_syntax="syn")
        finally:
            shutil.rmtree(directory, ignore_errors=True)
        self.assertEqual(report, again)
        self.assertEqual(default["analysis_limits"]["rust_syn_backend"], "not_invoked_default_scan_does_not_spawn")
        self.assertNotIn("rust_syn_parse_failed", [item["reason"] for item in default["coverage_gaps"]])
        self.assertEqual(report["scope"], "read_only_explicit_syn_plus_heuristic")
        limits = report["analysis_limits"]
        self.assertEqual(limits["parser_stage"], "explicit_syn_plus_token_heuristic")
        self.assertEqual(limits["rust_syn_backend"], "invoked_stdin_only_no_macro_expansion")
        self.assertEqual(limits["rust_macros"], "not_expanded")
        self.assertEqual(limits["rust_cfg"], "unresolved_not_evaluated")
        self.assertEqual(limits["rust_names"], "not_resolved")
        self.assertIs(limits["coverage_claim"], False)
        self.assertIs(report["cve_coverage"]["completeness"], False)
        self.assertIsNone(report["cve_coverage"]["queried_at"])
        self.assertNotIn(report["status"], {"PASS", "REVIEWED", "APPROVED"})
        rules = {item["rule"] for item in report["findings"]}
        self.assertIn("RUST_UNSAFE_INVENTORY", rules)
        self.assertIn("RUST_FFI_BOUNDARY", rules)
        self.assertIn("RUST_FFI_SYMBOL", rules)
        reasons = {item["reason"] for item in report["coverage_gaps"]}
        self.assertIn("rust_macro_not_expanded", reasons)
        self.assertIn("rust_cfg_unresolved", reasons)
        self.assertIn("rust_name_resolution_unresolved", reasons)
        self.assertIn("rust_module_file_not_read", reasons)
        encoded = json.dumps(report)
        self.assertNotIn("SECRET_SYMBOL_VALUE", encoded)
        self.assertNotIn("CVE complete", encoded)
        with self.assertRaises(ValueError):
            scan(directory, rust_syntax="compiler")

    def test_malformed_rust_and_missing_backend_fail_closed(self) -> None:
        directory = Path(tempfile.mkdtemp())
        try:
            (directory / "broken.rs").write_text("fn broken( { let _ = \"SECRET_PARSE_TEXT\";\n", encoding="utf-8")
            (directory / "marked.rs").write_text("unsafe fn marked() {}\n", encoding="utf-8")
            parsed = scan(directory, rust_syntax="syn")
            with patch.dict(os.environ, {"WOLF_SYN_BIN": str(directory / "missing-wolf-syn")}):
                missing = scan(directory, rust_syntax="syn")
        finally:
            shutil.rmtree(directory, ignore_errors=True)
        self.assertIn("rust_syn_parse_failed", [item["reason"] for item in parsed["coverage_gaps"]])
        self.assertEqual(parsed["status"], "INCOMPLETE")
        self.assertNotIn("SECRET_PARSE_TEXT", json.dumps(parsed))
        self.assertNotIn(parsed["status"], {"PASS", "REVIEWED", "APPROVED"})
        self.assertEqual(missing["analysis_limits"]["rust_syn_backend"], "explicit_request_incomplete")
        self.assertIn("rust_syn_backend_unavailable", [item["reason"] for item in missing["coverage_gaps"]])
        self.assertIn("RUST_UNSAFE_INVENTORY", [item["rule"] for item in missing["findings"]])
        self.assertIs(missing["analysis_limits"]["coverage_claim"], False)
        self.assertIs(missing["cve_coverage"]["completeness"], False)

    def test_cli_syn_is_opt_in_and_default_does_not_spawn(self) -> None:
        directory = Path(tempfile.mkdtemp())
        try:
            (directory / "lib.rs").write_text(
                "fn safe() {}\n// unsafe extern \"C\" { fn system(); }\n",
                encoding="utf-8",
            )
            spawned: list[int] = []

            def spy(*_args, **_kwargs):
                spawned.append(1)
                raise AssertionError("spawned")

            with patch("wolf_auditor.rust_syn.subprocess.run", side_effect=spy), patch(
                "sys.argv", ["wolf-auditor", str(directory)]
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
                code = main()
            self.assertEqual(spawned, [])
            self.assertNotIn("syn inventory opted in", err.getvalue())
            self.assertEqual(code, 0)
            with patch("sys.argv", ["wolf-auditor", str(directory), "--rust-syntax", "syn"]), redirect_stdout(
                io.StringIO()
            ) as out, redirect_stderr(io.StringIO()) as err:
                opted = main()
        finally:
            shutil.rmtree(directory, ignore_errors=True)
        self.assertIn("syn inventory opted in", err.getvalue())
        report = json.loads(out.getvalue())
        self.assertEqual(report["analysis_limits"]["rust_syn_backend"], "invoked_stdin_only_no_macro_expansion")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["coverage_gaps"], [])
        self.assertIs(report["analysis_limits"]["coverage_claim"], False)
        self.assertIs(report["cve_coverage"]["completeness"], False)
        self.assertEqual(report["status"], "NO_HEURISTIC_FINDINGS")
        self.assertNotIn(report["status"], {"PASS", "REVIEWED", "APPROVED"})
        self.assertEqual(opted, 0)
        empty = Path(tempfile.mkdtemp())
        try:
            (empty / "note.py").write_text("x = 1\n", encoding="utf-8")
            quiet = scan(empty, rust_syntax="syn")
        finally:
            shutil.rmtree(empty, ignore_errors=True)
        self.assertEqual(quiet["coverage_gaps"], [{"path": "<rust>", "reason": "rust_syn_no_rust_sources"}])
        self.assertEqual(quiet["status"], "INCOMPLETE")
        self.assertEqual(quiet["analysis_limits"]["rust_syn_backend"], "explicit_request_incomplete")


class AdversarialSynScanTests(unittest.TestCase):
    """Fixtures that distinguish a real syn inventory from a green exit code.

    The default token heuristic is left unchanged. A malformed `fn {` still
    produces no heuristic finding; that remains a false negative.
    """

    def test_scan_records_exact_lines_and_does_not_treat_macro_tokens_as_syn(self) -> None:
        source = "\n".join((
            "fn функция() {",
            "    unsafe { let _inner = 1; }",
            "}",
            "unsafe fn r#match() {",
            "    unsafe { let _nested = 1; }",
            "}",
            "fn unsafe_name() {}",
            "extern crate serde;",
            "#[link(name = \"c\")]",
            "fn native() {}",
            "#[unsafe]",
            "fn marked_attr() {}",
            "fn body() { hidden_unsafe!(unsafe { let _hidden = 1; }); }",
            "#[cfg_attr(not(test), derive(Hidden))]",
            "struct Item;",
            "#[cfg_attr(not(test), unsafe(no_mangle))]",
            "fn exported() {}",
            "",
        ))
        directory = Path(tempfile.mkdtemp())
        try:
            (directory / "lib.rs").write_text(source, encoding="utf-8")
            default = scan(directory)
            report = scan(directory, rust_syntax="syn")
            again = scan(directory, rust_syntax="syn")
        finally:
            shutil.rmtree(directory, ignore_errors=True)
        self.assertEqual(report, again)
        findings = {(item["rule"], item["line"]) for item in report["findings"]}
        gaps = {(item["reason"], item.get("line")) for item in report["coverage_gaps"]}
        inner = _line_of(source, "let _inner")
        nested = _line_of(source, "let _nested")
        raw_fn = _line_of(source, "unsafe fn r#match")
        decoy = _line_of(source, "fn unsafe_name")
        crate_line = _line_of(source, "extern crate serde")
        hidden = _line_of(source, "hidden_unsafe!")
        derive = _line_of(source, "derive(Hidden)")
        exported = _line_of(source, "unsafe(no_mangle)")
        self.assertIn(("RUST_UNSAFE_INVENTORY", inner), findings)
        self.assertIn(("RUST_UNSAFE_INVENTORY", nested), findings)
        self.assertIn(("RUST_UNSAFE_INVENTORY", raw_fn), findings)
        self.assertNotIn(("RUST_UNSAFE_INVENTORY", decoy), findings)
        self.assertNotIn(("RUST_FFI_BOUNDARY", crate_line), findings)
        self.assertNotIn(("RUST_FFI_SYMBOL", crate_line), findings)
        link = _line_of(source, "link(name")
        bare_unsafe = _line_of(source, "#[unsafe]")
        default_findings = {(item["rule"], item["line"]) for item in default["findings"]}
        self.assertIn(("RUST_FFI_BOUNDARY", link), findings)
        self.assertIn(("RUST_UNSAFE_INVENTORY", bare_unsafe), findings)
        self.assertNotIn(("RUST_FFI_BOUNDARY", link), default_findings)
        self.assertNotIn(("RUST_UNSAFE_INVENTORY", bare_unsafe), default_findings)
        self.assertEqual(default["analysis_limits"]["rust_syn_backend"], "not_invoked_default_scan_does_not_spawn")
        self.assertIn(("RUST_UNSAFE_INVENTORY", hidden), findings)
        self.assertIn(("rust_macro_not_expanded", hidden), gaps)
        self.assertIn(("rust_cfg_unresolved", derive), gaps)
        self.assertIn(("rust_macro_not_expanded", derive), gaps)
        self.assertIn(("RUST_UNSAFE_INVENTORY", exported), findings)
        self.assertIn(("RUST_FFI_SYMBOL", exported), findings)
        self.assertIn(("rust_cfg_unresolved", exported), gaps)
        self.assertNotIn(("rust_macro_not_expanded", exported), gaps)
        syn_only = analyze_rust_syntax("lib.rs", source)
        syn_findings = {(item["rule"], item["line"]) for item in syn_only["findings"]}
        self.assertNotIn(("RUST_UNSAFE_INVENTORY", hidden), syn_findings)
        self.assertIn(("RUST_UNSAFE_INVENTORY", inner), syn_findings)
        self.assertIn(("RUST_FFI_BOUNDARY", link), syn_findings)
        self.assertIn(("RUST_UNSAFE_INVENTORY", bare_unsafe), syn_findings)
        self.assertIn(("RUST_UNSAFE_INVENTORY", nested), syn_findings)
        self.assertFalse(syn_only["macros_expanded"])
        self.assertFalse(syn_only["cfg_evaluated"])
        self.assertFalse(syn_only["names_resolved"])
        self.assertIs(report["analysis_limits"]["coverage_claim"], False)
        self.assertEqual(report["analysis_limits"]["rust_macros"], "not_expanded")
        self.assertEqual(report["analysis_limits"]["rust_cfg"], "unresolved_not_evaluated")
        self.assertEqual(report["analysis_limits"]["rust_names"], "not_resolved")
        self.assertIs(report["cve_coverage"]["completeness"], False)
        self.assertNotIn(report["status"], {"PASS", "REVIEWED", "APPROVED"})

    def test_skipped_rust_is_incomplete_not_absent(self) -> None:
        oversized = Path(tempfile.mkdtemp())
        mixed = Path(tempfile.mkdtemp())
        exact = Path(tempfile.mkdtemp())
        try:
            (oversized / "big.rs").write_bytes(b"unsafe fn hidden() {}\n" + b"a" * MAX_FILE_BYTES)
            only = scan(oversized, rust_syntax="syn")
            default_only = scan(oversized)
            (mixed / "ok.rs").write_text("unsafe fn marked() {}\n", encoding="utf-8")
            (mixed / "big.rs").write_bytes(b"unsafe fn hidden() {}\n" + b"a" * MAX_FILE_BYTES)
            both = scan(mixed, rust_syntax="syn")
            header = b"unsafe fn marked() {}\n"
            (exact / "edge.rs").write_bytes(header + b" " * (MAX_FILE_BYTES - len(header)))
            bounded = scan(exact, rust_syntax="syn")
        finally:
            shutil.rmtree(oversized, ignore_errors=True)
            shutil.rmtree(mixed, ignore_errors=True)
            shutil.rmtree(exact, ignore_errors=True)
        self.assertEqual(only["status"], "INCOMPLETE")
        self.assertEqual(only["findings"], [])
        self.assertEqual(only["coverage_gaps"], [{"path": "big.rs", "reason": "file_size_limit"}])
        self.assertNotIn("rust_syn_no_rust_sources", _scan_reasons(only))
        self.assertEqual(only["analysis_limits"]["rust_syn_backend"], "explicit_request_incomplete")
        self.assertIs(only["analysis_limits"]["coverage_claim"], False)
        self.assertEqual(
            default_only["analysis_limits"]["rust_syn_backend"],
            "not_invoked_default_scan_does_not_spawn",
        )
        self.assertNotIn("rust_syn_no_rust_sources", _scan_reasons(default_only))
        self.assertEqual(both["status"], "INCOMPLETE")
        self.assertIn(("ok.rs", "RUST_UNSAFE_INVENTORY", 1), {
            (item["path"], item["rule"], item["line"]) for item in both["findings"]
        })
        self.assertNotIn("big.rs", [item["path"] for item in both["findings"]])
        self.assertIn({"path": "big.rs", "reason": "file_size_limit"}, both["coverage_gaps"])
        self.assertNotIn("rust_syn_no_rust_sources", _scan_reasons(both))
        self.assertEqual(both["analysis_limits"]["rust_syn_backend"], "explicit_request_incomplete")
        self.assertIs(both["analysis_limits"]["coverage_claim"], False)
        self.assertNotIn(both["status"], {"PASS", "REVIEWED", "APPROVED"})
        self.assertIn(("edge.rs", "RUST_UNSAFE_INVENTORY", 1), {
            (item["path"], item["rule"], item["line"]) for item in bounded["findings"]
        })
        self.assertEqual(
            bounded["analysis_limits"]["rust_syn_backend"],
            "invoked_stdin_only_no_macro_expansion",
        )
        self.assertNotIn("file_size_limit", _scan_reasons(bounded))

    def test_undecodable_symlink_and_budget_rust_stay_incomplete(self) -> None:
        broken = Path(tempfile.mkdtemp())
        linked = Path(tempfile.mkdtemp())
        outside = Path(tempfile.mkdtemp())
        limited = Path(tempfile.mkdtemp())
        denied_dir = Path(tempfile.mkdtemp())
        try:
            (broken / "bad.rs").write_bytes(b"\xffunsafe fn marked() {}\n")
            (broken / "ok.rs").write_text("unsafe fn marked() {}\n", encoding="utf-8")
            decoded = scan(broken, rust_syntax="syn")
            (outside / "secret.rs").write_text(
                "SECRET_OUTSIDE_MARKER\nunsafe fn from_disk() {}\n",
                encoding="utf-8",
            )
            (linked / "lib.rs").symlink_to(outside / "secret.rs")
            alias = scan(linked, rust_syntax="syn")
            (limited / "ok.rs").write_text("unsafe fn marked() {}\n", encoding="utf-8")
            with patch("wolf_auditor.engine.MAX_FILES", 0):
                budget = scan(limited, rust_syntax="syn")
                default_budget = scan(limited)
            hidden = denied_dir / "hidden.rs"
            hidden.write_text("unsafe fn marked() {}\n", encoding="utf-8")
            hidden.chmod(0)
            expected_reason = "PermissionError"
            try:
                hidden.read_bytes()
            except OSError as error:
                expected_reason = type(error).__name__
                denied = scan(denied_dir, rust_syntax="syn")
            else:
                real_read = Path.read_bytes

                def guarded(self, *args, **kwargs):
                    if self.name == "hidden.rs":
                        raise PermissionError("denied")
                    return real_read(self, *args, **kwargs)

                with patch.object(Path, "read_bytes", guarded):
                    denied = scan(denied_dir, rust_syntax="syn")
        finally:
            hidden = denied_dir / "hidden.rs"
            if hidden.exists() or hidden.is_symlink():
                hidden.chmod(0o644)
            shutil.rmtree(broken, ignore_errors=True)
            shutil.rmtree(linked, ignore_errors=True)
            shutil.rmtree(outside, ignore_errors=True)
            shutil.rmtree(limited, ignore_errors=True)
            shutil.rmtree(denied_dir, ignore_errors=True)
        self.assertEqual(decoded["status"], "INCOMPLETE")
        self.assertIn({"path": "bad.rs", "reason": "UnicodeDecodeError"}, decoded["coverage_gaps"])
        self.assertIn(("ok.rs", "RUST_UNSAFE_INVENTORY", 1), {
            (item["path"], item["rule"], item["line"]) for item in decoded["findings"]
        })
        self.assertNotIn("rust_syn_no_rust_sources", _scan_reasons(decoded))
        self.assertEqual(decoded["analysis_limits"]["rust_syn_backend"], "explicit_request_incomplete")
        self.assertNotIn("SECRET_OUTSIDE_MARKER", json.dumps(alias))
        self.assertEqual(alias["findings"], [])
        self.assertIn({"path": "lib.rs", "reason": "symlink_not_followed"}, alias["coverage_gaps"])
        self.assertNotIn("rust_syn_no_rust_sources", _scan_reasons(alias))
        self.assertEqual(alias["analysis_limits"]["rust_syn_backend"], "explicit_request_incomplete")
        self.assertEqual(alias["status"], "INCOMPLETE")
        self.assertEqual(budget["findings"], [])
        self.assertIn({"path": "ok.rs", "reason": "scan_file_budget_exceeded"}, budget["coverage_gaps"])
        self.assertNotIn("rust_syn_no_rust_sources", _scan_reasons(budget))
        self.assertEqual(budget["analysis_limits"]["rust_syn_backend"], "explicit_request_incomplete")
        self.assertEqual(
            default_budget["analysis_limits"]["rust_syn_backend"],
            "not_invoked_default_scan_does_not_spawn",
        )
        self.assertNotIn("rust_syn_no_rust_sources", _scan_reasons(default_budget))
        self.assertIn({"path": "hidden.rs", "reason": expected_reason}, denied["coverage_gaps"])
        self.assertEqual(denied["findings"], [])
        self.assertNotIn("rust_syn_no_rust_sources", _scan_reasons(denied))
        self.assertEqual(denied["analysis_limits"]["rust_syn_backend"], "explicit_request_incomplete")
        self.assertIs(denied["analysis_limits"]["coverage_claim"], False)
        self.assertNotIn(denied["status"], {"PASS", "REVIEWED", "APPROVED"})

    def test_empty_tree_and_non_rust_text_are_no_rust_sources(self) -> None:
        empty = Path(tempfile.mkdtemp())
        notes = Path(tempfile.mkdtemp())
        try:
            vacant = scan(empty, rust_syntax="syn")
            (notes / "notes.txt").write_text("unsafe fn not_scanned() {}\n", encoding="utf-8")
            ignored = scan(notes, rust_syntax="syn")
        finally:
            shutil.rmtree(empty, ignore_errors=True)
            shutil.rmtree(notes, ignore_errors=True)
        for report in (vacant, ignored):
            self.assertEqual(report["coverage_gaps"], [{"path": "<rust>", "reason": "rust_syn_no_rust_sources"}])
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["scanned_files"], 0)
            self.assertEqual(report["status"], "INCOMPLETE")
            self.assertEqual(report["analysis_limits"]["rust_syn_backend"], "explicit_request_incomplete")
            self.assertIs(report["analysis_limits"]["coverage_claim"], False)
            self.assertIs(report["cve_coverage"]["completeness"], False)
        self.assertNotIn("not_scanned", json.dumps(ignored))

    def test_backend_failure_at_scan_keeps_heuristic_and_drops_false_claims(self) -> None:
        directory = Path(tempfile.mkdtemp())
        garbage = directory / "not-wolf-syn"
        try:
            (directory / "lib.rs").write_text("unsafe fn marked() {}\n", encoding="utf-8")
            garbage.write_bytes(b"\x00not-an-executable\n")
            garbage.chmod(0o755)
            with patch.dict(os.environ, {"WOLF_SYN_BIN": str(garbage)}):
                corrupt = scan(directory, rust_syntax="syn")
            with patch.dict(os.environ, {"WOLF_SYN_BIN": "wolf_syn"}):
                relative = scan(directory, rust_syntax="syn")
            with patch.dict(os.environ, {"WOLF_SYN_BIN": str(directory / ".." / "wolf_syn")}):
                traversed = scan(directory, rust_syntax="syn")
            claimed = json.dumps({
                "coverage_claim": True,
                "macros_expanded": False,
                "cfg_evaluated": False,
                "names_resolved": False,
                "findings": [{"rule": "RUST_UNSAFE_INVENTORY", "line": 9}],
                "gaps": [],
            }).encode("utf-8")

            def false_claim(*_args, **_kwargs):
                return subprocess.CompletedProcess(args=["wolf_syn"], returncode=0, stdout=claimed)

            def nonzero(*_args, **_kwargs):
                return subprocess.CompletedProcess(args=["wolf_syn"], returncode=7, stdout=b"")

            with patch("wolf_auditor.rust_syn.subprocess.run", side_effect=false_claim):
                claimed_report = scan(directory, rust_syntax="syn")
            with patch("wolf_auditor.rust_syn.subprocess.run", side_effect=nonzero):
                failed = scan(directory, rust_syntax="syn")
            with patch(
                "wolf_auditor.rust_syn.subprocess.run",
                side_effect=subprocess.TimeoutExpired("wolf_syn", 1),
            ):
                timed = scan(directory, rust_syntax="syn")
        finally:
            shutil.rmtree(directory, ignore_errors=True)
        for report, reason in (
            (corrupt, "rust_syn_backend_failed"),
            (relative, "rust_syn_backend_unavailable"),
            (traversed, "rust_syn_backend_unavailable"),
            (claimed_report, "rust_syn_false_claim"),
            (failed, "rust_syn_backend_failed"),
            (timed, "rust_syn_timeout"),
        ):
            self.assertEqual(report["status"], "INCOMPLETE")
            self.assertIn(reason, _scan_reasons(report))
            self.assertEqual(report["analysis_limits"]["rust_syn_backend"], "explicit_request_incomplete")
            self.assertIs(report["analysis_limits"]["coverage_claim"], False)
            self.assertEqual(report["analysis_limits"]["rust_macros"], "not_expanded")
            self.assertIs(report["cve_coverage"]["completeness"], False)
            self.assertIsNone(report["cve_coverage"]["queried_at"])
            self.assertIn(("lib.rs", "RUST_UNSAFE_INVENTORY", 1), {
                (item["path"], item["rule"], item["line"]) for item in report["findings"]
            })
            self.assertNotIn(9, [item["line"] for item in report["findings"]])
            self.assertNotIn(report["status"], {"PASS", "REVIEWED", "APPROVED"})

    def test_path_and_include_do_not_read_outside_the_scanned_file(self) -> None:
        parent = Path(tempfile.mkdtemp())
        try:
            root = parent / "repo"
            outside = parent / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "secret.rs").write_text(
                "SECRET_OUTSIDE_MARKER\nunsafe fn from_disk() {}\n",
                encoding="utf-8",
            )
            source = "\n".join((
                "#[path = \"../outside/secret.rs\"]",
                "mod hidden;",
                "fn safe() { include!(concat!(\"../outside/secret.rs\")); }",
                "",
            ))
            (root / "lib.rs").write_text(source, encoding="utf-8")
            report = scan(root, rust_syntax="syn")
        finally:
            shutil.rmtree(parent, ignore_errors=True)
        encoded = json.dumps(report)
        self.assertNotIn("SECRET_OUTSIDE_MARKER", encoded)
        self.assertNotIn("from_disk", encoded)
        gaps = {(item["reason"], item.get("line")) for item in report["coverage_gaps"]}
        self.assertIn(("rust_module_file_not_read", _line_of(source, "mod hidden;")), gaps)
        self.assertIn(("rust_macro_not_expanded", _line_of(source, "include!")), gaps)
        self.assertNotIn("RUST_UNSAFE_INVENTORY", _rules(report))
        self.assertIs(report["analysis_limits"]["coverage_claim"], False)
        self.assertEqual(report["status"], "INCOMPLETE")

    def test_malformed_fn_is_a_heuristic_false_negative_and_syn_fail_closes(self) -> None:
        directory = Path(tempfile.mkdtemp())
        try:
            (directory / "broken.rs").write_text("fn {\n", encoding="utf-8")
            default = scan(directory)
            opted = scan(directory, rust_syntax="syn")
        finally:
            shutil.rmtree(directory, ignore_errors=True)
        self.assertEqual(default["findings"], [])
        self.assertEqual(
            default["coverage_gaps"],
            [],
            "default heuristic still misses malformed `fn {`; this assertion records that false negative",
        )
        self.assertEqual(default["status"], "NO_HEURISTIC_FINDINGS")
        self.assertEqual(
            default["analysis_limits"]["rust_syn_backend"],
            "not_invoked_default_scan_does_not_spawn",
        )
        self.assertEqual(default["analysis_limits"]["parser_stage"], "token_heuristic")
        self.assertEqual(opted["status"], "INCOMPLETE")
        self.assertEqual(opted["findings"], [])
        self.assertIn("rust_syn_parse_failed", _scan_reasons(opted))
        self.assertGreaterEqual(opted["coverage_gaps"][0]["line"], 1)
        self.assertEqual(
            opted["analysis_limits"]["rust_syn_backend"],
            "invoked_stdin_only_no_macro_expansion",
        )
        self.assertIs(opted["analysis_limits"]["coverage_claim"], False)
        self.assertNotIn(opted["status"], {"PASS", "REVIEWED", "APPROVED", "NO_HEURISTIC_FINDINGS"})

    def test_scan_keeps_prefix_findings_when_a_later_line_fails_to_parse(self) -> None:
        source = "\n".join((
            "unsafe fn marked() {}",
            "#[link(name = \"c\")]",
            "extern \"C\" {}",
            "#[unsafe]",
            "fn flagged() {}",
            "fn {",
            "",
        ))
        directory = Path(tempfile.mkdtemp())
        try:
            (directory / "lib.rs").write_text(source, encoding="utf-8")
            default = scan(directory)
            opted = scan(directory, rust_syntax="syn")
        finally:
            shutil.rmtree(directory, ignore_errors=True)
        self.assertEqual(
            default["analysis_limits"]["rust_syn_backend"],
            "not_invoked_default_scan_does_not_spawn",
        )
        self.assertNotIn("rust_syn_parse_failed", _scan_reasons(default))
        default_findings = {(item["path"], item["rule"], item["line"]) for item in default["findings"]}
        self.assertNotIn(("lib.rs", "RUST_FFI_BOUNDARY", _line_of(source, "#[link")), default_findings)
        self.assertNotIn(("lib.rs", "RUST_UNSAFE_INVENTORY", _line_of(source, "#[unsafe]")), default_findings)
        self.assertEqual(opted["status"], "INCOMPLETE")
        self.assertIs(opted["analysis_limits"]["coverage_claim"], False)
        self.assertEqual(opted["analysis_limits"]["rust_macros"], "not_expanded")
        self.assertEqual(opted["analysis_limits"]["rust_cfg"], "unresolved_not_evaluated")
        self.assertEqual(opted["analysis_limits"]["rust_names"], "not_resolved")
        self.assertIs(opted["cve_coverage"]["completeness"], False)
        self.assertIsNone(opted["cve_coverage"]["queried_at"])
        self.assertEqual(
            opted["analysis_limits"]["rust_syn_backend"],
            "invoked_stdin_only_no_macro_expansion",
        )
        findings = {(item["path"], item["rule"], item["line"]) for item in opted["findings"]}
        self.assertIn(("lib.rs", "RUST_UNSAFE_INVENTORY", 1), findings)
        self.assertIn(("lib.rs", "RUST_FFI_BOUNDARY", _line_of(source, "#[link")), findings)
        self.assertIn(("lib.rs", "RUST_UNSAFE_INVENTORY", _line_of(source, "#[unsafe]")), findings)
        self.assertNotIn(_line_of(source, "fn {"), [item["line"] for item in opted["findings"]])
        self.assertIn(("rust_syn_parse_failed", _line_of(source, "fn {")), {
            (item["reason"], item.get("line")) for item in opted["coverage_gaps"]
        })
        self.assertNotIn(opted["status"], {"PASS", "REVIEWED", "APPROVED", "NO_HEURISTIC_FINDINGS"})

    def test_rust_syntax_flag_rejects_values_outside_the_two_modes(self) -> None:
        directory = Path(tempfile.mkdtemp())
        try:
            for bad in (True, False, None, "compiler", "SYN"):
                with self.assertRaises(ValueError):
                    scan(directory, rust_syntax=bad)
        finally:
            shutil.rmtree(directory, ignore_errors=True)
