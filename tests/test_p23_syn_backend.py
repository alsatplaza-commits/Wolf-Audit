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
from wolf_auditor.engine import scan
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
            self.assertNotIn(code, {2})
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
        self.assertNotIn(report["status"], {"PASS", "REVIEWED", "APPROVED"})
        self.assertNotIn(opted, {2})
        empty = Path(tempfile.mkdtemp())
        try:
            (empty / "note.py").write_text("x = 1\n", encoding="utf-8")
            quiet = scan(empty, rust_syntax="syn")
        finally:
            shutil.rmtree(empty, ignore_errors=True)
        self.assertEqual(quiet["coverage_gaps"], [{"path": "<rust>", "reason": "rust_syn_no_rust_sources"}])
        self.assertEqual(quiet["status"], "INCOMPLETE")
        self.assertEqual(quiet["analysis_limits"]["rust_syn_backend"], "explicit_request_incomplete")
