"""CLI entry point: python -m wolf_auditor TARGET [--output report.json]."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import scan
from .reporting import to_sarif, to_sbom
from .osv import enrich_with_osv
from .policy import evaluate
from .delta import compare_reports


def main() -> int:
    parser = argparse.ArgumentParser(description="WOLF AUDITOR: read-only heuristic source audit")
    parser.add_argument("target", type=Path, help="local source directory to inspect; never executed")
    parser.add_argument("--output", type=Path, help="optional evidence JSON destination")
    parser.add_argument("--sarif", type=Path, help="optional redacted SARIF 2.1 report")
    parser.add_argument("--sbom", type=Path, help="optional CycloneDX 1.6 dependency inventory")
    parser.add_argument("--osv-online", action="store_true",
                        help="OPT IN: disclose package names and exact versions to OSV")
    parser.add_argument("--rust-syntax", choices=("heuristic", "syn"), default="heuristic",
                        help="OPT IN syn: stdin parse with the trusted wolf_syn helper. "
                             "Default heuristic does not spawn it. Syn does not expand macros, "
                             "evaluate cfg, resolve names, or load other modules.")
    parser.add_argument("--policy", type=Path, help="explicit JSON release policy")
    parser.add_argument("--gate-output", type=Path, help="optional JSON policy verdict; requires --policy")
    parser.add_argument("--baseline", type=Path, help="previous evidence JSON to compare against")
    parser.add_argument("--delta-output", type=Path, help="redacted delta JSON; requires --baseline")
    args = parser.parse_args()
    try:
        if args.gate_output and not args.policy:
            raise ValueError("--gate-output requires --policy")
        if args.delta_output and not args.baseline:
            raise ValueError("--delta-output requires --baseline")
        report = scan(args.target, rust_syntax=args.rust_syntax)
        if args.osv_online:
            print("OSV disclosure opted in: package names and exact versions sent to OSV", file=sys.stderr)
            report = enrich_with_osv(report)
        if args.rust_syntax == "syn":
            print(
                "Rust syn inventory opted in: trusted helper reads source on stdin; "
                "macros, cfg, names, and other modules stay unresolved",
                file=sys.stderr,
            )
        delta = None
        if args.baseline:
            if args.baseline.stat().st_size > 10_000_000:
                raise ValueError("baseline report exceeds 10 MB")
            previous = json.loads(args.baseline.read_text(encoding="utf-8"))
            delta = compare_reports(previous, report)
        verdict = None
        if args.policy:
            if args.policy.stat().st_size > 65_536:
                raise ValueError("policy file exceeds 64 KiB")
            policy_data = json.loads(args.policy.read_text(encoding="utf-8"))
            verdict = evaluate(report, policy_data)
        result = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        outputs = [
            (args.output, result),
            (args.sarif, json.dumps(to_sarif(report), ensure_ascii=False, indent=2) + "\n"),
            (args.sbom, json.dumps(to_sbom(report), ensure_ascii=False, indent=2) + "\n"),
            (args.gate_output, json.dumps(verdict, ensure_ascii=False, indent=2) + "\n"
             if verdict is not None else ""),
            (args.delta_output, json.dumps(delta, ensure_ascii=False, indent=2) + "\n"
             if delta is not None else ""),
        ]
        for destination, data in outputs:
            if destination is not None:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(data, encoding="utf-8")
        if args.output is None:
            sys.stdout.write(result)
        print(
            f"WOLF AUDITOR: {report['status']} | {report['scanned_files']} files | "
            f"{len(report['findings'])} findings | {len(report['coverage_gaps'])} gaps",
            file=sys.stderr,
        )
        if verdict is not None:
            print(f"WOLF AUDITOR GATE: {verdict['status']} reasons={verdict['reasons']}", file=sys.stderr)
            if "INCOMPLETE_COVERAGE" in verdict["reasons"]:
                return 2
            return 3 if verdict["status"] == "BLOCK" else 0
        return 2 if report["status"] == "INCOMPLETE" else (1 if report["findings"] else 0)
    except (OSError, ValueError) as error:
        print(f"AUDIT_INCOMPLETE: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
