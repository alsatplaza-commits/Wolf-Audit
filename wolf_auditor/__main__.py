"""CLI entry point: python -m wolf_auditor TARGET [--output report.json]."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import scan
from .reporting import to_sarif, to_sbom


def main() -> int:
    parser = argparse.ArgumentParser(description="WOLF AUDITOR: read-only heuristic source audit")
    parser.add_argument("target", type=Path, help="local source directory to inspect; never executed")
    parser.add_argument("--output", type=Path, help="optional evidence JSON destination")
    parser.add_argument("--sarif", type=Path, help="optional redacted SARIF 2.1 report")
    parser.add_argument("--sbom", type=Path, help="optional CycloneDX 1.6 dependency inventory")
    args = parser.parse_args()
    try:
        report = scan(args.target)
        result = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        outputs = [
            (args.output, result),
            (args.sarif, json.dumps(to_sarif(report), ensure_ascii=False, indent=2) + "\n"),
            (args.sbom, json.dumps(to_sbom(report), ensure_ascii=False, indent=2) + "\n"),
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
        return 2 if report["status"] == "INCOMPLETE" else (1 if report["findings"] else 0)
    except (OSError, ValueError) as error:
        print(f"AUDIT_INCOMPLETE: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
