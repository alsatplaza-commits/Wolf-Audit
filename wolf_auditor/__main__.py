"""CLI entry point: python -m wolf_auditor TARGET [--output report.json]."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import scan


def main() -> int:
    parser = argparse.ArgumentParser(description="WOLF AUDITOR: read-only heuristic source audit")
    parser.add_argument("target", type=Path, help="local source directory to inspect; never executed")
    parser.add_argument("--output", type=Path, help="optional report JSON destination")
    args = parser.parse_args()
    try:
        report = scan(args.target)
        result = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(result, encoding="utf-8")
        else:
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
