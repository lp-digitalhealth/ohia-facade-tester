"""Command line: python -m tester list | run [--case ID ...] [--out FILE]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import ConfigError, from_env
from .runner import available_cases, run_cases


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tester", description="Test an OHIA FHIR test server like a real client.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list the available cases")
    run = sub.add_parser("run", help="run cases against BASE_URL using API_TOKEN (both from the environment)")
    run.add_argument("--case", action="append", help="case id; repeat for several (default: all)")
    run.add_argument("--out", help="write the JSON report here")
    args = parser.parse_args(argv)

    if args.command == "list":
        print("\n".join(available_cases()))
        return 0

    try:
        cfg = from_env()
    except ConfigError as e:
        print("Configuration error: " + str(e), file=sys.stderr)
        return 2
    ids = args.case or available_cases()
    unknown = [c for c in ids if c not in available_cases()]
    if unknown:
        print("Unknown case(s): " + ", ".join(unknown), file=sys.stderr)
        return 2

    report = run_cases(ids, cfg)
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    _print(report)
    return 0 if report["summary"]["failed"] == 0 else 1


def _print(report: dict) -> None:
    print(f"Target: {report['target']}   {report['generated_at']}")
    for case in report["cases"]:
        print(f"\n{case['title']}  [{'PASS' if case['passed'] else 'FAIL'}]")
        for step in case["steps"]:
            print(f"  {'PASS' if step['passed'] else 'FAIL'}  {step['id']}  {step['title']}")
            for problem in step["problems"]:
                print("        - " + problem)
    s = report["summary"]
    print(f"\n{s['passed']} of {s['steps']} steps passed, {s['failed']} failed.")


if __name__ == "__main__":
    sys.exit(main())
