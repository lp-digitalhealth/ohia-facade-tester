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
    rcv = sub.add_parser("receiver", help="run the ARex receiver the arex-callback case calls back to, on a public host")
    rcv.add_argument("--listen", default="0.0.0.0:8080", help="host:port to listen on (default 0.0.0.0:8080)")
    rcv.add_argument("--public-url", required=True, help="the https address the test server will use to reach this receiver")
    args = parser.parse_args(argv)

    if args.command == "list":
        print("\n".join(available_cases()))
        return 0

    if args.command == "receiver":
        return _run_receiver(args)

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


def _run_receiver(args) -> int:
    import os
    import time

    from .receiver import ArexReceiver, ReceiverError

    base = (os.environ.get("BASE_URL") or "").strip().rstrip("/")
    token = (os.environ.get("RECEIVER_CONTROL_TOKEN") or "").strip()
    if not base:
        print("Configuration error: BASE_URL (the test server) is required so the receiver can read its public key.", file=sys.stderr)
        return 2
    host, _, port = args.listen.rpartition(":")
    try:
        receiver = ArexReceiver(server_base=base, listen=(host or "0.0.0.0", int(port)), public_url=args.public_url,
                                control_token=token or None).start()
    except (ReceiverError, ValueError, OSError) as e:
        print("Receiver error: " + str(e), file=sys.stderr)
        return 2
    print(f"ARex receiver listening on {args.listen}, advertised as {receiver.public_url}. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        receiver.stop()
    return 0


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
