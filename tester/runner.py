"""Runs a case (a JSON file describing steps) by looking up each step's check function.

A case file is the single source for both the runner and the teaching site: it names each step,
says what is expected and explains why. The check functions hold only the logic.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from .config import Config
from .exchange import Exchange, HttpClient, to_report

CASES_DIR = Path(__file__).resolve().parent.parent / "cases"


@dataclass
class Outcome:
    """What a check returns: the exchange it made (if any), what went wrong, and a short note."""
    exchange: Exchange | None = None
    problems: list[str] = field(default_factory=list)
    note: str = ""


class Context:
    def __init__(self, cfg: Config, http: HttpClient) -> None:
        self.cfg = cfg
        self.http = http
        self.state: dict[str, Any] = {}  # lets a later step reuse what an earlier one found, for one run

    def call(self, method: str, path: str, *, auth: bool = False, bearer: str | None = None,
             headers: dict[str, str] | None = None, body: bytes | str | None = None) -> Exchange:
        token = self.cfg.api_token if auth else bearer
        return self.http.request(method, self.cfg.url(path), headers=headers, body=body, bearer=token)


Check = Callable[[Context], Outcome]
REGISTRY: dict[str, Check] = {}


def check(step_id: str) -> Callable[[Check], Check]:
    def register(fn: Check) -> Check:
        if step_id in REGISTRY:
            raise ValueError("duplicate check id " + step_id)
        REGISTRY[step_id] = fn
        return fn
    return register


def load_case(case_id: str) -> dict[str, Any]:
    path = CASES_DIR / f"{case_id}.json"
    if not path.is_file():
        raise FileNotFoundError(f"No case file for '{case_id}' in {CASES_DIR}")
    return json.loads(path.read_text(encoding="utf-8"))


def available_cases() -> list[str]:
    return sorted(p.stem for p in CASES_DIR.glob("*.json"))


def run_case(case_id: str, ctx: Context) -> dict[str, Any]:
    # Import here so check modules register themselves.
    from . import checks  # noqa: F401

    case = load_case(case_id)
    secrets = [ctx.cfg.api_token]
    steps = []
    for spec in case["steps"]:
        fn = REGISTRY.get(spec["id"])
        if fn is None:
            outcome = Outcome(problems=[f"No check is implemented for step {spec['id']}."])
        else:
            try:
                outcome = fn(ctx)
            except Exception as e:  # a crashing check is a failed step, never a crashed run
                outcome = Outcome(problems=[f"The check itself failed to run: {type(e).__name__}: {e}"])
        steps.append({
            "id": spec["id"],
            "title": spec["title"],
            "expect": spec["expect"],
            "passed": not outcome.problems,
            "problems": [_clean(p, secrets) for p in outcome.problems],
            "note": _clean(outcome.note, secrets),
            "exchange": to_report(outcome.exchange, secrets) if outcome.exchange else None,
        })
    return {
        "id": case["id"],
        "title": case["title"],
        "passed": all(s["passed"] for s in steps),
        "steps": steps,
    }


def run_cases(case_ids: list[str], cfg: Config, http: HttpClient | None = None) -> dict[str, Any]:
    ctx = Context(cfg, http or HttpClient())
    cases = [run_case(c, ctx) for c in case_ids]
    steps = [s for c in cases for s in c["steps"]]
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "target": urlsplit(cfg.base_url).netloc,  # host only
        "summary": {"steps": len(steps), "passed": sum(1 for s in steps if s["passed"]),
                    "failed": sum(1 for s in steps if not s["passed"])},
        "cases": cases,
    }


def _clean(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text
