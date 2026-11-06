# ohia-facade-tester

Tests the OHIA FHIR test server the way a real partner would, and teaches developers new to FHIR what each step means.

Two purposes:

1. **Test the live server.** Run cases against a deployed server (`BASE_URL`) using its shared token (`API_TOKEN`). New use cases are added as new case files.
2. **Teach.** Each step in a case carries a plain-language explanation of the FHIR, OAuth and ARex ideas behind it. The same files drive the test runner and the teaching site.

It is deployed **separately** from the server it tests.

## Status

| Part | State |
|---|---|
| Runner, report format, redaction | Built, unit tested |
| `baseline` case (15 steps) | Built. Steps B06 to B14 verified against the real facade code running locally. B01 to B05 and B15 need the real proxy and HAPI and have **not** been run against them |
| UC07 and UC04a cases (need a public receiver) | Not built yet |
| Receiver, teaching site, GitHub Actions, second-VM automation | Not built yet |

## Run it

```bash
pip install -r requirements.txt          # only needed for the later signing steps
export BASE_URL=https://your-server.example.org     # server root, no /fhir
export API_TOKEN=...                                  # never put this on the command line
python -m tester list
python -m tester run --case baseline --out results.json
```

Exit code 0 = every step passed, 1 = a step failed, 2 = bad configuration.

## Safety

- The token is read from the environment only and is replaced by `***` everywhere in the report, including inside response bodies.
- Checks are read-only. The one write-style probe (B05) is built so that even a wrongly open server stores nothing.
- Reports name the target host only.

## Tests

```bash
python -m unittest discover -s . -t .
```

The unit tests run against a local model of the server (`tests/fake_server.py`) with switches that break one rule at a time, so each check is shown to fail when the thing it guards is broken. A model is not the server: the real run is the final proof.

## Adding a case

1. Add `cases/<id>.json` with `id`, `title`, and `steps` (each with `id`, `title`, `expect`, `why`).
2. Add a check function for each step id in `tester/checks/` using `@check("<id>")`.
3. `tests/test_baseline.py` fails if a step has no check, or a check has no step.
