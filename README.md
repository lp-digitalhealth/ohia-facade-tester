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
| `baseline` case (15 steps) | Built. **15 of 15 pass** against a real stack (Caddy, HAPI 8.12 with PostgreSQL, and the facade) brought up with Docker Compose from a clean clone of `ohia-fhir-test-server` (2026-11-12, x86_64 sandbox, plain HTTP on `localhost`, so `ALLOW_HTTP=1`). That includes B01 to B05 and B15, which earlier had only been run against a local model and the facade code. **Not** run against the live VM, an HTTPS certificate, arm64, or a server behind a separate public name |
| `patient-access` case (15 steps, UC07 interaction 6) | Built. Run against the real facade jar with the real data on one machine: 15 of 15 pass once the data is loaded. **Not** run through the real proxy (Caddy) or on a deployed server |
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

### The `patient-access` case

Plays a patient app against the server's `/patient-access/fhir` base (CARIN Blue Button 2.2.0): find the member by the payer online member ID, then read coverage and the two claims. It needs the server release that has that base (`ohia-fhir-test-server`, draft PR 39) and the payer-side data **loaded by the organizer** (`POST /ode/admin/seed-patient-access`). The tester never loads data. If it is not loaded, the lookups fail with a message that says so.

```bash
python -m tester run --case patient-access --out results.json
```

It checks the member by business keys that the data repository defines for UC07 (the payer online ID, the Medicaid beneficiary ID, the claim numbers and the pre-authorization number). If those change in `ohia-test-data`, update the constants at the top of `tester/checks/patient_access.py`.

## Safety

- The token is read from the environment only and is replaced by `***` everywhere in the report, including inside response bodies.
- Checks are read-only. The write-style probes (B05, P15) are built so that even a wrongly open server stores nothing.
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
