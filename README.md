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
| `patient-access` case (15 steps, UC07 interaction 6) | Built. Run against the real facade jar with the real data on one machine: 15 of 15 pass once the data is loaded. **Not** run through the real proxy (Caddy) or on a deployed server |
| `uc04a-send` case (13 steps, UC04a interaction 1: the tester plays the platform and sends the referral) | Built. Run against the real facade jar + real HAPI + real Caddy on one machine over plain http: 13 of 13 pass. **Not** run through real TLS or against the live VM, and never with a tester reached over the internet. Unit-tested against a model with 11 one-rule-at-a-time failure switches |
| UC07 case (the server sends to the tester) | Not built yet |
| Receiver, teaching site, GitHub Actions, second-VM automation | Not built yet |

## Run it

```bash
pip install -r requirements.txt          # only needed for cases where the tester signs or verifies (uc04a-send)
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

### The `uc04a-send` case

Plays the **teledentistry platform**: it POSTs the real UC04a interaction 1 Bundle (penicillin allergy, no dental home, an ARex manifest of two photos) to `/ode/receive/uc04a`. The server then calls the tester back to download the photos, so **the tester must be reachable from the server**. It runs a small ARex server (`tester/partner_arex.py`) while the case runs.

```bash
export PARTNER_PUBLIC_URL=https://tester.example.org   # https address the SERVER can reach this tester at
export PARTNER_PORT=9200                                # the tester listens here; point your reverse proxy at it
pip install -r requirements.txt                         # PyJWT and cryptography are needed here
python -m tester run --case uc04a-send --out results.json
```

- Local run: set `ALLOW_HTTP=1` and leave `PARTNER_PUBLIC_URL` empty; the tester then advertises `http://127.0.0.1:<port>`. A real server only accepts that if it was started with its test-only flags (see the server repo's `facade/e2e/README.md`). **Never use those flags on a deployment.**
- The case **writes** synthetic data to the server (the Bundle's resources, two receipts). Re-running is safe: the resources are PUT by id.
- Step U13 makes the tester serve photos with one bit flipped, to prove the server's digest check works.
- The sample data in `cases/data/uc04a-send/` is a copy of `ohia-test-data` branch `november_testing` at commit `34623681eb97c58dc8d44e5ca878f09da4342611` (`interaction-01-bundle.json` and `arex-payloads/`); see `cases/data/uc04a-send/SOURCE.md`. If that data changes, copy it again; a test fails if the photos no longer match the digests in the Bundle.
- Not verified: TLS to a public tester, a tester behind a real reverse proxy, and the live VM. The ARex draft leaves several wire details open; the contract used is the server's `docs/UC04A_SENDING_GUIDE.md`.

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
