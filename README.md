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
| `baseline` case (15 steps) | Built. Run against the live server (Oracle VM, behind Caddy and real HAPI) from a Windows computer on 2026-11-20: 15 of 15 passed (reported by the owner) |
| `patient-access` case (15 steps, UC07 interaction 6) | Built. Run against the live server on 2026-11-21: it found that Caddy's plain-text 401 hid the FHIR error (step P02); after the fix the owner reports 15 of 15 |
| `arex-callback` case (9 steps, UC04a) | Built. Run end to end on one machine against the **real server jar** (main) with a stand-in HAPI and the in-process receiver: 9 of 9 pass. **Not** run against the live server, a public receiver, or a real client's ARex server |
| ARex receiver (`python -m tester receiver`) | Built and unit tested. **Not deployed**: it needs a public https host |
| Teaching site, GitHub Actions, second-VM automation | Not built yet |

## Run it

```bash
pip install -r requirements.txt          # PyJWT and cryptography: only the arex-callback case needs them
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

### The `arex-callback` case

Tests the part of UC04a that comes **after** a client sends a referral: the test server calls **back** to the client's ARex server to fetch the images. This harness plays the client. It sends the sample UC04a referral with image links that point at a receiver it controls (`tester/receiver.py`), then checks what the server answered, what its receipt says, and what the receiver itself saw (a signed token request it verified with the server's public key, the manifest read, each image downloaded). It also runs two bad-sender cases: a tampered image must not be saved, and a refused token must stop the pull and be reported.

**This case writes.** It stores the sample referral on the server and leaves receipts there. The sample uses the same resource ids as the UC04a sample a real tester sends, so running it overwrites that tester's copy on the same server (the known limit in the server's docs). Use it on a test server.

The receiver must be reachable **from the server**:

- **Server on this machine** (local testing): nothing extra. The case starts the receiver itself on 127.0.0.1. The server must allow http and private addresses, which it does only with its two test-only flags (`facade.send.allow-http`, `facade.send.allow-private-targets`).
- **Server elsewhere** (a deployed server): run the receiver on a public https host, and tell the case where it is.

```bash
# on the public host (behind https, for example Caddy proxying to this port)
export BASE_URL=https://the-test-server.example.org      # so the receiver can read the server's public key
export RECEIVER_CONTROL_TOKEN=...                         # long random; lets the case read and steer this receiver
python -m tester receiver --listen 127.0.0.1:8080 --public-url https://receiver.example.org

# wherever you run the tests
export RECEIVER_URL=https://receiver.example.org
export RECEIVER_CONTROL_TOKEN=...                         # the same value
python -m tester run --case arex-callback
```

The control token never appears in a report. Not built yet: the automation that creates the public receiver host, and a run of this case against the live server.

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
