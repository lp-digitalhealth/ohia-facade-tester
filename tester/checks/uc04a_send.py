"""UC04a: the tester plays the teledentistry platform and sends the referral to the server.

The tester POSTs the real UC04a interaction 1 Bundle to /ode/receive/uc04a. The Bundle names two
intraoral photos but does not contain them. The server must then call BACK to the tester's ARex
server (tester/partner_arex.py), prove who it is, and download both photos, checking each against the
SHA-256 digest the Bundle declared.

The case WRITES to the server: it stores the Bundle in HAPI under the ids in the sample data and
creates two receipts (the second is the tampered-photo demonstration). Re-running is safe: HAPI
receives the same resources by PUT. The data is synthetic.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from ..partner_arex import PartnerArex
from ..runner import Context, Outcome, check

DATA = Path(__file__).resolve().parent.parent.parent / "cases" / "data" / "uc04a-send"
DIGEST_URL = "http://fhir.onyxhealth.io/us/arex/StructureDefinition/arex-digest"
CONTEXT_URL = "http://fhir.onyxhealth.io/us/arex/StructureDefinition/arex-transaction-context"
PRIVATE_JWK_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
# What the server is KNOWN to report for this sample data. Anything else is a surprise worth failing on.
KNOWN_FINDINGS = {
    "SIGNATURE_PLACEHOLDER",        # the sample manifest's signature is a placeholder (the draft spec does not say how to sign)
    "MANIFEST_EXPIRED_PER_PAYLOAD",  # the sample manifest's expiry date has passed; the data is a fixed sample
    "SUBSCRIPTION_NOT_STORED",       # real HAPI needs an extra extension on the sample Subscription
}
JSON_HEADERS = {"Content-Type": "application/fhir+json", "Accept": "application/json"}


# ---- the sample payload ----------------------------------------------------------------------

def _load_payload() -> dict:
    bundle = json.loads((DATA / "interaction-01-bundle.json").read_text(encoding="utf-8"))
    resources = [e["resource"] for e in bundle["entry"]]
    manifest = next(r for r in resources if r["resourceType"] == "List")
    entries = [r for r in resources if r["resourceType"] == "DocumentReference" and r["id"].startswith("arex-entry-")]
    objects = {r["id"]: (DATA / "arex-payloads" / f"intraoral-photo-{r['id'][-1]}.jpg").read_bytes() for r in entries}
    for r in entries:  # the sample must be internally honest, or every later step would blame the server
        declared = _declared_digest(r)
        actual = hashlib.sha256(objects[r["id"]]).hexdigest()
        if declared != actual:
            raise ValueError(f"The sample data is inconsistent: {r['id']} declares {declared} but the file is {actual}.")
    ids = [x["valueIdentifier"]["value"] for e in manifest["extension"] if e["url"] == CONTEXT_URL
           for x in e["extension"] if x["url"] == "businessIdentifier"]
    return {"bundle": bundle, "manifest": manifest, "entries": entries, "objects": objects, "referral_id": ids[0]}


def _declared_digest(entry: dict) -> str:
    for ext in entry["content"][0]["attachment"]["extension"]:
        if ext["url"] == DIGEST_URL:
            return next(p["valueString"] for p in ext["extension"] if p["url"] == "value")
    raise ValueError("no digest on " + entry["id"])


def _payload_for(payload: dict, partner_base: str) -> bytes:
    """The sample, with each photo's address pointed at THIS tester's ARex server."""
    bundle = copy.deepcopy(payload["bundle"])
    for e in bundle["entry"]:
        r = e["resource"]
        if r["id"] in payload["objects"] and r["resourceType"] == "DocumentReference":
            r["content"][0]["attachment"]["url"] = f"{partner_base}/arex/Binary/{r['id']}"
    return json.dumps(bundle).encode("utf-8")


# ---- shared steps of setup ---------------------------------------------------------------------

def _need(ctx: Context, key: str, problems: list[str]):
    """Return something an earlier step stored, or note that this step cannot run without it."""
    if key not in ctx.state:
        problems.append("This step needs an earlier step to have succeeded first (it did not).")
    return ctx.state.get(key)


def _send(ctx: Context, payload: dict, partner: PartnerArex):
    return ctx.call("POST", "/ode/receive/uc04a", auth=True, headers=JSON_HEADERS, body=_payload_for(payload, partner.base))


def _statuses(receipt: dict) -> list[str]:
    return [o.get("status") for o in receipt.get("objects", [])]


def _codes(receipt: dict) -> set[str]:
    return {f.get("code") for f in receipt.get("findings", [])}


# ---- the steps -----------------------------------------------------------------------------------

@check("U01")
def learn_server_identity(ctx: Context) -> Outcome:
    ex = ctx.call("GET", "/ode/identity", auth=True, headers={"Accept": "application/json"})
    problems: list[str] = []
    if ex.status != 200:
        return Outcome(ex, [f"Expected HTTP 200, got {ex.status} ({ex.error or 'no detail'})."])
    ident = ex.json() or {}
    if ident.get("signing_algorithm") != "RS384":
        problems.append(f"Expected the server to sign with RS384, it says {ident.get('signing_algorithm')!r}.")
    if not ident.get("client_id"):
        problems.append("The identity has no client_id.")
    keys_ex = ctx.call("GET", "/arex/jwks.json")
    kid = None
    if keys_ex.status != 200:
        problems.append(f"The public key set should be open (HTTP 200), got {keys_ex.status}.")
    else:
        keys = (keys_ex.json() or {}).get("keys") or []
        if not keys:
            problems.append("The public key set has no keys.")
        elif any(PRIVATE_JWK_FIELDS & set(k) for k in keys):
            problems.append("The public key set contains private key material.")
        else:
            kid = keys[0].get("kid")
    if not problems:
        ctx.state["uc04a_identity"] = {"client_id": ident["client_id"], "kid": kid}
    return Outcome(ex, problems, note=f"client id {ident.get('client_id')}, key id {kid}")


@check("U02")
def start_partner_server(ctx: Context) -> Outcome:
    problems: list[str] = []
    ident = _need(ctx, "uc04a_identity", problems)
    cfg = ctx.cfg
    if ident and not cfg.partner_public_url and not cfg.allow_http:
        return Outcome(problems=["Set PARTNER_PUBLIC_URL to the https address the server can reach this tester at, "
                                 "for example https://tester.example.org (a reverse proxy that forwards to PARTNER_PORT)."])
    if not ident:
        return Outcome(problems=problems)
    payload = _load_payload()
    partner = PartnerArex(host=cfg.partner_host if cfg.partner_public_url else "127.0.0.1", port=cfg.partner_port,
                          public_url=cfg.partner_public_url, jwks_url=cfg.url("/arex/jwks.json"),
                          client_id=ident["client_id"], manifest=payload["manifest"], objects=payload["objects"])
    ctx.on_close(partner.stop)
    ctx.state.update(uc04a_payload=payload, uc04a_partner=partner)
    ex = ctx.http.request("GET", partner.base + "/arex/.well-known/smart-configuration")
    if ex.status != 200:
        problems.append(f"The tester's own ARex server is not reachable at {partner.base} (HTTP {ex.status}, {ex.error}). "
                        "The server could not reach it either.")
    elif (ex.json() or {}).get("token_endpoint") != partner.token_endpoint:
        problems.append("The discovery document does not name the expected token endpoint.")
    partner.reset_observations()  # that request was ours, not the server's
    return Outcome(ex, problems, note=f"listening for the server at {partner.base}")


@check("U03")
def receive_needs_token(ctx: Context) -> Outcome:
    ex = ctx.call("POST", "/ode/receive/uc04a", headers=JSON_HEADERS, body=b'{"resourceType":"Bundle","type":"transaction"}')
    problems: list[str] = []
    if ex.status != 401:
        problems.append(f"Expected HTTP 401 without a token, got {ex.status}. A receiver that accepts anyone can be filled by anyone.")
    return Outcome(ex, problems)


@check("U04")
def reject_non_transaction(ctx: Context) -> Outcome:
    ex = ctx.call("POST", "/ode/receive/uc04a", auth=True, headers=JSON_HEADERS, body=b'{"resourceType":"Patient"}')
    problems: list[str] = []
    if ex.status != 422:
        problems.append(f"Expected HTTP 422 for something that is not a transaction Bundle, got {ex.status}.")
    return Outcome(ex, problems)


@check("U05")
def send_the_referral(ctx: Context) -> Outcome:
    problems: list[str] = []
    partner, payload = _need(ctx, "uc04a_partner", problems), ctx.state.get("uc04a_payload")
    if partner is None:
        return Outcome(problems=problems)
    ex = _send(ctx, payload, partner)
    if ex.status != 200:
        detail = (ex.json() or {}).get("error") if ex.json() else ex.error
        return Outcome(ex, [f"Expected HTTP 200, got {ex.status}. {detail or ''}".strip()])
    receipt = ex.json() or {}
    if receipt.get("accepted") is not True:
        problems.append("The receipt does not say accepted: true.")
    ctx.state["uc04a_receipt"] = receipt
    return Outcome(ex, problems, note=f"receipt {receipt.get('id')}")


@check("U06")
def referral_stored_and_identified(ctx: Context) -> Outcome:
    problems: list[str] = []
    receipt, payload = _need(ctx, "uc04a_receipt", problems), ctx.state.get("uc04a_payload")
    if receipt is None:
        return Outcome(problems=problems)
    total = len(payload["bundle"]["entry"])
    stored = receipt.get("hapiEntries")
    if not isinstance(stored, int) or stored < total - 1:  # one entry (the Subscription) may legitimately be left out
        problems.append(f"The Bundle has {total} entries; the server reports {stored!r} stored. At most one (the Subscription) may be left out.")
    if receipt.get("referralId") != payload["referral_id"]:
        problems.append(f"Expected referral id {payload['referral_id']!r}, the server found {receipt.get('referralId')!r}.")
    if receipt.get("manifestId") != payload["manifest"]["id"]:
        problems.append(f"Expected manifest id {payload['manifest']['id']!r}, the server found {receipt.get('manifestId')!r}.")
    return Outcome(problems=problems, note=f"{stored} of {total} entries stored")


@check("U07")
def server_proved_who_it_is(ctx: Context) -> Outcome:
    problems: list[str] = []
    partner = _need(ctx, "uc04a_partner", problems)
    if partner is None:
        return Outcome(problems=problems)
    if partner.assertions_rejected:
        problems.append("The tester refused the server's signed token request: " + "; ".join(partner.assertions_rejected))
    if partner.assertions_verified != 1:
        problems.append(f"Expected exactly one verified signed token request, saw {partner.assertions_verified}.")
    seen = {"discovery": partner.count("GET /arex/.well-known"), "token": partner.count("POST /arex/auth/token"),
            "manifest": partner.count("GET /arex/List/"), "images": partner.count("GET /arex/Binary/")}
    if seen != {"discovery": 1, "token": 1, "manifest": 1, "images": 2}:
        problems.append(f"Expected 1 discovery, 1 token, 1 published manifest and 2 image requests, saw {seen}.")
    if not any(s and "system/Binary.r" in s for s in partner.scopes):
        problems.append("The token request should ask for the system/Binary.r scope; the scopes seen were " + repr(partner.scopes))
    return Outcome(problems=problems, note=f"the server called back: {seen}")


@check("U08")
def photos_pulled_and_verified(ctx: Context) -> Outcome:
    problems: list[str] = []
    receipt, payload = _need(ctx, "uc04a_receipt", problems), ctx.state.get("uc04a_payload")
    if receipt is None:
        return Outcome(problems=problems)
    if _statuses(receipt) != ["saved", "saved"]:
        problems.append(f"Expected both photos to be 'saved', the receipt says {_statuses(receipt)}.")
    declared = {_declared_digest(e) for e in payload["entries"]}
    reported = {o.get("declaredSha256") for o in receipt.get("objects", [])}
    if reported != declared:
        problems.append("The receipt's digests are not the digests the Bundle declared.")
    if not all(o.get("viewable") for o in receipt.get("objects", [])):
        problems.append("Both photos are JPEG, so both should be marked viewable.")
    return Outcome(problems=problems)


@check("U09")
def findings_are_only_the_known_gaps(ctx: Context) -> Outcome:
    problems: list[str] = []
    receipt = _need(ctx, "uc04a_receipt", problems)
    if receipt is None:
        return Outcome(problems=problems)
    surprising = _codes(receipt) - KNOWN_FINDINGS
    if surprising:
        problems.append("The server reported findings the sample data should not cause: " + ", ".join(sorted(surprising)))
    return Outcome(problems=problems, note="findings: " + ", ".join(sorted(_codes(receipt))))


@check("U10")
def receipt_can_be_read_back(ctx: Context) -> Outcome:
    problems: list[str] = []
    receipt = _need(ctx, "uc04a_receipt", problems)
    if receipt is None:
        return Outcome(problems=problems)
    ex = ctx.call("GET", f"/ode/receipts/{receipt['id']}", auth=True, headers={"Accept": "application/json"})
    if ex.status != 200:
        problems.append(f"Expected HTTP 200 reading the receipt, got {ex.status}.")
    elif (ex.json() or {}).get("id") != receipt["id"]:
        problems.append("The receipt read back has a different id.")
    return Outcome(ex, problems)


@check("U11")
def referral_and_allergy_are_in_fhir(ctx: Context) -> Outcome:
    problems: list[str] = []
    if _need(ctx, "uc04a_receipt", problems) is None:
        return Outcome(problems=problems)
    ex = ctx.call("GET", "/fhir/AllergyIntolerance/allergyintolerance-penicillin", auth=True, headers={"Accept": "application/fhir+json"})
    if ex.status != 200:
        problems.append(f"Expected the allergy to be readable (HTTP 200), got {ex.status}.")
    else:
        body = ex.json() or {}
        if "91936005" not in json.dumps(body.get("code", {})) or (body.get("reaction") or [{}])[0].get("severity") != "moderate":
            problems.append("The allergy was stored but is not the penicillin / moderate one that was sent.")
    sr = ctx.call("GET", "/fhir/ServiceRequest/servicerequest-referral", auth=True, headers={"Accept": "application/fhir+json"})
    if sr.status != 200 or (sr.json() or {}).get("resourceType") != "ServiceRequest":
        problems.append(f"Expected the referral (ServiceRequest) to be readable, got HTTP {sr.status}.")
    return Outcome(sr, problems)


@check("U12")
def photos_are_served_back_exactly(ctx: Context) -> Outcome:
    problems: list[str] = []
    receipt, payload = _need(ctx, "uc04a_receipt", problems), ctx.state.get("uc04a_payload")
    if receipt is None:
        return Outcome(problems=problems)
    last = None
    for obj in receipt.get("objects", []):
        last = ctx.call("GET", f"/ode/receipts/{receipt['id']}/images/{obj.get('fileKey')}", auth=True)
        sent = payload["objects"].get(obj.get("entryId"))
        if last.status != 200:
            problems.append(f"{obj.get('entryId')}: expected HTTP 200, got {last.status}.")
        elif last.response_body != sent:
            problems.append(f"{obj.get('entryId')}: the bytes served back are not the bytes that were sent.")
        elif (last.header("Content-Type") or "").split(";")[0] != "image/jpeg":
            problems.append(f"{obj.get('entryId')}: expected Content-Type image/jpeg, got {last.header('Content-Type')!r}.")
    return Outcome(last, problems)


@check("U13")
def a_tampered_photo_is_caught(ctx: Context) -> Outcome:
    problems: list[str] = []
    partner, payload = _need(ctx, "uc04a_partner", problems), ctx.state.get("uc04a_payload")
    if partner is None:
        return Outcome(problems=problems)
    partner.reset_observations()
    partner.tamper = True
    try:
        ex = _send(ctx, payload, partner)
    finally:
        partner.tamper = False
    if ex.status != 200:
        return Outcome(ex, [f"Expected HTTP 200 (a failed pull is a result, not an error), got {ex.status}."])
    receipt = ex.json() or {}
    if _statuses(receipt) != ["digest-mismatch", "digest-mismatch"]:
        problems.append(f"Expected both altered photos to be 'digest-mismatch', the receipt says {_statuses(receipt)}.")
    if "DIGEST_MISMATCH" not in _codes(receipt):
        problems.append("Expected a DIGEST_MISMATCH finding.")
    if receipt.get("objects"):
        served = ctx.call("GET", f"/ode/receipts/{receipt['id']}/images/{receipt['objects'][0].get('fileKey')}", auth=True)
        if served.status != 404:
            problems.append(f"A photo that failed its digest must not be served; expected HTTP 404, got {served.status}.")
    return Outcome(ex, problems, note="one bit of each photo was flipped on the way")
