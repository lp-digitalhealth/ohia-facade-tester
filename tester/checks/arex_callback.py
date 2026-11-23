"""arex-callback checks: a client sends a referral, and the test server calls BACK to the client's ARex server.

This case plays the client. It sends the UC04a interaction 1 referral with image links that point at a receiver the
harness controls (see tester/receiver.py), then checks three things from three sides: what the server answered, what the
receipt says happened, and what the receiver actually saw. The case WRITES: it stores the sample referral on the server
and leaves receipts there. Use it only on a test server.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import urlsplit

from ..exchange import Exchange
from ..receiver import CONTROL_HEADER, ArexReceiver, ReceiverError
from ..runner import Context, Outcome, check
from .baseline import _status

POLL_SECONDS = 90  # how long a receipt may stay pending before the step fails
FAST_REPLY_MS = 15_000  # the answer must not wait for the callback
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# Findings that are normal while ARex is a draft or HAPI refuses the sample's Subscription; anything else is a problem.
EXPECTED_FINDINGS = {"SUBSCRIPTION_NOT_STORED", "SIGNATURE_PLACEHOLDER", "SIGNATURE_NOT_VERIFIED"}


# ---- the receiver, local or remote ---------------------------------------------------------------------

class _Local:
    """A receiver running inside this process (the server must be able to reach this machine)."""

    def __init__(self, receiver: ArexReceiver) -> None:
        self._r = receiver
        self.public_url = receiver.public_url

    def bundle(self) -> dict[str, Any]:
        return self._r.payload()

    def snapshot(self) -> dict[str, Any]:
        return self._r.snapshot()

    def reset(self) -> None:
        self._r.reset()

    def set_modes(self, **modes: bool) -> None:
        self._r.set_modes(**modes)


class _Remote:
    """A receiver running elsewhere (`python -m tester receiver`), steered through its control API."""

    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx
        self.public_url = ctx.cfg.receiver_url

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        ex = self._ctx.http.request(method, self.public_url + path, headers={CONTROL_HEADER: self._ctx.cfg.receiver_control_token,
                                                                             "Content-Type": "application/json"},
                                    body=None if body is None else json.dumps(body))
        if ex.status != 200:
            raise ReceiverError(f"The receiver's control API answered HTTP {ex.status} for {path} "
                                "(is RECEIVER_CONTROL_TOKEN the one the receiver was started with?)." if ex.status != -1 else
                                f"The receiver at {self.public_url} did not answer: {ex.error}")
        return ex.json()

    def bundle(self) -> dict[str, Any]:
        return self._call("GET", "/__harness/bundle")

    def snapshot(self) -> dict[str, Any]:
        return self._call("GET", "/__harness/log")

    def reset(self) -> None:
        self._call("POST", "/__harness/reset", {})

    def set_modes(self, **modes: bool) -> None:
        self._call("POST", "/__harness/mode", modes)


def _receiver(ctx: Context):
    """The receiver for this run, started or reached once. Raises ReceiverError with what to do if there is none."""
    if "receiver" in ctx.state:
        return ctx.state["receiver"]
    cfg = ctx.cfg
    if cfg.receiver_url:
        handle: Any = _Remote(ctx)
    else:
        host = urlsplit(cfg.base_url).hostname or ""
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ReceiverError("The server is not on this machine, so it cannot call back to a receiver started here. Run the receiver on a "
                                "public host (python -m tester receiver) and set RECEIVER_URL (and RECEIVER_CONTROL_TOKEN) to its address.")
        listen = cfg.receiver_listen or "127.0.0.1:0"
        h, _, p = listen.rpartition(":")
        receiver = ArexReceiver(server_base=cfg.base_url, listen=(h or "127.0.0.1", int(p or 0)),
                                control_token=cfg.receiver_control_token or None).start()
        ctx.on_close(receiver.stop)
        handle = _Local(receiver)
    ctx.state["receiver"] = handle
    return handle


def _need_receiver(ctx: Context, problems: list[str]):
    try:
        return _receiver(ctx)
    except (ReceiverError, ValueError, OSError) as e:
        problems.append(str(e))
        return None


# ---- send and wait --------------------------------------------------------------------------------------

def _send(ctx: Context, receiver) -> Exchange:
    return ctx.call("POST", "/ode/receive/uc04a", auth=True,
                    headers={"Content-Type": "application/fhir+json", "Accept": "application/fhir+json"},
                    body=json.dumps(receiver.bundle()))


def _receipt_id(ex: Exchange) -> str | None:
    value = ex.header("X-Receipt-Id")
    return value if value and UUID.match(value) else None


def _wait_for_receipt(ctx: Context, receipt_id: str, problems: list[str]) -> dict[str, Any] | None:
    deadline = time.monotonic() + POLL_SECONDS
    last: Exchange | None = None
    while True:
        last = ctx.call("GET", f"/ode/receipts/{receipt_id}", auth=True, headers={"Accept": "application/json"})
        body = last.json() if last.status == 200 else None
        if isinstance(body, dict) and body.get("state") != "pending":
            return body
        if last.status not in (200, -1):
            problems.append(f"Reading the receipt gave HTTP {last.status}.")
            return None
        if time.monotonic() >= deadline:
            problems.append(f"The receipt was still 'pending' after {POLL_SECONDS} seconds: the callback never finished.")
            return None
        time.sleep(1)


def _sent(ctx: Context, receiver, problems: list[str]) -> tuple[Exchange, dict[str, Any] | None]:
    ex = _send(ctx, receiver)
    if not _status(ex, 200, problems):
        return ex, None
    rid = _receipt_id(ex)
    if rid is None:
        problems.append("The reply carries no X-Receipt-Id header, so there is no way to find the result.")
        return ex, None
    return ex, _wait_for_receipt(ctx, rid, problems)


def _requests(snapshot: dict[str, Any], method: str, prefix: str) -> list[dict[str, Any]]:
    return [r for r in snapshot.get("requests", []) if r["method"] == method and r["path"].startswith(prefix)]


def _codes(receipt: dict[str, Any]) -> set[str]:
    return {f.get("code", "") for f in receipt.get("findings", [])}


# ---- the steps ------------------------------------------------------------------------------------------

@check("R01")
def receiver_ready(ctx: Context) -> Outcome:
    problems: list[str] = []
    receiver = _need_receiver(ctx, problems)
    if receiver is None:
        return Outcome(problems=problems)
    ex = ctx.http.request("GET", receiver.public_url + "/arex/.well-known/smart-configuration", headers={"Accept": "application/json"})
    if _status(ex, 200, problems):
        doc = ex.json() or {}
        endpoint = str(doc.get("token_endpoint", ""))
        if not endpoint.startswith(receiver.public_url + "/") or not endpoint.endswith("/arex/auth/token"):
            problems.append(f"The receiver's token_endpoint {endpoint!r} should be {receiver.public_url}/arex/auth/token.")
        if "RS384" not in doc.get("token_endpoint_auth_signing_alg_values_supported", []):
            problems.append("The receiver should accept RS384, the algorithm the server signs with.")
    if not problems:  # start every run from a clean receiver
        try:
            receiver.reset()
            receiver.set_modes(tamper=False, refuse_token=False)
        except ReceiverError as e:
            problems.append(str(e))
    return Outcome(ex, problems)


@check("R02")
def referral_answered_at_once(ctx: Context) -> Outcome:
    problems: list[str] = []
    receiver = _need_receiver(ctx, problems)
    if receiver is None:
        return Outcome(problems=problems)
    ex = _send(ctx, receiver)
    if _status(ex, 200, problems):
        body = ex.json()
        if "fhir+json" not in (ex.header("Content-Type") or "").lower():
            problems.append("The reply should be application/fhir+json.")
        if not isinstance(body, dict) or body.get("resourceType") != "Bundle" or body.get("type") != "transaction-response":
            problems.append("A posted transaction should be answered with a Bundle of type transaction-response (FHIR R4, HTTP: Batch/Transaction Response). "
                            "A custom body is not something a FHIR client can read.")
        rid = _receipt_id(ex)
        link = ex.header("Link") or ""
        if rid is None:
            problems.append("The reply has no X-Receipt-Id header saying where the result will be.")
        elif rid not in link or 'rel="receipt"' not in link:
            problems.append('The Link header should point at the receipt: <.../ode/receipts/{id}>; rel="receipt".')
        if ex.elapsed_ms > FAST_REPLY_MS:
            problems.append(f"The answer took {ex.elapsed_ms} ms. It should not wait for the callback to the sender.")
        ctx.state["sent_receipt_id"] = rid
    return Outcome(ex, problems, note="This step stores the sample referral on the server.")


@check("R03")
def callback_finishes(ctx: Context) -> Outcome:
    problems: list[str] = []
    rid = ctx.state.get("sent_receipt_id")
    if not rid:
        return Outcome(problems=["This step needs the receipt id from step R02."])
    receipt = _wait_for_receipt(ctx, rid, problems)
    if receipt is not None:
        ctx.state["receipt"] = receipt
        if receipt.get("state") != "complete":
            problems.append(f"The receipt ended in state {receipt.get('state')!r}, not 'complete'.")
        if receipt.get("accepted") is not True:
            problems.append("The receipt says the referral was not accepted.")
    return Outcome(ctx.call("GET", f"/ode/receipts/{rid}", auth=True), problems)


@check("R04")
def server_authenticated_to_receiver(ctx: Context) -> Outcome:
    problems: list[str] = []
    receiver = _need_receiver(ctx, problems)
    if receiver is None:
        return Outcome(problems=problems)
    snap = receiver.snapshot()
    if not _requests(snap, "GET", "/arex/.well-known/smart-configuration"):
        problems.append("The receiver never saw the server look up its discovery document, so the callback did not start.")
    tokens = _requests(snap, "POST", "/arex/auth/token")
    if not tokens:
        problems.append("The receiver never saw a token request from the server.")
    elif not any(t["status"] == 200 for t in tokens):
        problems.append("The server asked for a token but the receiver refused it every time.")
    if snap.get("assertions_verified", 0) < 1:
        problems.append("The receiver could not verify a signed assertion from the server with the public key at /arex/jwks.json.")
    if snap.get("assertions_rejected"):
        problems.append(f"The receiver rejected {len(snap['assertions_rejected'])} assertion(s): {snap['assertions_rejected']}.")
    return Outcome(problems=problems, note="Read from the receiver's own log, not from the server's receipt.")


@check("R05")
def manifest_read(ctx: Context) -> Outcome:
    problems: list[str] = []
    receiver = _need_receiver(ctx, problems)
    if receiver is None:
        return Outcome(problems=problems)
    manifests = _requests(receiver.snapshot(), "GET", "/arex/List/")
    if not manifests:
        problems.append("The receiver never saw the server read the published manifest.")
    elif not any(m["status"] == 200 for m in manifests):
        problems.append("The server asked for the manifest but the receiver did not give it to the server.")
    return Outcome(problems=problems)


@check("R06")
def every_image_pulled_and_verified(ctx: Context) -> Outcome:
    problems: list[str] = []
    receiver = _need_receiver(ctx, problems)
    receipt = ctx.state.get("receipt")
    if receiver is None or receipt is None:
        return Outcome(problems=problems or ["This step needs the finished receipt from step R03."])
    expected = [e["resource"] for e in receiver.bundle()["entry"] if e["resource"].get("resourceType") == "DocumentReference"
                and any(str(p).endswith("arex-content-entry") for p in e["resource"].get("meta", {}).get("profile", []))]
    objects = receipt.get("objects", [])
    if len(objects) != len(expected):
        problems.append(f"The receipt lists {len(objects)} image(s); the referral names {len(expected)}.")
    for o in objects:
        if o.get("status") != "saved":
            problems.append(f"Image {o.get('entryId')} was not saved (status {o.get('status')!r}).")
        elif o.get("sha256") != o.get("declaredSha256"):
            problems.append(f"Image {o.get('entryId')} was saved but its SHA-256 differs from the one declared.")
    if receipt.get("stoppedBecause"):
        problems.append(f"The pull stopped early: {receipt['stoppedBecause']}")
    unexpected = _codes(receipt) - EXPECTED_FINDINGS
    if unexpected:
        problems.append(f"Unexpected findings: {sorted(unexpected)}.")
    pulled = [r for r in _requests(receiver.snapshot(), "GET", "/arex/Binary/") if r["status"] == 200]
    if len(pulled) != len(expected):
        problems.append(f"The receiver served {len(pulled)} image download(s); expected {len(expected)}.")
    return Outcome(problems=problems, note="Findings in the normal range while ARex is a draft: " + ", ".join(sorted(EXPECTED_FINDINGS)))


@check("R07")
def saved_images_are_readable(ctx: Context) -> Outcome:
    problems: list[str] = []
    receipt = ctx.state.get("receipt")
    if receipt is None:
        return Outcome(problems=["This step needs the finished receipt from step R03."])
    last: Exchange | None = None
    saved = [o for o in receipt.get("objects", []) if o.get("status") == "saved"]
    if not saved:
        problems.append("No image was saved, so there is nothing to read back.")
    for o in saved:
        last = ctx.call("GET", f"/ode/receipts/{receipt['id']}/images/{o['fileKey']}", auth=True)
        if last.status != 200:
            problems.append(f"Reading image {o['entryId']} back gave HTTP {last.status}.")
        elif hashlib.sha256(last.response_body).hexdigest() != o.get("declaredSha256"):
            problems.append(f"Image {o['entryId']} read back with different bytes than the sender declared.")
        elif not o.get("viewable"):
            problems.append(f"Image {o['entryId']} is saved but not marked viewable: a page would not show it.")
    return Outcome(last, problems)


@check("R08")
def tampered_image_not_saved(ctx: Context) -> Outcome:
    problems: list[str] = []
    receiver = _need_receiver(ctx, problems)
    if receiver is None:
        return Outcome(problems=problems)
    try:
        receiver.set_modes(tamper=True)
        receiver.reset()
        ex, receipt = _sent(ctx, receiver, problems)
        if receipt is not None:
            if receipt.get("accepted") is not True:
                problems.append("The referral itself should still be stored when an image is bad.")
            if any(o.get("status") == "saved" for o in receipt.get("objects", [])):
                problems.append("An image whose bytes do not match the declared SHA-256 was saved. Only verified bytes may be.")
            if "DIGEST_MISMATCH" not in _codes(receipt):
                problems.append("The receipt should report DIGEST_MISMATCH.")
        return Outcome(ex, problems, note="The receiver changed one byte of every image it served.")
    finally:
        receiver.set_modes(tamper=False)


@check("R09")
def refused_token_stops_pull_and_is_reported(ctx: Context) -> Outcome:
    problems: list[str] = []
    receiver = _need_receiver(ctx, problems)
    if receiver is None:
        return Outcome(problems=problems)
    try:
        receiver.set_modes(refuse_token=True)
        receiver.reset()
        ex, receipt = _sent(ctx, receiver, problems)
        if receipt is not None:
            if receipt.get("accepted") is not True:
                problems.append("The referral itself should still be stored when the sender refuses the callback.")
            if "TOKEN_REFUSED" not in _codes(receipt):
                problems.append("The receipt should report TOKEN_REFUSED.")
            if any(o.get("status") == "saved" for o in receipt.get("objects", [])):
                problems.append("An image was saved although the sender refused to give the server a token.")
            if not receipt.get("stoppedBecause"):
                problems.append("The pull should say why it stopped.")
        if _requests(receiver.snapshot(), "GET", "/arex/Binary/"):
            problems.append("The server went on to download images after its token was refused.")
        return Outcome(ex, problems, note="The receiver answered every token request with invalid_client.")
    finally:
        receiver.set_modes(refuse_token=False)
