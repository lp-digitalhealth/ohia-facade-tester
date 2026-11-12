"""A model of the server's UC04a receive endpoint, for the unit tests (see fake_server.py).

It does what the real one does in outline: store the Bundle, then call back to the sender's ARex
server (discovery, signed token request, published manifest, images) and verify each digest. Switches
in `modes` break one rule at a time. It is a model of the contract in the server repo's
docs/UC04A_SENDING_GUIDE.md, not the server.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # one per test run is plenty
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True) | {"kid": "ohia-server-1", "alg": "RS384", "use": "sig"}
DIGEST = "http://fhir.onyxhealth.io/us/arex/StructureDefinition/arex-digest"
CONTEXT = "http://fhir.onyxhealth.io/us/arex/StructureDefinition/arex-transaction-context"


def _http(method, url, headers=None, data=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with _DIRECT.open(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError):
        return -1, b""


class Uc04aModel:
    def __init__(self, modes: dict) -> None:
        self.modes = modes
        self.store: dict[str, dict] = {}
        self.receipts: dict[str, dict] = {}
        self.images: dict[tuple[str, str], bytes] = {}

    # ---- FHIR read of what was stored
    def read(self, rtype_id: str):
        return self.store.get(rtype_id)

    # ---- /ode/receive/uc04a and /ode/receipts/...
    def receive(self, raw: bytes, own_base: str):
        m = self.modes
        try:
            bundle = json.loads(raw)
        except ValueError:
            return 422, {"error": "not JSON"}
        if bundle.get("resourceType") != "Bundle" or bundle.get("type") != "transaction":
            if not m.get("uc_accept_any"):
                return 422, {"error": "not a transaction Bundle"}
            return 200, {"accepted": True, "hapiEntries": 0, "objects": [], "findings": []}
        resources = [e["resource"] for e in bundle.get("entry", [])]
        stored = 0
        for r in resources:
            if r["resourceType"] == "Subscription":
                continue
            if m.get("uc_no_allergy") and r["resourceType"] == "AllergyIntolerance":
                continue
            if not m.get("uc_not_stored"):
                self.store[f"{r['resourceType']}/{r['id']}"] = r
                stored += 1
        manifest = next((r for r in resources if r["resourceType"] == "List"), None)
        if manifest is None:
            return 422, {"error": "no ARex manifest"}
        refs = [x["valueIdentifier"]["value"] for e in manifest["extension"] if e["url"] == CONTEXT
                for x in e["extension"] if x["url"] == "businessIdentifier"]
        entries = {r["id"]: r for r in resources if r["resourceType"] == "DocumentReference" and r["id"].startswith("arex-entry-")}
        receipt = {"id": str(uuid.uuid4()), "accepted": True, "hapiEntries": stored,
                   "referralId": "WRONG" if m.get("uc_wrong_referral") else refs[0], "manifestId": manifest["id"],
                   "objects": [], "findings": [{"code": c} for c in ("SIGNATURE_PLACEHOLDER", "MANIFEST_EXPIRED_PER_PAYLOAD", "SUBSCRIPTION_NOT_STORED")]}
        if m.get("uc_extra_finding"):
            receipt["findings"].append({"code": "REQUESTING_ORG_MISMATCH"})
        self._pull(receipt, entries, manifest, own_base)
        self.receipts[receipt["id"]] = receipt
        return 200, receipt

    def _pull(self, receipt, entries, manifest, own_base):
        m = self.modes
        for eid, e in entries.items():
            att = e["content"][0]["attachment"]
            digest = next(p["valueString"] for x in att["extension"] if x["url"] == DIGEST for p in x["extension"] if p["url"] == "value")
            receipt["objects"].append({"entryId": eid, "fileKey": eid, "status": "not-pulled", "viewable": False, "declaredSha256": digest, "_url": att["url"]})
        if m.get("uc_no_pull") or not entries:
            return self._finish(receipt)
        base = receipt["objects"][0]["_url"].split("/Binary/")[0]
        status, body = _http("GET", base + "/.well-known/smart-configuration")
        if status != 200:
            receipt["findings"].append({"code": "TOKEN_ENDPOINT_NOT_DISCOVERED"})
            return self._finish(receipt)
        token_endpoint = json.loads(body)["token_endpoint"]
        now = int(time.time())
        assertion = jwt.encode({"iss": "ohia-test-server", "sub": "ohia-test-server",
                                "aud": "https://elsewhere.example.org/token" if m.get("uc_bad_assertion") else token_endpoint,
                                "exp": now + 120, "jti": str(uuid.uuid4())}, KEY, algorithm="RS384", headers={"kid": "ohia-server-1"})
        form = urllib.parse.urlencode({
            "grant_type": "client_credentials", "scope": "system/List.r system/DocumentReference.r system/Provenance.r system/Binary.r",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": assertion,
            "authorization_details": json.dumps([{"type": "arex-manifest", "manifest": manifest["id"]}])}).encode()
        status, body = _http("POST", token_endpoint, {"Content-Type": "application/x-www-form-urlencoded"}, form)
        if status != 200:
            receipt["findings"].append({"code": "TOKEN_REFUSED"})
            return self._finish(receipt)
        auth = {"Authorization": "Bearer " + json.loads(body)["access_token"]}
        _http("GET", f"{base}/List/{manifest['id']}", auth)
        for o in receipt["objects"]:
            status, data = _http("GET", o["_url"], auth)
            if status != 200:
                o["status"] = "transfer-error"
                continue
            if hashlib.sha256(data).hexdigest() != o["declaredSha256"] and not m.get("uc_no_digest_check"):
                o["status"] = "digest-mismatch"
                receipt["findings"].append({"code": "DIGEST_MISMATCH"})
                continue
            o["status"], o["viewable"] = "saved", True
            self.images[(receipt["id"], o["fileKey"])] = b"not what was sent" if m.get("uc_serves_wrong_bytes") else data
        self._finish(receipt)

    @staticmethod
    def _finish(receipt):
        for o in receipt["objects"]:
            o.pop("_url", None)

    def route(self, path: str):
        """GET /ode/receipts/{id} and /ode/receipts/{id}/images/{key} -> (status, body, content-type) or None."""
        parts = [p for p in path.split("/") if p]
        if parts[:2] != ["ode", "receipts"]:
            return None
        if len(parts) == 3:
            if self.modes.get("uc_receipt_missing") or parts[2] not in self.receipts:
                return 404, {"error": "no such receipt"}, "application/json"
            return 200, self.receipts[parts[2]], "application/json"
        if len(parts) == 5 and parts[3] == "images":
            data = self.images.get((parts[2], parts[4]))
            return (200, data, "image/jpeg") if data is not None else (404, {"error": "no such image"}, "application/json")
        return None
