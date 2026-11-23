"""A model of the test server's receive-and-callback side, for the arex-callback tests.

It follows the contract of the real facade (POST /ode/receive/uc04a, receipts, the published public key) and really does the
callback: it signs an RS384 assertion, asks the receiver for a token, reads the manifest and downloads the images. Each
switch in `modes` breaks one rule so a test can show the matching step fails. It is a model, not the server: the run against
the real jar is the proof.
"""

from __future__ import annotations

import hashlib
import json
import urllib.parse
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from tests.fake_server import TOKEN

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _jwk(key) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "ohia-server-1", "alg": "RS384", "use": "sig"})
    return jwk


class FakeFacade:
    def __init__(self, **modes: bool) -> None:
        self.modes = modes
        self.receipts: dict[str, dict[str, Any]] = {}
        self.images: dict[tuple[str, str], bytes] = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status: int, body: Any = b"", headers: dict[str, str] | None = None, ctype: str = "application/json") -> None:
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _authed(self) -> bool:
                return self.headers.get("Authorization") == "Bearer " + TOKEN

            def do_GET(self):
                path = self.path.split("?")[0]
                if path == "/arex/jwks.json":
                    return self._send(200, {"keys": [_jwk(_KEY)]})
                if not self._authed():
                    return self._send(401, b"Unauthorized", ctype="text/plain")
                parts = path.strip("/").split("/")
                if parts[:2] == ["ode", "receipts"] and len(parts) == 3:
                    r = outer.receipts.get(parts[2])
                    return self._send(200, r) if r else self._send(404)
                if parts[:2] == ["ode", "receipts"] and len(parts) == 5 and parts[3] == "images":
                    data = outer.images.get((parts[2], parts[4]))
                    return self._send(200, data, ctype="image/jpeg") if data is not None else self._send(404)
                self._send(404)

            def do_POST(self):
                if self.path.split("?")[0] != "/ode/receive/uc04a":
                    return self._send(404)
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if not self._authed():
                    return self._send(401, b"Unauthorized", ctype="text/plain")
                bundle = json.loads(body)
                rid = str(uuid.uuid4())
                outer.receipts[rid] = {"id": rid, "state": "pending", "accepted": True, "stoppedBecause": None, "objects": [], "findings": []}
                response = {"resourceType": "Bundle", "type": "transaction-response", "entry": [{"response": {"status": "201 Created"}} for _ in bundle["entry"]]}
                headers = {"X-Receipt-Id": rid, "Link": f'<http://fake/ode/receipts/{rid}>; rel="receipt"'}
                m = outer.modes
                if m.get("old_reply"):  # the earlier behavior: wait for the callback, answer with the receipt, not FHIR
                    outer._pull(rid, bundle)
                    return self._send(200, outer.receipts[rid])
                if m.get("slow_reply"):  # a FHIR answer, but only after the callback
                    time.sleep(0.8)
                    outer._pull(rid, bundle)
                    return self._send(200, response, headers, "application/fhir+json")
                threading.Thread(target=outer._pull, args=(rid, bundle), daemon=True).start()
                self._send(200, response, headers, "application/fhir+json")

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    # ---- the callback
    def _pull(self, rid: str, bundle: dict[str, Any]) -> None:
        r = self.receipts[rid]
        m = self.modes
        entries = [e["resource"] for e in bundle["entry"] if e["resource"].get("resourceType") == "DocumentReference"
                   and any(str(p).endswith("arex-content-entry") for p in e["resource"].get("meta", {}).get("profile", []))]
        manifest = next(e["resource"] for e in bundle["entry"] if e["resource"].get("resourceType") == "List")
        if m.get("no_callback"):
            return self._finish(rid, "complete")
        att0 = entries[0]["content"][0]["attachment"]
        base = att0["url"].split("/Binary/")[0]
        origin = base.rsplit("/arex", 1)[0]
        token_endpoint = origin + "/arex/auth/token"
        try:
            self._open("GET", base + "/.well-known/smart-configuration")
            now = int(time.time())
            assertion = jwt.encode({"iss": "ohia-test-server", "sub": "ohia-test-server", "aud": token_endpoint, "jti": str(uuid.uuid4()),
                                    "exp": now + 120}, _OTHER_KEY if m.get("bad_signature") else _KEY, algorithm="RS384",
                                   headers={"kid": "ohia-server-1"})
            form = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": "system/List.r system/Binary.r",
                                           "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                           "client_assertion": assertion,
                                           "authorization_details": json.dumps([{"type": "arex-manifest", "manifest": manifest["id"]}])}).encode()
            try:
                token = json.loads(self._open("POST", token_endpoint, form, {"Content-Type": "application/x-www-form-urlencoded"}))["access_token"]
            except urllib.error.HTTPError:
                r["findings"].append({"code": "TOKEN_REFUSED", "message": "the sender refused the token request"})
                r["stoppedBecause"] = "token refused"
                return self._finish(rid, "complete")
            self._open("GET", f"{base}/List/{manifest['id']}", None, {"Authorization": "Bearer " + token})
            for e in entries:
                att = e["content"][0]["attachment"]
                declared = next(p["valueString"] for ext in att["extension"] if ext["url"].endswith("arex-digest")
                                for p in ext["extension"] if p["url"] == "value")
                data = self._open("GET", att["url"], None, {"Authorization": "Bearer " + token}, raw=True)
                actual = hashlib.sha256(data).hexdigest()
                ok = actual == declared or m.get("skip_digest_check")
                if not ok and not any(f["code"] == "DIGEST_MISMATCH" for f in r["findings"]):
                    r["findings"].append({"code": "DIGEST_MISMATCH", "message": "bytes differ from the declared digest"})
                r["objects"].append({"entryId": e["id"], "fileKey": e["id"], "status": "saved" if ok else "digest-mismatch",
                                     "sha256": actual, "declaredSha256": declared, "viewable": ok})
                if ok:
                    self.images[(rid, e["id"])] = data
        finally:
            if r["state"] == "pending" and not m.get("stuck"):
                self._finish(rid, "complete")

    def _finish(self, rid: str, state: str) -> None:
        if not self.modes.get("stuck"):  # a stuck callback never marks its receipt finished, whichever way it ended
            self.receipts[rid]["state"] = state

    @staticmethod
    def _open(method: str, url: str, data: bytes | None = None, headers: dict[str, str] | None = None, raw: bool = False):
        req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
        with _NO_PROXY.open(req, timeout=10) as resp:
            body = resp.read()
        return body if raw else body.decode()

    def __enter__(self) -> "FakeFacade":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
