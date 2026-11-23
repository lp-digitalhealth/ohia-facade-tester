"""A stand-in ARex server: the client's side of UC04a, so the test server's callback can be tested.

The test server receives a referral and then calls BACK to the sender's ARex server to fetch the images. This class is
that sender's server. It serves discovery, a token endpoint that verifies the RS384 assertion the test server signs
(with the public key the test server publishes), the published manifest and the images, and it records every request,
so a test can check what the test server really did and not only what its receipt says.

It runs inside the test process (for a server that can reach this machine) or as its own process on a public host
(`python -m tester receiver`). It never holds a secret of the test server: it only reads the server's public key.
"""

from __future__ import annotations

import copy
import hashlib
import http.server
import json
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus, urlsplit

DATA_DIR = Path(__file__).resolve().parent / "data" / "uc04a"
SAMPLE_HOST = "https://meridian-teledental.example.org"
ARex = "http://fhir.onyxhealth.io/us/arex/StructureDefinition/"
TOKEN_SECONDS = 300
CONTROL_HEADER = "X-Harness-Token"


class ReceiverError(Exception):
    """The receiver could not be set up or reached."""


def _digest_of(attachment: dict[str, Any]) -> str | None:
    for ext in attachment.get("extension", []):
        if str(ext.get("url", "")).endswith("arex-digest"):
            for part in ext.get("extension", []):
                if part.get("url") == "value":
                    return part.get("valueString")
    return None


def build_payload(public_url: str, data_dir: Path = DATA_DIR) -> tuple[dict[str, Any], dict[str, bytes]]:
    """The UC04a interaction 1 Bundle with its image links pointed at `public_url`, and the image bytes by entry id.

    The sample's digests are real SHA-256 values over the sample images, and this checks that they still are. The
    manifest's expiry is moved to two weeks ahead so the server does not report an expired manifest.
    """
    text = (data_dir / "interaction-01-bundle.json").read_text(encoding="utf-8").replace(SAMPLE_HOST, public_url.rstrip("/"))
    bundle = json.loads(text)
    photos: dict[str, bytes] = {}
    files = sorted(p for p in data_dir.glob("*.jpg"))
    entries = [e["resource"] for e in bundle["entry"] if e["resource"].get("resourceType") == "DocumentReference"
               and any(str(p).endswith("arex-content-entry") for p in e["resource"].get("meta", {}).get("profile", []))]
    entries.sort(key=lambda r: r["id"])
    if len(entries) != len(files):
        raise ReceiverError(f"The sample has {len(entries)} content entries but {len(files)} image files.")
    for entry, path in zip(entries, files):
        data = path.read_bytes()
        declared = _digest_of(entry["content"][0]["attachment"])
        if declared != hashlib.sha256(data).hexdigest():
            raise ReceiverError(f"The digest declared for {entry['id']} does not match {path.name}.")
        photos[entry["id"]] = data
    expires = (datetime.now(timezone.utc) + timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for e in bundle["entry"]:
        r = e["resource"]
        if r.get("resourceType") == "List":
            for ext in r.get("extension", []):
                if str(ext.get("url", "")).endswith("arex-expires"):
                    ext["valueInstant"] = expires
    return bundle, photos


def manifest_of(bundle: dict[str, Any]) -> dict[str, Any]:
    for e in bundle["entry"]:
        r = e["resource"]
        if r.get("resourceType") == "List" and any(str(p).endswith("arex-manifest") for p in r.get("meta", {}).get("profile", [])):
            return r
    raise ReceiverError("The sample has no ARex manifest.")


class ArexReceiver:
    """See the module docstring. `server_base` is the test server's public base (where /arex/jwks.json is)."""

    def __init__(self, *, server_base: str, listen: tuple[str, int] = ("127.0.0.1", 0), public_url: str | None = None,
                 client_id: str = "ohia-test-server", control_token: str | None = None, data_dir: Path = DATA_DIR) -> None:
        self.server_base = server_base.rstrip("/")
        self.client_id = client_id
        self.control_token = control_token
        loopback = listen[0] in ("127.0.0.1", "localhost", "::1")
        if not loopback and not control_token:
            raise ReceiverError("A receiver that listens beyond this machine needs a control token (RECEIVER_CONTROL_TOKEN).")
        self._data_dir = data_dir
        self.modes = {"tamper": False, "refuse_token": False}
        self.requests: list[dict[str, Any]] = []
        self.assertions_verified = 0
        self.assertions_rejected: list[str] = []
        self._tokens: dict[str, tuple[float, str]] = {}
        self._seen_jti: set[str] = set()
        self._jwks: dict[str, Any] | None = None
        self._lock = threading.Lock()
        self._httpd = http.server.ThreadingHTTPServer(listen, self._handler())
        host, port = self._httpd.server_address[0], self._httpd.server_address[1]
        self.public_url = (public_url or f"http://{host}:{port}").rstrip("/")
        self.token_endpoint = self.public_url + "/arex/auth/token"
        self.bundle, self.photos = build_payload(self.public_url, data_dir)
        self.manifest = manifest_of(self.bundle)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    # ---- lifecycle
    def start(self) -> "ArexReceiver":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    # ---- what the test reads and sets
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"requests": list(self.requests), "assertions_verified": self.assertions_verified,
                    "assertions_rejected": list(self.assertions_rejected), "tokens_issued": len(self._tokens), "modes": dict(self.modes)}

    def reset(self) -> None:
        with self._lock:
            self.requests.clear()
            self.assertions_verified = 0
            self.assertions_rejected.clear()
            self._tokens.clear()
            self._seen_jti.clear()

    def set_modes(self, **modes: bool) -> None:
        for key in modes:
            if key not in self.modes:
                raise ReceiverError(f"Unknown mode {key!r}.")
        self.modes.update({k: bool(v) for k, v in modes.items()})

    def payload(self) -> dict[str, Any]:
        return copy.deepcopy(self.bundle)

    # ---- verifying the server's signed assertion with its published public key
    def _public_key(self, kid: str | None):
        import jwt  # PyJWT
        for attempt in (1, 2):
            if self._jwks is None or attempt == 2:
                with urllib.request.build_opener(urllib.request.ProxyHandler({} if self._is_local(self.server_base) else None)).open(
                        self.server_base + "/arex/jwks.json", timeout=20) as r:
                    self._jwks = json.loads(r.read())
            for key in self._jwks.get("keys", []):
                if key.get("kid") == kid:
                    return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        raise ValueError(f"unknown kid {kid}")

    @staticmethod
    def _is_local(url: str) -> bool:
        return (urlsplit(url).hostname or "") in ("127.0.0.1", "localhost", "::1")

    def _check_assertion(self, assertion: str) -> str | None:
        import jwt
        header = jwt.get_unverified_header(assertion)
        if header.get("alg") != "RS384":
            return f"alg {header.get('alg')} (RS384 expected)"
        claims = jwt.decode(assertion, key=self._public_key(header.get("kid")), algorithms=["RS384"], audience=self.token_endpoint,
                            options={"require": ["exp", "iss", "sub", "aud", "jti"]})
        if claims["iss"] != self.client_id or claims["sub"] != self.client_id:
            return f"iss/sub are not {self.client_id}"
        if claims["exp"] - time.time() > TOKEN_SECONDS + 30:
            return "exp is too far ahead"
        with self._lock:
            if claims["jti"] in self._seen_jti:
                return "jti replay"
            self._seen_jti.add(claims["jti"])
        return None

    # ---- HTTP
    def _note(self, method: str, path: str, status: int, note: str = "") -> None:
        with self._lock:
            self.requests.append({"time": time.time(), "method": method, "path": path, "status": status, "note": note})

    def _handler(self):
        outer = self
        manifest_id_of = lambda: outer.manifest["id"]  # noqa: E731

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def _send(self, status: int, body: bytes = b"", ctype: str = "application/json", note: str = "", log: bool = True) -> None:
                if log:
                    outer._note(self.command, self.path.split("?")[0], status, note)
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _json(self, status: int, obj: Any, **kw) -> None:
                self._send(status, json.dumps(obj).encode(), **kw)

            def _control_ok(self) -> bool:
                return (outer.control_token is None and outer._is_local(outer.public_url)) or self.headers.get(CONTROL_HEADER) == outer.control_token

            def _bearer(self) -> str | None:
                h = self.headers.get("Authorization", "")
                token = h[7:] if h.startswith("Bearer ") else None
                entry = outer._tokens.get(token) if token else None
                return token if entry and entry[0] > time.time() else None

            def do_GET(self):
                path = self.path.split("?")[0]
                if path.startswith("/__harness/"):
                    if not self._control_ok():
                        return self._send(401, b"", log=False)
                    if path == "/__harness/bundle":
                        return self._json(200, outer.payload(), log=False)
                    if path == "/__harness/log":
                        return self._json(200, outer.snapshot(), log=False)
                    return self._send(404, b"", log=False)
                if path == "/arex/.well-known/smart-configuration":
                    return self._json(200, {"token_endpoint": outer.token_endpoint, "grant_types_supported": ["client_credentials"],
                                            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                                            "token_endpoint_auth_signing_alg_values_supported": ["RS384"],
                                            "authorization_details_types_supported": ["arex-manifest"]})
                if path.startswith("/arex/List/"):
                    if not self._bearer():
                        return self._send(401, b"", note="no valid token")
                    if path.rsplit("/", 1)[-1] != manifest_id_of():
                        return self._send(404, b"", note="not this manifest")
                    return self._json(200, outer.manifest, ctype="application/fhir+json")
                if path.startswith("/arex/Binary/"):
                    if not self._bearer():
                        return self._send(401, b"", note="no valid token")
                    data = outer.photos.get(path.rsplit("/", 1)[-1])
                    if data is None:
                        return self._send(404, b"", note="no such image")
                    if outer.modes["tamper"]:
                        data = data[:-1] + bytes([data[-1] ^ 1])
                    return self._send(200, data, "image/jpeg", note="tampered" if outer.modes["tamper"] else "")
                self._send(404, b"")

            def do_POST(self):
                path = self.path.split("?")[0]
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", "replace")
                if path.startswith("/__harness/"):
                    if not self._control_ok():
                        return self._send(401, b"", log=False)
                    if path == "/__harness/reset":
                        outer.reset()
                        return self._json(200, {"ok": True}, log=False)
                    if path == "/__harness/mode":
                        try:
                            outer.set_modes(**json.loads(body or "{}"))
                        except (ReceiverError, ValueError) as e:
                            return self._json(400, {"error": str(e)}, log=False)
                        return self._json(200, outer.snapshot()["modes"], log=False)
                    return self._send(404, b"", log=False)
                if path != "/arex/auth/token":
                    return self._send(404, b"")
                form = {k: unquote_plus(v) for k, _, v in (p.partition("=") for p in body.split("&") if p)}
                if outer.modes["refuse_token"] or form.get("grant_type") != "client_credentials":
                    with outer._lock:
                        outer.assertions_rejected.append("refused by switch" if outer.modes["refuse_token"] else "grant_type")
                    return self._json(401, {"error": "invalid_client"}, note="refused")
                try:
                    problem = outer._check_assertion(form.get("client_assertion", ""))
                except Exception as e:  # any verification error is a refusal
                    problem = f"verification failed: {type(e).__name__}"
                if problem:
                    with outer._lock:
                        outer.assertions_rejected.append(problem)
                    return self._json(401, {"error": "invalid_client", "error_description": problem}, note=problem)
                try:
                    details = json.loads(form.get("authorization_details", "[]"))
                except ValueError:
                    details = []
                if len(details) != 1 or details[0].get("type") != "arex-manifest" or details[0].get("manifest") != manifest_id_of():
                    return self._json(400, {"error": "invalid_request"}, note="authorization_details")
                with outer._lock:
                    outer.assertions_verified += 1
                    token = str(uuid.uuid4())
                    outer._tokens[token] = (time.time() + TOKEN_SECONDS, details[0]["manifest"])
                return self._json(200, {"access_token": token, "token_type": "bearer", "expires_in": TOKEN_SECONDS},
                                  note="scope=" + form.get("scope", ""))

        return Handler
