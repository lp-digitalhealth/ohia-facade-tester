"""A small ARex content server that the tester runs while it plays the sending platform.

In UC04a the platform (Meridian) sends a referral that names photos, but does not carry them. The
receiving server then calls BACK to fetch them. This class is the thing it calls. It does what a real
ARex server must do, in this order:

1. Publish discovery (`/.well-known/smart-configuration`) so the caller can find the token endpoint.
2. Accept a token request carrying a signed JWT (RS384). It checks the signature against the public
   key the caller publishes, and the claims (issuer, audience, expiry, one-time `jti`).
3. Serve the published manifest (`List`) and each image, but only to a caller holding a token.

Every request is recorded, so the checks can say exactly what the server did. A few switches make it
misbehave on purpose (`tamper`, `refuse_token`), which is how a test proves the server notices.

Written for teaching: the logic is short and each step has a comment saying why. Requires PyJWT and
cryptography (see requirements.txt). The adaptation source is the server repo's own independent
stand-in, so the tester and the server's own end-to-end check agree on the wire contract.
"""

from __future__ import annotations

import http.server
import json
import threading
import time
import urllib.request
import uuid
from urllib.parse import unquote_plus

_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never route a local fetch via a proxy


class PartnerArex:
    def __init__(self, *, host: str, port: int, public_url: str, jwks_url: str, client_id: str,
                 manifest: dict, objects: dict[str, bytes], token_type: str = "arex-manifest") -> None:
        self.manifest, self.objects = manifest, objects
        self.jwks_url, self.client_id, self.token_type = jwks_url, client_id, token_type
        self._server = http.server.ThreadingHTTPServer((host, port), self._handler())
        self.port = self._server.server_address[1]
        # The address the SERVER must use to reach us. Behind a proxy that differs from host:port.
        self.base = (public_url or f"http://127.0.0.1:{self.port}").rstrip("/")
        self.token_endpoint = self.base + "/arex/auth/token"
        # switches: misbehave on purpose so a test can prove the server notices
        self.tamper = False
        self.refuse_token = False
        # observations
        self.requests: list[str] = []
        self.scopes: list[str | None] = []
        self.assertions_verified = 0
        self.assertions_rejected: list[str] = []
        self._tokens: dict[str, float] = {}
        self._seen_jti: set[str] = set()
        self._jwks: dict | None = None
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def reset_observations(self) -> None:
        self.requests.clear()
        self.scopes.clear()
        self.assertions_verified = 0
        self.assertions_rejected.clear()
        self._tokens.clear()
        self.tamper = self.refuse_token = False

    def count(self, prefix: str) -> int:
        return sum(1 for r in self.requests if r.startswith(prefix))

    # ---- verifying the server's signed assertion with the public key it publishes
    def _public_key(self, kid: str | None):
        import jwt  # imported here so the other cases run without PyJWT installed

        for attempt in (1, 2):  # second try re-reads the key set, in case the server rotated its key
            if self._jwks is None or attempt == 2:
                with _DIRECT.open(self.jwks_url, timeout=15) as r:
                    self._jwks = json.loads(r.read())
            for key in self._jwks.get("keys", []):
                if key.get("kid") == kid:
                    return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        raise ValueError(f"no key with kid {kid!r} in {self.jwks_url}")

    def _check_assertion(self, assertion: str) -> str | None:
        """Return None if the assertion is acceptable, else a short reason it is not."""
        import jwt

        header = jwt.get_unverified_header(assertion)
        if header.get("alg") != "RS384":
            return f"algorithm {header.get('alg')!r}, expected RS384"
        claims = jwt.decode(assertion, key=self._public_key(header.get("kid")), algorithms=["RS384"],
                            audience=self.token_endpoint, options={"require": ["exp", "iss", "sub", "aud", "jti"]})
        if claims["iss"] != self.client_id or claims["sub"] != self.client_id:
            return "iss and sub must both be the client id"
        if claims["exp"] - time.time() > 330:
            return "exp is too far in the future (limit 5 minutes)"
        if claims["jti"] in self._seen_jti:
            return "jti was already used (replay)"
        self._seen_jti.add(claims["jti"])
        return None

    def _handler(self):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code: int, body: bytes = b"", ctype: str = "application/json") -> None:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self) -> bool:
                header = self.headers.get("Authorization", "")
                return header.startswith("Bearer ") and header[7:] in outer._tokens

            def do_GET(self):
                outer.requests.append("GET " + self.path)
                if self.path == "/arex/.well-known/smart-configuration":
                    return self._send(200, json.dumps({
                        "token_endpoint": outer.token_endpoint,
                        "authorization_details_types_supported": [outer.token_type]}).encode())
                if self.path.startswith("/arex/List/"):
                    if not self._authorized():
                        return self._send(401)
                    if self.path.rsplit("/", 1)[-1] != outer.manifest["id"]:
                        return self._send(404)
                    return self._send(200, json.dumps(outer.manifest).encode(), "application/fhir+json")
                if self.path.startswith("/arex/Binary/"):
                    if not self._authorized():
                        return self._send(401)
                    data = outer.objects.get(self.path.rsplit("/", 1)[-1])
                    if data is None:
                        return self._send(404)
                    if outer.tamper:
                        data = data[:-1] + bytes([data[-1] ^ 1])  # flip one bit: the digest must catch it
                    return self._send(200, data, "image/jpeg")
                self._send(404)

            def do_POST(self):
                outer.requests.append("POST " + self.path)
                body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
                if self.path != "/arex/auth/token":
                    return self._send(404)
                form = {k: unquote_plus(v) for k, v in (p.split("=", 1) for p in body.split("&") if "=" in p)}
                outer.scopes.append(form.get("scope"))
                if outer.refuse_token or form.get("grant_type") != "client_credentials":
                    outer.assertions_rejected.append("refused by switch" if outer.refuse_token else "wrong grant_type")
                    return self._send(401, b'{"error":"invalid_client"}')
                try:
                    problem = outer._check_assertion(form.get("client_assertion", ""))
                except Exception as e:  # any verification error is a refusal
                    problem = f"verification failed: {type(e).__name__}"
                if problem:
                    outer.assertions_rejected.append(problem)
                    return self._send(401, json.dumps({"error": "invalid_client", "error_description": problem}).encode())
                outer.assertions_verified += 1
                details = json.loads(form.get("authorization_details", "[]"))
                if len(details) != 1 or details[0].get("type") != outer.token_type:
                    return self._send(400, b'{"error":"invalid_request"}')
                if details[0].get("manifest") != outer.manifest["id"]:
                    return self._send(400, b'{"error":"invalid_grant"}')
                token = str(uuid.uuid4())
                outer._tokens[token] = time.time() + 300
                return self._send(200, json.dumps({"access_token": token, "token_type": "bearer", "expires_in": 300}).encode())

        return Handler
