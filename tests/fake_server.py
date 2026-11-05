"""A local stand-in for the proxy + HAPI + facade, following the contract in the server repo's
Caddyfile and facade code. It exists so the runner can be tested without the real server.

Each flag in `modes` breaks one rule, so a test can prove the matching check fails.
This is a model of the server, not the server: the real-server run is the final proof.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

TOKEN = "unit-test-token-0123456789abcdef"


class FakeServer:
    def __init__(self, **modes: bool) -> None:
        self.modes = modes
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def _send(self, status, body=b"", headers=None, ctype="application/json"):
                if isinstance(body, (dict, list)):
                    body = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _authed(self):
                return self.headers.get("Authorization") == "Bearer " + TOKEN

            def _unauth(self):
                self._send(401, b"Unauthorized", {"WWW-Authenticate": "Bearer"}, "text/plain")

            def do_GET(self):
                self._route("GET")

            def do_POST(self):
                self._route("POST")

            def _route(self, method):
                m = outer.modes
                path = self.path.split("?")[0]
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                base = f"http://127.0.0.1:{outer.port}"
                public = "http://localhost" if m.get("localhost") else base

                if path == "/fhir/metadata" and method == "GET":
                    return self._send(200, {"resourceType": "CapabilityStatement", "fhirVersion": "4.0.1"})
                if path.startswith("/fhir"):
                    if self._authed():
                        if method == "POST":
                            return self._send(201, {"resourceType": "Patient"})
                        body = {"resourceType": "Bundle", "type": "searchset", "total": 0}
                        if m.get("echo"):
                            body["leak"] = TOKEN
                        return self._send(200, body)
                    if m.get("open_fhir"):
                        if method == "POST":
                            return self._send(400, {"resourceType": "OperationOutcome"})
                        return self._send(200, {"resourceType": "Bundle", "type": "searchset", "total": 0})
                    return self._unauth()
                if path.startswith("/ode"):
                    if not self._authed():
                        return self._unauth()
                    if path == "/ode/health":
                        return self._send(200, {"status": "ok", "service": "ohia-facade"})
                    if path == "/ode/identity":
                        return self._send(200, {"client_id": "ohia-test-server", "signing_algorithm": "RS384",
                                                "jwks_uri": public + "/arex/jwks.json"})
                if path == "/arex/.well-known/smart-configuration":
                    return self._send(200, {
                        "issuer": public + "/arex", "token_endpoint": public + "/arex/auth/token",
                        "grant_types_supported": ["client_credentials"],
                        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                        "token_endpoint_auth_signing_alg_values_supported": ["RS384", "ES384"]})
                if path == "/arex/jwks.json":
                    key = {"kty": "RSA", "kid": "ohia-server-1", "alg": "RS384", "use": "sig", "n": "abc", "e": "AQAB"}
                    if m.get("leaky_jwks"):
                        key["d"] = "secret"
                    return self._send(200, {"keys": [key]}, ctype="application/jwk-set+json")
                if path == "/arex/auth/token" and method == "POST":
                    form = parse_qs(raw.decode())
                    if form.get("grant_type") != ["client_credentials"]:
                        return self._send(400, {"error": "unsupported_grant_type"})
                    return self._send(401, {"error": "invalid_client"})
                if path.startswith("/arex/"):
                    return self._send(401, {"resourceType": "OperationOutcome"},
                                      {"WWW-Authenticate": 'Bearer error="invalid_token"'})
                if path.startswith("/viewer"):
                    headers = {"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
                    if not m.get("no_csp"):
                        headers["Content-Security-Policy"] = ("default-src 'none'; script-src 'self'; style-src 'self'; "
                                                              "frame-ancestors 'none'")
                    return self._send(200, b"<html></html>", headers, "text/html")
                if path == "/internal/health":
                    if m.get("expose_internal"):
                        return self._send(200, {"status": "ok"})
                    if not self._authed():
                        return self._unauth()
                    return self._send(404, {"resourceType": "OperationOutcome"})
                return self._unauth() if not self._authed() else self._send(404, {})

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self) -> "FakeServer":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
