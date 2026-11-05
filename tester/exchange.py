"""One HTTP request and its response, recorded so a report (and the teaching site) can show it.

Redirects are never followed: a redirect from a server under test is itself a finding.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

MAX_READ = 5_000_000
EXCERPT = 2000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - urllib hook
        return None


@dataclass
class Exchange:
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str
    status: int  # -1 when the request never got an HTTP answer
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: bytes = b""
    elapsed_ms: int = 0
    error: str | None = None

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        for key, value in self.response_headers.items():
            if key.lower() == wanted:
                return value
        return None

    def json(self) -> Any:
        try:
            return json.loads(self.response_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None


class HttpClient:
    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                body: bytes | str | None = None, bearer: str | None = None) -> Exchange:
        hdrs = dict(headers or {})
        if bearer is not None:
            hdrs["Authorization"] = "Bearer " + bearer
        data = body.encode("utf-8") if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        started = time.monotonic()
        shown = body if isinstance(body, str) else ("" if body is None else f"<{len(body)} bytes>")
        try:
            with self._opener.open(req, timeout=self._timeout) as resp:
                return self._done(method, url, hdrs, shown, resp.status, resp.headers, resp.read(MAX_READ), started)
        except urllib.error.HTTPError as e:
            return self._done(method, url, hdrs, shown, e.code, e.headers, e.read(MAX_READ), started)
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            reason = getattr(e, "reason", e)
            return Exchange(method, url, hdrs, shown, -1, elapsed_ms=int((time.monotonic() - started) * 1000),
                            error=f"{type(reason).__name__}: {reason}")

    @staticmethod
    def _done(method, url, hdrs, shown, status, resp_headers, payload, started) -> Exchange:
        return Exchange(method, url, hdrs, shown, status, {k: v for k, v in resp_headers.items()}, payload,
                        int((time.monotonic() - started) * 1000))


# ---- redaction ----------------------------------------------------------------------------------

_FORM_SECRETS = re.compile(r"(client_assertion=)[^&\s\"]+")
_JSON_SECRETS = re.compile(r'("(?:access_token|client_assertion)"\s*:\s*")[^"]+')


def _scrub(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    text = _FORM_SECRETS.sub(r"\1***", text)
    return _JSON_SECRETS.sub(r"\1***", text)


def to_report(ex: Exchange, secrets: list[str]) -> dict[str, Any]:
    """A report-safe copy: secrets and tokens removed, bodies shortened, binary bodies summarised."""
    req_headers = {k: ("Bearer ***" if k.lower() == "authorization" else _scrub(v, secrets))
                   for k, v in ex.request_headers.items()}
    if b"\x00" in ex.response_body[:512]:
        body = f"<{len(ex.response_body)} bytes of binary data>"
    else:
        body = _scrub(ex.response_body.decode("utf-8", errors="replace"), secrets)
        if len(body) > EXCERPT:
            body = body[:EXCERPT] + "..."
    return {
        "method": ex.method,
        "url": _scrub(ex.url, secrets),
        "request_headers": req_headers,
        "request_body": _scrub(ex.request_body, secrets)[:EXCERPT],
        "status": ex.status,
        "response_headers": {k: _scrub(v, secrets) for k, v in ex.response_headers.items()},
        "response_body": body,
        "elapsed_ms": ex.elapsed_ms,
        "error": ex.error,
    }
