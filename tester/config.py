"""Settings, read from environment variables. Nothing secret is ever written to disk or to a report."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping


class ConfigError(Exception):
    """A required setting is missing or unsafe."""


@dataclass(frozen=True)
class Config:
    base_url: str  # e.g. https://203-0-113-7.sslip.io  (no trailing slash, no /fhir)
    api_token: str = field(repr=False)  # the server's shared bearer token; never printed
    allow_http: bool = False  # tests against a local server only

    def url(self, path: str) -> str:
        return self.base_url + (path if path.startswith("/") else "/" + path)


def from_env(env: Mapping[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    base = (env.get("BASE_URL") or "").strip().rstrip("/")
    token = (env.get("API_TOKEN") or "").strip()
    allow_http = (env.get("ALLOW_HTTP") or "") == "1"
    if not base:
        raise ConfigError("BASE_URL is required, for example https://your-server.example.org")
    if not token:
        raise ConfigError("API_TOKEN is required (the server's shared bearer token). Set it as an environment variable or secret, never on the command line.")
    if base.endswith("/fhir"):
        raise ConfigError("BASE_URL must be the server root, without /fhir.")
    if not base.startswith("https://") and not (allow_http and base.startswith("http://")):
        raise ConfigError("BASE_URL must start with https:// (set ALLOW_HTTP=1 only for a local test server).")
    return Config(base_url=base, api_token=token, allow_http=allow_http)
