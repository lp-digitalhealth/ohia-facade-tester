"""Baseline checks: what any client can verify about the server with no test partner at all.

Every check is read-only. Two (B05, B11) send a deliberately malformed request, chosen so that
even a server that is wrongly open would refuse it without storing anything.
"""

from __future__ import annotations

from ..exchange import Exchange
from ..runner import Context, Outcome, check

PRIVATE_JWK_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}


def _status(ex: Exchange, expected: int, problems: list[str]) -> bool:
    if ex.status == -1:
        problems.append(f"No HTTP answer: {ex.error}")
        return False
    if ex.status != expected:
        problems.append(f"Expected HTTP {expected}, got {ex.status}.")
        return False
    return True


def _bearer_challenge(ex: Exchange, problems: list[str]) -> None:
    challenge = ex.header("WWW-Authenticate") or ""
    if "bearer" not in challenge.lower():
        problems.append("The 401 should carry a 'WWW-Authenticate: Bearer' header so a client knows how to authenticate.")


@check("B01")
def metadata_is_open(ctx: Context) -> Outcome:
    ex = ctx.call("GET", "/fhir/metadata", headers={"Accept": "application/fhir+json"})
    problems: list[str] = []
    if _status(ex, 200, problems):
        body = ex.json() or {}
        if body.get("resourceType") != "CapabilityStatement":
            problems.append("The body is not a CapabilityStatement.")
        if not str(body.get("fhirVersion", "")).startswith("4.0"):
            problems.append(f"Expected FHIR R4 (4.0.x), the server says {body.get('fhirVersion')!r}.")
    return Outcome(ex, problems)


@check("B02")
def fhir_needs_token(ctx: Context) -> Outcome:
    ex = ctx.call("GET", "/fhir/Patient", headers={"Accept": "application/fhir+json"})
    problems: list[str] = []
    if _status(ex, 401, problems):
        _bearer_challenge(ex, problems)
    return Outcome(ex, problems)


@check("B03")
def fhir_with_token(ctx: Context) -> Outcome:
    ex = ctx.call("GET", "/fhir/Patient?_count=1", auth=True, headers={"Accept": "application/fhir+json"})
    problems: list[str] = []
    if _status(ex, 200, problems):
        if (ex.json() or {}).get("resourceType") != "Bundle":
            problems.append("A search should return a Bundle.")
    return Outcome(ex, problems)


@check("B04")
def wrong_token_refused(ctx: Context) -> Outcome:
    ex = ctx.call("GET", "/fhir/Patient", bearer="wrong-" + ctx.cfg.api_token, headers={"Accept": "application/fhir+json"})
    problems: list[str] = []
    _status(ex, 401, problems)
    return Outcome(ex, problems)


@check("B05")
def write_needs_token(ctx: Context) -> Outcome:
    # The body names a different resource type than the URL. A correctly locked server answers 401
    # before reading it; a server that was left open would answer 400 and still store nothing.
    ex = ctx.call("POST", "/fhir/Patient", headers={"Content-Type": "application/fhir+json"},
                  body='{"resourceType":"Observation"}')
    problems: list[str] = []
    if _status(ex, 401, problems):
        _bearer_challenge(ex, problems)
    return Outcome(ex, problems)


@check("B06")
def facade_needs_token(ctx: Context) -> Outcome:
    ex = ctx.call("GET", "/ode/health")
    problems: list[str] = []
    _status(ex, 401, problems)
    return Outcome(ex, problems)


@check("B07")
def facade_health(ctx: Context) -> Outcome:
    ex = ctx.call("GET", "/ode/health", auth=True)
    problems: list[str] = []
    if _status(ex, 200, problems):
        body = ex.json() or {}
        if body.get("status") != "ok" or body.get("service") != "ohia-facade":
            problems.append(f"Expected {{status: ok, service: ohia-facade}}, got {body!r}.")
    elif ex.status in (502, 503, 504):
        problems.append("The proxy could not reach the facade container. Is it running and healthy?")
    return Outcome(ex, problems)


@check("B08")
def smart_discovery(ctx: Context) -> Outcome:
    ex = ctx.call("GET", "/arex/.well-known/smart-configuration", headers={"Accept": "application/json"})
    problems: list[str] = []
    if _status(ex, 200, problems):
        doc = ex.json() or {}
        endpoint = str(doc.get("token_endpoint", ""))
        if not endpoint.startswith(ctx.cfg.base_url + "/"):
            problems.append(f"token_endpoint {endpoint!r} does not start with this server's public address "
                            f"{ctx.cfg.base_url!r}. A tester following it would be sent to the wrong place. "
                            "Usual cause: PUBLIC_BASE_URL is unset or wrong in the server's .env.")
        if not endpoint.endswith("/arex/auth/token"):
            problems.append("token_endpoint should end with /arex/auth/token.")
        if "client_credentials" not in doc.get("grant_types_supported", []):
            problems.append("client_credentials must be a supported grant.")
        if "private_key_jwt" not in doc.get("token_endpoint_auth_methods_supported", []):
            problems.append("private_key_jwt must be a supported client authentication method.")
        if "RS384" not in doc.get("token_endpoint_auth_signing_alg_values_supported", []):
            problems.append("RS384 must be a supported signing algorithm.")
    return Outcome(ex, problems)


@check("B09")
def jwks_public_only(ctx: Context) -> Outcome:
    ex = ctx.call("GET", "/arex/jwks.json")
    problems: list[str] = []
    if _status(ex, 200, problems):
        keys = (ex.json() or {}).get("keys")
        if not isinstance(keys, list) or not keys:
            problems.append("The key set is empty.")
        else:
            for key in keys:
                leaked = sorted(PRIVATE_JWK_FIELDS & set(key))
                if leaked:
                    problems.append(f"Key {key.get('kid')!r} publishes private fields {leaked}. Rotate it immediately.")
                if key.get("kty") != "RSA" or not key.get("kid"):
                    problems.append("Each key should be an RSA key with a kid.")
    return Outcome(ex, problems)


@check("B10")
def token_bad_grant(ctx: Context) -> Outcome:
    ex = ctx.call("POST", "/arex/auth/token", headers={"Content-Type": "application/x-www-form-urlencoded"},
                  body="grant_type=password&username=x&password=y")
    problems: list[str] = []
    if _status(ex, 400, problems) and (ex.json() or {}).get("error") != "unsupported_grant_type":
        problems.append("Expected the OAuth error 'unsupported_grant_type'.")
    return Outcome(ex, problems)


@check("B11")
def token_forged_assertion(ctx: Context) -> Outcome:
    body = ("grant_type=client_credentials"
            "&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
            "&client_assertion=not.a.jwt")
    ex = ctx.call("POST", "/arex/auth/token", headers={"Content-Type": "application/x-www-form-urlencoded"}, body=body)
    problems: list[str] = []
    if _status(ex, 401, problems) and (ex.json() or {}).get("error") != "invalid_client":
        problems.append("Expected the OAuth error 'invalid_client'.")
    return Outcome(ex, problems)


@check("B12")
def content_needs_arex_token(ctx: Context) -> Outcome:
    ex = ctx.call("GET", "/arex/List/does-not-exist", headers={"Accept": "application/fhir+json"})
    problems: list[str] = []
    if _status(ex, 401, problems):
        challenge = ex.header("WWW-Authenticate") or ""
        if "invalid_token" not in challenge:
            problems.append("The challenge should say error=\"invalid_token\".")
    return Outcome(ex, problems)


@check("B13")
def viewer_headers(ctx: Context) -> Outcome:
    ex = ctx.call("GET", "/viewer/")
    problems: list[str] = []
    if _status(ex, 200, problems):
        csp = ex.header("Content-Security-Policy") or ""
        for needle in ("default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"):
            if needle not in csp:
                problems.append(f"Content-Security-Policy is missing {needle!r}.")
        if (ex.header("X-Frame-Options") or "").upper() != "DENY":
            problems.append("X-Frame-Options should be DENY.")
        if (ex.header("X-Content-Type-Options") or "").lower() != "nosniff":
            problems.append("X-Content-Type-Options should be nosniff.")
        if "no-store" not in (ex.header("Cache-Control") or ""):
            problems.append("Cache-Control should include no-store.")
    return Outcome(ex, problems)


@check("B14")
def identity(ctx: Context) -> Outcome:
    ex = ctx.call("GET", "/ode/identity", auth=True)
    problems: list[str] = []
    if _status(ex, 200, problems):
        doc = ex.json() or {}
        if not doc.get("client_id"):
            problems.append("client_id is missing.")
        if doc.get("signing_algorithm") != "RS384":
            problems.append("signing_algorithm should be RS384.")
        uri = str(doc.get("jwks_uri", ""))
        if not uri.startswith(ctx.cfg.base_url + "/") or not uri.endswith("/arex/jwks.json"):
            problems.append(f"jwks_uri {uri!r} should be {ctx.cfg.base_url}/arex/jwks.json.")
    return Outcome(ex, problems)


@check("B15")
def internal_not_exposed(ctx: Context) -> Outcome:
    # /internal/health is the container's own health probe. Caddy must not route it to the facade.
    ex = ctx.call("GET", "/internal/health", auth=True)
    problems: list[str] = []
    body = ex.json()
    if ex.status == -1:  # no answer proves nothing about routing: never let an outage look like a pass
        problems.append(f"No HTTP answer: {ex.error}")
    elif ex.status == 200 and isinstance(body, dict) and body.get("status") == "ok" and "resourceType" not in body:
        problems.append("The facade's internal health endpoint is reachable from the internet.")
    return Outcome(ex, problems, note="Any answer other than the facade's own {status: ok} is correct here.")
