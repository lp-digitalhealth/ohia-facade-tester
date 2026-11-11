"""Patient-access checks: a patient app reading the payer's CARIN Blue Button 2.2.0 data (UC07 interaction 6).

Every check is read-only. P15 sends a write whose body names the wrong resource type, so even a wrongly open
server rejects it and stores nothing. The payer-side data must already be loaded by the organizer; the tester
never loads it.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from ..exchange import Exchange
from ..runner import Context, Outcome, check
from .baseline import _bearer_challenge, _status

BASE = "/patient-access/fhir"
ACCEPT = {"Accept": "application/fhir+json"}
C4BB = "http://hl7.org/fhir/us/carin-bb/StructureDefinition/C4BB-"
IG = "http://hl7.org/fhir/us/carin-bb/ImplementationGuide/hl7.fhir.us.carin-bb|2.2.0"
TYPES = ("Patient", "Coverage", "Organization", "Practitioner", "ExplanationOfBenefit")

# The test member, as the data repository defines it in UC07 interaction 6.
ONLINE_ID = "https://dentaquest.example.org/fhir/online-id|DQ-ONLINE-TX-0038211"
MEDICAID_ID = "http://texas.medicaid.gov/beneficiary|TX-MCD-0038211"
PREAUTH = "TX-DQ-PA-2026-061204"
RESTORATIVE_CLAIM = "DQ-EOB-2026-UC07-002"
SERVICE_FROM_RESTORATIVE = "ge2026-07-22"


def _get(ctx: Context, path: str) -> Exchange:
    return ctx.call("GET", BASE + path, auth=True, headers=ACCEPT)


def _resources(ex: Exchange) -> list[dict[str, Any]]:
    """The search hits in a Bundle (the 'outcome' entry that says nothing is loaded is not a hit)."""
    body = ex.json()
    if not isinstance(body, dict) or body.get("resourceType") != "Bundle":
        return []
    return [e["resource"] for e in body.get("entry", [])
            if isinstance(e.get("resource"), dict) and (e.get("search") or {}).get("mode") != "outcome"]


def _profiles(resource: dict[str, Any]) -> list[str]:
    return [p for p in resource.get("meta", {}).get("profile", []) if isinstance(p, str)]


def _has_profile(resource: dict[str, Any], name: str) -> bool:
    return any(p.startswith(C4BB + name) and p.endswith("|2.2.0") for p in _profiles(resource))


def _not_loaded_hint(ex: Exchange, problems: list[str]) -> None:
    if "not loaded" in ex.response_body.decode("utf-8", errors="replace").lower():
        problems.append("The server says the payer-side data is not loaded. The organizer loads it once with "
                        "POST /ode/admin/seed-patient-access.")


def _bundle(ex: Exchange, problems: list[str]) -> bool:
    if not _status(ex, 200, problems):
        return False
    if (ex.json() or {}).get("resourceType") != "Bundle":
        problems.append("A search should return a Bundle.")
        return False
    return True


def _links_are_public(ex: Exchange, ctx: Context, problems: list[str]) -> None:
    prefix = ctx.cfg.base_url + BASE + "/"
    for entry in (ex.json() or {}).get("entry", []):
        url = str(entry.get("fullUrl", ""))
        if url and not url.startswith(prefix):
            problems.append(f"fullUrl {url!r} does not start with this server's public address {prefix!r}. "
                            "Usual cause: the public base URL is unset or wrong in the server's .env.")
            return


def _search_member(ctx: Context, identifier: str) -> tuple[Exchange, list[dict[str, Any]]]:
    ex = _get(ctx, "/Patient?identifier=" + quote(identifier, safe=":/"))
    return ex, _resources(ex)


def _member(ctx: Context) -> dict[str, Any] | None:
    """The member found by the online ID (cached for the run); None if that search finds no single Patient."""
    if "member" not in ctx.state:
        _, found = _search_member(ctx, ONLINE_ID)
        ctx.state["member"] = found[0] if len(found) == 1 else None
    return ctx.state["member"]


def _need_member(ctx: Context, problems: list[str]) -> dict[str, Any] | None:
    member = _member(ctx)
    if member is None:
        problems.append("This step needs the member found in step P05, and that search did not find exactly one Patient.")
    return member


def _eobs(ctx: Context, member: dict[str, Any], extra: str = "") -> tuple[Exchange, list[dict[str, Any]]]:
    ex = _get(ctx, f"/ExplanationOfBenefit?patient={member['id']}{extra}")
    return ex, _resources(ex)


def _identifier_values(resource: dict[str, Any]) -> set[tuple[str, str]]:
    return {(str(i.get("system", "")), str(i.get("value", ""))) for i in resource.get("identifier", [])}


@check("P01")
def capability(ctx: Context) -> Outcome:
    ex = ctx.call("GET", BASE + "/metadata", headers=ACCEPT)
    problems: list[str] = []
    if _status(ex, 200, problems):
        cs = ex.json() or {}
        if cs.get("resourceType") != "CapabilityStatement":
            problems.append("The body is not a CapabilityStatement.")
        if not str(cs.get("fhirVersion", "")).startswith("4.0"):
            problems.append(f"Expected FHIR R4 (4.0.x), the server says {cs.get('fhirVersion')!r}.")
        if IG not in cs.get("implementationGuide", []):
            problems.append(f"implementationGuide should list {IG}.")
        declared = {r.get("type"): {i.get("code") for i in r.get("interaction", [])}
                    for rest in cs.get("rest", []) for r in rest.get("resource", [])}
        for name in TYPES:
            if name not in declared:
                problems.append(f"{name} is not declared.")
            elif not {"read", "search-type"} <= declared[name]:
                problems.append(f"{name} should offer read and search-type.")
            elif declared[name] - {"read", "search-type"}:
                problems.append(f"{name} offers {sorted(declared[name] - {'read', 'search-type'})}; a patient-access base must be read and search only.")
        extra = set(declared) - set(TYPES)
        if extra:
            problems.append(f"Unexpected resource types declared: {sorted(extra)}.")
    return Outcome(ex, problems)


@check("P02")
def needs_token(ctx: Context) -> Outcome:
    ex = ctx.call("GET", BASE + "/Patient", headers=ACCEPT)
    problems: list[str] = []
    if _status(ex, 401, problems):
        _bearer_challenge(ex, problems)
        if (ex.json() or {}).get("resourceType") != "OperationOutcome":
            problems.append("The 401 body should be an OperationOutcome.")
    return Outcome(ex, problems)


@check("P03")
def wrong_token(ctx: Context) -> Outcome:
    ex = ctx.call("GET", BASE + "/Patient", bearer="wrong-" + ctx.cfg.api_token, headers=ACCEPT)
    problems: list[str] = []
    _status(ex, 401, problems)
    return Outcome(ex, problems)


@check("P04")
def cors_preflight(ctx: Context) -> Outcome:
    ex = ctx.call("OPTIONS", BASE + "/Patient", headers={
        "Origin": "https://patient-app.example", "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization"})
    problems: list[str] = []
    if ex.status == -1:
        problems.append(f"No HTTP answer: {ex.error}")
    elif not 200 <= ex.status < 300:
        problems.append(f"A preflight must succeed without a token; got HTTP {ex.status}. A browser app would be blocked.")
    else:
        if not ex.header("Access-Control-Allow-Origin"):
            problems.append("Access-Control-Allow-Origin is missing, so a browser will refuse the real request.")
        if "authorization" not in (ex.header("Access-Control-Allow-Headers") or "").lower():
            problems.append("Access-Control-Allow-Headers should allow Authorization, or the browser cannot send the token.")
    return Outcome(ex, problems, note="Whether a browser accepts the real request still depends on the app; this checks the server's side.")


@check("P05")
def find_by_online_id(ctx: Context) -> Outcome:
    ex, found = _search_member(ctx, ONLINE_ID)
    problems: list[str] = []
    if _bundle(ex, problems):
        if len(found) != 1:
            problems.append(f"Expected exactly one Patient, found {len(found)}.")
            _not_loaded_hint(ex, problems)
        else:
            if found[0].get("resourceType") != "Patient" or not _has_profile(found[0], "Patient"):
                problems.append("The Patient should declare the Blue Button C4BB-Patient profile pinned to |2.2.0.")
            _links_are_public(ex, ctx, problems)
    return Outcome(ex, problems)


@check("P06")
def find_by_medicaid_id(ctx: Context) -> Outcome:
    ex, found = _search_member(ctx, MEDICAID_ID)
    problems: list[str] = []
    if _bundle(ex, problems):
        if len(found) != 1:
            problems.append(f"Expected exactly one Patient, found {len(found)}.")
            _not_loaded_hint(ex, problems)
        else:
            member = _member(ctx)
            if member is not None and found[0].get("id") != member.get("id"):
                problems.append("The Medicaid ID found a different Patient than the online ID did.")
    return Outcome(ex, problems)


@check("P07")
def read_patient(ctx: Context) -> Outcome:
    problems: list[str] = []
    member = _need_member(ctx, problems)
    if member is None:
        return Outcome(problems=problems)
    ex = _get(ctx, "/Patient/" + member["id"])
    if _status(ex, 200, problems):
        patient = ex.json() or {}
        if patient.get("resourceType") != "Patient" or patient.get("id") != member["id"]:
            problems.append("The read returned a different resource than the search found.")
        have = _identifier_values(patient)
        for ident in (ONLINE_ID, MEDICAID_ID):
            system, value = ident.split("|", 1)
            if (system, value) not in have:
                problems.append(f"The Patient lacks the identifier {ident}.")
    return Outcome(ex, problems)


@check("P08")
def not_found(ctx: Context) -> Outcome:
    ex = _get(ctx, "/Patient/no-such-patient")
    problems: list[str] = []
    if _status(ex, 404, problems) and (ex.json() or {}).get("resourceType") != "OperationOutcome":
        problems.append("The 404 body should be an OperationOutcome.")
    return Outcome(ex, problems)


@check("P09")
def coverage(ctx: Context) -> Outcome:
    problems: list[str] = []
    member = _need_member(ctx, problems)
    if member is None:
        return Outcome(problems=problems)
    ex = _get(ctx, f"/Coverage?beneficiary=Patient/{member['id']}")
    if _bundle(ex, problems):
        found = _resources(ex)
        if len(found) != 1:
            problems.append(f"Expected one Coverage, found {len(found)}.")
        else:
            if not _has_profile(found[0], "Coverage"):
                problems.append("The Coverage should declare the Blue Button C4BB-Coverage profile pinned to |2.2.0.")
            if found[0].get("beneficiary", {}).get("reference") != "Patient/" + member["id"]:
                problems.append("The Coverage's beneficiary should be the member's Patient.")
    return Outcome(ex, problems)


@check("P10")
def claims(ctx: Context) -> Outcome:
    problems: list[str] = []
    member = _need_member(ctx, problems)
    if member is None:
        return Outcome(problems=problems)
    ex, found = _eobs(ctx, member)
    if _bundle(ex, problems):
        if len(found) != 2:
            problems.append(f"Expected two claims, found {len(found)}.")
        for eob in found:
            label = f"EOB {eob.get('id')}"
            if not _has_profile(eob, "ExplanationOfBenefit-Oral"):
                problems.append(f"{label} should declare the Blue Button C4BB-ExplanationOfBenefit-Oral profile pinned to |2.2.0.")
            if eob.get("patient", {}).get("reference") != "Patient/" + member["id"]:
                problems.append(f"{label}: patient should reference the member.")
            for key in ("status", "insurer", "provider"):
                if not eob.get(key):
                    problems.append(f"{label} has no {key}.")
            if not _identifier_values(eob):
                problems.append(f"{label} has no claim number (identifier).")
        _links_are_public(ex, ctx, problems)
    return Outcome(ex, problems)


def _amount(eob: dict[str, Any], code: str) -> float | None:
    for total in eob.get("total", []):
        if any(c.get("code") == code for c in total.get("category", {}).get("coding", [])):
            amount = total.get("amount", {})
            return amount.get("value") if amount.get("currency") == "USD" else None
    return None


@check("P11")
def amounts_and_preauth(ctx: Context) -> Outcome:
    problems: list[str] = []
    member = _need_member(ctx, problems)
    if member is None:
        return Outcome(problems=problems)
    ex, found = _eobs(ctx, member)
    if _bundle(ex, problems):
        refs: list[str] = []
        for eob in found:
            submitted, benefit = _amount(eob, "submitted"), _amount(eob, "benefit")
            if submitted is None or benefit is None:
                problems.append(f"EOB {eob.get('id')} needs total amounts for submitted and benefit in USD.")
            elif benefit > submitted:
                problems.append(f"EOB {eob.get('id')}: benefit {benefit} is above submitted {submitted}.")
            for ins in eob.get("insurance", []):
                refs.extend(ins.get("preAuthRef", []))
        if PREAUTH not in refs:
            problems.append(f"No claim carries the pre-authorization number {PREAUTH} (insurance.preAuthRef).")
    return Outcome(ex, problems)


@check("P12")
def service_date(ctx: Context) -> Outcome:
    problems: list[str] = []
    member = _need_member(ctx, problems)
    if member is None:
        return Outcome(problems=problems)
    ex, found = _eobs(ctx, member, "&service-date=" + SERVICE_FROM_RESTORATIVE)
    if _bundle(ex, problems):
        numbers = [v for eob in found for _, v in _identifier_values(eob)]
        if len(found) != 1 or RESTORATIVE_CLAIM not in numbers:
            problems.append(f"Expected only the restorative claim {RESTORATIVE_CLAIM}, got {len(found)} claim(s): {numbers}.")
    return Outcome(ex, problems)


@check("P13")
def references_resolve(ctx: Context) -> Outcome:
    problems: list[str] = []
    member = _need_member(ctx, problems)
    if member is None:
        return Outcome(problems=problems)
    ex, found = _eobs(ctx, member)
    refs: set[str] = set()
    for eob in found:
        refs.add(eob.get("insurer", {}).get("reference", ""))
        refs.add(eob.get("provider", {}).get("reference", ""))
        refs.update(c.get("provider", {}).get("reference", "") for c in eob.get("careTeam", []))
        refs.update(i.get("coverage", {}).get("reference", "") for i in eob.get("insurance", []))
        refs.add(eob.get("patient", {}).get("reference", ""))
    refs.discard("")
    if not refs:
        problems.append("No references found in the claims to follow.")
    last = ex
    for ref in sorted(refs):
        kind, _, rid = ref.partition("/")
        if kind not in TYPES or not rid:
            problems.append(f"Reference {ref!r} is not a Type/id on this server.")
            continue
        last = _get(ctx, "/" + ref)
        if last.status != 200 or (last.json() or {}).get("resourceType") != kind:
            problems.append(f"Following {ref} gave HTTP {last.status}; a patient app would show a blank where it belongs.")
    return Outcome(last, problems, note=f"Followed {len(refs)} reference(s); the exchange shown is the last read.")


@check("P14")
def unsupported_param(ctx: Context) -> Outcome:
    ex = _get(ctx, "/Patient?favourite-colour=blue")
    problems: list[str] = []
    if ex.status == 200:
        problems.append("The server ignored a search parameter it does not know and answered 200. A client would "
                        "believe the filter was applied and could show the wrong person's data.")
    elif _status(ex, 400, problems):
        body = ex.json() or {}
        if body.get("resourceType") != "OperationOutcome" or "favourite-colour" not in ex.response_body.decode("utf-8", errors="replace"):
            problems.append("The 400 should be an OperationOutcome that names the parameter.")
    return Outcome(ex, problems)


@check("P15")
def write_refused(ctx: Context) -> Outcome:
    ex = ctx.call("POST", BASE + "/Patient", auth=True, headers={"Content-Type": "application/fhir+json"},
                  body='{"resourceType":"Observation"}')
    problems: list[str] = []
    if ex.status == -1:
        problems.append(f"No HTTP answer: {ex.error}")
    elif ex.status not in (403, 405):
        problems.append(f"A patient-access base must refuse writes with 403 or 405; got HTTP {ex.status}.")
    return Outcome(ex, problems)
