"""A compact model of the server's patient-access base, for the fake server. It follows the contract of the
real base (ohia-fhir-test-server, /patient-access/fhir) and the shape of the UC07 interaction-06 data. It is a
model, not the data: the run against the real server is the final proof."""

from __future__ import annotations

from typing import Any

C4BB = "http://hl7.org/fhir/us/carin-bb/StructureDefinition/C4BB-"
ONLINE = ("https://dentaquest.example.org/fhir/online-id", "DQ-ONLINE-TX-0038211")
MEDICAID = ("http://texas.medicaid.gov/beneficiary", "TX-MCD-0038211")
PA = "TX-DQ-PA-2026-061204"
PID = "patient-joe-castle-payer"


def _meta(name: str) -> dict[str, Any]:
    return {"lastUpdated": "2026-07-28T06:00:00-05:00", "profile": [C4BB + name + "|2.2.0"]}


def _total(submitted: int, benefit: int) -> list[dict[str, Any]]:
    def one(code: str, value: int) -> dict[str, Any]:
        return {"category": {"coding": [{"code": code}]}, "amount": {"value": value, "currency": "USD"}}
    return [one("submitted", submitted), one("benefit", benefit)]


def _eob(rid: str, number: str, day: str, provider: str, submitted: int, benefit: int, preauth: str | None) -> dict[str, Any]:
    insurance: dict[str, Any] = {"focal": True, "coverage": {"reference": "Coverage/cov-1"}}
    if preauth:
        insurance["preAuthRef"] = [preauth]
    return {"resourceType": "ExplanationOfBenefit", "id": rid, "meta": _meta("ExplanationOfBenefit-Oral"), "status": "active",
            "identifier": [{"system": "https://dentaquest.example.org/fhir/eob-identifier", "value": number}],
            "patient": {"reference": "Patient/" + PID}, "billablePeriod": {"start": day, "end": day},
            "insurer": {"reference": "Organization/org-1"}, "provider": {"reference": "Practitioner/" + provider},
            "careTeam": [{"provider": {"reference": "Practitioner/" + provider}}], "insurance": [insurance],
            "total": _total(submitted, benefit)}


def build(*, drop_preauth: bool = False, dangling_insurer: bool = False, open_world: bool = False) -> dict[str, dict[str, Any]]:
    """The resources, keyed 'Type/id'. Flags break one thing in the data."""
    eobs = [_eob("eob-ped", "DQ-EOB-2026-UC07-001", "2026-07-08", "pract-1", 130, 88, None),
            _eob("eob-res", "DQ-EOB-2026-UC07-002", "2026-07-22", "pract-2", 2260, 1530, None if drop_preauth else PA)]
    if dangling_insurer:
        for e in eobs:
            e["insurer"] = {"reference": "Organization/org-missing"}
    resources = [
        {"resourceType": "Patient", "id": PID, "meta": _meta("Patient"),
         "identifier": [{"system": MEDICAID[0], "value": MEDICAID[1]}, {"system": ONLINE[0], "value": ONLINE[1]}]},
        {"resourceType": "Coverage", "id": "cov-1", "meta": _meta("Coverage"), "beneficiary": {"reference": "Patient/" + PID}},
        {"resourceType": "Organization", "id": "org-1", "meta": _meta("Organization")},
        {"resourceType": "Practitioner", "id": "pract-1", "meta": _meta("Practitioner")},
        {"resourceType": "Practitioner", "id": "pract-2", "meta": _meta("Practitioner")},
        *eobs,
    ]
    return {f"{r['resourceType']}/{r['id']}": r for r in resources}


def search(resources: dict[str, dict[str, Any]], rtype: str, params: dict[str, list[str]]) -> tuple[int, dict[str, Any]]:
    """Returns (status, body). Supports what the tester asks for; anything else is a 400, as on the real base."""
    allowed = {"Patient": {"identifier"}, "Coverage": {"beneficiary"}, "ExplanationOfBenefit": {"patient", "service-date"}}.get(rtype, set())
    for name in params:
        if name not in allowed:
            return 400, {"resourceType": "OperationOutcome", "issue": [{"severity": "error", "code": "not-supported",
                         "details": {"text": f"The search parameter '{name}' is not supported on {rtype}."}}]}
    hits = [r for k, r in resources.items() if k.startswith(rtype + "/")]
    for name, values in params.items():
        value = values[0]
        if name == "identifier":
            system, _, val = value.partition("|")
            hits = [r for r in hits if any(i.get("system") == system and i.get("value") == val for i in r.get("identifier", []))]
        elif name in ("patient", "beneficiary"):
            wanted = value if "/" in value else "Patient/" + value
            field = "beneficiary" if rtype == "Coverage" else "patient"
            hits = [r for r in hits if r[field]["reference"] == wanted]
        elif name == "service-date" and value.startswith("ge"):
            hits = [r for r in hits if r["billablePeriod"]["end"] >= value[2:]]
    return 200, {"resourceType": "Bundle", "type": "searchset", "total": len(hits), "entry": [{"resource": r} for r in hits]}
