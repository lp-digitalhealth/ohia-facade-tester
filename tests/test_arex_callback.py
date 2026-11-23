import hashlib
import json
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from unittest import mock

import jwt

from tester import config as tester_config
from tester.checks import arex_callback
from tester.config import Config, ConfigError, from_env
from tester.receiver import ArexReceiver, ReceiverError, build_payload
from tester.runner import run_cases
from tests.fake_facade import _KEY, _OTHER_KEY, FakeFacade
from tests.fake_server import TOKEN

STEPS = {f"R{n:02d}" for n in range(1, 10)}
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def run(**modes: bool) -> dict:
    with FakeFacade(**modes) as facade:
        return run_cases(["arex-callback"], Config(base_url=facade.base_url, api_token=TOKEN, allow_http=True))


def failed(report: dict) -> set[str]:
    return {s["id"] for c in report["cases"] for s in c["steps"] if not s["passed"]}


class CallbackAgainstAHealthyServer(unittest.TestCase):
    def test_every_step_passes(self):
        report = run()
        self.assertEqual(failed(report), set(), [s for c in report["cases"] for s in c["steps"] if not s["passed"]])
        self.assertEqual(report["summary"]["steps"], 9)

    def test_the_case_has_the_nine_steps(self):
        from tester.runner import load_case
        self.assertEqual({s["id"] for s in load_case("arex-callback")["steps"]}, STEPS)


class EachStepFailsWhenItsRuleIsBroken(unittest.TestCase):
    """Controls: each broken server fails the steps that guard the broken rule, and the others still pass."""

    def test_server_answers_with_its_own_receipt_after_the_callback(self):
        # no FHIR answer, no headers: R02 fails, and every step that needs the receipt id cannot go on
        self.assertEqual(failed(run(old_reply=True)), {"R02", "R03", "R06", "R07", "R08", "R09"})

    def test_server_answers_with_fhir_but_only_after_the_callback(self):
        with mock.patch.object(arex_callback, "FAST_REPLY_MS", 300):
            self.assertEqual(failed(run(slow_reply=True)), {"R02"})

    def test_server_never_calls_back(self):
        self.assertEqual(failed(run(no_callback=True)), {"R04", "R05", "R06", "R07", "R08", "R09"})

    def test_server_signs_with_a_key_it_does_not_publish(self):
        self.assertEqual(failed(run(bad_signature=True)), {"R04", "R05", "R06", "R07", "R08"})

    def test_server_saves_an_image_whose_digest_does_not_match(self):
        self.assertEqual(failed(run(skip_digest_check=True)), {"R08"})

    def test_receipt_never_leaves_pending(self):
        with mock.patch.object(arex_callback, "POLL_SECONDS", 2):
            self.assertEqual(failed(run(stuck=True)), {"R03", "R06", "R07", "R08", "R09"})


class ReceiverSetup(unittest.TestCase):
    def test_a_server_that_is_not_on_this_machine_needs_a_public_receiver(self):
        cfg = Config(base_url="https://server.example.org", api_token=TOKEN)
        report = run_cases(["arex-callback"], cfg)
        r01 = report["cases"][0]["steps"][0]
        self.assertFalse(r01["passed"])
        self.assertIn("RECEIVER_URL", " ".join(r01["problems"]))

    def test_an_unreachable_remote_receiver_fails_without_crashing(self):
        cfg = Config(base_url="http://127.0.0.1:9", api_token=TOKEN, allow_http=True, receiver_url="http://127.0.0.1:9", receiver_control_token="c")
        self.assertEqual(failed(run_cases(["arex-callback"], cfg)), STEPS)

    def test_receiver_settings_are_validated(self):
        base = {"BASE_URL": "https://x.org", "API_TOKEN": "t"}
        with self.assertRaises(ConfigError):
            from_env({**base, "RECEIVER_URL": "http://recv.example.org"})
        self.assertEqual(from_env({**base, "RECEIVER_URL": "https://recv.example.org/"}).receiver_url, "https://recv.example.org")
        self.assertNotIn("secret", repr(from_env({**base, "RECEIVER_CONTROL_TOKEN": "secret"})))

    def test_the_control_token_never_reaches_the_report(self):
        with FakeFacade() as facade:
            cfg = Config(base_url=facade.base_url, api_token=TOKEN, allow_http=True, receiver_control_token="control-secret-123")
            self.assertNotIn("control-secret-123", json.dumps(run_cases(["arex-callback"], cfg)))


class TheReceiver(unittest.TestCase):
    def setUp(self):
        self.facade = FakeFacade().__enter__()
        self.addCleanup(self.facade.__exit__, None, None, None)
        self.receiver = ArexReceiver(server_base=self.facade.base_url).start()
        self.addCleanup(self.receiver.stop)
        self.manifest_id = self.receiver.manifest["id"]

    def assertion(self, key=_KEY, **claims) -> str:
        body = {"iss": "ohia-test-server", "sub": "ohia-test-server", "aud": self.receiver.token_endpoint, "jti": str(uuid.uuid4()),
                "exp": int(time.time()) + 120, **claims}
        return jwt.encode(body, key, algorithm="RS384", headers={"kid": "ohia-server-1"})

    def token_request(self, assertion: str, manifest: str | None = None):
        form = urllib.parse.urlencode({"grant_type": "client_credentials", "client_assertion": assertion,
                                       "authorization_details": json.dumps([{"type": "arex-manifest", "manifest": manifest or self.manifest_id}])}).encode()
        req = urllib.request.Request(self.receiver.token_endpoint, data=form, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with _NO_PROXY.open(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def get(self, path: str, token: str | None = None):
        req = urllib.request.Request(self.receiver.public_url + path, headers={"Authorization": "Bearer " + token} if token else {})
        try:
            with _NO_PROXY.open(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, b""

    def test_a_genuine_assertion_gets_a_token_that_opens_the_manifest_and_images(self):
        status, body = self.token_request(self.assertion())
        self.assertEqual(status, 200)
        token = body["access_token"]
        self.assertEqual(self.get(f"/arex/List/{self.manifest_id}", token)[0], 200)
        entry = next(iter(self.receiver.photos))
        status, data = self.get(f"/arex/Binary/{entry}", token)
        self.assertEqual((status, data), (200, self.receiver.photos[entry]))

    def test_nothing_is_served_without_a_token(self):
        entry = next(iter(self.receiver.photos))
        self.assertEqual(self.get(f"/arex/List/{self.manifest_id}")[0], 401)
        self.assertEqual(self.get(f"/arex/Binary/{entry}")[0], 401)

    def test_a_forged_assertion_is_refused_and_counted(self):
        status, body = self.token_request(self.assertion(key=_OTHER_KEY))
        self.assertEqual((status, body["error"]), (401, "invalid_client"))
        self.assertEqual(self.receiver.snapshot()["assertions_verified"], 0)
        self.assertEqual(len(self.receiver.snapshot()["assertions_rejected"]), 1)

    def test_a_replayed_assertion_is_refused(self):
        assertion = self.assertion()
        self.assertEqual(self.token_request(assertion)[0], 200)
        self.assertEqual(self.token_request(assertion)[0], 401)

    def test_an_assertion_for_another_client_or_audience_is_refused(self):
        self.assertEqual(self.token_request(self.assertion(iss="someone-else", sub="someone-else"))[0], 401)
        self.assertEqual(self.token_request(self.assertion(aud="https://elsewhere.example/arex/auth/token"))[0], 401)

    def test_a_token_is_for_one_manifest(self):
        self.assertEqual(self.token_request(self.assertion(), manifest="some-other-manifest")[0], 400)

    def test_the_payload_points_at_the_receiver_and_its_digests_are_real(self):
        bundle = self.receiver.payload()
        text = json.dumps(bundle)
        self.assertNotIn("https://meridian-teledental.example.org", text)  # (a synthetic email address in the sample keeps the bare name)
        self.assertIn(self.receiver.public_url + "/arex/Binary/", text)
        for entry_id, data in self.receiver.photos.items():
            entry = next(e["resource"] for e in bundle["entry"] if e["resource"]["id"] == entry_id)
            declared = next(p["valueString"] for ext in entry["content"][0]["attachment"]["extension"] if ext["url"].endswith("arex-digest")
                            for p in ext["extension"] if p["url"] == "value")
            self.assertEqual(declared, hashlib.sha256(data).hexdigest())

    def test_the_manifest_expiry_is_in_the_future(self):
        expiry = next(ext["valueInstant"] for ext in self.receiver.manifest["extension"] if ext["url"].endswith("arex-expires"))
        self.assertGreater(expiry, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def test_tamper_mode_changes_the_bytes_served(self):
        _, body = self.token_request(self.assertion())
        entry = next(iter(self.receiver.photos))
        self.receiver.set_modes(tamper=True)
        _, data = self.get(f"/arex/Binary/{entry}", body["access_token"])
        self.assertNotEqual(data, self.receiver.photos[entry])
        self.assertEqual(len(data), len(self.receiver.photos[entry]))

    def test_an_unknown_mode_is_refused(self):
        with self.assertRaises(ReceiverError):
            self.receiver.set_modes(not_a_mode=True)

    def test_a_receiver_beyond_this_machine_needs_a_control_token(self):
        with self.assertRaises(ReceiverError):
            ArexReceiver(server_base=self.facade.base_url, listen=("0.0.0.0", 0))

    def test_the_control_api_needs_the_token_when_one_is_set(self):
        r = ArexReceiver(server_base=self.facade.base_url, control_token="tok").start()
        self.addCleanup(r.stop)
        open_req = urllib.request.Request(r.public_url + "/__harness/log")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            _NO_PROXY.open(open_req, timeout=10)
        self.assertEqual(ctx.exception.code, 401)
        ok_req = urllib.request.Request(r.public_url + "/__harness/log", headers={"X-Harness-Token": "tok"})
        with _NO_PROXY.open(ok_req, timeout=10) as resp:
            self.assertEqual(resp.status, 200)


if __name__ == "__main__":
    unittest.main()
