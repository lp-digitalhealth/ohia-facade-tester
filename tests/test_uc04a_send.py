import json
import unittest

from tester import runner
from tester.config import Config, from_env, ConfigError
from tester.runner import run_cases
from tests.fake_server import TOKEN, FakeServer

STEPS = {f"U{n:02d}" for n in range(1, 14)}


def run_against(server: FakeServer, **cfg) -> dict:
    return run_cases(["uc04a-send"], Config(base_url=server.base_url, api_token=TOKEN, allow_http=True, **cfg))


def failed_ids(report: dict) -> set[str]:
    return {s["id"] for c in report["cases"] for s in c["steps"] if not s["passed"]}


class AgainstHealthyServer(unittest.TestCase):
    def test_every_step_passes(self):
        with FakeServer() as server:
            report = run_against(server)
        self.assertEqual(failed_ids(report), set(), [s for s in report["cases"][0]["steps"] if not s["passed"]])
        self.assertEqual(report["summary"]["steps"], 13)

    def test_the_case_has_the_thirteen_steps(self):
        self.assertEqual({s["id"] for s in runner.load_case("uc04a-send")["steps"]}, STEPS)

    def test_the_report_never_contains_the_token_or_a_signed_assertion(self):
        with FakeServer() as server:
            text = json.dumps(run_against(server))
        self.assertNotIn(TOKEN, text)
        self.assertNotIn("eyJ", text)  # a JWT always starts this way

    def test_cleanup_runs_even_when_the_run_fails(self):
        from tester.exchange import HttpClient
        ctx = runner.Context(Config(base_url="http://127.0.0.1:1", api_token="t", allow_http=True), HttpClient())
        closed = []
        ctx.on_close(lambda: closed.append(1))
        ctx.on_close(lambda: 1 / 0)  # a failing cleanup must not stop the others
        ctx.close()
        self.assertEqual(closed, [1])


class EachCheckFailsWhenItsRuleIsBroken(unittest.TestCase):
    """Controls: each broken server must fail exactly the steps that guard the broken rule."""

    def check_mode(self, expected: set[str], **modes: bool):
        with FakeServer(**modes) as server:
            self.assertEqual(failed_ids(run_against(server)), expected, modes)

    def test_receive_open_without_token(self):
        self.check_mode({"U03"}, uc_open_receive=True)

    def test_accepts_anything(self):
        self.check_mode({"U04"}, uc_accept_any=True)

    def test_never_pulls_the_photos(self):
        self.check_mode({"U07", "U08", "U12", "U13"}, uc_no_pull=True)

    def test_signed_assertion_is_wrong(self):
        self.check_mode({"U07", "U08", "U09", "U12", "U13"}, uc_bad_assertion=True)

    def test_does_not_check_the_digest(self):
        self.check_mode({"U13"}, uc_no_digest_check=True)

    def test_new_unexpected_finding(self):
        self.check_mode({"U09"}, uc_extra_finding=True)

    def test_wrong_referral_id(self):
        self.check_mode({"U06"}, uc_wrong_referral=True)

    def test_nothing_stored(self):
        self.check_mode({"U06", "U11"}, uc_not_stored=True)

    def test_allergy_not_stored(self):
        self.check_mode({"U06", "U11"}, uc_no_allergy=True)  # one entry fewer stored, and the allergy cannot be read

    def test_receipt_cannot_be_read_back(self):
        self.check_mode({"U10"}, uc_receipt_missing=True)

    def test_serves_other_bytes(self):
        self.check_mode({"U12"}, uc_serves_wrong_bytes=True)


class VendoredData(unittest.TestCase):
    def test_photos_match_the_digests_declared_in_the_bundle(self):
        from tester.checks.uc04a_send import _load_payload
        payload = _load_payload()  # raises if any photo does not match its declared SHA-256
        self.assertEqual(sorted(payload["objects"]), ["arex-entry-photo-1", "arex-entry-photo-2"])

    def test_no_photo_address_leaks_through_unchanged(self):
        from tester.checks.uc04a_send import _load_payload, _payload_for
        text = _payload_for(_load_payload(), "https://t.example.org").decode()
        self.assertEqual(text.count("https://t.example.org/arex/Binary/"), 2)
        self.assertNotIn("meridian-teledental.example.org/arex/Binary", text)


class SetupProblems(unittest.TestCase):
    def test_unreachable_partner_address_fails_the_start_step(self):
        with FakeServer() as server:
            failed = failed_ids(run_against(server, partner_public_url="http://127.0.0.1:1"))
        self.assertIn("U02", failed)

    def test_an_https_address_is_required_unless_http_is_allowed(self):
        with FakeServer() as server:
            report = run_cases(["uc04a-send"], Config(base_url=server.base_url, api_token=TOKEN, allow_http=False))
        step = next(s for s in report["cases"][0]["steps"] if s["id"] == "U02")
        self.assertFalse(step["passed"])
        self.assertIn("PARTNER_PUBLIC_URL", step["problems"][0])

    def test_config_reads_partner_settings(self):
        cfg = from_env({"BASE_URL": "https://s.example.org", "API_TOKEN": "t", "PARTNER_PUBLIC_URL": "https://p.example.org/", "PARTNER_PORT": "9200"})
        self.assertEqual((cfg.partner_public_url, cfg.partner_port), ("https://p.example.org", 9200))

    def test_config_refuses_insecure_partner_url(self):
        with self.assertRaises(ConfigError):
            from_env({"BASE_URL": "https://s.example.org", "API_TOKEN": "t", "PARTNER_PUBLIC_URL": "http://p.example.org"})
        with self.assertRaises(ConfigError):
            from_env({"BASE_URL": "https://s.example.org", "API_TOKEN": "t", "PARTNER_PORT": "abc"})


if __name__ == "__main__":
    unittest.main()
