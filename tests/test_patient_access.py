import json
import unittest

from tester import runner
from tester.config import Config
from tester.runner import run_cases
from tests.fake_server import TOKEN, FakeServer

STEPS = {f"P{n:02d}" for n in range(1, 16)}


def run_against(server: FakeServer, token: str = TOKEN) -> dict:
    return run_cases(["patient-access"], Config(base_url=server.base_url, api_token=token, allow_http=True))


def failed_ids(report: dict) -> set[str]:
    return {s["id"] for c in report["cases"] for s in c["steps"] if not s["passed"]}


def step(report: dict, step_id: str) -> dict:
    return next(s for s in report["cases"][0]["steps"] if s["id"] == step_id)


class PatientAccessAgainstHealthyServer(unittest.TestCase):
    def test_every_step_passes(self):
        with FakeServer() as server:
            report = run_against(server)
        self.assertEqual(failed_ids(report), set(), [s for s in report["cases"][0]["steps"] if not s["passed"]])
        self.assertEqual(report["summary"]["steps"], 15)

    def test_the_case_has_the_fifteen_steps(self):
        self.assertEqual({s["id"] for s in runner.load_case("patient-access")["steps"]}, STEPS)


class EachCheckFailsWhenItsRuleIsBroken(unittest.TestCase):
    """Controls: each broken server must fail exactly the steps that guard the broken rule."""

    def check_mode(self, expected: set[str], **modes: bool):
        with FakeServer(**modes) as server:
            self.assertEqual(failed_ids(run_against(server)), expected, modes)

    def test_open_without_token(self):
        self.check_mode({"P02", "P03"}, pa_open=True)

    def test_a_401_that_is_not_an_operation_outcome(self):
        self.check_mode({"P02"}, pa_plain_401=True)

    def test_no_cors_headers(self):
        self.check_mode({"P04"}, pa_no_cors=True)

    def test_preflight_demands_a_token(self):
        self.check_mode({"P04"}, pa_preflight_needs_token=True)

    def test_server_accepts_writes(self):
        self.check_mode({"P15"}, pa_writable=True)

    def test_capability_statement_claims_create(self):
        self.check_mode({"P01"}, pa_write_capability=True)

    def test_unknown_search_parameter_is_ignored(self):
        self.check_mode({"P14"}, pa_ignores_params=True)

    def test_links_point_at_localhost(self):
        self.check_mode({"P05", "P10"}, pa_localhost=True)

    def test_preauthorization_number_missing(self):
        self.check_mode({"P11"}, pa_no_preauth=True)

    def test_a_reference_that_cannot_be_followed(self):
        self.check_mode({"P13"}, pa_dangling=True)

    def test_a_missing_record_is_not_a_404(self):
        self.check_mode({"P08"}, pa_missing_is_ok=True)

    def test_the_date_filter_is_ignored(self):
        self.check_mode({"P12"}, pa_ignores_dates=True)

    def test_data_not_loaded_fails_the_steps_that_need_it_and_says_how_to_load_it(self):
        with FakeServer(pa_not_loaded=True) as server:
            report = run_against(server)
        self.assertEqual(failed_ids(report), {"P05", "P06", "P07", "P09", "P10", "P11", "P12", "P13"})
        self.assertIn("seed-patient-access", " ".join(step(report, "P05")["problems"]))
        self.assertIn("needs the member found in step P05", " ".join(step(report, "P10")["problems"]))

    def test_wrong_token_in_config_fails_the_authenticated_steps(self):
        with FakeServer() as server:
            report = run_against(server, token="not-the-real-token")
        self.assertEqual(failed_ids(report), STEPS - {"P01", "P02", "P03", "P04"})


class PatientAccessRobustness(unittest.TestCase):
    def test_unreachable_server_fails_every_step_without_crashing(self):
        report = run_cases(["patient-access"], Config(base_url="http://127.0.0.1:9", api_token=TOKEN, allow_http=True))
        self.assertEqual(failed_ids(report), STEPS)

    def test_the_token_never_reaches_the_report(self):
        with FakeServer() as server:
            report = run_against(server)
        self.assertNotIn(TOKEN, json.dumps(report))

    def test_the_tester_only_reads_except_for_the_one_refused_probe(self):
        with FakeServer() as server:
            report = run_against(server)
        methods = {s["exchange"]["method"] for s in report["cases"][0]["steps"] if s["exchange"]}
        self.assertEqual(methods, {"GET", "OPTIONS", "POST"})
        post = step(report, "P15")["exchange"]
        self.assertEqual(json.loads(post["request_body"]), {"resourceType": "Observation"})


if __name__ == "__main__":
    unittest.main()
