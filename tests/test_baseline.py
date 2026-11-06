import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tester import runner
from tester.__main__ import main
from tester.config import Config, ConfigError, from_env
from tester.exchange import HttpClient
from tester.runner import Context, Outcome, available_cases, check, run_cases
from tests.fake_server import TOKEN, FakeServer

ALL_STEPS = {f"B{n:02d}" for n in range(1, 16)}


def run_against(server: FakeServer, token: str = TOKEN) -> dict:
    cfg = Config(base_url=server.base_url, api_token=token, allow_http=True)
    return run_cases(["baseline"], cfg)


def failed_ids(report: dict) -> set[str]:
    return {s["id"] for c in report["cases"] for s in c["steps"] if not s["passed"]}


class BaselineAgainstHealthyServer(unittest.TestCase):
    def test_every_step_passes(self):
        with FakeServer() as server:
            report = run_against(server)
        self.assertEqual(failed_ids(report), set(), [s for c in report["cases"] for s in c["steps"] if not s["passed"]])
        self.assertEqual(report["summary"]["steps"], 15)
        self.assertEqual(report["summary"]["failed"], 0)


class EachCheckFailsWhenItsRuleIsBroken(unittest.TestCase):
    """Controls: each broken server must fail exactly the checks that guard the broken rule."""

    def check_mode(self, expected: set[str], **modes: bool):
        with FakeServer(**modes) as server:
            self.assertEqual(failed_ids(run_against(server)), expected, modes)

    def test_open_fhir(self):
        self.check_mode({"B02", "B04", "B05"}, open_fhir=True)

    def test_issuer_points_at_localhost(self):
        self.check_mode({"B08", "B14"}, localhost=True)

    def test_private_key_leaked(self):
        self.check_mode({"B09"}, leaky_jwks=True)

    def test_viewer_without_csp(self):
        self.check_mode({"B13"}, no_csp=True)

    def test_internal_health_exposed(self):
        self.check_mode({"B15"}, expose_internal=True)

    def test_wrong_token_in_config_fails_authenticated_steps(self):
        with FakeServer() as server:
            report = run_against(server, token="not-the-real-token")
        self.assertEqual(failed_ids(report), {"B03", "B07", "B14"})


class RunnerRobustness(unittest.TestCase):
    def test_unreachable_server_fails_every_step_without_crashing(self):
        cfg = Config(base_url="http://127.0.0.1:9", api_token=TOKEN, allow_http=True)
        report = run_cases(["baseline"], cfg)
        self.assertEqual(failed_ids(report), ALL_STEPS)
        self.assertIn("No HTTP answer", report["cases"][0]["steps"][0]["problems"][0])

    def test_a_crashing_check_is_a_failed_step_not_a_crashed_run(self):
        @check("ZZ99")
        def boom(ctx: Context) -> Outcome:
            raise RuntimeError("kaboom")

        self.addCleanup(runner.REGISTRY.pop, "ZZ99", None)
        case = {"id": "tmp", "title": "tmp", "steps": [
            {"id": "ZZ99", "title": "boom", "expect": "x"}, {"id": "NOPE", "title": "missing", "expect": "x"}]}
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "tmp.json").write_text(json.dumps(case), encoding="utf-8")
            with mock.patch.object(runner, "CASES_DIR", Path(d)):
                result = runner.run_case("tmp", Context(Config("http://x", TOKEN, True), HttpClient()))
        self.assertFalse(result["passed"])
        self.assertIn("kaboom", result["steps"][0]["problems"][0])
        self.assertIn("No check is implemented", result["steps"][1]["problems"][0])


class SecretsNeverReachTheReport(unittest.TestCase):
    def test_token_is_redacted_in_headers_and_bodies(self):
        with FakeServer(echo=True) as server:
            report = run_against(server)
        text = json.dumps(report)
        self.assertNotIn(TOKEN, text)
        b03 = next(s for s in report["cases"][0]["steps"] if s["id"] == "B03")
        self.assertEqual(b03["exchange"]["request_headers"]["Authorization"], "Bearer ***")
        self.assertIn("***", b03["exchange"]["response_body"])  # the echoed token was scrubbed, not dropped

    def test_report_names_only_the_host(self):
        with FakeServer() as server:
            report = run_against(server)
        self.assertEqual(report["target"], f"127.0.0.1:{server.port}")


class CaseFilesMatchChecks(unittest.TestCase):
    def test_every_step_has_a_check_and_every_check_has_a_step(self):
        from tester import checks  # noqa: F401
        in_files = set()
        for case_id in available_cases():
            case = runner.load_case(case_id)
            for step in case["steps"]:
                for key in ("id", "title", "expect", "why"):
                    self.assertTrue(step.get(key), f"{case_id}/{step.get('id')} lacks {key}")
                in_files.add(step["id"])
        self.assertEqual(in_files, set(runner.REGISTRY) - {"ZZ99"})


class ConfigAndCli(unittest.TestCase):
    def test_config_rules(self):
        with self.assertRaises(ConfigError):
            from_env({})
        with self.assertRaises(ConfigError):
            from_env({"BASE_URL": "https://x.org"})
        with self.assertRaises(ConfigError):
            from_env({"BASE_URL": "http://x.org", "API_TOKEN": "t"})
        with self.assertRaises(ConfigError):
            from_env({"BASE_URL": "https://x.org/fhir", "API_TOKEN": "t"})
        self.assertEqual(from_env({"BASE_URL": "https://x.org/", "API_TOKEN": "t"}).base_url, "https://x.org")
        self.assertNotIn("t'", repr(from_env({"BASE_URL": "https://x.org", "API_TOKEN": "t"})))

    def test_token_is_not_in_config_repr(self):
        self.assertNotIn(TOKEN, repr(Config("https://x.org", TOKEN)))

    def test_cli_exit_codes_and_report_file(self):
        with FakeServer() as good, tempfile.TemporaryDirectory() as d:
            out = Path(d) / "results.json"
            env = {"BASE_URL": good.base_url, "API_TOKEN": TOKEN, "ALLOW_HTTP": "1"}
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(main(["run", "--case", "baseline", "--out", str(out)]), 0)
            self.assertEqual(json.loads(out.read_text())["summary"]["failed"], 0)
        with FakeServer(open_fhir=True) as bad:
            env = {"BASE_URL": bad.base_url, "API_TOKEN": TOKEN, "ALLOW_HTTP": "1"}
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(main(["run", "--case", "baseline"]), 1)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(main(["run"]), 2)
        with mock.patch.dict(os.environ, {"BASE_URL": "https://x.org", "API_TOKEN": "t"}, clear=True):
            self.assertEqual(main(["run", "--case", "nope"]), 2)


if __name__ == "__main__":
    unittest.main()
