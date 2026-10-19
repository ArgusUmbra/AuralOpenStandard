import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import textwrap
import unittest

from tools import run_aural_conformance as runner


ROOT = Path(__file__).resolve().parents[1]
SOURCE_CORPUS = ROOT / "tests" / "fixtures" / "conformance"


FAKE_ADAPTER = r'''
import json
import sys
import time

request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
mode = sys.argv[1]
base = {
    "protocol": "org.aural.conformance.adapter",
    "protocol_version": 1,
    "case_id": request["case_id"],
}

if mode == "process-failure":
    print("controlled failure", file=sys.stderr)
    raise SystemExit(9)
if mode == "malformed":
    sys.stdout.write("{")
    raise SystemExit(0)
if mode == "duplicate":
    sys.stdout.write(
        '{"protocol":"org.aural.conformance.adapter",'
        '"protocol":"org.aural.conformance.adapter",'
        '"protocol_version":1,"case_id":' + json.dumps(request["case_id"]) +
        ',"outcome":"accept"}'
    )
    raise SystemExit(0)
if mode == "wrong-version":
    base["protocol_version"] = 2
    base["outcome"] = "accept"
elif mode == "wrong-case":
    base["case_id"] = request["case_id"] + "/wrong"
    base["outcome"] = "accept"
elif mode == "missing-outcome":
    pass
elif mode == "extra-output":
    base["outcome"] = "accept"
    sys.stdout.write(json.dumps(base) + "\nnot-json\n")
    raise SystemExit(0)
elif mode == "oversize":
    sys.stdout.write("x" * 70000)
    raise SystemExit(0)
elif mode == "timeout":
    time.sleep(2)
    base["outcome"] = "accept"
elif mode == "accept":
    base["outcome"] = "accept"
elif mode == "reject":
    base["outcome"] = "reject"
elif mode == "correct":
    base["outcome"] = (
        "reject" if "/invalid-" in request["case_id"] else "accept"
    )
else:
    raise SystemExit(10)

sys.stdout.write(json.dumps(base, separators=(",", ":")) + "\n")
'''


class ConformanceRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.adapter_dir = cls.root / "adapter path with spaces"
        cls.adapter_dir.mkdir()
        cls.adapter = cls.adapter_dir / "fake adapter.py"
        cls.adapter.write_text(textwrap.dedent(FAKE_ADAPTER), encoding="utf-8")
        _, cases, _ = runner.load_cases(runner.DEFAULT_MANIFEST)
        cls.cases = cases
        cls.positive = next(
            case for case in cases
            if case.requirement == "required" and case.expected_outcome == "accept"
        )
        cls.negative = next(
            case for case in cases
            if case.requirement == "required" and case.expected_outcome == "reject"
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def command(self, mode):
        return [sys.executable, str(self.adapter), mode]

    def run_case(self, case, mode, timeout=2.0):
        return runner.run_case(case, self.command(mode), timeout)

    def copied_corpus(self):
        destination = self.root / f"corpus-{next(tempfile._get_candidate_names())}"
        shutil.copytree(SOURCE_CORPUS, destination)
        self.addCleanup(shutil.rmtree, destination)
        return destination, destination / runner.DEFAULT_MANIFEST.name

    def invoke(self, mode, *, include_legacy=False, extra=None, manifest=None):
        report = self.root / f"report-{next(tempfile._get_candidate_names())}.json"
        arguments = [
            "--report", str(report),
            "--adapter", sys.executable,
            "--adapter-arg", str(self.adapter),
            "--adapter-arg", mode,
        ]
        if include_legacy:
            arguments.append("--include-legacy")
        if manifest is not None:
            arguments.extend(["--manifest", str(manifest)])
        if extra:
            arguments.extend(extra)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = runner.main(arguments)
        return status, report

    def test_correct_positive_case_acceptance_passes(self):
        result = self.run_case(self.positive, "accept")
        self.assertEqual("PASS", result["status"])
        self.assertEqual("accept", result["observed_outcome"])

    def test_correct_negative_case_rejection_passes(self):
        result = self.run_case(self.negative, "reject")
        self.assertEqual("PASS", result["status"])
        self.assertEqual("reject", result["observed_outcome"])

    def test_incorrect_acceptance_fails(self):
        self.assertEqual("FAIL", self.run_case(self.negative, "accept")["status"])

    def test_incorrect_rejection_fails(self):
        self.assertEqual("FAIL", self.run_case(self.positive, "reject")["status"])

    def test_adapter_process_failure_is_error(self):
        result = self.run_case(self.positive, "process-failure")
        self.assertEqual("ERROR", result["status"])
        self.assertEqual("adapter-process-failed", result["error"]["code"])

    def test_malformed_output_json_is_error(self):
        result = self.run_case(self.positive, "malformed")
        self.assertEqual("ERROR", result["status"])
        self.assertEqual("invalid-adapter-response", result["error"]["code"])

    def test_duplicate_json_keys_are_rejected(self):
        result = self.run_case(self.positive, "duplicate")
        self.assertEqual("ERROR", result["status"])
        self.assertIn("duplicate JSON object key", result["error"]["message"])

    def test_wrong_protocol_version_is_error(self):
        result = self.run_case(self.positive, "wrong-version")
        self.assertEqual("ERROR", result["status"])
        self.assertIn("wrong protocol version", result["error"]["message"])

    def test_wrong_case_id_is_error(self):
        result = self.run_case(self.positive, "wrong-case")
        self.assertEqual("ERROR", result["status"])
        self.assertIn("case_id", result["error"]["message"])

    def test_missing_required_output_is_error(self):
        result = self.run_case(self.positive, "missing-outcome")
        self.assertEqual("ERROR", result["status"])
        self.assertIn("outcome", result["error"]["message"])

    def test_process_timeout_has_distinct_status(self):
        result = self.run_case(self.positive, "timeout", timeout=0.05)
        self.assertEqual("TIMEOUT", result["status"])
        self.assertEqual("adapter-timeout", result["error"]["code"])

    def test_unexpected_extra_output_is_error(self):
        result = self.run_case(self.positive, "extra-output")
        self.assertEqual("ERROR", result["status"])
        self.assertIn("one strict JSON document", result["error"]["message"])

    def test_excessive_output_size_is_error(self):
        result = self.run_case(self.positive, "oversize")
        self.assertEqual("ERROR", result["status"])
        self.assertEqual("adapter-output-too-large", result["error"]["code"])

    def test_missing_fixture_fails_manifest_preflight(self):
        corpus, manifest = self.copied_corpus()
        (corpus / "valid-minimal.aural").unlink()
        status, report = self.invoke("correct", manifest=manifest)
        self.assertEqual(runner.EXIT_RUNNER_ERROR, status)
        self.assertFalse(report.exists())

    def test_corrupted_fixture_fails_manifest_preflight(self):
        corpus, manifest = self.copied_corpus()
        fixture = corpus / "valid-minimal.aural"
        payload = bytearray(fixture.read_bytes())
        payload[0] ^= 1
        fixture.write_bytes(payload)
        status, report = self.invoke("correct", manifest=manifest)
        self.assertEqual(runner.EXIT_RUNNER_ERROR, status)
        self.assertFalse(report.exists())

    def test_invalid_executable_produces_incomplete_report(self):
        missing = self.root / "does not exist" / "adapter executable"
        report = self.root / "invalid-executable-report.json"
        arguments = ["--report", str(report), "--adapter", str(missing)]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = runner.main(arguments)
        self.assertEqual(runner.EXIT_INCOMPLETE, status)
        document = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual("INCOMPLETE", document["overall_result"])
        self.assertEqual(30, document["summary"]["execution_errors"])

    def test_paths_containing_spaces_are_preserved_as_one_argument(self):
        spaced_executable = self.adapter_dir / Path(sys.executable).name
        shutil.copy2(sys.executable, spaced_executable)
        result = runner.run_case(
            self.positive,
            [str(spaced_executable), str(self.adapter), "accept"],
            2.0,
        )
        self.assertEqual("PASS", result["status"])
        parsed = runner.argument_parser().parse_args([
            "--report", str(self.root / "a report.json"),
            "--adapter", str(self.root / "program files" / "adapter executable"),
            "--adapter-arg", "argument with spaces",
        ])
        self.assertEqual("argument with spaces", parsed.adapter_arg[0])
        self.assertIn("program files", parsed.adapter)

    def test_required_case_omission_is_incomplete(self):
        results = []
        for case in [item for item in self.cases if item.requirement == "required"][:-1]:
            result = runner.skipped_case_result(case)
            result["status"] = "PASS"
            result.pop("error")
            results.append(result)
        summary = runner.summarize(results, 30)
        self.assertEqual("INCOMPLETE", summary["overall_result"])
        self.assertEqual(29, summary["required"]["selected"])

    def test_explicit_required_skip_is_incomplete(self):
        required = [item for item in self.cases if item.requirement == "required"]
        results = []
        for case in required:
            result = runner.skipped_case_result(case)
            if case is not required[0]:
                result["status"] = "PASS"
                result.pop("error")
            results.append(result)
        summary = runner.summarize(results, 30)
        self.assertEqual("INCOMPLETE", summary["overall_result"])
        self.assertEqual(1, summary["required"]["skipped"])

    def test_optional_legacy_selection_does_not_change_required_score(self):
        status, report = self.invoke("correct", include_legacy=True)
        self.assertEqual(runner.EXIT_PASS, status)
        document = json.loads(report.read_text(encoding="utf-8"))
        self.assertTrue(document["optional_legacy_included"])
        self.assertEqual(32, len(document["cases"]))
        self.assertEqual(2, document["summary"]["optional"]["passed"])
        self.assertEqual("PASS", document["overall_result"])

    def test_optional_legacy_failures_do_not_change_required_score(self):
        results = []
        for case in self.cases:
            result = runner.skipped_case_result(case)
            result["status"] = "PASS" if case.requirement == "required" else "FAIL"
            result.pop("error")
            results.append(result)
        summary = runner.summarize(results, 30)
        self.assertEqual(2, summary["optional"]["failed"])
        self.assertEqual("PASS", summary["overall_result"])

    def test_summary_counts_distinguish_every_status(self):
        statuses = ["PASS", "FAIL", "ERROR", "TIMEOUT", "SKIP"]
        results = []
        for index, case in enumerate(
            item for item in self.cases if item.requirement == "required"
        ):
            result = runner.skipped_case_result(case)
            result["status"] = statuses[index] if index < len(statuses) else "PASS"
            results.append(result)
        summary = runner.summarize(results, 30)
        self.assertEqual(26, summary["passed"])
        self.assertEqual(1, summary["failed"])
        self.assertEqual(1, summary["execution_errors"])
        self.assertEqual(1, summary["timeouts"])
        self.assertEqual(1, summary["skipped"])

    def test_machine_readable_report_structure(self):
        status, report = self.invoke("correct")
        self.assertEqual(runner.EXIT_PASS, status)
        document = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(runner.REPORT_SCHEMA, document["schema"])
        self.assertEqual(1, document["schema_version"])
        self.assertEqual(30, len(document["cases"]))
        self.assertEqual(30, document["summary"]["required_cases"])
        self.assertEqual("PASS", document["overall_result"])
        case = document["cases"][0]
        self.assertEqual(
            {
                "case_id", "profile_id", "profile_version", "requirement",
                "expected_outcome", "observed_outcome", "status", "duration_ms",
                "fixture",
            },
            set(case),
        )
        self.assertEqual(64, len(case["fixture"]["sha256"]))

    def test_reject_everything_adapter_has_failure_exit_status(self):
        status, report = self.invoke("reject")
        self.assertEqual(runner.EXIT_FAIL, status)
        document = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual("FAIL", document["overall_result"])
        self.assertEqual(4, document["summary"]["required"]["failed"])

    def test_correct_adapter_has_success_exit_status(self):
        status, report = self.invoke("correct")
        self.assertEqual(runner.EXIT_PASS, status)
        self.assertEqual(
            "PASS", json.loads(report.read_text(encoding="utf-8"))["overall_result"],
        )

    def test_report_path_cannot_target_conformance_fixtures(self):
        protected = SOURCE_CORPUS / "runner-report.json"
        with self.assertRaisesRegex(runner.RunnerError, "fixture directory"):
            runner.validate_report_path(protected, runner.DEFAULT_MANIFEST)
        self.assertFalse(protected.exists())

    def test_manifest_with_required_case_omitted_is_rejected(self):
        _, manifest = self.copied_corpus()
        document = json.loads(manifest.read_text(encoding="utf-8"))
        document["cases"] = [
            case for case in document["cases"]
            if case["id"] != self.positive.case_id
        ]
        manifest.write_text(json.dumps(document), encoding="utf-8")
        status, report = self.invoke("correct", manifest=manifest)
        self.assertEqual(runner.EXIT_RUNNER_ERROR, status)
        self.assertFalse(report.exists())


if __name__ == "__main__":
    unittest.main()
