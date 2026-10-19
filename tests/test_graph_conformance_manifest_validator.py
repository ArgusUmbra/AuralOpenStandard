import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import validate_graph_conformance_manifest as validator


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "validate_graph_conformance_manifest.py"
SOURCE_FIXTURES = ROOT / "tests" / "fixtures"
MANIFEST_NAME = "graph-cases.v1.json"


class GraphConformanceManifestValidatorTests(unittest.TestCase):
    def run_validator(self, manifest=None):
        command = [sys.executable, str(VALIDATOR)]
        if manifest is not None:
            command.append(str(manifest))
        return subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    def copied_corpus(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture_root = Path(temporary.name) / "fixtures"
        fixture_root.mkdir()
        manifest = SOURCE_FIXTURES / "graph_conformance" / MANIFEST_NAME
        document = self.load_manifest(manifest)
        relative_paths = {
            "graph_conformance/graph-cases.v1.json",
            document["source_index"]["path"],
            document["separate_resource_suites"][0]["index"]["path"],
        }
        for case in document["cases"]:
            relative_paths.update(item["path"] for item in case["inputs"])
        for relative in sorted(relative_paths):
            source = SOURCE_FIXTURES.joinpath(*relative.split("/"))
            target = fixture_root.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return fixture_root, fixture_root / "graph_conformance" / MANIFEST_NAME

    @staticmethod
    def load_manifest(path):
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def write_manifest(path, document):
        path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def case(self, document, source_case):
        return next(case for case in document["cases"] if case["source_case"] == source_case)

    def assert_validation_fails(self, completed, message):
        self.assertEqual(1, completed.returncode, completed.stdout)
        self.assertIn("FAIL:", completed.stderr)
        self.assertIn(message, completed.stderr)

    def test_valid_committed_manifest_passes(self):
        completed = self.run_validator()
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("validated 35 graph cases (11 accept/24 reject)", completed.stdout)
        self.assertIn("89 ordered input descriptors", completed.stdout)
        self.assertIn("all sizes, SHA-256 digests", completed.stdout)

    def test_all_35_source_cases_are_accounted_for_in_order(self):
        public = self.load_manifest(
            SOURCE_FIXTURES / "graph_conformance" / MANIFEST_NAME
        )
        source = self.load_manifest(
            SOURCE_FIXTURES / "graph_conformance" / "cases.json"
        )
        self.assertEqual(35, len(public["cases"]))
        self.assertEqual(
            [case["id"] for case in source["cases"]],
            [case["source_case"] for case in public["cases"]],
        )

    def test_incorrect_sha256_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["inputs"][0]["sha256"] = "0" * 64
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "SHA-256 mismatch")

    def test_incorrect_size_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["inputs"][0]["size"] += 1
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "size mismatch")

    def test_missing_fixture_fails(self):
        fixture_root, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        relative = document["cases"][0]["inputs"][0]["path"]
        fixture_root.joinpath(*relative.split("/")).unlink()
        self.assert_validation_fails(self.run_validator(manifest), "does not exist")

    def test_duplicate_case_id_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][1]["id"] = document["cases"][0]["id"]
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "duplicate case ID")

    def test_duplicate_input_occurrence_removed_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        case = self.case(document, "D-identical-duplicates")
        case["inputs"].pop(2)
        for index, item in enumerate(case["inputs"]):
            item["order"] = index
        self.write_manifest(manifest, document)
        self.assert_validation_fails(
            self.run_validator(manifest), "required order and multiplicity"
        )

    def test_incorrect_input_ordering_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        case = self.case(document, "C-parent-child")
        case["inputs"][0], case["inputs"][1] = case["inputs"][1], case["inputs"][0]
        for index, item in enumerate(case["inputs"]):
            item["order"] = index
        self.write_manifest(manifest, document)
        self.assert_validation_fails(
            self.run_validator(manifest), "required order and multiplicity"
        )

    def test_incorrect_expected_outcome_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["expected"] = {
            "outcome": "reject",
            "expectation_level": "experimental-profile-defined",
            "failure": {"category": "signature", "stage": "signature"},
        }
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "does not match source case")

    def test_invalid_failure_category_or_stage_fails(self):
        for field, value, message in (
            ("category", "adapter-message", "failure.category has invalid value"),
            ("stage", ["record"], "failure.stage must be a string"),
        ):
            with self.subTest(field=field):
                _, manifest = self.copied_corpus()
                document = self.load_manifest(manifest)
                failure = self.case(
                    document, "N01-invalid-ed25519-signature"
                )["expected"]["failure"]
                failure[field] = value
                self.write_manifest(manifest, document)
                self.assert_validation_fails(self.run_validator(manifest), message)

    def test_missing_expected_result_field_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        del document["cases"][0]["expected"]["graph"]["maximum_depth"]
        self.write_manifest(manifest, document)
        self.assert_validation_fails(
            self.run_validator(manifest), "normalized graph-result fields"
        )

    def test_absolute_path_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["inputs"][0]["path"] = "C:/event.json"
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "must be relative")

    def test_directory_traversal_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["inputs"][0]["path"] = "../event.json"
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "unsafe traversal")

    def test_symlink_escape_fails(self):
        fixture_root, manifest = self.copied_corpus()
        outside = fixture_root.parent / "outside"
        outside.mkdir()
        target = outside / "event.json"
        target.write_bytes(b"event")
        link = fixture_root / "linked"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            fixture = validator.FixtureRecord(
                "test-case",
                "linked/event.json",
                hashlib.sha256(b"event").hexdigest(),
                5,
            )
            symbolic_link = mock.Mock(st_mode=stat.S_IFLNK)
            with mock.patch(
                "tools.validate_core_conformance_manifest.Path.lstat",
                return_value=symbolic_link,
            ):
                with self.assertRaisesRegex(validator.ValidationError, "symbolic link"):
                    validator._register_fixture(fixture_root, fixture, {})
            return
        document = self.load_manifest(manifest)
        record = document["cases"][0]["inputs"][0]
        record.update(
            path="linked/event.json",
            size=5,
            sha256=hashlib.sha256(b"event").hexdigest(),
        )
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "symbolic link")

    def test_non_regular_input_fails(self):
        fixture_root, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        relative = document["cases"][0]["inputs"][0]["path"]
        path = fixture_root.joinpath(*relative.split("/"))
        path.unlink()
        path.mkdir()
        self.assert_validation_fails(self.run_validator(manifest), "not a regular file")

    def test_duplicate_json_keys_fail(self):
        _, manifest = self.copied_corpus()
        text = manifest.read_text(encoding="utf-8")
        needle = '  "schema": "urn:aural:conformance:signed-event-graph-cases",\n'
        self.assertEqual(1, text.count(needle))
        manifest.write_text(text.replace(needle, needle + needle), encoding="utf-8")
        self.assert_validation_fails(
            self.run_validator(manifest), "duplicate JSON object key 'schema'"
        )

    def test_invalid_manifest_version_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["schema_version"] = 2
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "manifest.schema_version")

    def test_corrupted_compressed_resource_metadata_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        case = self.case(document, "H-parent-fanout-64")
        case["inputs"][0]["representation"]["expanded_sha256"] = "0" * 64
        self.write_manifest(manifest, document)
        self.assert_validation_fails(
            self.run_validator(manifest), "inputs[0].representation"
        )

    def test_public_expectations_match_original_source_manifest(self):
        public = self.load_manifest(
            SOURCE_FIXTURES / "graph_conformance" / MANIFEST_NAME
        )
        source = self.load_manifest(
            SOURCE_FIXTURES / "graph_conformance" / "cases.json"
        )
        for public_case, source_case in zip(public["cases"], source["cases"]):
            self.assertEqual(
                validator._expected_result(source_case, source),
                public_case["expected"],
                source_case["id"],
            )

    def test_materialized_adapter_inputs_match_original_transformation(self):
        source = self.load_manifest(
            SOURCE_FIXTURES / "graph_conformance" / "cases.json"
        )
        cases = {case["id"]: case for case in source["cases"]}
        for case_id, relative in validator.MATERIALIZED_EVENTS.items():
            descriptor = cases[case_id]["diagnostic_input_construction"][
                "signed_events"
            ][0]
            self.assertEqual(
                {"type": "append_signature_text", "suffix": "=="},
                descriptor["transform"],
            )
            source_relative = source["diagnostic_inputs"][descriptor["input"]]["path"]
            source_path = SOURCE_FIXTURES / "graph_conformance" / source_relative
            original = source_path.resolve().read_bytes()
            derived = original[:-2] + b"==" + original[-2:]
            materialized = SOURCE_FIXTURES.joinpath(*relative.split("/")).read_bytes()
            self.assertEqual(derived, materialized, case_id)
            self.assertEqual(descriptor["sha256"], hashlib.sha256(materialized).hexdigest())


if __name__ == "__main__":
    unittest.main()
