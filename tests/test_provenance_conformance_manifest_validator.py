import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import validate_provenance_conformance_manifest as validator


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "validate_provenance_conformance_manifest.py"
SOURCE_FIXTURES = ROOT / "tests" / "fixtures"
MANIFEST_NAME = "provenance-cases.v1.json"


class ProvenanceConformanceManifestValidatorTests(unittest.TestCase):
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
            timeout=20,
        )

    def copied_corpus(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture_root = Path(temporary.name) / "fixtures"
        shutil.copytree(SOURCE_FIXTURES / "provenance", fixture_root / "provenance")
        (fixture_root / "conformance").mkdir()
        shutil.copy2(
            SOURCE_FIXTURES / "conformance" / "valid-unicode.aural",
            fixture_root / "conformance" / "valid-unicode.aural",
        )
        return fixture_root, fixture_root / "provenance" / MANIFEST_NAME

    @staticmethod
    def load_manifest(path):
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def write_manifest(path, document):
        path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def assert_validation_fails(self, completed, message):
        self.assertEqual(1, completed.returncode, completed.stdout)
        self.assertIn("FAIL:", completed.stderr)
        self.assertIn(message, completed.stderr)

    def test_valid_committed_corpus_passes(self):
        completed = self.run_validator()
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("validated 45 provenance cases (3 accept/42 reject)", completed.stdout)
        self.assertIn("13 Ed25519 vectors (1 accept/12 reject)", completed.stdout)
        self.assertIn("all sizes and SHA-256 digests match", completed.stdout)

    def test_incorrect_sha256_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["inputs"][0]["sha256"] = "0" * 64
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "SHA-256 mismatch")

    def test_incorrect_byte_size_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["inputs"][0]["size"] += 1
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "size mismatch")

    def test_missing_fixture_fails(self):
        fixture_root, manifest = self.copied_corpus()
        (fixture_root / "provenance" / "valid-original-acquired.json").unlink()
        self.assert_validation_fails(self.run_validator(manifest), "does not exist")

    def test_duplicate_case_id_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][1]["id"] = document["cases"][0]["id"]
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "duplicate case ID")

    def test_invalid_case_reference_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["source_case"] = "missing-case"
        self.write_manifest(manifest, document)
        self.assert_validation_fails(
            self.run_validator(manifest), "invalid source case reference"
        )

    def test_duplicate_json_keys_fail(self):
        _, manifest = self.copied_corpus()
        text = manifest.read_text(encoding="utf-8")
        needle = '  "schema": "urn:aural:conformance:provenance-cases",\n'
        self.assertEqual(1, text.count(needle))
        manifest.write_text(text.replace(needle, needle + needle), encoding="utf-8")
        self.assert_validation_fails(
            self.run_validator(manifest), "duplicate JSON object key 'schema'"
        )

    def test_invalid_schema_or_version_fails(self):
        for field, value, message in (
            ("schema", "urn:example:wrong", "manifest.schema"),
            ("schema_version", 2, "manifest.schema_version"),
        ):
            with self.subTest(field=field):
                _, manifest = self.copied_corpus()
                document = self.load_manifest(manifest)
                document[field] = value
                self.write_manifest(manifest, document)
                self.assert_validation_fails(self.run_validator(manifest), message)

    def test_missing_required_input_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["inputs"].pop()
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "inputs do not match")

    def test_unsafe_relative_path_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["inputs"][0]["path"] = "../provenance/event.json"
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "unsafe traversal")

    def test_absolute_path_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["inputs"][0]["path"] = "C:/event.json"
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "must be relative")

    def test_symlink_escape_fails(self):
        fixture_root, manifest = self.copied_corpus()
        outside = fixture_root.parent / "outside"
        outside.mkdir()
        shutil.copy2(
            fixture_root / "provenance" / "valid-original-acquired.json",
            outside / "event.json",
        )
        link = fixture_root / "linked"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            symbolic_link = mock.Mock(st_mode=stat.S_IFLNK)
            record = validator.FixtureRecord("test-case", "linked/event.json", "0" * 64, 0)
            with mock.patch.object(Path, "lstat", return_value=symbolic_link):
                with self.assertRaisesRegex(validator.ValidationError, "symbolic link"):
                    validator._verify_fixture(fixture_root, record)
            return
        document = self.load_manifest(manifest)
        document["cases"][0]["inputs"][0]["path"] = "linked/event.json"
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "symbolic link")

    def test_invalid_expected_outcome_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["expected"]["outcome"] = "maybe"
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "invalid value 'maybe'")

    def test_incorrect_case_count_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"].pop()
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "exactly 45 cases")

    def test_incorrect_ed25519_vector_count_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["ed25519_vectors"]["records"].pop()
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "exactly 13 vectors")

    def test_incorrect_vector_reference_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["ed25519_vectors"]["records"][0]["source_record"] = "missing-vector"
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "source_record")


if __name__ == "__main__":
    unittest.main()
