import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import validate_core_conformance_manifest as validator


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "validate_core_conformance_manifest.py"
SOURCE_FIXTURES = ROOT / "tests" / "fixtures" / "conformance"
MANIFEST_NAME = "core-reader-0.2-cases.v1.json"


class CoreConformanceManifestValidatorTests(unittest.TestCase):
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
        destination = Path(temporary.name) / "conformance"
        shutil.copytree(SOURCE_FIXTURES, destination)
        return destination, destination / MANIFEST_NAME

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

    def test_valid_committed_manifest_passes(self):
        completed = self.run_validator()
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("validated 32 cases and 32 fixtures", completed.stdout)
        self.assertIn("all sizes and SHA-256 digests match", completed.stdout)

    def test_modified_fixture_bytes_fail(self):
        corpus, manifest = self.copied_corpus()
        fixture = corpus / "valid-minimal.aural"
        payload = bytearray(fixture.read_bytes())
        payload[len(payload) // 2] ^= 1
        fixture.write_bytes(payload)
        self.assert_validation_fails(
            self.run_validator(manifest), "SHA-256 mismatch"
        )

    def test_incorrect_declared_sha256_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["input"]["sha256"] = "0" * 64
        self.write_manifest(manifest, document)
        self.assert_validation_fails(
            self.run_validator(manifest), "SHA-256 mismatch"
        )

    def test_incorrect_declared_size_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["input"]["size"] += 1
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "size mismatch")

    def test_duplicate_case_id_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][1]["id"] = document["cases"][0]["id"]
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "duplicate case ID")

    def test_missing_required_metadata_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        del document["cases"][0]["expected"]
        self.write_manifest(manifest, document)
        self.assert_validation_fails(
            self.run_validator(manifest), "missing required field 'expected'"
        )

    def test_path_traversal_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["input"]["path"] = "../invalid-altered-original.aural"
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "unsafe traversal")

    def test_absolute_path_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["input"]["path"] = (
            "C:/invalid-altered-original.aural"
        )
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "must be relative")

    def test_missing_fixture_fails(self):
        corpus, manifest = self.copied_corpus()
        (corpus / "invalid-altered-original.aural").unlink()
        self.assert_validation_fails(self.run_validator(manifest), "does not exist")

    def test_symlink_escape_fails(self):
        corpus, manifest = self.copied_corpus()
        outside = corpus.parent / "outside"
        outside.mkdir()
        shutil.copy2(
            corpus / "invalid-altered-original.aural",
            outside / "invalid-altered-original.aural",
        )
        link = corpus / "linked"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            record = validator.FixtureRecord(
                "test-case",
                "linked/invalid-altered-original.aural",
                "0" * 64,
                0,
            )
            symbolic_link = mock.Mock(st_mode=stat.S_IFLNK)
            with mock.patch.object(Path, "lstat", return_value=symbolic_link):
                with self.assertRaisesRegex(validator.ValidationError, "symbolic link"):
                    validator._safe_fixture_path(corpus, record)
            return
        document = self.load_manifest(manifest)
        document["cases"][0]["input"]["path"] = (
            "linked/invalid-altered-original.aural"
        )
        self.write_manifest(manifest, document)
        self.assert_validation_fails(self.run_validator(manifest), "symbolic link")

    def test_duplicate_json_object_keys_fail(self):
        _, manifest = self.copied_corpus()
        text = manifest.read_text(encoding="utf-8")
        needle = '  "schema": "urn:aural:conformance:core-reader-cases",\n'
        self.assertEqual(1, text.count(needle))
        manifest.write_text(text.replace(needle, needle + needle), encoding="utf-8")
        self.assert_validation_fails(
            self.run_validator(manifest), "duplicate JSON object key 'schema'"
        )

    def test_invalid_case_count_fails(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"].pop()
        self.write_manifest(manifest, document)
        self.assert_validation_fails(
            self.run_validator(manifest), "must contain exactly 32 cases"
        )

    def test_informative_reason_is_not_a_diagnostic_code(self):
        _, manifest = self.copied_corpus()
        document = self.load_manifest(manifest)
        document["cases"][0]["informative_reason"] = "Free-form explanation."
        self.write_manifest(manifest, document)
        completed = self.run_validator(manifest)
        self.assertEqual(0, completed.returncode, completed.stderr)


if __name__ == "__main__":
    unittest.main()
