import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

from aural import core, provenance


ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_CORPUS = ROOT / 'tests' / 'fixtures' / 'provenance'
PACKAGE_CORPUS = ROOT / 'tests' / 'fixtures' / 'conformance'
VALID_PACKAGE = PACKAGE_CORPUS / 'valid-unicode.aural'


class ProvenanceBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads(
            (PROVENANCE_CORPUS / 'expected.json').read_text(encoding='utf-8'),
        )
        cls.key_path = PROVENANCE_CORPUS / 'valid-key.json'
        cls.key_raw = cls.key_path.read_bytes()

    def verify_event(self, event_name, package_path=VALID_PACKAGE):
        return provenance.verify_signed_event(
            (PROVENANCE_CORPUS / event_name).read_bytes(), [self.key_raw],
            package_path=package_path,
        )

    def assert_package_error(self, category, operation):
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            operation()
        self.assertEqual(category, raised.exception.category)
        self.assertEqual(provenance.VerificationStage.PACKAGE, raised.exception.stage)

    def test_all_three_valid_vectors_bind_to_verified_package(self):
        positive = [case for case in self.expected['cases'].values()
                    if case['outcome'] == 'accept']
        self.assertEqual(3, len(positive))
        for case in positive:
            with self.subTest(event=case['event']):
                result = self.verify_event(case['event'])
                self.assertEqual(provenance.VerificationStatus.SIGNATURE_VALID, result.status)
                self.assertEqual(provenance.AssetIntegrityStatus.VERIFIED,
                                 result.asset_integrity)
                self.assertEqual(case['signed_event_digest'], result.signed_event_sha256)

    def test_complete_provenance_corpus_matches_expected_package_outcomes(self):
        compared = 0
        for name, case in self.expected['cases'].items():
            event = PROVENANCE_CORPUS / case['event']
            keys = [PROVENANCE_CORPUS / key for key in case['keys']]
            package_path = PROVENANCE_CORPUS / case['package']
            with self.subTest(case=name):
                try:
                    result = provenance.verify_signed_event_files(
                        event, keys, package_path=package_path,
                    )
                    actual = 'accept'
                    self.assertEqual(provenance.AssetIntegrityStatus.VERIFIED,
                                     result.asset_integrity)
                except provenance.ProvenanceVerificationError as exc:
                    actual = exc.category.value
                expected = ('accept' if case['outcome'] == 'accept'
                            else case['error_category'])
                self.assertEqual(expected, actual)
            compared += 1
        self.assertEqual(45, compared)

    def test_manifest_substitution_is_subject_binding_failure(self):
        self.assert_package_error(
            provenance.ErrorCategory.SUBJECT_BINDING,
            lambda: self.verify_event(
                'valid-original-acquired.json', PACKAGE_CORPUS / 'valid-minimal.aural',
            ),
        )

    def test_original_wav_substitution_is_subject_binding_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'substituted.wav'
            with zipfile.ZipFile(VALID_PACKAGE) as archive:
                audio = bytearray(archive.read('audio/original.wav'))
            audio[-1] ^= 1
            source.write_bytes(audio)
            substituted = root / 'substituted.aural'
            core.package(source, substituted)
            self.assertEqual('integrity_valid', core.verify(substituted)['status'])
            self.assert_package_error(
                provenance.ErrorCategory.SUBJECT_BINDING,
                lambda: self.verify_event('valid-original-acquired.json', substituted),
            )

    def test_path_and_length_mismatches_are_subject_binding_failures(self):
        verified = core.verify_detailed(VALID_PACKAGE)
        wrong_path = dict(verified, original_path='audio/substituted.wav')
        with mock.patch.object(provenance.core, 'verify_detailed', return_value=wrong_path):
            self.assert_package_error(
                provenance.ErrorCategory.SUBJECT_BINDING,
                lambda: self.verify_event('valid-original-acquired.json'),
            )

        self.assert_package_error(
            provenance.ErrorCategory.SUBJECT_BINDING,
            lambda: self.verify_event('invalid-subject-length.json'),
        )

    def test_invalid_truncated_and_missing_packages_fail_integrity(self):
        self.assert_package_error(
            provenance.ErrorCategory.PACKAGE_INTEGRITY,
            lambda: self.verify_event(
                'valid-original-acquired.json', PACKAGE_CORPUS / 'invalid-extra-field.aural',
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            truncated = root / 'truncated.aural'
            payload = VALID_PACKAGE.read_bytes()
            truncated.write_bytes(payload[:len(payload) // 2])
            for path in (truncated, root / 'missing.aural'):
                with self.subTest(package=path.name):
                    self.assert_package_error(
                        provenance.ErrorCategory.PACKAGE_INTEGRITY,
                        lambda path=path: self.verify_event(
                            'valid-original-acquired.json', path,
                        ),
                    )

    def test_signature_failure_precedes_package_verification(self):
        with mock.patch.object(
                provenance.core, 'verify_detailed',
                side_effect=AssertionError('package verification must not run')) as detailed:
            with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
                self.verify_event('invalid-signature.json')
        self.assertEqual(provenance.ErrorCategory.SIGNATURE, raised.exception.category)
        self.assertEqual(provenance.VerificationStage.SIGNATURE, raised.exception.stage)
        detailed.assert_not_called()

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_python_and_node_agree_on_bound_status_and_digest(self):
        positive = [case for case in self.expected['cases'].values()
                    if case['outcome'] == 'accept']
        python_results = []
        for case in positive:
            result = provenance.verify_signed_event_files(
                PROVENANCE_CORPUS / case['event'], [self.key_path],
                package_path=VALID_PACKAGE,
            )
            python_results.append({
                'status': result.status.value,
                'signed_event_sha256': result.signed_event_sha256,
                'asset_integrity': result.asset_integrity.value,
            })

        validator_uri = (ROOT / 'interop' / 'validate_provenance.mjs').as_uri()
        cases = [str(PROVENANCE_CORPUS / case['event']) for case in positive]
        script = (
            "import {verifySignedEventFiles} from " + json.dumps(validator_uri) + ";"
            "const results=[];"
            "for(const event of " + json.dumps(cases) + "){"
            "const result=await verifySignedEventFiles(event,["
            + json.dumps(str(self.key_path)) + "]," + json.dumps(str(VALID_PACKAGE)) + ");"
            "results.push({status:result.status,signed_event_sha256:result.signed_event_sha256,"
            "asset_integrity:result.asset_integrity});}console.log(JSON.stringify(results));"
        )
        completed = subprocess.run(
            ['node', '--input-type=module', '--eval', script],
            capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(python_results, json.loads(completed.stdout))

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_python_and_node_categorize_invalid_package_integrity(self):
        invalid_package = PACKAGE_CORPUS / 'invalid-extra-field.aural'
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            self.verify_event('valid-original-acquired.json', invalid_package)
        self.assertEqual(provenance.ErrorCategory.PACKAGE_INTEGRITY,
                         raised.exception.category)

        validator_uri = (ROOT / 'interop' / 'validate_provenance.mjs').as_uri()
        event_path = PROVENANCE_CORPUS / 'valid-original-acquired.json'
        script = (
            "import {verifySignedEventFiles} from " + json.dumps(validator_uri) + ";"
            "try{await verifySignedEventFiles(" + json.dumps(str(event_path)) + ",["
            + json.dumps(str(self.key_path)) + "]," + json.dumps(str(invalid_package)) + ");}"
            "catch(error){console.log(JSON.stringify({category:error.category,message:error.message}));}"
        )
        completed = subprocess.run(
            ['node', '--input-type=module', '--eval', script],
            capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        node_error = json.loads(completed.stdout)
        self.assertEqual('package_integrity', node_error['category'])
        self.assertIn('central profile', node_error['message'])


if __name__ == '__main__':
    unittest.main()
