from pathlib import Path
import unittest
from unittest import mock

from aural import provenance


ROOT = Path(__file__).resolve().parents[1]
PROVENANCE = ROOT / 'tests' / 'fixtures' / 'provenance'
PACKAGES = ROOT / 'tests' / 'fixtures' / 'conformance'
VALID_PACKAGE = PACKAGES / 'valid-unicode.aural'


class ProvenanceGraphBindingTests(unittest.TestCase):
    def record(self, name):
        return (PROVENANCE / name).read_bytes()

    def assert_package_error(self, category, operation):
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            operation()
        self.assertEqual(category, raised.exception.category)
        self.assertEqual(provenance.VerificationStage.PACKAGE,
                         raised.exception.stage)

    def test_matching_package_is_verified_once_and_bound_to_every_event(self):
        records = [
            self.record('valid-received-with-parent.json'),
            self.record('valid-unknown-optional.json'),
            self.record('valid-original-acquired.json'),
        ]
        key = self.record('valid-key.json')
        with mock.patch.object(
                provenance.core, 'verify_detailed',
                wraps=provenance.core.verify_detailed) as package_verify, mock.patch.object(
                    provenance, '_validate_package_binding',
                    wraps=provenance._validate_package_binding) as bind:
            result = provenance.verify_signed_event_graph(
                records, [key], package_path=VALID_PACKAGE,
            )

        self.assertEqual(1, package_verify.call_count)
        self.assertEqual(3, bind.call_count)
        self.assertEqual(provenance.GraphVerificationStatus.CONSISTENT, result.status)
        self.assertTrue(all(
            event.asset_integrity is provenance.AssetIntegrityStatus.VERIFIED
            for event in result.events
        ))

    def test_disconnected_signed_graph_is_consistent_and_deterministic(self):
        records = [
            self.record('valid-unknown-optional.json'),
            self.record('valid-original-acquired.json'),
        ]
        key = self.record('valid-key.json')
        forward = provenance.verify_signed_event_graph(records, [key])
        reverse = provenance.verify_signed_event_graph(list(reversed(records)), [key])
        self.assertEqual(forward, reverse)
        self.assertEqual(2, len(forward.events))
        self.assertEqual(1, forward.maximum_depth)

    def test_bound_byte_and_file_apis_are_equivalent(self):
        event_names = [
            'valid-received-with-parent.json',
            'valid-original-acquired.json',
        ]
        event_paths = [PROVENANCE / name for name in event_names]
        key_path = PROVENANCE / 'valid-key.json'
        byte_result = provenance.verify_signed_event_graph(
            [path.read_bytes() for path in event_paths],
            [key_path.read_bytes()],
            package_path=VALID_PACKAGE,
        )
        file_result = provenance.verify_signed_event_graph_files(
            event_paths, [key_path], package_path=VALID_PACKAGE,
        )
        self.assertEqual(byte_result, file_result)

    def test_corrupt_and_malformed_packages_fail_integrity(self):
        record = self.record('valid-original-acquired.json')
        key = self.record('valid-key.json')
        for package in (
                PACKAGES / 'invalid-altered-original.aural',
                PACKAGES / 'invalid-malformed-json.aural'):
            with self.subTest(package=package.name):
                self.assert_package_error(
                    provenance.ErrorCategory.PACKAGE_INTEGRITY,
                    lambda package=package: provenance.verify_signed_event_graph(
                        [record], [key], package_path=package,
                    ),
                )

    def test_valid_package_with_wrong_subject_fails_binding(self):
        self.assert_package_error(
            provenance.ErrorCategory.SUBJECT_BINDING,
            lambda: provenance.verify_signed_event_graph(
                [self.record('valid-original-acquired.json')],
                [self.record('valid-key.json')],
                package_path=PACKAGES / 'valid-minimal.aural',
            ),
        )

    def test_signed_subject_mismatch_fails_after_independent_verification(self):
        with mock.patch.object(
                provenance.core, 'verify_detailed',
                wraps=provenance.core.verify_detailed) as package_verify:
            self.assert_package_error(
                provenance.ErrorCategory.SUBJECT_BINDING,
                lambda: provenance.verify_signed_event_graph(
                    [self.record('invalid-subject-original.json')],
                    [self.record('valid-key.json')],
                    package_path=VALID_PACKAGE,
                ),
            )
        self.assertEqual(1, package_verify.call_count)


if __name__ == '__main__':
    unittest.main()
