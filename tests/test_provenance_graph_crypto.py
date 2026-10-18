import base64
import json
from pathlib import Path
import unittest
from unittest import mock

from aural import provenance


FIXTURES = Path(__file__).parent / 'fixtures' / 'provenance'


class ProvenanceGraphCryptographicTests(unittest.TestCase):
    def record(self, name):
        return (FIXTURES / name).read_bytes()

    def assert_error(self, category, stage, records, keys, **kwargs):
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            provenance.verify_signed_event_graph(records, keys, **kwargs)
        self.assertEqual(category, raised.exception.category)
        self.assertEqual(stage, raised.exception.stage)
        return raised.exception

    def test_one_valid_signed_root_reaches_fail_closed_boundary(self):
        self.assert_error(
            provenance.ErrorCategory.NOT_IMPLEMENTED,
            provenance.VerificationStage.GRAPH,
            [self.record('valid-original-acquired.json')],
            [self.record('valid-key.json')],
        )

    def test_multiple_valid_signed_events_reach_fail_closed_boundary(self):
        records = [
            self.record('valid-received-with-parent.json'),
            self.record('valid-unknown-optional.json'),
            self.record('valid-original-acquired.json'),
        ]
        with mock.patch.object(
                provenance, 'verify_signed_event', wraps=provenance.verify_signed_event) as verify:
            self.assert_error(
                provenance.ErrorCategory.NOT_IMPLEMENTED,
                provenance.VerificationStage.GRAPH,
                records,
                [self.record('valid-key.json')],
            )
        self.assertEqual(3, verify.call_count)

    def test_tampered_signature_fails_cryptographic_verification(self):
        self.assert_error(
            provenance.ErrorCategory.SIGNATURE,
            provenance.VerificationStage.SIGNATURE,
            [self.record('invalid-signature.json')],
            [self.record('valid-key.json')],
        )

    def test_unknown_signing_key_fails_key_resolution(self):
        self.assert_error(
            provenance.ErrorCategory.MISSING_KEY,
            provenance.VerificationStage.KEY,
            [self.record('valid-original-acquired.json')],
            [],
        )

    def test_wrong_supplied_public_key_fails_key_id_validation(self):
        wrong_key = json.loads(self.record('valid-key.json'))
        wrong_key['public_key'] = base64.urlsafe_b64encode(bytes.fromhex(
            '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'
        )).rstrip(b'=').decode('ascii')
        wrong_key_raw = provenance._jcs_text(
            wrong_key, provenance.VerificationStage.KEY,
        ).encode('utf-8')
        self.assert_error(
            provenance.ErrorCategory.KEY_ID_MISMATCH,
            provenance.VerificationStage.KEY,
            [self.record('valid-original-acquired.json')],
            [wrong_key_raw],
        )

    def test_malformed_signing_key_record_preserves_individual_error(self):
        self.assert_error(
            provenance.ErrorCategory.UNSUPPORTED_ALGORITHM,
            provenance.VerificationStage.KEY,
            [self.record('valid-original-acquired.json')],
            [self.record('key-invalid-algorithm.json')],
        )

    def test_valid_duplicate_is_verified_once_logically(self):
        record = self.record('valid-original-acquired.json')
        key = self.record('valid-key.json')
        with mock.patch.object(
                provenance, 'verify_signed_event', wraps=provenance.verify_signed_event) as verify:
            self.assert_error(
                provenance.ErrorCategory.NOT_IMPLEMENTED,
                provenance.VerificationStage.GRAPH,
                [record, record, record],
                [key],
            )
        self.assertEqual(1, verify.call_count)

    def test_mixed_valid_and_invalid_events_fail_cryptographically(self):
        self.assert_error(
            provenance.ErrorCategory.SIGNATURE,
            provenance.VerificationStage.SIGNATURE,
            [
                self.record('valid-unknown-optional.json'),
                self.record('invalid-signature.json'),
            ],
            [self.record('valid-key.json')],
        )

    def test_structural_failures_remain_graph_failures(self):
        root = self.record('valid-original-acquired.json')
        child = self.record('valid-received-with-parent.json')
        key = self.record('valid-key.json')
        self.assert_error(
            provenance.ErrorCategory.MISSING_PARENT,
            provenance.VerificationStage.GRAPH,
            [child],
            [key],
        )
        self.assert_error(
            provenance.ErrorCategory.EVENT_ID_COLLISION,
            provenance.VerificationStage.GRAPH,
            [root, self.record('invalid-signature.json')],
            [key],
        )

    def test_package_binding_remains_out_of_scope_and_success_is_fail_closed(self):
        error = self.assert_error(
            provenance.ErrorCategory.NOT_IMPLEMENTED,
            provenance.VerificationStage.GRAPH,
            [self.record('valid-original-acquired.json')],
            [self.record('valid-key.json')],
            package_path=FIXTURES / 'does-not-exist.aural',
        )
        self.assertNotEqual(
            provenance.GraphVerificationStatus.CONSISTENT,
            getattr(error, 'status', None),
        )


if __name__ == '__main__':
    unittest.main()
