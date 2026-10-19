import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

from aural import provenance
from tests._provenance_graph_helpers import signed_record


FIXTURES = Path(__file__).parent / 'fixtures' / 'provenance'
GRAPH_FIXTURES = Path(__file__).parent / 'fixtures' / 'graph_conformance'


class ProvenanceGraphCryptographicTests(unittest.TestCase):
    def record(self, name):
        return (FIXTURES / name).read_bytes()

    def padded_signature(self, raw):
        self.assertTrue(raw.endswith(b'"}'))
        return raw[:-2] + b'==' + raw[-2:]

    def assert_error(self, category, stage, records, keys, **kwargs):
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            provenance.verify_signed_event_graph(records, keys, **kwargs)
        self.assertEqual(category, raised.exception.category)
        self.assertEqual(stage, raised.exception.stage)
        return raised.exception

    def test_one_valid_signed_root_is_consistent_without_package_binding(self):
        result = provenance.verify_signed_event_graph(
            [self.record('valid-original-acquired.json')],
            [self.record('valid-key.json')],
        )
        self.assertEqual(provenance.GraphVerificationStatus.CONSISTENT, result.status)
        self.assertEqual(1, len(result.events))
        self.assertEqual(
            provenance.AssetIntegrityStatus.NOT_CHECKED,
            result.events[0].asset_integrity,
        )
        self.assertEqual(provenance.ParentClosureStatus.CLOSED,
                         result.declared_parent_closure)
        self.assertEqual(provenance.HistoryCompletenessStatus.NOT_ESTABLISHED,
                         result.history_completeness)

    def test_multiple_valid_signed_events_are_consistent(self):
        records = [
            self.record('valid-received-with-parent.json'),
            self.record('valid-unknown-optional.json'),
            self.record('valid-original-acquired.json'),
        ]
        with mock.patch.object(
                provenance, '_verify_validated_signed_event',
                wraps=provenance._verify_validated_signed_event) as verify:
            result = provenance.verify_signed_event_graph(
                records,
                [self.record('valid-key.json')],
            )
        self.assertEqual(3, verify.call_count)
        self.assertEqual(provenance.GraphVerificationStatus.CONSISTENT, result.status)
        self.assertEqual(3, len(result.events))
        self.assertEqual(2, result.maximum_depth)

    def test_graph_parses_each_bounded_record_and_key_once(self):
        records = [
            self.record('valid-received-with-parent.json'),
            self.record('valid-unknown-optional.json'),
            self.record('valid-original-acquired.json'),
        ]
        key = self.record('valid-key.json')
        with mock.patch.object(
                provenance, '_parse_validate_record',
                wraps=provenance._parse_validate_record) as parse_event, mock.patch.object(
                    provenance, '_validate_key_record',
                    wraps=provenance._validate_key_record) as parse_key, mock.patch.object(
                        provenance, '_signed_event_sha256',
                        wraps=provenance._signed_event_sha256) as hash_event:
            result = provenance.verify_signed_event_graph(records, [key])

        self.assertEqual(provenance.GraphVerificationStatus.CONSISTENT, result.status)
        self.assertEqual(len(records), parse_event.call_count)
        self.assertEqual(1, parse_key.call_count)
        self.assertEqual(len(records), hash_event.call_count)

    def test_tampered_signature_fails_cryptographic_verification(self):
        self.assert_error(
            provenance.ErrorCategory.SIGNATURE,
            provenance.VerificationStage.SIGNATURE,
            [self.record('invalid-signature.json')],
            [self.record('valid-key.json')],
        )

    def test_noncanonical_signature_text_fails_during_record_validation(self):
        self.assert_error(
            provenance.ErrorCategory.ENCODING,
            provenance.VerificationStage.RECORD,
            [self.record('invalid-padded-signature.json')],
            [self.record('valid-key.json')],
        )

    def test_noncanonical_signature_text_precedes_missing_parent(self):
        child = self.padded_signature(self.record('valid-received-with-parent.json'))
        self.assert_error(
            provenance.ErrorCategory.ENCODING,
            provenance.VerificationStage.RECORD,
            [child],
            [self.record('valid-key.json')],
        )

    def test_noncanonical_signature_text_precedes_parent_digest_mismatch(self):
        child = self.padded_signature(
            (GRAPH_FIXTURES / 'parent-digest-mismatch.json').read_bytes(),
        )
        self.assert_error(
            provenance.ErrorCategory.ENCODING,
            provenance.VerificationStage.RECORD,
            [child, self.record('valid-original-acquired.json')],
            [self.record('valid-key.json')],
        )

    def test_assertion_modification_without_resigning_fails(self):
        document = json.loads(self.record('valid-unknown-optional.json'))
        document['assertion']['claims']['source_description'] = 'attacker replacement'
        tampered = provenance._jcs_text(
            document, provenance.VerificationStage.RECORD,
        ).encode('utf-8')
        self.assert_error(
            provenance.ErrorCategory.SIGNATURE,
            provenance.VerificationStage.SIGNATURE,
            [self.record('valid-original-acquired.json'), tampered],
            [self.record('valid-key.json')],
        )

    def test_wrong_valid_public_key_cannot_be_associated_with_signature(self):
        public_key = bytes.fromhex(
            '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'
        )
        unrelated = {
            'algorithm': 'Ed25519',
            'key_id': 'urn:aural:key:ed25519:' + hashlib.sha256(
                provenance.KEY_ID_DOMAIN + public_key,
            ).hexdigest(),
            'key_schema': 'org.aural.signing-key',
            'key_schema_version': '1',
            'public_key': base64.urlsafe_b64encode(public_key).rstrip(b'=').decode('ascii'),
        }
        unrelated_raw = provenance._jcs_text(
            unrelated, provenance.VerificationStage.KEY,
        ).encode('utf-8')
        record = self.record('valid-original-acquired.json')
        self.assert_error(
            provenance.ErrorCategory.MISSING_KEY,
            provenance.VerificationStage.KEY,
            [record],
            [unrelated_raw],
        )
        result = provenance.verify_signed_event_graph(
            [record], [unrelated_raw, self.record('valid-key.json')],
        )
        self.assertEqual(provenance.GraphVerificationStatus.CONSISTENT, result.status)

    def test_duplicate_supplied_key_id_is_rejected_as_ambiguous(self):
        key = self.record('valid-key.json')
        self.assert_error(
            provenance.ErrorCategory.DUPLICATE_KEY,
            provenance.VerificationStage.KEY,
            [self.record('valid-original-acquired.json')],
            [key, key],
        )

    def test_competing_malformed_key_error_is_order_independent(self):
        records = [self.record('valid-original-acquired.json')]
        keys = [
            self.record('key-invalid-algorithm.json'),
            self.record('key-invalid-encoding.json'),
        ]
        outcomes = []
        for ordered in (keys, list(reversed(keys))):
            with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
                provenance.verify_signed_event_graph(records, ordered)
            outcomes.append((raised.exception.category, raised.exception.stage))
        self.assertEqual(outcomes[0], outcomes[1])

    def test_valid_signature_with_incorrect_parent_digest_fails_graph_resolution(self):
        parent = self.record('valid-original-acquired.json')
        child = json.loads(self.record('valid-received-with-parent.json'))['assertion']
        child = copy.deepcopy(child)
        child['parents'][0]['signed_event_digest']['value'] = '0' * 64
        signed_child = signed_record(child)

        individual = provenance.verify_signed_event(
            signed_child, [self.record('valid-key.json')],
        )
        self.assertEqual(provenance.VerificationStatus.SIGNATURE_VALID, individual.status)
        self.assert_error(
            provenance.ErrorCategory.PARENT_DIGEST_MISMATCH,
            provenance.VerificationStage.GRAPH,
            [parent, signed_child],
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
                provenance, '_verify_validated_signed_event',
                wraps=provenance._verify_validated_signed_event) as verify:
            result = provenance.verify_signed_event_graph(
                [record, record, record], [key],
            )
        self.assertEqual(1, verify.call_count)
        self.assertEqual(1, len(result.events))
        self.assertEqual(2, result.duplicate_signed_records)

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

    def test_requested_package_binding_cannot_be_silently_skipped(self):
        self.assert_error(
            provenance.ErrorCategory.PACKAGE_INTEGRITY,
            provenance.VerificationStage.PACKAGE,
            [self.record('valid-original-acquired.json')],
            [self.record('valid-key.json')],
            package_path=FIXTURES / 'does-not-exist.aural',
        )


if __name__ == '__main__':
    unittest.main()
