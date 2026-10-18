from pathlib import Path
import unittest
from unittest import mock

from aural import provenance


FIXTURES = Path(__file__).parent / 'fixtures' / 'provenance'


class ProvenanceGraphIndexTests(unittest.TestCase):
    def record(self, name):
        return (FIXTURES / name).read_bytes()

    def assert_error(self, category, stage, operation):
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            operation()
        self.assertEqual(category, raised.exception.category)
        self.assertEqual(stage, raised.exception.stage)

    def test_one_valid_record(self):
        record = self.record('valid-original-acquired.json')
        index = provenance._index_signed_event_records([record])
        event_id = 'urn:uuid:11111111-2222-4333-8444-555555555555'
        self.assertEqual([event_id], list(index.by_event_id))
        self.assertEqual(record, index.by_event_id[event_id].record)
        self.assertEqual(
            'e01de77607deebd20886b063a8573ce0ced436081df57e734c11ea21c6f9870e',
            index.by_event_id[event_id].signed_event_sha256,
        )
        self.assertEqual(0, index.duplicate_signed_records)

    def test_identical_duplicate_record(self):
        record = self.record('valid-original-acquired.json')
        index = provenance._index_signed_event_records([record, record])
        self.assertEqual(1, len(index.by_event_id))
        self.assertEqual(1, index.duplicate_signed_records)

    def test_same_event_id_with_different_signed_bytes(self):
        records = [
            self.record('valid-original-acquired.json'),
            self.record('invalid-signature.json'),
        ]
        self.assert_error(
            provenance.ErrorCategory.EVENT_ID_COLLISION,
            provenance.VerificationStage.GRAPH,
            lambda: provenance.verify_signed_event_graph(records, []),
        )

    def test_digest_collision_defensive_path(self):
        records = [
            self.record('valid-original-acquired.json'),
            self.record('valid-unknown-optional.json'),
        ]
        with mock.patch.object(
                provenance, '_signed_event_sha256', return_value='0' * 64):
            self.assert_error(
                provenance.ErrorCategory.SIGNED_EVENT_DIGEST_COLLISION,
                provenance.VerificationStage.GRAPH,
                lambda: provenance._index_signed_event_records(records),
            )

    def test_input_order_independence(self):
        records = [
            self.record('valid-original-acquired.json'),
            self.record('valid-unknown-optional.json'),
            self.record('valid-received-with-parent.json'),
        ]
        forward = provenance._index_signed_event_records(records)
        reverse = provenance._index_signed_event_records(list(reversed(records)))
        self.assertEqual(forward, reverse)
        self.assertEqual(sorted(forward.by_event_id), list(forward.by_event_id))

    def test_malformed_record_rejection(self):
        record = self.record('invalid-noncanonical.json')
        self.assert_error(
            provenance.ErrorCategory.CANONICALIZATION,
            provenance.VerificationStage.RECORD,
            lambda: provenance.verify_signed_event_graph([record], []),
        )

    def test_malformed_record_among_valid_records_is_not_excluded(self):
        valid = self.record('valid-original-acquired.json')
        malformed = self.record('invalid-noncanonical.json')
        for records in ([valid, malformed], [malformed, valid]):
            with self.subTest(records=records):
                self.assert_error(
                    provenance.ErrorCategory.CANONICALIZATION,
                    provenance.VerificationStage.RECORD,
                    lambda records=records: provenance.verify_signed_event_graph(
                        records, [self.record('valid-key.json')],
                    ),
                )

    def test_competing_malformed_record_error_is_order_independent(self):
        records = [
            self.record('invalid-noncanonical.json'),
            self.record('invalid-bom.json'),
        ]
        outcomes = []
        for ordered in (records, list(reversed(records))):
            with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
                provenance.verify_signed_event_graph(ordered, [])
            outcomes.append((raised.exception.category, raised.exception.stage))
        self.assertEqual(outcomes[0], outcomes[1])


if __name__ == '__main__':
    unittest.main()
