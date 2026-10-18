from dataclasses import FrozenInstanceError
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from aural import provenance


class ProvenanceGraphFoundationTests(unittest.TestCase):
    def assert_error(self, category, stage, operation):
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            operation()
        self.assertEqual(category, raised.exception.category)
        self.assertEqual(stage, raised.exception.stage)
        return raised.exception

    def test_default_limits_and_result_types_are_immutable(self):
        limits = provenance.GraphVerificationLimits()
        self.assertEqual(4096, limits.event_records)
        self.assertEqual(64 * 1024 * 1024, limits.aggregate_event_bytes)
        self.assertEqual(1024 * 1024, limits.event_bytes)
        self.assertEqual(64, limits.parent_fanout)
        self.assertEqual(256, limits.graph_depth)
        self.assertEqual(64, limits.key_records)
        self.assertEqual(16 * 1024, limits.key_record_bytes)
        self.assertEqual(256 * 1024, limits.aggregate_key_bytes)
        self.assertEqual('consistent', provenance.GraphVerificationStatus.CONSISTENT.value)
        self.assertEqual('closed', provenance.ParentClosureStatus.CLOSED.value)
        self.assertEqual('graph', provenance.VerificationStage.GRAPH.value)
        graph_categories = {
            provenance.ErrorCategory.EVENT_ID_COLLISION,
            provenance.ErrorCategory.SIGNED_EVENT_DIGEST_COLLISION,
            provenance.ErrorCategory.MISSING_PARENT,
            provenance.ErrorCategory.PARENT_DIGEST_MISMATCH,
            provenance.ErrorCategory.CYCLE,
        }
        self.assertEqual(5, len(graph_categories))
        with self.assertRaises(FrozenInstanceError):
            limits.event_records = 1

        result = provenance.GraphVerificationResult(
            status=provenance.GraphVerificationStatus.CONSISTENT,
            events=(),
            duplicate_signed_records=0,
            maximum_depth=1,
            declared_parent_closure=provenance.ParentClosureStatus.CLOSED,
            history_completeness=provenance.HistoryCompletenessStatus.NOT_ESTABLISHED,
        )
        with self.assertRaises(FrozenInstanceError):
            result.maximum_depth = 2

    def test_invalid_limit_configurations_are_controlled(self):
        invalid = [
            {'event_records': 0},
            {'event_records': provenance.MAX_GRAPH_EVENT_RECORDS + 1},
            {'aggregate_event_bytes': 0},
            {
                'aggregate_event_bytes':
                    provenance.MAX_AGGREGATE_GRAPH_EVENT_BYTES + 1,
            },
            {'parent_fanout': -1},
            {'parent_fanout': provenance.MAX_GRAPH_PARENT_REFERENCES + 1},
            {'graph_depth': 0},
            {'graph_depth': provenance.MAX_GRAPH_DEPTH + 1},
            {'event_records': True},
            {'event_bytes': provenance.MAX_EVENT_BYTES + 1},
        ]
        for values in invalid:
            with self.subTest(values=values):
                self.assert_error(
                    provenance.ErrorCategory.CONFIGURATION,
                    provenance.VerificationStage.INPUT,
                    lambda values=values: provenance.GraphVerificationLimits(**values),
                )

        self.assert_error(
            provenance.ErrorCategory.CONFIGURATION,
            provenance.VerificationStage.INPUT,
            lambda: provenance.verify_signed_event_graph(
                [b'x'], [], limits=provenance.VerificationLimits(),
            ),
        )

    def test_empty_event_collection_is_rejected(self):
        for operation in (
                lambda: provenance.verify_signed_event_graph([], []),
                lambda: provenance.verify_signed_event_graph_files([], [])):
            self.assert_error(
                provenance.ErrorCategory.INPUT,
                provenance.VerificationStage.INPUT,
                operation,
            )

    def test_excessive_event_counts_are_rejected_before_processing(self):
        records = [b'x'] * (provenance.MAX_GRAPH_EVENT_RECORDS + 1)
        self.assert_error(
            provenance.ErrorCategory.RESOURCE_LIMIT,
            provenance.VerificationStage.INPUT,
            lambda: provenance.verify_signed_event_graph(records, []),
        )
        with mock.patch.object(provenance.os, 'open') as opened:
            self.assert_error(
                provenance.ErrorCategory.RESOURCE_LIMIT,
                provenance.VerificationStage.INPUT,
                lambda: provenance.verify_signed_event_graph_files(records, []),
            )
            opened.assert_not_called()

    def test_excessive_aggregate_event_bytes_are_rejected(self):
        limits = provenance.GraphVerificationLimits(aggregate_event_bytes=1)
        self.assert_error(
            provenance.ErrorCategory.RESOURCE_LIMIT,
            provenance.VerificationStage.INPUT,
            lambda: provenance.verify_signed_event_graph([b'x', b'x'], [], limits=limits),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / 'first.json'
            second = root / 'second.json'
            first.write_bytes(b'x')
            second.write_bytes(b'x')
            with mock.patch.object(provenance, '_read_preflighted_file') as reader:
                self.assert_error(
                    provenance.ErrorCategory.RESOURCE_LIMIT,
                    provenance.VerificationStage.INPUT,
                    lambda: provenance.verify_signed_event_graph_files(
                        [first, second], [], limits=limits,
                    ),
                )
                reader.assert_not_called()

    def test_invalid_record_types_are_controlled(self):
        operations = (
            lambda: provenance.verify_signed_event_graph(b'x', []),
            lambda: provenance.verify_signed_event_graph([bytearray(b'x')], []),
            lambda: provenance.verify_signed_event_graph([b'x'], b'key'),
            lambda: provenance.verify_signed_event_graph([b'x'], [bytearray(b'key')]),
        )
        for operation in operations:
            self.assert_error(
                provenance.ErrorCategory.INPUT,
                provenance.VerificationStage.INPUT,
                operation,
            )

    def test_file_path_input_type_errors_are_controlled(self):
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / 'event.json'
            event.write_bytes(b'x')
            operations = (
                lambda: provenance.verify_signed_event_graph_files(str(event), []),
                lambda: provenance.verify_signed_event_graph_files([object()], []),
                lambda: provenance.verify_signed_event_graph_files([event], 'key.json'),
            )
            for operation in operations:
                self.assert_error(
                    provenance.ErrorCategory.INPUT,
                    provenance.VerificationStage.INPUT,
                    operation,
                )

    def test_missing_files_are_controlled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = root / 'event.json'
            event.write_bytes(b'x')
            for operation in (
                    lambda: provenance.verify_signed_event_graph_files(
                        [root / 'missing-event.json'], [],
                    ),
                    lambda: provenance.verify_signed_event_graph_files(
                        [event], [root / 'missing-key.json'],
                    )):
                self.assert_error(
                    provenance.ErrorCategory.INPUT,
                    provenance.VerificationStage.INPUT,
                    operation,
                )

    def test_existing_event_and_key_resource_limits_are_preserved(self):
        checks = (
            lambda: provenance.verify_signed_event_graph(
                [b'xx'], [], limits=provenance.GraphVerificationLimits(event_bytes=1),
            ),
            lambda: provenance.verify_signed_event_graph(
                [b'x'], [b'xx'],
                limits=provenance.GraphVerificationLimits(key_record_bytes=1),
            ),
            lambda: provenance.verify_signed_event_graph(
                [b'x'], [b'x'],
                limits=provenance.GraphVerificationLimits(key_records=0),
            ),
            lambda: provenance.verify_signed_event_graph(
                [b'x'], [b'xx', b'xx'],
                limits=provenance.GraphVerificationLimits(
                    key_record_bytes=2, aggregate_key_bytes=3,
                ),
            ),
        )
        for operation in checks:
            self.assert_error(
                provenance.ErrorCategory.RESOURCE_LIMIT,
                provenance.VerificationStage.INPUT,
                operation,
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = root / 'event.json'
            key = root / 'key.json'
            event.write_bytes(b'xx')
            key.write_bytes(b'xx')
            file_checks = (
                lambda: provenance.verify_signed_event_graph_files(
                    [event], [],
                    limits=provenance.GraphVerificationLimits(event_bytes=1),
                ),
                lambda: provenance.verify_signed_event_graph_files(
                    [event], [key],
                    limits=provenance.GraphVerificationLimits(key_record_bytes=1),
                ),
            )
            for operation in file_checks:
                with mock.patch.object(provenance, '_read_preflighted_file') as reader:
                    self.assert_error(
                        provenance.ErrorCategory.RESOURCE_LIMIT,
                        provenance.VerificationStage.INPUT,
                        operation,
                    )
                    reader.assert_not_called()

    def test_byte_and_file_graph_apis_return_equivalent_success(self):
        fixtures = Path(__file__).parent / 'fixtures' / 'provenance'
        record = (fixtures / 'valid-original-acquired.json').read_bytes()
        key = (fixtures / 'valid-key.json').read_bytes()
        byte_result = provenance.verify_signed_event_graph([record], [key])
        self.assertEqual(provenance.GraphVerificationStatus.CONSISTENT,
                         byte_result.status)

        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / 'event.json'
            key_path = Path(temporary) / 'key.json'
            event.write_bytes(record)
            key_path.write_bytes(key)
            file_result = provenance.verify_signed_event_graph_files(
                [event], [key_path],
            )
        self.assertEqual(byte_result, file_result)

    def test_byte_and_file_graph_apis_report_equivalent_missing_parent(self):
        fixtures = Path(__file__).parent / 'fixtures' / 'provenance'
        event_path = fixtures / 'valid-received-with-parent.json'
        key_path = fixtures / 'valid-key.json'
        byte_error = self.assert_error(
            provenance.ErrorCategory.MISSING_PARENT,
            provenance.VerificationStage.GRAPH,
            lambda: provenance.verify_signed_event_graph(
                [event_path.read_bytes()], [key_path.read_bytes()],
            ),
        )
        file_error = self.assert_error(
            provenance.ErrorCategory.MISSING_PARENT,
            provenance.VerificationStage.GRAPH,
            lambda: provenance.verify_signed_event_graph_files(
                [event_path], [key_path],
            ),
        )
        self.assertEqual(
            (byte_error.category, byte_error.stage),
            (file_error.category, file_error.stage),
        )

    def test_byte_and_file_graph_apis_report_equivalent_parent_digest_mismatch(self):
        fixtures = Path(__file__).parent / 'fixtures' / 'provenance'
        event_paths = [
            fixtures / 'valid-received-with-parent.json',
            fixtures / 'invalid-signature.json',
        ]
        key_path = fixtures / 'valid-key.json'
        byte_error = self.assert_error(
            provenance.ErrorCategory.PARENT_DIGEST_MISMATCH,
            provenance.VerificationStage.GRAPH,
            lambda: provenance.verify_signed_event_graph(
                [path.read_bytes() for path in event_paths],
                [key_path.read_bytes()],
            ),
        )
        file_error = self.assert_error(
            provenance.ErrorCategory.PARENT_DIGEST_MISMATCH,
            provenance.VerificationStage.GRAPH,
            lambda: provenance.verify_signed_event_graph_files(
                event_paths, [key_path],
            ),
        )
        self.assertEqual(
            (byte_error.category, byte_error.stage),
            (file_error.category, file_error.stage),
        )


if __name__ == '__main__':
    unittest.main()
