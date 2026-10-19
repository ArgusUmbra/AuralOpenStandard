from dataclasses import FrozenInstanceError
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from aural import provenance


FIXTURES = Path(__file__).parent / 'fixtures' / 'provenance'
VALID_EVENT = FIXTURES / 'valid-original-acquired.json'
VALID_PARENT_EVENT = FIXTURES / 'valid-received-with-parent.json'
VALID_KEY = FIXTURES / 'valid-key.json'
VALID_PACKAGE = Path(__file__).parent / 'fixtures' / 'conformance' / 'valid-unicode.aural'


class _DescriptorTracker:
    def __init__(self):
        self._open = os.open
        self._fstat = os.fstat
        self._active = set()
        self.open_count = 0
        self.maximum = 0

    def _refresh(self):
        active = set()
        for descriptor in self._active:
            try:
                self._fstat(descriptor)
            except OSError:
                continue
            active.add(descriptor)
        self._active = active

    def __call__(self, path, flags, *args, **kwargs):
        self._refresh()
        descriptor = self._open(path, flags, *args, **kwargs)
        self._active.add(descriptor)
        self.open_count += 1
        self.maximum = max(self.maximum, len(self._active))
        return descriptor

    def live_count(self):
        self._refresh()
        return len(self._active)


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
                self.assertEqual(1, reader.call_count)

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

    def test_graph_file_inputs_have_one_descriptor_peak(self):
        tracker = _DescriptorTracker()
        with mock.patch.object(provenance.os, 'open', side_effect=tracker):
            result = provenance.verify_signed_event_graph_files(
                [VALID_EVENT, VALID_PARENT_EVENT], [VALID_KEY],
            )

        self.assertEqual(provenance.GraphVerificationStatus.CONSISTENT, result.status)
        self.assertEqual(3, tracker.open_count)
        self.assertEqual(1, tracker.maximum)
        self.assertEqual(0, tracker.live_count())

    def assert_open_failure_cleanup(self, event_paths, key_paths, fail_at):
        tracker = _DescriptorTracker()
        attempts = 0
        live_before_failure = []

        def failing_open(path, flags, *args, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == fail_at:
                live_before_failure.append(tracker.live_count())
                raise OSError('synthetic open failure')
            return tracker(path, flags, *args, **kwargs)

        with mock.patch.object(provenance.os, 'open', side_effect=failing_open):
            self.assert_error(
                provenance.ErrorCategory.INPUT,
                provenance.VerificationStage.INPUT,
                lambda: provenance.verify_signed_event_graph_files(event_paths, key_paths),
            )
        self.assertEqual([0], live_before_failure)
        self.assertEqual(1, tracker.maximum)
        self.assertEqual(0, tracker.live_count())

    def test_later_event_and_key_open_failures_leave_no_descriptors(self):
        self.assert_open_failure_cleanup([VALID_EVENT, VALID_EVENT], [], 2)
        self.assert_open_failure_cleanup([VALID_EVENT], [VALID_KEY], 2)

    def test_bounded_read_failure_leaves_no_descriptors(self):
        tracker = _DescriptorTracker()
        real_file_open = open

        class FailingReadHandle:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.handle.close()

            def fileno(self):
                return self.handle.fileno()

            def readinto(self, _buffer):
                raise OSError('synthetic bounded read failure')

        def failing_file_open(*args, **kwargs):
            return FailingReadHandle(real_file_open(*args, **kwargs))

        with mock.patch.object(provenance.os, 'open', side_effect=tracker), \
                mock.patch('builtins.open', side_effect=failing_file_open):
            self.assert_error(
                provenance.ErrorCategory.INPUT,
                provenance.VerificationStage.INPUT,
                lambda: provenance.verify_signed_event_graph_files([VALID_EVENT], []),
            )
        self.assertEqual(1, tracker.maximum)
        self.assertEqual(0, tracker.live_count())

    def test_post_read_identity_failure_leaves_no_descriptors(self):
        tracker = _DescriptorTracker()
        real_fstat = os.fstat
        calls = 0

        def changed_after_read(descriptor):
            nonlocal calls
            metadata = real_fstat(descriptor)
            calls += 1
            if calls != 2:
                return metadata
            return SimpleNamespace(
                st_mode=metadata.st_mode,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns + 1,
                st_ctime_ns=metadata.st_ctime_ns,
            )

        with mock.patch.object(provenance.os, 'open', side_effect=tracker), \
                mock.patch.object(provenance.os, 'fstat', side_effect=changed_after_read):
            self.assert_error(
                provenance.ErrorCategory.INPUT,
                provenance.VerificationStage.INPUT,
                lambda: provenance.verify_signed_event_graph_files([VALID_EVENT], []),
            )
        self.assertEqual(1, tracker.maximum)
        self.assertEqual(0, tracker.live_count())

    def test_size_limit_failures_leave_no_descriptors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / 'first.json'
            second = root / 'second.json'
            first.write_bytes(b'xx')
            second.write_bytes(b'xx')

            tracker = _DescriptorTracker()
            with mock.patch.object(provenance.os, 'open', side_effect=tracker):
                self.assert_error(
                    provenance.ErrorCategory.RESOURCE_LIMIT,
                    provenance.VerificationStage.INPUT,
                    lambda: provenance.verify_signed_event_graph_files(
                        [first], [],
                        limits=provenance.GraphVerificationLimits(event_bytes=1),
                    ),
                )
            self.assertEqual(1, tracker.maximum)
            self.assertEqual(0, tracker.live_count())

            tracker = _DescriptorTracker()
            with mock.patch.object(provenance.os, 'open', side_effect=tracker):
                self.assert_error(
                    provenance.ErrorCategory.RESOURCE_LIMIT,
                    provenance.VerificationStage.INPUT,
                    lambda: provenance.verify_signed_event_graph_files(
                        [first, second], [],
                        limits=provenance.GraphVerificationLimits(
                            event_bytes=2, aggregate_event_bytes=3,
                        ),
                    ),
                )
            self.assertEqual(1, tracker.maximum)
            self.assertEqual(0, tracker.live_count())

    def test_duplicate_paths_preserve_event_and_key_behavior(self):
        result = provenance.verify_signed_event_graph_files(
            [VALID_EVENT, VALID_EVENT], [VALID_KEY],
        )
        self.assertEqual(1, result.duplicate_signed_records)
        self.assertEqual(1, len(result.events))

        self.assert_error(
            provenance.ErrorCategory.DUPLICATE_KEY,
            provenance.VerificationStage.KEY,
            lambda: provenance.verify_signed_event_graph_files(
                [VALID_EVENT], [VALID_KEY, VALID_KEY],
            ),
        )

    def test_package_verification_starts_after_graph_inputs_close(self):
        tracker = _DescriptorTracker()
        package_start_live_counts = []
        real_package_verify = provenance._verify_package_for_binding

        def checked_package_verify(path):
            package_start_live_counts.append(tracker.live_count())
            return real_package_verify(path)

        with mock.patch.object(provenance.os, 'open', side_effect=tracker), \
                mock.patch.object(
                    provenance, '_verify_package_for_binding',
                    side_effect=checked_package_verify,
                ):
            result = provenance.verify_signed_event_graph_files(
                [VALID_EVENT], [VALID_KEY], package_path=VALID_PACKAGE,
            )

        self.assertEqual([0], package_start_live_counts)
        self.assertEqual(1, tracker.maximum)
        self.assertEqual(0, tracker.live_count())
        self.assertTrue(all(
            event.asset_integrity is provenance.AssetIntegrityStatus.VERIFIED
            for event in result.events
        ))

    def test_early_read_failure_precedes_later_open_failure(self):
        tracker = _DescriptorTracker()
        attempts = 0
        early = provenance.ProvenanceVerificationError(
            provenance.ErrorCategory.INPUT,
            provenance.VerificationStage.INPUT,
            'synthetic early read failure',
        )

        def failing_second_open(path, flags, *args, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 2:
                raise OSError('synthetic later open failure')
            return tracker(path, flags, *args, **kwargs)

        with mock.patch.object(provenance.os, 'open', side_effect=failing_second_open), \
                mock.patch.object(provenance, '_read_preflighted_file', side_effect=early):
            error = self.assert_error(
                provenance.ErrorCategory.INPUT,
                provenance.VerificationStage.INPUT,
                lambda: provenance.verify_signed_event_graph_files(
                    [VALID_EVENT, VALID_EVENT], [],
                ),
            )
        self.assertEqual('synthetic early read failure', str(error))
        self.assertEqual(1, attempts)
        self.assertEqual(0, tracker.live_count())

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
                (
                    lambda: provenance.verify_signed_event_graph_files(
                        [event], [],
                        limits=provenance.GraphVerificationLimits(event_bytes=1),
                    ),
                    0,
                ),
                (
                    lambda: provenance.verify_signed_event_graph_files(
                        [event], [key],
                        limits=provenance.GraphVerificationLimits(key_record_bytes=1),
                    ),
                    1,
                ),
            )
            for operation, expected_reads in file_checks:
                with mock.patch.object(provenance, '_read_preflighted_file') as reader:
                    self.assert_error(
                        provenance.ErrorCategory.RESOURCE_LIMIT,
                        provenance.VerificationStage.INPUT,
                        operation,
                    )
                    self.assertEqual(expected_reads, reader.call_count)

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
