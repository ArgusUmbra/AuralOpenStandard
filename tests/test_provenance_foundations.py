from contextlib import ExitStack
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from aural import provenance


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'fixtures' / 'provenance'


class _ReadHandle:
    def __init__(self, payload=b'', *, truncate=False):
        self.payload = payload
        self.offset = 0
        self.truncate = truncate
        self.requests = []

    def readinto(self, target):
        self.requests.append(len(target))
        if self.truncate:
            return 0
        count = min(len(target), len(self.payload) - self.offset)
        target[:count] = self.payload[self.offset:self.offset + count]
        self.offset += count
        return count

    def fileno(self):
        return 123


def _stat(size, *, modified=1):
    return SimpleNamespace(
        st_dev=1,
        st_ino=2,
        st_size=size,
        st_mtime_ns=modified,
        st_ctime_ns=1,
    )


class ProvenanceFoundationTests(unittest.TestCase):
    def assert_error(self, category, operation):
        with self.assertRaises(provenance.ProvenanceVerificationError) as raised:
            operation()
        self.assertEqual(category, raised.exception.category)
        return raised.exception

    def test_limits_are_normative_by_default_and_immutable(self):
        limits = provenance.VerificationLimits()
        self.assertEqual(1024 * 1024, limits.event_bytes)
        self.assertEqual(16 * 1024, limits.key_record_bytes)
        self.assertEqual(64, limits.key_records)
        self.assertEqual(256 * 1024, limits.aggregate_key_bytes)
        with self.assertRaises(FrozenInstanceError):
            limits.event_bytes = 1

    def test_limits_may_tighten_but_cannot_relax_profile(self):
        tightened = provenance.VerificationLimits(
            event_bytes=1,
            key_record_bytes=1,
            key_records=0,
            aggregate_key_bytes=0,
        )
        self.assertEqual(1, tightened.event_bytes)
        invalid = [
            {'event_bytes': provenance.MAX_EVENT_BYTES + 1},
            {'key_record_bytes': provenance.MAX_KEY_RECORD_BYTES + 1},
            {'key_records': provenance.MAX_KEY_RECORDS + 1},
            {'aggregate_key_bytes': provenance.MAX_AGGREGATE_KEY_BYTES + 1},
            {'event_bytes': True},
        ]
        for values in invalid:
            with self.subTest(values=values):
                error = self.assert_error(
                    provenance.ErrorCategory.CONFIGURATION,
                    lambda values=values: provenance.VerificationLimits(**values),
                )
                self.assertEqual(provenance.VerificationStage.INPUT, error.stage)

    def test_result_type_is_immutable(self):
        result = provenance.VerificationResult(
            status=provenance.VerificationStatus.SIGNATURE_VALID,
            event_id='event',
            evidence_id='evidence',
            signing_key_id='key',
            signed_event_sha256='00' * 32,
            asset_integrity=provenance.AssetIntegrityStatus.NOT_CHECKED,
            investigator_identity=provenance.InvestigatorIdentityStatus.NOT_ESTABLISHED,
            key_trust=provenance.KeyTrustStatus.NOT_EVALUATED,
            time_assurance=provenance.TimeAssuranceStatus.UNKNOWN,
            history_completeness=provenance.HistoryCompletenessStatus.NOT_ESTABLISHED,
            declared_parent_count=0,
        )
        with self.assertRaises(FrozenInstanceError):
            result.status = provenance.VerificationStatus.SIGNATURE_VALID

    def test_bytes_interface_enforces_every_resource_limit(self):
        checks = [
            (
                lambda: provenance.verify_signed_event(
                    b'xx', [], limits=provenance.VerificationLimits(event_bytes=1),
                ),
                'event bytes',
            ),
            (
                lambda: provenance.verify_signed_event(
                    b'x', [b'xx'],
                    limits=provenance.VerificationLimits(key_record_bytes=1),
                ),
                'key bytes',
            ),
            (
                lambda: provenance.verify_signed_event(
                    b'x', [b'x'], limits=provenance.VerificationLimits(key_records=0),
                ),
                'key count',
            ),
            (
                lambda: provenance.verify_signed_event(
                    b'x', [b'xx', b'xx'],
                    limits=provenance.VerificationLimits(
                        key_record_bytes=2, aggregate_key_bytes=3,
                    ),
                ),
                'aggregate key bytes',
            ),
        ]
        for operation, label in checks:
            with self.subTest(limit=label):
                self.assert_error(provenance.ErrorCategory.RESOURCE_LIMIT, operation)

    def test_interfaces_return_signature_results_and_missing_package_fails_closed(self):
        event = CORPUS / 'valid-original-acquired.json'
        key = CORPUS / 'valid-key.json'
        direct = provenance.verify_signed_event(event.read_bytes(), [key.read_bytes()])
        files = provenance.verify_signed_event_files(event, [key])
        self.assertEqual(provenance.VerificationStatus.SIGNATURE_VALID, direct.status)
        self.assertEqual(direct, files)

        for operation in (
                lambda: provenance.verify_signed_event(
                    event.read_bytes(), [key.read_bytes()], package_path='missing.aural',
                ),
                lambda: provenance.verify_signed_event_files(
                    event, [key], package_path='missing.aural',
                )):
            error = self.assert_error(provenance.ErrorCategory.PACKAGE_INTEGRITY, operation)
            self.assertEqual(provenance.VerificationStage.PACKAGE, error.stage)

    def test_oversized_files_are_rejected_before_bulk_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = root / 'event.json'
            key = root / 'key.json'
            event.write_bytes(b'xx')
            key.write_bytes(b'xx')
            with mock.patch.object(provenance, '_read_preflighted_file') as reader:
                self.assert_error(
                    provenance.ErrorCategory.RESOURCE_LIMIT,
                    lambda: provenance.verify_signed_event_files(
                        event, [], limits=provenance.VerificationLimits(event_bytes=1),
                    ),
                )
                reader.assert_not_called()
            with mock.patch.object(provenance, '_read_preflighted_file') as reader:
                self.assert_error(
                    provenance.ErrorCategory.RESOURCE_LIMIT,
                    lambda: provenance.verify_signed_event_files(
                        event, [key],
                        limits=provenance.VerificationLimits(
                            event_bytes=2, key_record_bytes=1,
                        ),
                    ),
                )
                reader.assert_not_called()

    def test_aggregate_file_limit_is_checked_before_any_bulk_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = root / 'event.json'
            first = root / 'first.json'
            second = root / 'second.json'
            event.write_bytes(b'x')
            first.write_bytes(b'xx')
            second.write_bytes(b'xx')
            limits = provenance.VerificationLimits(
                key_record_bytes=2, aggregate_key_bytes=3,
            )
            with mock.patch.object(provenance, '_read_preflighted_file') as reader:
                self.assert_error(
                    provenance.ErrorCategory.RESOURCE_LIMIT,
                    lambda: provenance.verify_signed_event_files(
                        event, [first, second], limits=limits,
                    ),
                )
                reader.assert_not_called()

    def test_nonregular_file_is_rejected_before_bulk_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(provenance, '_read_preflighted_file') as reader:
                error = self.assert_error(
                    provenance.ErrorCategory.INPUT,
                    lambda: provenance.verify_signed_event_files(root, []),
                )
                self.assertEqual(provenance.VerificationStage.INPUT, error.stage)
                reader.assert_not_called()

    def test_truncated_input_is_a_controlled_failure(self):
        source = provenance._PreflightedFile(
            _ReadHandle(truncate=True),
            provenance._FileSnapshot(1, 2, 4, 1, 1),
            'signed-event record',
        )
        error = self.assert_error(
            provenance.ErrorCategory.INPUT,
            lambda: provenance._read_preflighted_file(source),
        )
        self.assertIn('truncated', str(error))

    def test_changed_input_is_a_controlled_failure(self):
        handle = _ReadHandle(b'data')
        source = provenance._PreflightedFile(
            handle,
            provenance._FileSnapshot(1, 2, 4, 1, 1),
            'signed-event record',
        )
        with mock.patch.object(provenance.os, 'fstat', return_value=_stat(4, modified=2)):
            error = self.assert_error(
                provenance.ErrorCategory.INPUT,
                lambda: provenance._read_preflighted_file(source),
            )
        self.assertIn('changed', str(error))

    def test_reads_are_chunk_bounded(self):
        payload = b'x' * (provenance.READ_CHUNK + 1)
        handle = _ReadHandle(payload)
        source = provenance._PreflightedFile(
            handle,
            provenance._FileSnapshot(1, 2, len(payload), 1, 1),
            'signed-event record',
        )
        with mock.patch.object(provenance.os, 'fstat', return_value=_stat(len(payload))):
            self.assertEqual(payload, provenance._read_preflighted_file(source))
        self.assertEqual([provenance.READ_CHUNK, 1], handle.requests)

    def test_key_count_is_checked_before_opening_files(self):
        limits = provenance.VerificationLimits(key_records=0)
        with mock.patch('builtins.open') as opened:
            self.assert_error(
                provenance.ErrorCategory.RESOURCE_LIMIT,
                lambda: provenance.verify_signed_event_files('event', ['key'], limits=limits),
            )
            opened.assert_not_called()


if __name__ == '__main__':
    unittest.main()
