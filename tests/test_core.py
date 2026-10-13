import binascii
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import wave
import zipfile
import aural.core as core
from aural.core import AuralError, canonical_json, package, verify, extract

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.wav = self.d / 'source.wav'
        with wave.open(str(self.wav), 'wb') as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(8000)
            w.writeframes(b'\x00\x00' * 160)
        self.pkg = self.d / 'evidence.aural'
        package(self.wav, self.pkg)

    def write_wav(self, path, sample=b'\x00\x00'):
        with wave.open(str(path), 'wb') as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(8000)
            w.writeframes(sample * 160)

    def rewrite_manifest(self, destination, manifest):
        with zipfile.ZipFile(self.pkg) as src, zipfile.ZipFile(destination, 'w') as dst:
            for name in src.namelist():
                data = manifest if name == 'manifest.json' else src.read(name)
                dst.writestr(name, data, compress_type=zipfile.ZIP_STORED)

    def raw_stored_zip(self, entries, local_names=None):
        local_names = local_names or [name for name, _ in entries]
        local = bytearray()
        central = bytearray()
        for (central_name, data), local_name in zip(entries, local_names):
            offset = len(local)
            crc = binascii.crc32(data) & 0xffffffff
            local += struct.pack(
                '<IHHHHHIIIHH', 0x04034b50, 20, 0, 0, 0, 0,
                crc, len(data), len(data), len(local_name), 0,
            )
            local += local_name + data
            central += struct.pack(
                '<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, 0, 0, 0,
                crc, len(data), len(data), len(central_name), 0, 0, 0, 0, 0,
                offset,
            )
            central += central_name
        archive = local + central
        archive += struct.pack(
            '<IHHHHIIH', 0x06054b50, 0, 0, len(entries), len(entries),
            len(central), len(local), 0,
        )
        return bytes(archive)

    def as_zip64(self, archive, zip64_offset_adjustment=0):
        fields = struct.unpack('<IHHHHIIH', archive[-22:])
        _, disk, cd_disk, disk_entries, entries, cd_size, cd_offset, comment = fields
        self.assertEqual((disk, cd_disk, comment), (0, 0, 0))
        prefix = archive[:-22]
        zip64_offset = len(prefix)
        zip64_record = struct.pack(
            '<IQHHIIQQQQ', 0x06064b50, 44, 45, 45, 0, 0,
            disk_entries, entries, cd_size, cd_offset,
        )
        locator = struct.pack(
            '<IIQI', 0x07064b50, 0,
            zip64_offset + zip64_offset_adjustment, 1,
        )
        classic = struct.pack(
            '<IHHHHIIH', 0x06054b50, 0, 0, 0xffff, 0xffff,
            0xffffffff, 0xffffffff, 0,
        )
        return prefix + zip64_record + locator + classic

    def test_round_trip(self):
        self.assertEqual(verify(self.pkg)['status'], 'integrity_valid')
        out = self.d / 'restored.wav'
        extract(self.pkg, out)
        self.assertEqual(self.wav.read_bytes(), out.read_bytes())

    def test_modified_audio_rejected(self):
        broken = self.d / 'modified.aural'
        with zipfile.ZipFile(self.pkg) as src, zipfile.ZipFile(broken, 'w') as dst:
            for entry in src.infolist():
                payload = bytearray(src.read(entry.filename))
                if entry.filename.endswith('.wav'):
                    payload[-1] ^= 1
                dst.writestr(entry.filename, payload, compress_type=zipfile.ZIP_STORED)
        with self.assertRaisesRegex(AuralError, 'SHA-256 mismatch'):
            verify(broken)

    def test_duplicate_entry_rejected(self):
        broken = self.d / 'duplicate.aural'
        import warnings
        with zipfile.ZipFile(self.pkg) as src, zipfile.ZipFile(broken, 'w') as dst:
            for name in src.namelist():
                dst.writestr(name, src.read(name))
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                dst.writestr('manifest.json', src.read('manifest.json'))
        with self.assertRaisesRegex(AuralError, 'duplicate'):
            verify(broken)

    def test_traversal_rejected(self):
        broken = self.d / 'traversal.aural'
        with zipfile.ZipFile(self.pkg) as src, zipfile.ZipFile(broken, 'w') as dst:
            for name in src.namelist():
                dst.writestr(name, src.read(name))
            dst.writestr('../malicious.txt', b'bad')
        with self.assertRaisesRegex(AuralError, 'Unsafe'):
            verify(broken)

    def test_manifest_change_rejected_if_not_canonical(self):
        broken = self.d / 'manifest.aural'
        with zipfile.ZipFile(self.pkg) as src, zipfile.ZipFile(broken, 'w') as dst:
            for name in src.namelist():
                data = src.read(name)
                if name == 'manifest.json':
                    data = json.dumps(json.loads(data), indent=2).encode('utf-8')
                dst.writestr(name, data)
        with self.assertRaisesRegex(AuralError, 'canonical'):
            verify(broken)

    def test_undeclared_bytes_outside_zip_entries_rejected(self):
        original = self.pkg.read_bytes()
        variants = {
            'prefix': b'MZ-polyglot-prefix' + original,
            'suffix': original + b'undeclared-trailing-data',
        }
        for label, payload in variants.items():
            with self.subTest(label=label):
                broken = self.d / f'{label}.aural'
                broken.write_bytes(payload)
                with self.assertRaises(AuralError):
                    verify(broken)

    def test_zip_comments_rejected_as_undeclared_data(self):
        broken = self.d / 'commented.aural'
        broken.write_bytes(self.pkg.read_bytes())
        with zipfile.ZipFile(broken, 'a') as archive:
            archive.comment = b'undeclared archive comment'
        with self.assertRaises(AuralError):
            verify(broken)

    def test_embedded_nul_member_names_rejected(self):
        with zipfile.ZipFile(self.pkg) as archive:
            manifest = archive.read('manifest.json')
            audio = archive.read('audio/original.wav')
        payload = self.raw_stored_zip([
            (b'manifest.json\x00hidden', manifest),
            (b'audio/original.wav\x00hidden', audio),
        ])
        broken = self.d / 'nul-names.aural'
        broken.write_bytes(payload)
        with self.assertRaisesRegex(AuralError, 'NUL'):
            verify(broken)

    def test_local_and_central_member_names_must_match(self):
        with zipfile.ZipFile(self.pkg) as archive:
            manifest = archive.read('manifest.json')
            audio = archive.read('audio/original.wav')
        entries = [(b'manifest.json', manifest), (b'audio/original.wav', audio)]
        payload = self.raw_stored_zip(
            entries,
            local_names=[b'manifest.JSON', b'audio/original.wav'],
        )
        broken = self.d / 'name-mismatch.aural'
        broken.write_bytes(payload)
        with self.assertRaisesRegex(AuralError, 'name'):
            verify(broken)

    def test_physical_archive_size_checked_before_zipfile_parsing(self):
        size = self.pkg.stat().st_size
        with mock.patch.object(core, 'MAX_ARCHIVE_SIZE', size - 1), \
                mock.patch.object(core.zipfile, 'ZipFile', side_effect=AssertionError('ZIP parsed')):
            with self.assertRaisesRegex(AuralError, 'physical size'):
                verify(self.pkg)
        with mock.patch.object(core, 'MAX_ARCHIVE_SIZE', size):
            self.assertEqual('integrity_valid', verify(self.pkg)['status'])

    def test_excessive_declared_entry_count_rejected_before_zipfile_parsing(self):
        payload = bytearray(self.pkg.read_bytes())
        eocd = len(payload) - 22
        struct.pack_into('<H', payload, eocd + 8, core.MAX_ENTRIES + 1)
        struct.pack_into('<H', payload, eocd + 10, core.MAX_ENTRIES + 1)
        broken = self.d / 'too-many-entries.aural'
        broken.write_bytes(payload)
        with mock.patch.object(core.zipfile, 'ZipFile', side_effect=AssertionError('ZIP parsed')):
            with self.assertRaisesRegex(AuralError, 'entry count'):
                verify(broken)

    def test_central_directory_size_limit_checked_before_zipfile_parsing(self):
        payload = bytearray(self.pkg.read_bytes())
        eocd = len(payload) - 22
        struct.pack_into('<I', payload, eocd + 12, core.MAX_CENTRAL_DIRECTORY + 1)
        broken = self.d / 'oversized-central-directory.aural'
        broken.write_bytes(payload)
        with mock.patch.object(core.zipfile, 'ZipFile', side_effect=AssertionError('ZIP parsed')):
            with self.assertRaisesRegex(AuralError, 'Central-directory size'):
                verify(broken)

    def test_malformed_eocd_metadata_rejected_before_zipfile_parsing(self):
        original = self.pkg.read_bytes()
        cases = {}
        bad_signature = bytearray(original)
        bad_signature[-22:-18] = b'BAD!'
        cases['signature'] = bad_signature
        bad_size = bytearray(original)
        central_size = struct.unpack_from('<I', bad_size, len(bad_size) - 22 + 12)[0]
        struct.pack_into('<I', bad_size, len(bad_size) - 22 + 12, central_size + 1)
        cases['central_size'] = bad_size
        bad_count = bytearray(original)
        struct.pack_into('<H', bad_count, len(bad_count) - 22 + 8, 1)
        struct.pack_into('<H', bad_count, len(bad_count) - 22 + 10, 1)
        cases['central_count'] = bad_count
        for label, payload in cases.items():
            with self.subTest(label=label):
                broken = self.d / f'bad-eocd-{label}.aural'
                broken.write_bytes(payload)
                with mock.patch.object(
                        core.zipfile, 'ZipFile', side_effect=AssertionError('ZIP parsed')):
                    with self.assertRaises(AuralError):
                        verify(broken)

    def test_bounded_zip64_eocd_supported_and_malformed_locator_rejected(self):
        original = self.pkg.read_bytes()
        valid = self.d / 'zip64.aural'
        valid.write_bytes(self.as_zip64(original))
        self.assertEqual('integrity_valid', verify(valid)['status'])
        broken = self.d / 'zip64-bad-locator.aural'
        broken.write_bytes(self.as_zip64(original, zip64_offset_adjustment=1))
        with self.assertRaises(AuralError):
            verify(broken)

    def test_malformed_manifests_fail_closed(self):
        with zipfile.ZipFile(self.pkg) as archive:
            document = json.loads(archive.read('manifest.json'))
        document['title'] = ''
        valid = canonical_json(document)
        cases = {
            'non_object': b'[]\n',
            'invalid_syntax': b'{"broken":]\n',
            'invalid_utf8': b'{"title":"\xff"}\n',
            'excessive_nesting': b'[' * 2000 + b'0' + b']' * 2000 + b'\n',
            'non_finite_number': valid.replace(b'"title":""', b'"title":1e999'),
            'unpaired_surrogate': valid.replace(b'"title":""', b'"title":"\\ud800"'),
        }
        for label, manifest in cases.items():
            with self.subTest(label=label):
                broken = self.d / f'malformed-{label}.aural'
                self.rewrite_manifest(broken, manifest)
                with self.assertRaises(AuralError):
                    verify(broken)

    def test_manifest_metadata_types_are_enforced(self):
        with zipfile.ZipFile(self.pkg) as archive:
            valid = json.loads(archive.read('manifest.json'))
        cases = {
            'missing_format': {key: value for key, value in valid.items() if key != 'format'},
            'non_string_title': {**valid, 'title': {'nested': 'value'}},
            'invalid_recorded_at': {**valid, 'recorded_at': []},
            'unknown_field': {**valid, 'unexpected': 'value'},
        }
        for label, manifest in cases.items():
            with self.subTest(label=label):
                broken = self.d / f'metadata-{label}.aural'
                self.rewrite_manifest(broken, canonical_json(manifest))
                with self.assertRaises(AuralError):
                    verify(broken)

    def test_extract_uses_the_archive_instance_it_verified(self):
        replacement_wav = self.d / 'replacement.wav'
        self.write_wav(replacement_wav, b'\x01\x00')
        replacement_pkg = self.d / 'replacement.aural'
        package(replacement_wav, replacement_pkg)
        original_verify = core.verify

        def verify_then_replace(path):
            result = original_verify(path)
            os.replace(replacement_pkg, self.pkg)
            return result

        output = self.d / 'snapshot.wav'
        with mock.patch('aural.core.verify', side_effect=verify_then_replace):
            extract(self.pkg, output)
        self.assertEqual(self.wav.read_bytes(), output.read_bytes())

    def test_extract_does_not_overwrite_destination_created_during_write(self):
        output = self.d / 'raced-output.wav'
        sentinel = b'created by another process'
        original_fdopen = core.os.fdopen

        class RacingWriter:
            def __init__(self, wrapped):
                self.wrapped = wrapped
                self.created_destination = False

            def __enter__(self):
                self.wrapped.__enter__()
                return self

            def __exit__(self, *args):
                return self.wrapped.__exit__(*args)

            def write(self, data):
                if not self.created_destination:
                    output.write_bytes(sentinel)
                    self.created_destination = True
                return self.wrapped.write(data)

        def racing_fdopen(*args, **kwargs):
            return RacingWriter(original_fdopen(*args, **kwargs))

        with mock.patch('aural.core.os.fdopen', side_effect=racing_fdopen):
            with self.assertRaisesRegex(AuralError, 'overwrite'):
                extract(self.pkg, output)
        self.assertEqual(sentinel, output.read_bytes())

    def test_original_draft_sample_remains_compatible(self):
        repository = Path(__file__).resolve().parents[1]
        sample_package = repository / 'examples' / 'sample.aural'
        sample_wav = repository / 'examples' / 'sample.wav'
        self.assertEqual('integrity_valid', verify(sample_package)['status'])
        output = self.d / 'sample.wav'
        extract(sample_package, output)
        self.assertEqual(sample_wav.read_bytes(), output.read_bytes())

if __name__ == '__main__':
    unittest.main()
