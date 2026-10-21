import binascii
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile

from aural import core, provenance


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'fixtures' / 'conformance'
PROVENANCE = ROOT / 'tests' / 'fixtures' / 'provenance'
VALID = CORPUS / 'valid-unicode.aural'
NODE_VALIDATOR = ROOT / 'interop' / 'validate_aural.mjs'


@unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
class NodeZip64Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with zipfile.ZipFile(VALID) as archive:
            cls.entries = [
                (b'manifest.json', archive.read('manifest.json')),
                (b'audio/original.wav', archive.read('audio/original.wav')),
            ]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def build_zip64(self, *, entry_zip64=False, partial_classic_eocd=False,
                    redundant_end=False, duplicate_extra=False,
                    unsupported_extra=False):
        local = bytearray()
        records = []
        for name, data in self.entries:
            offset = len(local)
            crc = binascii.crc32(data) & 0xffffffff
            use_zip64 = entry_zip64 and name == b'audio/original.wav'
            extra = b''
            needed = 45 if use_zip64 else 20
            size32 = 0xffffffff if use_zip64 else len(data)
            if use_zip64:
                payload = struct.pack('<QQ', len(data), len(data))
                extra = struct.pack('<HH', 0x0001, len(payload)) + payload
            local += struct.pack(
                '<IHHHHHIIIHH', 0x04034b50, needed, 0, 0, 0, 0,
                crc, size32, size32, len(name), len(extra),
            )
            local += name + extra + data
            records.append((name, data, crc, offset, needed, use_zip64))

        central_offset = len(local)
        central = bytearray()
        for name, data, crc, offset, needed, use_zip64 in records:
            extra = b''
            size32 = len(data)
            offset32 = offset
            if use_zip64:
                payload = struct.pack('<QQQ', len(data), len(data), offset)
                field = struct.pack('<HH', 0x0001, len(payload)) + payload
                extra = field
                if duplicate_extra:
                    extra += field
                if unsupported_extra:
                    extra += struct.pack('<HH', 0x9999, 0)
                size32 = 0xffffffff
                offset32 = 0xffffffff
            central += struct.pack(
                '<IHHHHHHIIIHHHHHII', 0x02014b50, 20, needed, 0, 0, 0, 0,
                crc, size32, size32, len(name), len(extra), 0, 0, 0, 0, offset32,
            )
            central += name + extra

        archive = local + central
        zip64_offset = len(archive)
        archive += struct.pack(
            '<IQHHIIQQQQ', 0x06064b50, 44, 45, 45, 0, 0,
            2, 2, len(central), central_offset,
        )
        archive += struct.pack('<IIQI', 0x07064b50, 0, zip64_offset, 1)
        if redundant_end:
            archive += struct.pack(
                '<IHHHHIIH', 0x06054b50, 0, 0, 2, 2,
                len(central), central_offset, 0,
            )
        elif partial_classic_eocd:
            archive += struct.pack(
                '<IHHHHIIH', 0x06054b50, 0, 0, 2, 2,
                0xffffffff, 0xffffffff, 0,
            )
        else:
            archive += struct.pack(
                '<IHHHHIIH', 0x06054b50, 0, 0, 0xffff, 0xffff,
                0xffffffff, 0xffffffff, 0,
            )
        return bytes(archive)

    def write(self, name, payload):
        path = self.root / name
        path.write_bytes(payload)
        return path

    @staticmethod
    def signature_offsets(payload, signature):
        offsets = []
        position = 0
        while True:
            position = payload.find(signature, position)
            if position < 0:
                return offsets
            offsets.append(position)
            position += 1

    def node_detailed(self, path):
        validator_uri = NODE_VALIDATOR.as_uri()
        script = (
            f"import {{verifyDetailed}} from {json.dumps(validator_uri)};"
            f"console.log(JSON.stringify(await verifyDetailed({json.dumps(str(path))})));"
        )
        completed = subprocess.run(
            ['node', '--input-type=module', '--eval', script],
            capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)

    @staticmethod
    def python_accepts(path):
        try:
            core.verify(path)
        except core.AuralError:
            return False
        return True

    @staticmethod
    def node_accepts(path):
        completed = subprocess.run(
            ['node', str(NODE_VALIDATOR), str(path)],
            capture_output=True, text=True, check=False, timeout=20,
        )
        return completed.returncode == 0

    def assert_both_reject(self, name, payload):
        path = self.write(name, payload)
        self.assertFalse(self.python_accepts(path), 'Python unexpectedly accepted')
        self.assertFalse(self.node_accepts(path), 'Node unexpectedly accepted')

    def test_classic_and_permitted_zip64_layouts_agree(self):
        for name, payload in (
                ('zip64-end-only.aural', self.build_zip64()),
                ('zip64-partial-classic.aural', self.build_zip64(
                    partial_classic_eocd=True,
                )),
                ('zip64-entry-and-end.aural', self.build_zip64(entry_zip64=True))):
            with self.subTest(package=name):
                path = self.write(name, payload)
                python_result = core.verify_detailed(path)
                self.assertEqual(python_result, self.node_detailed(path))
                completed = subprocess.run(
                    ['node', str(NODE_VALIDATOR), str(path)],
                    capture_output=True, text=True, check=False, timeout=20,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual(
                    {'status', 'version', 'audio_sha256', 'audio_bytes'},
                    set(json.loads(completed.stdout)),
                )

        self.assertEqual(core.verify_detailed(VALID), self.node_detailed(VALID))

    def test_zip64_package_preserves_provenance_binding(self):
        package_path = self.write('bound-zip64.aural', self.build_zip64(entry_zip64=True))
        event = PROVENANCE / 'valid-original-acquired.json'
        key = PROVENANCE / 'valid-key.json'
        python_result = provenance.verify_signed_event_files(
            event, [key], package_path=package_path,
        )
        validator_uri = (ROOT / 'interop' / 'validate_provenance.mjs').as_uri()
        script = (
            f"import {{verifySignedEventFiles}} from {json.dumps(validator_uri)};"
            f"console.log(JSON.stringify(await verifySignedEventFiles({json.dumps(str(event))},"
            f"[{json.dumps(str(key))}],{json.dumps(str(package_path))})));"
        )
        completed = subprocess.run(
            ['node', '--input-type=module', '--eval', script],
            capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        node_result = json.loads(completed.stdout)
        self.assertEqual(python_result.status.value, node_result['status'])
        self.assertEqual(python_result.asset_integrity.value, node_result['asset_integrity'])
        self.assertEqual(python_result.signed_event_sha256,
                         node_result['signed_event_sha256'])

    def test_invalid_zip64_end_records_and_locators_agree(self):
        original = self.build_zip64()
        end64 = original.rfind(b'PK\x06\x06')
        locator = original.rfind(b'PK\x06\x07')
        eocd = original.rfind(b'PK\x05\x06')
        cases = {}

        value = bytearray(original)
        value[locator:locator + 4] = b'BAD!'
        cases['bad-locator-signature'] = value
        value = bytearray(original)
        struct.pack_into('<Q', value, locator + 8, end64 + 1)
        cases['bad-locator-offset'] = value
        value = bytearray(original)
        value[end64:end64 + 4] = b'BAD!'
        cases['bad-end-signature'] = value
        value = bytearray(original)
        struct.pack_into('<Q', value, end64 + 4, 45)
        cases['bad-end-size'] = value
        value = bytearray(original)
        struct.pack_into('<H', value, end64 + 14, 46)
        cases['bad-end-version'] = value
        value = bytearray(original)
        struct.pack_into('<I', value, locator + 4, 1)
        cases['multidisk-locator'] = value
        value = bytearray(original)
        struct.pack_into('<H', value, eocd + 8, 1)
        cases['classic-disagreement'] = value
        cases['truncated-end-record'] = (
            original[:locator - 1] + original[locator:]
        )
        cases['duplicate-end-record'] = (
            original[:locator] + original[end64:end64 + 56] + original[locator:]
        )
        cases['redundant-end-records'] = self.build_zip64(redundant_end=True)
        cases['missing-required-end-records'] = original[:end64] + original[eocd:]

        for name, payload in cases.items():
            with self.subTest(case=name):
                self.assert_both_reject(name + '.aural', payload)

    def test_invalid_zip64_entry_fields_agree(self):
        original = self.build_zip64(entry_zip64=True)
        locals_ = self.signature_offsets(original, b'PK\x03\x04')
        centrals = self.signature_offsets(original, b'PK\x01\x02')
        audio_local = locals_[1]
        audio_central = centrals[1]
        local_name = struct.unpack_from('<H', original, audio_local + 26)[0]
        central_name = struct.unpack_from('<H', original, audio_central + 28)[0]
        local_extra = audio_local + 30 + local_name
        central_extra = audio_central + 46 + central_name
        cases = {}

        value = bytearray(original)
        struct.pack_into('<Q', value, local_extra + 4, len(self.entries[1][1]) + 1)
        cases['local-central-size-mismatch'] = value
        value = bytearray(original)
        struct.pack_into('<Q', value, central_extra + 20, 1)
        cases['incorrect-local-offset'] = value
        value = bytearray(original)
        struct.pack_into('<H', value, central_extra + 2, 23)
        cases['truncated-extra-field'] = value
        value = bytearray(original)
        struct.pack_into('<Q', value, central_extra + 4, 1 << 53)
        cases['unsafe-size-conversion'] = value
        value = bytearray(original)
        struct.pack_into('<Q', value, central_extra + 4, core.MAX_AUDIO + 1)
        struct.pack_into('<Q', value, central_extra + 12, core.MAX_AUDIO + 1)
        cases['above-audio-limit'] = value
        value = bytearray(original)
        struct.pack_into('<Q', value, central_extra + 20, 0)
        cases['overlapping-local-headers'] = value
        cases['duplicate-extra'] = self.build_zip64(
            entry_zip64=True, duplicate_extra=True,
        )
        cases['unsupported-extra'] = self.build_zip64(
            entry_zip64=True, unsupported_extra=True,
        )

        for name, payload in cases.items():
            with self.subTest(case=name):
                self.assert_both_reject(name + '.aural', payload)

    def test_zip64_archive_limit_is_checked_before_parsing(self):
        payload = self.build_zip64(entry_zip64=True)
        path = self.write('limited.aural', payload)
        validator_uri = NODE_VALIDATOR.as_uri()
        script = (
            f"import {{verify}} from {json.dumps(validator_uri)};"
            f"try{{await verify({json.dumps(str(path))},{{maxArchive:{len(payload) - 1}}});}}"
            "catch(error){console.log(error.message);process.exitCode=7;}"
        )
        completed = subprocess.run(
            ['node', '--input-type=module', '--eval', script],
            capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(7, completed.returncode)
        self.assertEqual('archive size', completed.stdout.strip())


if __name__ == '__main__':
    unittest.main()
