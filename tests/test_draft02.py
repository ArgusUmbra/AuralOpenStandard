import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import wave
import zipfile

from aural import core
from aural.core import AuralError, canonical_json, extract, package, verify, verify_detailed


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'fixtures' / 'conformance'


class Draft02Tests(unittest.TestCase):
    @staticmethod
    def rewrite_manifest(source, destination, manifest):
        with zipfile.ZipFile(source) as existing, zipfile.ZipFile(destination, 'w') as output:
            for name in existing.namelist():
                payload = manifest if name == 'manifest.json' else existing.read(name)
                output.writestr(name, payload, compress_type=zipfile.ZIP_STORED)

    def test_corpus_hashes_and_python_outcomes(self):
        expected = json.loads((CORPUS / 'expected.json').read_text(encoding='utf-8'))
        for name, case in expected['fixtures'].items():
            with self.subTest(fixture=name):
                path = CORPUS / name
                self.assertEqual(case['fixture_sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
                if case['outcome'] == 'reject':
                    with self.assertRaises(AuralError):
                        verify(path)
                else:
                    result = verify(path)
                    outcome = 'accept-legacy-0.1' if result['legacy'] else 'accept-0.2'
                    self.assertEqual(case['outcome'], outcome)
                    if outcome == 'accept-0.2':
                        self.assertEqual('integrity_valid', result['status'])
                        self.assertEqual('0.2-draft', result['version'])
                        self.assertEqual(expected['audio']['length'], result['audio_bytes'])
                        self.assertEqual(expected['audio']['sha256'], result['audio_sha256'])

    def test_golden_manifest_bytes(self):
        expected = json.loads((CORPUS / 'expected.json').read_text(encoding='utf-8'))
        raw = (CORPUS / expected['golden_manifest']['path']).read_bytes()
        self.assertEqual(402, len(raw))
        self.assertFalse(raw.endswith(b'\n'))
        self.assertEqual(expected['golden_manifest']['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(raw, canonical_json(json.loads(raw)))
        with zipfile.ZipFile(CORPUS / 'valid-unicode.aural') as archive:
            self.assertEqual(raw, archive.read('manifest.json'))
        # RFC 8785 orders the supplementary key's UTF-16 surrogate before U+E000.
        self.assertLess(raw.index('𝄞'.encode()), raw.index('\ue000'.encode()))

    def test_python_detailed_api_is_explicit_and_verify_contract_is_unchanged(self):
        fixture = CORPUS / 'valid-unicode.aural'
        basic = verify(fixture)
        detailed = verify_detailed(fixture)
        self.assertEqual(
            {'status', 'version', 'legacy', 'audio_sha256', 'audio_bytes', 'warning'},
            set(basic),
        )
        self.assertEqual(
            {
                'status', 'format', 'version', 'manifest_sha256', 'original_path',
                'audio_sha256', 'audio_bytes',
            },
            set(detailed),
        )
        self.assertEqual('org.aural.audio-evidence', detailed['format'])
        self.assertEqual('0.2-draft', detailed['version'])
        self.assertEqual('audio/original.wav', detailed['original_path'])
        self.assertEqual(
            '83ff69181aa5a1eb7b04a042eee89081a155a61736838615444f60c95672c3da',
            detailed['manifest_sha256'],
        )
        shared = ('status', 'version', 'audio_sha256', 'audio_bytes')
        self.assertEqual(
            {key: detailed[key] for key in shared},
            {key: basic[key] for key in shared},
        )

        self.assertTrue(verify(CORPUS / 'legacy-0.1.aural')['legacy'])
        with self.assertRaisesRegex(AuralError, 'Draft 0.2'):
            verify_detailed(CORPUS / 'legacy-0.1.aural')

    def test_writer_is_v02_and_preserves_original_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source.wav'
            with wave.open(str(source), 'wb') as output:
                output.setparams((1, 2, 8000, 0, 'NONE', 'not compressed'))
                output.writeframes(b'\x01\x00' * 16)
            original = source.read_bytes()
            target = root / 'evidence.aural'
            document = package(
                source, target, title='Field 𝄞',
                recorded_at='2026-10-13T18:00:00Z')
            self.assertEqual('0.2-draft', document['version'])
            self.assertEqual('integrity_valid', verify(target)['status'])
            restored = root / 'restored.wav'
            extract(target, restored)
            self.assertEqual(original, restored.read_bytes())
            with zipfile.ZipFile(target) as archive:
                self.assertEqual(canonical_json(document), archive.read('manifest.json'))

    def test_timestamp_profile(self):
        self.assertTrue(core._valid_rfc3339('2026-10-13T18:00:00Z'))
        self.assertTrue(core._valid_rfc3339('2026-10-13T12:00:00.123456789-06:00'))
        for invalid in (
                '2026-10-13 18:00:00Z', '2026-10-13T18:00:60Z',
                '2026-02-29T00:00:00Z', '2026-10-13T18:00:00-00:00',
                '2026-10-13T18:00:00+14:01'):
            with self.subTest(value=invalid):
                self.assertFalse(core._valid_rfc3339(invalid))

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_manifest_container_depth_boundary_agrees_across_validators(self):
        with zipfile.ZipFile(CORPUS / 'valid-minimal.aural') as archive:
            base = json.loads(archive.read('manifest.json'))

        manifests = {}
        for depth, nested_arrays in ((32, 30), (33, 31)):
            document = dict(base)
            value = 'leaf'
            for _ in range(nested_arrays):
                value = [value]
            document['extensions'] = {'urn:test:depth': value}
            manifests[depth] = core._jcs_text(document).encode('utf-8')

        core._raw_json_depth(manifests[32])
        core._check_ijson(json.loads(manifests[32]))
        with self.assertRaisesRegex(AuralError, 'nesting'):
            core._raw_json_depth(manifests[33])
        with self.assertRaisesRegex(AuralError, 'nesting'):
            core._check_ijson(json.loads(manifests[33]))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = {}
            for depth, manifest in manifests.items():
                packages[depth] = root / f'depth-{depth}.aural'
                self.rewrite_manifest(
                    CORPUS / 'valid-minimal.aural', packages[depth], manifest,
                )

            self.assertEqual('integrity_valid', verify(packages[32])['status'])
            with self.assertRaisesRegex(AuralError, 'nesting'):
                verify(packages[33])

            validator = ROOT / 'interop' / 'validate_aural.mjs'
            accepted = subprocess.run(
                ['node', str(validator), str(packages[32])],
                capture_output=True, text=True, check=False, timeout=20,
            )
            rejected = subprocess.run(
                ['node', str(validator), str(packages[33])],
                capture_output=True, text=True, check=False, timeout=20,
            )
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            self.assertEqual(1, rejected.returncode)
            self.assertIn('JSON depth', rejected.stderr)

        self.assertTrue(verify(CORPUS / 'legacy-0.1.aural')['legacy'])

    def test_manifest_size_checked_before_json_parse(self):
        with self.assertRaisesRegex(AuralError, 'size'):
            core._parse_manifest(b' ' * (core.MAX_MANIFEST + 1))

    def test_legacy_zip64_extra_regression_is_version_isolated(self):
        legacy = verify(CORPUS / 'legacy-0.1-zip64-extra.aural')
        self.assertTrue(legacy['legacy'])
        self.assertEqual('0.1-draft', legacy['version'])
        with self.assertRaisesRegex(AuralError, 'Unnecessary ZIP64'):
            verify(CORPUS / 'invalid-unnecessary-zip64-extra.aural')

    def test_central_directory_entry_comment_is_present_and_rejected(self):
        path = CORPUS / 'invalid-entry-comment.aural'
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(b'undeclared entry comment', archive.infolist()[0].comment)
        with self.assertRaisesRegex(AuralError, 'comments'):
            verify(path)

    def test_v02_zip_profile_precedes_application_manifest_validation(self):
        with mock.patch.object(
                core, '_parse_v02_manifest', side_effect=AssertionError('manifest processed')):
            with self.assertRaisesRegex(AuralError, 'extra field'):
                verify(CORPUS / 'invalid-extra-field.aural')

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_independent_node_validator_agrees_on_v02_corpus(self):
        expected = json.loads((CORPUS / 'expected.json').read_text(encoding='utf-8'))
        validator = ROOT / 'interop' / 'validate_aural.mjs'
        checked = 0
        for name, case in expected['fixtures'].items():
            if case['outcome'] == 'accept-legacy-0.1':
                continue  # The independent minimal validator implements Draft 0.2 only.
            with self.subTest(fixture=name):
                completed = subprocess.run(
                    ['node', str(validator), str(CORPUS / name)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(case['outcome'] == 'accept-0.2', completed.returncode == 0,
                                 completed.stderr)
                if case['outcome'] == 'accept-0.2':
                    result = json.loads(completed.stdout)
                    self.assertEqual(
                        {'status', 'version', 'audio_sha256', 'audio_bytes'}, set(result),
                    )
                    self.assertEqual('integrity_valid', result['status'])
                    self.assertEqual('0.2-draft', result['version'])
                    self.assertEqual(expected['audio']['length'], result['audio_bytes'])
                    self.assertEqual(expected['audio']['sha256'], result['audio_sha256'])
                checked += 1
        self.assertGreaterEqual(checked, 20)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_node_detailed_api_is_explicitly_opt_in(self):
        validator_uri = (ROOT / 'interop' / 'validate_aural.mjs').as_uri()
        fixture = str(CORPUS / 'valid-minimal.aural')
        script = (
            f"import {{verify,verifyDetailed}} from {json.dumps(validator_uri)};"
            f"console.log(JSON.stringify([await verify({json.dumps(fixture)}),"
            f"await verifyDetailed({json.dumps(fixture)})]));"
        )
        completed = subprocess.run(
            ['node', '--input-type=module', '--eval', script],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        basic, detailed = json.loads(completed.stdout)
        self.assertEqual(
            {'status', 'version', 'audio_sha256', 'audio_bytes'}, set(basic),
        )
        self.assertEqual(
            {
                'status', 'format', 'version', 'manifest_sha256', 'original_path',
                'audio_sha256', 'audio_bytes',
            },
            set(detailed),
        )
        self.assertEqual({key: detailed[key] for key in basic}, basic)
        self.assertEqual(verify_detailed(Path(fixture)), detailed)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_node_rejects_oversized_file_before_bulk_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            oversized = Path(temporary) / 'oversized.aural'
            oversized.write_bytes(b'x' * 257)
            validator_uri = (ROOT / 'interop' / 'validate_aural.mjs').as_uri()
            script = (
                f"import {{ verify }} from {json.dumps(validator_uri)};"
                f"try {{ await verify({json.dumps(str(oversized))}, {{maxArchive: 256}}); }}"
                "catch (error) { console.error(`AURAL ERROR: ${error.message}`); process.exitCode = 1; }"
            )
            completed = subprocess.run(
                ['node', '--input-type=module', '--eval', script],
                capture_output=True, text=True, check=False, timeout=10,
            )
            self.assertEqual(1, completed.returncode)
            self.assertIn('AURAL ERROR: archive size', completed.stderr)

    def test_node_validator_uses_bounded_positional_io(self):
        source = (ROOT / 'interop' / 'validate_aural.mjs').read_text(encoding='utf-8')
        self.assertNotIn('readFile(', source)
        self.assertIn("const IO_CHUNK = 1024 * 1024", source)
        self.assertIn("const before = await handle.stat({ bigint: true })", source)
        self.assertIn("await this.handle.read(", source)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is not installed')
    def test_node_streams_audio_with_bounded_buffer_allocations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'large.wav'
            with source.open('wb') as output:
                output.write(b'RIFF\x00\x00\x00\x00WAVE')
                output.truncate(5 * 1024 * 1024)
            archive = root / 'large.aural'
            package(source, archive)
            validator_uri = (ROOT / 'interop' / 'validate_aural.mjs').as_uri()
            script = (
                "const originalAlloc = Buffer.alloc; let maximum = 0;"
                "Buffer.alloc = function(size, ...args) { maximum = Math.max(maximum, size);"
                " if (size > 4 * 1024 * 1024) throw new Error('oversized allocation');"
                " return originalAlloc(size, ...args); };"
                f"const {{ verify }} = await import({json.dumps(validator_uri)});"
                f"const result = await verify({json.dumps(str(archive))});"
                "console.log(JSON.stringify({...result, maximum_allocation: maximum}));"
            )
            completed = subprocess.run(
                ['node', '--input-type=module', '--eval', script],
                capture_output=True, text=True, check=False, timeout=30,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(5 * 1024 * 1024, result['audio_bytes'])
            self.assertLessEqual(result['maximum_allocation'], 1024 * 1024)


if __name__ == '__main__':
    unittest.main()
