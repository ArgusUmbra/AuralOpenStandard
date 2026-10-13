import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import wave
import zipfile
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

if __name__ == '__main__':
    unittest.main()
