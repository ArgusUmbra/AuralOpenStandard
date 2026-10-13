"""AURAL draft 0.1 package writer and strict basic integrity verifier."""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import zipfile

FORMAT = 'org.aural.audio-evidence'
VERSION = '0.1-draft'
MAX_MANIFEST = 1024 * 1024
MAX_ENTRIES = 1000
MAX_TOTAL_UNCOMPRESSED = 10 * 1024**3
MAX_AUDIO = 8 * 1024**3
CHUNK = 1024 * 1024

class AuralError(ValueError):
    pass

def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(CHUNK), b''):
            digest.update(block)
    return digest.hexdigest()

def package(source, destination, title='', recorded_at=None):
    source, destination = Path(source), Path(destination)
    if source.suffix.lower() != '.wav' or not source.is_file():
        raise AuralError('Draft 0.1 accepts an existing WAV file only')
    if destination.resolve() == source.resolve():
        raise AuralError('Source and destination must differ')
    size = source.stat().st_size
    if size > MAX_AUDIO:
        raise AuralError('Audio exceeds draft size limit')
    with source.open('rb') as f:
        start = f.read(12)
    if not ((start[:4] in (b'RIFF', b'RF64') and start[8:] == b'WAVE')):
        raise AuralError('Audio does not appear to be RIFF WAV or RF64 WAV')
    name = 'audio/original.wav'
    manifest = {
        'format': FORMAT,
        'version': VERSION,
        'title': title,
        'recorded_at': recorded_at,
        'original': name,
        'assets': [{ 'path': name, 'role': 'original', 'media_type': 'audio/wav',
                     'size': size, 'sha256': sha256_file(source)}],
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.aural-', suffix='.tmp', dir=destination.parent)
    os.close(fd)
    try:
        with zipfile.ZipFile(tmp, 'w', allowZip64=True) as z:
            z.writestr('manifest.json', canonical_json(manifest), compress_type=zipfile.ZIP_STORED)
            z.write(source, arcname=name, compress_type=zipfile.ZIP_STORED)
        # Catch modifications to source while packaging; never emit inconsistent package.
        verify(tmp)
        os.replace(tmp, destination)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return manifest

def _safe_name(name):
    return (bool(name) and '\\' not in name and not name.startswith('/')
            and not re.match(r'^[A-Za-z]:', name)
            and all(segment not in ('', '.', '..') for segment in name.split('/')))

def verify(path):
    """Verify declared payload hashes and conservative ZIP/profile structure.

    NOT proof of recording authenticity, sender identity, or chain of custody.
    """
    try:
        with zipfile.ZipFile(path, 'r', allowZip64=True) as z:
            infos = z.infolist()
            names = [i.filename for i in infos]
            if not names or len(names) > MAX_ENTRIES or len(names) != len(set(names)):
                raise AuralError('Empty archive, duplicate names, or too many entries')
            if not all(_safe_name(n) for n in names):
                raise AuralError('Unsafe archive path')
            if any(i.is_dir() or i.flag_bits & 1 or i.compress_type != zipfile.ZIP_STORED for i in infos):
                raise AuralError('Directories, encryption and compression are not allowed in draft 0.1')
            if any((i.external_attr >> 16) & 0o170000 == 0o120000 for i in infos):
                raise AuralError('Symlinks are not allowed')
            if sum(i.file_size for i in infos) > MAX_TOTAL_UNCOMPRESSED:
                raise AuralError('Archive exceeds size limit')
            if 'manifest.json' not in names or z.getinfo('manifest.json').file_size > MAX_MANIFEST:
                raise AuralError('Missing or oversized manifest')
            raw = z.read('manifest.json')
            def unique_keys(pairs):
                obj = {}
                for key, val in pairs:
                    if key in obj:
                        raise AuralError('Duplicate JSON key')
                    obj[key] = val
                return obj
            doc = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_keys)
            if canonical_json(doc) != raw:
                raise AuralError('Manifest is not canonical JSON')
            if doc.get('format') != FORMAT or doc.get('version') != VERSION:
                raise AuralError('Wrong format or unsupported draft version')
            assets = doc.get('assets')
            if not isinstance(assets, list) or len(assets) != 1:
                raise AuralError('Draft 0.1 requires exactly one asset')
            asset = assets[0]
            if set(asset) != {'path', 'role', 'media_type', 'size', 'sha256'}:
                raise AuralError('Invalid asset descriptor')
            if (asset['path'] != 'audio/original.wav' or doc.get('original') != asset['path']
                    or asset['role'] != 'original' or asset['media_type'] != 'audio/wav'):
                raise AuralError('Invalid original audio descriptor')
            if set(names) != {'manifest.json', asset['path']}:
                raise AuralError('Undeclared or missing archive entry')
            info = z.getinfo(asset['path'])
            if type(asset['size']) is not int or asset['size'] != info.file_size or info.file_size > MAX_AUDIO:
                raise AuralError('Audio size mismatch')
            if not isinstance(asset['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', asset['sha256']):
                raise AuralError('Malformed SHA-256')
            with z.open(asset['path']) as f:
                header = f.read(12)
                if not (header[:4] in (b'RIFF', b'RF64') and header[8:] == b'WAVE'):
                    raise AuralError('Invalid WAV signature')
                digest = hashlib.sha256(header)
                for block in iter(lambda: f.read(CHUNK), b''):
                    digest.update(block)
            if digest.hexdigest() != asset['sha256']:
                raise AuralError('SHA-256 mismatch: audio modified or corrupt')
            return {'status': 'integrity_valid', 'version': VERSION,
                    'audio_sha256': asset['sha256'], 'audio_bytes': info.file_size,
                    'warning': 'No source authenticity or signer identity verification in draft 0.1'}
    except (zipfile.BadZipFile, json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError, OSError, EOFError) as exc:
        raise AuralError(f'Invalid AURAL package: {exc}') from exc

def extract(path, destination):
    verify(path)
    destination = Path(destination)
    if destination.exists():
        raise AuralError('Refusing to overwrite existing output')
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.aural-extract-', dir=destination.parent)
    try:
        with zipfile.ZipFile(path) as z, os.fdopen(fd, 'wb') as target, z.open('audio/original.wav') as src:
            while True:
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                target.write(chunk)
        os.replace(tmp, destination)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return destination
