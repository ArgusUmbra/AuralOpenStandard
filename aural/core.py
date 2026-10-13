"""AURAL draft 0.1 package writer and strict basic integrity verifier."""
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import tempfile
import zipfile

FORMAT = 'org.aural.audio-evidence'
VERSION = '0.1-draft'
MAX_MANIFEST = 1024 * 1024
MAX_ENTRIES = 1000
MAX_TOTAL_UNCOMPRESSED = 10 * 1024**3
MAX_AUDIO = 8 * 1024**3
CHUNK = 1024 * 1024
MAX_CENTRAL_DIRECTORY = 4 * 1024**2
MAX_ZIP64_END_RECORD = 64 * 1024
MAX_ARCHIVE_SIZE = MAX_TOTAL_UNCOMPRESSED + MAX_CENTRAL_DIRECTORY + 1024**2
MANIFEST_KEYS = {'format', 'version', 'title', 'recorded_at', 'original', 'assets'}
ASSET_KEYS = {'path', 'role', 'media_type', 'size', 'sha256'}
INVALID_PACKAGE_ERRORS = (
    zipfile.BadZipFile, json.JSONDecodeError, UnicodeError, KeyError, TypeError,
    AttributeError, OSError, EOFError, RecursionError, OverflowError, ValueError,
    struct.error,
)

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
    return (bool(name) and '\x00' not in name and '\\' not in name and not name.startswith('/')
            and not re.match(r'^[A-Za-z]:', name)
            and all(segment not in ('', '.', '..') for segment in name.split('/')))

def _archive_source(path):
    if hasattr(path, 'read') and hasattr(path, 'seek'):
        return nullcontext(path)
    return open(path, 'rb')

def _read_exact(source, size, description):
    data = source.read(size)
    if len(data) != size:
        raise AuralError(f'Truncated {description}')
    return data

def _zip64_central_values(extra, uncompressed, compressed, local_offset, disk):
    zip64 = None
    cursor = 0
    while cursor < len(extra):
        if len(extra) - cursor < 4:
            raise AuralError('Malformed ZIP extra field')
        field_id, field_size = struct.unpack_from('<HH', extra, cursor)
        cursor += 4
        end = cursor + field_size
        if end > len(extra):
            raise AuralError('Malformed ZIP extra field')
        if field_id == 0x0001:
            if zip64 is not None:
                raise AuralError('Duplicate ZIP64 extra field')
            zip64 = extra[cursor:end]
        cursor = end

    required = (uncompressed == 0xffffffff, compressed == 0xffffffff,
                local_offset == 0xffffffff, disk == 0xffff)
    if not any(required):
        return local_offset, disk
    if zip64 is None:
        raise AuralError('Missing ZIP64 extra field')
    position = 0

    def take(size):
        nonlocal position
        if position + size > len(zip64):
            raise AuralError('Truncated ZIP64 extra field')
        value = int.from_bytes(zip64[position:position + size], 'little')
        position += size
        return value

    if required[0]:
        take(8)
    if required[1]:
        take(8)
    if required[2]:
        local_offset = take(8)
    if required[3]:
        disk = take(4)
    return local_offset, disk

def _scan_central_directory(source, central, declared_entries, central_offset):
    names = []
    local_offsets = []
    cursor = 0
    for _ in range(declared_entries):
        if len(central) - cursor < 46:
            raise AuralError('Central-directory entry count is contradictory')
        fields = struct.unpack_from('<4s6H3L5H2L', central, cursor)
        if fields[0] != zipfile.stringCentralDir:
            raise AuralError('Malformed central-directory entry')
        flags, compression = fields[3], fields[4]
        compressed, uncompressed = fields[8], fields[9]
        name_size, extra_size, comment_size = fields[10], fields[11], fields[12]
        disk, local_offset = fields[13], fields[16]
        entry_end = cursor + 46 + name_size + extra_size + comment_size
        if entry_end > len(central):
            raise AuralError('Truncated central-directory entry')
        name_start = cursor + 46
        raw_name = bytes(central[name_start:name_start + name_size])
        extra_start = name_start + name_size
        extra = bytes(central[extra_start:extra_start + extra_size])
        if b'\x00' in raw_name:
            raise AuralError('NUL byte is not allowed in ZIP member names')
        if comment_size:
            raise AuralError('ZIP entry comments are not allowed in draft 0.1')
        encoding = 'utf-8' if flags & 0x800 else 'cp437'
        name = raw_name.decode(encoding)
        if '\x00' in name:
            raise AuralError('NUL byte is not allowed in ZIP member names')
        local_offset, disk = _zip64_central_values(
            extra, uncompressed, compressed, local_offset, disk,
        )
        if disk != 0:
            raise AuralError('Multi-disk ZIP archives are not allowed')
        if local_offset + 30 > central_offset:
            raise AuralError('Invalid local-file-header offset')

        position = source.tell()
        try:
            source.seek(local_offset)
            local = struct.unpack(
                '<4s5H3L2H', _read_exact(source, 30, 'local file header'),
            )
            if local[0] != zipfile.stringFileHeader:
                raise AuralError('Malformed local file header')
            local_flags, local_compression = local[2], local[3]
            local_name_size, local_extra_size = local[9], local[10]
            if local_offset + 30 + local_name_size + local_extra_size > central_offset:
                raise AuralError('Local file header overlaps central directory')
            local_name = _read_exact(source, local_name_size, 'local member name')
            if local_name != raw_name:
                raise AuralError('Local and central ZIP member names differ')
            if local_flags != flags or local_compression != compression:
                raise AuralError('Local and central ZIP metadata differ')
        finally:
            source.seek(position)
        names.append(name)
        local_offsets.append(local_offset)
        cursor = entry_end

    if cursor != len(central):
        raise AuralError('Central-directory size or entry count is contradictory')
    if not local_offsets or min(local_offsets) != 0:
        raise AuralError('ZIP preamble is not allowed in draft 0.1')
    if len(local_offsets) != len(set(local_offsets)):
        raise AuralError('ZIP members cannot share a local file header')
    return names

def _preflight_archive(source):
    current = source.tell()
    try:
        source.seek(0, os.SEEK_END)
        physical_size = source.tell()
        if physical_size > MAX_ARCHIVE_SIZE:
            raise AuralError('Archive physical size exceeds implementation limit')
        if physical_size < 22:
            raise AuralError('Truncated ZIP end-of-central-directory record')

        eocd_offset = physical_size - 22
        source.seek(eocd_offset)
        eocd = struct.unpack(
            '<4s4H2LH', _read_exact(source, 22, 'ZIP end-of-central-directory record'),
        )
        signature, disk, central_disk, disk_entries, entries, central_size, central_offset, comment = eocd
        if signature != zipfile.stringEndArchive:
            raise AuralError('Missing ZIP end-of-central-directory record')
        if comment:
            raise AuralError('ZIP comments are not allowed in draft 0.1')

        uses_zip64 = (disk == 0xffff or central_disk == 0xffff
                      or disk_entries == 0xffff or entries == 0xffff
                      or central_size == 0xffffffff or central_offset == 0xffffffff)
        directory_end = eocd_offset
        if uses_zip64:
            locator_offset = eocd_offset - 20
            if locator_offset < 0:
                raise AuralError('Missing ZIP64 locator')
            source.seek(locator_offset)
            locator = struct.unpack(
                '<4sLQL', _read_exact(source, 20, 'ZIP64 locator'),
            )
            locator_signature, locator_disk, zip64_offset, total_disks = locator
            if locator_signature != zipfile.stringEndArchive64Locator:
                raise AuralError('Missing ZIP64 locator')
            if locator_disk != 0 or total_disks != 1:
                raise AuralError('Multi-disk ZIP64 archives are not allowed')
            if zip64_offset + 56 > locator_offset:
                raise AuralError('Invalid ZIP64 end-record offset')
            source.seek(zip64_offset)
            zip64 = struct.unpack(
                '<4sQ2H2L4Q', _read_exact(source, 56, 'ZIP64 end record'),
            )
            (zip64_signature, record_size, _made_by, _needed, zip64_disk,
             zip64_central_disk, zip64_disk_entries, zip64_entries,
             zip64_central_size, zip64_central_offset) = zip64
            if zip64_signature != zipfile.stringEndArchive64:
                raise AuralError('Missing ZIP64 end record')
            if record_size < 44 or record_size > MAX_ZIP64_END_RECORD:
                raise AuralError('Invalid ZIP64 end-record size')
            if zip64_offset + 12 + record_size != locator_offset:
                raise AuralError('Contradictory ZIP64 end-record size or offset')
            if zip64_disk != 0 or zip64_central_disk != 0:
                raise AuralError('Multi-disk ZIP64 archives are not allowed')
            if zip64_disk_entries != zip64_entries:
                raise AuralError('Contradictory ZIP64 entry counts')
            comparisons = (
                (disk, zip64_disk, 0xffff),
                (central_disk, zip64_central_disk, 0xffff),
                (disk_entries, zip64_disk_entries, 0xffff),
                (entries, zip64_entries, 0xffff),
                (central_size, zip64_central_size, 0xffffffff),
                (central_offset, zip64_central_offset, 0xffffffff),
            )
            if any(classic not in (actual, sentinel)
                   for classic, actual, sentinel in comparisons):
                raise AuralError('Classic and ZIP64 end records disagree')
            disk_entries, entries = zip64_disk_entries, zip64_entries
            central_size, central_offset = zip64_central_size, zip64_central_offset
            directory_end = zip64_offset
        elif disk != 0 or central_disk != 0 or disk_entries != entries:
            raise AuralError('Multi-disk or contradictory ZIP metadata')

        if entries > MAX_ENTRIES:
            raise AuralError('ZIP entry count exceeds implementation limit')
        if central_size > MAX_CENTRAL_DIRECTORY:
            raise AuralError('Central-directory size exceeds implementation limit')
        if entries * 46 > central_size:
            raise AuralError('Central-directory size is inconsistent with entry count')
        if central_offset + central_size != directory_end:
            raise AuralError('Central-directory offset or size is contradictory')
        source.seek(central_offset)
        central = _read_exact(source, central_size, 'central directory')
        return _scan_central_directory(source, central, entries, central_offset)
    finally:
        source.seek(current)

def _validate_zip_envelope(z, infos):
    """Reject bytes that ZIP readers can hide outside the declared entries."""
    if z.comment or any(info.comment for info in infos):
        raise AuralError('ZIP comments are not allowed in draft 0.1')
    if not infos or min(info.header_offset for info in infos) != 0:
        raise AuralError('ZIP preamble is not allowed in draft 0.1')
    current = z.fp.tell()
    try:
        z.fp.seek(-22, os.SEEK_END)
        if z.fp.read(4) != zipfile.stringEndArchive:
            raise AuralError('Trailing data is not allowed after the ZIP archive')
    finally:
        z.fp.seek(current)

def _parse_manifest(raw):
    def unique_keys(pairs):
        obj = {}
        for key, val in pairs:
            if key in obj:
                raise AuralError('Duplicate JSON key')
            obj[key] = val
        return obj

    doc = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_keys)
    if not isinstance(doc, dict) or set(doc) != MANIFEST_KEYS:
        raise AuralError('Invalid manifest fields')
    if doc['format'] != FORMAT or doc['version'] != VERSION:
        raise AuralError('Wrong format or unsupported draft version')
    if not isinstance(doc['title'], str):
        raise AuralError('Manifest title must be a string')
    if doc['recorded_at'] is not None and not isinstance(doc['recorded_at'], str):
        raise AuralError('Manifest recorded_at must be a string or null')
    assets = doc['assets']
    if not isinstance(assets, list) or len(assets) != 1:
        raise AuralError('Draft 0.1 requires exactly one asset')
    asset = assets[0]
    if not isinstance(asset, dict) or set(asset) != ASSET_KEYS:
        raise AuralError('Invalid asset descriptor')
    if (asset['path'] != 'audio/original.wav' or doc['original'] != asset['path']
            or asset['role'] != 'original' or asset['media_type'] != 'audio/wav'):
        raise AuralError('Invalid original audio descriptor')
    if type(asset['size']) is not int:
        raise AuralError('Audio size must be an integer')
    if not isinstance(asset['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', asset['sha256']):
        raise AuralError('Malformed SHA-256')
    if canonical_json(doc) != raw:
        raise AuralError('Manifest is not canonical JSON')
    return doc, asset

def _verify_archive(z, expected_names, audio_target=None):
    infos = z.infolist()
    names = [i.filename for i in infos]
    if len(infos) != len(expected_names):
        raise AuralError('ZIP entry count changed after preflight')
    for info, expected_name in zip(infos, expected_names):
        if (info.orig_filename != expected_name or info.filename != info.orig_filename
                or '\x00' in info.orig_filename):
            raise AuralError('ZIP parser filename differs from raw member name')
    if not names or len(names) > MAX_ENTRIES or len(names) != len(set(names)):
        raise AuralError('Empty archive, duplicate names, or too many entries')
    _validate_zip_envelope(z, infos)
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
    doc, asset = _parse_manifest(z.read('manifest.json'))
    if set(names) != {'manifest.json', asset['path']}:
        raise AuralError('Undeclared or missing archive entry')
    info = z.getinfo(asset['path'])
    if asset['size'] != info.file_size or info.file_size > MAX_AUDIO:
        raise AuralError('Audio size mismatch')
    with z.open(asset['path']) as f:
        header = f.read(12)
        if not (header[:4] in (b'RIFF', b'RF64') and header[8:] == b'WAVE'):
            raise AuralError('Invalid WAV signature')
        digest = hashlib.sha256(header)
        if audio_target is not None:
            audio_target.write(header)
        for block in iter(lambda: f.read(CHUNK), b''):
            digest.update(block)
            if audio_target is not None:
                audio_target.write(block)
    if digest.hexdigest() != asset['sha256']:
        raise AuralError('SHA-256 mismatch: audio modified or corrupt')
    return {'status': 'integrity_valid', 'version': VERSION,
            'audio_sha256': asset['sha256'], 'audio_bytes': info.file_size,
            'warning': 'No source authenticity or signer identity verification in draft 0.1'}

def verify(path):
    """Verify declared payload hashes and conservative ZIP/profile structure.

    NOT proof of recording authenticity, sender identity, or chain of custody.
    """
    try:
        with _archive_source(path) as source:
            expected_names = _preflight_archive(source)
            source.seek(0)
            with zipfile.ZipFile(source, 'r', allowZip64=True) as z:
                return _verify_archive(z, expected_names)
    except AuralError:
        raise
    except INVALID_PACKAGE_ERRORS as exc:
        raise AuralError(f'Invalid AURAL package: {exc}') from exc

def extract(path, destination):
    destination = Path(destination)
    if destination.exists():
        raise AuralError('Refusing to overwrite existing output')
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.aural-extract-', dir=destination.parent)
    try:
        try:
            target = os.fdopen(fd, 'wb')
            fd = None
            with target, _archive_source(path) as source:
                expected_names = _preflight_archive(source)
                source.seek(0)
                with zipfile.ZipFile(source, 'r', allowZip64=True) as z:
                    _verify_archive(z, expected_names, audio_target=target)
        except AuralError:
            raise
        except INVALID_PACKAGE_ERRORS as exc:
            raise AuralError(f'Invalid AURAL package: {exc}') from exc
        try:
            os.link(tmp, destination)
        except FileExistsError as exc:
            raise AuralError('Refusing to overwrite existing output') from exc
        os.unlink(tmp)
    finally:
        if fd is not None:
            os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)
    return destination
