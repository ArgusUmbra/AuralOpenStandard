"""AURAL Draft 0.2 writer and verifier with a distinct Draft 0.1 path."""
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import tempfile
import zipfile

FORMAT = 'org.aural.audio-evidence'
VERSION = '0.2-draft'
LEGACY_VERSION = '0.1-draft'
MAX_MANIFEST = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_ENTRIES = 1000  # Preflight ceiling; Draft 0.2 requires exactly two.
MAX_TOTAL_UNCOMPRESSED = 10 * 1024**3
MAX_AUDIO = 8 * 1024**3
MAX_ARCHIVE_SIZE = MAX_AUDIO + 16 * 1024**2
MAX_CENTRAL_DIRECTORY = 4 * 1024**2
MAX_ZIP64_END_RECORD = 64 * 1024
MAX_SAFE_INTEGER = 9007199254740991
MAX_TITLE = 4096
CHUNK = 1024 * 1024

LEGACY_MANIFEST_KEYS = {'format', 'version', 'title', 'recorded_at', 'original', 'assets'}
V02_REQUIRED_KEYS = {'format', 'version', 'original', 'assets'}
V02_OPTIONAL_KEYS = {'title', 'recorded_at', 'extensions', 'critical_extensions'}
ASSET_KEYS = {'path', 'role', 'media_type', 'size', 'sha256'}
V02_NAMES = {'manifest.json', 'audio/original.wav'}
SUPPORTED_EXTENSIONS = frozenset()
RFC3339_RE = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})'
    r'(?:\.([0-9]{1,9}))?(Z|[+-]\d{2}:\d{2})$'
)
EXTENSION_ID_RE = re.compile(r'^[a-z][a-z0-9+.-]*:[\x21-\x7e]+$')
INVALID_PACKAGE_ERRORS = (
    zipfile.BadZipFile, json.JSONDecodeError, UnicodeError, KeyError, TypeError,
    AttributeError, OSError, EOFError, RecursionError, OverflowError, ValueError,
    struct.error,
)


class AuralError(ValueError):
    pass


def _invalid_scalar(text):
    for char in text:
        value = ord(char)
        if 0xD800 <= value <= 0xDFFF:
            return True
        if 0xFDD0 <= value <= 0xFDEF or value & 0xFFFF in (0xFFFE, 0xFFFF):
            return True
    return False


def _check_ijson(value, containing_depth=0):
    if value is None or isinstance(value, bool):
        return
    if type(value) is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise AuralError('JSON integer exceeds interoperable range')
        return
    if isinstance(value, float):
        raise AuralError('Draft 0.2 JSON numbers must be integers')
    if isinstance(value, str):
        if _invalid_scalar(value):
            raise AuralError('JSON strings must contain Unicode scalar values')
        return
    if isinstance(value, list):
        depth = containing_depth + 1
        if depth > MAX_JSON_DEPTH:
            raise AuralError('Manifest nesting exceeds Draft 0.2 limit')
        for item in value:
            _check_ijson(item, depth)
        return
    if isinstance(value, dict):
        depth = containing_depth + 1
        if depth > MAX_JSON_DEPTH:
            raise AuralError('Manifest nesting exceeds Draft 0.2 limit')
        for key, item in value.items():
            if not isinstance(key, str) or _invalid_scalar(key):
                raise AuralError('JSON object names must contain Unicode scalar values')
            _check_ijson(item, depth)
        return
    raise AuralError('Value is not representable as interoperable JSON')


def _jcs_string(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def _jcs_text(value):
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if type(value) is int:
        return str(value)
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, list):
        return '[' + ','.join(_jcs_text(item) for item in value) + ']'
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode('utf-16-be'))
        return '{' + ','.join(
            _jcs_string(key) + ':' + _jcs_text(value[key]) for key in keys
        ) + '}'
    raise AuralError('Value is outside the Draft 0.2 JCS profile')


def canonical_json(value):
    """Return RFC 8785 bytes for the Draft 0.2 integer-only I-JSON profile."""
    _check_ijson(value)
    return _jcs_text(value).encode('utf-8')


def _legacy_canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for block in iter(lambda: source.read(CHUNK), b''):
            digest.update(block)
    return digest.hexdigest()


def _valid_rfc3339(value):
    match = RFC3339_RE.fullmatch(value)
    if not match or value.endswith('-00:00'):
        return False
    year, month, day, hour, minute, second = map(int, match.groups()[:6])
    if year == 0 or second > 59:
        return False
    zone = match.group(8)
    if zone != 'Z':
        zone_hour, zone_minute = map(int, zone[1:].split(':'))
        if zone_hour > 14 or zone_minute > 59 or (zone_hour == 14 and zone_minute != 0):
            return False
    try:
        datetime(year, month, day, hour, minute, second)
    except ValueError:
        return False
    return True


def _new_zip_info(name):
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 0
    info.external_attr = 0x20
    return info


def package(source, destination, title='', recorded_at=None):
    """Write a Draft 0.2 package while preserving the source bytes exactly."""
    source, destination = Path(source), Path(destination)
    if source.suffix.lower() != '.wav' or not source.is_file():
        raise AuralError('Draft 0.2 accepts an existing WAV file only')
    if destination.resolve() == source.resolve():
        raise AuralError('Source and destination must differ')
    if not isinstance(title, str) or len(title) > MAX_TITLE or _invalid_scalar(title):
        raise AuralError('Title must be at most 4096 Unicode scalar values')
    if recorded_at is not None and (
            not isinstance(recorded_at, str) or not _valid_rfc3339(recorded_at)):
        raise AuralError('recorded_at must be a Draft 0.2 RFC 3339 timestamp')
    size = source.stat().st_size
    if size > MAX_AUDIO:
        raise AuralError('Audio exceeds Draft 0.2 size limit')
    with source.open('rb') as audio:
        start = audio.read(12)
    if not (start[:4] in (b'RIFF', b'RF64') and start[8:] == b'WAVE'):
        raise AuralError('Audio does not appear to be RIFF WAVE or RF64 WAVE')

    name = 'audio/original.wav'
    manifest = {
        'format': FORMAT,
        'version': VERSION,
        'original': name,
        'assets': [{'path': name, 'role': 'original', 'media_type': 'audio/wav',
                    'size': size, 'sha256': sha256_file(source)}],
    }
    if title:
        manifest['title'] = title
    if recorded_at is not None:
        manifest['recorded_at'] = recorded_at
    manifest_bytes = canonical_json(manifest)
    if len(manifest_bytes) > MAX_MANIFEST:
        raise AuralError('Manifest exceeds Draft 0.2 size limit')

    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.aural-', suffix='.tmp', dir=destination.parent)
    os.close(fd)
    try:
        with zipfile.ZipFile(tmp, 'w', allowZip64=True) as archive:
            archive.writestr(_new_zip_info('manifest.json'), manifest_bytes)
            audio_info = _new_zip_info(name)
            audio_info.file_size = size
            with source.open('rb') as audio, archive.open(
                    audio_info, 'w', force_zip64=size >= zipfile.ZIP64_LIMIT) as target:
                shutil.copyfileobj(audio, target, CHUNK)
        verify(tmp)
        os.replace(tmp, destination)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return manifest


def _safe_name(name):
    return (bool(name) and '\x00' not in name and '\\' not in name
            and not name.startswith('/') and not re.match(r'^[A-Za-z]:', name)
            and all(segment not in ('', '.', '..') for segment in name.split('/')))


def _file_snapshot(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@contextmanager
def _archive_source(path):
    """Yield one stable package handle; caller-owned file-like inputs are unchanged.

    Path inputs must remain the same regular, non-symlink file for the complete
    operation. Metadata checks detect ordinary replacement and modification,
    but cannot defend against a hostile filesystem that restores metadata.
    """
    if hasattr(path, 'read') and hasattr(path, 'seek'):
        yield path
        return

    try:
        path_before = os.lstat(path)
    except (OSError, TypeError, ValueError) as exc:
        raise AuralError(f'Cannot inspect AURAL package path: {exc}') from exc
    if stat.S_ISLNK(path_before.st_mode):
        raise AuralError('AURAL package path must not be a symbolic link')
    if not stat.S_ISREG(path_before.st_mode):
        raise AuralError('AURAL package path must identify a regular file')

    flags = os.O_RDONLY
    for name in ('O_BINARY', 'O_CLOEXEC', 'O_NOINHERIT', 'O_NONBLOCK', 'O_NOFOLLOW'):
        flags |= getattr(os, name, 0)
    try:
        descriptor = os.open(path, flags)
    except (OSError, TypeError, ValueError) as exc:
        raise AuralError(f'Cannot open AURAL package path safely: {exc}') from exc

    try:
        handle_before = os.fstat(descriptor)
        if not stat.S_ISREG(handle_before.st_mode):
            raise AuralError('AURAL package handle must identify a regular file')
        if _file_snapshot(path_before) != _file_snapshot(handle_before):
            raise AuralError('AURAL package changed while it was being opened')

        with open(descriptor, 'rb', closefd=True) as source:
            descriptor = None
            yield source
            try:
                handle_after = os.fstat(source.fileno())
                path_after = os.lstat(path)
            except OSError as exc:
                raise AuralError(
                    f'AURAL package changed or disappeared during verification: {exc}'
                ) from exc
            if (stat.S_ISLNK(path_after.st_mode)
                    or not stat.S_ISREG(path_after.st_mode)
                    or _file_snapshot(handle_before) != _file_snapshot(handle_after)
                    or _file_snapshot(handle_before) != _file_snapshot(path_after)):
                raise AuralError('AURAL package changed during verification')
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_exact(source, size, description):
    data = source.read(size)
    if len(data) != size:
        raise AuralError(f'Truncated {description}')
    return data


def _extra_fields(extra):
    fields = []
    cursor = 0
    while cursor < len(extra):
        if len(extra) - cursor < 4:
            raise AuralError('Malformed ZIP extra field')
        field_id, field_size = struct.unpack_from('<HH', extra, cursor)
        cursor += 4
        end = cursor + field_size
        if end > len(extra):
            raise AuralError('Malformed ZIP extra field')
        fields.append((field_id, bytes(extra[cursor:end])))
        cursor = end
    return fields


def _zip64_field(fields):
    values = [data for field_id, data in fields if field_id == 0x0001]
    if len(values) > 1:
        raise AuralError('Duplicate ZIP64 extra field')
    return values[0] if values else None


def _take_zip64(data, position, size):
    if data is None or position + size > len(data):
        raise AuralError('Missing or truncated ZIP64 extra field')
    return int.from_bytes(data[position:position + size], 'little'), position + size


def _central_zip64(fields, uncompressed, compressed, local_offset, disk):
    data = _zip64_field(fields)
    position = 0
    required = (uncompressed == 0xffffffff, compressed == 0xffffffff,
                local_offset == 0xffffffff, disk == 0xffff)
    if uncompressed == 0xffffffff:
        uncompressed, position = _take_zip64(data, position, 8)
    if compressed == 0xffffffff:
        compressed, position = _take_zip64(data, position, 8)
    if local_offset == 0xffffffff:
        local_offset, position = _take_zip64(data, position, 8)
    if disk == 0xffff:
        disk, position = _take_zip64(data, position, 4)
    # Draft 0.1 did not prohibit a well-framed but unnecessary ZIP64 field,
    # and the Assignment 002 verifier ignored it.  Exact necessity is a
    # Draft 0.2 conformance rule applied after version dispatch.
    if data is not None and any(required) and position != len(data):
        raise AuralError('Unnecessary or oversized ZIP64 extra field')
    return uncompressed, compressed, local_offset, disk


def _local_zip64(fields, uncompressed, compressed):
    data = _zip64_field(fields)
    position = 0
    required = (uncompressed == 0xffffffff, compressed == 0xffffffff)
    if uncompressed == 0xffffffff:
        uncompressed, position = _take_zip64(data, position, 8)
    if compressed == 0xffffffff:
        compressed, position = _take_zip64(data, position, 8)
    if data is not None and any(required) and position != len(data):
        raise AuralError('Unnecessary or oversized ZIP64 extra field')
    return uncompressed, compressed


def _scan_central_directory(source, central, declared_entries, central_offset):
    entries = []
    cursor = 0
    for _ in range(declared_entries):
        if len(central) - cursor < 46:
            raise AuralError('Central-directory entry count is contradictory')
        fields = struct.unpack_from('<4s6H3L5H2L', central, cursor)
        if fields[0] != zipfile.stringCentralDir:
            raise AuralError('Malformed central-directory entry')
        (made_by, needed, flags, compression, mod_time, mod_date, crc,
         compressed, uncompressed, name_size, extra_size, comment_size,
         disk, internal_attr, external_attr, local_offset) = fields[1:]
        entry_end = cursor + 46 + name_size + extra_size + comment_size
        if entry_end > len(central):
            raise AuralError('Truncated central-directory entry')
        name_start = cursor + 46
        raw_name = bytes(central[name_start:name_start + name_size])
        extra_start = name_start + name_size
        raw_extra = bytes(central[extra_start:extra_start + extra_size])
        comment = bytes(central[extra_start + extra_size:entry_end])
        central_extras = _extra_fields(raw_extra)
        if b'\x00' in raw_name:
            raise AuralError('NUL byte is not allowed in ZIP member names')
        encoding = 'utf-8' if flags & 0x800 else 'cp437'
        name = raw_name.decode(encoding)
        central_zip64_required = (
            uncompressed == 0xffffffff, compressed == 0xffffffff,
            local_offset == 0xffffffff, disk == 0xffff,
        )
        uncompressed, compressed, local_offset, disk = _central_zip64(
            central_extras, uncompressed, compressed, local_offset, disk)
        if disk != 0:
            raise AuralError('Multi-disk ZIP archives are not allowed')
        if local_offset + 30 > central_offset:
            raise AuralError('Invalid local-file-header offset')

        position = source.tell()
        try:
            source.seek(local_offset)
            local = struct.unpack('<4s5H3L2H', _read_exact(source, 30, 'local file header'))
            if local[0] != zipfile.stringFileHeader:
                raise AuralError('Malformed local file header')
            (local_needed, local_flags, local_compression, local_time, local_date,
             local_crc, local_compressed, local_uncompressed,
             local_name_size, local_extra_size) = local[1:]
            header_end = local_offset + 30 + local_name_size + local_extra_size
            if header_end > central_offset:
                raise AuralError('Local file header overlaps central directory')
            local_name = _read_exact(source, local_name_size, 'local member name')
            local_extra_raw = _read_exact(source, local_extra_size, 'local extra field')
            local_extras = _extra_fields(local_extra_raw)
            local_zip64_required = (
                local_uncompressed == 0xffffffff,
                local_compressed == 0xffffffff,
            )
            local_uncompressed, local_compressed = _local_zip64(
                local_extras, local_uncompressed, local_compressed)
            if local_name != raw_name:
                raise AuralError('Local and central ZIP member names differ')
            if local_flags != flags or local_compression != compression:
                raise AuralError('Local and central ZIP metadata differ')
        finally:
            source.seek(position)

        data_end = header_end + compressed
        if data_end > central_offset:
            raise AuralError('ZIP member data overlaps central directory')
        entries.append({
            'name': name, 'raw_name': raw_name, 'flags': flags,
            'compression': compression, 'crc': crc, 'compressed': compressed,
            'uncompressed': uncompressed, 'local_offset': local_offset,
            'header_end': header_end, 'data_end': data_end, 'made_by': made_by,
            'needed': needed, 'mod_time': mod_time, 'mod_date': mod_date,
            'internal_attr': internal_attr, 'external_attr': external_attr,
            'comment': comment, 'central_extras': central_extras,
            'central_zip64_required': central_zip64_required,
            'local_extras': local_extras, 'local_needed': local_needed,
            'local_zip64_required': local_zip64_required,
            'local_flags': local_flags, 'local_compression': local_compression,
            'local_time': local_time, 'local_date': local_date,
            'local_crc': local_crc, 'local_compressed': local_compressed,
            'local_uncompressed': local_uncompressed,
        })
        cursor = entry_end

    if cursor != len(central):
        raise AuralError('Central-directory size or entry count is contradictory')
    offsets = [entry['local_offset'] for entry in entries]
    if not offsets or min(offsets) != 0:
        raise AuralError('ZIP preamble is not allowed')
    if len(offsets) != len(set(offsets)):
        raise AuralError('ZIP members cannot share a local file header')
    return entries


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
        eocd = struct.unpack('<4s4H2LH', _read_exact(
            source, 22, 'ZIP end-of-central-directory record'))
        (signature, disk, central_disk, disk_entries, entries,
         central_size, central_offset, comment) = eocd
        if signature != zipfile.stringEndArchive:
            raise AuralError('Missing ZIP end-of-central-directory record')
        if comment:
            raise AuralError('ZIP comments are not allowed')

        uses_zip64 = (disk == 0xffff or central_disk == 0xffff
                      or disk_entries == 0xffff or entries == 0xffff
                      or central_size == 0xffffffff or central_offset == 0xffffffff)
        directory_end = eocd_offset
        zip64_record_size = None
        zip64_needed = None
        if uses_zip64:
            locator_offset = eocd_offset - 20
            if locator_offset < 0:
                raise AuralError('Missing ZIP64 locator')
            source.seek(locator_offset)
            locator = struct.unpack('<4sLQL', _read_exact(source, 20, 'ZIP64 locator'))
            locator_signature, locator_disk, zip64_offset, total_disks = locator
            if locator_signature != zipfile.stringEndArchive64Locator:
                raise AuralError('Missing ZIP64 locator')
            if locator_disk != 0 or total_disks != 1:
                raise AuralError('Multi-disk ZIP64 archives are not allowed')
            if zip64_offset + 56 > locator_offset:
                raise AuralError('Invalid ZIP64 end-record offset')
            source.seek(zip64_offset)
            zip64 = struct.unpack('<4sQ2H2L4Q', _read_exact(
                source, 56, 'ZIP64 end record'))
            (zip64_signature, zip64_record_size, _made_by, zip64_needed, zip64_disk,
             zip64_central_disk, zip64_disk_entries, zip64_entries,
             zip64_central_size, zip64_central_offset) = zip64
            if zip64_signature != zipfile.stringEndArchive64:
                raise AuralError('Missing ZIP64 end record')
            if not 44 <= zip64_record_size <= MAX_ZIP64_END_RECORD:
                raise AuralError('Invalid ZIP64 end-record size')
            if zip64_offset + 12 + zip64_record_size != locator_offset:
                raise AuralError('Contradictory ZIP64 end-record size or offset')
            if zip64_disk != 0 or zip64_central_disk != 0:
                raise AuralError('Multi-disk ZIP64 archives are not allowed')
            if zip64_disk_entries != zip64_entries:
                raise AuralError('Contradictory ZIP64 entry counts')
            comparisons = (
                (disk, zip64_disk, 0xffff), (central_disk, zip64_central_disk, 0xffff),
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
        else:
            if eocd_offset >= 20:
                source.seek(eocd_offset - 20)
                if _read_exact(source, 4, 'pre-EOCD record') == zipfile.stringEndArchive64Locator:
                    raise AuralError('Unnecessary ZIP64 end records are not allowed')
            if disk != 0 or central_disk != 0 or disk_entries != entries:
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
        scanned = _scan_central_directory(source, central, entries, central_offset)
        return {'entries': scanned, 'uses_zip64': uses_zip64,
                'zip64_record_size': zip64_record_size,
                'zip64_needed': zip64_needed,
                'central_offset': central_offset, 'physical_size': physical_size}
    finally:
        source.seek(current)


def _validate_zip_envelope(archive, infos):
    if archive.comment or any(info.comment for info in infos):
        raise AuralError('ZIP comments are not allowed')
    if not infos or min(info.header_offset for info in infos) != 0:
        raise AuralError('ZIP preamble is not allowed')
    current = archive.fp.tell()
    try:
        archive.fp.seek(-22, os.SEEK_END)
        if archive.fp.read(4) != zipfile.stringEndArchive:
            raise AuralError('Trailing data is not allowed after the ZIP archive')
    finally:
        archive.fp.seek(current)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuralError('Duplicate JSON key')
        result[key] = value
    return result


def _reject_float(_value):
    raise AuralError('Draft 0.2 JSON numbers must be integers')


def _safe_int(value):
    parsed = int(value)
    if not -MAX_SAFE_INTEGER <= parsed <= MAX_SAFE_INTEGER:
        raise AuralError('JSON integer exceeds interoperable range')
    return parsed


def _reject_constant(_value):
    raise AuralError('Non-finite JSON numbers are not allowed')


def _raw_json_depth(raw):
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5c:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x7b, 0x5b):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise AuralError('Manifest nesting exceeds Draft 0.2 limit')
        elif byte in (0x7d, 0x5d):
            depth -= 1


def _load_json(raw, strict_v02=False):
    if strict_v02:
        _raw_json_depth(raw)
    text = raw.decode('utf-8')
    kwargs = {'object_pairs_hook': _unique_object, 'parse_constant': _reject_constant}
    if strict_v02:
        kwargs.update(parse_int=_safe_int, parse_float=_reject_float)
    return json.loads(text, **kwargs)


def _parse_legacy_manifest(raw, document):
    if not isinstance(document, dict) or set(document) != LEGACY_MANIFEST_KEYS:
        raise AuralError('Invalid Draft 0.1 manifest fields')
    if document['format'] != FORMAT or document['version'] != LEGACY_VERSION:
        raise AuralError('Wrong format or unsupported draft version')
    if not isinstance(document['title'], str):
        raise AuralError('Manifest title must be a string')
    if document['recorded_at'] is not None and not isinstance(document['recorded_at'], str):
        raise AuralError('Manifest recorded_at must be a string or null')
    assets = document['assets']
    if not isinstance(assets, list) or len(assets) != 1:
        raise AuralError('Draft 0.1 requires exactly one asset')
    asset = assets[0]
    if not isinstance(asset, dict) or set(asset) != ASSET_KEYS:
        raise AuralError('Invalid asset descriptor')
    if (asset['path'] != 'audio/original.wav' or document['original'] != asset['path']
            or asset['role'] != 'original' or asset['media_type'] != 'audio/wav'):
        raise AuralError('Invalid original audio descriptor')
    if type(asset['size']) is not int:
        raise AuralError('Audio size must be an integer')
    if not isinstance(asset['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', asset['sha256']):
        raise AuralError('Malformed SHA-256')
    if _legacy_canonical_json(document) != raw:
        raise AuralError('Draft 0.1 manifest is not canonical JSON')
    return document, asset, LEGACY_VERSION


def _valid_extension_id(value):
    return (isinstance(value, str) and len(value) <= 255
            and EXTENSION_ID_RE.fullmatch(value) is not None)


def _parse_v02_manifest(raw, initial_document):
    document = _load_json(raw, strict_v02=True)
    if document != initial_document:
        raise AuralError('Manifest parsing was inconsistent')
    _check_ijson(document)
    if not isinstance(document, dict):
        raise AuralError('Draft 0.2 manifest must be an object')
    keys = set(document)
    if not V02_REQUIRED_KEYS <= keys or not keys <= V02_REQUIRED_KEYS | V02_OPTIONAL_KEYS:
        raise AuralError('Invalid or unknown Draft 0.2 manifest fields')
    if document['format'] != FORMAT or document['version'] != VERSION:
        raise AuralError('Wrong format or unsupported draft version')
    if document['original'] != 'audio/original.wav':
        raise AuralError('Invalid original asset path')
    if 'title' in document and (
            not isinstance(document['title'], str) or len(document['title']) > MAX_TITLE):
        raise AuralError('Manifest title must be a string of at most 4096 characters')
    if 'recorded_at' in document and (
            not isinstance(document['recorded_at'], str)
            or not _valid_rfc3339(document['recorded_at'])):
        raise AuralError('Manifest recorded_at is not a Draft 0.2 RFC 3339 timestamp')
    assets = document['assets']
    if not isinstance(assets, list) or len(assets) != 1:
        raise AuralError('Draft 0.2 requires exactly one asset')
    asset = assets[0]
    if not isinstance(asset, dict) or set(asset) != ASSET_KEYS:
        raise AuralError('Invalid Draft 0.2 asset descriptor')
    if (asset['path'] != document['original'] or asset['role'] != 'original'
            or asset['media_type'] != 'audio/wav'):
        raise AuralError('Invalid original audio descriptor')
    if type(asset['size']) is not int or not 0 <= asset['size'] <= MAX_AUDIO:
        raise AuralError('Audio size must be a non-negative bounded integer')
    if not isinstance(asset['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', asset['sha256']):
        raise AuralError('Malformed SHA-256')

    extensions = document.get('extensions', {})
    if not isinstance(extensions, dict) or any(
            not _valid_extension_id(identifier) for identifier in extensions):
        raise AuralError('Extension identifiers do not match the AURAL URI-form syntax')
    critical = document.get('critical_extensions', [])
    if (not isinstance(critical, list) or any(not isinstance(item, str) for item in critical)
            or len(critical) != len(set(critical))):
        raise AuralError('critical_extensions must be an array of unique identifiers')
    if any(not _valid_extension_id(identifier) for identifier in critical):
        raise AuralError('Invalid critical extension identifier')
    if any(identifier not in extensions for identifier in critical):
        raise AuralError('Every critical extension must have an extension value')
    unsupported = [identifier for identifier in critical
                   if identifier not in SUPPORTED_EXTENSIONS]
    if unsupported:
        raise AuralError(f'Unknown critical extension: {unsupported[0]}')
    if canonical_json(document) != raw:
        raise AuralError('Draft 0.2 manifest is not RFC 8785 canonical JSON')
    return document, asset, VERSION


def _manifest_identity(raw):
    if len(raw) > MAX_MANIFEST:
        raise AuralError('Manifest exceeds Draft 0.2 size limit')
    _raw_json_depth(raw)
    document = _load_json(raw)
    if not isinstance(document, dict):
        raise AuralError('Manifest must be a JSON object')
    if document.get('format') != FORMAT:
        raise AuralError('Wrong AURAL format identifier')
    version = document.get('version')
    if version not in (LEGACY_VERSION, VERSION):
        raise AuralError(f'Unsupported AURAL version: {version!r}')
    return document, version


def _parse_manifest(raw, document=None):
    if document is None:
        document, version = _manifest_identity(raw)
    else:
        version = document.get('version')
    if version == LEGACY_VERSION:
        return _parse_legacy_manifest(raw, document)
    if version == VERSION:
        return _parse_v02_manifest(raw, document)
    raise AuralError(f'Unsupported AURAL version: {version!r}')


def _validate_v02_zip(preflight):
    entries = preflight['entries']
    if len(entries) != 2 or {entry['name'] for entry in entries} != V02_NAMES:
        raise AuralError('Draft 0.2 requires exactly its two declared entries')
    ordered = sorted(entries, key=lambda entry: entry['local_offset'])
    if ordered[0]['local_offset'] != 0:
        raise AuralError('ZIP prefix is not allowed')
    for first, second in zip(ordered, ordered[1:]):
        if first['data_end'] != second['local_offset']:
            raise AuralError('Undeclared data or overlap exists between ZIP entries')
    if ordered[-1]['data_end'] != preflight['central_offset']:
        raise AuralError('Undeclared data exists before the central directory')
    if preflight['uses_zip64'] and preflight['zip64_record_size'] != 44:
        raise AuralError('ZIP64 extensible data is not allowed in Draft 0.2')
    if preflight['uses_zip64'] and preflight['zip64_needed'] != 45:
        raise AuralError('ZIP64 end record must require ZIP version 4.5')

    if {entry['raw_name'] for entry in entries} != {b'manifest.json', b'audio/original.wav'}:
        raise AuralError('Draft 0.2 member names must use exact ASCII bytes')
    for entry in entries:
        if entry['flags'] not in (0, 0x0800):
            raise AuralError('Unsupported ZIP general-purpose flags')
        if entry['compression'] != 0 or entry['compressed'] != entry['uncompressed']:
            raise AuralError('Draft 0.2 entries must use stored compression method 0')
        if entry['comment']:
            raise AuralError('ZIP entry comments are not allowed')
        if any(field_id != 0x0001 for field_id, _ in
               entry['central_extras'] + entry['local_extras']):
            raise AuralError('Only ZIP64 extra fields are allowed')
        central_zip64 = any(field_id == 0x0001 for field_id, _ in entry['central_extras'])
        local_zip64 = any(field_id == 0x0001 for field_id, _ in entry['local_extras'])
        if ((central_zip64 and not any(entry['central_zip64_required']))
                or (local_zip64 and not any(entry['local_zip64_required']))):
            raise AuralError('Unnecessary ZIP64 extra field is not allowed in Draft 0.2')
        if (entry['needed'] != entry['local_needed']
                or entry['mod_time'] != entry['local_time']
                or entry['mod_date'] != entry['local_date']
                or entry['crc'] != entry['local_crc']
                or entry['compressed'] != entry['local_compressed']
                or entry['uncompressed'] != entry['local_uncompressed']):
            raise AuralError('Local and central ZIP header values differ')
        if entry['needed'] not in (10, 20, 45):
            raise AuralError('Unsupported ZIP version-needed value')
        if (entry['central_extras'] or entry['local_extras']) and entry['needed'] != 45:
            raise AuralError('ZIP64 entries must require ZIP version 4.5')
        mode_type = (entry['external_attr'] >> 16) & 0o170000
        if mode_type not in (0, 0o100000) or entry['external_attr'] & 0x10:
            raise AuralError('ZIP members must describe regular files')


def _verify_archive(archive, preflight, audio_target=None, *, detailed=False):
    infos = archive.infolist()
    expected_names = [entry['name'] for entry in preflight['entries']]
    names = [info.filename for info in infos]
    if len(infos) != len(expected_names):
        raise AuralError('ZIP entry count changed after preflight')
    for info, expected_name in zip(infos, expected_names):
        if (info.orig_filename != expected_name or info.filename != info.orig_filename
                or '\x00' in info.orig_filename):
            raise AuralError('ZIP parser filename differs from raw member name')
    if not names or len(names) > MAX_ENTRIES or len(names) != len(set(names)):
        raise AuralError('Empty archive, duplicate names, or too many entries')
    _validate_zip_envelope(archive, infos)
    if not all(_safe_name(name) for name in names):
        raise AuralError('Unsafe archive path')
    if any(info.is_dir() or info.flag_bits & 1 or info.compress_type != zipfile.ZIP_STORED
           for info in infos):
        raise AuralError('Directories, encryption and compression are not allowed')
    if any((info.external_attr >> 16) & 0o170000 == 0o120000 for info in infos):
        raise AuralError('Symlinks are not allowed')
    if sum(info.file_size for info in infos) > MAX_TOTAL_UNCOMPRESSED:
        raise AuralError('Archive exceeds size limit')
    if 'manifest.json' not in names or archive.getinfo('manifest.json').file_size > MAX_MANIFEST:
        raise AuralError('Missing or oversized manifest')

    manifest_raw = archive.read('manifest.json')
    initial_document, version = _manifest_identity(manifest_raw)
    # Version-independent envelope checks have already completed.  Once the
    # bounded manifest identifies Draft 0.2, enforce its complete ZIP profile
    # before application-level manifest/schema processing.
    if version == VERSION:
        _validate_v02_zip(preflight)
    _document, asset, version = _parse_manifest(manifest_raw, initial_document)
    if set(names) != {'manifest.json', asset['path']}:
        raise AuralError('Undeclared or missing archive entry')
    info = archive.getinfo(asset['path'])
    if asset['size'] != info.file_size or info.file_size > MAX_AUDIO:
        raise AuralError('Audio size mismatch')
    with archive.open(asset['path']) as audio:
        header = audio.read(12)
        if not (header[:4] in (b'RIFF', b'RF64') and header[8:] == b'WAVE'):
            raise AuralError('Invalid WAV signature')
        digest = hashlib.sha256(header)
        if audio_target is not None:
            audio_target.write(header)
        for block in iter(lambda: audio.read(CHUNK), b''):
            digest.update(block)
            if audio_target is not None:
                audio_target.write(block)
    audio_sha256 = digest.hexdigest()
    if audio_sha256 != asset['sha256']:
        raise AuralError('SHA-256 mismatch: audio modified or corrupt')
    warning = ('No source authenticity, signer identity, or chain-of-custody '
               f'verification in {version}')
    if detailed:
        if version != VERSION:
            raise AuralError('Detailed package verification requires AURAL Draft 0.2')
        return {
            'status': 'integrity_valid',
            'format': _document['format'],
            'version': version,
            'manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
            'original_path': asset['path'],
            'audio_sha256': audio_sha256,
            'audio_bytes': info.file_size,
        }
    return {
        'status': 'integrity_valid',
        'version': version,
        'legacy': version == LEGACY_VERSION,
        'audio_sha256': audio_sha256,
        'audio_bytes': info.file_size,
        'warning': warning,
    }


def _verify_path(path, *, detailed):
    try:
        with _archive_source(path) as source:
            preflight = _preflight_archive(source)
            source.seek(0)
            with zipfile.ZipFile(source, 'r', allowZip64=True) as archive:
                return _verify_archive(archive, preflight, detailed=detailed)
    except AuralError:
        raise
    except INVALID_PACKAGE_ERRORS as exc:
        raise AuralError(f'Invalid AURAL package: {exc}') from exc


def verify(path):
    """Verify structure, canonical manifest bytes, CRC32, and payload SHA-256.

    Filesystem paths must name stable regular files and must not be symlinks.
    Caller-owned seekable file-like inputs remain supported without path-based
    type or metadata-stability checks.
    """
    return _verify_path(path, detailed=False)


def verify_detailed(path):
    """Verify Draft 0.2 and return independently derived binding metadata."""
    return _verify_path(path, detailed=True)


def extract(path, destination):
    """Verify and atomically extract the original without overwriting a file."""
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
                preflight = _preflight_archive(source)
                source.seek(0)
                with zipfile.ZipFile(source, 'r', allowZip64=True) as archive:
                    _verify_archive(archive, preflight, audio_target=target)
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
