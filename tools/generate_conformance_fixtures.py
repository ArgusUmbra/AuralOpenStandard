"""Regenerate the small, deterministic AURAL Draft 0.2 conformance corpus."""
from __future__ import annotations

import binascii
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aural import core

OUT = ROOT / 'tests' / 'fixtures' / 'conformance'
AUDIO_NAME = 'audio/original.wav'


def wav_bytes(samples=b'\x00\x00' * 4):
    fmt = struct.pack('<HHIIHH', 1, 1, 8000, 16000, 2, 16)
    body = b'fmt ' + struct.pack('<I', len(fmt)) + fmt
    body += b'data' + struct.pack('<I', len(samples)) + samples
    return b'RIFF' + struct.pack('<I', 4 + len(body)) + b'WAVE' + body


def manifest(audio, **members):
    value = {
        'format': core.FORMAT,
        'version': core.VERSION,
        'original': AUDIO_NAME,
        'assets': [{
            'path': AUDIO_NAME,
            'role': 'original',
            'media_type': 'audio/wav',
            'size': len(audio),
            'sha256': hashlib.sha256(audio).hexdigest(),
        }],
    }
    value.update(members)
    return value


def write_package(path, manifest_bytes, audio, *, audio_name=AUDIO_NAME,
                  compression=zipfile.ZIP_STORED, duplicate_manifest=False):
    with zipfile.ZipFile(path, 'w', allowZip64=True) as archive:
        mi = core._new_zip_info('manifest.json')
        mi.compress_type = compression
        archive.writestr(mi, manifest_bytes)
        ai = core._new_zip_info(audio_name)
        ai.compress_type = compression
        archive.writestr(ai, audio)
        if duplicate_manifest:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                archive.writestr(core._new_zip_info('manifest.json'), manifest_bytes)


def write_raw_classic_package(path, entries, *, entry_comments=None):
    """Write the narrow classic ZIP profile without using aural.core or zipfile."""
    entry_comments = entry_comments or {}
    local = bytearray()
    central = bytearray()
    dos_date = 33  # 1980-01-01
    for name, data in entries:
        raw_name = name.encode('ascii')
        comment = entry_comments.get(name, b'')
        offset = len(local)
        crc = binascii.crc32(data) & 0xffffffff
        local += struct.pack(
            '<IHHHHHIIIHH', 0x04034b50, 20, 0, 0, 0, dos_date,
            crc, len(data), len(data), len(raw_name), 0,
        )
        local += raw_name + data
        central += struct.pack(
            '<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, 0, 0, dos_date,
            crc, len(data), len(data), len(raw_name), 0, len(comment),
            0, 0, 0, offset,
        )
        central += raw_name + comment
    archive = local + central
    archive += struct.pack(
        '<IHHHHIIH', 0x06054b50, 0, 0, len(entries), len(entries),
        len(central), len(local), 0,
    )
    path.write_bytes(archive)


def write_raw_zip64_end_package(path, entries, mode):
    """Write a classic-entry package with a controlled ZIP64 end-record chain."""
    if mode not in {'required', 'redundant', 'missing'}:
        raise ValueError(f'unsupported ZIP64 end-record mode: {mode}')
    write_raw_classic_package(path, entries)
    classic = bytearray(path.read_bytes())
    eocd = bytearray(classic[-22:])
    body = classic[:-22]
    central_size = struct.unpack_from('<I', eocd, 12)[0]
    central_offset = struct.unpack_from('<I', eocd, 16)[0]
    entry_count = struct.unpack_from('<H', eocd, 10)[0]

    # Counts are the selected sentinel fields. Keeping classic size and offset
    # non-sentinel exercises their required equality with the ZIP64 values.
    if mode in {'required', 'missing'}:
        struct.pack_into('<HH', eocd, 8, 0xffff, 0xffff)
    if mode == 'missing':
        path.write_bytes(body + eocd)
        return

    zip64_offset = len(body)
    zip64_eocd = struct.pack(
        '<IQHHIIQQQQ', 0x06064b50, 44, 45, 45, 0, 0,
        entry_count, entry_count, central_size, central_offset,
    )
    locator = struct.pack('<IIQI', 0x07064b50, 0, zip64_offset, 1)
    path.write_bytes(body + zip64_eocd + locator + eocd)


def write_with_unnecessary_zip64_extra(path, entries):
    with zipfile.ZipFile(path, 'w', allowZip64=True) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 0
            info.external_attr = 0x20
            info.extra = struct.pack('<HH', 0x0001, 0)
            archive.writestr(info, data)


def mutate(path, operation):
    payload = bytearray(path.read_bytes())
    operation(payload)
    path.write_bytes(payload)


def add(expected, name, outcome, reason):
    expected[name] = {'outcome': outcome, 'reason': reason}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    audio = wav_bytes()
    minimal = manifest(audio)
    minimal_bytes = core.canonical_json(minimal)
    expected = {}

    write_package(OUT / 'valid-minimal.aural', minimal_bytes, audio)
    add(expected, 'valid-minimal.aural', 'accept-0.2', 'minimal canonical Draft 0.2 package')

    digest = hashlib.sha256(audio).hexdigest()
    independent_manifest = (
        '{"assets":[{"media_type":"audio/wav","path":"audio/original.wav",'
        f'"role":"original","sha256":"{digest}","size":{len(audio)}}}],'
        '"format":"org.aural.audio-evidence","original":"audio/original.wav",'
        '"version":"0.2-draft"}'
    ).encode('utf-8')
    write_raw_classic_package(
        OUT / 'valid-independent.aural',
        [('manifest.json', independent_manifest), (AUDIO_NAME, audio)],
    )
    add(expected, 'valid-independent.aural', 'accept-0.2',
        'independently assembled classic ZIP and literal canonical manifest')

    write_raw_zip64_end_package(
        OUT / 'valid-required-zip64-end.aural',
        [('manifest.json', minimal_bytes), (AUDIO_NAME, audio)],
        'required',
    )
    add(expected, 'valid-required-zip64-end.aural', 'accept-0.2',
        'ZIP64 EOCD and locator required by classic EOCD count sentinels')

    write_raw_zip64_end_package(
        OUT / 'invalid-redundant-zip64-end.aural',
        [('manifest.json', minimal_bytes), (AUDIO_NAME, audio)],
        'redundant',
    )
    add(expected, 'invalid-redundant-zip64-end.aural', 'reject',
        'ZIP64 EOCD and locator are prohibited without a classic EOCD sentinel')

    write_raw_zip64_end_package(
        OUT / 'invalid-missing-required-zip64-end.aural',
        [('manifest.json', minimal_bytes), (AUDIO_NAME, audio)],
        'missing',
    )
    add(expected, 'invalid-missing-required-zip64-end.aural', 'reject',
        'classic EOCD sentinels require a ZIP64 EOCD and locator')

    unicode_doc = manifest(
        audio,
        title='Café 𝄞',
        recorded_at='2026-10-13T18:00:00Z',
        extensions={'https://example.org/optional': {'\ue000': 'BMP', '𝄞': 'supplementary'}},
    )
    golden = core.canonical_json(unicode_doc)
    (OUT / 'golden-manifest.json').write_bytes(golden)
    write_package(OUT / 'valid-unicode.aural', golden, audio)
    add(expected, 'valid-unicode.aural', 'accept-0.2', 'Unicode and UTF-16 JCS key ordering')

    optional_doc = manifest(audio, extensions={'urn:example:unknown-optional': {'count': 1}})
    write_package(OUT / 'valid-unknown-optional.aural', core.canonical_json(optional_doc), audio)
    add(expected, 'valid-unknown-optional.aural', 'accept-0.2', 'unknown non-critical extension')

    shutil.copyfile(ROOT / 'examples' / 'sample.aural', OUT / 'legacy-0.1.aural')
    add(expected, 'legacy-0.1.aural', 'accept-legacy-0.1', 'distinct Draft 0.1 compatibility path')

    with zipfile.ZipFile(ROOT / 'examples' / 'sample.aural') as legacy:
        legacy_entries = [(info.filename, legacy.read(info)) for info in legacy.infolist()]
    write_with_unnecessary_zip64_extra(
        OUT / 'legacy-0.1-zip64-extra.aural', legacy_entries)
    add(expected, 'legacy-0.1-zip64-extra.aural', 'accept-legacy-0.1',
        'Assignment 002-compatible unnecessary ZIP64 extra field')

    pretty = json.dumps(minimal, indent=2, ensure_ascii=False).encode('utf-8')
    write_package(OUT / 'invalid-noncanonical.aural', pretty, audio)
    add(expected, 'invalid-noncanonical.aural', 'reject', 'manifest is not exact JCS bytes')

    write_package(OUT / 'invalid-malformed-json.aural', b'{"format":', audio)
    add(expected, 'invalid-malformed-json.aural', 'reject', 'malformed JSON')

    write_package(OUT / 'invalid-utf8.aural', b'{"format":"\xff"}', audio)
    add(expected, 'invalid-utf8.aural', 'reject', 'invalid UTF-8')

    duplicate = minimal_bytes[:-1] + b',"version":"0.2-draft"}'
    write_package(OUT / 'invalid-duplicate-key.aural', duplicate, audio)
    add(expected, 'invalid-duplicate-key.aural', 'reject', 'duplicate JSON object name')

    scalar_doc = manifest(audio, title='x')
    scalar_bytes = core.canonical_json(scalar_doc)
    write_package(OUT / 'invalid-unpaired-surrogate.aural',
                  scalar_bytes.replace(b'"title":"x"', b'"title":"\\ud800"'), audio)
    add(expected, 'invalid-unpaired-surrogate.aural', 'reject', 'isolated escaped surrogate')

    write_package(OUT / 'invalid-noncharacter.aural',
                  scalar_bytes.replace(b'"title":"x"', b'"title":"\\ufdd0"'), audio)
    add(expected, 'invalid-noncharacter.aural', 'reject', 'I-JSON Unicode noncharacter')

    size_token = f'"size":{len(audio)}'.encode()
    write_package(OUT / 'invalid-fraction.aural',
                  minimal_bytes.replace(size_token, f'"size":{len(audio)}.0'.encode()), audio)
    add(expected, 'invalid-fraction.aural', 'reject', 'fractional JSON number')

    write_package(OUT / 'invalid-unsafe-integer.aural',
                  minimal_bytes.replace(size_token, b'"size":9007199254740992'), audio)
    add(expected, 'invalid-unsafe-integer.aural', 'reject', 'integer outside interoperable range')

    write_package(OUT / 'invalid-negative-zero.aural',
                  minimal_bytes.replace(size_token, b'"size":-0'), audio)
    add(expected, 'invalid-negative-zero.aural', 'reject', 'negative zero is not canonical')

    nested = 0
    for _ in range(31):
        nested = [nested]
    too_deep = manifest(audio, extensions={'urn:example:deep': nested})
    deep_bytes = json.dumps(
        too_deep, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    write_package(OUT / 'invalid-excessive-depth.aural', deep_bytes, audio)
    add(expected, 'invalid-excessive-depth.aural', 'reject', 'manifest nesting exceeds 32')

    bad_hash = manifest(audio)
    bad_hash['assets'][0]['sha256'] = '0' * 64
    write_package(OUT / 'invalid-asset-hash.aural', core.canonical_json(bad_hash), audio)
    add(expected, 'invalid-asset-hash.aural', 'reject', 'incorrect declared SHA-256')

    altered = bytearray(audio)
    altered[-1] ^= 1
    write_package(OUT / 'invalid-altered-original.aural', minimal_bytes, bytes(altered))
    add(expected, 'invalid-altered-original.aural', 'reject', 'altered original with valid ZIP CRC32')

    write_package(OUT / 'invalid-malformed-local-header.aural', minimal_bytes, audio)
    mutate(OUT / 'invalid-malformed-local-header.aural', lambda data: data.__setitem__(slice(0, 4), b'BAD!'))
    add(expected, 'invalid-malformed-local-header.aural', 'reject', 'malformed local header signature')

    write_package(OUT / 'invalid-local-central-crc.aural', minimal_bytes, audio)
    def corrupt_local_crc(data):
        struct.pack_into('<I', data, 14, (struct.unpack_from('<I', data, 14)[0] + 1) & 0xffffffff)
    mutate(OUT / 'invalid-local-central-crc.aural', corrupt_local_crc)
    add(expected, 'invalid-local-central-crc.aural', 'reject', 'local and central CRC32 disagree')

    with zipfile.ZipFile(OUT / 'invalid-extra-field.aural', 'w') as archive:
        mi = core._new_zip_info('manifest.json')
        mi.extra = struct.pack('<HH', 0x5455, 0)
        archive.writestr(mi, minimal_bytes)
        archive.writestr(core._new_zip_info(AUDIO_NAME), audio)
    add(expected, 'invalid-extra-field.aural', 'reject', 'non-ZIP64 extra field')

    write_with_unnecessary_zip64_extra(
        OUT / 'invalid-unnecessary-zip64-extra.aural',
        [('manifest.json', minimal_bytes), (AUDIO_NAME, audio)],
    )
    add(expected, 'invalid-unnecessary-zip64-extra.aural', 'reject',
        'Draft 0.2 forbids ZIP64 extra fields without matching sentinels')

    write_raw_classic_package(
        OUT / 'invalid-entry-comment.aural',
        [('manifest.json', minimal_bytes), (AUDIO_NAME, audio)],
        entry_comments={'manifest.json': b'undeclared entry comment'},
    )
    add(expected, 'invalid-entry-comment.aural', 'reject',
        'central-directory entry comment is prohibited')

    write_package(OUT / 'invalid-special-file.aural', minimal_bytes, audio)
    def mark_symlink(data):
        eocd = len(data) - 22
        central = struct.unpack_from('<I', data, eocd + 16)[0]
        first_size = 46 + struct.unpack_from('<H', data, central + 28)[0]
        first_size += struct.unpack_from('<H', data, central + 30)[0]
        first_size += struct.unpack_from('<H', data, central + 32)[0]
        second = central + first_size
        struct.pack_into('<H', data, second + 4, (3 << 8) | 20)
        struct.pack_into('<I', data, second + 38, 0o120777 << 16)
    mutate(OUT / 'invalid-special-file.aural', mark_symlink)
    add(expected, 'invalid-special-file.aural', 'reject', 'entry metadata describes a symlink')

    write_package(OUT / 'invalid-unsafe-filename.aural', minimal_bytes, audio,
                  audio_name='../original.wav')
    add(expected, 'invalid-unsafe-filename.aural', 'reject', 'unsafe and undeclared filename')

    write_package(OUT / 'invalid-compression.aural', minimal_bytes, audio,
                  compression=zipfile.ZIP_DEFLATED)
    add(expected, 'invalid-compression.aural', 'reject', 'unsupported DEFLATE compression')

    oversized = manifest(audio)
    oversized['assets'][0]['size'] = core.MAX_AUDIO + 1
    write_package(OUT / 'invalid-excessive-declared-size.aural',
                  core.canonical_json(oversized), audio)
    add(expected, 'invalid-excessive-declared-size.aural', 'reject', 'declared audio exceeds 8 GiB')

    future = manifest(audio)
    future['version'] = '0.3-draft'
    write_package(OUT / 'invalid-version.aural', core.canonical_json(future), audio)
    add(expected, 'invalid-version.aural', 'reject', 'unsupported format version')

    critical = manifest(
        audio,
        extensions={'urn:example:critical': {'enabled': True}},
        critical_extensions=['urn:example:critical'],
    )
    write_package(OUT / 'invalid-critical-extension.aural', core.canonical_json(critical), audio)
    add(expected, 'invalid-critical-extension.aural', 'reject', 'unknown critical extension')

    unknown = manifest(audio, unexpected='value')
    write_package(OUT / 'invalid-unknown-member.aural', core.canonical_json(unknown), audio)
    add(expected, 'invalid-unknown-member.aural', 'reject', 'unknown core manifest member')

    write_package(OUT / 'invalid-duplicate-entry.aural', minimal_bytes, audio,
                  duplicate_manifest=True)
    add(expected, 'invalid-duplicate-entry.aural', 'reject', 'duplicate ZIP entry')

    write_package(OUT / 'invalid-trailer.aural', minimal_bytes, audio)
    with (OUT / 'invalid-trailer.aural').open('ab') as target:
        target.write(b'undeclared trailer')
    add(expected, 'invalid-trailer.aural', 'reject', 'bytes after terminal EOCD')

    for name, item in expected.items():
        item['fixture_sha256'] = hashlib.sha256((OUT / name).read_bytes()).hexdigest()
    metadata = {
        'corpus': 'AURAL Draft 0.2 conformance fixtures',
        'golden_manifest': {
            'path': 'golden-manifest.json',
            'length': len(golden),
            'sha256': hashlib.sha256(golden).hexdigest(),
            'trailing_lf': False,
        },
        'audio': {
            'length': len(audio),
            'sha256': hashlib.sha256(audio).hexdigest(),
        },
        'fixtures': expected,
    }
    (OUT / 'expected.json').write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')


if __name__ == '__main__':
    main()
