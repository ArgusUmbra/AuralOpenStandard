"""Experimental AURAL provenance record parsing and bounded input handling.

Cryptographic signature verification, signed-event digesting, and AURAL package
binding are intentionally not implemented yet.
"""

import base64
import binascii
from collections.abc import Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import date
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import BinaryIO, Optional, Union


MAX_EVENT_BYTES = 1024 * 1024
MAX_KEY_RECORD_BYTES = 16 * 1024
MAX_KEY_RECORDS = 64
MAX_AGGREGATE_KEY_BYTES = 256 * 1024
MAX_JSON_DEPTH = 32
MAX_PARENTS = 4096
MAX_AUDIO_BYTES = 8 * 1024**3
MAX_SAFE_INTEGER = 9007199254740991
MAX_EXTENSION_ID_BYTES = 255
MAX_DESCRIPTION_SCALARS = 4096
READ_CHUNK = 64 * 1024

EVENT_SCHEMA = 'org.aural.provenance-event'
EVENT_SCHEMA_VERSION = '1'
SIGNATURE_PROFILE = 'org.aural.signature.ed25519-jcs-v1'
EVENT_TYPE = 'urn:aural:event:original-asset-acquired:1'
KEY_SCHEMA = 'org.aural.signing-key'
KEY_SCHEMA_VERSION = '1'
KEY_ALGORITHM = 'Ed25519'
KEY_ID_DOMAIN = b'AURAL-KEY-ID-V1\x00Ed25519\x00'

UUID_URN_RE = re.compile(
    r'^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
)
HASH_RE = re.compile(r'^[0-9a-f]{64}$')
KEY_ID_RE = re.compile(r'^urn:aural:key:ed25519:[0-9a-f]{64}$')
EXTENSION_ID_RE = re.compile(r'^[a-z][a-z0-9+.-]*:[!-~]+$')
TIMESTAMP_RE = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})'
    r'(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$'
)

PathLike = Union[str, os.PathLike]


class VerificationStatus(str, Enum):
    SIGNATURE_VALID = 'signature_valid'


class AssetIntegrityStatus(str, Enum):
    VERIFIED = 'verified'
    NOT_CHECKED = 'not_checked'


class InvestigatorIdentityStatus(str, Enum):
    NOT_ESTABLISHED = 'not_established'


class KeyTrustStatus(str, Enum):
    NOT_EVALUATED = 'not_evaluated'


class TimeAssuranceStatus(str, Enum):
    CLAIMED_ONLY = 'claimed_only'
    UNKNOWN = 'unknown'


class HistoryCompletenessStatus(str, Enum):
    NOT_ESTABLISHED = 'not_established'


class ErrorCategory(str, Enum):
    CONFIGURATION = 'configuration'
    INPUT = 'input'
    RESOURCE_LIMIT = 'resource_limit'
    JSON_PROFILE = 'json_profile'
    CANONICALIZATION = 'canonicalization'
    SCHEMA = 'schema'
    ENCODING = 'encoding'
    IDENTIFIER = 'identifier'
    TIMESTAMP = 'timestamp'
    PARENT_REFERENCE = 'parent_reference'
    UNSUPPORTED_VERSION = 'unsupported_version'
    UNSUPPORTED_SIGNATURE_PROFILE = 'unsupported_signature_profile'
    UNSUPPORTED_EVENT_TYPE = 'unsupported_event_type'
    UNSUPPORTED_ALGORITHM = 'unsupported_algorithm'
    UNSUPPORTED_EXTENSION = 'unsupported_extension'
    UNSUPPORTED_TIME_BASIS = 'unsupported_time_basis'
    PUBLIC_KEY = 'public_key'
    KEY_ID_MISMATCH = 'key_id_mismatch'
    DUPLICATE_KEY = 'duplicate_key'
    MISSING_KEY = 'missing_key'
    SIGNATURE = 'signature'
    PROVIDER_UNAVAILABLE = 'provider_unavailable'
    PACKAGE_INTEGRITY = 'package_integrity'
    SUBJECT_BINDING = 'subject_binding'
    NOT_IMPLEMENTED = 'not_implemented'


class VerificationStage(str, Enum):
    INPUT = 'input'
    RECORD = 'record'
    KEY = 'key'
    SIGNATURE = 'signature'
    PACKAGE = 'package'


class ProvenanceVerificationError(ValueError):
    """A controlled provenance verification failure.

    ``category`` and ``stage`` are stable API values. The human-readable
    message is diagnostic and is not part of the compatibility contract.
    """

    def __init__(self, category, stage, message):
        self.category = ErrorCategory(category)
        self.stage = VerificationStage(stage)
        super().__init__(message)


def _validate_limit(name, value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProvenanceVerificationError(
            ErrorCategory.CONFIGURATION,
            VerificationStage.INPUT,
            f'{name} must be an integer from {minimum} through {maximum}',
        )


@dataclass(frozen=True, slots=True)
class VerificationLimits:
    """Optional local limits that can tighten, but never relax, the profile."""

    event_bytes: int = MAX_EVENT_BYTES
    key_record_bytes: int = MAX_KEY_RECORD_BYTES
    key_records: int = MAX_KEY_RECORDS
    aggregate_key_bytes: int = MAX_AGGREGATE_KEY_BYTES

    def __post_init__(self):
        _validate_limit('event_bytes', self.event_bytes, 1, MAX_EVENT_BYTES)
        _validate_limit('key_record_bytes', self.key_record_bytes, 1, MAX_KEY_RECORD_BYTES)
        _validate_limit('key_records', self.key_records, 0, MAX_KEY_RECORDS)
        _validate_limit(
            'aggregate_key_bytes', self.aggregate_key_bytes, 0, MAX_AGGREGATE_KEY_BYTES,
        )


@dataclass(frozen=True, slots=True)
class VerificationResult:
    status: VerificationStatus
    event_id: str
    evidence_id: str
    signing_key_id: str
    signed_event_sha256: str
    asset_integrity: AssetIntegrityStatus
    investigator_identity: InvestigatorIdentityStatus
    key_trust: KeyTrustStatus
    time_assurance: TimeAssuranceStatus
    history_completeness: HistoryCompletenessStatus
    declared_parent_count: int


@dataclass(frozen=True, slots=True)
class _ValidatedRecord:
    document: dict
    assertion: dict


@dataclass(frozen=True, slots=True)
class _ValidatedKey:
    document: dict
    public_key: bytes


@dataclass(frozen=True, slots=True)
class _FileSnapshot:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _PreflightedFile:
    handle: BinaryIO
    snapshot: _FileSnapshot
    label: str


class _DuplicateName(ValueError):
    pass


class _ProhibitedNumber(ValueError):
    pass


def _fail(category, stage, message):
    raise ProvenanceVerificationError(category, stage, message)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateName(key)
        result[key] = value
    return result


def _safe_integer(token):
    if token == '-0':
        raise _ProhibitedNumber('negative zero')
    value = int(token)
    if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        raise _ProhibitedNumber('unsafe integer')
    return value


def _reject_fraction(_token):
    raise _ProhibitedNumber('fractional or exponent-form number')


def _reject_constant(_token):
    raise _ProhibitedNumber('non-finite number')


def _check_raw_depth(raw, label, stage):
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
                _fail(
                    ErrorCategory.RESOURCE_LIMIT,
                    stage,
                    f'{label} nesting depth exceeds {MAX_JSON_DEPTH}',
                )
        elif byte in (0x7d, 0x5d):
            depth -= 1


def _check_string(value, stage):
    for character in value:
        point = ord(character)
        if 0xd800 <= point <= 0xdfff:
            _fail(
                ErrorCategory.JSON_PROFILE,
                stage,
                'JSON strings must contain Unicode scalar values',
            )
        if (0xfdd0 <= point <= 0xfdef
                or point & 0xffff in (0xfffe, 0xffff)):
            _fail(
                ErrorCategory.JSON_PROFILE,
                stage,
                'JSON strings must not contain Unicode noncharacters',
            )


def _jcs_text(value, stage):
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if type(value) is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            _fail(ErrorCategory.JSON_PROFILE, stage, 'JSON integer exceeds safe range')
        return str(value)
    if isinstance(value, str):
        _check_string(value, stage)
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if isinstance(value, list):
        return '[' + ','.join(_jcs_text(item, stage) for item in value) + ']'
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                _fail(ErrorCategory.JSON_PROFILE, stage, 'JSON member name is not a string')
            _check_string(key, stage)
        keys = sorted(value, key=lambda key: key.encode('utf-16-be'))
        return '{' + ','.join(
            json.dumps(key, ensure_ascii=False, separators=(',', ':'))
            + ':' + _jcs_text(value[key], stage)
            for key in keys
        ) + '}'
    _fail(ErrorCategory.JSON_PROFILE, stage, 'unsupported JSON value')


def _parse_canonical_json(raw, label, stage):
    if raw.startswith(b'\xef\xbb\xbf'):
        _fail(ErrorCategory.JSON_PROFILE, stage, f'{label} has a UTF-8 BOM')
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.JSON_PROFILE, stage, f'{label} is not strict UTF-8',
        ) from exc
    _check_raw_depth(raw, label, stage)
    try:
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_int=_safe_integer,
            parse_float=_reject_fraction,
            parse_constant=_reject_constant,
        )
    except _DuplicateName as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.CANONICALIZATION,
            stage,
            f'{label} has a duplicate JSON member name',
        ) from exc
    except _ProhibitedNumber as exc:
        category = (ErrorCategory.CANONICALIZATION
                    if str(exc) == 'fractional or exponent-form number'
                    else ErrorCategory.JSON_PROFILE)
        raise ProvenanceVerificationError(category, stage, f'{label} has a prohibited number') from exc
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.JSON_PROFILE, stage, f'{label} is malformed JSON',
        ) from exc
    encoded = _jcs_text(document, stage).encode('utf-8')
    if encoded != raw:
        _fail(
            ErrorCategory.CANONICALIZATION,
            stage,
            f'{label} is not exact RFC 8785 JCS',
        )
    return document


def _exact_object(value, required, optional=()):
    if not isinstance(value, dict):
        return False
    actual = set(value)
    required = set(required)
    return required <= actual and actual <= required | set(optional)


def _canonical_base64url(value, expected_length, label, stage):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        _fail(ErrorCategory.ENCODING, stage, f'{label} is not unpadded base64url')
    try:
        decoded = base64.b64decode(
            value + '=' * (-len(value) % 4), altchars=b'-_', validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.ENCODING, stage, f'{label} is not valid base64url',
        ) from exc
    round_trip = base64.urlsafe_b64encode(decoded).rstrip(b'=').decode('ascii')
    if len(decoded) != expected_length or round_trip != value:
        _fail(
            ErrorCategory.ENCODING,
            stage,
            f'{label} has the wrong length or a noncanonical encoding',
        )
    return decoded


def _valid_uuid_urn(value):
    return isinstance(value, str) and UUID_URN_RE.fullmatch(value) is not None


def _valid_hash(value):
    return isinstance(value, str) and HASH_RE.fullmatch(value) is not None


def _validate_extensions(container, stage):
    extensions = container.get('extensions', {})
    critical = container.get('critical_extensions', [])
    if not isinstance(extensions, dict):
        _fail(ErrorCategory.SCHEMA, stage, 'extensions must be an object')
    for identifier in extensions:
        if (EXTENSION_ID_RE.fullmatch(identifier) is None
                or len(identifier.encode('ascii')) > MAX_EXTENSION_ID_BYTES):
            _fail(ErrorCategory.SCHEMA, stage, 'invalid extension identifier')
    if not isinstance(critical, list):
        _fail(ErrorCategory.SCHEMA, stage, 'critical_extensions must be an array')
    seen = set()
    for identifier in critical:
        if (not isinstance(identifier, str)
                or EXTENSION_ID_RE.fullmatch(identifier) is None
                or identifier in seen
                or identifier not in extensions):
            _fail(
                ErrorCategory.SCHEMA,
                stage,
                'critical extension is malformed, duplicated, or missing its value',
            )
        seen.add(identifier)
        _fail(
            ErrorCategory.UNSUPPORTED_EXTENSION,
            stage,
            f'unsupported critical extension: {identifier}',
        )


def _validate_timestamp(value):
    if not isinstance(value, str) or value.endswith('-00:00'):
        return False
    match = TIMESTAMP_RE.fullmatch(value)
    if match is None:
        return False
    year, month, day, hour, minute, second = map(int, match.groups()[:6])
    if year == 0 or hour > 23 or minute > 59 or second > 59:
        return False
    try:
        date(year, month, day)
    except ValueError:
        return False
    offset = match.group(7)
    if offset != 'Z':
        offset_hour = int(offset[1:3])
        offset_minute = int(offset[4:6])
        if (offset_hour > 14 or offset_minute > 59
                or offset_hour == 14 and offset_minute != 0):
            return False
    return True


def _validate_parents(assertion):
    parents = assertion['parents']
    if not isinstance(parents, list) or len(parents) > MAX_PARENTS:
        _fail(
            ErrorCategory.SCHEMA,
            VerificationStage.RECORD,
            f'parents must be an array of at most {MAX_PARENTS} references',
        )
    previous = None
    seen = set()
    for parent in parents:
        if (not _exact_object(parent, {'event_id', 'signed_event_digest'})
                or not _valid_uuid_urn(parent.get('event_id'))):
            _fail(ErrorCategory.SCHEMA, VerificationStage.RECORD, 'malformed parent reference')
        digest = parent['signed_event_digest']
        if not _exact_object(digest, {'algorithm', 'value'}):
            _fail(ErrorCategory.SCHEMA, VerificationStage.RECORD, 'malformed parent digest')
        parent_id = parent['event_id']
        if parent_id == assertion['event_id']:
            _fail(ErrorCategory.PARENT_REFERENCE, VerificationStage.RECORD, 'self-reference is prohibited')
        if parent_id in seen:
            _fail(ErrorCategory.PARENT_REFERENCE, VerificationStage.RECORD, 'duplicate parent event_id')
        if previous is not None and parent_id <= previous:
            _fail(
                ErrorCategory.PARENT_REFERENCE,
                VerificationStage.RECORD,
                'parents are not in ascending event_id order',
            )
        if digest['algorithm'] != 'sha-256':
            _fail(
                ErrorCategory.UNSUPPORTED_ALGORITHM,
                VerificationStage.RECORD,
                'unsupported parent digest algorithm',
            )
        if not _valid_hash(digest['value']):
            _fail(
                ErrorCategory.PARENT_REFERENCE,
                VerificationStage.RECORD,
                'parent digest must be lowercase hexadecimal SHA-256',
            )
        seen.add(parent_id)
        previous = parent_id


def _validate_subject(subject):
    if not _exact_object(subject, {'format', 'manifest_sha256', 'original', 'version'}):
        _fail(ErrorCategory.SCHEMA, VerificationStage.RECORD, 'subject has missing or unknown members')
    if subject['format'] != 'org.aural.audio-evidence' or subject['version'] != '0.2-draft':
        _fail(
            ErrorCategory.UNSUPPORTED_VERSION,
            VerificationStage.RECORD,
            'subject is not an AURAL Draft 0.2 package',
        )
    if not _valid_hash(subject['manifest_sha256']):
        _fail(ErrorCategory.SCHEMA, VerificationStage.RECORD, 'invalid manifest_sha256')
    original = subject['original']
    if not _exact_object(original, {'byte_length', 'path', 'sha256'}):
        _fail(
            ErrorCategory.SCHEMA,
            VerificationStage.RECORD,
            'subject.original has missing or unknown members',
        )
    if (original['path'] != 'audio/original.wav'
            or not _valid_hash(original['sha256'])
            or type(original['byte_length']) is not int
            or not 0 <= original['byte_length'] <= MAX_AUDIO_BYTES):
        _fail(ErrorCategory.SCHEMA, VerificationStage.RECORD, 'invalid original asset binding')


def _validate_claimed_times(claimed_times):
    if not isinstance(claimed_times, list) or not 1 <= len(claimed_times) <= 3:
        _fail(ErrorCategory.SCHEMA, VerificationStage.RECORD, 'claimed_times length is invalid')
    order = {'device-reported': 0, 'import': 1, 'signing': 2}
    seen = set()
    previous = -1
    for claimed_time in claimed_times:
        if (not _exact_object(claimed_time, {'basis', 'value'})
                or claimed_time.get('basis') not in order):
            _fail(
                ErrorCategory.UNSUPPORTED_TIME_BASIS,
                VerificationStage.RECORD,
                'unsupported or malformed claimed-time basis',
            )
        basis = claimed_time['basis']
        if basis in seen:
            _fail(ErrorCategory.SCHEMA, VerificationStage.RECORD, 'claimed-time basis is duplicated')
        if order[basis] <= previous:
            _fail(
                ErrorCategory.SCHEMA,
                VerificationStage.RECORD,
                'claimed-time entries are out of order',
            )
        if not _validate_timestamp(claimed_time['value']):
            _fail(
                ErrorCategory.TIMESTAMP,
                VerificationStage.RECORD,
                'malformed claimed-time RFC 3339 value',
            )
        seen.add(basis)
        previous = order[basis]


def _validate_claims(claims, signing_key_id):
    required = {
        'acquiring_key_id', 'acquisition_method', 'earlier_modification_history',
        'key_protection', 'source_description', 'source_type',
    }
    optional = {'acquisition_environment', 'claimed_times'}
    if not _exact_object(claims, required, optional):
        _fail(
            ErrorCategory.SCHEMA,
            VerificationStage.RECORD,
            'claims have missing or unknown core members',
        )
    sources = {
        'native-capture': 'device-microphone',
        'external-recorder-import': 'external-recorder',
        'received-evidence-import': 'received-evidence',
        'other-import': 'other',
    }
    if claims['acquisition_method'] not in sources:
        _fail(ErrorCategory.SCHEMA, VerificationStage.RECORD, 'unsupported acquisition_method')
    if claims['source_type'] != sources[claims['acquisition_method']]:
        _fail(
            ErrorCategory.SCHEMA,
            VerificationStage.RECORD,
            'source_type does not match acquisition_method',
        )
    if claims['earlier_modification_history'] not in {'none-known', 'known', 'unknown'}:
        _fail(
            ErrorCategory.SCHEMA,
            VerificationStage.RECORD,
            'unsupported earlier_modification_history value',
        )
    if claims['key_protection'] not in {
            'software', 'os-keystore', 'hardware-backed', 'secure-element', 'unknown'}:
        _fail(ErrorCategory.SCHEMA, VerificationStage.RECORD, 'unsupported key_protection value')
    if claims['acquiring_key_id'] != signing_key_id:
        _fail(
            ErrorCategory.SCHEMA,
            VerificationStage.RECORD,
            'acquiring_key_id must equal signing_key_id',
        )
    description = claims['source_description']
    if not isinstance(description, str) or not 1 <= len(description) <= MAX_DESCRIPTION_SCALARS:
        _fail(ErrorCategory.SCHEMA, VerificationStage.RECORD, 'source_description length is invalid')
    if 'acquisition_environment' in claims:
        environment = claims['acquisition_environment']
        if not isinstance(environment, str) or not 1 <= len(environment) <= MAX_DESCRIPTION_SCALARS:
            _fail(
                ErrorCategory.SCHEMA,
                VerificationStage.RECORD,
                'acquisition_environment length is invalid',
            )
    if 'claimed_times' in claims:
        _validate_claimed_times(claims['claimed_times'])


def _validate_assertion(assertion):
    required = {
        'claims', 'event_id', 'event_schema', 'event_schema_version', 'event_type',
        'evidence_id', 'parents', 'signature_profile', 'signing_key_id', 'subject',
    }
    optional = {'extensions', 'critical_extensions'}
    if not _exact_object(assertion, required, optional):
        _fail(
            ErrorCategory.SCHEMA,
            VerificationStage.RECORD,
            'assertion has missing or unknown core members',
        )
    if (assertion['event_schema'] != EVENT_SCHEMA
            or assertion['event_schema_version'] != EVENT_SCHEMA_VERSION):
        _fail(
            ErrorCategory.UNSUPPORTED_VERSION,
            VerificationStage.RECORD,
            'unsupported event schema or version',
        )
    if assertion['signature_profile'] != SIGNATURE_PROFILE:
        _fail(
            ErrorCategory.UNSUPPORTED_SIGNATURE_PROFILE,
            VerificationStage.RECORD,
            'unsupported signature profile',
        )
    if not _valid_uuid_urn(assertion['event_id']) or not _valid_uuid_urn(assertion['evidence_id']):
        _fail(
            ErrorCategory.IDENTIFIER,
            VerificationStage.RECORD,
            'event_id and evidence_id must be lowercase UUIDv4 URNs',
        )
    if (not isinstance(assertion['signing_key_id'], str)
            or KEY_ID_RE.fullmatch(assertion['signing_key_id']) is None):
        _fail(ErrorCategory.IDENTIFIER, VerificationStage.RECORD, 'invalid signing_key_id')
    _validate_extensions(assertion, VerificationStage.RECORD)
    _validate_parents(assertion)
    _validate_subject(assertion['subject'])
    if assertion['event_type'] != EVENT_TYPE:
        _fail(
            ErrorCategory.UNSUPPORTED_EVENT_TYPE,
            VerificationStage.RECORD,
            'unsupported event_type',
        )
    _validate_claims(assertion['claims'], assertion['signing_key_id'])


def _parse_validate_record(raw):
    document = _parse_canonical_json(
        raw, 'signed-event record', VerificationStage.RECORD,
    )
    if not _exact_object(document, {'assertion', 'signature'}):
        _fail(
            ErrorCategory.SCHEMA,
            VerificationStage.RECORD,
            'signed-event envelope must contain exactly assertion and signature',
        )
    _validate_assertion(document['assertion'])
    return _ValidatedRecord(document, document['assertion'])


def _validate_key_record(raw):
    document = _parse_canonical_json(raw, 'public-key record', VerificationStage.KEY)
    required = {'algorithm', 'key_id', 'key_schema', 'key_schema_version', 'public_key'}
    optional = {'extensions', 'critical_extensions'}
    if not _exact_object(document, required, optional):
        _fail(
            ErrorCategory.SCHEMA,
            VerificationStage.KEY,
            'public-key record has missing or unknown core members',
        )
    if (document['key_schema'] != KEY_SCHEMA
            or document['key_schema_version'] != KEY_SCHEMA_VERSION):
        _fail(
            ErrorCategory.UNSUPPORTED_VERSION,
            VerificationStage.KEY,
            'unsupported public-key record schema or version',
        )
    if document['algorithm'] != KEY_ALGORITHM:
        _fail(
            ErrorCategory.UNSUPPORTED_ALGORITHM,
            VerificationStage.KEY,
            'unsupported public-key algorithm',
        )
    _validate_extensions(document, VerificationStage.KEY)
    public_key = _canonical_base64url(
        document['public_key'], 32, 'public_key', VerificationStage.KEY,
    )
    expected_id = 'urn:aural:key:ed25519:' + hashlib.sha256(
        KEY_ID_DOMAIN + public_key,
    ).hexdigest()
    if document['key_id'] != expected_id:
        _fail(
            ErrorCategory.KEY_ID_MISMATCH,
            VerificationStage.KEY,
            'public key does not match key_id',
        )
    return _ValidatedKey(document, public_key)


def _resolve_public_key(raw_records, signing_key_id):
    keys = {}
    for raw in raw_records:
        key = _validate_key_record(raw)
        key_id = key.document['key_id']
        if key_id in keys:
            _fail(
                ErrorCategory.DUPLICATE_KEY,
                VerificationStage.KEY,
                'duplicate public-key record for key_id',
            )
        keys[key_id] = key
    selected = keys.get(signing_key_id)
    if selected is None:
        _fail(
            ErrorCategory.MISSING_KEY,
            VerificationStage.KEY,
            'no public-key record matches signing_key_id',
        )
    return selected


def _limits_or_default(limits):
    if limits is None:
        return VerificationLimits()
    if not isinstance(limits, VerificationLimits):
        raise ProvenanceVerificationError(
            ErrorCategory.CONFIGURATION,
            VerificationStage.INPUT,
            'limits must be a VerificationLimits instance or None',
        )
    return limits


def _snapshot(file_stat):
    return _FileSnapshot(
        device=file_stat.st_dev,
        inode=file_stat.st_ino,
        size=file_stat.st_size,
        modified_ns=file_stat.st_mtime_ns,
        changed_ns=file_stat.st_ctime_ns,
    )


def _open_preflighted_file(stack, path, maximum, label):
    try:
        handle = stack.enter_context(open(Path(path), 'rb', buffering=0))
        before = os.fstat(handle.fileno())
    except (OSError, TypeError, ValueError) as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.INPUT,
            VerificationStage.INPUT,
            f'cannot open {label}: {exc}',
        ) from exc

    if not stat.S_ISREG(before.st_mode):
        raise ProvenanceVerificationError(
            ErrorCategory.RESOURCE_LIMIT,
            VerificationStage.INPUT,
            f'{label} must be a regular file',
        )
    if before.st_size < 1 or before.st_size > maximum:
        raise ProvenanceVerificationError(
            ErrorCategory.RESOURCE_LIMIT,
            VerificationStage.INPUT,
            f'{label} size is outside the configured limit',
        )
    return _PreflightedFile(handle, _snapshot(before), label)


def _read_preflighted_file(source):
    size = source.snapshot.size
    raw = bytearray(size)
    view = memoryview(raw)
    offset = 0
    while offset < size:
        request = min(READ_CHUNK, size - offset)
        try:
            count = source.handle.readinto(view[offset:offset + request])
        except OSError as exc:
            raise ProvenanceVerificationError(
                ErrorCategory.INPUT,
                VerificationStage.INPUT,
                f'{source.label} could not be read: {exc}',
            ) from exc
        if not count:
            raise ProvenanceVerificationError(
                ErrorCategory.INPUT,
                VerificationStage.INPUT,
                f'{source.label} was truncated during reading',
            )
        offset += count

    try:
        after = _snapshot(os.fstat(source.handle.fileno()))
    except OSError as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.INPUT,
            VerificationStage.INPUT,
            f'{source.label} could not be inspected after reading: {exc}',
        ) from exc
    if after != source.snapshot:
        raise ProvenanceVerificationError(
            ErrorCategory.INPUT,
            VerificationStage.INPUT,
            f'{source.label} changed during reading',
        )
    return bytes(raw)


def _validate_key_sequence(values, label):
    if (not isinstance(values, Sequence)
            or isinstance(values, (str, bytes, bytearray, memoryview))):
        raise ProvenanceVerificationError(
            ErrorCategory.INPUT,
            VerificationStage.INPUT,
            f'{label} must be a finite sequence',
        )


def _raise_signature_not_implemented():
    raise ProvenanceVerificationError(
        ErrorCategory.NOT_IMPLEMENTED,
        VerificationStage.SIGNATURE,
        'Ed25519 signature verification is not implemented',
    )


def verify_signed_event(
        record: bytes,
        public_key_records: Sequence[bytes],
        *,
        package_path: Optional[PathLike] = None,
        limits: Optional[VerificationLimits] = None,
) -> VerificationResult:
    """Validate record structure and key resolution.

    This implementation stops at the signature stage and raises
    ``not_implemented``. It never returns ``signature_valid``.
    """
    del package_path  # Package binding is intentionally deferred beyond Assignment 006B-2A.
    effective = _limits_or_default(limits)
    if type(record) is not bytes:
        raise ProvenanceVerificationError(
            ErrorCategory.INPUT, VerificationStage.INPUT, 'signed-event record must be bytes',
        )
    if not 1 <= len(record) <= effective.event_bytes:
        raise ProvenanceVerificationError(
            ErrorCategory.RESOURCE_LIMIT,
            VerificationStage.INPUT,
            'signed-event record size is outside the configured limit',
        )
    _validate_key_sequence(public_key_records, 'public-key records')
    if len(public_key_records) > effective.key_records:
        raise ProvenanceVerificationError(
            ErrorCategory.RESOURCE_LIMIT,
            VerificationStage.INPUT,
            'too many public-key records',
        )
    aggregate = 0
    for raw in public_key_records:
        if type(raw) is not bytes:
            raise ProvenanceVerificationError(
                ErrorCategory.INPUT,
                VerificationStage.INPUT,
                'public-key record must be bytes',
            )
        if not 1 <= len(raw) <= effective.key_record_bytes:
            raise ProvenanceVerificationError(
                ErrorCategory.RESOURCE_LIMIT,
                VerificationStage.INPUT,
                'public-key record size is outside the configured limit',
            )
        aggregate += len(raw)
        if aggregate > effective.aggregate_key_bytes:
            raise ProvenanceVerificationError(
                ErrorCategory.RESOURCE_LIMIT,
                VerificationStage.INPUT,
                'aggregate public-key data exceeds the configured limit',
            )
    validated = _parse_validate_record(record)
    _resolve_public_key(public_key_records, validated.assertion['signing_key_id'])
    _canonical_base64url(
        validated.document['signature'], 64, 'signature', VerificationStage.SIGNATURE,
    )
    _raise_signature_not_implemented()


def verify_signed_event_files(
        event_path: PathLike,
        key_paths: Sequence[PathLike],
        *,
        package_path: Optional[PathLike] = None,
        limits: Optional[VerificationLimits] = None,
) -> VerificationResult:
    """Read bounded detached inputs, then invoke ``verify_signed_event``."""
    effective = _limits_or_default(limits)
    _validate_key_sequence(key_paths, 'public-key paths')
    if len(key_paths) > effective.key_records:
        raise ProvenanceVerificationError(
            ErrorCategory.RESOURCE_LIMIT,
            VerificationStage.INPUT,
            'too many public-key records',
        )

    with ExitStack() as stack:
        event = _open_preflighted_file(
            stack, event_path, effective.event_bytes, 'signed-event record',
        )
        keys = []
        aggregate = 0
        for path in key_paths:
            key = _open_preflighted_file(
                stack, path, effective.key_record_bytes, 'public-key record',
            )
            aggregate += key.snapshot.size
            if aggregate > effective.aggregate_key_bytes:
                raise ProvenanceVerificationError(
                    ErrorCategory.RESOURCE_LIMIT,
                    VerificationStage.INPUT,
                    'aggregate public-key data exceeds the configured limit',
                )
            keys.append(key)

        record_raw = _read_preflighted_file(event)
        key_record_raws = [_read_preflighted_file(key) for key in keys]

    return verify_signed_event(
        record_raw,
        key_record_raws,
        package_path=package_path,
        limits=effective,
    )


__all__ = [
    'AssetIntegrityStatus',
    'ErrorCategory',
    'HistoryCompletenessStatus',
    'InvestigatorIdentityStatus',
    'KeyTrustStatus',
    'ProvenanceVerificationError',
    'TimeAssuranceStatus',
    'VerificationLimits',
    'VerificationResult',
    'VerificationStage',
    'VerificationStatus',
    'verify_signed_event',
    'verify_signed_event_files',
]
