"""Experimental AURAL provenance signature and evidence-binding verification."""

import base64
import binascii
from collections.abc import Sequence
from contextlib import ExitStack
from dataclasses import dataclass, replace
from datetime import date
from enum import Enum
from functools import lru_cache
import hashlib
import heapq
import json
import os
from pathlib import Path
import re
import stat
from typing import BinaryIO, Optional, Tuple, Union

from . import core


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
MAX_GRAPH_EVENT_RECORDS = 4096
MAX_AGGREGATE_GRAPH_EVENT_BYTES = 64 * 1024 * 1024
MAX_GRAPH_PARENT_REFERENCES = 64
MAX_GRAPH_DEPTH = 256
READ_CHUNK = 64 * 1024

EVENT_SCHEMA = 'org.aural.provenance-event'
EVENT_SCHEMA_VERSION = '1'
SIGNATURE_PROFILE = 'org.aural.signature.ed25519-jcs-v1'
EVENT_TYPE = 'urn:aural:event:original-asset-acquired:1'
KEY_SCHEMA = 'org.aural.signing-key'
KEY_SCHEMA_VERSION = '1'
KEY_ALGORITHM = 'Ed25519'
KEY_ID_DOMAIN = b'AURAL-KEY-ID-V1\x00Ed25519\x00'
SIGNATURE_DOMAIN = b'AURAL-PROVENANCE-EVENT-V1\x00'
SIGNED_EVENT_DOMAIN = b'AURAL-SIGNED-EVENT-V1\x00'

ED25519_P = (1 << 255) - 19
ED25519_L = (1 << 252) + 27742317777372353535851937790883648493
ED25519_SMALL_ORDER_Y = frozenset({
    0,
    1,
    ED25519_P - 1,
    int('7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7', 16),
    int('05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826', 16),
})

# Assignment 005B's complete 13-vector provider acceptance gate. The
# application prechecks and provider are tested together once per process.
_ED25519_PROVIDER_VECTORS = (
    (False, '0100000000000000000000000000000000000000000000000000000000000000',
     '5a63617368',
     '0100000000000000000000000000000000000000000000000000000000000000'
     '0000000000000000000000000000000000000000000000000000000000000000'),
    (False, 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
     '8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6',
     'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'
     '0000000000000000000000000000000000000000000000000000000000000000'),
    (False, 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
     '9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79',
     'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43'
     'a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04'),
    (False, 'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43',
     'aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab',
     'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa'
     '8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e'),
    (True, 'cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d',
     '9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79',
     '9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f'
     '87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009'),
    (False, 'cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d',
     'e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c',
     '160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed512'
     '5ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09'),
    (False, 'cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d',
     'e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c',
     '21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7'
     'e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405'),
    (False, '442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623',
     '85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40',
     'e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e'
     '547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514'),
    (False, '442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623',
     '85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40',
     '8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa1942'
     '7e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22'),
    (False, 'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43',
     '9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41',
     'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
     '03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f'),
    (False, 'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43',
     '9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41',
     'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
     'ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908'),
    (False, 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
     'e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b',
     'a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc'
     'a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04'),
    (False, 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
     '39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f',
     'a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc'
     'a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04'),
)

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


class GraphVerificationStatus(str, Enum):
    CONSISTENT = 'consistent'


class ParentClosureStatus(str, Enum):
    CLOSED = 'closed'


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
    EVENT_ID_COLLISION = 'event_id_collision'
    SIGNED_EVENT_DIGEST_COLLISION = 'signed_event_digest_collision'
    MISSING_PARENT = 'missing_parent'
    PARENT_DIGEST_MISMATCH = 'parent_digest_mismatch'
    CYCLE = 'cycle'
    NOT_IMPLEMENTED = 'not_implemented'


class VerificationStage(str, Enum):
    INPUT = 'input'
    RECORD = 'record'
    KEY = 'key'
    SIGNATURE = 'signature'
    PACKAGE = 'package'
    GRAPH = 'graph'


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
class GraphVerificationLimits(VerificationLimits):
    """Bound graph preflight work without relaxing single-event limits.

    ``graph_depth`` counts nodes on the longest parent-to-descendant path;
    a root by itself therefore has depth one.
    """

    event_records: int = MAX_GRAPH_EVENT_RECORDS
    aggregate_event_bytes: int = MAX_AGGREGATE_GRAPH_EVENT_BYTES
    parent_fanout: int = MAX_GRAPH_PARENT_REFERENCES
    graph_depth: int = MAX_GRAPH_DEPTH

    def __post_init__(self):
        VerificationLimits.__post_init__(self)
        _validate_limit(
            'event_records', self.event_records, 1, MAX_GRAPH_EVENT_RECORDS,
        )
        _validate_limit(
            'aggregate_event_bytes', self.aggregate_event_bytes,
            1, MAX_AGGREGATE_GRAPH_EVENT_BYTES,
        )
        _validate_limit(
            'parent_fanout', self.parent_fanout, 0, MAX_GRAPH_PARENT_REFERENCES,
        )
        _validate_limit('graph_depth', self.graph_depth, 1, MAX_GRAPH_DEPTH)


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
class GraphVerificationResult:
    status: GraphVerificationStatus
    events: Tuple[VerificationResult, ...]
    duplicate_signed_records: int
    maximum_depth: int
    declared_parent_closure: ParentClosureStatus
    history_completeness: HistoryCompletenessStatus


@dataclass(frozen=True, slots=True)
class _ValidatedRecord:
    document: dict
    assertion: dict


@dataclass(frozen=True, slots=True)
class _IndexedSignedRecord:
    record: bytes
    validated: _ValidatedRecord
    signed_event_sha256: str


@dataclass(frozen=True, slots=True)
class _SignedEventIndex:
    by_event_id: dict
    duplicate_signed_records: int


@dataclass(frozen=True, slots=True)
class _ResolvedSignedEventGraph:
    """Unique records in deterministic parent-first order.

    ``maximum_depth`` counts nodes, so every root has depth one.
    """

    records: Tuple[_IndexedSignedRecord, ...]
    maximum_depth: int


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
    path: Optional[PathLike] = None


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
        basis = claimed_time.get('basis') if isinstance(claimed_time, dict) else None
        if (not _exact_object(claimed_time, {'basis', 'value'})
                or not isinstance(basis, str) or basis not in order):
            _fail(
                ErrorCategory.UNSUPPORTED_TIME_BASIS,
                VerificationStage.RECORD,
                'unsupported or malformed claimed-time basis',
            )
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
    acquisition_method = claims['acquisition_method']
    if not isinstance(acquisition_method, str) or acquisition_method not in sources:
        _fail(ErrorCategory.SCHEMA, VerificationStage.RECORD, 'unsupported acquisition_method')
    if claims['source_type'] != sources[acquisition_method]:
        _fail(
            ErrorCategory.SCHEMA,
            VerificationStage.RECORD,
            'source_type does not match acquisition_method',
        )
    modification_history = claims['earlier_modification_history']
    if (not isinstance(modification_history, str)
            or modification_history not in {'none-known', 'known', 'unknown'}):
        _fail(
            ErrorCategory.SCHEMA,
            VerificationStage.RECORD,
            'unsupported earlier_modification_history value',
        )
    key_protection = claims['key_protection']
    if not isinstance(key_protection, str) or key_protection not in {
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


def _signed_event_sha256(record):
    return hashlib.sha256(SIGNED_EVENT_DOMAIN + record).hexdigest()


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
    _validate_ed25519_point_encoding(
        public_key, 'Ed25519 public key', ErrorCategory.PUBLIC_KEY, VerificationStage.KEY,
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


def _validate_public_key_records(raw_records):
    keys = {}
    ordered_records = sorted(
        raw_records, key=lambda raw: (hashlib.sha256(raw).digest(), raw),
    )
    for raw in ordered_records:
        key = _validate_key_record(raw)
        key_id = key.document['key_id']
        if key_id in keys:
            _fail(
                ErrorCategory.DUPLICATE_KEY,
                VerificationStage.KEY,
                'duplicate public-key record for key_id',
            )
        keys[key_id] = key
    return keys


def _select_public_key(keys, signing_key_id):
    selected = keys.get(signing_key_id)
    if selected is None:
        _fail(
            ErrorCategory.MISSING_KEY,
            VerificationStage.KEY,
            'no public-key record matches signing_key_id',
        )
    return selected


def _resolve_public_key(raw_records, signing_key_id):
    return _select_public_key(
        _validate_public_key_records(raw_records), signing_key_id,
    )


def _ed25519_point_encoding_is_acceptable(encoded):
    if type(encoded) is not bytes or len(encoded) != 32:
        return False
    sign = encoded[31] >> 7
    y = int.from_bytes(encoded, 'little') & ((1 << 255) - 1)
    if y >= ED25519_P or sign and y in (1, ED25519_P - 1):
        return False
    return y not in ED25519_SMALL_ORDER_Y


def _validate_ed25519_point_encoding(encoded, label, category, stage):
    if type(encoded) is not bytes or len(encoded) != 32:
        _fail(category, stage, f'{label} must be 32 bytes')
    sign = encoded[31] >> 7
    y = int.from_bytes(encoded, 'little') & ((1 << 255) - 1)
    if y >= ED25519_P or sign and y in (1, ED25519_P - 1):
        _fail(category, stage, f'{label} is not a canonical Ed25519 point encoding')
    if y in ED25519_SMALL_ORDER_Y:
        _fail(category, stage, f'{label} has small order')


def _profile_accepts_with_provider(public_key, message, signature, key_type, invalid_signature):
    if (not _ed25519_point_encoding_is_acceptable(public_key)
            or type(signature) is not bytes or len(signature) != 64
            or not _ed25519_point_encoding_is_acceptable(signature[:32])
            or int.from_bytes(signature[32:], 'little') >= ED25519_L):
        return False
    try:
        key_type.from_public_bytes(public_key).verify(signature, message)
    except (invalid_signature, ValueError):
        return False
    return True


@lru_cache(maxsize=1)
def _provider_capability():
    """Return a provider only after the complete profile gate passes once."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except (ImportError, OSError) as exc:
        return None, None, f'Python cryptography is unavailable: {exc}'

    try:
        for expected, public_key, message, signature in _ED25519_PROVIDER_VECTORS:
            actual = _profile_accepts_with_provider(
                bytes.fromhex(public_key), bytes.fromhex(message), bytes.fromhex(signature),
                Ed25519PublicKey, InvalidSignature,
            )
            if actual is not expected:
                return None, None, 'cryptographic provider failed the 13-vector AURAL profile gate'
    except Exception as exc:  # Provider initialization failures must not escape or downgrade.
        return None, None, f'cryptographic provider self-test failed: {exc}'
    return Ed25519PublicKey, InvalidSignature, None


def _verify_ed25519_profile(public_key, message, signature):
    _validate_ed25519_point_encoding(
        public_key, 'Ed25519 public key', ErrorCategory.PUBLIC_KEY, VerificationStage.SIGNATURE,
    )
    _validate_ed25519_point_encoding(
        signature[:32], 'Ed25519 signature R', ErrorCategory.SIGNATURE,
        VerificationStage.SIGNATURE,
    )
    if int.from_bytes(signature[32:], 'little') >= ED25519_L:
        _fail(
            ErrorCategory.SIGNATURE, VerificationStage.SIGNATURE,
            'Ed25519 signature scalar S is out of range',
        )

    key_type, invalid_signature, provider_error = _provider_capability()
    if provider_error is not None:
        _fail(ErrorCategory.PROVIDER_UNAVAILABLE, VerificationStage.SIGNATURE, provider_error)
    try:
        verifier = key_type.from_public_bytes(public_key)
    except ValueError as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.PUBLIC_KEY, VerificationStage.SIGNATURE,
            'invalid Ed25519 public key',
        ) from exc
    except Exception as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.PROVIDER_UNAVAILABLE, VerificationStage.SIGNATURE,
            f'cryptographic provider could not load the public key: {exc}',
        ) from exc
    try:
        verifier.verify(signature, message)
    except (invalid_signature, ValueError) as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.SIGNATURE, VerificationStage.SIGNATURE,
            'Ed25519 signature verification failed',
        ) from exc
    except Exception as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.PROVIDER_UNAVAILABLE, VerificationStage.SIGNATURE,
            f'cryptographic provider failed during verification: {exc}',
        ) from exc


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


def _graph_limits_or_default(limits):
    if limits is None:
        return GraphVerificationLimits()
    if not isinstance(limits, GraphVerificationLimits):
        raise ProvenanceVerificationError(
            ErrorCategory.CONFIGURATION,
            VerificationStage.INPUT,
            'limits must be a GraphVerificationLimits instance or None',
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
        file_path = Path(path)
        path_before = os.lstat(file_path)
    except (OSError, TypeError, ValueError) as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.INPUT,
            VerificationStage.INPUT,
            f'cannot inspect {label}: {exc}',
        ) from exc

    if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
        raise ProvenanceVerificationError(
            ErrorCategory.RESOURCE_LIMIT,
            VerificationStage.INPUT,
            f'{label} must be a regular, non-symbolic-link file',
        )

    if os.name != 'nt' and (not hasattr(os, 'O_NONBLOCK') or not hasattr(os, 'O_NOFOLLOW')):
        raise ProvenanceVerificationError(
            ErrorCategory.INPUT,
            VerificationStage.INPUT,
            f'{label} cannot be opened safely on this platform',
        )
    flags = os.O_RDONLY
    for name in ('O_BINARY', 'O_CLOEXEC', 'O_NOINHERIT', 'O_NONBLOCK', 'O_NOFOLLOW'):
        flags |= getattr(os, name, 0)
    try:
        descriptor = os.open(file_path, flags)
    except (OSError, TypeError, ValueError) as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.INPUT,
            VerificationStage.INPUT,
            f'cannot open {label} safely: {exc}',
        ) from exc

    try:
        try:
            before = os.fstat(descriptor)
        except OSError as exc:
            raise ProvenanceVerificationError(
                ErrorCategory.INPUT,
                VerificationStage.INPUT,
                f'{label} handle could not be inspected safely: {exc}',
            ) from exc
        if not stat.S_ISREG(before.st_mode):
            raise ProvenanceVerificationError(
                ErrorCategory.RESOURCE_LIMIT,
                VerificationStage.INPUT,
                f'{label} handle must identify a regular file',
            )
        if _snapshot(path_before) != _snapshot(before):
            raise ProvenanceVerificationError(
                ErrorCategory.INPUT,
                VerificationStage.INPUT,
                f'{label} changed while it was being opened',
            )
        try:
            handle = open(descriptor, 'rb', buffering=0, closefd=True)
        except (OSError, TypeError, ValueError) as exc:
            raise ProvenanceVerificationError(
                ErrorCategory.INPUT,
                VerificationStage.INPUT,
                f'{label} descriptor could not be wrapped safely: {exc}',
            ) from exc
    except Exception:
        os.close(descriptor)
        raise
    stack.enter_context(handle)

    if before.st_size < 1 or before.st_size > maximum:
        raise ProvenanceVerificationError(
            ErrorCategory.RESOURCE_LIMIT,
            VerificationStage.INPUT,
            f'{label} size is outside the configured limit',
        )
    return _PreflightedFile(handle, _snapshot(before), label, file_path)


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
        handle_after = os.fstat(source.handle.fileno())
        path_after = os.lstat(source.path) if source.path is not None else None
    except OSError as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.INPUT,
            VerificationStage.INPUT,
            f'{source.label} could not be inspected after reading: {exc}',
        ) from exc
    if (not stat.S_ISREG(handle_after.st_mode)
            or _snapshot(handle_after) != source.snapshot
            or (path_after is not None
                and (stat.S_ISLNK(path_after.st_mode)
                     or not stat.S_ISREG(path_after.st_mode)
                     or _snapshot(path_after) != source.snapshot))):
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


def _validate_graph_record_inputs(records, limits):
    _validate_key_sequence(records, 'signed-event records')
    if not records:
        raise ProvenanceVerificationError(
            ErrorCategory.INPUT,
            VerificationStage.INPUT,
            'signed-event records must not be empty',
        )
    if len(records) > limits.event_records:
        raise ProvenanceVerificationError(
            ErrorCategory.RESOURCE_LIMIT,
            VerificationStage.INPUT,
            'too many signed-event records',
        )

    aggregate = 0
    for record in records:
        if type(record) is not bytes:
            raise ProvenanceVerificationError(
                ErrorCategory.INPUT,
                VerificationStage.INPUT,
                'signed-event record must be bytes',
            )
        if not 1 <= len(record) <= limits.event_bytes:
            raise ProvenanceVerificationError(
                ErrorCategory.RESOURCE_LIMIT,
                VerificationStage.INPUT,
                'signed-event record size is outside the configured limit',
            )
        aggregate += len(record)
        if aggregate > limits.aggregate_event_bytes:
            raise ProvenanceVerificationError(
                ErrorCategory.RESOURCE_LIMIT,
                VerificationStage.INPUT,
                'aggregate signed-event data exceeds the configured limit',
            )


def _index_signed_event_records(records, limits=None):
    """Strictly validate and deterministically index bounded signed records."""
    effective = _graph_limits_or_default(limits)
    _validate_graph_record_inputs(records, effective)

    ordered_records = [(_signed_event_sha256(record), record) for record in records]
    ordered_records.sort(key=lambda item: (item[0], item[1]))
    indexed = []
    for signed_event_sha256, record in ordered_records:
        validated = _parse_validate_record(record)
        _canonical_base64url(
            validated.document['signature'], 64, 'signature', VerificationStage.RECORD,
        )
        indexed.append(_IndexedSignedRecord(
            record=record,
            validated=validated,
            signed_event_sha256=signed_event_sha256,
        ))
    indexed.sort(key=lambda item: (
        item.validated.assertion['event_id'],
        item.signed_event_sha256,
        item.record,
    ))

    by_digest = {}
    by_event_id = {}
    duplicates = 0
    for item in indexed:
        digest_record = by_digest.get(item.signed_event_sha256)
        if digest_record is not None and digest_record != item.record:
            _fail(
                ErrorCategory.SIGNED_EVENT_DIGEST_COLLISION,
                VerificationStage.GRAPH,
                'signed-event digest identifies different record bytes',
            )
        by_digest[item.signed_event_sha256] = item.record

        event_id = item.validated.assertion['event_id']
        existing = by_event_id.get(event_id)
        if existing is not None:
            if existing.signed_event_sha256 != item.signed_event_sha256:
                _fail(
                    ErrorCategory.EVENT_ID_COLLISION,
                    VerificationStage.GRAPH,
                    'event_id identifies different signed-event digests',
                )
            duplicates += 1
            continue
        by_event_id[event_id] = item

    return _SignedEventIndex(by_event_id, duplicates)


def _resolve_signed_event_graph(index, limits=None):
    """Resolve exact parent identities and return a bounded DAG ordering."""
    effective = _graph_limits_or_default(limits)
    if not isinstance(index, _SignedEventIndex):
        _fail(
            ErrorCategory.CONFIGURATION,
            VerificationStage.INPUT,
            'index must be a _SignedEventIndex',
        )

    event_ids = sorted(index.by_event_id)
    children = {event_id: [] for event_id in event_ids}
    parent_counts = {}

    for event_id in event_ids:
        item = index.by_event_id[event_id]
        parents = item.validated.assertion['parents']
        if len(parents) > effective.parent_fanout:
            _fail(
                ErrorCategory.RESOURCE_LIMIT,
                VerificationStage.GRAPH,
                'event parent fanout exceeds the configured limit',
            )
        parent_counts[event_id] = len(parents)
        for reference in parents:
            parent_id = reference['event_id']
            parent = index.by_event_id.get(parent_id)
            if parent is None:
                _fail(
                    ErrorCategory.MISSING_PARENT,
                    VerificationStage.GRAPH,
                    'declared parent event_id is absent',
                )
            referenced_digest = reference['signed_event_digest']['value']
            if parent.signed_event_sha256 != referenced_digest:
                _fail(
                    ErrorCategory.PARENT_DIGEST_MISMATCH,
                    VerificationStage.GRAPH,
                    'declared parent digest does not match the indexed event',
                )
            children[parent_id].append(event_id)

    eligible = [event_id for event_id in event_ids if parent_counts[event_id] == 0]
    heapq.heapify(eligible)
    depths = {event_id: 1 for event_id in eligible}
    ordered = []
    maximum_depth = 0
    depth_exceeded = False

    while eligible:
        event_id = heapq.heappop(eligible)
        ordered.append(index.by_event_id[event_id])
        depth = depths[event_id]
        maximum_depth = max(maximum_depth, depth)
        if depth > effective.graph_depth:
            depth_exceeded = True

        for child_id in children[event_id]:
            depths[child_id] = max(depths.get(child_id, 1), depth + 1)
            parent_counts[child_id] -= 1
            if parent_counts[child_id] == 0:
                heapq.heappush(eligible, child_id)

    if len(ordered) != len(event_ids):
        _fail(
            ErrorCategory.CYCLE,
            VerificationStage.GRAPH,
            'signed-event parent graph contains a directed cycle',
        )
    if depth_exceeded:
        _fail(
            ErrorCategory.RESOURCE_LIMIT,
            VerificationStage.GRAPH,
            'graph depth exceeds the configured limit',
        )

    return _ResolvedSignedEventGraph(tuple(ordered), maximum_depth)


def _verify_package_for_binding(package_path):
    """Independently verify one Draft 0.2 package for subject binding."""
    try:
        return core.verify_detailed(package_path)
    except core.AuralError as exc:
        raise ProvenanceVerificationError(
            ErrorCategory.PACKAGE_INTEGRITY,
            VerificationStage.PACKAGE,
            f'AURAL package verification failed: {exc}',
        ) from exc


def _validate_package_binding(assertion, package):
    """Compare all six signed subject fields with verified package metadata."""
    subject = assertion['subject']
    original = subject['original']
    if (package['format'] != subject['format']
            or package['version'] != subject['version']
            or package['manifest_sha256'] != subject['manifest_sha256']
            or package['original_path'] != original['path']
            or package['audio_sha256'] != original['sha256']
            or package['audio_bytes'] != original['byte_length']):
        _fail(
            ErrorCategory.SUBJECT_BINDING,
            VerificationStage.PACKAGE,
            'signed subject does not match the independently verified AURAL package',
        )


def _verify_validated_signed_event(
        record, validated, validated_keys, signed_event_sha256=None,
):
    """Verify one already parsed record against one validated key index."""
    assertion = validated.assertion
    selected_key = _select_public_key(
        validated_keys, assertion['signing_key_id'],
    )
    signature = _canonical_base64url(
        validated.document['signature'], 64, 'signature', VerificationStage.SIGNATURE,
    )
    assertion_bytes = _jcs_text(
        assertion, VerificationStage.SIGNATURE,
    ).encode('utf-8')
    _verify_ed25519_profile(
        selected_key.public_key, SIGNATURE_DOMAIN + assertion_bytes, signature,
    )

    return VerificationResult(
        status=VerificationStatus.SIGNATURE_VALID,
        event_id=assertion['event_id'],
        evidence_id=assertion['evidence_id'],
        signing_key_id=assertion['signing_key_id'],
        signed_event_sha256=(signed_event_sha256
                             if signed_event_sha256 is not None
                             else _signed_event_sha256(record)),
        asset_integrity=AssetIntegrityStatus.NOT_CHECKED,
        investigator_identity=InvestigatorIdentityStatus.NOT_ESTABLISHED,
        key_trust=KeyTrustStatus.NOT_EVALUATED,
        time_assurance=(TimeAssuranceStatus.CLAIMED_ONLY
                        if 'claimed_times' in assertion['claims']
                        else TimeAssuranceStatus.UNKNOWN),
        history_completeness=HistoryCompletenessStatus.NOT_ESTABLISHED,
        declared_parent_count=len(assertion['parents']),
    )


def verify_signed_event(
        record: bytes,
        public_key_records: Sequence[bytes],
        *,
        package_path: Optional[PathLike] = None,
        limits: Optional[VerificationLimits] = None,
) -> VerificationResult:
    """Validate a detached record and return a signature-only result."""
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
    validated_keys = _validate_public_key_records(public_key_records)
    result = _verify_validated_signed_event(record, validated, validated_keys)
    if package_path is not None:
        package = _verify_package_for_binding(package_path)
        _validate_package_binding(validated.assertion, package)
        result = replace(result, asset_integrity=AssetIntegrityStatus.VERIFIED)
    return result


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


def verify_signed_event_graph(
        records: Sequence[bytes],
        public_key_records: Sequence[bytes],
        *,
        package_path: Optional[PathLike] = None,
        limits: Optional[GraphVerificationLimits] = None,
) -> GraphVerificationResult:
    """Verify graph structure, every unique signature, and optional binding.

    ``CLOSED`` describes only resolution of the supplied parent references.
    History completeness remains unestablished.  When ``package_path`` is
    omitted, each event reports that physical package integrity was not checked.
    """
    effective = _graph_limits_or_default(limits)
    _validate_graph_record_inputs(records, effective)

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

    index = _index_signed_event_records(records, effective)
    resolved = _resolve_signed_event_graph(index, effective)
    validated_keys = _validate_public_key_records(public_key_records)
    verified_events = [
        _verify_validated_signed_event(
            indexed_record.record,
            indexed_record.validated,
            validated_keys,
            indexed_record.signed_event_sha256,
        )
        for indexed_record in resolved.records
    ]

    if package_path is not None:
        package = _verify_package_for_binding(package_path)
        for indexed_record in resolved.records:
            _validate_package_binding(indexed_record.validated.assertion, package)
        verified_events = [
            replace(event, asset_integrity=AssetIntegrityStatus.VERIFIED)
            for event in verified_events
        ]

    return GraphVerificationResult(
        status=GraphVerificationStatus.CONSISTENT,
        events=tuple(verified_events),
        duplicate_signed_records=index.duplicate_signed_records,
        maximum_depth=resolved.maximum_depth,
        declared_parent_closure=ParentClosureStatus.CLOSED,
        history_completeness=HistoryCompletenessStatus.NOT_ESTABLISHED,
    )


def verify_signed_event_graph_files(
        event_paths: Sequence[PathLike],
        key_paths: Sequence[PathLike],
        *,
        package_path: Optional[PathLike] = None,
        limits: Optional[GraphVerificationLimits] = None,
) -> GraphVerificationResult:
    """Read bounded detached graph inputs, then invoke graph preflight."""
    effective = _graph_limits_or_default(limits)
    _validate_key_sequence(event_paths, 'signed-event paths')
    if not event_paths:
        raise ProvenanceVerificationError(
            ErrorCategory.INPUT,
            VerificationStage.INPUT,
            'signed-event paths must not be empty',
        )
    if len(event_paths) > effective.event_records:
        raise ProvenanceVerificationError(
            ErrorCategory.RESOURCE_LIMIT,
            VerificationStage.INPUT,
            'too many signed-event paths',
        )
    _validate_key_sequence(key_paths, 'public-key paths')
    if len(key_paths) > effective.key_records:
        raise ProvenanceVerificationError(
            ErrorCategory.RESOURCE_LIMIT,
            VerificationStage.INPUT,
            'too many public-key records',
        )

    record_raws = []
    aggregate = 0
    for index, path in enumerate(event_paths):
        with ExitStack() as stack:
            event = _open_preflighted_file(
                stack, path, effective.event_bytes,
                f'signed-event record {index}',
            )
            aggregate += event.snapshot.size
            if aggregate > effective.aggregate_event_bytes:
                raise ProvenanceVerificationError(
                    ErrorCategory.RESOURCE_LIMIT,
                    VerificationStage.INPUT,
                    'aggregate signed-event data exceeds the configured limit',
                )
            record_raws.append(_read_preflighted_file(event))

    key_record_raws = []
    aggregate = 0
    for path in key_paths:
        with ExitStack() as stack:
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
            key_record_raws.append(_read_preflighted_file(key))

    return verify_signed_event_graph(
        record_raws,
        key_record_raws,
        package_path=package_path,
        limits=effective,
    )


__all__ = [
    'AssetIntegrityStatus',
    'ErrorCategory',
    'GraphVerificationLimits',
    'GraphVerificationResult',
    'GraphVerificationStatus',
    'HistoryCompletenessStatus',
    'InvestigatorIdentityStatus',
    'KeyTrustStatus',
    'ParentClosureStatus',
    'ProvenanceVerificationError',
    'TimeAssuranceStatus',
    'VerificationLimits',
    'VerificationResult',
    'VerificationStage',
    'VerificationStatus',
    'verify_signed_event',
    'verify_signed_event_files',
    'verify_signed_event_graph',
    'verify_signed_event_graph_files',
]
