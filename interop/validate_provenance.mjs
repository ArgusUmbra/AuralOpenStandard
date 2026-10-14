#!/usr/bin/env node
// Independent validator for the experimental AURAL provenance signature v1 profile.
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { verifyDetailed as verifyAuralDetailed } from './validate_aural.mjs';

const EVENT_SCHEMA = 'org.aural.provenance-event';
const EVENT_SCHEMA_VERSION = '1';
const SIGNATURE_PROFILE = 'org.aural.signature.ed25519-jcs-v1';
const EVENT_TYPE = 'urn:aural:event:original-asset-acquired:1';
const KEY_SCHEMA = 'org.aural.signing-key';
const KEY_SCHEMA_VERSION = '1';
const KEY_ALGORITHM = 'Ed25519';
const DOMAIN = Buffer.from('AURAL-PROVENANCE-EVENT-V1\0', 'ascii');
const RECORD_DOMAIN = Buffer.from('AURAL-SIGNED-EVENT-V1\0', 'ascii');
const KEY_DOMAIN = Buffer.from('AURAL-KEY-ID-V1\0Ed25519\0', 'ascii');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const MAX_RECORD = 1024 * 1024;
const MAX_KEY_RECORD = 16 * 1024;
const MAX_KEY_RECORDS = 64;
const MAX_KEY_DATA = 256 * 1024;
const MAX_DEPTH = 32;
const MAX_PARENTS = 4096;
const ED25519_P = (1n << 255n) - 19n;
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const SMALL_ORDER_Y = new Set([
  0n,
  1n,
  ED25519_P - 1n,
  BigInt('0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7'),
  BigInt('0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826'),
]);

function fail(category, message) {
  const error = new Error(message);
  error.category = category;
  throw error;
}

function checkString(value) {
  for (let i = 0; i < value.length; i++) {
    const first = value.charCodeAt(i);
    let point = first;
    if (first >= 0xd800 && first <= 0xdbff) {
      if (i + 1 >= value.length) fail('json_profile', 'unpaired Unicode surrogate');
      const second = value.charCodeAt(++i);
      if (second < 0xdc00 || second > 0xdfff) fail('json_profile', 'unpaired Unicode surrogate');
      point = 0x10000 + ((first - 0xd800) << 10) + second - 0xdc00;
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      fail('json_profile', 'unpaired Unicode surrogate');
    }
    if ((point >= 0xfdd0 && point <= 0xfdef)
        || (point & 0xffff) === 0xfffe || (point & 0xffff) === 0xffff) {
      fail('json_profile', 'Unicode noncharacter');
    }
  }
}

function canonical(value, containingDepth = 0) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    checkString(value);
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      fail('json_profile', 'JSON numbers must be safe integers and not negative zero');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const depth = containingDepth + 1;
    if (depth > MAX_DEPTH) fail('resource_limit', 'JSON nesting depth exceeds 32');
    return '[' + value.map(item => canonical(item, depth)).join(',') + ']';
  }
  if (value && typeof value === 'object') {
    const depth = containingDepth + 1;
    if (depth > MAX_DEPTH) fail('resource_limit', 'JSON nesting depth exceeds 32');
    return '{' + Object.keys(value).sort().map(key => {
      checkString(key);
      return JSON.stringify(key) + ':' + canonical(value[key], depth);
    }).join(',') + '}';
  }
  fail('json_profile', 'unsupported JSON value');
}

function parseCanonical(raw, label, maximum) {
  if (!Buffer.isBuffer(raw)) fail('input', `${label} must be supplied as bytes`);
  if (raw.length === 0 || raw.length > maximum) fail('resource_limit', `${label} size is invalid`);
  if (raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) {
    fail('json_profile', `${label} has a UTF-8 BOM`);
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch {
    fail('json_profile', `${label} is not strict UTF-8`);
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail('json_profile', `${label} is malformed JSON`);
  }
  let encoded;
  try {
    encoded = Buffer.from(canonical(value), 'utf8');
  } catch (error) {
    if (error.category) throw error;
    fail('json_profile', `${label} cannot be canonicalized`);
  }
  if (!raw.equals(encoded)) fail('canonicalization', `${label} is not exact RFC 8785 JCS`);
  return value;
}

function exactKeys(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return required.every(key => actual.includes(key))
    && actual.every(key => required.includes(key) || optional.includes(key));
}

function canonicalBase64url(value, expectedLength, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    fail('encoding', `${label} is not unpadded base64url`);
  }
  let decoded;
  try {
    decoded = Buffer.from(value, 'base64url');
  } catch {
    fail('encoding', `${label} is not valid base64url`);
  }
  if (decoded.length !== expectedLength || decoded.toString('base64url') !== value) {
    fail('encoding', `${label} has the wrong length or a noncanonical encoding`);
  }
  return decoded;
}

function littleEndianInteger(bytes) {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) result = (result << 8n) | BigInt(bytes[i]);
  return result;
}

function validateEd25519PointEncoding(encoded, label, category) {
  if (!Buffer.isBuffer(encoded) || encoded.length !== 32) fail(category, `${label} must be 32 bytes`);
  const copy = Buffer.from(encoded);
  const sign = copy[31] >>> 7;
  copy[31] &= 0x7f;
  const y = littleEndianInteger(copy);
  if (y >= ED25519_P || (sign === 1 && (y === 1n || y === ED25519_P - 1n))) {
    fail(category, `${label} is not a canonical Ed25519 point encoding`);
  }
  if (SMALL_ORDER_Y.has(y)) fail(category, `${label} has small order`);
}

function verifyEd25519ProfileOrFail(publicKeyBytes, message, signature) {
  validateEd25519PointEncoding(publicKeyBytes, 'Ed25519 public key', 'public_key');
  validateEd25519PointEncoding(signature.subarray(0, 32), 'Ed25519 signature R', 'signature');
  if (littleEndianInteger(signature.subarray(32)) >= ED25519_L) {
    fail('signature', 'Ed25519 signature scalar S is out of range');
  }
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, publicKeyBytes]), format: 'der', type: 'spki',
    });
  } catch {
    fail('public_key', 'invalid Ed25519 public key');
  }
  if (!verifySignature(null, message, publicKey, signature)) {
    fail('signature', 'Ed25519 signature verification failed');
  }
}

export function verifyEd25519Profile(publicKeyBytes, message, signature) {
  try {
    if (!Buffer.isBuffer(publicKeyBytes) || !Buffer.isBuffer(message) || !Buffer.isBuffer(signature)
        || publicKeyBytes.length !== 32 || signature.length !== 64) return false;
    verifyEd25519ProfileOrFail(publicKeyBytes, message, signature);
    return true;
  } catch {
    return false;
  }
}

function validUuidUrn(value) {
  return typeof value === 'string'
    && /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}

function validHash(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function validTimestamp(value) {
  if (typeof value !== 'string') return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match || value.endsWith('-00:00')) return false;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  if (!year || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > days[month - 1]) return false;
  if (match[7] !== 'Z') {
    const hours = Number(match[7].slice(1, 3));
    const minutes = Number(match[7].slice(4));
    if (hours > 14 || minutes > 59 || (hours === 14 && minutes !== 0)) return false;
  }
  return true;
}

function scalarLength(value) {
  return typeof value === 'string' ? [...value].length : -1;
}

function validateExtensions(container, knownExtensions = new Set()) {
  const extensions = container.extensions ?? {};
  const critical = container.critical_extensions ?? [];
  const idPattern = /^[a-z][a-z0-9+.-]*:[!-~]+$/;
  if (!extensions || typeof extensions !== 'object' || Array.isArray(extensions)) {
    fail('schema', 'extensions must be an object');
  }
  for (const id of Object.keys(extensions)) {
    if (!idPattern.test(id) || Buffer.byteLength(id, 'ascii') > 255) {
      fail('schema', 'invalid extension identifier');
    }
  }
  if (!Array.isArray(critical) || new Set(critical).size !== critical.length) {
    fail('schema', 'critical_extensions must be a unique array');
  }
  for (const id of critical) {
    if (typeof id !== 'string' || !idPattern.test(id) || !(id in extensions)) {
      fail('schema', 'critical extension is malformed or missing its value');
    }
    if (!knownExtensions.has(id)) fail('unsupported_extension', `unsupported critical extension: ${id}`);
  }
}

function computedKeyId(publicKey) {
  const fingerprint = createHash('sha256').update(KEY_DOMAIN).update(publicKey).digest('hex');
  return `urn:aural:key:ed25519:${fingerprint}`;
}

function validateKeyRecord(raw) {
  const key = parseCanonical(raw, 'public-key record', MAX_KEY_RECORD);
  const required = ['algorithm', 'key_id', 'key_schema', 'key_schema_version', 'public_key'];
  if (!exactKeys(key, required, ['extensions', 'critical_extensions'])) {
    fail('schema', 'public-key record has missing or unknown core members');
  }
  if (key.key_schema !== KEY_SCHEMA || key.key_schema_version !== KEY_SCHEMA_VERSION) {
    fail('unsupported_version', 'unsupported public-key record schema or version');
  }
  if (key.algorithm !== KEY_ALGORITHM) fail('unsupported_algorithm', 'unsupported public-key algorithm');
  validateExtensions(key);
  const publicKey = canonicalBase64url(key.public_key, 32, 'public_key');
  validateEd25519PointEncoding(publicKey, 'Ed25519 public key', 'public_key');
  const expectedId = computedKeyId(publicKey);
  if (key.key_id !== expectedId) fail('key_id_mismatch', 'public key does not match key_id');
  return { ...key, publicKey };
}

function validateParentReferences(assertion) {
  if (!Array.isArray(assertion.parents) || assertion.parents.length > MAX_PARENTS) {
    fail('schema', 'parents must be an array of at most 4096 references');
  }
  let previous = null;
  const seen = new Set();
  for (const parent of assertion.parents) {
    if (!exactKeys(parent, ['event_id', 'signed_event_digest'])
        || !validUuidUrn(parent.event_id)
        || !exactKeys(parent.signed_event_digest, ['algorithm', 'value'])) {
      fail('schema', 'malformed parent reference');
    }
    if (parent.event_id === assertion.event_id) fail('parent_reference', 'self-reference is prohibited');
    if (seen.has(parent.event_id)) fail('parent_reference', 'duplicate parent event_id');
    if (previous !== null && parent.event_id <= previous) {
      fail('parent_reference', 'parents are not in ascending event_id order');
    }
    if (parent.signed_event_digest.algorithm !== 'sha-256') {
      fail('unsupported_algorithm', 'unsupported parent digest algorithm');
    }
    if (!validHash(parent.signed_event_digest.value)) {
      fail('parent_reference', 'parent digest must be 32-byte lowercase hexadecimal SHA-256');
    }
    seen.add(parent.event_id);
    previous = parent.event_id;
  }
}

function validateSubject(subject) {
  if (!exactKeys(subject, ['format', 'manifest_sha256', 'original', 'version'])) {
    fail('schema', 'subject has missing or unknown members');
  }
  if (subject.format !== 'org.aural.audio-evidence' || subject.version !== '0.2-draft') {
    fail('unsupported_version', 'subject is not an AURAL Draft 0.2 container');
  }
  if (!validHash(subject.manifest_sha256)) fail('schema', 'invalid manifest_sha256');
  if (!exactKeys(subject.original, ['byte_length', 'path', 'sha256'])) {
    fail('schema', 'subject.original has missing or unknown members');
  }
  if (subject.original.path !== 'audio/original.wav' || !validHash(subject.original.sha256)
      || !Number.isSafeInteger(subject.original.byte_length)
      || subject.original.byte_length < 0 || subject.original.byte_length > 8 * 1024 ** 3) {
    fail('schema', 'invalid original asset binding');
  }
}

function validateClaims(claims, signingKeyId) {
  const required = [
    'acquiring_key_id', 'acquisition_method', 'earlier_modification_history',
    'key_protection', 'source_description', 'source_type',
  ];
  const optional = ['acquisition_environment', 'claimed_times'];
  if (!exactKeys(claims, required, optional)) {
    fail('schema', 'claims have missing or unknown core members');
  }
  if (!['native-capture', 'external-recorder-import', 'received-evidence-import', 'other-import']
    .includes(claims.acquisition_method)) fail('schema', 'unsupported acquisition_method');
  if (!['device-microphone', 'external-recorder', 'received-evidence', 'other']
    .includes(claims.source_type)) fail('schema', 'unsupported source_type');
  const sourceForMethod = {
    'native-capture': 'device-microphone',
    'external-recorder-import': 'external-recorder',
    'received-evidence-import': 'received-evidence',
    'other-import': 'other',
  };
  if (claims.source_type !== sourceForMethod[claims.acquisition_method]) {
    fail('schema', 'source_type does not match acquisition_method');
  }
  if (!['none-known', 'known', 'unknown'].includes(claims.earlier_modification_history)) {
    fail('schema', 'unsupported earlier_modification_history value');
  }
  if (!['software', 'os-keystore', 'hardware-backed', 'secure-element', 'unknown']
    .includes(claims.key_protection)) fail('schema', 'unsupported key_protection value');
  if (claims.acquiring_key_id !== signingKeyId) {
    fail('schema', 'acquiring_key_id must equal signing_key_id');
  }
  if (scalarLength(claims.source_description) < 1 || scalarLength(claims.source_description) > 4096) {
    fail('schema', 'source_description length is invalid');
  }
  if ('acquisition_environment' in claims
      && (scalarLength(claims.acquisition_environment) < 1
          || scalarLength(claims.acquisition_environment) > 4096)) {
    fail('schema', 'acquisition_environment length is invalid');
  }
  if ('claimed_times' in claims) {
    if (!Array.isArray(claims.claimed_times) || claims.claimed_times.length < 1
        || claims.claimed_times.length > 3) fail('schema', 'claimed_times length is invalid');
    const seen = new Set();
    const order = new Map([['device-reported', 0], ['import', 1], ['signing', 2]]);
    let previous = -1;
    for (const time of claims.claimed_times) {
      if (!exactKeys(time, ['basis', 'value'])
          || !['device-reported', 'import', 'signing'].includes(time.basis)) {
        fail('unsupported_time_basis', 'unsupported or malformed claimed-time basis');
      }
      if (seen.has(time.basis)) fail('schema', 'claimed-time basis is duplicated');
      if (order.get(time.basis) <= previous) fail('schema', 'claimed-time entries are out of order');
      if (!validTimestamp(time.value)) fail('timestamp', 'malformed claimed-time RFC 3339 value');
      seen.add(time.basis);
      previous = order.get(time.basis);
    }
  }
}

function validateAssertion(assertion) {
  const required = [
    'claims', 'event_id', 'event_schema', 'event_schema_version', 'event_type',
    'evidence_id', 'parents', 'signature_profile', 'signing_key_id', 'subject',
  ];
  if (!exactKeys(assertion, required, ['extensions', 'critical_extensions'])) {
    fail('schema', 'assertion has missing or unknown core members');
  }
  if (assertion.event_schema !== EVENT_SCHEMA || assertion.event_schema_version !== EVENT_SCHEMA_VERSION) {
    fail('unsupported_version', 'unsupported event schema or version');
  }
  if (assertion.signature_profile !== SIGNATURE_PROFILE) {
    fail('unsupported_signature_profile', 'unsupported signature profile');
  }
  if (!validUuidUrn(assertion.event_id) || !validUuidUrn(assertion.evidence_id)) {
    fail('identifier', 'event_id and evidence_id must be lowercase UUIDv4 URNs');
  }
  if (!/^urn:aural:key:ed25519:[0-9a-f]{64}$/.test(assertion.signing_key_id)) {
    fail('identifier', 'invalid signing_key_id');
  }
  validateExtensions(assertion);
  validateParentReferences(assertion);
  validateSubject(assertion.subject);
  if (assertion.event_type !== EVENT_TYPE) fail('unsupported_event_type', 'unsupported event_type');
  validateClaims(assertion.claims, assertion.signing_key_id);
}

export function verifySignedEvent(recordRaw, keyRecordRaws, options = {}) {
  const maximum = Number.isSafeInteger(options.maxRecord) && options.maxRecord >= 0
    ? Math.min(options.maxRecord, MAX_RECORD) : MAX_RECORD;
  const record = parseCanonical(recordRaw, 'signed-event record', maximum);
  if (!exactKeys(record, ['assertion', 'signature'])) {
    fail('schema', 'signed-event envelope must contain exactly assertion and signature');
  }
  validateAssertion(record.assertion);
  if (!Array.isArray(keyRecordRaws)) fail('input', 'public-key records must be an array');
  const maxKeyRecords = boundedOption(options.maxKeyRecords, MAX_KEY_RECORDS);
  const maxKeyData = boundedOption(options.maxKeyData, MAX_KEY_DATA);
  if (keyRecordRaws.length > maxKeyRecords) fail('resource_limit', 'too many public-key records');
  const keys = new Map();
  let aggregateKeyData = 0;
  for (const raw of keyRecordRaws) {
    if (!Buffer.isBuffer(raw)) fail('input', 'public-key record must be supplied as bytes');
    aggregateKeyData += raw.length;
    if (aggregateKeyData > maxKeyData) {
      fail('resource_limit', 'aggregate public-key data exceeds limit');
    }
    const key = validateKeyRecord(raw);
    if (keys.has(key.key_id)) fail('duplicate_key', 'duplicate public-key record for key_id');
    keys.set(key.key_id, key);
  }
  const key = keys.get(record.assertion.signing_key_id);
  if (!key) fail('missing_key', 'no public-key record matches signing_key_id');
  const signature = canonicalBase64url(record.signature, 64, 'signature');
  const assertionBytes = Buffer.from(canonical(record.assertion), 'utf8');
  const signatureInput = Buffer.concat([DOMAIN, assertionBytes]);
  verifyEd25519ProfileOrFail(key.publicKey, signatureInput, signature);
  const signedEventDigest = createHash('sha256').update(RECORD_DOMAIN).update(recordRaw).digest('hex');
  return {
    status: 'signature_valid',
    event_id: record.assertion.event_id,
    evidence_id: record.assertion.evidence_id,
    signing_key_id: record.assertion.signing_key_id,
    signed_event_sha256: signedEventDigest,
    asset_integrity: 'not_checked',
    investigator_identity: 'not_established',
    key_trust: 'not_evaluated',
    time_assurance: record.assertion.claims.claimed_times ? 'claimed_only' : 'unknown',
    history_completeness: 'not_established',
    assertion: record.assertion,
  };
}

function sameSnapshot(before, after) {
  return before.dev === after.dev && before.ino === after.ino && before.size === after.size
    && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs;
}

function safeOpenFlags(label) {
  if (process.platform !== 'win32'
      && (!Number.isInteger(constants.O_NONBLOCK)
          || !Number.isInteger(constants.O_NOFOLLOW))) {
    fail('input', `${label} cannot be opened safely on this platform`);
  }
  let flags = constants.O_RDONLY;
  for (const flag of [constants.O_CLOEXEC, constants.O_NONBLOCK, constants.O_NOFOLLOW]) {
    if (Number.isInteger(flag)) flags |= flag;
  }
  return flags;
}

async function readStableBoundedFile(filePath, maximum, label) {
  let pathBefore;
  try {
    pathBefore = await lstat(filePath, { bigint: true });
  } catch (error) {
    fail('input', `${label} could not be inspected safely`);
  }
  if (pathBefore.isSymbolicLink() || !pathBefore.isFile()) {
    fail('resource_limit', `${label} must be a regular, non-symbolic-link file`);
  }

  let handle;
  try {
    handle = await open(filePath, safeOpenFlags(label));
  } catch (error) {
    if (error?.category) throw error;
    fail('input', `${label} could not be opened safely`);
  }
  let failed = false;
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) {
      fail('resource_limit', `${label} handle must identify a regular file`);
    }
    if (!sameSnapshot(pathBefore, before)) {
      fail('input', `${label} changed while it was being opened`);
    }
    if (before.size < 1n || before.size > BigInt(maximum)) {
      fail('resource_limit', `${label} size or file type is invalid`);
    }
    const raw = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < raw.length) {
      const { bytesRead } = await handle.read(raw, offset, raw.length - offset, offset);
      if (bytesRead === 0) fail('input', `${label} was truncated during reading`);
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    let pathAfter;
    try {
      pathAfter = await lstat(filePath, { bigint: true });
    } catch (error) {
      fail('input', `${label} changed or disappeared during reading`);
    }
    if (!after.isFile() || pathAfter.isSymbolicLink() || !pathAfter.isFile()
        || !sameSnapshot(before, after) || !sameSnapshot(before, pathAfter)) {
      fail('input', `${label} changed during reading`);
    }
    return raw;
  } catch (error) {
    failed = true;
    if (error?.category) throw error;
    fail('input', `${label} could not be processed safely`);
  } finally {
    try {
      await handle.close();
    } catch (error) {
      if (!failed) fail('input', `${label} could not be closed safely`);
    }
  }
}

function boundedOption(value, maximum) {
  return Number.isSafeInteger(value) && value >= 0 ? Math.min(value, maximum) : maximum;
}

export async function verifySignedEventFiles(
  eventPath, keyPaths, packagePath = undefined, options = {},
) {
  if (!Array.isArray(keyPaths)) fail('input', 'public-key paths must be an array');
  const maxKeyRecords = boundedOption(options.maxKeyRecords, MAX_KEY_RECORDS);
  if (keyPaths.length > maxKeyRecords) fail('resource_limit', 'too many public-key records');
  const maxRecord = boundedOption(options.maxRecord, MAX_RECORD);
  const maxKeyRecord = boundedOption(options.maxKeyRecord, MAX_KEY_RECORD);
  const maxKeyData = boundedOption(options.maxKeyData, MAX_KEY_DATA);
  const recordRaw = await readStableBoundedFile(eventPath, maxRecord, 'signed-event record');
  const keyRecordRaws = [];
  let aggregateKeyData = 0;
  for (const keyPath of keyPaths) {
    const remainingKeyData = maxKeyData - aggregateKeyData;
    const raw = await readStableBoundedFile(
      keyPath, Math.min(maxKeyRecord, remainingKeyData), 'public-key record',
    );
    aggregateKeyData += raw.length;
    keyRecordRaws.push(raw);
  }
  const result = verifySignedEvent(recordRaw, keyRecordRaws);
  if (packagePath !== undefined) {
    let asset;
    try {
      asset = await verifyAuralDetailed(packagePath);
    } catch (error) {
      const detail = error?.auralValidationFailure === true
        ? error.message : 'package input could not be verified';
      fail('package_integrity', `AURAL package verification failed: ${detail}`);
    }
    const subject = result.assertion.subject;
    if (asset.version !== subject.version || asset.format !== subject.format
        || asset.manifest_sha256 !== subject.manifest_sha256
        || asset.original_path !== subject.original.path
        || asset.audio_sha256 !== subject.original.sha256
        || asset.audio_bytes !== subject.original.byte_length) {
      fail('subject_binding', 'signed subject does not match the independently verified AURAL package');
    }
    result.asset_integrity = 'verified';
  }
  delete result.assertion;
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 5) {
      fail('usage', 'usage: node interop/validate_provenance.mjs EVENT KEY AURAL_PACKAGE');
    }
    console.log(JSON.stringify(await verifySignedEventFiles(
      process.argv[2], [process.argv[3]], process.argv[4],
    )));
  } catch (error) {
    console.error(`AURAL PROVENANCE ERROR [${error.category ?? 'internal'}]: ${error.message}`);
    process.exitCode = 1;
  }
}
