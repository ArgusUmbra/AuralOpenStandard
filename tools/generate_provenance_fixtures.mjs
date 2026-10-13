#!/usr/bin/env node
// Regenerate deterministic fixtures for the experimental provenance signature v1 profile.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'tests', 'fixtures', 'provenance');
const DOMAIN = Buffer.from('AURAL-PROVENANCE-EVENT-V1\0', 'ascii');
const RECORD_DOMAIN = Buffer.from('AURAL-SIGNED-EVENT-V1\0', 'ascii');
const KEY_DOMAIN = Buffer.from('AURAL-KEY-ID-V1\0Ed25519\0', 'ascii');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

// Edge cases 0-11 are the published ed25519-speccheck vectors (Apache-2.0).
// The identity case is the canonical trivial forgery accepted by cofactored-only policies.
const ed25519Adversarial = {
  source: 'https://github.com/novifinancial/ed25519-speccheck',
  source_license: 'Apache-2.0',
  policy: 'canonical points; reject small-order A and R; S < L; uncofactored equation',
  vectors: [
    {
      name: 'identity-key-identity-r', classification: 'identity points', expected: false,
      message: '5a63617368', public_key: '01' + '00'.repeat(31),
      signature: '01' + '00'.repeat(63),
    },
    {
      name: 'small-a-small-r', classification: 'small-order A and R', expected: false,
      message: '8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6',
      public_key: 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
      signature: 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a' + '00'.repeat(32),
    },
    {
      name: 'small-a-mixed-r', classification: 'small-order A', expected: false,
      message: '9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79',
      public_key: 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
      signature: 'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04',
    },
    {
      name: 'mixed-a-small-r', classification: 'small-order R', expected: false,
      message: 'aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab',
      public_key: 'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43',
      signature: 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e',
    },
    {
      name: 'mixed-a-mixed-r-uncofactored', classification: 'mixed-order points; exact equation holds', expected: true,
      message: '9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79',
      public_key: 'cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d',
      signature: '9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009',
    },
    {
      name: 'cofactored-only', classification: 'mixed-order points; cofactored equation only', expected: false,
      message: 'e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c',
      public_key: 'cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d',
      signature: '160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09',
    },
    {
      name: 'cofactored-prereduced', classification: 'cofactored equation variant only', expected: false,
      message: 'e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c',
      public_key: 'cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d',
      signature: '21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405',
    },
    {
      name: 'scalar-l-plus', classification: 'S greater than L', expected: false,
      message: '85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40',
      public_key: '442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623',
      signature: 'e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514',
    },
    {
      name: 'scalar-high', classification: 'S far greater than L', expected: false,
      message: '85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40',
      public_key: '442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623',
      signature: '8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22',
    },
    {
      name: 'noncanonical-r-reduced-hash', classification: 'noncanonical R', expected: false,
      message: '9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41',
      public_key: 'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43',
      signature: 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f',
    },
    {
      name: 'noncanonical-r-wire-hash', classification: 'noncanonical R', expected: false,
      message: '9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41',
      public_key: 'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43',
      signature: 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908',
    },
    {
      name: 'noncanonical-a-reduced-hash', classification: 'noncanonical A', expected: false,
      message: 'e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b',
      public_key: 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      signature: 'a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04',
    },
    {
      name: 'noncanonical-a-wire-hash', classification: 'noncanonical A', expected: false,
      message: '39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f',
      public_key: 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      signature: 'a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04',
    },
  ],
};

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number'
      || typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}

function bytes(value) { return Buffer.from(canonical(value), 'utf8'); }
function clone(value) { return structuredClone(value); }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }

// RFC 8032 test-vector seed #1. It is test-only material and is never emitted.
const testSeed = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
const privateKey = createPrivateKey({
  key: Buffer.concat([PKCS8_PREFIX, testSeed]), format: 'der', type: 'pkcs8',
});
const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
const publicKey = publicDer.subarray(publicDer.length - 32);
const keyId = 'urn:aural:key:ed25519:' + sha256(Buffer.concat([KEY_DOMAIN, publicKey]));

const keyRecord = {
  algorithm: 'Ed25519',
  key_id: keyId,
  key_schema: 'org.aural.signing-key',
  key_schema_version: '1',
  public_key: publicKey.toString('base64url'),
};

const assertion = {
  event_schema: 'org.aural.provenance-event',
  event_schema_version: '1',
  signature_profile: 'org.aural.signature.ed25519-jcs-v1',
  event_id: 'urn:uuid:11111111-2222-4333-8444-555555555555',
  event_type: 'urn:aural:event:original-asset-acquired:1',
  evidence_id: 'urn:uuid:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
  signing_key_id: keyId,
  subject: {
    format: 'org.aural.audio-evidence',
    version: '0.2-draft',
    manifest_sha256: '83ff69181aa5a1eb7b04a042eee89081a155a61736838615444f60c95672c3da',
    original: {
      path: 'audio/original.wav',
      sha256: '125f39eda3fea4265c129447c18ea5a89ed7302255c7a33ef104393c1f716873',
      byte_length: 52,
    },
  },
  parents: [],
  claims: {
    acquisition_method: 'external-recorder-import',
    source_type: 'external-recorder',
    source_description: 'Synthetic external-recorder import for conformance testing',
    acquiring_key_id: keyId,
    key_protection: 'software',
    earlier_modification_history: 'unknown',
    claimed_times: [
      { basis: 'device-reported', value: '2026-10-13T18:00:00Z' },
      { basis: 'import', value: '2026-10-13T18:05:00Z' },
      { basis: 'signing', value: '2026-10-13T18:05:01Z' },
    ],
    acquisition_environment: 'Synthetic test environment; no device authenticity claim',
  },
};

function signedRecord(value) {
  const assertionBytes = bytes(value);
  const signatureInput = Buffer.concat([DOMAIN, assertionBytes]);
  const signature = sign(null, signatureInput, privateKey);
  return {
    assertionBytes,
    signatureInput,
    signature,
    record: bytes({ assertion: value, signature: signature.toString('base64url') }),
  };
}

const cases = {};
const outputs = new Map();

function add(name, outcome, reason, category, eventBytes, keys = ['valid-key.json']) {
  const event = `${name}.json`;
  outputs.set(event, eventBytes);
  cases[name] = {
    outcome,
    reason,
    event,
    keys,
    package: '../conformance/valid-unicode.aural',
    ...(category ? { error_category: category } : {}),
  };
}

function addSignedInvalid(name, mutate, category, reason) {
  const value = clone(assertion);
  mutate(value);
  add(name, 'reject', reason, category, signedRecord(value).record);
}

const valid = signedRecord(assertion);
outputs.set('valid-key.json', bytes(keyRecord));
outputs.set('valid-original-acquired.assertion.json', valid.assertionBytes);
outputs.set('valid-original-acquired.signature-input.bin', valid.signatureInput);
outputs.set('ed25519-adversarial.json', Buffer.from(JSON.stringify(ed25519Adversarial, null, 2) + '\n'));
add('valid-original-acquired', 'accept', 'complete original-asset-acquired vector', null, valid.record);

const received = clone(assertion);
received.event_id = 'urn:uuid:11111111-2222-4333-a444-555555555555';
received.claims.acquisition_method = 'received-evidence-import';
received.claims.source_type = 'received-evidence';
received.claims.source_description = 'Synthetic receipt linked to an earlier signed acquisition event';
received.parents = [{
  event_id: assertion.event_id,
  signed_event_digest: {
    algorithm: 'sha-256',
    value: sha256(Buffer.concat([RECORD_DOMAIN, valid.record])),
  },
}];
add('valid-received-with-parent', 'accept', 'received evidence references the golden parent', null,
  signedRecord(received).record);

const optional = clone(assertion);
optional.event_id = 'urn:uuid:11111111-2222-4333-9444-555555555555';
optional.extensions = {
  'urn:example:annotation': { '\ue000': 'BMP', '𝄞': 'supplementary UTF-16 ordering' },
};
add('valid-unknown-optional', 'accept', 'unknown non-critical extension', null,
  signedRecord(optional).record);

add('invalid-noncanonical', 'reject', 'pretty-printed record is not exact JCS', 'canonicalization',
  Buffer.from(JSON.stringify(JSON.parse(valid.record), null, 2), 'utf8'));
add('invalid-trailing-newline', 'reject', 'canonical record has a trailing LF', 'canonicalization',
  Buffer.concat([valid.record, Buffer.from('\n')]));
add('invalid-bom', 'reject', 'record begins with a UTF-8 BOM', 'json_profile',
  Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), valid.record]));
const invalidUtf8 = Buffer.from(valid.record);
const utf8Target = invalidUtf8.indexOf(Buffer.from('Synthetic external-recorder'));
invalidUtf8[utf8Target] = 0xff;
add('invalid-utf8', 'reject', 'record contains invalid UTF-8', 'json_profile', invalidUtf8);
const duplicateNameText = valid.record.toString('utf8');
const duplicateSignature = JSON.parse(duplicateNameText).signature;
add('invalid-duplicate-name', 'reject', 'envelope contains a duplicate signature name',
  'canonicalization', Buffer.from(duplicateNameText.slice(0, -1)
    + `,"signature":${JSON.stringify(duplicateSignature)}}`));
const envelopeMember = JSON.parse(valid.record);
envelopeMember.signatures = [];
add('invalid-envelope-member', 'reject', 'unknown envelope member suggests multisignature', 'schema',
  bytes(envelopeMember));

const badSignature = JSON.parse(valid.record);
const signatureBytes = Buffer.from(badSignature.signature, 'base64url');
signatureBytes[0] ^= 1;
badSignature.signature = signatureBytes.toString('base64url');
add('invalid-signature', 'reject', 'one signature bit is changed', 'signature', bytes(badSignature));

const paddedSignature = JSON.parse(valid.record);
paddedSignature.signature += '==';
add('invalid-padded-signature', 'reject', 'signature uses padded base64url', 'encoding',
  bytes(paddedSignature));
const noncanonicalScalar = JSON.parse(valid.record);
noncanonicalScalar.signature = Buffer.alloc(64, 0xff).toString('base64url');
add('invalid-signature-scalar', 'reject', 'signature has an out-of-range S scalar', 'signature',
  bytes(noncanonicalScalar));

addSignedInvalid('invalid-signature-profile', value => {
  value.signature_profile = 'org.aural.signature.future-v2';
}, 'unsupported_signature_profile', 'unknown signature profile fails closed');
addSignedInvalid('invalid-schema-version', value => {
  value.event_schema_version = '2';
}, 'unsupported_version', 'unknown event schema version fails closed');
addSignedInvalid('invalid-event-id', value => {
  value.event_id = 'urn:uuid:11111111-2222-1333-8444-555555555555';
}, 'identifier', 'event identifier is not UUIDv4');
addSignedInvalid('invalid-unknown-member', value => {
  value.unprotected_meaning = 'not allowed';
}, 'schema', 'unknown assertion core member');
addSignedInvalid('invalid-critical-extension', value => {
  value.extensions = { 'urn:example:critical': true };
  value.critical_extensions = ['urn:example:critical'];
}, 'unsupported_extension', 'unknown critical extension');
addSignedInvalid('invalid-critical-extension-missing', value => {
  value.critical_extensions = ['urn:example:missing'];
}, 'schema', 'critical extension has no corresponding value');
addSignedInvalid('invalid-timestamp', value => {
  value.claims.claimed_times[0].value = '2026-02-30T18:00:00Z';
}, 'timestamp', 'invalid RFC 3339 calendar date');
addSignedInvalid('invalid-time-basis', value => {
  value.claims.claimed_times[0].basis = 'trusted';
}, 'unsupported_time_basis', 'trusted is not a supported claimed-time basis');
addSignedInvalid('invalid-time-order', value => {
  value.claims.claimed_times.reverse();
}, 'schema', 'claimed-time entries are out of required order');
addSignedInvalid('invalid-source-pair', value => {
  value.claims.source_type = 'device-microphone';
}, 'schema', 'source type does not match acquisition method');
addSignedInvalid('invalid-key-protection', value => {
  value.claims.key_protection = 'probably-hardware';
}, 'schema', 'unsupported key-protection disclosure');
addSignedInvalid('invalid-acquiring-key', value => {
  value.claims.acquiring_key_id = 'urn:aural:key:ed25519:' + '0'.repeat(64);
}, 'schema', 'acquiring key does not equal signing key');
addSignedInvalid('invalid-subject-manifest', value => {
  value.subject.manifest_sha256 = '0'.repeat(64);
}, 'subject_binding', 'manifest digest does not match package');
addSignedInvalid('invalid-subject-original', value => {
  value.subject.original.sha256 = '0'.repeat(64);
}, 'subject_binding', 'original digest does not match package');
addSignedInvalid('invalid-subject-length', value => {
  value.subject.original.byte_length = 51;
}, 'subject_binding', 'original length does not match package');

const selfParent = {
  event_id: assertion.event_id,
  signed_event_digest: { algorithm: 'sha-256', value: '1'.repeat(64) },
};
addSignedInvalid('invalid-parent-self', value => {
  value.parents = [selfParent];
}, 'parent_reference', 'event references itself as a parent');
addSignedInvalid('invalid-parent-duplicate', value => {
  const parent = {
    event_id: 'urn:uuid:00000000-0000-4000-8000-000000000001',
    signed_event_digest: { algorithm: 'sha-256', value: '1'.repeat(64) },
  };
  value.parents = [parent, clone(parent)];
}, 'parent_reference', 'duplicate parent event identifier');
addSignedInvalid('invalid-parent-order', value => {
  value.parents = [
    {
      event_id: 'urn:uuid:00000000-0000-4000-8000-000000000002',
      signed_event_digest: { algorithm: 'sha-256', value: '2'.repeat(64) },
    },
    {
      event_id: 'urn:uuid:00000000-0000-4000-8000-000000000001',
      signed_event_digest: { algorithm: 'sha-256', value: '1'.repeat(64) },
    },
  ];
}, 'parent_reference', 'parent array is not sorted');
addSignedInvalid('invalid-parent-digest', value => {
  value.parents = [{
    event_id: 'urn:uuid:00000000-0000-4000-8000-000000000001',
    signed_event_digest: { algorithm: 'sha-256', value: '1'.repeat(62) },
  }];
}, 'parent_reference', 'parent digest is not 32 bytes');
addSignedInvalid('invalid-parent-algorithm', value => {
  value.parents = [{
    event_id: 'urn:uuid:00000000-0000-4000-8000-000000000001',
    signed_event_digest: { algorithm: 'sha-512', value: '1'.repeat(64) },
  }];
}, 'unsupported_algorithm', 'unknown parent digest algorithm');
const fraction = Buffer.from(valid.record.toString('utf8').replace('"byte_length":52', '"byte_length":52.0'));
add('invalid-fraction', 'reject', 'floating-point JSON number', 'canonicalization', fraction);
const unsafe = Buffer.from(valid.record.toString('utf8').replace('"byte_length":52', '"byte_length":9007199254740992'));
add('invalid-unsafe-integer', 'reject', 'integer outside interoperable range', 'json_profile', unsafe);
const negativeZero = Buffer.from(valid.record.toString('utf8').replace('"byte_length":52', '"byte_length":-0'));
add('invalid-negative-zero', 'reject', 'negative zero JSON token', 'json_profile', negativeZero);
const surrogate = Buffer.from(valid.record.toString('utf8').replace(
  'Synthetic external-recorder import for conformance testing', '\\ud800'));
add('invalid-unpaired-surrogate', 'reject', 'unpaired escaped surrogate', 'json_profile', surrogate);
const noncharacter = Buffer.from(valid.record.toString('utf8').replace(
  'Synthetic external-recorder import for conformance testing', '\\ufdd0'));
add('invalid-noncharacter', 'reject', 'Unicode noncharacter', 'json_profile', noncharacter);

addSignedInvalid('invalid-excessive-depth', value => {
  let nested = true;
  for (let i = 0; i < 32; i++) nested = [nested];
  value.extensions = { 'urn:example:deep': nested };
}, 'resource_limit', 'complete record exceeds maximum JSON nesting depth');

const badKeyId = clone(keyRecord);
badKeyId.key_id = 'urn:aural:key:ed25519:' + '0'.repeat(64);
outputs.set('key-invalid-id.json', bytes(badKeyId));
add('invalid-key-id', 'reject', 'key_id does not match public key', 'key_id_mismatch', valid.record,
  ['key-invalid-id.json']);

const badKeyEncoding = clone(keyRecord);
badKeyEncoding.public_key += '=';
outputs.set('key-invalid-encoding.json', bytes(badKeyEncoding));
add('invalid-key-encoding', 'reject', 'padded public-key base64url', 'encoding', valid.record,
  ['key-invalid-encoding.json']);

const unknownKeyMember = clone(keyRecord);
unknownKeyMember.display_name = 'Unauthenticated Name';
outputs.set('key-invalid-unknown-member.json', bytes(unknownKeyMember));
add('invalid-key-unknown-member', 'reject', 'unknown public-key core member', 'schema', valid.record,
  ['key-invalid-unknown-member.json']);
const badKeyAlgorithm = clone(keyRecord);
badKeyAlgorithm.algorithm = 'Ed448';
outputs.set('key-invalid-algorithm.json', bytes(badKeyAlgorithm));
add('invalid-key-algorithm', 'reject', 'unsupported public-key algorithm', 'unsupported_algorithm',
  valid.record, ['key-invalid-algorithm.json']);

const identityPublicKey = Buffer.alloc(32);
identityPublicKey[0] = 1;
const identityKeyId = 'urn:aural:key:ed25519:'
  + sha256(Buffer.concat([KEY_DOMAIN, identityPublicKey]));
const identityKeyRecord = {
  algorithm: 'Ed25519',
  key_id: identityKeyId,
  key_schema: 'org.aural.signing-key',
  key_schema_version: '1',
  public_key: identityPublicKey.toString('base64url'),
};
const identityAssertion = clone(assertion);
identityAssertion.signing_key_id = identityKeyId;
identityAssertion.claims.acquiring_key_id = identityKeyId;
const identityForgery = bytes({
  assertion: identityAssertion,
  signature: Buffer.concat([identityPublicKey, Buffer.alloc(32)]).toString('base64url'),
});
outputs.set('key-invalid-small-order.json', bytes(identityKeyRecord));
add('invalid-public-key-small-order', 'reject', 'identity public key and identity-R forgery',
  'public_key', identityForgery, ['key-invalid-small-order.json']);
add('invalid-duplicate-key-record', 'reject', 'duplicate key_id in supplied key records', 'duplicate_key',
  valid.record, ['valid-key.json', 'valid-key.json']);
add('invalid-missing-key-record', 'reject', 'no supplied key matches signing_key_id', 'missing_key',
  valid.record, []);

async function main() {
  await mkdir(OUT, { recursive: true });
  for (const [name, payload] of outputs) await writeFile(path.join(OUT, name), payload);
  for (const item of Object.values(cases)) {
    const eventBytes = outputs.get(item.event);
    item.event_sha256 = sha256(eventBytes);
    if (item.outcome === 'accept') {
      item.signed_event_digest = sha256(Buffer.concat([RECORD_DOMAIN, eventBytes]));
    }
  }
  const packageBytes = await readFile(path.join(ROOT, 'tests', 'fixtures', 'conformance', 'valid-unicode.aural'));
  const metadata = {
    corpus: 'AURAL experimental provenance signature v1 conformance fixtures',
    private_key_material_included: false,
    public_key: {
      algorithm: 'Ed25519',
      raw_base64url: publicKey.toString('base64url'),
      key_id: keyId,
      key_record_sha256: sha256(outputs.get('valid-key.json')),
    },
    golden_vector: {
      assertion_length: valid.assertionBytes.length,
      assertion_sha256: sha256(valid.assertionBytes),
      signature_input_length: valid.signatureInput.length,
      signature_input_sha256: sha256(valid.signatureInput),
      signature_base64url: valid.signature.toString('base64url'),
      record_length: valid.record.length,
      record_sha256: sha256(valid.record),
      signed_event_digest: sha256(Buffer.concat([RECORD_DOMAIN, valid.record])),
      bound_package_sha256: sha256(packageBytes),
    },
    files_sha256: Object.fromEntries([...outputs.entries()].sort(([a], [b]) => a.localeCompare(b))
      .map(([name, payload]) => [name, sha256(payload)])),
    cases,
  };
  await writeFile(path.join(OUT, 'expected.json'), JSON.stringify(metadata, null, 2) + '\n');
}

await main();
