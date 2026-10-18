import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as signMessage,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  __testing,
  IndexedSignedEvent,
  indexSignedEventRecords,
  MAX_AGGREGATE_GRAPH_EVENT_BYTES,
  MAX_GRAPH_DEPTH,
  MAX_GRAPH_EVENT_RECORDS,
  MAX_GRAPH_PARENT_REFERENCES,
  SignedEventGraphIndex,
  verifySignedEventGraph,
} from '../interop/signed_event_graph.mjs';
import {
  signedEventSha256,
  verifySignedEvent,
} from '../interop/validate_provenance.mjs';

const ROOT = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(ROOT, 'fixtures', 'provenance');
const KEY_ID_DOMAIN = Buffer.from('AURAL-KEY-ID-V1\0Ed25519\0', 'ascii');
const SIGNATURE_DOMAIN = Buffer.from('AURAL-PROVENANCE-EVENT-V1\0', 'ascii');

async function fixture(name) {
  return readFile(join(FIXTURES, name));
}

function outcome(index) {
  return {
    status: index.status,
    verificationStatus: index.verificationStatus,
    recordCount: index.recordCount,
    duplicateRecordCount: index.duplicateRecordCount,
    eventIds: index.eventIds,
    digests: index.signedEventDigests,
    records: index.records.map(record => record.recordBytes.toString('hex')),
  };
}

function expectError(category, stage) {
  return error => error?.category === category && error?.stage === stage;
}

function compareText(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number'
      || typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort(compareText).map(
    key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
  ).join(',')}}`;
}

const GRAPH_TEMPLATE = JSON.parse(await fixture('valid-original-acquired.json'));

class GraphBuilder {
  constructor() {
    this.records = new Map();
  }

  eventId(number) {
    const first = number.toString(16).padStart(8, '0');
    const last = number.toString(16).padStart(12, '0');
    return `urn:uuid:${first}-2222-4333-8444-${last}`;
  }

  document(number, parents = []) {
    const document = structuredClone(GRAPH_TEMPLATE);
    document.assertion.event_id = this.eventId(number);
    document.assertion.parents = parents.map(([eventId, digest]) => ({
      event_id: eventId,
      signed_event_digest: { algorithm: 'sha-256', value: digest },
    })).sort((left, right) => compareText(left.event_id, right.event_id));
    return document;
  }

  encode(document) {
    return Buffer.from(canonicalJson(document), 'utf8');
  }

  add(number, parentNumbers = []) {
    const parents = parentNumbers.map(parentNumber => {
      const record = this.records.get(parentNumber);
      assert.ok(record, `parent ${parentNumber} must be built first`);
      return [this.eventId(parentNumber), signedEventSha256(record)];
    });
    const record = this.encode(this.document(number, parents));
    this.records.set(number, record);
    return record;
  }
}

class GenuineSignedGraphBuilder extends GraphBuilder {
  signer() {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const publicKeyBytes = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
    const fingerprint = createHash('sha256')
      .update(KEY_ID_DOMAIN)
      .update(publicKeyBytes)
      .digest('hex');
    const keyId = `urn:aural:key:ed25519:${fingerprint}`;
    const keyRecord = this.encode({
      algorithm: 'Ed25519',
      key_id: keyId,
      key_schema: 'org.aural.signing-key',
      key_schema_version: '1',
      public_key: publicKeyBytes.toString('base64url'),
    });
    return { keyId, keyRecord, privateKey };
  }

  addSigned(number, signer, parentNumbers = []) {
    const parents = parentNumbers.map(parentNumber => {
      const record = this.records.get(parentNumber);
      assert.ok(record, `parent ${parentNumber} must be built first`);
      return [this.eventId(parentNumber), signedEventSha256(record)];
    });
    const document = this.document(number, parents);
    document.assertion.signing_key_id = signer.keyId;
    document.assertion.claims.acquiring_key_id = signer.keyId;
    const assertionBytes = Buffer.from(canonicalJson(document.assertion), 'utf8');
    document.signature = signMessage(
      null,
      Buffer.concat([SIGNATURE_DOMAIN, assertionBytes]),
      signer.privateKey,
    ).toString('base64url');
    const record = this.encode(document);
    this.records.set(number, record);
    return record;
  }
}

function tamperSignature(record) {
  const document = JSON.parse(record);
  const signature = Buffer.from(document.signature, 'base64url');
  signature[0] ^= 1;
  document.signature = signature.toString('base64url');
  return Buffer.from(canonicalJson(document), 'utf8');
}

function resolveRecords(records, options = {}) {
  const index = indexSignedEventRecords(records);
  return [index, __testing.resolveSignedEventGraphStructure(index, options)];
}

function syntheticIndex(dependencies) {
  const builder = new GraphBuilder();
  const numbers = Object.keys(dependencies).map(Number).sort((left, right) => left - right);
  const digests = new Map(numbers.map(number => [number, number.toString(16).padStart(64, '0')]));
  const entries = numbers.map(number => {
    const parents = dependencies[number].map(parentNumber => [
      builder.eventId(parentNumber), digests.get(parentNumber),
    ]);
    const document = builder.document(number, parents);
    return new IndexedSignedEvent(
      builder.encode(document), document, digests.get(number),
    );
  });
  return new SignedEventGraphIndex(entries.reverse(), 0);
}

function capturedError(operation) {
  let captured;
  try {
    operation();
  } catch (error) {
    captured = error;
  }
  assert.ok(captured, 'operation unexpectedly succeeded');
  return [captured.category, captured.stage, captured.message];
}

test('indexes one canonical event without claiming graph verification', async () => {
  const record = await fixture('valid-original-acquired.json');
  const original = Buffer.from(record);
  const index = indexSignedEventRecords([record]);
  const eventId = 'urn:uuid:11111111-2222-4333-8444-555555555555';
  const digest = 'e01de77607deebd20886b063a8573ce0ced436081df57e734c11ea21c6f9870e';

  assert.equal(index.status, 'indexed_not_verified');
  assert.equal(index.verificationStatus, 'not_implemented');
  assert.equal(index.parentResolution, 'not_performed');
  assert.equal(index.signatureVerification, 'not_performed');
  assert.equal(index.historyCompleteness, 'not_established');
  assert.equal(index.recordCount, 1);
  assert.equal(index.duplicateRecordCount, 0);
  assert.deepEqual(index.eventIds, [eventId]);
  assert.deepEqual(index.signedEventDigests, [digest]);
  assert.deepEqual(index.getByEventId(eventId).recordBytes, original);
  assert.equal(index.getByDigest(digest).eventId, eventId);

  record[0] ^= 0xff;
  assert.deepEqual(index.getByEventId(eventId).recordBytes, original);
  const exposed = index.getByEventId(eventId).recordBytes;
  exposed[0] ^= 0xff;
  assert.deepEqual(index.getByEventId(eventId).recordBytes, original);
});

test('indexes multiple distinct events by identity and digest', async () => {
  const first = await fixture('valid-original-acquired.json');
  const second = await fixture('valid-unknown-optional.json');
  const index = indexSignedEventRecords([second, first]);

  assert.equal(index.recordCount, 2);
  assert.deepEqual(index.eventIds, [
    'urn:uuid:11111111-2222-4333-8444-555555555555',
    'urn:uuid:11111111-2222-4333-9444-555555555555',
  ]);
  assert.equal(index.byEventId.size, 2);
  assert.equal(index.byDigest.size, 2);
});

test('collapses identical duplicate records into one logical event', async () => {
  const record = await fixture('valid-original-acquired.json');
  const index = indexSignedEventRecords([record, record, record]);

  assert.equal(index.recordCount, 1);
  assert.equal(index.duplicateRecordCount, 2);
  assert.equal(index.byEventId.size, 1);
  assert.equal(index.byDigest.size, 1);
});

test('rejects one event ID associated with distinct signed-event digests', async () => {
  const records = await Promise.all([
    fixture('valid-original-acquired.json'),
    fixture('invalid-signature.json'),
  ]);
  assert.throws(
    () => indexSignedEventRecords(records),
    expectError('event_id_collision', 'graph'),
  );
});

test('defensively rejects one digest associated with distinct record bytes', async () => {
  const records = await Promise.all([
    fixture('valid-original-acquired.json'),
    fixture('valid-unknown-optional.json'),
  ]);
  assert.throws(
    () => __testing.indexSignedEventRecordsWithDigest(
      records, {}, () => '0'.repeat(64),
    ),
    expectError('signed_event_digest_collision', 'graph'),
  );
});

test('rejects noncanonical or malformed input without excluding it', async () => {
  const valid = await fixture('valid-original-acquired.json');
  const noncanonical = await fixture('invalid-noncanonical.json');
  assert.throws(
    () => indexSignedEventRecords([valid, noncanonical]),
    expectError('canonicalization', 'record'),
  );

  const malformedSignature = await fixture('invalid-padded-signature.json');
  assert.throws(
    () => indexSignedEventRecords([malformedSignature]),
    expectError('encoding', 'record'),
  );

  const malformed = await fixture('invalid-bom.json');
  const outcomes = [];
  for (const records of [[noncanonical, malformed], [malformed, noncanonical]]) {
    try {
      indexSignedEventRecords(records);
      assert.fail('malformed records unexpectedly indexed');
    } catch (error) {
      outcomes.push([error.category, error.stage, error.message]);
    }
  }
  assert.deepEqual(outcomes[0], outcomes[1]);
});

test('logical index is independent of supplied record order', async () => {
  const records = await Promise.all([
    fixture('valid-original-acquired.json'),
    fixture('valid-unknown-optional.json'),
    fixture('valid-received-with-parent.json'),
  ]);
  assert.deepEqual(
    outcome(indexSignedEventRecords(records)),
    outcome(indexSignedEventRecords([...records].reverse())),
  );
});

test('enforces the configured event count limit before record processing', async () => {
  const record = await fixture('valid-original-acquired.json');
  assert.equal(MAX_GRAPH_EVENT_RECORDS, 4096);
  assert.throws(
    () => indexSignedEventRecords([record, record], { maxEventRecords: 1 }),
    expectError('resource_limit', 'input'),
  );
  assert.throws(
    () => indexSignedEventRecords(Array(MAX_GRAPH_EVENT_RECORDS + 1).fill(record)),
    expectError('resource_limit', 'input'),
  );
});

test('enforces the configured aggregate byte limit with small fixtures', async () => {
  const record = await fixture('valid-original-acquired.json');
  assert.equal(MAX_AGGREGATE_GRAPH_EVENT_BYTES, 64 * 1024 * 1024);
  assert.throws(
    () => indexSignedEventRecords(
      [record, record], { maxAggregateEventBytes: record.length * 2 - 1 },
    ),
    expectError('resource_limit', 'input'),
  );
});

test('domain-separated digests agree with Python conformance vectors', async () => {
  const vectors = [
    ['valid-original-acquired.json', 'e01de77607deebd20886b063a8573ce0ced436081df57e734c11ea21c6f9870e'],
    ['valid-unknown-optional.json', '6ca603ec338e14aefa93510dbd727b2b31048bfe5cfa3b627c1130b34ea7cbea'],
    ['valid-received-with-parent.json', '046f625d475a05f792d7f41354e12e016c2e32690034f157515b63337384937d'],
  ];
  for (const [name, expected] of vectors) {
    const index = indexSignedEventRecords([await fixture(name)]);
    assert.deepEqual(index.signedEventDigests, [expected], name);
  }
});

test('cryptographically verifies one genuine signed event but reports an incomplete graph', async () => {
  const [record, key] = await Promise.all([
    fixture('valid-original-acquired.json'),
    fixture('valid-key.json'),
  ]);
  const result = verifySignedEventGraph([record], [key]);

  assert.equal(result.status, 'verification_incomplete');
  assert.equal(result.verificationStatus, 'not_implemented');
  assert.equal(result.parentResolution, 'resolved');
  assert.equal(result.signatureVerification, 'valid');
  assert.equal(result.packageIntegrity, 'not_checked');
  assert.equal(result.historyCompleteness, 'not_established');
  assert.equal(result.recordCount, 1);
  assert.equal(result.maximumDepth, 1);
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].status, 'signature_valid');
  assert.equal(
    result.events[0].signed_event_sha256,
    'e01de77607deebd20886b063a8573ce0ced436081df57e734c11ea21c6f9870e',
  );
});

test('cryptographically verifies a genuine parent-first multi-event graph', async () => {
  const [root, child, key] = await Promise.all([
    fixture('valid-original-acquired.json'),
    fixture('valid-received-with-parent.json'),
    fixture('valid-key.json'),
  ]);
  const result = verifySignedEventGraph([child, root], [key]);

  assert.deepEqual(result.eventIds, [
    'urn:uuid:11111111-2222-4333-8444-555555555555',
    'urn:uuid:11111111-2222-4333-a444-555555555555',
  ]);
  assert.deepEqual(result.events.map(event => event.event_id), result.eventIds);
  assert.equal(result.maximumDepth, 2);
  assert.equal(result.events.every(event => event.status === 'signature_valid'), true);
});

test('rejects an invalid or tampered graph signature', async () => {
  const [record, key] = await Promise.all([
    fixture('invalid-signature.json'),
    fixture('valid-key.json'),
  ]);
  assert.throws(
    () => verifySignedEventGraph([record], [key]),
    expectError('signature', 'signature'),
  );
});

test('rejects a graph event whose signing key is missing', async () => {
  const record = await fixture('valid-original-acquired.json');
  assert.throws(
    () => verifySignedEventGraph([record], []),
    expectError('missing_key', 'key'),
  );
});

test('rejects a wrong supplied public key', async () => {
  const record = await fixture('valid-original-acquired.json');
  const builder = new GenuineSignedGraphBuilder();
  const wrongSigner = builder.signer();
  const wrongKey = JSON.parse(wrongSigner.keyRecord);
  wrongKey.key_id = JSON.parse(record).assertion.signing_key_id;
  assert.throws(
    () => verifySignedEventGraph([record], [builder.encode(wrongKey)]),
    expectError('key_id_mismatch', 'key'),
  );
});

test('rejects a malformed public-key record', async () => {
  const [record, malformedKey] = await Promise.all([
    fixture('valid-original-acquired.json'),
    fixture('key-invalid-encoding.json'),
  ]);
  assert.throws(
    () => verifySignedEventGraph([record], [malformedKey]),
    expectError('encoding', 'key'),
  );
});

test('rejects duplicate public-key identifiers, including identical key records', async () => {
  const [record, key] = await Promise.all([
    fixture('valid-original-acquired.json'),
    fixture('valid-key.json'),
  ]);
  assert.throws(
    () => verifySignedEventGraph([record], [key, key]),
    expectError('duplicate_key', 'key'),
  );
});

test('accepts multiple distinct valid signing keys and selects each key by identifier', () => {
  const builder = new GenuineSignedGraphBuilder();
  const firstSigner = builder.signer();
  const secondSigner = builder.signer();
  const first = builder.addSigned(1, firstSigner);
  const second = builder.addSigned(2, secondSigner);

  const result = verifySignedEventGraph(
    [second, first],
    [secondSigner.keyRecord, firstSigner.keyRecord],
  );
  assert.equal(result.recordCount, 2);
  assert.deepEqual(
    result.events.map(event => event.signing_key_id),
    [firstSigner.keyId, secondSigner.keyId],
  );
});

test('verifies identical duplicate signed events once logically', async () => {
  const [record, key] = await Promise.all([
    fixture('valid-original-acquired.json'),
    fixture('valid-key.json'),
  ]);
  const result = verifySignedEventGraph([record, record, record], [key]);

  assert.equal(result.recordCount, 1);
  assert.equal(result.duplicateRecordCount, 2);
  assert.equal(result.events.length, 1);
});

test('rejects a mixed graph containing valid and invalid unique signatures', () => {
  const builder = new GenuineSignedGraphBuilder();
  const signer = builder.signer();
  const valid = builder.addSigned(1, signer);
  const invalid = tamperSignature(builder.addSigned(2, signer));

  assert.throws(
    () => verifySignedEventGraph([invalid, valid], [signer.keyRecord]),
    expectError('signature', 'signature'),
  );
});

test('rejects structural faults before processing malformed key input', async () => {
  const builder = new GraphBuilder();
  const child = builder.encode(builder.document(1, [[builder.eventId(2), '0'.repeat(64)]]));
  const malformedKey = await fixture('key-invalid-encoding.json');

  assert.throws(
    () => verifySignedEventGraph([child], [malformedKey]),
    expectError('missing_parent', 'graph'),
  );
});

test('public graph verification rejects synthetic-index substitution', async () => {
  const key = await fixture('valid-key.json');
  const index = syntheticIndex({ 1: [] });

  assert.throws(
    () => verifySignedEventGraph(index, [key]),
    expectError('input', 'input'),
  );
});

test('graph verification enforces resolution limits only after validated indexing', () => {
  const builder = new GenuineSignedGraphBuilder();
  const signer = builder.signer();
  const root = builder.addSigned(1, signer);
  const child = builder.addSigned(2, signer, [1]);

  assert.throws(
    () => indexSignedEventRecords([root, child], { maxGraphDepth: 1 }),
    expectError('configuration', 'input'),
  );
  assert.throws(
    () => verifySignedEventGraph([root, child], [signer.keyRecord], { maxGraphDepth: 1 }),
    expectError('resource_limit', 'graph'),
  );
  assert.throws(
    () => verifySignedEventGraph(
      [root, child], [signer.keyRecord], { maxParentReferences: 0 },
    ),
    expectError('resource_limit', 'graph'),
  );
});

test('graph verification preserves key count and aggregate-byte input limits', async () => {
  const [record, key] = await Promise.all([
    fixture('valid-original-acquired.json'),
    fixture('valid-key.json'),
  ]);

  assert.throws(
    () => verifySignedEventGraph([record], [key], { maxKeyRecords: 0 }),
    expectError('resource_limit', 'input'),
  );
  assert.throws(
    () => verifySignedEventGraph([record], [key], { maxKeyData: key.length - 1 }),
    expectError('resource_limit', 'input'),
  );
});

test('existing individual-event verifier behavior remains signature-only', async () => {
  const [record, invalid, key] = await Promise.all([
    fixture('valid-original-acquired.json'),
    fixture('invalid-signature.json'),
    fixture('valid-key.json'),
  ]);
  const result = verifySignedEvent(record, [key]);

  assert.equal(result.status, 'signature_valid');
  assert.equal(result.asset_integrity, 'not_checked');
  assert.equal(result.history_completeness, 'not_established');
  assert.equal(
    result.signed_event_sha256,
    'e01de77607deebd20886b063a8573ce0ced436081df57e734c11ea21c6f9870e',
  );
  assert.throws(
    () => verifySignedEvent(invalid, [key]),
    error => error?.category === 'signature',
  );
});

test('valid graph cryptography never claims package or historical completion', async () => {
  const [record, key] = await Promise.all([
    fixture('valid-original-acquired.json'),
    fixture('valid-key.json'),
  ]);
  const result = verifySignedEventGraph([record], [key]);
  const serialized = JSON.stringify(result);

  assert.equal(result.status, 'verification_incomplete');
  assert.equal(result.verificationStatus, 'not_implemented');
  assert.equal(serialized.includes('CONSISTENT'), false);
  assert.equal(serialized.includes('VERIFIED'), false);
  assert.equal(serialized.includes('ESTABLISHED'), false);
});

test('structurally resolves a single root without claiming cryptographic verification', () => {
  const builder = new GraphBuilder();
  const [index, resolved] = resolveRecords([builder.add(7)]);

  assert.equal(index.status, 'indexed_not_verified');
  assert.equal(resolved.status, 'structural_only');
  assert.equal(resolved.verificationStatus, 'not_performed');
  assert.equal(resolved.parentResolution, 'resolved');
  assert.equal(resolved.signatureVerification, 'not_performed');
  assert.equal(resolved.historyCompleteness, 'not_established');
  assert.equal(resolved.maximumDepth, 1);
  assert.deepEqual(resolved.eventIds, [builder.eventId(7)]);
});

test('resolves a linear chain in parent-first order', () => {
  const builder = new GraphBuilder();
  const records = [builder.add(40)];
  records.push(builder.add(30, [40]));
  records.push(builder.add(20, [30]));
  records.push(builder.add(10, [20]));

  const [, resolved] = resolveRecords(records.reverse());
  assert.deepEqual(
    resolved.eventIds,
    [40, 30, 20, 10].map(number => builder.eventId(number)),
  );
  assert.equal(resolved.maximumDepth, 4);
});

test('uses ASCII event-ID ties for branching dependencies', () => {
  const builder = new GraphBuilder();
  const records = [builder.add(40)];
  records.push(builder.add(30, [40]));
  records.push(builder.add(20, [40]));

  const [, resolved] = resolveRecords(records);
  assert.deepEqual(
    resolved.eventIds,
    [40, 20, 30].map(number => builder.eventId(number)),
  );
  assert.equal(resolved.maximumDepth, 2);
});

test('resolves a diamond with a shared ancestor without a false cycle', () => {
  const builder = new GraphBuilder();
  const records = [builder.add(40)];
  records.push(builder.add(30, [40]));
  records.push(builder.add(20, [40]));
  records.push(builder.add(10, [20, 30]));

  const [, resolved] = resolveRecords(records);
  assert.deepEqual(
    resolved.eventIds,
    [40, 20, 30, 10].map(number => builder.eventId(number)),
  );
  assert.equal(resolved.maximumDepth, 3);
});

test('orders multiple independent roots by event ID', () => {
  const builder = new GraphBuilder();
  const records = [30, 10, 20].map(number => builder.add(number));

  const [, resolved] = resolveRecords(records);
  assert.deepEqual(
    resolved.eventIds,
    [10, 20, 30].map(number => builder.eventId(number)),
  );
  assert.equal(resolved.maximumDepth, 1);
});

test('resolves disconnected valid components parent-first', () => {
  const builder = new GraphBuilder();
  const records = [builder.add(40), builder.add(20)];
  records.push(builder.add(30, [40]));
  records.push(builder.add(10, [20]));

  const [, resolved] = resolveRecords(records);
  assert.deepEqual(
    resolved.eventIds,
    [20, 10, 40, 30].map(number => builder.eventId(number)),
  );
  assert.equal(resolved.maximumDepth, 2);
});

test('identical duplicates remain one structural node', () => {
  const builder = new GraphBuilder();
  const root = builder.add(20);
  const child = builder.add(10, [20]);

  const [index, resolved] = resolveRecords([child, root, child, root, root]);
  assert.equal(index.recordCount, 2);
  assert.equal(index.duplicateRecordCount, 3);
  assert.equal(resolved.recordCount, 2);
  assert.equal(resolved.maximumDepth, 2);
  assert.deepEqual(resolved.eventIds, [builder.eventId(20), builder.eventId(10)]);
});

test('reversed and reordered inputs produce identical structural results', () => {
  const builder = new GraphBuilder();
  const records = [builder.add(50), builder.add(40)];
  records.push(builder.add(30, [50]));
  records.push(builder.add(20, [40]));
  records.push(builder.add(10, [20, 30]));
  const permutations = [
    records,
    [...records].reverse(),
    [records[2], records[4], records[0], records[3], records[1]],
  ];

  const outcomes = permutations.map(items => {
    const [, resolved] = resolveRecords(items);
    return [resolved.eventIds, resolved.maximumDepth];
  });
  assert.deepEqual(outcomes[1], outcomes[0]);
  assert.deepEqual(outcomes[2], outcomes[0]);
});

test('resolves existing Python conformance fixtures by exact parent identity and digest', async () => {
  const root = await fixture('valid-original-acquired.json');
  const child = await fixture('valid-received-with-parent.json');
  const [, resolved] = resolveRecords([child, root]);

  assert.deepEqual(resolved.eventIds, [
    'urn:uuid:11111111-2222-4333-8444-555555555555',
    'urn:uuid:11111111-2222-4333-a444-555555555555',
  ]);
  assert.equal(resolved.maximumDepth, 2);
});

test('classifies an absent declared parent as missing_parent', () => {
  const builder = new GraphBuilder();
  const child = builder.encode(builder.document(1, [[builder.eventId(2), '0'.repeat(64)]]));
  const index = indexSignedEventRecords([child]);

  assert.throws(
    () => __testing.resolveSignedEventGraphStructure(index),
    expectError('missing_parent', 'graph'),
  );
});

test('rejects a correct parent ID with the wrong digest', () => {
  const builder = new GraphBuilder();
  const parent = builder.add(2);
  const child = builder.encode(builder.document(1, [[builder.eventId(2), '0'.repeat(64)]]));
  const index = indexSignedEventRecords([parent, child]);

  assert.throws(
    () => __testing.resolveSignedEventGraphStructure(index),
    expectError('parent_digest_mismatch', 'graph'),
  );
});

test('reports deterministic structural errors under reordered input', () => {
  const builder = new GraphBuilder();
  const mismatchParent = builder.add(20);
  const mismatch = builder.encode(builder.document(10, [
    [builder.eventId(20), '0'.repeat(64)],
  ]));
  const missing = builder.encode(builder.document(30, [
    [builder.eventId(40), '0'.repeat(64)],
  ]));
  const records = [missing, mismatchParent, mismatch];

  const errors = [records, [...records].reverse()].map(items => capturedError(() => {
    const index = indexSignedEventRecords(items);
    __testing.resolveSignedEventGraphStructure(index);
  }));
  assert.deepEqual(errors[1], errors[0]);
  assert.equal(errors[0][0], 'parent_digest_mismatch');
});

test('defensive structural test: detects an internal self-cycle', () => {
  assert.throws(
    () => __testing.resolveSignedEventGraphStructure(syntheticIndex({ 1: [1] })),
    expectError('cycle', 'graph'),
  );
});

test('defensive structural test: detects an internal two-event cycle', () => {
  assert.throws(
    () => __testing.resolveSignedEventGraphStructure(syntheticIndex({ 1: [2], 2: [1] })),
    expectError('cycle', 'graph'),
  );
});

test('defensive structural test: detects an internal longer cycle', () => {
  assert.throws(
    () => __testing.resolveSignedEventGraphStructure(
      syntheticIndex({ 1: [3], 2: [1], 3: [2] }),
    ),
    expectError('cycle', 'graph'),
  );
});

test('defensive structural test: detects a cycle in a disconnected component', () => {
  assert.throws(
    () => __testing.resolveSignedEventGraphStructure(
      syntheticIndex({ 1: [], 2: [1], 3: [4], 4: [3] }),
    ),
    expectError('cycle', 'graph'),
  );
});

test('accepts parent fanout 64 and rejects parent fanout 65', () => {
  assert.equal(MAX_GRAPH_PARENT_REFERENCES, 64);
  const builder = new GraphBuilder();
  const roots = [];
  for (let number = 1; number <= 65; number += 1) roots.push(builder.add(number));

  const atLimit = builder.add(100, Array.from({ length: 64 }, (_, index) => index + 1));
  const [, resolved] = resolveRecords([...roots.slice(0, 64), atLimit]);
  assert.equal(resolved.recordCount, 65);
  assert.equal(resolved.maximumDepth, 2);

  const overLimit = builder.add(101, Array.from({ length: 65 }, (_, index) => index + 1));
  const overLimitIndex = indexSignedEventRecords([...roots, overLimit]);
  assert.throws(
    () => __testing.resolveSignedEventGraphStructure(overLimitIndex),
    expectError('resource_limit', 'graph'),
  );
});

test('accepts graph depth 256 and rejects graph depth 257', () => {
  assert.equal(MAX_GRAPH_DEPTH, 256);
  const builder = new GraphBuilder();
  const records = [builder.add(1)];
  for (let number = 2; number <= MAX_GRAPH_DEPTH + 1; number += 1) {
    records.push(builder.add(number, [number - 1]));
  }

  const [, resolved] = resolveRecords(records.slice(0, MAX_GRAPH_DEPTH));
  assert.equal(resolved.maximumDepth, MAX_GRAPH_DEPTH);

  const overLimitIndex = indexSignedEventRecords(records);
  assert.throws(
    () => __testing.resolveSignedEventGraphStructure(overLimitIndex),
    expectError('resource_limit', 'graph'),
  );
});

test('graph limits may tighten but cannot relax the profile boundaries', () => {
  const builder = new GraphBuilder();
  const root = builder.add(1);
  const child = builder.add(2, [1]);
  const index = indexSignedEventRecords([root, child]);

  assert.throws(
    () => __testing.resolveSignedEventGraphStructure(index, { maxParentReferences: 0 }),
    expectError('resource_limit', 'graph'),
  );
  assert.throws(
    () => __testing.resolveSignedEventGraphStructure(index, { maxGraphDepth: 1 }),
    expectError('resource_limit', 'graph'),
  );
  assert.throws(
    () => __testing.resolveSignedEventGraphStructure(
      index, { maxParentReferences: MAX_GRAPH_PARENT_REFERENCES + 1 },
    ),
    expectError('configuration', 'input'),
  );
  assert.throws(
    () => __testing.resolveSignedEventGraphStructure(
      index, { maxGraphDepth: MAX_GRAPH_DEPTH + 1 },
    ),
    expectError('configuration', 'input'),
  );
});
