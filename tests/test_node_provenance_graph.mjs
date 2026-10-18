import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  __testing,
  indexSignedEventRecords,
  MAX_AGGREGATE_GRAPH_EVENT_BYTES,
  MAX_GRAPH_EVENT_RECORDS,
} from '../interop/signed_event_graph.mjs';

const ROOT = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(ROOT, 'fixtures', 'provenance');

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
