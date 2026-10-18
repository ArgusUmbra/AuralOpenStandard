import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';

import { verifySignedEventGraphDetailed } from '../interop/signed_event_graph.mjs';
import { verifySignedEvent } from '../interop/validate_provenance.mjs';

function sha256(raw) {
  return createHash('sha256').update(raw).digest('hex');
}

function relativePath(base, value, label) {
  if (typeof value !== 'string' || isAbsolute(value)) {
    throw new Error(`${label} must be a relative path`);
  }
  return resolve(base, value);
}

if (process.argv.length !== 4) {
  throw new Error(
    'usage: node tests/graph_aggregate_boundary_node_adapter.mjs CASES FIXTURE_DESCRIPTOR',
  );
}

const casesPath = resolve(process.argv[2]);
const fixturePath = resolve(process.argv[3]);
const expected = JSON.parse(await readFile(casesPath, 'utf8'));
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
const expectedBase = dirname(casesPath);
const fixtureBase = dirname(fixturePath);
const key = await readFile(relativePath(expectedBase, expected.public_key, 'public key'));
const fixtureById = new Map(fixture.cases.map(testCase => [testCase.id, testCase]));
const results = {};

for (const testCase of expected.cases) {
  const generated = fixtureById.get(testCase.id);
  if (generated === undefined) throw new Error(`${testCase.id}: generated case is missing`);
  const records = [];
  const commitment = createHash('sha256');
  for (const path of generated.record_paths) {
    const record = await readFile(relativePath(fixtureBase, path, 'signed event'));
    records.push(record);
    commitment.update(record);
  }
  const evidence = {
    record_count: records.length,
    aggregate_event_bytes: records.reduce((total, record) => total + record.length, 0),
    maximum_event_bytes: Math.max(...records.map(record => record.length)),
    event_byte_lengths: records.map(record => record.length),
    ordered_input_sha256: commitment.digest('hex'),
    record_sha256: records.map(sha256),
  };
  try {
    evidence.result = await verifySignedEventGraphDetailed(records, [key]);
    evidence.accepted = true;
  } catch (error) {
    evidence.accepted = false;
    evidence.error = {
      category: error?.category ?? 'internal',
      stage: error?.stage ?? 'internal',
      message: error?.message ?? String(error),
    };
  }

  if (testCase.expected.accepted) {
    evidence.all_event_signatures_valid = evidence.accepted
      && evidence.result.recordCount === records.length
      && evidence.result.events.every(event => event.status === 'signature_valid');
    evidence.distinct_event_id_count = evidence.accepted
      ? new Set(evidence.result.eventIds).size : 0;
  } else {
    const verified = records.map(record => verifySignedEvent(record, [key]));
    evidence.all_event_signatures_valid = verified.every(
      event => event.status === 'signature_valid',
    );
    evidence.distinct_event_id_count = new Set(
      verified.map(event => event.event_id),
    ).size;
  }
  results[testCase.id] = evidence;
}

process.stdout.write(JSON.stringify({ cases: results }));
