#!/usr/bin/env node
// Regenerate only the deterministic event-count graph-conformance bundle.
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = resolve(
  ROOT, 'tests', 'fixtures', 'provenance', 'valid-original-acquired.json',
);
const OUTPUT = resolve(
  ROOT, 'tests', 'fixtures', 'graph_conformance', 'graph-event-count-cases.json.gz',
);
const DOMAIN = Buffer.from('AURAL-PROVENANCE-EVENT-V1\0', 'ascii');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const TEST_SEED = Buffer.from(
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  'hex',
);
const SOURCE_SHA256 =
  '81d6ca95ac7a352155dd2f6b921b69e47a156bda4cd8ab8c2019c534794a708b';
const EXPECTED_BUNDLE_SHA256 =
  'a5f3f3bc2dccdfec7dadc7cc8fafeecb88f7989f1a0791bb8f803b433aa49415';
const EVENT_COUNT = 4097;
const MAX_RECORD_BYTES = 1024 * 1024;
const MAX_AGGREGATE_BYTES = 64 * 1024 * 1024;

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

function eventId(number) {
  const first = number.toString(16).padStart(8, '0');
  const last = number.toString(16).padStart(12, '0');
  return `urn:uuid:${first}-2222-4333-8444-${last}`;
}

const sourceBytes = await readFile(SOURCE);
const sourceSha256 = createHash('sha256').update(sourceBytes).digest('hex');
if (sourceSha256 !== SOURCE_SHA256) {
  throw new Error(`unexpected source fixture SHA-256: ${sourceSha256}`);
}
const template = JSON.parse(sourceBytes).assertion;
const privateKey = createPrivateKey({
  key: Buffer.concat([PKCS8_PREFIX, TEST_SEED]),
  format: 'der',
  type: 'pkcs8',
});

const events = [];
for (let number = 1; number <= EVENT_COUNT; number += 1) {
  const assertion = structuredClone(template);
  assertion.event_id = eventId(number);
  assertion.parents = [];
  const assertionBytes = Buffer.from(canonicalJson(assertion), 'utf8');
  const signature = sign(
    null, Buffer.concat([DOMAIN, assertionBytes]), privateKey,
  ).toString('base64url');
  const record = Buffer.from(canonicalJson({ assertion, signature }), 'utf8');
  events.push({ eventId: assertion.event_id, record });
}

if (new Set(events.map(event => event.eventId)).size !== EVENT_COUNT) {
  throw new Error('event-count fixture contains duplicate event IDs');
}
if (events.some(event => event.record.length > MAX_RECORD_BYTES)) {
  throw new Error('event-count fixture contains an oversized record');
}
const aggregateBytes = events.reduce((total, event) => total + event.record.length, 0);
if (aggregateBytes > MAX_AGGREGATE_BYTES) {
  throw new Error('event-count fixture exceeds the aggregate record-byte limit');
}

const acceptedEvents = events.slice(0, EVENT_COUNT - 1);
const records = [...acceptedEvents, events.at(-1)].map(
  event => event.record.toString('utf8'),
);
const bundle = Buffer.from(JSON.stringify({
  schema: 'org.aural.graph-resource-fixtures',
  schema_version: '1',
  collections: { event_count_roots: records },
}), 'utf8');
const compressed = gzipSync(bundle, { level: 9, mtime: 0 });
const bundleSha256 = createHash('sha256').update(compressed).digest('hex');
if (bundleSha256 !== EXPECTED_BUNDLE_SHA256) {
  throw new Error(`unexpected graph event-count bundle SHA-256: ${bundleSha256}`);
}
await writeFile(OUTPUT, compressed);
