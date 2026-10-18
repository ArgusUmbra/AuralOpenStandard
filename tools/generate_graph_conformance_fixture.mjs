#!/usr/bin/env node
// Regenerate the deterministic graph-conformance records.
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = resolve(
  ROOT, 'tests', 'fixtures', 'provenance', 'valid-received-with-parent.json',
);
const ROOT_SOURCE = resolve(
  ROOT, 'tests', 'fixtures', 'provenance', 'valid-original-acquired.json',
);
const MULTI_PARENT_OUTPUT = resolve(
  ROOT, 'tests', 'fixtures', 'graph_conformance', 'valid-multi-parent.json',
);
const PARENT_DIGEST_MISMATCH_OUTPUT = resolve(
  ROOT, 'tests', 'fixtures', 'graph_conformance', 'parent-digest-mismatch.json',
);
const RESOURCE_BUNDLE_OUTPUT = resolve(
  ROOT, 'tests', 'fixtures', 'graph_conformance', 'graph-resource-cases.json.gz',
);
const DOMAIN = Buffer.from('AURAL-PROVENANCE-EVENT-V1\0', 'ascii');
const RECORD_DOMAIN = Buffer.from('AURAL-SIGNED-EVENT-V1\0', 'ascii');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
// RFC 8032 test-vector seed #1. This is public, test-only material and is
// deliberately kept in the generator rather than emitted in any fixture.
const TEST_SEED = Buffer.from(
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  'hex',
);
const EXPECTED_MULTI_PARENT_DIGEST =
  '9656cab8765ad6c4741424c0eb71f6dd3f5faad243a08510b1c690005496de05';
const EXPECTED_PARENT_DIGEST_MISMATCH_DIGEST =
  '8f8cbe0ec48aa6184696c3715818d05c5d8852a116d1ce6580540db261deb0bf';
const EXPECTED_RESOURCE_BUNDLE_SHA256 =
  '502b62a1d48c23fb158db53efc39e5838b72863dae13079a7f7610b49c58f0eb';

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

const privateKey = createPrivateKey({
  key: Buffer.concat([PKCS8_PREFIX, TEST_SEED]),
  format: 'der',
  type: 'pkcs8',
});

function signedRecord(assertion) {
  const assertionBytes = Buffer.from(canonicalJson(assertion), 'utf8');
  const signature = sign(
    null, Buffer.concat([DOMAIN, assertionBytes]), privateKey,
  ).toString('base64url');
  const record = Buffer.from(canonicalJson({ assertion, signature }), 'utf8');
  const digest = createHash('sha256').update(RECORD_DOMAIN).update(record).digest('hex');
  return { digest, record };
}

function eventId(number) {
  const first = number.toString(16).padStart(8, '0');
  const last = number.toString(16).padStart(12, '0');
  return `urn:uuid:${first}-2222-4333-8444-${last}`;
}

function buildSignedEvent(template, number, parents = []) {
  const assertion = structuredClone(template);
  assertion.event_id = eventId(number);
  assertion.parents = parents.map(parent => ({
    event_id: eventId(parent.number),
    signed_event_digest: { algorithm: 'sha-256', value: parent.digest },
  })).sort((left, right) => compareText(left.event_id, right.event_id));
  return { number, ...signedRecord(assertion) };
}

function records(collection) {
  return collection.map(item => item.record.toString('utf8'));
}

const source = JSON.parse(await readFile(SOURCE, 'utf8')).assertion;
const rootSource = JSON.parse(await readFile(ROOT_SOURCE, 'utf8')).assertion;

const multiParentAssertion = structuredClone(source);
multiParentAssertion.parents.push({
  event_id: 'urn:uuid:11111111-2222-4333-9444-555555555555',
  signed_event_digest: {
    algorithm: 'sha-256',
    value: '6ca603ec338e14aefa93510dbd727b2b31048bfe5cfa3b627c1130b34ea7cbea',
  },
});
multiParentAssertion.parents.sort(
  (left, right) => compareText(left.event_id, right.event_id),
);
const multiParent = signedRecord(multiParentAssertion);
if (multiParent.digest !== EXPECTED_MULTI_PARENT_DIGEST) {
  throw new Error(`unexpected multi-parent signed-event digest: ${multiParent.digest}`);
}

const parentDigestMismatchAssertion = structuredClone(source);
parentDigestMismatchAssertion.parents[0].signed_event_digest.value = '0'.repeat(64);
const parentDigestMismatch = signedRecord(parentDigestMismatchAssertion);
if (parentDigestMismatch.digest !== EXPECTED_PARENT_DIGEST_MISMATCH_DIGEST) {
  throw new Error(
    `unexpected parent-digest-mismatch signed-event digest: ${parentDigestMismatch.digest}`,
  );
}

await writeFile(MULTI_PARENT_OUTPUT, multiParent.record);
await writeFile(PARENT_DIGEST_MISMATCH_OUTPUT, parentDigestMismatch.record);

const fanoutRoots = [];
for (let number = 1; number <= 65; number += 1) {
  fanoutRoots.push(buildSignedEvent(rootSource, number));
}
const fanout64 = buildSignedEvent(rootSource, 1000, fanoutRoots.slice(0, 64));
const fanout65 = buildSignedEvent(rootSource, 1001, fanoutRoots);

const depthEvents = [buildSignedEvent(rootSource, 10001)];
for (let number = 10002; number <= 10257; number += 1) {
  depthEvents.push(buildSignedEvent(rootSource, number, [depthEvents.at(-1)]));
}

const resourceBundle = Buffer.from(JSON.stringify({
  schema: 'org.aural.graph-resource-fixtures',
  schema_version: '1',
  collections: {
    fanout_64: records([...fanoutRoots.slice(0, 64), fanout64]),
    fanout_65: records([...fanoutRoots, fanout65]),
    depth_256: records(depthEvents.slice(0, 256)),
    depth_257: records(depthEvents),
  },
}), 'utf8');
const compressedResourceBundle = gzipSync(resourceBundle, { level: 9, mtime: 0 });
const resourceBundleSha256 = createHash('sha256').update(compressedResourceBundle).digest('hex');
if (resourceBundleSha256 !== EXPECTED_RESOURCE_BUNDLE_SHA256) {
  throw new Error(`unexpected graph-resource bundle SHA-256: ${resourceBundleSha256}`);
}
await writeFile(RESOURCE_BUNDLE_OUTPUT, compressedResourceBundle);
