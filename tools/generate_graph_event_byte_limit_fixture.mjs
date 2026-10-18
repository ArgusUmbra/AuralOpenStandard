#!/usr/bin/env node
// Regenerate only the deterministic per-record byte-limit conformance bundle.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = resolve(
  ROOT, 'tests', 'fixtures', 'provenance', 'valid-original-acquired.json',
);
const OUTPUT = resolve(
  ROOT, 'tests', 'fixtures', 'graph_conformance', 'graph-event-byte-limit-cases.json.gz',
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
  '60c4c6d9ef3933a9fc1736ded925ff9e0e2f59b29e058bf9021879fbedd63d3e';
const MAX_RECORD_BYTES = 1024 * 1024;
const PADDING_EXTENSION = 'urn:aural:test:event-byte-padding';

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
const publicKey = createPublicKey(privateKey);

function signedRecord(assertion) {
  const assertionBytes = Buffer.from(canonicalJson(assertion), 'utf8');
  const signatureBytes = sign(null, Buffer.concat([DOMAIN, assertionBytes]), privateKey);
  const record = Buffer.from(canonicalJson({
    assertion,
    signature: signatureBytes.toString('base64url'),
  }), 'utf8');
  if (!verify(null, Buffer.concat([DOMAIN, assertionBytes]), publicKey, signatureBytes)) {
    throw new Error('generated Ed25519 signature did not verify');
  }
  return record;
}

function recordAtLength(targetLength, eventId) {
  const assertion = structuredClone(template);
  assertion.event_id = eventId;
  assertion.parents = [];
  assertion.extensions = { [PADDING_EXTENSION]: '' };
  const emptyRecord = signedRecord(assertion);
  const paddingLength = targetLength - emptyRecord.length;
  if (paddingLength < 0) throw new Error(`target record length is too small: ${targetLength}`);
  assertion.extensions[PADDING_EXTENSION] = 'a'.repeat(paddingLength);
  const record = signedRecord(assertion);
  if (record.length !== targetLength) {
    throw new Error(`expected ${targetLength} record bytes, got ${record.length}`);
  }
  return record;
}

const atLimit = recordAtLength(
  MAX_RECORD_BYTES, 'urn:uuid:20000000-2222-4333-8444-000000000001',
);
const overLimit = recordAtLength(
  MAX_RECORD_BYTES + 1, 'urn:uuid:20000000-2222-4333-8444-000000000002',
);
const bundle = Buffer.from(JSON.stringify({
  schema: 'org.aural.graph-resource-fixtures',
  schema_version: '1',
  collections: {
    event_bytes_at_limit: [atLimit.toString('utf8')],
    event_bytes_over_limit: [overLimit.toString('utf8')],
  },
}), 'utf8');
const compressed = gzipSync(bundle, { level: 9, mtime: 0 });
const bundleSha256 = createHash('sha256').update(compressed).digest('hex');
if (bundleSha256 !== EXPECTED_BUNDLE_SHA256) {
  throw new Error(`unexpected graph event-byte-limit bundle SHA-256: ${bundleSha256}`);
}
await writeFile(OUTPUT, compressed);
