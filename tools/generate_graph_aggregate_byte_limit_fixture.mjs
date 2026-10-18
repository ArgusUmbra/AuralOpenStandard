#!/usr/bin/env node
// Generate deterministic aggregate signed-event byte-limit fixtures in a caller-owned directory.
import {
  createHash, createPrivateKey, createPublicKey, sign, verify,
} from 'node:crypto';
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import {
  dirname, isAbsolute, normalize, relative, resolve, sep,
} from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = resolve(
  ROOT, 'tests', 'fixtures', 'provenance', 'valid-original-acquired.json',
);
const DOMAIN = Buffer.from('AURAL-PROVENANCE-EVENT-V1\0', 'ascii');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const TEST_SEED = Buffer.from(
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  'hex',
);
const SOURCE_SHA256 =
  '81d6ca95ac7a352155dd2f6b921b69e47a156bda4cd8ab8c2019c534794a708b';
const AGGREGATE_LIMIT = 64 * 1024 * 1024;
const MAX_RECORD_BYTES = 1024 * 1024;
const RECORD_COUNT = 65;
const SHARED_RECORD_COUNT = RECORD_COUNT - 1;
const SHARED_RECORD_BYTES = 1_040_000;
const AT_LIMIT_TAIL_BYTES = AGGREGATE_LIMIT - SHARED_RECORD_COUNT * SHARED_RECORD_BYTES;
const PADDING_EXTENSION = 'urn:aural:test:aggregate-byte-padding';

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

function sha256(raw) {
  return createHash('sha256').update(raw).digest('hex');
}

function isPathWithin(parent, candidate, allowSame = false) {
  const difference = relative(parent, candidate);
  if (difference === '') return allowSame;
  return difference !== '..'
    && !difference.startsWith(`..${sep}`)
    && !isAbsolute(difference);
}

async function requireFreshTemporaryOutput(rawOutputDirectory) {
  if (typeof rawOutputDirectory !== 'string'
      || rawOutputDirectory.length === 0
      || rawOutputDirectory.includes('\0')
      || !isAbsolute(rawOutputDirectory)) {
    throw new Error('output directory must be an absolute path');
  }
  const normalizedOutput = normalize(rawOutputDirectory);
  if (normalizedOutput !== rawOutputDirectory) {
    throw new Error('output directory must already be safely normalized');
  }

  const temporaryPath = resolve(tmpdir());
  const repositoryPath = resolve(ROOT);
  const [temporaryRoot, repositoryRoot] = await Promise.all([
    realpath(temporaryPath),
    realpath(ROOT),
  ]);
  const outputDirectory = resolve(normalizedOutput);
  if (isPathWithin(repositoryPath, outputDirectory, true)
      || isPathWithin(repositoryRoot, outputDirectory, true)) {
    throw new Error('output directory must not be inside the repository checkout');
  }
  if (!isPathWithin(temporaryPath, outputDirectory)) {
    throw new Error('output directory must be under the operating system temporary directory');
  }

  const outputParent = dirname(outputDirectory);
  let parentStat;
  try {
    parentStat = await lstat(outputParent);
  } catch (error) {
    throw new Error('output directory parent must already exist', { cause: error });
  }
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) {
    throw new Error('output directory parent must be a real directory');
  }
  const parentReal = await realpath(outputParent);
  if (!isPathWithin(temporaryRoot, parentReal, true)) {
    throw new Error(
      'output directory parent resolves outside the operating system temporary directory',
    );
  }
  if (isPathWithin(repositoryRoot, parentReal, true)) {
    throw new Error('output directory parent resolves inside the repository checkout');
  }

  let outputExists = true;
  try {
    await lstat(outputDirectory);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    outputExists = false;
  }
  if (outputExists) {
    throw new Error('output directory must not already exist');
  }

  try {
    await mkdir(outputDirectory, { recursive: false, mode: 0o700 });
  } catch (error) {
    if (error?.code === 'EEXIST') {
      throw new Error('output directory must not already exist', { cause: error });
    }
    throw error;
  }

  const [createdStat, createdReal] = await Promise.all([
    lstat(outputDirectory),
    realpath(outputDirectory),
  ]);
  if (!createdStat.isDirectory() || createdStat.isSymbolicLink()
      || !isPathWithin(temporaryRoot, createdReal)
      || isPathWithin(repositoryRoot, createdReal, true)) {
    throw new Error('created output directory is not a safe temporary directory');
  }
  return { outputDirectory, createdReal, createdStat };
}

async function assertUnredirectedOutput(output) {
  const [currentStat, currentReal] = await Promise.all([
    lstat(output.outputDirectory),
    realpath(output.outputDirectory),
  ]);
  if (!currentStat.isDirectory() || currentStat.isSymbolicLink()
      || currentStat.dev !== output.createdStat.dev
      || currentStat.ino !== output.createdStat.ino
      || relative(output.createdReal, currentReal) !== ''
      || relative(currentReal, output.createdReal) !== '') {
    throw new Error('output directory changed or was redirected during generation');
  }
}

async function writeFreshOutput(output, basename, data) {
  if (typeof basename !== 'string' || basename.length === 0
      || dirname(basename) !== '.' || normalize(basename) !== basename) {
    throw new Error('output filename must be a normalized basename');
  }
  await assertUnredirectedOutput(output);
  const destination = resolve(output.outputDirectory, basename);
  if (dirname(destination) !== output.outputDirectory) {
    throw new Error('output filename escaped the designated directory');
  }
  await writeFile(destination, data, { flag: 'wx' });
}

const checkOnly = process.argv.length === 4 && process.argv[2] === '--check-output-only';
if ((!checkOnly && process.argv.length !== 3) || (checkOnly && process.argv.length !== 4)) {
  throw new Error(
    'usage: node tools/generate_graph_aggregate_byte_limit_fixture.mjs '
      + '[--check-output-only] ABSOLUTE_FRESH_TEMPORARY_OUTPUT_DIRECTORY',
  );
}

const output = await requireFreshTemporaryOutput(process.argv[checkOnly ? 3 : 2]);
if (checkOnly) {
  process.stdout.write(`${JSON.stringify({ output_directory: output.createdReal })}\n`);
  process.exit(0);
}

const sourceBytes = await readFile(SOURCE);
const sourceSha256 = sha256(sourceBytes);
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

function signedRecordAtLength(targetLength, number) {
  const assertion = structuredClone(template);
  assertion.event_id = eventId(number);
  assertion.parents = [];
  assertion.extensions = { [PADDING_EXTENSION]: '' };

  const emptyAssertion = Buffer.from(canonicalJson(assertion), 'utf8');
  const emptySignature = sign(
    null, Buffer.concat([DOMAIN, emptyAssertion]), privateKey,
  ).toString('base64url');
  const emptyRecord = Buffer.from(canonicalJson({ assertion, signature: emptySignature }), 'utf8');
  const paddingLength = targetLength - emptyRecord.length;
  if (paddingLength < 0) throw new Error(`target record length is too small: ${targetLength}`);

  assertion.extensions[PADDING_EXTENSION] = 'a'.repeat(paddingLength);
  const assertionBytes = Buffer.from(canonicalJson(assertion), 'utf8');
  const signatureBytes = sign(null, Buffer.concat([DOMAIN, assertionBytes]), privateKey);
  const record = Buffer.from(canonicalJson({
    assertion,
    signature: signatureBytes.toString('base64url'),
  }), 'utf8');
  if (record.length !== targetLength) {
    throw new Error(`expected ${targetLength} record bytes, got ${record.length}`);
  }
  if (!verify(null, Buffer.concat([DOMAIN, assertionBytes]), publicKey, signatureBytes)) {
    throw new Error('generated Ed25519 signature did not verify');
  }
  return record;
}

if (AT_LIMIT_TAIL_BYTES < 1 || AT_LIMIT_TAIL_BYTES + 1 > MAX_RECORD_BYTES) {
  throw new Error('chosen record distribution does not fit the per-record limit');
}

const sharedPaths = [];
const sharedRecords = [];
for (let number = 1; number <= SHARED_RECORD_COUNT; number += 1) {
  const record = signedRecordAtLength(SHARED_RECORD_BYTES, number);
  const relativePath = `event-${number.toString().padStart(4, '0')}.json`;
  await writeFreshOutput(output, relativePath, record);
  sharedPaths.push(relativePath);
  sharedRecords.push(record);
}

const atLimitTail = signedRecordAtLength(AT_LIMIT_TAIL_BYTES, RECORD_COUNT);
const overLimitTail = signedRecordAtLength(AT_LIMIT_TAIL_BYTES + 1, RECORD_COUNT);
const atLimitTailPath = 'event-0065-at-limit.json';
const overLimitTailPath = 'event-0065-over-limit.json';
await writeFreshOutput(output, atLimitTailPath, atLimitTail);
await writeFreshOutput(output, overLimitTailPath, overLimitTail);

function describeCase(id, tailPath, tailRecord) {
  const records = [...sharedRecords, tailRecord];
  const commitment = createHash('sha256');
  for (const record of records) commitment.update(record);
  return {
    id,
    record_paths: [...sharedPaths, tailPath],
    record_count: records.length,
    event_byte_lengths: records.map(record => record.length),
    aggregate_event_bytes: records.reduce((total, record) => total + record.length, 0),
    ordered_input_sha256: commitment.digest('hex'),
    record_sha256: records.map(sha256),
  };
}

const descriptor = {
  schema: 'org.aural.graph-aggregate-byte-fixtures',
  schema_version: '1',
  source_sha256: sourceSha256,
  cases: [
    describeCase('H-aggregate-bytes-at-limit', atLimitTailPath, atLimitTail),
    describeCase('N-aggregate-bytes-over-limit', overLimitTailPath, overLimitTail),
  ],
};
await writeFreshOutput(
  output,
  'fixture.json',
  Buffer.from(`${JSON.stringify(descriptor, null, 2)}\n`, 'utf8'),
);
process.stdout.write(`${JSON.stringify(descriptor)}\n`);
