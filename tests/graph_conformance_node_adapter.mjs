import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';

import { verifySignedEventGraphDetailed } from '../interop/signed_event_graph.mjs';
import {
  verifyEd25519Profile,
  verifySignedEvent,
} from '../interop/validate_provenance.mjs';

const SIGNATURE_DOMAIN = Buffer.from('AURAL-PROVENANCE-EVENT-V1\0', 'ascii');

function sha256(raw) {
  return createHash('sha256').update(raw).digest('hex');
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

function independentlyVerifySignature(record, keyRecords) {
  try {
    const document = JSON.parse(record.toString('utf8'));
    const key = keyRecords.map(raw => JSON.parse(raw.toString('utf8'))).find(
      item => item.key_id === document.assertion.signing_key_id,
    );
    if (key === undefined) return false;
    const message = Buffer.concat([
      SIGNATURE_DOMAIN,
      Buffer.from(canonicalJson(document.assertion), 'utf8'),
    ]);
    return verifyEd25519Profile(
      Buffer.from(key.public_key, 'base64url'),
      message,
      Buffer.from(document.signature, 'base64url'),
    );
  } catch {
    return false;
  }
}

function fixturePath(base, relativePath) {
  if (typeof relativePath !== 'string' || isAbsolute(relativePath)) {
    throw new Error(`fixture path must be relative: ${String(relativePath)}`);
  }
  return resolve(base, relativePath);
}

async function main() {
  if (process.argv.length !== 3) {
    throw new Error('usage: node tests/graph_conformance_node_adapter.mjs MANIFEST');
  }
  const manifestPath = resolve(process.argv[2]);
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  const base = dirname(manifestPath);
  const cases = {};
  const bundles = {};

  for (const [alias, fixture] of Object.entries(manifest.bundles ?? {})) {
    const compressed = await readFile(fixturePath(base, fixture.path));
    if (sha256(compressed) !== fixture.sha256) {
      throw new Error(`${alias}: resource bundle SHA-256 does not match manifest pin`);
    }
    const document = JSON.parse(gunzipSync(compressed));
    if (document.schema !== 'org.aural.graph-resource-fixtures'
        || document.schema_version !== '1'
        || document.collections === null
        || typeof document.collections !== 'object'
        || Array.isArray(document.collections)) {
      throw new Error(`${alias}: invalid graph-resource fixture bundle`);
    }
    bundles[alias] = document;
  }

  for (const testCase of manifest.cases) {
    const keyPaths = testCase.public_keys.map(
      alias => fixturePath(base, manifest.public_keys[alias]),
    );
    let records;
    if (testCase.resource_bundle !== undefined) {
      const selection = testCase.resource_bundle;
      const encoded = bundles[selection.bundle].collections[selection.collection];
      if (!Array.isArray(encoded)) {
        throw new Error(`${testCase.id}: resource bundle collection must be an array`);
      }
      let selected = encoded;
      if (selection.record_count !== undefined) {
        if (!Number.isSafeInteger(selection.record_count)
            || selection.record_count < 1
            || selection.record_count > encoded.length) {
          throw new Error(`${testCase.id}: invalid resource bundle record count`);
        }
        selected = encoded.slice(0, selection.record_count);
      }
      records = selected.map(record => Buffer.from(record, 'utf8'));
    } else {
      const eventPaths = testCase.signed_events.map(
        alias => fixturePath(base, manifest.events[alias].path),
      );
      records = await Promise.all(eventPaths.map(path => readFile(path)));
    }
    const keys = await Promise.all(keyPaths.map(path => readFile(path)));
    const packageFixture = testCase.package === undefined
      ? undefined : manifest.packages[testCase.package];
    const packagePath = packageFixture === undefined
      ? undefined : fixturePath(base, packageFixture.path);
    const options = packagePath === undefined ? {} : { packagePath };
    const evidence = {
      event_input_sha256: records.map(sha256),
      key_input_sha256: keys.map(sha256),
    };
    const claims = testCase.claims ?? {};
    if (claims.input_event_count !== undefined) {
      evidence.input_event_count = records.length;
    }
    if (claims.distinct_event_id_count !== undefined) {
      evidence.distinct_event_id_count = new Set(records.map(
        record => JSON.parse(record.toString('utf8')).assertion.event_id,
      )).size;
    }
    if (claims.aggregate_event_bytes !== undefined) {
      evidence.aggregate_event_bytes = records.reduce(
        (total, record) => total + record.length, 0,
      );
    }
    if (claims.maximum_event_bytes !== undefined) {
      evidence.maximum_event_bytes = Math.max(...records.map(record => record.length));
    }
    if (claims.event_byte_lengths !== undefined) {
      evidence.event_byte_lengths = records.map(record => record.length);
    }
    if (packagePath !== undefined) {
      evidence.package_input_sha256 = sha256(await readFile(packagePath));
    }
    try {
      evidence.result = await verifySignedEventGraphDetailed(records, keys, options);
    } catch (error) {
      evidence.error = {
        category: error?.category ?? 'internal',
        stage: error?.stage ?? 'internal',
        message: error?.message ?? String(error),
      };
    }
    if (claims.all_event_signatures_valid === true) {
      if (claims.signature_evidence === 'graph_verifier'
          && evidence.result !== undefined) {
        evidence.all_event_signatures_valid = evidence.result.recordCount === records.length
          && evidence.result.events.every(event => event.status === 'signature_valid');
      } else if (claims.signature_evidence === 'independent_ed25519') {
        evidence.all_event_signatures_valid = records.every(
          record => independentlyVerifySignature(record, keys),
        );
      } else {
        evidence.all_event_signatures_valid = records.every(record => {
          try {
            return verifySignedEvent(record, keys).status === 'signature_valid';
          } catch {
            return false;
          }
        });
      }
    }
    cases[testCase.id] = evidence;
  }

  process.stdout.write(JSON.stringify({ cases }));
}

try {
  await main();
} catch (error) {
  const category = error?.category === undefined ? 'adapter' : error.category;
  const stage = error?.stage === undefined ? 'adapter' : error.stage;
  console.error(`graph conformance adapter failed [${category}/${stage}]: ${error.message}`);
  process.exitCode = 1;
}
