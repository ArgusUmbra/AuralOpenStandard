import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';

import { verifySignedEventGraphDetailed } from '../interop/signed_event_graph.mjs';

function sha256(raw) {
  return createHash('sha256').update(raw).digest('hex');
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

  for (const testCase of manifest.cases) {
    const eventPaths = testCase.signed_events.map(
      alias => fixturePath(base, manifest.events[alias].path),
    );
    const keyPaths = testCase.public_keys.map(
      alias => fixturePath(base, manifest.public_keys[alias]),
    );
    const records = await Promise.all(eventPaths.map(path => readFile(path)));
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
