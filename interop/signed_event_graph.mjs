// Bounded, deterministic signed-event graph ingestion for the AURAL profile.
// Internal parent resolution is structural-only; graph cryptography remains deferred.
import {
  signedEventSha256,
  validateSignedEventRecord,
} from './validate_provenance.mjs';

export const MAX_GRAPH_EVENT_RECORDS = 4096;
export const MAX_AGGREGATE_GRAPH_EVENT_BYTES = 64 * 1024 * 1024;
export const MAX_SIGNED_EVENT_BYTES = 1024 * 1024;
export const MAX_GRAPH_PARENT_REFERENCES = 64;
export const MAX_GRAPH_DEPTH = 256;

const LIMIT_NAMES = new Set([
  'maxEventRecords',
  'maxAggregateEventBytes',
  'maxRecord',
  'maxParentReferences',
  'maxGraphDepth',
]);

export class SignedEventGraphError extends Error {
  constructor(category, stage, message, options = undefined) {
    super(message, options);
    this.name = 'SignedEventGraphError';
    this.category = category;
    this.stage = stage;
  }
}

function fail(category, stage, message, options = undefined) {
  throw new SignedEventGraphError(category, stage, message, options);
}

function configuredLimit(options, name, maximum, minimum = 1) {
  if (!(name in options)) return maximum;
  const value = options[name];
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(
      'configuration',
      'input',
      `${name} must be an integer from ${minimum} through ${maximum}`,
    );
  }
  return value;
}

function graphLimits(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    fail('configuration', 'input', 'graph indexing options must be an object');
  }
  for (const name of Object.keys(options)) {
    if (!LIMIT_NAMES.has(name)) {
      fail('configuration', 'input', `unknown graph indexing option: ${name}`);
    }
  }
  return Object.freeze({
    maxEventRecords: configuredLimit(options, 'maxEventRecords', MAX_GRAPH_EVENT_RECORDS),
    maxAggregateEventBytes: configuredLimit(
      options, 'maxAggregateEventBytes', MAX_AGGREGATE_GRAPH_EVENT_BYTES,
    ),
    maxRecord: configuredLimit(options, 'maxRecord', MAX_SIGNED_EVENT_BYTES),
    maxParentReferences: configuredLimit(
      options, 'maxParentReferences', MAX_GRAPH_PARENT_REFERENCES, 0,
    ),
    maxGraphDepth: configuredLimit(options, 'maxGraphDepth', MAX_GRAPH_DEPTH),
  });
}

function copyBoundedInputs(records, limits) {
  if (!Array.isArray(records)) {
    fail('input', 'input', 'signed-event records must be an array');
  }
  if (records.length === 0) {
    fail('input', 'input', 'signed-event records must not be empty');
  }
  if (records.length > limits.maxEventRecords) {
    fail('resource_limit', 'input', 'too many signed-event records');
  }

  let aggregateBytes = 0;
  const copies = [];
  for (const record of records) {
    if (!Buffer.isBuffer(record)) {
      fail('input', 'input', 'signed-event record must be supplied as bytes');
    }
    if (record.length < 1 || record.length > limits.maxRecord) {
      fail('resource_limit', 'input', 'signed-event record size is outside the configured limit');
    }
    aggregateBytes += record.length;
    if (aggregateBytes > limits.maxAggregateEventBytes) {
      fail(
        'resource_limit',
        'input',
        'aggregate signed-event data exceeds the configured limit',
      );
    }
    copies.push(Buffer.from(record));
  }
  return copies;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export class IndexedSignedEvent {
  #recordBytes;

  constructor(recordBytes, document, digest) {
    // recordBytes is already an ingestion-owned defensive copy.
    this.#recordBytes = recordBytes;
    this.document = deepFreeze(document);
    this.assertion = this.document.assertion;
    this.eventId = this.assertion.event_id;
    this.signedEventSha256 = digest;
    Object.freeze(this);
  }

  get recordBytes() {
    return Buffer.from(this.#recordBytes);
  }

  hasSameRecordBytes(other) {
    return other instanceof IndexedSignedEvent && this.#recordBytes.equals(other.#recordBytes);
  }

  compareRecordBytes(other) {
    if (!(other instanceof IndexedSignedEvent)) {
      throw new TypeError('record comparison requires an IndexedSignedEvent');
    }
    return Buffer.compare(this.#recordBytes, other.#recordBytes);
  }
}

export class SignedEventGraphIndex {
  #byEventId;

  #byDigest;

  constructor(entries, duplicateRecordCount) {
    this.#byEventId = new Map(entries.map(entry => [entry.eventId, entry]));
    this.#byDigest = new Map(
      [...entries]
        .sort((left, right) => compareText(
          left.signedEventSha256, right.signedEventSha256,
        ))
        .map(entry => [entry.signedEventSha256, entry]),
    );
    this.status = 'indexed_not_verified';
    this.verificationStatus = 'not_implemented';
    this.parentResolution = 'not_performed';
    this.signatureVerification = 'not_performed';
    this.historyCompleteness = 'not_established';
    this.recordCount = entries.length;
    this.duplicateRecordCount = duplicateRecordCount;
    this.eventIds = Object.freeze([...this.#byEventId.keys()]);
    this.signedEventDigests = Object.freeze([...this.#byDigest.keys()]);
    this.records = Object.freeze([...entries]);
    Object.freeze(this);
  }

  get byEventId() {
    return new Map(this.#byEventId);
  }

  get byDigest() {
    return new Map(this.#byDigest);
  }

  getByEventId(eventId) {
    return this.#byEventId.get(eventId);
  }

  getByDigest(digest) {
    return this.#byDigest.get(digest);
  }
}

class StructurallyResolvedSignedEventGraph {
  constructor(records, maximumDepth) {
    this.status = 'structural_only';
    this.verificationStatus = 'not_performed';
    this.parentResolution = 'resolved';
    this.signatureVerification = 'not_performed';
    this.historyCompleteness = 'not_established';
    this.recordCount = records.length;
    this.maximumDepth = maximumDepth;
    this.eventIds = Object.freeze(records.map(record => record.eventId));
    this.records = Object.freeze([...records]);
    Object.freeze(this);
  }
}

function comparePrepared(left, right) {
  const digestOrder = compareText(left.digest, right.digest);
  return digestOrder || Buffer.compare(left.recordBytes, right.recordBytes);
}

function compareText(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

class TextMinHeap {
  #values = [];

  get size() {
    return this.#values.length;
  }

  push(value) {
    let index = this.#values.length;
    this.#values.push(value);
    while (index > 0) {
      const parent = Math.floor((index - 1) / 2);
      if (compareText(this.#values[parent], value) <= 0) break;
      this.#values[index] = this.#values[parent];
      index = parent;
    }
    this.#values[index] = value;
  }

  pop() {
    const minimum = this.#values[0];
    const last = this.#values.pop();
    if (this.#values.length === 0) return minimum;

    let index = 0;
    while (true) {
      const left = index * 2 + 1;
      if (left >= this.#values.length) break;
      const right = left + 1;
      let child = left;
      if (right < this.#values.length
          && compareText(this.#values[right], this.#values[left]) < 0) {
        child = right;
      }
      if (compareText(this.#values[child], last) >= 0) break;
      this.#values[index] = this.#values[child];
      index = child;
    }
    this.#values[index] = last;
    return minimum;
  }
}

function resolveSignedEventGraphStructure(index, options = {}) {
  const limits = graphLimits(options);
  if (!(index instanceof SignedEventGraphIndex)) {
    fail('configuration', 'input', 'index must be a SignedEventGraphIndex');
  }

  // Re-sort defensively instead of depending on Map or constructor insertion order.
  const eventIds = [...index.eventIds].sort(compareText);

  // Enforce fanout for every node before allocating adjacency structures.
  for (const eventId of eventIds) {
    const parents = index.getByEventId(eventId).assertion.parents;
    if (parents.length > limits.maxParentReferences) {
      fail(
        'resource_limit',
        'graph',
        'event parent fanout exceeds the configured limit',
      );
    }
  }

  const children = new Map(eventIds.map(eventId => [eventId, []]));
  const parentCounts = new Map();

  // Nodes are visited by event ID, giving deterministic precedence to faults.
  // Adjacency is populated only after each reference is resolved exactly.
  for (const eventId of eventIds) {
    const parents = index.getByEventId(eventId).assertion.parents;
    parentCounts.set(eventId, parents.length);
    for (const reference of parents) {
      const parentId = reference.event_id;
      const parent = index.getByEventId(parentId);
      if (parent === undefined) {
        fail('missing_parent', 'graph', 'declared parent event_id is absent');
      }
      if (parent.signedEventSha256 !== reference.signed_event_digest.value) {
        fail(
          'parent_digest_mismatch',
          'graph',
          'declared parent digest does not match the indexed event',
        );
      }
      children.get(parentId).push(eventId);
    }
  }

  const eligible = new TextMinHeap();
  const depths = new Map();
  for (const eventId of eventIds) {
    if (parentCounts.get(eventId) === 0) {
      eligible.push(eventId);
      depths.set(eventId, 1);
    }
  }

  const ordered = [];
  let maximumDepth = 0;
  let depthExceeded = false;
  while (eligible.size > 0) {
    const eventId = eligible.pop();
    ordered.push(index.getByEventId(eventId));
    const depth = depths.get(eventId);
    maximumDepth = Math.max(maximumDepth, depth);
    if (depth > limits.maxGraphDepth) depthExceeded = true;

    for (const childId of children.get(eventId)) {
      depths.set(childId, Math.max(depths.get(childId) ?? 1, depth + 1));
      const remaining = parentCounts.get(childId) - 1;
      parentCounts.set(childId, remaining);
      if (remaining === 0) eligible.push(childId);
    }
  }

  if (ordered.length !== eventIds.length) {
    fail('cycle', 'graph', 'signed-event parent graph contains a directed cycle');
  }
  if (depthExceeded) {
    fail('resource_limit', 'graph', 'graph depth exceeds the configured limit');
  }

  return new StructurallyResolvedSignedEventGraph(ordered, maximumDepth);
}

function indexWithDigest(records, options, digestFunction) {
  const limits = graphLimits(options);
  const boundedRecords = copyBoundedInputs(records, limits);
  const prepared = boundedRecords.map(recordBytes => ({
    recordBytes,
    digest: digestFunction(recordBytes),
  }));
  for (const item of prepared) {
    if (typeof item.digest !== 'string' || !/^[0-9a-f]{64}$/.test(item.digest)) {
      fail('configuration', 'input', 'signed-event digest function returned an invalid digest');
    }
  }
  prepared.sort(comparePrepared);

  const validated = prepared.map(item => {
    let document;
    try {
      document = validateSignedEventRecord(item.recordBytes, { maxRecord: limits.maxRecord });
    } catch (error) {
      if (error?.category) {
        throw new SignedEventGraphError(error.category, 'record', error.message, { cause: error });
      }
      throw error;
    }
    return new IndexedSignedEvent(item.recordBytes, document, item.digest);
  });

  validated.sort((left, right) => (
    compareText(left.eventId, right.eventId)
      || compareText(left.signedEventSha256, right.signedEventSha256)
      || left.compareRecordBytes(right)
  ));

  const byDigest = new Map();
  const byEventId = new Map();
  let duplicateRecordCount = 0;
  for (const entry of validated) {
    const digestEntry = byDigest.get(entry.signedEventSha256);
    if (digestEntry && !digestEntry.hasSameRecordBytes(entry)) {
      fail(
        'signed_event_digest_collision',
        'graph',
        'signed-event digest identifies different record bytes',
      );
    }
    if (!digestEntry) byDigest.set(entry.signedEventSha256, entry);

    const identityEntry = byEventId.get(entry.eventId);
    if (identityEntry) {
      if (identityEntry.signedEventSha256 !== entry.signedEventSha256) {
        fail(
          'event_id_collision',
          'graph',
          'event_id identifies different signed-event digests',
        );
      }
      duplicateRecordCount += 1;
      continue;
    }
    byEventId.set(entry.eventId, entry);
  }

  return new SignedEventGraphIndex([...byEventId.values()], duplicateRecordCount);
}

export function indexSignedEventRecords(records, options = {}) {
  return indexWithDigest(records, options, signedEventSha256);
}

// A narrow test seam for the otherwise infeasible SHA-256 collision branch.
export const __testing = Object.freeze({
  indexSignedEventRecordsWithDigest(records, options, digestFunction) {
    if (typeof digestFunction !== 'function') {
      fail('configuration', 'input', 'digestFunction must be a function');
    }
    return indexWithDigest(records, options, digestFunction);
  },
  // Structural-only seam for Phase 008B tests and later Phase 008C integration.
  resolveSignedEventGraphStructure(index, options = {}) {
    return resolveSignedEventGraphStructure(index, options);
  },
});
