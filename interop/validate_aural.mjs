#!/usr/bin/env node
// Independent, dependency-free Draft 0.2 validator for bounded classic and ZIP64 ZIP.
import { open } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const FORMAT = 'org.aural.audio-evidence';
const VERSION = '0.2-draft';
const MAX_MANIFEST = 1024 * 1024;
const MAX_AUDIO = 8 * 1024 ** 3;
const MAX_ARCHIVE = MAX_AUDIO + 16 * 1024 ** 2;
const MAX_CENTRAL = 4 * 1024 ** 2;
const IO_CHUNK = 1024 * 1024;
const names = new Set(['manifest.json', 'audio/original.wav']);

function fail(message) {
  const error = new Error(message);
  error.auralValidationFailure = true;
  throw error;
}
function u16(b, p) { return b.readUInt16LE(p); }
function u32(b, p) { return b.readUInt32LE(p); }
function equal(a, b) { return a.length === b.length && a.equals(b); }
function u64(b, p, description) {
  const value = b.readBigUInt64LE(p);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail(`unsafe ZIP64 ${description}`);
  return Number(value);
}
function safeAdd(...values) {
  let total = 0;
  for (const value of values) {
    if (!Number.isSafeInteger(value) || value < 0 || total > Number.MAX_SAFE_INTEGER - value) {
      fail('unsafe ZIP offset arithmetic');
    }
    total += value;
  }
  return total;
}

function extraFields(extra) {
  const fields = [];
  let cursor = 0;
  while (cursor < extra.length) {
    if (cursor + 4 > extra.length) fail('malformed ZIP extra field');
    const id = u16(extra, cursor), size = u16(extra, cursor + 2);
    cursor += 4;
    const end = cursor + size;
    if (end > extra.length) fail('malformed ZIP extra field');
    fields.push({ id, data: extra.subarray(cursor, end) });
    cursor = end;
  }
  return fields;
}

function expandZip64(extra, values, central) {
  const fields = extraFields(extra);
  if (fields.some(field => field.id !== 0x0001)) {
    fail(central ? 'central profile' : 'local/central mismatch');
  }
  const zip64 = fields.filter(field => field.id === 0x0001);
  if (zip64.length > 1) fail('duplicate ZIP64 extra field');
  const required = [
    values.size === 0xffffffff,
    values.compressed === 0xffffffff,
    ...(central ? [values.localOffset === 0xffffffff, values.disk === 0xffff] : []),
  ];
  if (!required.some(Boolean)) {
    if (zip64.length) fail('unnecessary ZIP64 extra field');
    return { ...values, usesZip64: false };
  }
  if (zip64.length !== 1) fail('missing ZIP64 extra field');
  const data = zip64[0].data;
  let cursor = 0;
  const take64 = description => {
    if (cursor + 8 > data.length) fail('truncated ZIP64 extra field');
    const value = u64(data, cursor, description);
    cursor += 8;
    return value;
  };
  const take32 = () => {
    if (cursor + 4 > data.length) fail('truncated ZIP64 extra field');
    const value = u32(data, cursor);
    cursor += 4;
    return value;
  };
  const expanded = { ...values, usesZip64: true };
  if (required[0]) expanded.size = take64('uncompressed size');
  if (required[1]) expanded.compressed = take64('compressed size');
  if (central && required[2]) expanded.localOffset = take64('local-header offset');
  if (central && required[3]) expanded.disk = take32();
  if (cursor !== data.length) fail('oversized ZIP64 extra field');
  return expanded;
}

const crcTable = Array.from({ length: 256 }, (_, value) => {
  let crc = value;
  for (let bit = 0; bit < 8; bit++) crc = (crc & 1) ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1);
  return crc >>> 0;
});
function updateCrc32(crc, data) {
  for (const byte of data) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return crc >>> 0;
}
function crc32(data) { return (updateCrc32(0xffffffff, data) ^ 0xffffffff) >>> 0; }

function sameSnapshot(left, right) {
  return left.size === right.size && left.dev === right.dev && left.ino === right.ino
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

class BoundedReader {
  constructor(handle, snapshot) {
    this.handle = handle;
    this.snapshot = snapshot;
    this.size = Number(snapshot.size);
  }

  async readExact(position, length, description) {
    if (!Number.isSafeInteger(position) || !Number.isSafeInteger(length)
        || position < 0 || length < 0 || position + length > this.size) {
      fail(`truncated ${description}`);
    }
    const result = Buffer.alloc(length);
    let offset = 0;
    while (offset < length) {
      const { bytesRead } = await this.handle.read(
        result, offset, length - offset, position + offset,
      );
      if (bytesRead === 0) fail(`truncated ${description}`);
      offset += bytesRead;
    }
    return result;
  }
}

function checkString(text) {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    let point = unit;
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = text.charCodeAt(++i);
      if (!(low >= 0xdc00 && low <= 0xdfff)) fail('unpaired surrogate');
      point = 0x10000 + ((unit - 0xd800) << 10) + low - 0xdc00;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) fail('unpaired surrogate');
    if ((point >= 0xfdd0 && point <= 0xfdef) || (point & 0xffff) === 0xfffe || (point & 0xffff) === 0xffff) {
      fail('Unicode noncharacter');
    }
  }
}

function canonical(value, containingDepth = 0) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') { checkString(value); return JSON.stringify(value); }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fail('number is not a safe integer');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const depth = containingDepth + 1;
    if (depth > 32) fail('JSON depth');
    return '[' + value.map(v => canonical(v, depth)).join(',') + ']';
  }
  if (typeof value === 'object') {
    const depth = containingDepth + 1;
    if (depth > 32) fail('JSON depth');
    return '{' + Object.keys(value).sort().map(key => {
      checkString(key);
      return JSON.stringify(key) + ':' + canonical(value[key], depth);
    }).join(',') + '}';
  }
  fail('unsupported JSON value');
}

function leap(year) { return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0); }
function validTimestamp(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!m || value.endsWith('-00:00')) return false;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number);
  if (!year || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const days = [31, leap(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > days[month - 1]) return false;
  if (m[7] !== 'Z') {
    const zh = Number(m[7].slice(1, 3)), zm = Number(m[7].slice(4));
    if (zh > 14 || zm > 59 || (zh === 14 && zm !== 0)) return false;
  }
  return true;
}

function exactKeys(object, required, optional = []) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) return false;
  const actual = Object.keys(object);
  return required.every(k => actual.includes(k)) && actual.every(k => required.includes(k) || optional.includes(k));
}

function validateManifest(raw) {
  if (raw.length > MAX_MANIFEST) fail('manifest size');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(raw); } catch { fail('invalid UTF-8'); }
  let doc;
  try { doc = JSON.parse(text); } catch { fail('malformed JSON'); }
  if (Buffer.from(canonical(doc), 'utf8').compare(raw) !== 0) fail('manifest is not JCS canonical');
  if (!exactKeys(doc, ['assets', 'format', 'original', 'version'],
                 ['title', 'recorded_at', 'extensions', 'critical_extensions'])) fail('manifest members');
  if (doc.format !== FORMAT || doc.version !== VERSION || doc.original !== 'audio/original.wav') fail('identity fields');
  if ('title' in doc && (typeof doc.title !== 'string' || [...doc.title].length > 4096)) fail('title');
  if ('recorded_at' in doc && (typeof doc.recorded_at !== 'string' || !validTimestamp(doc.recorded_at))) fail('timestamp');
  if (!Array.isArray(doc.assets) || doc.assets.length !== 1) fail('asset count');
  const asset = doc.assets[0];
  if (!exactKeys(asset, ['media_type', 'path', 'role', 'sha256', 'size'])) fail('asset members');
  if (asset.media_type !== 'audio/wav' || asset.path !== doc.original || asset.role !== 'original') fail('asset identity');
  if (!Number.isSafeInteger(asset.size) || asset.size < 0 || asset.size > MAX_AUDIO) fail('asset size');
  if (typeof asset.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(asset.sha256)) fail('asset hash');
  const extensionId = /^[a-z][a-z0-9+.-]*:[!-~]+$/;
  const extensions = doc.extensions ?? {};
  if (!extensions || typeof extensions !== 'object' || Array.isArray(extensions)
      || Object.keys(extensions).some(k => k.length > 255 || !extensionId.test(k))) fail('extensions');
  const critical = doc.critical_extensions ?? [];
  if (!Array.isArray(critical) || new Set(critical).size !== critical.length
      || critical.some(k => typeof k !== 'string' || !extensionId.test(k) || !(k in extensions))) fail('critical extensions');
  if (critical.length) fail('unknown critical extension');
  return asset;
}

async function parseZip(reader) {
  if (reader.size < 22) fail('archive size');
  const end = reader.size - 22;
  const eocd = await reader.readExact(end, 22, 'end of central directory');
  if (u32(eocd, 0) !== 0x06054b50 || u16(eocd, 20) !== 0) fail('terminal EOCD');
  const classic = {
    disk: u16(eocd, 4), centralDisk: u16(eocd, 6), diskCount: u16(eocd, 8),
    count: u16(eocd, 10), centralSize: u32(eocd, 12), centralOffset: u32(eocd, 16),
  };
  const usesZip64 = classic.disk === 0xffff || classic.centralDisk === 0xffff
    || classic.diskCount === 0xffff || classic.count === 0xffff
    || classic.centralSize === 0xffffffff || classic.centralOffset === 0xffffffff;
  let { disk, centralDisk, diskCount, count, centralSize, centralOffset } = classic;
  let directoryEnd = end;
  if (usesZip64) {
    const locatorOffset = end - 20;
    if (locatorOffset < 0) fail('missing ZIP64 locator');
    const locator = await reader.readExact(locatorOffset, 20, 'ZIP64 locator');
    if (u32(locator, 0) !== 0x07064b50) fail('missing ZIP64 locator');
    const locatorDisk = u32(locator, 4);
    const zip64Offset = u64(locator, 8, 'end-record offset');
    const totalDisks = u32(locator, 16);
    if (locatorDisk !== 0 || totalDisks !== 1) fail('multi-disk ZIP64');
    if (safeAdd(zip64Offset, 56) > locatorOffset) fail('invalid ZIP64 end-record offset');
    const zip64 = await reader.readExact(zip64Offset, 56, 'ZIP64 end record');
    if (u32(zip64, 0) !== 0x06064b50) fail('missing ZIP64 end record');
    const recordSize = u64(zip64, 4, 'end-record size');
    if (recordSize !== 44 || safeAdd(zip64Offset, 12, recordSize) !== locatorOffset) {
      fail('invalid ZIP64 end-record size or layout');
    }
    const needed = u16(zip64, 14);
    disk = u32(zip64, 16);
    centralDisk = u32(zip64, 20);
    diskCount = u64(zip64, 24, 'disk entry count');
    count = u64(zip64, 32, 'entry count');
    centralSize = u64(zip64, 40, 'central-directory size');
    centralOffset = u64(zip64, 48, 'central-directory offset');
    if (needed !== 45) fail('ZIP64 end record must require version 4.5');
    if (disk !== 0 || centralDisk !== 0) fail('multi-disk ZIP64');
    if (diskCount !== count) fail('contradictory ZIP64 entry counts');
    const comparisons = [
      [classic.disk, disk, 0xffff], [classic.centralDisk, centralDisk, 0xffff],
      [classic.diskCount, diskCount, 0xffff], [classic.count, count, 0xffff],
      [classic.centralSize, centralSize, 0xffffffff],
      [classic.centralOffset, centralOffset, 0xffffffff],
    ];
    if (comparisons.some(([oldValue, value, sentinel]) => oldValue !== sentinel && oldValue !== value)) {
      fail('classic and ZIP64 end records disagree');
    }
    directoryEnd = zip64Offset;
  } else if (disk !== 0 || centralDisk !== 0 || diskCount !== count) {
    fail('multi-disk or contradictory ZIP metadata');
  }
  if (count !== 2 || diskCount !== count || centralSize > MAX_CENTRAL
      || safeAdd(centralOffset, centralSize) !== directoryEnd) fail('central directory envelope');
  const central = await reader.readExact(centralOffset, centralSize, 'central directory');
  const entries = [];
  let cursor = 0;
  for (let i = 0; i < count; i++) {
    if (cursor + 46 > central.length || u32(central, cursor) !== 0x02014b50) fail('central header');
    const needed = u16(central, cursor + 6), flags = u16(central, cursor + 8);
    const method = u16(central, cursor + 10), time = u16(central, cursor + 12), date = u16(central, cursor + 14);
    const crc = u32(central, cursor + 16);
    const classicCompressed = u32(central, cursor + 20), classicSize = u32(central, cursor + 24);
    const nameLen = u16(central, cursor + 28), extraLen = u16(central, cursor + 30), commentLen = u16(central, cursor + 32);
    const classicDisk = u16(central, cursor + 34), external = u32(central, cursor + 38);
    const classicLocalOffset = u32(central, cursor + 42);
    const next = cursor + 46 + nameLen + extraLen + commentLen;
    if (next > central.length || commentLen || ![0, 0x800].includes(flags) || method !== 0) {
      fail('central profile');
    }
    const rawName = central.subarray(cursor + 46, cursor + 46 + nameLen);
    const centralExtra = central.subarray(cursor + 46 + nameLen, cursor + 46 + nameLen + extraLen);
    const expanded = expandZip64(centralExtra, {
      size: classicSize, compressed: classicCompressed,
      localOffset: classicLocalOffset, disk: classicDisk,
    }, true);
    const { size, compressed, localOffset, disk } = expanded;
    if (disk !== 0 || compressed !== size || ![10, 20, 45].includes(needed)
        || (expanded.usesZip64 && needed !== 45)) fail('central profile');
    if (rawName.some(byte => byte > 0x7f)) fail('non-ASCII name');
    const name = rawName.toString('ascii');
    const modeType = (external >>> 16) & 0xf000;
    if (!names.has(name) || ![0, 0x8000].includes(modeType) || (external & 0x10)) fail('name or file type');
    if ((name === 'manifest.json' && size > MAX_MANIFEST)
        || (name === 'audio/original.wav' && size > MAX_AUDIO)) fail('entry size limit');
    if (safeAdd(localOffset, 30) > centralOffset) fail('local header');
    const local = await reader.readExact(localOffset, 30, 'local header');
    if (u32(local, 0) !== 0x04034b50) fail('local header');
    const localNeeded = u16(local, 4), localFlags = u16(local, 6);
    const localMethod = u16(local, 8), localTime = u16(local, 10), localDate = u16(local, 12);
    const localCrc = u32(local, 14);
    const classicLocalCompressed = u32(local, 18), classicLocalSize = u32(local, 22);
    const localNameLen = u16(local, 26), localExtraLen = u16(local, 28);
    const localHeaderEnd = safeAdd(localOffset, 30, localNameLen, localExtraLen);
    if (localHeaderEnd > centralOffset) fail('local/central mismatch');
    const localName = await reader.readExact(localOffset + 30, localNameLen, 'local member name');
    const localExtra = await reader.readExact(
      safeAdd(localOffset, 30, localNameLen), localExtraLen, 'local extra field',
    );
    const localExpanded = expandZip64(localExtra, {
      size: classicLocalSize, compressed: classicLocalCompressed,
    }, false);
    const localCompressed = localExpanded.compressed, localSize = localExpanded.size;
    if (!equal(rawName, localName) || localNeeded !== needed || localFlags !== flags
        || localMethod !== method || localTime !== time || localDate !== date || localCrc !== crc
        || localCompressed !== compressed || localSize !== size
        || ((expanded.usesZip64 || localExpanded.usesZip64) && needed !== 45)) {
      fail('local/central mismatch');
    }
    const dataStart = localHeaderEnd;
    const dataEnd = safeAdd(dataStart, size);
    if (dataEnd > centralOffset) fail('entry overlaps central directory');
    entries.push({ name, localOffset, dataStart, dataEnd, size, crc });
    cursor = next;
  }
  if (cursor !== central.length || new Set(entries.map(e => e.name)).size !== 2) fail('duplicate or extra entry');
  entries.sort((a, b) => a.localOffset - b.localOffset);
  if (entries[0].localOffset !== 0 || entries[0].dataEnd !== entries[1].localOffset
      || entries[1].dataEnd !== centralOffset) fail('undeclared ZIP bytes');
  return new Map(entries.map(entry => [entry.name, entry]));
}

async function readSmallEntry(reader, entry, limit) {
  if (entry.size > limit) fail('manifest size');
  const data = await reader.readExact(entry.dataStart, entry.size, entry.name);
  if (crc32(data) !== entry.crc) fail('entry CRC32');
  return data;
}

async function digestAudio(reader, entry) {
  let position = entry.dataStart;
  let remaining = entry.size;
  let crc = 0xffffffff;
  const hash = createHash('sha256');
  const header = Buffer.alloc(Math.min(12, entry.size));
  let headerLength = 0;
  while (remaining) {
    const length = Math.min(IO_CHUNK, remaining);
    const chunk = await reader.readExact(position, length, 'audio payload');
    if (headerLength < header.length) {
      const copied = chunk.copy(header, headerLength, 0, header.length - headerLength);
      headerLength += copied;
    }
    crc = updateCrc32(crc, chunk);
    hash.update(chunk);
    position += length;
    remaining -= length;
  }
  if (((crc ^ 0xffffffff) >>> 0) !== entry.crc) fail('entry CRC32');
  if (!(['RIFF', 'RF64'].includes(header.subarray(0, 4).toString('ascii')))
      || header.subarray(8, 12).toString('ascii') !== 'WAVE') fail('WAVE signature');
  return hash.digest('hex');
}

async function verifyArchive(path, options = {}) {
  const handle = await open(path, 'r');
  try {
    const before = await handle.stat({ bigint: true });
    const requestedLimit = options.maxArchive;
    const archiveLimit = Number.isSafeInteger(requestedLimit) && requestedLimit >= 0
      ? Math.min(requestedLimit, MAX_ARCHIVE) : MAX_ARCHIVE;
    if (!before.isFile() || before.size > BigInt(archiveLimit)) fail('archive size');
    const reader = new BoundedReader(handle, before);
    const entries = await parseZip(reader);
    const manifestEntry = entries.get('manifest.json');
    const audioEntry = entries.get('audio/original.wav');
    const manifest = await readSmallEntry(reader, manifestEntry, MAX_MANIFEST);
    const asset = validateManifest(manifest);
    if (audioEntry.size !== asset.size || audioEntry.size > MAX_AUDIO) fail('audio size mismatch');
    const digest = await digestAudio(reader, audioEntry);
    if (digest !== asset.sha256) fail('audio SHA-256 mismatch');
    const after = await handle.stat({ bigint: true });
    if (!sameSnapshot(before, after)) fail('archive changed during validation');
    const details = {
      status: 'integrity_valid',
      format: FORMAT,
      version: VERSION,
      manifest_sha256: createHash('sha256').update(manifest).digest('hex'),
      original_path: asset.path,
      audio_sha256: digest,
      audio_bytes: audioEntry.size,
    };
    return details;
  } finally {
    await handle.close();
  }
}

export async function verifyDetailed(path, options = {}) {
  return verifyArchive(path, options);
}

export async function verify(path, options = {}) {
  const details = await verifyArchive(path, options);
  return {
    status: details.status,
    version: details.version,
    audio_sha256: details.audio_sha256,
    audio_bytes: details.audio_bytes,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 3) fail('usage: node interop/validate_aural.mjs FILE');
    console.log(JSON.stringify(await verify(process.argv[2])));
  } catch (error) {
    console.error(`AURAL ERROR: ${error.message}`);
    process.exitCode = 1;
  }
}
