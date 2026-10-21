# AURAL Audio Evidence Container — Draft 0.2

**Status:** proposed experimental draft; not an adopted or registered standard.  
**Identifier:** `org.aural.audio-evidence`  
**Version:** `0.2-draft`  
**Proposed extension:** `.aural`

## 1. Conformance and terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described by BCP 14 when, and only when, they appear in all capitals.

An AURAL *writer* creates a package. An AURAL *reader* parses or extracts one. A *verifier* is a reader that applies every required structural and integrity check. An *original* is the complete byte sequence supplied to the writer; AURAL does not assert how those bytes were created.

Normative references are [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174), [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259), [RFC 7493](https://www.rfc-editor.org/rfc/rfc7493), [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339), and PKWARE's [ZIP File Format Specification 6.3.10](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT).

## 2. Scope and trust model

A Draft 0.2 package preserves one original WAVE-family audio file and a canonical manifest describing its byte length and SHA-256 digest.

A successful verification establishes only that:

- the container conforms to this draft;
- the original bytes match the manifest's size and SHA-256; and
- the ZIP CRC32 values are correct.

It does **not** establish recorder identity, time accuracy, authorship, authenticity before packaging, absence of pre-package editing, interpretation of the recording, or chain of custody. The manifest is unsigned. An attacker able to replace both manifest and original can create another internally valid package.

Digital signatures, provenance records, sensors, transcripts, annotations, and derived media are outside this draft.

## 3. Logical package

A package MUST contain exactly these two regular-file entries and no others:

| Path | Purpose |
|---|---|
| `manifest.json` | Draft 0.2 canonical manifest |
| `audio/original.wav` | complete original byte sequence |

The original entry MUST be byte-for-byte identical to the writer input. A writer MUST NOT rewrite headers, chunks, tags, padding, samples, or any other bytes.

The first 12 original bytes MUST have `RIFF` or `RF64` at offsets 0–3 and `WAVE` at offsets 8–11. This is an identification check only. Readers are not required to validate the complete WAVE structure.

## 4. Manifest serialization

### 4.1 JSON and encoding

`manifest.json` MUST be a single RFC 8259 JSON object encoded as UTF-8 without a byte-order mark. Its uncompressed length MUST NOT exceed 1,048,576 bytes. Nothing, including a line ending, may follow the JSON object.

The parsed data MUST satisfy I-JSON and these additional profile rules:

1. Object member names MUST be unique after JSON escape processing. A reader MUST reject duplicates at every depth.
2. Names and string values MUST consist only of Unicode scalar values and MUST NOT contain Unicode noncharacters. Invalid UTF-8, isolated UTF-16 surrogates (including escaped ones), and noncharacters MUST be rejected.
3. Unicode MUST be preserved as-is. Writers and readers MUST NOT apply NFC, NFD, or other normalization.
4. Every JSON number MUST be an integer token with value in `-9007199254740991` through `9007199254740991`, inclusive. Fractional and exponent notation, negative zero, NaN, and infinities MUST be rejected. Larger exact values belong in strings defined by an extension.
5. The maximum container depth is 32. The root object has depth 1; entering an object or array increments depth by one.

### 4.2 JCS canonicality

The manifest bytes MUST be exactly the RFC 8785 JSON Canonicalization Scheme (JCS) serialization of the parsed manifest. In particular:

- no whitespace is emitted between tokens;
- strings use the RFC 8785/ECMAScript escaping rules;
- object names are ordered by UTF-16 code units; and
- no trailing LF or other bytes are present.

A verifier MUST parse with duplicate detection, validate the data model, independently produce or otherwise validate the JCS form, and require byte equality. Sorted keys from a language's ordinary JSON serializer are not sufficient evidence of JCS behavior.

Draft 0.2's integer-only rule narrows valid JCS inputs; it does not alter JCS.

## 5. Manifest data model

The machine-readable companion schema is [`manifest-0.2.schema.json`](manifest-0.2.schema.json). The prose is authoritative where JSON Schema cannot express byte-level, duplicate-name, canonicalization, critical-extension, or ZIP constraints.

### 5.1 Top-level members

| Member | Required | Type and constraint |
|---|---:|---|
| `format` | yes | string exactly `org.aural.audio-evidence` |
| `version` | yes | string exactly `0.2-draft` |
| `original` | yes | string exactly `audio/original.wav` |
| `assets` | yes | array containing exactly one descriptor from §5.2 |
| `title` | no | string, at most 4,096 Unicode scalar values |
| `recorded_at` | no | timestamp string from §5.3 |
| `extensions` | no | object from §5.4 |
| `critical_extensions` | no | array from §5.4 |

A core member not listed above MUST cause rejection. Omission and JSON `null` are not interchangeable; neither optional string accepts `null`.

### 5.2 Asset descriptor

The sole member of `assets` MUST be an object containing exactly:

| Member | Type and value |
|---|---|
| `path` | string exactly `audio/original.wav` |
| `role` | string exactly `original` |
| `media_type` | string exactly `audio/wav` |
| `size` | integer equal to the original's complete byte length, 0 through 8,589,934,592 |
| `sha256` | 64 lowercase ASCII hexadecimal characters, SHA-256 of the complete original bytes |

`audio/wav` is a required Draft 0.2 token but is not presently registered in the [IANA media-type registry](https://www.iana.org/assignments/media-types). It MUST NOT be represented as an IANA registration claim.

### 5.3 Timestamp

`recorded_at`, when present, is unverified source-declared metadata. It MUST use this RFC 3339 profile:

```text
YYYY-MM-DDTHH:MM:SS[.1-to-9-digits](Z|+HH:MM|-HH:MM)
```

Calendar and clock fields MUST be valid; year `0000`, leap-second value `60`, lowercase `t`/`z`, offsets beyond ±14:00, and unknown offset `-00:00` are prohibited. An offset of 14 hours MUST have zero minutes. Writers SHOULD use UTC (`Z`) when the instant is known.

### 5.4 Extensions

An extension identifier is a URI-form, globally scoped ASCII name. It MUST be 1–255 bytes and match `^[a-z][a-z0-9+.-]*:[!-~]+$`. This exact syntax, rather than a generic URI library's acceptance rules, defines conformance. Definers SHOULD use a syntactically valid HTTPS URI or URN under their control and SHOULD avoid fragments.

`extensions`, when present, maps extension identifiers to values satisfying §4. `critical_extensions`, when present, is an array of unique extension identifiers. Every critical identifier MUST also be a key in `extensions`.

A reader:

- MUST accept an unknown extension that is not named as critical;
- MUST NOT assign semantics to an unknown extension;
- MUST reject an unsupported critical extension; and
- SHOULD preserve unknown optional extension data unchanged when rewriting a manifest for reasons unrelated to that extension.

No extension is standardized or mandatory in Draft 0.2. Unknown members outside `extensions` are not extensions and MUST be rejected.

### 5.5 Example

This display is non-normative and wrapped for readability. A stored manifest has no insignificant whitespace.

```json
{
  "assets": [{
    "media_type": "audio/wav",
    "path": "audio/original.wav",
    "role": "original",
    "sha256": "4b3f...64-lowercase-hex-digits...c201",
    "size": 44
  }],
  "format": "org.aural.audio-evidence",
  "original": "audio/original.wav",
  "recorded_at": "2026-10-13T18:00:00Z",
  "title": "Example",
  "version": "0.2-draft"
}
```

## 6. ZIP container profile

### 6.1 Records and methods

The container MUST be a single-disk ZIP archive following APPNOTE 6.3.10. It MUST contain one local header and one central-directory header for each of the two entries, followed by one central directory and one end-of-central-directory (EOCD) record. ZIP64 end records and entry-level ZIP64 extra fields MUST satisfy their separate necessity rules in Section 6.4; neither form is permitted as an optional alternative encoding.

Both entries MUST use compression method 0 (stored). Encryption, patched data, strong encryption, central-directory encryption, data descriptors, archive-extra-data records, central-directory digital signatures, split/spanned disks, and any other compression method are prohibited.

General-purpose flags MUST be zero except that bit 11 (UTF-8 names) MAY be set. Bit 3 (data descriptor) and bit 0 (encryption) MUST be clear.

### 6.2 Names and paths

The file-name octets in both local and central headers MUST be exactly ASCII `manifest.json` or `audio/original.wav`. Local and central bytes MUST agree. Because both names are ASCII, bit 11 does not alter their interpretation.

Names with NUL, backslash, empty segments, `.` or `..` segments, absolute paths, drive prefixes, aliases, case variations, or Unicode lookalikes are invalid. Directory entries are prohibited.

### 6.3 Header consistency and layout

For each entry, local and central values for version-needed, flags, method, modification time/date, CRC32, compressed size, uncompressed size, and file-name bytes MUST agree after ZIP64 expansion. Stored compressed and uncompressed sizes MUST be equal.

The first local header MUST begin at physical offset zero. Local header, name, allowed extra field, and data regions MUST be contiguous and non-overlapping. The second local header MUST immediately follow the first entry data. The central directory MUST immediately follow the second entry data. The applicable ZIP64 records and EOCD MUST immediately follow the central directory. Prefixes, trailers, gaps, and undeclared bytes are prohibited.

Entry order is not significant to readers. Writers SHOULD place `manifest.json` first.

### 6.4 Comments, extra fields, and ZIP64

The archive comment and every entry comment MUST be empty.

The only permitted local or central extra field is ZIP64 extended information header ID `0x0001`. Local and central headers are evaluated independently. In either header, this extra field MUST occur exactly once when at least one corresponding classic size, disk-start, or local-header-offset field uses its ZIP64 sentinel, and MUST NOT occur when none of that header's corresponding classic fields uses a ZIP64 sentinel. Its data MUST contain every value required by those sentinels, contain no value for a non-sentinel field, follow APPNOTE order, and have exactly the resulting length with no trailing data. Every other extra field is prohibited.

Readers and writers MUST support ZIP64 for an original above the classic limit. When any classic EOCD disk-number, entry-count, central-directory-size, or central-directory-offset field uses its ZIP64 sentinel, a ZIP64 EOCD version-1 record of size exactly 44 bytes and a single-disk ZIP64 locator MUST be present and consistent. When none of those classic EOCD fields uses its ZIP64 sentinel, a ZIP64 EOCD record and ZIP64 locator MUST NOT be present. A ZIP64 extensible data sector is prohibited. Classic non-sentinel values, if present alongside a required ZIP64 EOCD record, MUST equal their ZIP64 values.

Version-needed MUST be 1.0, 2.0, or 4.5 (`10`, `20`, or `45`) and MUST be sufficient for the used structures.

### 6.5 CRC32 and file metadata

Each local and central CRC32 MUST equal the ZIP CRC32 of the complete corresponding entry data. A verifier MUST validate CRC32 even though SHA-256 separately covers the original.

DOS directory attributes and high-word Unix-style file types other than regular file (including symlink, device, FIFO, and socket) are prohibited regardless of the creator-system field. A zero/unspecified type is acceptable. Permission bits, creator platform, internal attributes, and valid MS-DOS modification timestamps carry no AURAL semantics and MAY vary. Readers MUST NOT treat them as evidence metadata.

### 6.6 Resource limits

A reader MUST reject a Draft 0.2 package exceeding any of these declared or physical bounds before allocating or decompressing based on the offending value:

| Resource | Maximum |
|---|---:|
| ZIP entries | exactly 2 |
| manifest uncompressed size | 1,048,576 bytes |
| original uncompressed size | 8,589,934,592 bytes (8 GiB) |
| central-directory size | 4,194,304 bytes (4 MiB) |
| physical archive size | 8,606,711,808 bytes (8 GiB + 16 MiB) |
| manifest container depth | 32 |

Contradictory counts, sizes, offsets, disks, sentinels, or record lengths MUST cause rejection.

## 7. Verification algorithm

A verifier MUST, in an order that does not trust attacker-controlled allocation sizes:

1. enforce the physical-size bound;
2. locate and validate the terminal EOCD and bounded ZIP64 records;
3. validate central-directory size, count, records, and local offsets;
4. validate names, allowed flags/methods/extras, header agreement, contiguity, and regular-file metadata;
5. read `manifest.json` under its size bound, decode UTF-8, reject duplicate names and invalid I-JSON, and validate exact JCS bytes;
6. validate the Draft 0.2 data model and version/extension support;
7. require exact agreement between manifest assets and ZIP entries;
8. validate CRC32 while reading each entry;
9. validate the WAVE signature, byte count, and SHA-256 of the complete original; and
10. report success only if every check succeeds.

A verifier that also supports an incompatible legacy version MAY, after steps 1–3,
read the bounded manifest and perform only duplicate-safe JSON parsing plus
`format`/`version` identification needed for version dispatch. If it identifies
Draft 0.2, it MUST complete step 4 before performing the remaining Draft 0.2
manifest and application-level validation in steps 5–10. This exception does not
permit deferred size, offset, count, or other version-independent safety checks.

Extraction MUST occur from the same opened archive snapshot that was verified. A conformant extractor MUST NOT overwrite an existing output unless an explicit, separately documented caller policy authorizes that action.

## 8. Versioning and legacy compatibility

Draft versions are exact capability identifiers, not decimal numbers. A Draft 0.2 reader MUST accept `0.2-draft` only on its Draft 0.2 path and MUST reject an unknown version. All different pre-1.0 version identifiers are incompatible revisions. There is no minor-version fallback, numeric comparison, range negotiation, or "closest" version rule. Compatible evolution within this identifier is limited to unknown non-critical extensions and purely editorial corrections that do not change conformance. A behavioral change requires a new version identifier.

A product MAY implement a separately identified Draft 0.1 compatibility path. Such a path MUST:

- validate Draft 0.1 according to its own manifest bytes and schema, including its trailing LF;
- report `0.1-draft` and legacy status to the caller;
- never reinterpret a Draft 0.1 package as Draft 0.2; and
- preserve original bytes during any user-authorized migration.

Draft 0.2 writers MUST emit `0.2-draft` and MUST NOT emit, edit, or relabel a legacy package as a side effect of verification.

Draft 0.1 cannot be relabeled because its canonical manifest has a trailing LF, requires `title` and nullable `recorded_at`, and lacks the Draft 0.2 extension and timestamp rules. Its ZIP profile also did not normatively resolve every extra-field, flag, and local-header case now resolved here. These are explicit incompatibilities, even when both packages preserve identical original bytes.

## 9. Canonical identity and deterministic output

The canonical manifest bytes and original SHA-256 provide logical comparison points. This specification does not define a canonical ZIP byte stream. Whole-archive hashes can differ because permitted ZIP metadata, entry order, and timestamps differ. ZIP64 representation is necessity-based rather than a writer choice. Applications comparing packages SHOULD compare verified version, canonical manifest bytes, and asset digests rather than assuming archive-byte equality.

## 10. Security and privacy considerations

Implementations must treat every length, offset, name, and JSON value as hostile. They should stream the original, bound memory use, avoid temporary-file races, and not extract by path concatenation. Verification errors should fail closed and should not expose partially extracted evidence as valid.

Stored audio and manifest metadata may be sensitive. This draft provides no confidentiality, access control, erasure, redaction, anonymity, signature, timestamp authority, revocation, or trusted identity mechanism.
