# AURAL Draft 0.2 interoperability guidance

This document is informative implementation guidance. The specification remains authoritative.

## Demonstrated result

Two independent implementations currently agree on the Draft 0.2 corpus:

- the Python reference uses `zipfile` only after a manual raw-record preflight; and
- `interop/validate_aural.mjs` is a dependency-free Node.js validator with its own bounded positional ZIP reader, CRC32 implementation, JCS validation, schema checks, streaming SHA-256 verification, and WAVE signature check.

On Node.js 24.19.0 and Python 3.11.5, both implementations accept all four Draft 0.2 positive fixtures and reject all 26 Draft 0.2 negative fixtures. The Python implementation additionally accepts two Draft 0.1 fixtures through its separate legacy path. The Node validator intentionally supports only classic-size ZIP records and is therefore an independent validator, not yet a fully conformant general reader for ZIP64 packages.

The Node validator opens the pathname once, checks the resulting file handle's physical size before allocating archive-controlled buffers, reads the central directory under the 4 MiB bound, and streams audio in 1 MiB chunks. It compares file-handle metadata before and after validation so truncation, extension, or ordinary in-place modification produces a controlled failure; replacement of the pathname cannot switch the already-open validation object.

Java 21 was available during this work, but no third implementation was added. Rust, Go, .NET/C#, and C++ toolchains were unavailable. Guidance below is therefore analysis, not a claim that those implementations have passed the corpus.

## Canonical JSON hazards

### Python

`json.dumps(sort_keys=True)` is not JCS. Python sorts by Unicode code point, while JCS sorts property names as UTF-16 code units. The golden U+1D11E/U+E000 pair exposes this difference. Python float formatting must not be used as a substitute for ECMAScript formatting. Draft 0.2 avoids that issue by allowing only safe integers.

Use strict UTF-8 decoding, `object_pairs_hook` for duplicate detection, a `parse_int` range check, and rejection callbacks for floats and non-finite constants. Validate escaped surrogates and Unicode noncharacters after parsing.

### Kotlin and Java

Java `String` comparison is UTF-16 based and can implement JCS key ordering naturally, but library map serializers may preserve insertion order or choose another order. Jackson and Gson commonly collapse duplicate names unless configured or intercepted at token level. Parse as a token stream or enable strict duplicate detection.

Use `long` only after checking the safe-integer range. `java.util.zip.ZipFile` primarily exposes central-directory views; it is not sufficient by itself for local-header equality, hidden gaps, prefixes, duplicates, and all extra-field rules. Preflight bytes independently.

### Rust

`serde_json::Value` object construction can lose duplicate names and map ordering depends on features. Detect duplicates with a custom visitor and emit JCS explicitly. Reject all JSON floating tokens even if they mathematically denote an integer.

The `zip` crate's accepted feature set varies by version. Disable unsupported compression/encryption paths and independently inspect local and central records. Use checked arithmetic for every offset plus length.

### Go

Go map iteration order is deliberately unstable. `encoding/json` sorting behavior alone is not a JCS conformance statement, and ordinary unmarshalling overwrites duplicate keys. Use `json.Decoder.Token` to detect duplicates and `UseNumber` to validate the lexical and safe-integer constraints before conversion.

`archive/zip` is useful for CRC and entry streaming but should follow a raw structural preflight. Be careful that `FileHeader` names are decoded strings rather than the exact on-disk octets required by this profile.

### JavaScript and TypeScript

`JSON.stringify` supplies JCS primitive serialization and JavaScript's default string sort uses UTF-16 code units. Recursively sorting object keys is still required. `JSON.parse` keeps only one duplicate member, so compare the input bytes with the canonical reserialization or use a duplicate-aware parser. Walk strings to reject unpaired surrogates and noncharacters. Require `Number.isSafeInteger` for every number.

Node's standard library has no ZIP reader. The included validator parses the small stored-only profile directly. Browser implementations should use bounded random access rather than copying an attacker-declared archive into multiple buffers.

### C++

JSON libraries differ in duplicate handling, number storage, Unicode validation, and object ordering. Configure SAX/event parsing where possible. `std::string` compares UTF-8 bytes, which is not a general substitute for UTF-16 JCS ordering; convert property names to UTF-16 code units for comparison.

ZIP libraries frequently enable broad compatibility features by default. Restrict methods and flags, retain raw filename bytes, and add an envelope preflight around the library.

## ZIP interoperability checklist

Across languages, implementations should verify the same sequence:

1. physical bound and terminal EOCD;
2. single-disk counts and bounded central directory;
3. exact raw ASCII names and duplicate rejection;
4. local/central agreement after ZIP64 expansion;
5. stored method, allowed flags, allowed extra fields, and no comments;
6. contiguous regions with no prefix, gap, overlap, or trailer;
7. regular-file metadata only;
8. CRC32 while consuming entry bytes; and
9. manifest size/JCS/schema followed by original SHA-256.

Do not extract first and validate later. Do not use a platform path-normalization API to decide whether an archive name is safe; compare the exact permitted name bytes.

## ZIP metadata and reproducibility

MS-DOS timestamps have two-second granularity and different libraries synthesize different creator systems, permission bits, and version-needed values. These fields are intentionally non-semantic within the allowed profile. A reproducible writer may use `1980-01-01T00:00:00` ZIP timestamps and stable entry order, as the reference does, but readers must not require those choices.

Therefore:

- manifest byte equality is portable;
- original SHA-256 equality is portable;
- whole-archive byte equality is not required; and
- ZIP timestamps must never substitute for `recorded_at`.

## Recommended porting process

Start with `golden-manifest.json`, then the three positive packages, then each negative group. Confirm exact manifest SHA-256 before adding ZIP handling. Run the implementation against `expected.json` and publish toolchain/library versions and discrepancies. A claim of independent interoperability should identify at least two implementations that actually ran the same immutable fixture hashes.
