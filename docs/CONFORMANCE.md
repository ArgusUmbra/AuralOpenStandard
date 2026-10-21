# AURAL Draft 0.2 conformance

## Conformance claims

A **Draft 0.2 writer** conforms only if every package it emits satisfies all writer requirements in the Draft 0.2 specification. It MUST preserve input bytes, emit an exact JCS manifest, use only the profiled ZIP structures, and verify its output or provide equivalent assurance before publishing it.

A **Draft 0.2 reader** conforms only if it accepts every applicable positive fixture and rejects every Draft 0.2 negative fixture. A reader that does not implement extraction may still conform as a verifier. A reader MUST NOT report integrity success before validating both ZIP CRC32 and the manifest SHA-256.

A **Draft 0.1-compatible reader** is an additional capability. It MUST identify legacy success separately. It is not required for a minimal Draft 0.2 reader, and it does not permit Draft 0.1 output from a Draft 0.2 writer.

Implementations SHOULD return stable machine-readable error categories. Exact human error text is not part of conformance.

## Corpus layout and reproducibility

Fixtures are in `tests/fixtures/conformance/`. `expected.json` is the machine-readable outcome and SHA-256 index. `tools/generate_conformance_fixtures.py` deterministically regenerates the corpus from a 52-byte synthetic WAVE file; it contains no investigation evidence. `valid-independent.aural` is assembled by a small raw-record writer and literal canonical manifest that do not call the Python reference implementation's canonicalizer, package writer, or private ZIP helpers.

Run from the repository root:

```powershell
python tools\generate_conformance_fixtures.py
python -m unittest discover -s tests -v
node interop\validate_aural.mjs tests\fixtures\conformance\valid-minimal.aural
```

Regeneration MUST leave every `fixture_sha256` in `expected.json` unchanged unless the corpus is intentionally revised and documented.

## Golden manifest vector

`golden-manifest.json` is exactly 402 UTF-8 bytes, has no BOM and no trailing LF, and has SHA-256:

```text
83ff69181aa5a1eb7b04a042eee89081a155a61736838615444f60c95672c3da
```

Its exact decoded content (the code fence's display line ending is not part of the vector) is:

```json
{"assets":[{"media_type":"audio/wav","path":"audio/original.wav","role":"original","sha256":"125f39eda3fea4265c129447c18ea5a89ed7302255c7a33ef104393c1f716873","size":52}],"extensions":{"https://example.org/optional":{"𝄞":"supplementary","":"BMP"}},"format":"org.aural.audio-evidence","original":"audio/original.wav","recorded_at":"2026-10-13T18:00:00Z","title":"Café 𝄞","version":"0.2-draft"}
```

The synthetic original is 52 bytes with SHA-256 `125f39eda3fea4265c129447c18ea5a89ed7302255c7a33ef104393c1f716873`. The key `𝄞` (UTF-16 `D834 DD1E`) precedes U+E000, demonstrating JCS UTF-16 ordering where Python code-point ordering would differ.

## Expected fixture outcomes

`accept-0.2` means full Draft 0.2 integrity success. `accept-legacy-0.1` means success only through a visibly distinct legacy path. `reject` means no content may be reported as verified or extracted.

| Fixture | Outcome | Condition |
|---|---|---|
| `valid-minimal.aural` | accept-0.2 | minimal canonical package |
| `valid-independent.aural` | accept-0.2 | independently assembled canonical manifest and classic ZIP records |
| `valid-required-zip64-end.aural` | accept-0.2 | ZIP64 end records required by classic EOCD count sentinels |
| `valid-unicode.aural` | accept-0.2 | Unicode plus UTF-16 JCS ordering |
| `valid-unknown-optional.aural` | accept-0.2 | unknown optional extension |
| `legacy-0.1.aural` | accept-legacy-0.1 | distinct legacy path |
| `legacy-0.1-zip64-extra.aural` | accept-legacy-0.1 | safe Assignment 002 behavior for an unnecessary ZIP64 extra field |
| `invalid-noncanonical.aural` | reject | pretty-printed, non-JCS manifest |
| `invalid-malformed-json.aural` | reject | truncated JSON |
| `invalid-utf8.aural` | reject | invalid UTF-8 |
| `invalid-duplicate-key.aural` | reject | duplicate object name |
| `invalid-unpaired-surrogate.aural` | reject | isolated escaped surrogate |
| `invalid-noncharacter.aural` | reject | I-JSON Unicode noncharacter |
| `invalid-fraction.aural` | reject | fractional number |
| `invalid-unsafe-integer.aural` | reject | integer outside safe range |
| `invalid-negative-zero.aural` | reject | negative zero/noncanonical number |
| `invalid-excessive-depth.aural` | reject | nesting exceeds 32 |
| `invalid-asset-hash.aural` | reject | incorrect declared SHA-256 |
| `invalid-altered-original.aural` | reject | altered audio with internally correct ZIP CRC32 |
| `invalid-malformed-local-header.aural` | reject | bad local-header signature |
| `invalid-missing-required-zip64-end.aural` | reject | classic EOCD sentinels without the required ZIP64 end records |
| `invalid-local-central-crc.aural` | reject | local/central CRC disagreement |
| `invalid-extra-field.aural` | reject | non-ZIP64 extra field |
| `invalid-unnecessary-zip64-extra.aural` | reject | Draft 0.2 ZIP64 field without a corresponding sentinel |
| `invalid-redundant-zip64-end.aural` | reject | ZIP64 end records without a corresponding classic EOCD sentinel |
| `invalid-entry-comment.aural` | reject | central-directory entry comment |
| `invalid-special-file.aural` | reject | Unix symlink metadata |
| `invalid-unsafe-filename.aural` | reject | traversal/undeclared path |
| `invalid-compression.aural` | reject | DEFLATE rather than stored method |
| `invalid-duplicate-entry.aural` | reject | duplicate ZIP name |
| `invalid-trailer.aural` | reject | bytes after EOCD |
| `invalid-excessive-declared-size.aural` | reject | asset size above 8 GiB |
| `invalid-version.aural` | reject | unknown draft version |
| `invalid-critical-extension.aural` | reject | unsupported critical extension |
| `invalid-unknown-member.aural` | reject | unknown member outside extension point |

The public corpus covers classic archives, a required bounded ZIP64 end-record chain, a missing required chain, a redundant otherwise-valid chain, and an unnecessary entry-level ZIP64 extra field. The suite additionally covers malformed ZIP64 locators, archive prefixes, ZIP and central-directory entry comments, embedded NUL names, local/central filename disagreement, excessive entry count and central-directory size, extraction snapshot integrity, no-overwrite behavior, byte-identical legacy extraction, and pre-allocation rejection through a reduced Node archive ceiling that cannot raise the normative limit.

## Verification report requirements

On success, a verifier SHOULD report at least:

- actual format version;
- whether a legacy path was used;
- original byte length;
- verified lowercase SHA-256; and
- an explicit warning that internal integrity is not source authenticity.

On failure, it MUST NOT return a partial success. Extraction output created before a late failure MUST be removed or kept inaccessible.

## Adding fixtures

Each new rule with a practical malformed representation SHOULD gain one smallest-useful negative fixture. A positive fixture SHOULD be added for a newly permitted structure. Fixture names are stable test-vector identifiers; changing bytes requires updating the index and explaining why in design history.
