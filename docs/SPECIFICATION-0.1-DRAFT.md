# AURAL Audio Evidence Container — Draft 0.1 (experimental)

**Status:** prototype only; not an accepted or registered standard. **Extension:** `.aural` (proposed; naming review outstanding). **MIME type:** none assigned. This document defines the narrow *reference prototype profile*, not the intended full AURAL standard.

## Purpose and trust boundary

AURAL encapsulates original recordings and evidence metadata in a portable package. A valid hash establishes **consistency with the package manifest**, not that a capture is authentic, paranormal, unedited before packaging, from a particular device, or recorded at the declared time. The manifest is currently **unsigned**, so a malicious person can replace both audio and hash and produce a valid package. Signatures and independently trusted capture identity are future work.

## Draft 0.1 profile

- Container: ZIP64-compatible ZIP; exactly two entries: `manifest.json` and `audio/original.wav`.
- Entries are uncompressed (`ZIP_STORED`). No encryption, directories, symlinks, duplicate file names, undeclared assets, or unsafe paths.
- ZIP entries should be written in order: manifest first, audio second (not a verifier requirement).
- The original audio bytes are preserved unchanged, including all WAV headers and metadata.
- The source must start with `RIFF` or `RF64`, then `WAVE` at offset 8; **this is only a signature check, not complete WAV parsing**.
- `manifest.json`: UTF-8 JSON canonicalized in this draft by alphabetically sorted keys, compact separators, raw non-ASCII Unicode, and one trailing LF. This *is not* RFC 8785 JCS and is not sufficient for cross-language canonicalization guarantees. The future signature profile must adopt a standardized algorithm (likely RFC 8785 with strict I-JSON constraints).
- SHA-256 of *complete original WAV file bytes* is stored as 64 lowercase hexadecimal characters.
- `format` = `org.aural.audio-evidence`; `version` = `0.1-draft`.
- `recorded_at` is nullable and represents unverified source-declared capture time; prefer RFC 3339 UTC when known. `title` is a free-form label.
- `original` = `audio/original.wav`.
- `assets` is an array containing one entry with `path`, `role=original`, `media_type=audio/wav`, `size` (byte length), `sha256` (lowercase hexadecimal).
- This implementation caps a manifest at 1 MiB, at most 1,000 ZIP entries, 8 GiB per original audio, and 10 GiB total uncompressed size. These limits are implementation safeguards; future standard limits may differ.

### Example manifest (hash shortened **for illustration only**)

```json
{
  "assets": [{"media_type":"audio/wav","path":"audio/original.wav","role":"original","sha256":"<64 lowercase hex digits>","size":44}],
  "format":"org.aural.audio-evidence",
  "original":"audio/original.wav",
  "recorded_at":null,
  "title":"Example",
  "version":"0.1-draft"
}
```

## Future design questions (NOT implemented yet)

- Canonical serialization and normalized time/event models; RFC 8785 candidate.
- Cryptographic signatures (Ed25519 candidate), keys, trust stores, signature revocation, replay protection.
- Hash-linked, append-only *logical* provenance records; ZIP rewrites do not imply lost logical history.
- Source classes: phone capture, external recorder, received evidence, derived audio.
- Structured transcripts, annotations, sensors, baselines, external equipment, team attestations.
- Multiple originals, time alignment, large-file streaming, derivative source graphs.
- Content privacy, redaction and selective disclosure without changing original evidence.
- ZIP parsing threat modeling, decompression budgets, ZIP64 ambiguities, archive library behavior.
- Extension collision review, documentation governance, trademark considerations, licensing and registry strategy.

## Interoperability policy

`.aural` is deliberately not `.evp`: format use must not imply acceptance of an EVP interpretation. The specification is intended to be vendor-neutral, and reference software is licensed permissively. Formal adoption requires independent implementations and published conformance fixtures.
