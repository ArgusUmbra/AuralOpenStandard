# AURAL Draft 0.2 design decisions

## Status

This record explains the architecture of the proposed Draft 0.2. It is informative; `SPECIFICATION-0.2-DRAFT.md` is normative where it uses normative language.

## Standards basis reviewed

The design was checked against the RFC Editor publications for RFC 8259 (JSON), RFC 7493 (I-JSON), RFC 8785 (JCS), its two verified errata including the negative-zero guidance, and RFC 3339 timestamps; PKWARE APPNOTE 6.3.10 (final, 2022-11-01) for ZIP and ZIP64 records; and the current IANA media-type registry. The IANA registry does not list `audio/wav` or `audio/vnd.wave`. No ISO ZIP or WAVE specification text was locally available, so this draft does not claim to have reviewed those sources.

## D-001: the specification, not Python, is authoritative

Draft 0.1 mixed a useful prototype profile with behaviors inherited from Python's `json` and `zipfile` modules. Draft 0.2 defines bytes and rejection rules independently. Reference-code behavior that is not stated in the specification is not a format requirement.

## D-002: use RFC 8785 JCS with a safe-integer JSON subset

The manifest is exactly an RFC 8785 JSON Canonicalization Scheme serialization, without a trailing line ending. Draft 0.2 additionally permits only integer JSON numbers in the inclusive I-JSON safe range `[-9007199254740991, 9007199254740991]`. This is a schema/profile constraint, not a new canonicalization algorithm.

This avoids falsely treating Python `json.dumps(sort_keys=True)` as JCS. Python key order differs from JCS for some supplementary-plane property names, and Python does not implement the ECMAScript number-to-string algorithm required by JCS. Floating-point values were rejected rather than defining a second number algorithm. Decimal measurements can be carried in later extensions as strings with explicit semantics.

Rejected alternatives were the Draft 0.1 sorted-key dialect, unrestricted IEEE-754 numbers, and importing a dependency solely for numbers that the core manifest does not need.

## D-003: one original WAVE asset

Draft 0.2 remains a minimal evidence-preservation container: exactly one `RIFF` WAVE or `RF64` WAVE asset at `audio/original.wav`. The signature check is identification, not full WAVE validation. Full provenance, signatures, sensor records, transcripts, derivatives, and multiple originals remain out of scope.

The `audio/wav` value is retained for deployed compatibility, but it is not currently an IANA-registered audio media type. Registration or a different standards-track identifier needs external review before a stable release.

## D-004: narrow stored-only ZIP profile

Stored method 0 makes size budgeting and byte preservation easy to audit and removes decompression-bomb behavior. Fixed ASCII paths eliminate filename-normalization and legacy-encoding ambiguity. Data descriptors, encryption, comments, non-ZIP64 extra fields, split archives, prefixes, trailers, gaps, and special files are prohibited.

ZIP64 is retained because the normative maximum original is 8 GiB. Readers accept structurally necessary ZIP64 only; writers use it only when a corresponding classic field cannot represent its value. ZIP metadata such as timestamps and creator platform is not evidence metadata.

## D-005: logical canonicality is not deterministic ZIP output

The manifest and original payload have canonical identities. The enclosing ZIP byte stream does not: legal creator fields, permission bits, entry order, and timestamps can differ. ZIP64 use is determined by classic-field capacity and is not an independent writer choice. Two conformant packages can therefore have different whole-file SHA-256 values while representing the same logical package.

Reference writers use stable timestamps and entry order as a reproducibility aid. Readers do not depend on those choices.

## D-006: closed core, explicitly namespaced extensions

Unknown members in the core manifest or asset descriptor are rejected. Future data belongs in `extensions`, keyed by a bounded URI-form ASCII identifier controlled by its defining organization. Unknown optional extensions are accepted and ignored semantically. Every name in `critical_extensions` must exist in `extensions`; an unsupported critical extension causes rejection.

This avoids accidental reinterpretation while preserving an evolution path. No extension semantics are standardized in Draft 0.2.

## D-007: pre-1.0 drafts are exact, incompatible versions

`0.1-draft` and `0.2-draft` are not aliases. A reader may expose a separate legacy path, but it must report the actual version. A writer conforming to Draft 0.2 emits only `0.2-draft`.

Draft 0.1 manifests end in LF and use a different closed schema. Relabeling one as Draft 0.2 would change its meaning and is prohibited. Migration means verifying the old package, preserving the original bytes, and creating a new Draft 0.2 package with an explicitly recorded external migration process.

## D-008: timestamps are source-declared metadata

`recorded_at` is optional and uses a deliberately strict RFC 3339 profile: an explicit offset, uppercase `T` and `Z`, seconds, no leap second, no unknown `-00:00` offset, and at most nine fractional digits. UTC is recommended. The value is not authenticated and must not be treated as trusted capture time.

## D-009: hard limits are normative

The manifest is at most 1 MiB and 32 containers deep; the original is at most 8 GiB; the physical archive is at most 8 GiB plus 16 MiB; the central directory is at most 4 MiB; and Draft 0.2 has exactly two entries. These bounds permit deterministic resource policy across implementations.

## D-010: independent validation must inspect raw ZIP records

High-level ZIP APIs commonly hide duplicate entries, local/central disagreements, filename byte encodings, prefixes, and trailers. A conformant verifier must preflight raw structures before trusting library abstractions. The Node validator intentionally parses records independently of Python's `zipfile` implementation.

## D-011: legacy tolerance follows version dispatch

Version-independent preflight rejects unsafe sizes, offsets, malformed extra-field framing, duplicate ZIP64 fields, and truncated required ZIP64 values. Draft 0.2 then applies its stricter rule that a ZIP64 extra field is present only when a corresponding sentinel requires it.

Draft 0.1 did not prohibit a well-framed unnecessary ZIP64 extra field, and the Assignment 002 verifier at commit `6abee8b` accepted it. The compatibility path retains that bounded behavior without relaxing Draft 0.2. Malformed extra-field framing, duplicate ZIP64 fields, missing required values, and oversized required ZIP64 data remain rejected for both versions.

## D-012: ZIP64 is strictly necessity-based in Draft 0.2

Draft 0.2 requires an archive-level ZIP64 EOCD record and locator if any corresponding classic EOCD field uses its ZIP64 sentinel, and prohibits both records otherwise. Local and central ZIP64 extra fields follow the same necessity rule independently: every sentinel-required value is present in APPNOTE order, no non-required value or trailing byte is present, and the extra field is absent when that header has no corresponding sentinel.

The earlier wording required the archive-level chain when a sentinel appeared but did not state the converse as a direct `MUST NOT`. That allowed readers to disagree about a redundant but internally consistent ZIP64 chain. The strict rule removes that interoperability ambiguity, minimizes equivalent structural encodings, and aligns archive-level behavior with the already explicit per-entry rule. This is a behavioral clarification: readers that accepted unnecessary ZIP64 end records must change, while conforming classic archives and necessity-driven ZIP64 archives are unchanged.
