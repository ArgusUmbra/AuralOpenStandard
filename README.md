# AURAL — Open Audio Evidence Standard

**An open, vendor-neutral format for preserving, exchanging, and independently verifying audio evidence.**

**Status:** Draft 0.2 — experimental open-standard proposal  
**File extension:** `.aural`  
**License:** MIT  
**Reference implementations:** Python and Node.js

AURAL preserves original WAV recordings byte-for-byte inside a strictly specified evidence container. A canonical manifest, cryptographic hashes, and a separate digital-signature system allow third-party tools to independently verify the integrity and consistency of supplied evidence without relying on proprietary software or cloud services.

**AURAL is designed to answer an important question: Can another investigator independently inspect the evidence and determine exactly what has—and has not—been verified?**

AURAL is not limited to paranormal research, although EVP and field investigations motivated its development. The format is intended for any application where preserving original audio and documenting its provenance are important.

Aural Umbra is intended to be the first application built around AURAL, but the standard is independently implementable and does not require Aural Umbra.

> **Important:** AURAL verifies cryptographic integrity and consistency of supplied evidence records. It does not independently establish human identity, recording origin, trusted capture time, historical completeness, or the nature of a recorded phenomenon.

## 1. Evidence container

A Draft 0.2 `.aural` file is a tightly specified ZIP/ZIP64 archive containing exactly two entries:

```text
investigation.aural
├── manifest.json
└── audio/
    └── original.wav
```

**The original WAV is preserved byte-for-byte.** Audio samples, RIFF chunks, and existing WAV metadata are not rewritten during packaging.

The container provides:

- **Original audio preservation:** No transcoding, recompression, or destructive processing.
- **Canonical metadata:** RFC 8785 JSON Canonicalization Scheme (JCS).
- **SHA-256 integrity:** Independently calculated fingerprints of the original audio.
- **Strict archive structure:** Exactly defined entries, ordering, and ZIP metadata requirements.
- **Bounded resource usage:** Validation limits designed to reduce malformed-archive and resource-exhaustion risks.
- **Independent verification:** Compatible tools can validate the package without Aural Umbra or a central server.

Entries use ZIP STORE, without compression.

Draft 0.2 specifies a maximum package size of 8 GiB. Python and Node.js implement the bounded ZIP64 profile, although successful end-to-end verification of a genuine recording larger than 4 GiB remains an outstanding integration test.

### Why not simply use a WAV and detached signature?

A WAV and digital signature can establish that particular bytes were signed.

AURAL additionally defines a common, testable structure for packaging the original audio, representing metadata, validating archive contents, constraining resource usage, and linking signed assertions to specific evidence.

This gives independent developers the same rules for interpreting and validating evidence packages rather than relying on application-specific conventions.

## 2. Cryptographic integrity and signed provenance

AURAL uses established cryptographic primitives rather than inventing new cryptographic algorithms.

**SHA-256** provides content fingerprints that allow tools to detect changes to the original WAV and other referenced data.

**Ed25519** provides digital signatures for structured assertions concerning evidence and its documented history.

Signed assertions use canonical JSON and domain-separated cryptographic constructions defined in the experimental provenance specification.

### The detached-signature design

**Draft 0.2 does not embed digital signatures inside the `.aural` archive.**

Instead, signed provenance records remain detached from the original evidence package:

```text
investigation.aural
signed-event.json
investigator-public-key.json
```

This deliberately keeps the original two-entry container stable and allows additional assertions to be produced without rewriting the original WAV or its archive.

The signed-event profile can reference:

- Evidence and event identifiers.
- The canonical manifest's SHA-256 digest.
- The original WAV's SHA-256 digest.
- The original WAV's path and byte length.
- Event types and supported claims.
- Claimed timestamps.
- References to preceding signed events.

An independent verifier checks the signature, independently validates the evidence package, and compares the signed claims with the actual package contents.

The binding includes the container format and version, manifest digest, original WAV path, WAV digest, and WAV byte length.

**A valid signature establishes that a corresponding private key signed the assertion. It does not, by itself, establish who controlled that key or whether the assertion was truthful.**

## 3. Recording time and provenance

Reliable timestamps are an important part of audio evidence, but there is a difference between preserving a timestamp and independently establishing its accuracy.

AURAL's current signed provenance profile can protect claimed timestamp information against undetected modification.

It does not automatically prove that the device clock was accurate when the recording occurred.

### Planned: externally referenced capture timing

Future integrations, including Aural Umbra, are intended to support stronger timestamp evidence through additional capture-time measurements.

Possible inputs include:

- Device wall-clock timestamps.
- Monotonic clocks linked to the audio capture timeline.
- GNSS-derived time references where available.
- Clock offsets, uncertainty estimates, and synchronization status.
- Recording-clock discontinuities and measurement gaps.
- Corroboration from independently synchronized devices.

GNSS can provide an independent timing reference relative to a device's ordinary system clock. However, a GNSS-derived timestamp is not automatically a cryptographic proof of capture time.

A verifier must distinguish between:

**Claimed time:** A timestamp reported by a device or investigator.

**GNSS-referenced time:** A timestamp accompanied by documented GNSS timing observations and uncertainty measurements.

**Externally attested time:** A timestamp supported by an additional trusted or independently verifiable timing source.

These categories describe different evidentiary strengths; they are not interchangeable guarantees.

**GNSS time-reference collection, assurance classification, and externally attested capture timing are planned capabilities, not implemented guarantees of the current Draft 0.2 container or signed-event verifier.**

GNSS availability will not be a requirement for creating, reading, or verifying an AURAL evidence package.

## 4. Independent verification

AURAL provides Python and Node.js implementations for independently validating supported evidence structures.

Current implemented capabilities include:

- Draft 0.2 archive integrity verification.
- Exact original WAV preservation checks.
- SHA-256 digest validation.
- Canonical manifest validation.
- Classic ZIP and bounded ZIP64 validation.
- Experimental Ed25519 signed-event verification.
- Evidence-to-signed-assertion binding.
- Controlled malformed-input rejection.
- Resource-limited file handling and archive inspection.

The implementations have been tested using shared conformance fixtures, positive and negative examples, and adversarial Ed25519 test vectors.

The signed-event graph verifier remains under development. Current individual-event verification must not be confused with verification of a complete investigation history.

### What verification establishes

| Question | Current AURAL capability |
|---|---|
| Does this WAV match its recorded SHA-256 fingerprint? | Yes |
| Does the signed assertion verify against the supplied public key? | Yes |
| Does the signed evidence description match the supplied AURAL package? | Yes, when package binding is performed |
| Is the public key independently associated with the claimed investigator? | Not established automatically |
| Was the recording created at the claimed date and time? | Not established automatically |
| Has the complete custody history been supplied? | Not established |
| Does the recording represent a paranormal or anomalous event? | Not determined by cryptographic verification |

A successful integrity check does not establish that evidence was genuine when first captured. Independent capture records, device assurance, trusted time references, and corroborating evidence can strengthen those conclusions.

## 5. Quick start

### Requirements

- Python 3.10+ for the reference Python implementation.
- No third-party Python dependencies for basic container packaging, verification, or extraction.
- Python `cryptography` package for experimental signed provenance verification.
- Node.js for the independent JavaScript verifiers.

### Create an AURAL package

```bash
python -m aural pack "recording.wav" "investigation.aural" --title "Field session"
```

### Verify an AURAL package

```bash
python -m aural verify "investigation.aural"
```

### Extract the original WAV

```bash
python -m aural extract "investigation.aural" "recovered.wav"
```

The extracted WAV preserves the original bytes.

### Run the test suite

```bash
python -W error -m unittest discover -s tests -v
```

### Verify independently with Node.js

```bash
node interop/validate_aural.mjs tests/fixtures/conformance/valid-minimal.aural
```

### Verify an experimental signed event

```bash
node interop/validate_provenance.mjs tests/fixtures/provenance/valid-original-acquired.json tests/fixtures/provenance/valid-key.json tests/fixtures/conformance/valid-unicode.aural
```

All bundled examples and conformance fixtures are synthetic test material, not real investigation evidence.

## 6. Documentation

### Container format

- [Draft 0.2 specification](docs/SPECIFICATION-0.2-DRAFT.md)
- [Conformance fixtures and validation](docs/CONFORMANCE.md)
- [Interoperability and implementation guidance](docs/INTEROPERABILITY.md)

Draft 0.1 remains documented and readable through its separate legacy verification path.

### Cryptographic provenance

- [Experimental signed-event specification](docs/PROVENANCE-SIGNATURE-1-DRAFT.md)
- [Provenance conformance vectors](docs/PROVENANCE-CONFORMANCE.md)

The provenance profile is experimental and remains independently versioned from Draft 0.2.

## 7. Development status

| Component | Status |
|---|---|
| Draft 0.2 evidence container | Implemented |
| Byte-preserving WAV packaging | Implemented |
| Canonical JSON manifest and SHA-256 integrity | Implemented |
| Independent Python/Node verification | Implemented |
| Bounded ZIP64 verification | Implemented; large-file integration testing pending |
| Detached Ed25519 signed-event verification | Experimental implementation |
| Signed assertion-to-evidence binding | Experimental implementation |
| Signed-event graph indexing and duplicate detection | Initial implementation |
| Complete signed-event graph verification | In development |
| Device and investigator identity assurance | Future work |
| GNSS-referenced timestamp provenance | Planned |
| Independent timing attestations | Planned |
| Chain-of-custody and team attestations | Planned |
| Portable signed evidence bundle | Planned |
| Aural Umbra application integration | Separate development |
| AURAL Research Network | Future project |

Implemented components remain subject to testing, security review, and specification evolution. AURAL is not yet a formally ratified or production-certified standard.

## 8. Relationship to Aural Umbra

AURAL and Aural Umbra are related but independent.

**Aural Umbra** is an Android application being developed to capture recordings and investigation context, including environmental measurements, operator notes, timestamps, and supporting provenance information.

**AURAL** is the proposed open evidence standard through which compatible applications can preserve and exchange independently inspectable evidence.

**The future AURAL Research Network** is envisioned as a research environment for indexing, searching, comparing, and examining evidence across investigations.

Applications other than Aural Umbra may implement AURAL without seeking permission or relying on a hosted AURAL service, subject to the repository license and evolving specification requirements.

Core evidence packaging and verification are designed to operate offline.

## 9. Design principles

1. **Preserve the original.** Original recorded audio must remain unchanged.
2. **Make verification independent.** Evidence should not require proprietary software or cloud services.
3. **Expose uncertainty.** Cryptographic integrity, time assurance, identity, and historical authenticity must remain distinguishable.
4. **Use established cryptography.** Prefer independently reviewable algorithms and explicit verification profiles.
5. **Maintain interoperability.** Support independently developed readers, writers, and conformance tests.
6. **Keep the format open.** Third parties should be able to implement compatible tools.
7. **Support future evidence types.** Extend functionality through explicit versioning without silently changing existing contracts.
8. **Preserve researcher independence.** No mandatory accounts, subscriptions, or central infrastructure for core verification.

## 10. License and governance

The implementation and repository text are available under the MIT License. See [LICENSE](LICENSE).

A dedicated specification license and governance charter may be considered as the proposal matures.

Contributions, independent implementations, interoperability testing, and technical review are welcome.

---

**AURAL is an experimental open-standard proposal, not a released or formally ratified industry standard.**

*Preserve the original. Authenticate the assertions. Verify the history. Expose the uncertainty.*
