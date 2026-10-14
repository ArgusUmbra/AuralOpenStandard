# AURAL - Open Audio Evidence Standard

**An open, vendor-neutral format for preserving, exchanging, and independently verifying audio evidence.**

**Status:** Draft 0.2 experimental proposal  
**File extension:** `.aural`  
**License:** MIT  
**Implementation:** Python and Node.js reference verification tools

AURAL is designed to help investigators preserve original recordings, document their processing and provenance, and exchange audio evidence without depending on a particular application, commercial service, or research platform.

Aural Umbra is intended to be the first application built around AURAL, but the format is independently implementable and does not require Aural Umbra.

**AURAL verifies cryptographic integrity and consistency of supplied evidence records. It does not determine whether a recording is authentic, paranormal, or scientifically significant.**

## How AURAL works

A Draft 0.2 `.aural` file is a tightly specified ZIP/ZIP64 container with two entries:

```text
investigation.aural
├── manifest.json
└── audio/
    └── original.wav
```

- **Original WAV preservation:** Audio is stored byte-for-byte, without transcoding or modifying RIFF chunks.
- **Canonical manifest:** Metadata follows RFC 8785 JSON Canonicalization Scheme (JCS).
- **SHA-256 integrity:** Verification independently checks the original audio against the manifest.
- **Strict archive validation:** Bounded ZIP/ZIP64 structure, entry ordering, and resource limits.
- **Interoperability:** The format is documented for third-party implementations.

ZIP entries use STORE (no compression). Draft 0.2 supports a bounded 8 GiB package profile.

## Cryptographic provenance

AURAL also provides an experimental, detached signed-event profile using:

- Ed25519 digital signatures.
- RFC 8785 canonical signed assertions.
- Domain-separated SHA-256 identifiers.
- Content-derived signing-key identifiers.
- Signed references to the original manifest and audio.
- Structured verification results with explicit trust limitations.

Provenance records remain separate from the Draft 0.2 archive.

```text
investigation.aural
signed-event.json
investigator-public-key.json
```

The verifier can independently validate a signed assertion and compare its claims against the actual AURAL package.

These checks include the container format and version, canonical manifest digest, original WAV path, WAV digest, and WAV byte length.

A valid signature does not independently establish the human identity of the signer, trusted capture time, or completeness of the investigation history.

## Independent verification

AURAL includes separate Python and Node.js verifier implementations.

Both have been tested against shared conformance fixtures, signed-event vectors, and adversarial cryptographic cases.

Supported verification capabilities include:

- Archive structure and integrity validation.
- Classic ZIP and bounded ZIP64 support.
- Ed25519 signed-event verification.
- Original audio and manifest binding.
- Controlled malformed-input rejection.
- Bounded resource handling.
- Explicit reporting of unestablished trust properties.

**Large-file qualification:** ZIP64 structural interoperability has been tested, but successful end-to-end verification of a genuine recording larger than 4 GiB remains a pending integration test.

## Quick start

### Requirements

- Python 3.10+ for the Python reference implementation.
- No third-party Python dependencies for basic container pack, verify, or extract operations.
- The `cryptography` Python package for experimental signed provenance verification.
- Node.js for the independent JavaScript verifier.

### Create an AURAL package

```bash
python -m aural pack "recording.wav" "investigation.aural" --title "Field session"
```

### Verify a package

```bash
python -m aural verify "investigation.aural"
```

### Extract the unchanged original WAV

```bash
python -m aural extract "investigation.aural" "recovered.wav"
```

### Run conformance and regression tests

```bash
python -W error -m unittest discover -s tests -v
```

### Independent Node.js verification

```bash
node interop/validate_aural.mjs tests/fixtures/conformance/valid-minimal.aural
```

### Experimental signed-event verification

```bash
node interop/validate_provenance.mjs tests/fixtures/provenance/valid-original-acquired.json tests/fixtures/provenance/valid-key.json tests/fixtures/conformance/valid-unicode.aural
```

All example evidence and conformance fixtures are synthetic and must not be represented as real investigation evidence.

## Documentation

**Container standard**

- [Draft 0.2 specification](docs/SPECIFICATION-0.2-DRAFT.md)
- [Conformance tests](docs/CONFORMANCE.md)
- [Interoperability and porting guidance](docs/INTEROPERABILITY.md)

**Cryptographic provenance**

- [Experimental signed-event specification](docs/PROVENANCE-SIGNATURE-1-DRAFT.md)
- [Provenance conformance vectors](docs/PROVENANCE-CONFORMANCE.md)

Draft 0.1 remains documented and supported through a distinct legacy verification path.

## Development status

| Component | Status |
|---|---|
| Draft 0.2 evidence container | Implemented |
| Byte-preserving original WAV packaging | Implemented |
| SHA-256 integrity validation | Implemented |
| Independent Python/Node verification | Implemented |
| Bounded ZIP64 validation | Implemented |
| Detached Ed25519 signed-event verification | Experimental implementation |
| Signed evidence-to-package binding | Experimental implementation |
| Signed-event graph verification | In development |
| Chain-of-custody and team attestations | Planned |
| Portable all-in-one signed evidence bundle | Planned |
| Aural Umbra application integration | Separate application work |
| AURAL Research Network integration | Future work |

Implemented components are not necessarily production-hardened or formally standardized. See the specifications and conformance documentation for supported guarantees and limitations.

## Design principles

1. **Preserve the original.** Never rewrite original recorded audio during evidence packaging.
2. **Make verification independent.** Evidence must not require one company's application or server.
3. **Expose uncertainty.** Cryptographic validity and historical authenticity are different claims.
4. **Keep the format open.** Third-party developers should be able to implement compatible readers and writers.
5. **Support offline investigation.** Core evidence verification must not require cloud infrastructure.
6. **Maintain portability.** Evidence should remain inspectable as applications and platforms change.

## License

The implementation and repository text are available under the MIT License. See [LICENSE](LICENSE).

A dedicated standards-governance charter and specification licensing arrangement may be considered as the proposal matures.

AURAL is an experimental open-standard proposal, not an approved or formally ratified industry standard.
