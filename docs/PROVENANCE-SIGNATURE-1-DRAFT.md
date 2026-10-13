# AURAL Experimental Provenance Signature Profile 1

**Status:** experimental development draft; not an adopted, registered, or finalized standard
**Event schema:** `org.aural.provenance-event`, version `1`
**Signature profile:** `org.aural.signature.ed25519-jcs-v1`
**Initial event type:** `urn:aural:event:original-asset-acquired:1`

## 1. Conformance and scope

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described by BCP 14 when, and only when, they appear in all capitals.

This document defines one detached, single-signature JSON event format. It defines exact bytes for Ed25519 signing, public-key identification, signed-event hashing, and binding an event to an AURAL Draft 0.2 package. It does not modify the AURAL Draft 0.2 container. In particular, a writer MUST NOT add an event or key record to a Draft 0.2 ZIP archive, whose membership remains exactly as defined by [`SPECIFICATION-0.2-DRAFT.md`](SPECIFICATION-0.2-DRAFT.md).

This profile does not define a complete provenance system, graph traversal, trust store, investigator identity proof, key revocation, key rotation, trusted timestamp, transparency service, or a new container version. It does not define RSA, ECDSA, P-256, Ed25519ctx, Ed25519ph, or generic algorithm negotiation.

Normative references are [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174), [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259), [RFC 7493](https://www.rfc-editor.org/rfc/rfc7493), [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648), [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339), [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), and [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562).

## 2. Security model and terminology

An *assertion* is the JSON object whose canonical bytes are signed. A *signed-event record* is the outer object containing exactly that assertion and its signature. A *public-key record* supplies verification material. A *subject package* is the separate AURAL Draft 0.2 package to which an assertion refers.

A conforming signature verification establishes only that the holder of the private key corresponding to the identified public key signed the exact assertion. It does not establish who controlled that key, whether a display name is accurate, when the signature was made, whether the acquisition claim is true, whether the claimed source was authentic, or whether omitted earlier history exists.

A verifier MUST keep these conclusions separate:

1. record syntax and canonicality;
2. cryptographic signature validity;
3. subject-package integrity and binding;
4. key-to-person or key-to-organization identity;
5. key trust, authorization, and revocation status;
6. time assurance; and
7. graph/history completeness.

A successful result under this document can establish items 1–3. Items 4–7 require evidence or policy outside this profile. A verifier MUST NOT describe a signature from a self-declared key as authenticated investigator identity.

## 3. Signed-event envelope

The signed-event record MUST be one JSON object containing exactly these members:

| Member | Type | Requirement |
|---|---|---|
| `assertion` | object | assertion from §4 |
| `signature` | string | canonical unpadded base64url encoding of the 64-byte Ed25519 signature |

No other envelope member is permitted. The signature value is necessarily outside the assertion; every field selecting or affecting its meaning, including schema, profile, key identifier, event type, subject, claims, parent references, and extensions, MUST be inside the assertion.

The initial profile has exactly one assertion and one signature. A reader MUST NOT infer multisignature behavior from arrays, repeated members, extension data, or additional envelope members.

An illustrative envelope is shown below. Whitespace is for display only and the values are abbreviated, so this is not a conformance vector.

```json
{
  "assertion": {
    "event_schema": "org.aural.provenance-event",
    "event_schema_version": "1",
    "signature_profile": "org.aural.signature.ed25519-jcs-v1",
    "event_id": "urn:uuid:...",
    "event_type": "urn:aural:event:original-asset-acquired:1",
    "evidence_id": "urn:uuid:...",
    "signing_key_id": "urn:aural:key:ed25519:...",
    "subject": {},
    "parents": [],
    "claims": {}
  },
  "signature": "..."
}
```

## 4. Assertion data model

### 4.1 Core members

The assertion MUST contain exactly the following required core members and MAY contain only the two optional members listed here:

| Member | Required | Type and value |
|---|---:|---|
| `event_schema` | yes | string exactly `org.aural.provenance-event` |
| `event_schema_version` | yes | string exactly `1` |
| `signature_profile` | yes | string exactly `org.aural.signature.ed25519-jcs-v1` |
| `event_id` | yes | lowercase UUIDv4 URN from §4.2 |
| `event_type` | yes | string exactly `urn:aural:event:original-asset-acquired:1` in this profile |
| `evidence_id` | yes | lowercase UUIDv4 URN from §4.2 |
| `signing_key_id` | yes | key identifier from §8 |
| `subject` | yes | object from §10 |
| `parents` | yes | array of zero to 4,096 references from §9 |
| `claims` | yes | object from §11 |
| `extensions` | no | object from §13 |
| `critical_extensions` | no | array from §13 |

An unknown member outside the extension mechanism MUST cause rejection. JSON `null` is not a substitute for an absent optional member.

### 4.2 Event and evidence identifiers

`event_id` and `evidence_id` MUST use this exact lowercase ASCII form:

```text
urn:uuid:xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
```

Each `x` is a lowercase hexadecimal digit and `y` is one of `8`, `9`, `a`, or `b`. The underlying value MUST be a UUIDv4 generated with a cryptographically secure random source in accordance with RFC 9562. Fixed identifiers in conformance fixtures are exempt from the randomness requirement.

`event_id` identifies one signed event. `evidence_id` is a logical label intended to relate events concerning the same evidence. Neither identifier is a content digest. `evidence_id` MUST NOT replace the manifest or original-asset digests.

## 5. JSON input profile and resource limits

### 5.1 Exact encoding

A signed-event record and a public-key record MUST each be a single RFC 8259 JSON object encoded as strict UTF-8 without a byte-order mark. No whitespace, line ending, NUL, or other byte may precede or follow the canonical object.

Parsing and the data model MUST obey all of these rules at every depth:

1. Object member names MUST be unique after JSON escape processing.
2. Names and string values MUST contain only Unicode scalar values and MUST NOT contain Unicode noncharacters.
3. Invalid UTF-8 and unpaired UTF-16 surrogates, including escaped surrogates, MUST be rejected.
4. Unicode normalization MUST NOT be performed. Canonically equivalent Unicode strings remain byte-distinct values.
5. A JSON number MUST be an integer token in the inclusive range `-9007199254740991` through `9007199254740991`.
6. Fractional notation, exponent notation, negative zero, NaN, and infinities MUST be rejected.
7. A field defined by a future extension as an integer outside the safe range MUST be represented as a string. A non-negative decimal counter string MUST match `0|[1-9][0-9]*`; a signed decimal string, if an extension explicitly permits one, MUST match `0|-?[1-9][0-9]*`. The extension MUST define its bounds. No current core field uses a large decimal string.

### 5.2 Depth

Maximum JSON container depth is 32. A root object has depth 1. Each object or array directly contained in another object or array has its containing depth plus one. A scalar does not create another depth level. The limit is evaluated on the complete signed-event record, including extension values. It is evaluated independently on each public-key record.

For example, the outer record object is depth 1, its `assertion` object is depth 2, `subject` is depth 3, and `subject.original` is depth 4.

### 5.3 Size and counts

A verifier MUST apply these bounds before allocation or processing based on attacker-controlled values:

| Resource | Maximum |
|---|---:|
| complete signed-event record bytes | 1,048,576 bytes |
| one public-key record | 16,384 bytes |
| supplied public-key records | 64 |
| aggregate supplied public-key record bytes | 262,144 bytes |
| JSON container depth | 32 |
| parent references | 4,096 |
| extension identifier | 255 ASCII bytes |
| `source_description` | 4,096 Unicode scalar values |
| `acquisition_environment` | 4,096 Unicode scalar values |
| claimed-time entries | 3 |

The 1 MiB limit covers the complete supplied signed-event record, including the assertion, signature text, member names, and punctuation. Because the assertion is contained within that record, it has no additional independent 1 MiB allowance. Implementations MAY impose lower local limits only if they do not claim general conformance.

A file-oriented verifier MUST open a stable file handle before inspection, require a regular file, inspect its physical size through that handle, and reject a size above the applicable limit before allocating a file-sized buffer or reading content. It MUST read through that same handle with bounded I/O. It MUST treat truncation, a short read before the inspected size, or a detectable change in file identity, size, modification time, or change time during the read as a controlled input failure. It MUST NOT begin unbounded parallel reads of caller-supplied event or key paths. Key-record count and aggregate-size limits MUST be checked before an allocation would exceed them.

## 6. Canonical encoding

The canonical encoding function in this document is RFC 8785 JCS applied after validation of §5's narrower JSON profile.

For both the assertion and the complete signed-event record:

- object names are ordered by UTF-16 code units as required by JCS;
- no insignificant whitespace is emitted;
- strings use the JCS/ECMAScript escaping rules;
- no trailing newline is emitted; and
- no Unicode normalization is performed.

`JCS(assertion)` means the UTF-8 bytes of the JCS serialization of the parsed assertion object, considered as its own root value for serialization. Depth conformance is nevertheless evaluated in the complete record as specified in §5.2.

A verifier MUST independently reproduce or validate the canonical signed-event serialization and MUST compare it byte-for-byte with the complete supplied record bytes before reporting success. Canonicalizing only the assertion is insufficient. Ordinary key sorting or a language's default `json.dumps`, `JSON.stringify`, map iteration, or equivalent is not by itself an implementation of RFC 8785.

The public-key record also MUST be byte-for-byte equal to its JCS serialization.

## 7. Signature construction

### 7.1 Domain and input

The domain separator is the following 25 ASCII bytes:

```text
AURAL-PROVENANCE-EVENT-V1
```

The signature input is exactly:

```text
ASCII("AURAL-PROVENANCE-EVENT-V1") || 0x00 || JCS(assertion)
```

The NUL separator is one octet with value zero. It is not JSON text and is not base64 encoded. The domain label and separator are fixed by this profile, so their framing is unambiguous. A future signature profile MUST use a different profile identifier and domain separator.

### 7.2 Algorithm and encodings

The signature algorithm is pure Ed25519 as specified by RFC 8032. Ed25519ph and Ed25519ctx MUST NOT be used. A signer MUST pass the complete signature input from §7.1 as the Ed25519 message; it MUST NOT prehash that input at the application layer.

The public key is the 32-byte RFC 8032 compressed Edwards-curve point encoding `A`. The signature is the 64-byte RFC 8032 `R || S` encoding. The following acceptance policy is normative and resolves the latitude in RFC 8032 Section 5.1.7:

1. `A` and `R` MUST each be exactly 32 bytes and MUST decode to an Edwards25519 curve point under RFC 8032 Section 5.1.3. The encoded `y` coordinate MUST be less than `p = 2^255 - 19`. An encoding with the sign bit set when the recovered `x` is zero MUST be rejected. Thus each accepted encoding is canonical and round-trips to the identical bytes.
2. `A` and `R` MUST NOT have order dividing the cofactor 8. Equivalently, `[8]A` and `[8]R` MUST each differ from the identity point. Identity points and every other order-2, order-4, or order-8 point are rejected.
3. `S` is interpreted as an unsigned 32-byte little-endian integer and MUST satisfy `0 <= S < L`, where `L = 2^252 + 27742317777372353535851937790883648493`.
4. Let `M` be the exact signature input from Section 7.1 and let `k = SHA-512(R_encoded || A_encoded || M) mod L`, with the digest interpreted as an unsigned little-endian integer before reduction. Verification MUST require the uncofactored equation `[S]B = R + [k]A`. The RFC 8032 cofactored equation `[8][S]B = [8]R + [8][k]A` MUST NOT be used as the acceptance test.

This policy rejects the trivial identity-key/identity-`R`/zero-`S` forgery and fixes one acceptance set for individual verification. ZIP-215 and other cofactored or noncanonical policies are incompatible with this signature profile.

Standard Ed25519 key generation produces `A` in the prime-order subgroup and standard signing produces `R` in that subgroup. This verifier profile does not require a separate full-prime-order membership test for a non-small-order `A` or `R`; a point with a nonzero torsion component is therefore a mixed-order point and is permitted only if it is canonical, is not small order, and satisfies the exact uncofactored equation above. This is an intentional interoperability choice: commonly available one-shot Ed25519 verification APIs do not expose full subgroup validation. A future profile MAY require full public-key validation as defined by NIST SP 800-186, but it would be a distinct acceptance policy and signature-profile revision.

An implementation MUST NOT infer that its cryptographic provider enforces these rules merely because the provider labels an operation `Ed25519`. It MUST apply the canonical-encoding, small-order, and scalar checks itself or use a provider API whose behavior for each check has been demonstrated. It MUST also demonstrate the provider's uncofactored behavior with the adversarial vectors in `tests/fixtures/provenance/ed25519-adversarial.json`.

The signature string is RFC 4648 base64url without `=` padding. It therefore has exactly 86 ASCII characters. Decoders MUST reject whitespace, standard-base64 `+` or `/`, padding, invalid pad bits, non-alphabet characters, a decoded length other than 64, or any spelling that does not round-trip to the identical unpadded base64url string.

Where a conformance tool accepts raw private material, a 32-byte value means the Ed25519 private seed `k` from RFC 8032, not an expanded scalar, a concatenated private/public form, PKCS #8, or a platform keystore handle. Private-key representation is not part of the event wire format. Public conformance records and public-key records MUST NOT contain private-key material.

### 7.3 Profile dispatch

A verifier MUST compare `signature_profile` as an exact case-sensitive string before using the profile. An unknown or altered signature profile MUST fail closed. A verifier MUST NOT choose an algorithm from key length, signature length, a key-record hint, or an extension.

## 8. Public keys and key identifiers

### 8.1 Key identifier

For the raw 32-byte Ed25519 public key, calculate:

```text
key_material =
    ASCII("AURAL-KEY-ID-V1")
    || 0x00
    || ASCII("Ed25519")
    || 0x00
    || raw_32_byte_public_key

fingerprint = SHA-256(key_material)

key_id =
    "urn:aural:key:ed25519:"
    || lowercase_hex(fingerprint)
```

`Ed25519` is case-sensitive and contains exactly the seven displayed ASCII bytes. `lowercase_hex` emits exactly 64 lowercase ASCII hexadecimal characters. The framing separates this identifier from keys used by other protocols or future AURAL algorithms.

### 8.2 Public-key record

A public-key record MUST contain exactly these required members and MAY contain only the extension members shown:

| Member | Required | Type and value |
|---|---:|---|
| `key_schema` | yes | string exactly `org.aural.signing-key` |
| `key_schema_version` | yes | string exactly `1` |
| `algorithm` | yes | string exactly `Ed25519` |
| `key_id` | yes | computed identifier from §8.1 |
| `public_key` | yes | canonical unpadded base64url for exactly 32 bytes; exactly 43 characters |
| `extensions` | no | object from §13 |
| `critical_extensions` | no | array from §13 |

The public-key record MUST satisfy §§5–6. A verifier MUST decode `public_key`, apply the canonical and non-small-order `A` requirements from §7.2, recompute `key_id`, and require exact equality. A malformed record, unsupported schema version or algorithm, invalid public-key encoding, small-order key, or mismatched identifier MUST be rejected.

A verifier obtains public-key records from a caller-supplied detached file, an evidence bundle outside the Draft 0.2 ZIP, or a local/offline key collection. No online key server is required. Every record selected as input to a verification operation MUST pass the public-key-record profile. Exactly one supplied record MUST match `assertion.signing_key_id`. A missing match MUST fail signature validation. Duplicate supplied records with the same `key_id`, even byte-identical records, MUST be rejected as ambiguous input. Unrelated valid records with distinct key IDs MAY be ignored after validation.

A key record is key material, not an identity certificate. Names, account identifiers, or device labels from outside this core schema remain unauthenticated unless a separate trust mechanism binds them to the key. Private keys MUST NOT appear in a public-key record, signed-event record, or distributed evidence package.

## 9. Signed-event digests and parent references

### 9.1 Complete-record digest

After the supplied record has passed exact canonicality, its signed-event digest is:

```text
record_bytes = JCS({"assertion": assertion, "signature": canonical_base64url_signature})

signed_event_digest = SHA-256(
    ASCII("AURAL-SIGNED-EVENT-V1")
    || 0x00
    || record_bytes
)
```

`record_bytes` MUST equal the complete supplied record bytes. The digest is conventionally rendered as 64 lowercase hexadecimal characters. It identifies the assertion/signature pair, not merely the assertion and not a physical ZIP archive.

### 9.2 Parent reference format

Each `parents` element MUST contain exactly:

```json
{
  "event_id": "urn:uuid:...",
  "signed_event_digest": {
    "algorithm": "sha-256",
    "value": "64-lowercase-hexadecimal-characters"
  }
}
```

The parent `event_id` follows §4.2. The algorithm token is exactly `sha-256`. The value is the 32-byte digest from §9.1 rendered as exactly 64 lowercase hexadecimal characters. An unknown algorithm or invalid digest length/encoding MUST cause rejection.

Parent elements MUST be ordered by ascending ASCII comparison of `event_id`. Parent event identifiers MUST be unique. An event MUST NOT name its own `event_id` as a parent. Two parent references with the same event ID are duplicates even if their digest values differ.

A zero-parent event is a genesis event. An `original-asset-acquired` event MAY be a genesis event, including when no earlier signed history is available. When a received or imported asset has a known earlier conforming signed event, the writer SHOULD reference it as a parent. A parent does not by itself prove that the parent concerns the same bytes or evidence; a future graph validator must check those relationships. The representation is defined now so later event types can form a DAG without changing signed bytes or digest construction.

Graph ingestion rules for a future graph-aware implementation are:

- the same `event_id` associated with different signed-event digests is an event-ID collision and MUST fail graph validation;
- receiving the identical canonical record more than once MAY be treated as idempotent ingestion, not a second node;
- a present parent record MUST have both the referenced event ID and digest;
- a missing parent does not invalidate the child record's signature, but history MUST be reported as incomplete and full graph validation MUST NOT succeed; and
- cycles, reachability, graph policy, and traversal are outside this assignment.

## 10. AURAL Draft 0.2 subject binding

`subject` MUST contain exactly:

```json
{
  "format": "org.aural.audio-evidence",
  "version": "0.2-draft",
  "manifest_sha256": "64-lowercase-hexadecimal-characters",
  "original": {
    "path": "audio/original.wav",
    "sha256": "64-lowercase-hexadecimal-characters",
    "byte_length": 52
  }
}
```

The displayed byte length is illustrative. Requirements are:

| Field | Requirement |
|---|---|
| `format` | exactly `org.aural.audio-evidence` |
| `version` | exactly `0.2-draft` |
| `manifest_sha256` | SHA-256 of the exact canonical `manifest.json` entry bytes, as lowercase hexadecimal |
| `original.path` | exactly `audio/original.wav` |
| `original.sha256` | SHA-256 of the complete original WAV bytes, as lowercase hexadecimal |
| `original.byte_length` | safe non-negative JSON integer, at most 8,589,934,592, equal to the complete original length |

The assertion's `evidence_id` is the logical evidence identifier bound to this subject by the signature. It is not repeated inside `subject`.

Identity layers are deliberately distinct. The original asset is identified by its path, byte length, and SHA-256. The manifest is identified by `manifest_sha256`. The logical Draft 0.2 package identity for this profile is the tuple (`format`, `version`, `manifest_sha256`); it is not a hash of ZIP bytes. The event label is `event_id`, while the immutable assertion/signature pair is identified by the signed-event digest. `evidence_id` groups related claims and is not interchangeable with any content identity.

To validate the binding, a verifier MUST independently validate the subject package under the complete AURAL Draft 0.2 specification, including ZIP structure, exact canonical manifest bytes, CRC32, WAVE identification, original length, and original SHA-256. It MUST then:

1. hash the exact verified `manifest.json` entry bytes with SHA-256 and compare `manifest_sha256`;
2. compare `format`, `version`, and the original path;
3. compare the manifest's original SHA-256 and size with the signed values; and
4. independently compare the verified original bytes' SHA-256 and length with the signed values.

A mismatch MUST fail subject binding even if the Ed25519 signature is valid. A whole-ZIP digest MUST NOT substitute for these logical bindings. Physical ZIP hashes MAY be defined later as transfer-specific claims but do not define logical evidence identity.

Verification MUST NOT rewrite, normalize, transcode, or otherwise modify the original audio bytes.

## 11. Initial event: original asset acquired

`urn:aural:event:original-asset-acquired:1` is a signer's claim that the subject's particular original bytes were acquired, captured, imported, or received. It does not state that a recorder authenticated the bytes.

For this event, `claims` MUST contain the six required members and MAY contain the two optional members below. No other claim member is permitted.

| Member | Required | Requirement |
|---|---:|---|
| `acquisition_method` | yes | one of `native-capture`, `external-recorder-import`, `received-evidence-import`, `other-import` |
| `source_type` | yes | respectively `device-microphone`, `external-recorder`, `received-evidence`, or `other` |
| `source_description` | yes | non-empty string, at most 4,096 Unicode scalar values |
| `acquiring_key_id` | yes | key identifier exactly equal to assertion `signing_key_id` |
| `key_protection` | yes | one of `software`, `os-keystore`, `hardware-backed`, `secure-element`, or `unknown` |
| `earlier_modification_history` | yes | one of `none-known`, `known`, or `unknown` |
| `claimed_times` | no | array from §12 |
| `acquisition_environment` | no | non-empty string, at most 4,096 Unicode scalar values |

The method and source type MUST use the pair shown in the table. This supports phone-native capture, import from an external recorder, previously received evidence, and a bounded fallback for another import. A new semantic category requires a new event-type revision rather than a novel string.

`none-known` means only that the signer reports no known earlier modification; it is not proof of an unmodified origin. `known` means the signer knows of earlier modification history, and `unknown` means the signer cannot make either statement. Free-text descriptions MAY explain the claim but MUST NOT be interpreted as cryptographic device attestation.

`key_protection` discloses the signer's best available classification of the private key at signing time. `software` includes an exportable application-managed key; `os-keystore` is OS-controlled without a verified hardware guarantee; `hardware-backed` and `secure-element` assert the corresponding platform protection; and `unknown` states that the application cannot determine the level. This value is itself only a signed claim unless separate attestation is verified.

Any acquisition method MAY have an empty `parents` array when no earlier signed event is available. A received or imported event SHOULD include known earlier signed events as parents; absence of such a reference is not proof that no earlier event or modification exists.

## 12. Claimed times

`claimed_times`, when present, MUST contain one to three objects. Each object contains exactly:

| Member | Type and requirement |
|---|---|
| `basis` | one of `device-reported`, `import`, or `signing` |
| `value` | timestamp string from the profile below |

Each basis may occur at most once. Entries MUST appear in this order when present: `device-reported`, then `import`, then `signing`. Omitted categories are allowed.

The timestamp profile is:

```text
YYYY-MM-DDTHH:MM:SS[.1-to-9-digits](Z|+HH:MM|-HH:MM)
```

Calendar and clock fields MUST be valid. Year `0000`, leap-second value `60`, lowercase `t` or `z`, offset `-00:00`, offsets beyond ±14:00, and a 14-hour offset with nonzero minutes are prohibited. Writers SHOULD use `Z` when UTC is known.

If `claimed_times` is absent, time is unknown under this profile. A device without a reliable wall clock is not required to invent a timestamp. Every supported value is only a signed claim:

- `device-reported` reports a device-supplied time;
- `import` reports when import or acquisition was claimed to occur; and
- `signing` reports when signing was claimed to occur.

`trusted`, `rfc3161`, or any other basis is unsupported and MUST cause rejection. Independently trusted time is not produced by this profile. An RFC 3161 or transparency-based extension requires separately standardized semantics and validation.

## 13. Extensions and versions

An extension identifier MUST be a globally scoped ASCII URI-form string, 1–255 bytes, matching `^[a-z][a-z0-9+.-]*:[!-~]+$`. Definers SHOULD use an HTTPS URI or URN under their control.

`extensions`, when present, maps extension identifiers to values satisfying §§5–6. `critical_extensions`, when present, is an array of unique extension identifiers. Every critical identifier MUST also be a key in `extensions`.

A verifier:

- MUST accept and preserve without interpretation an unknown non-critical extension when otherwise rewriting a record for a purpose that permits rewriting;
- MUST reject an unknown critical extension;
- MUST reject a critical identifier lacking a corresponding value;
- MUST NOT assign semantics to an unknown extension; and
- MUST NOT let an extension redefine, alias, relax, or contradict a core field or validation rule.

The closed-core rule applies independently to the envelope, assertion, subject, original descriptor, parent reference, digest descriptor, claims, claimed-time object, and public-key record.

Schema versions and signature profiles are exact capability identifiers, not numbers for range matching. Unsupported `event_schema_version`, `key_schema_version`, `event_type`, or `signature_profile` values MUST fail closed. There is no closest-version fallback. A semantic change requires an explicit new schema, event-type revision, or signature profile as appropriate.

## 14. Validation procedure

A verifier MUST perform checks in an order that bounds attacker-controlled work and MUST report no partial success after any failure:

1. Bound the complete event record at 1 MiB, the key-record count at 64, each supplied key record at 16 KiB, and aggregate key-record data at 256 KiB before parsing or file-sized allocation. File inputs MUST follow §5.3's stable-handle procedure.
2. Decode strict UTF-8; reject BOM, malformed JSON, duplicate names, invalid Unicode, prohibited numbers, and excessive depth.
3. Validate exact JCS byte equality for the complete event and supplied key records.
4. Require exactly `assertion` and `signature` in the envelope.
5. Validate the closed assertion schema, exact schema version, exact signature profile, identifiers, extensions, resource counts, subject, parent references, event type, claims, and claimed times.
6. Parse supplied public-key records, reject malformed or duplicate key identifiers, select exactly one matching key, decode its 32 bytes, apply §7.2's canonical and non-small-order checks, and recompute its key ID.
7. Decode the signature as exactly 64 canonical base64url bytes; validate canonical, non-small-order `R` and `S < L`.
8. independently compute `JCS(assertion)` and the exact signature input from §7.1.
9. Verify pure Ed25519 using the exact uncofactored acceptance policy in §7.2.
10. Compute the signed-event digest from the complete canonical record.
11. When the subject package is available, independently verify it under Draft 0.2 and perform every comparison in §10.
12. Report the distinct outcomes from §2. A valid signature MUST NOT silently imply identity, trust, trusted time, or complete history.

An implementation MAY order independent semantic checks differently, but it MUST apply input bounds before expensive processing and MUST produce the same accept/reject result.

## 15. Failure conditions

Each of the following is fatal to the indicated validation operation:

| Condition | Required result |
|---|---|
| oversized, malformed, duplicate-name, non-JCS, or profile-invalid JSON | reject record |
| unknown core member | reject record |
| unknown critical extension | reject semantic validation |
| unknown schema version, event type, or signature profile | reject semantic/signature validation |
| malformed UUID or key identifier | reject record |
| missing matching key record | signature not validatable; fail operation |
| duplicate supplied `key_id` | reject key input |
| malformed, unsupported, or ID-mismatched key record | reject key input |
| noncanonical, identity, or other small-order public key | reject key input |
| malformed/noncanonical signature encoding or invalid signature | reject cryptographic validation |
| noncanonical or small-order `R`, `S >= L`, or cofactored-only equation | reject cryptographic validation |
| malformed, duplicate, unordered, self, or unsupported-algorithm parent reference | reject record |
| missing parent during a future graph check | record signature may remain valid; report history incomplete and do not report complete graph validation |
| event ID mapped to different record digests | fail graph validation as collision |
| package absent | signature may be valid; report subject integrity not checked |
| package invalid or signed subject mismatch | fail subject binding |
| claimed time present but validly formed | report signed claim only, never trusted time |

## 16. Implementation and platform requirements

Implementations SHOULD use a maintained cryptographic library rather than implement Ed25519 arithmetic themselves. Private keys SHOULD be generated from a cryptographically secure random source, protected against disclosure, and used through constant-time implementations appropriate to the platform.

The byte-level prechecks in §7.2 require no custom elliptic-curve arithmetic: canonical `y` and scalar bounds are integer comparisons, and the finite set of canonical small-order encodings can be rejected by exact comparison. The maintained provider performs curve decoding and the uncofactored verification equation. Provider and version are part of an implementation's conformance evidence.

The reference conformance run verified Node.js 24.19.0/OpenSSL 3.5.7, Python cryptography 50.0.1/OpenSSL 4.0.2, and OpenJDK 21 SunEC against the adversarial acceptance set. The raw Node and Python providers did not have identical small-order behavior, which is why the application-level checks are mandatory. Bouncy Castle's current public source performs canonical and small-order public-key checks and an individual verification equation, but an Android implementation MUST test the exact provider and version it ships; this document does not claim that every Android `Signature` provider has the required acceptance set. A provider that accepts the cofactored-only vector or cannot be combined with the mandatory prechecks is not conforming to this profile.

Software Ed25519 signing is permitted on Android and other platforms. An application MUST populate `claims.key_protection` with its best available accurate classification and SHOULD separately disclose any verified attestation state in a future standardized extension. It MUST NOT describe a software key as hardware-backed or an unattested key as device-authenticated.

Loss of a self-managed private key can make future signing impossible; compromise permits fraudulent new assertions under that key. This profile defines neither recovery nor revocation. Applications MUST NOT place operational private keys, seed values, exported private-key objects, or recovery material in public conformance artifacts or evidence packages.

## 17. Privacy and operational considerations

Event descriptions, environment details, timestamps, key reuse, and stable evidence identifiers can reveal sensitive information or permit correlation. Implementations SHOULD minimize optional personal data and apply access controls appropriate to evidence records. This format provides integrity and signed claims, not confidentiality.

Detached records and key records SHOULD be transferred with the subject package using a mechanism that preserves exact bytes and unambiguous file association. The subject package remains independently usable as Draft 0.2. Deleting or withholding a detached event does not alter its package, which is why absence of an event cannot prove absence of prior activity.

## 18. Conformance vectors

The normative constructions in this document are illustrated by the public corpus in `tests/fixtures/provenance/`. Corpus metadata, byte lengths, hashes, the exact assertion, exact signature input, signature, key ID, and signed-event digest are documented in [`PROVENANCE-CONFORMANCE.md`](PROVENANCE-CONFORMANCE.md). The corpus includes no emitted private-key material.
