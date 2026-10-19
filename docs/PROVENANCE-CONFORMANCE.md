# AURAL experimental provenance signature v1 conformance

## Status and claims

This corpus tests the experimental profile in [`PROVENANCE-SIGNATURE-1-DRAFT.md`](PROVENANCE-SIGNATURE-1-DRAFT.md). It does not make that profile an adopted standard.

A conforming v1 verifier MUST accept both positive cases and reject every negative case in `tests/fixtures/provenance/expected.json`. It MUST verify the exact event bytes, key identifier, Ed25519 signature, and AURAL Draft 0.2 subject binding. Exact human-readable error text is not normative; the index's error categories are stable test-harness expectations.

The corpus contains 45 signed-event cases: 3 positive and 42 negative. It also contains 13 primitive Ed25519 acceptance-set vectors. None contains investigation evidence. No emitted fixture contains a private seed or private-key object. The deterministic generator uses public, test-only RFC 8032 vector material and MUST NOT be adapted to operational key generation.

## Regeneration and validation

Run from the repository root:

```powershell
node tools\generate_provenance_fixtures.mjs
python -m unittest discover -s tests -v
node interop\validate_provenance.mjs `
  tests\fixtures\provenance\valid-original-acquired.json `
  tests\fixtures\provenance\valid-key.json `
  tests\fixtures\conformance\valid-unicode.aural
```

Regeneration MUST leave all generated fixture bytes and hashes unchanged unless the experimental profile and corpus are intentionally revised together. `expected.json` is the generator-owned case list and SHA-256 index. Its `files_sha256` object names every generated fixture payload, including invalid key records and the primitive adversarial vectors; `expected.json` necessarily cannot contain its own digest. The separately maintained public manifest, `provenance-cases.v1.json`, is metadata and is not part of that generator-owned payload inventory. Tests require exact generated-payload inventory equality, so a missing index entry, an unexpected generated payload, or altered bytes fail conformance.

## Golden verification vector

The golden event binds the existing Draft 0.2 `valid-unicode.aural` fixture and its exact `golden-manifest.json` bytes. The event, key record, assertion, and binary signature input are separate files so an implementation can test each construction independently.

| Item | Exact value |
|---|---|
| raw public key, unpadded base64url | `11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo` |
| key ID | `urn:aural:key:ed25519:81a0a20f3cd85dc5662c25dec74739da5ce28507b6821ca7470ff8e530608255` |
| public-key record SHA-256 | `fea2167d922cbf64bf3a2982a366e7bfeeeb6e0a7e9c9710ae91845023df9609` |
| assertion length | 1,330 bytes |
| assertion SHA-256 | `929ac312d855b1b4e9f2e15bd1cd3e1024822fdbcf2ed6172518e7e3a15343a0` |
| signature-input length | 1,356 bytes |
| signature-input SHA-256 | `6365124f209c4bf461ea3e89eecc90c65d61875439236e1eeafdd5547d5410f6` |
| Ed25519 signature, unpadded base64url | `APZ-SBL3tiVLpKnax1uzM-M0-kydTiq-u7DIeprO2nZgTKFdZogpapTwivVbjENhuzsuAqeK9rU435jpieL_Cg` |
| signed-event record length | 1,445 bytes |
| plain record SHA-256, diagnostic only | `81d6ca95ac7a352155dd2f6b921b69e47a156bda4cd8ab8c2019c534794a708b` |
| domain-separated signed-event digest | `e01de77607deebd20886b063a8573ce0ced436081df57e734c11ea21c6f9870e` |
| bound physical package SHA-256, diagnostic only | `61bc898ebcc547586c11bbfc2507b1111ce91342f5b49559789d1c2d052bbf85` |

The public-key record is exactly 242 UTF-8 bytes, without BOM or trailing newline:

```json
{"algorithm":"Ed25519","key_id":"urn:aural:key:ed25519:81a0a20f3cd85dc5662c25dec74739da5ce28507b6821ca7470ff8e530608255","key_schema":"org.aural.signing-key","key_schema_version":"1","public_key":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
```

The signature input file is exactly:

```text
ASCII("AURAL-PROVENANCE-EVENT-V1") || 0x00 || contents of valid-original-acquired.assertion.json
```

The plain record and physical package hashes are included only to detect fixture drift. Parent references use the domain-separated signed-event digest, not the plain SHA-256 and not the ZIP hash.

## Positive cases

| Fixture | Condition |
|---|---|
| `valid-original-acquired.json` | complete canonical, signed, package-bound genesis event |
| `valid-received-with-parent.json` | received-evidence acquisition referencing the golden event ID and signed-event digest |
| `valid-unknown-optional.json` | signed unknown non-critical extension plus supplementary/BMP UTF-16 key ordering |

All three use `valid-key.json` and bind `../conformance/valid-unicode.aural`.

## Negative cases

| Fixture stem | Condition exercised |
|---|---|
| `invalid-noncanonical` | pretty-printed record rather than exact JCS |
| `invalid-trailing-newline` | byte follows the canonical object |
| `invalid-bom` | UTF-8 BOM |
| `invalid-utf8` | invalid UTF-8 octet |
| `invalid-duplicate-name` | duplicate envelope member name |
| `invalid-envelope-member` | unknown outer member suggesting an unsupported multisignature form |
| `invalid-fraction` | floating-point JSON token |
| `invalid-unsafe-integer` | integer outside the safe range |
| `invalid-negative-zero` | negative-zero token |
| `invalid-unpaired-surrogate` | isolated escaped surrogate |
| `invalid-noncharacter` | Unicode noncharacter |
| `invalid-excessive-depth` | complete record deeper than 32 containers |
| `invalid-signature` | changed Ed25519 signature bit |
| `invalid-padded-signature` | padded rather than canonical unpadded base64url |
| `invalid-signature-scalar` | out-of-range Ed25519 `S` representation |
| `invalid-signature-profile` | unknown signature profile |
| `invalid-schema-version` | unsupported event schema version |
| `invalid-event-id` | identifier is not UUIDv4 |
| `invalid-unknown-member` | unknown assertion core field |
| `invalid-critical-extension` | unknown critical extension |
| `invalid-critical-extension-missing` | critical name lacks a corresponding extension value |
| `invalid-timestamp` | impossible RFC 3339 calendar date |
| `invalid-time-basis` | unsupported `trusted` time basis |
| `invalid-time-order` | claimed-time entries are not in canonical semantic order |
| `invalid-source-pair` | source type contradicts acquisition method |
| `invalid-key-protection` | unsupported key-protection disclosure |
| `invalid-acquiring-key` | acquiring key differs from signing key |
| `invalid-subject-manifest` | signed manifest digest differs from the verified package |
| `invalid-subject-original` | signed original digest differs from the verified package |
| `invalid-subject-length` | signed original length differs from the verified package |
| `invalid-parent-self` | event names itself as a parent |
| `invalid-parent-duplicate` | duplicate parent event ID |
| `invalid-parent-order` | parent references are not sorted by event ID |
| `invalid-parent-digest` | parent SHA-256 has the wrong length |
| `invalid-parent-algorithm` | unsupported parent digest algorithm |
| `invalid-key-id` | public key and content-derived key ID disagree |
| `invalid-key-encoding` | public key uses padded base64url |
| `invalid-key-unknown-member` | unknown public-key record core member |
| `invalid-key-algorithm` | unsupported key algorithm |
| `invalid-public-key-small-order` | identity public key and identity-`R`/zero-`S` trivial forgery |
| `invalid-duplicate-key-record` | two supplied records have the same key ID |
| `invalid-missing-key-record` | no supplied record matches the assertion key ID |

## Ed25519 acceptance-set vectors

`ed25519-adversarial.json` separates primitive verification semantics from event parsing. It contains the published Apache-2.0 `ed25519-speccheck` cases plus an explicit identity-key/identity-`R` case. The expected AURAL policy rejects identity and other small-order points, noncanonical `A` or `R`, `S >= L`, and signatures that satisfy only the cofactored equation. It accepts the one mixed-order case whose canonical points satisfy the exact uncofactored equation. These vectors do not change the message framing used by signed events; they test the provider-facing Ed25519 acceptance primitive directly.

The automated cross-check has three deliberately distinct layers:

1. primitive provider verification of the exact message, key, and signature bytes;
2. positive-vector agreement on independently implemented JCS, key-ID framing, signature input, signature verification, and signed-event hashing; and
3. negative-vector agreement on the complete acceptance set after application-level point and scalar prechecks.

The independent Python path uses Python cryptography when it is already installed and does not import generator helpers or Node canonicalization code. If cryptography is absent, `unittest` reports both Python tests as explicit skips; that run MUST NOT be described as having Python cryptographic coverage. A dependency-free Java cross-check separately exercises the installed JCA Ed25519 provider and is likewise an explicit skip when Java is absent. The release-candidate run used Node.js 24.19.0/OpenSSL 3.5.7, Python cryptography 50.0.1/OpenSSL 4.0.2, and OpenJDK 21 SunEC. Provider versions SHOULD be recorded with release evidence because behavior can change.

## Result reporting

The independent validator reports `signature_valid` only after canonicality, semantics, key selection, key-ID recomputation, and Ed25519 verification. With the package argument it separately reports `asset_integrity: verified` only after full Draft 0.2 validation and subject comparison. Its positive output deliberately retains:

- `investigator_identity: not_established`;
- `key_trust: not_evaluated`;
- `time_assurance: claimed_only` or `unknown`; and
- `history_completeness: not_established`.

These fields are safeguards against treating a valid self-managed signature as proof of identity, trusted time, or complete history.

## Adding vectors

A new normative rejection rule SHOULD receive the smallest practical negative vector. A newly permitted structure SHOULD receive a positive vector. Fixture names are stable identifiers. Changes to vector bytes require updating `expected.json`, this document's golden values when applicable, and the design rationale for the profile.
