# AURAL Experimental Signed-Event Graph Profile 1

**Status:** Experimental specification draft

**Profile:** Signed-event graph verification, revision 1

**Depends on:** [AURAL Detached Provenance Signature Profile 1](PROVENANCE-SIGNATURE-1-DRAFT.md) and [AURAL Open Standard Draft 0.2](SPECIFICATION-0.2-DRAFT.md)

This document specifies the current experimental profile for verifying a finite set of detached AURAL signed-event records as a graph. It does not change the signed-event wire format, public-key record format, AURAL Draft 0.2 package format, or any existing public verification API.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in BCP 14 when, and only when, they appear in all capitals.

Because this profile is experimental, an implementation or document MUST NOT describe it as an adopted AURAL standard. Normative language here defines interoperable behavior for this experimental revision only.

## 1. Scope and relationship to signed-event records

The Detached Provenance Signature Profile 1 defines one signed-event record, its canonical encoding, its signature, its public-key record, parent-reference syntax, and its binding to one AURAL Draft 0.2 subject package. That profile explicitly leaves graph traversal, reachability, and graph policy outside its scope.

This graph profile adds rules for:

- accepting an unordered finite collection of complete signed-event record byte strings;
- indexing logical events and resolving their declared parents;
- rejecting ambiguous identities and structurally invalid graphs;
- producing deterministic parent-first order;
- enforcing graph-level resource limits;
- verifying every logical event signature; and
- optionally verifying one AURAL Draft 0.2 package against every logical event.

It does not define a graph container or graph manifest. Input ordering has no evidentiary meaning. It does not establish that the supplied record set is a complete history, that records outside the supplied set do not exist, or that a signer, clock, acquisition event, or asserted fact is trustworthy.

## 2. Behavior-to-specification matrix

The source references in this table identify the graph implementation baseline at commit `63bd5d8e4d2934099cbab188d214a20cb8432472`; the diagnostic-policy rows reflect the active N17–N22 conformance state described in Section 14. “Existing requirement” refers to the individual signed-event specification, not merely to implementation agreement.

| Behavior | Python behavior | Node.js behavior | Existing requirement | Disposition in this profile |
|---|---|---|---|---|
| Input is a non-empty finite sequence of complete record bytes | Required | Required | None at graph level | Normative |
| Event count, individual bytes, and aggregate bytes are checked before deduplication | Yes | Yes | Individual 1 MiB record limit only | Normative |
| Raw duplicate inputs consume all input limits | Yes | Yes | Not specified | Normative |
| Identical signed-event bytes collapse to one logical event and increment a duplicate count | Yes | Yes | Individual profile permits idempotent treatment | Normative |
| Same event ID with distinct signed-event digests fails | Yes | Yes | Required for a future graph validator | Normative |
| Same signed-event digest with distinct bytes fails | Yes | Yes | Required for a future graph validator | Normative |
| Parent references match exact event ID and signed-event digest | Yes | Yes | Required | Inherited and normative |
| Missing declared parent fails complete verification and reports unclosed declared-parent closure | Yes | Yes | Required for full-graph success | Normative |
| Parent digest mismatch fails | Yes | Yes | Required | Normative |
| Parent fanout is at most 64 in graph verification | Yes | Yes | Individual records permit up to 4096 parents | Normative graph-specific bound |
| Maximum resolved depth is 256 nodes, with each root at depth 1 | Yes | Yes | Not specified | Normative |
| Cycles fail | Yes | Yes | Graph policy previously out of scope | Normative |
| Disconnected acyclic components are accepted | Yes | Yes | Reachability previously out of scope | Normative for record-set verification; not proof of one history |
| Output is parent-first and the smallest ASCII event ID among eligible events is selected next | Yes | Yes | Traversal previously out of scope | Normative |
| Graph structure is resolved before key and signature verification | Yes | Yes | Not specified | Normative stage order, subject to Section 11 |
| Every supplied public-key record is validated; duplicate key IDs fail | Yes | Yes | Required | Inherited and normative |
| Every unique logical event signature is verified | Yes | Yes | Required per individual event | Normative |
| Optional package is verified once and bound to every unique logical event | Yes | Yes | Six-field binding required per event | Normative |
| No package supplied yields `not_checked`, not a binding success | Yes | Yes | Required result distinction | Inherited and normative |
| Successful closed graphs report history completeness as `not_established` | Yes | Yes | Signature cannot establish completeness | Normative result limitation |
| Valid record sets with different `evidence_id` values may be structurally resolved | No cross-event check | No cross-event check | No graph policy | **OPEN DESIGN DECISION** |
| Parent and child may name different six-field subjects when no package is supplied | No cross-event check | No cross-event check | No graph policy | **OPEN DESIGN DECISION** |
| Competing malformed event records covered by the digest/bytes ordering rule are selected independently of input order | Digest/bytes ordering | Digest/bytes ordering | Independent checks may be reordered | Normative only where Section 11 expressly defines it |
| Padded or otherwise noncanonical signature text is classified at the same stage | Validated before graph resolution as `encoding` at the `record` stage | Validated before graph resolution as `encoding` at the `record` stage | Rejection required; stage previously unspecified | **APPROVED AND IMPLEMENTED DIAGNOSTIC POLICY:** actively enforced by N17–N19 |
| Competing malformed key records select the same failure independently of key input order | Bounded raw graph key records are sorted by `(SHA-256(raw bytes), raw bytes)` before validation | Bounded raw graph key records are sorted by `(SHA-256(raw bytes), raw bytes)` before validation | Rejection required; precedence previously unspecified | **APPROVED AND IMPLEMENTED DIAGNOSTIC POLICY:** actively enforced by N20–N22 |
| Fanout failure precedes or follows missing-parent and parent-digest-mismatch failures | Checked per event with parent resolution | All fanout checked before parent resolution | Rejection required; precedence unspecified | **OPEN DESIGN DECISION** |
| Result property spelling | Python aggregate names use snake case | Node aggregate names use camel case | No serialized graph result format | Intentional language-specific API behavior |
| Package verification call shape | Synchronous | Promise only when package verification is requested; detailed API is asynchronous | No graph API specified | Intentional language-specific API behavior |

Primary implementation references are [Python graph limits and result types](../aural/provenance.py#L247), [Python indexing and graph resolution](../aural/provenance.py#L1207), [Python complete verification](../aural/provenance.py#L1506), [Node.js input bounds](../interop/signed_event_graph.mjs#L115), [Node.js graph resolution](../interop/signed_event_graph.mjs#L324), [Node.js indexing](../interop/signed_event_graph.mjs#L407), and [Node.js complete verification](../interop/signed_event_graph.mjs#L555).

## 3. Inputs

### 3.1 Signed-event records

The event input MUST be a finite, non-empty sequence. Each element MUST be the complete bytes of exactly one canonical signed-event record conforming to Detached Provenance Signature Profile 1. A verifier MUST treat the sequence as an unordered record set; sequence position MUST NOT affect graph identity, success, normalized results, or the selected failure where this profile defines precedence.

The verifier MUST NOT rewrite, reserialize, or repair a record before hashing or validation. The signed-event digest MUST be computed from the exact supplied canonical record bytes according to the individual profile.

### 3.2 Public-key records

The key input MUST be a finite sequence of complete public-key record byte strings. Every supplied key record MUST be validated, including records not selected by an event. A key record MUST satisfy the closed schema, canonical JSON, Ed25519 public-key encoding, small-order rejection, and derived key-ID requirements of the individual profile.

Two supplied public-key records with the same `key_id` MUST fail verification, including byte-identical duplicates. Each logical event MUST resolve exactly one supplied key record whose `key_id` equals its `assertion.signing_key_id`. Absence is `missing_key`; ambiguous or invalid key material MUST NOT be ignored merely because another usable key is present.

### 3.3 Optional subject package

At most one AURAL Draft 0.2 package may be supplied for binding verification. When absent, package integrity and subject binding are not checked. When present, the package MUST be independently verified once under the complete Draft 0.2 requirements before a successful graph result is returned.

No graph-specific data may be taken from filenames, filesystem metadata, record order, ZIP comments, or other out-of-band labels.

## 4. Identity, digests, and parent references

The profile uses three distinct identifiers:

1. `event_id` is the event label declared inside the signed assertion.
2. The signed-event digest is the domain-separated SHA-256 digest of the complete canonical signed-event record, as defined by the individual profile.
3. `evidence_id` is a signed logical grouping claim and is not an event identifier, content digest, or graph identifier.

For each parent reference, `event_id` MUST identify one supplied logical event and `signed_event_digest.value` MUST equal that event's computed signed-event digest. The digest algorithm MUST be `sha-256`. Parent references retain all individual-record requirements: canonical ASCII ordering by parent `event_id`, uniqueness, and no self-reference.

A verifier MUST NOT substitute the assertion digest, signature-input digest, public-key ID, manifest digest, original-audio digest, or whole-package digest for the signed-event digest.

## 5. Duplicate accounting and collision handling

Resource accounting MUST occur over raw input records before any duplicate collapse.

After each record has passed record validation, the verifier MUST create a logical index as follows:

1. Byte-identical records with the same computed signed-event digest and event ID represent one logical event.
2. For `n` byte-identical occurrences, the logical index contains one event and the duplicate count increases by `n - 1`.
3. One computed signed-event digest associated with distinct record bytes MUST fail as `signed_event_digest_collision` at the graph stage.
4. One event ID associated with distinct signed-event digests MUST fail as `event_id_collision` at the graph stage.

Collision failures MUST occur before key selection, signature verification, or package verification. Duplicate collapse MUST NOT cause a verifier to undercount event input count, individual input size, or aggregate input size.

## 6. Resource limits

All upper boundaries in this section are inclusive. Values one unit over a boundary MUST fail with category `resource_limit`. A verifier MAY expose locally configured limits that are no greater than these maxima. A run using tighter limits is not evidence that all maximum-boundary conformance cases pass.

| Resource | Limit | Accounting rule |
|---|---:|---|
| Signed-event input records | 4096 | Raw input occurrences before deduplication |
| One signed-event record | 1,048,576 bytes | Exact supplied bytes |
| Aggregate signed-event bytes | 67,108,864 bytes | Sum of every raw input occurrence before deduplication |
| Public-key input records | 64 | Raw input occurrences, including duplicate IDs |
| One public-key record | 16,384 bytes | Exact supplied bytes |
| Aggregate public-key bytes | 262,144 bytes | Sum of every raw key input occurrence |
| Parent references on one graph event | 64 | The validated assertion's parent array |
| Resolved graph depth | 256 nodes | Each root has depth 1 |
| JSON nesting depth | 32 | Inherited from the individual profile |

The individual signed-event format permits as many as 4096 parent references so that a record remains syntactically valid under that profile. This graph profile deliberately imposes a stricter verification fanout of 64. A record with 65 through 4096 otherwise valid parents is a valid individual-profile record but MUST be rejected by this graph profile.

Input count, individual byte length, and aggregate byte length MUST be checked before parsing, hashing, deduplication, key selection, or cryptographic verification. Implementations MUST use arithmetic that cannot wrap or silently lose precision at these limits. They SHOULD avoid allocation proportional to attacker-declared values before validating those values.

## 7. Indexing, validation, and deterministic ordering

### 7.1 Record indexing

To make malformed-record selection independent of input order, a verifier MUST compute the signed-event digest of each bounded raw record and process candidate records in ascending order of:

1. lowercase signed-event digest text; then
2. raw record bytes.

Each candidate MUST then pass the individual profile's UTF-8, canonical JSON, closed-schema, identifier, subject, parent-reference, canonical signature-text encoding, and other pre-graph semantic checks. Canonical signature-text encoding is classified according to the approved policy in Section 11.2. After the applicable record validation, logical candidates MUST be ordered by:

1. ASCII `event_id`;
2. signed-event digest; then
3. raw record bytes

before collision and duplicate processing.

### 7.2 Structural resolution

The verifier MUST process logical events by ascending ASCII `event_id` when constructing graph relationships. It MUST reject fanout excess, a missing parent, or a parent digest mismatch. This event ordering does not define the relative error precedence among those conditions; Section 11.2 leaves that precedence provisional. The verifier MUST then perform a deterministic topological traversal:

1. make every zero-parent event eligible;
2. choose the eligible event with the smallest ASCII `event_id`;
3. append that event to the result;
4. make a child eligible only after every declared parent has been appended; and
5. repeat until no eligible event remains.

If events remain, the graph contains a cycle and verification MUST fail as `cycle`. Otherwise, the resulting event sequence is the required parent-first order.

For an isolated absent referenced event, verification MUST fail with category `missing_parent` at the graph stage. `missing_parent` means declared-parent closure could not be established for the supplied record set. Verification fails rather than returning a partial or successful graph result. The failure reports an unclosed supplied parent set; it does not establish whether any undeclared or otherwise withheld historical records exist.

Graph depth is the maximum number of nodes on any directed path ending at an event. Each root has depth 1; every other event has depth one greater than the maximum depth of its declared parents. After acyclicity has been established, depth greater than 256 MUST fail as `resource_limit` at the graph stage.

The cycle check therefore precedes the depth-limit result when both conditions could be alleged. A verifier MUST NOT return a successful partial traversal.

### 7.3 Disconnected components

This profile verifies a supplied record set, not a claim that all records form one rooted history. Multiple disconnected acyclic components MUST be accepted when every component independently satisfies all requirements. The same global smallest-eligible-event rule applies across components and may interleave their output.

Acceptance of disconnected components means only that the supplied set is structurally consistent. It does not prove that the components concern the same evidence, share a trust domain, or collectively form a complete history.

## 8. Package binding and the six-field subject contract

When a package is supplied, each unique logical event MUST bind to that same independently verified package. The verifier MUST compare all six fields required by the individual profile:

1. `subject.format`;
2. `subject.version`;
3. `subject.manifest_sha256`;
4. `subject.original.path`;
5. `subject.original.sha256`; and
6. `subject.original.byte_length`.

Every comparison MUST be exact and MUST use values derived from successful Draft 0.2 package verification. A whole-ZIP digest is not a substitute. One mismatch in any logical event MUST fail the entire graph operation as `subject_binding` at the package stage. Identical duplicate input records are bound once as their one logical event.

When no package is supplied, each event's asset-integrity result and the conceptual graph-wide package-integrity status MUST be `not_checked`. The graph-wide status MAY be exposed as an explicit aggregate property or derived unambiguously from the uniform per-event asset-integrity results; an explicit aggregate property is not required. These results MUST NOT be described as verified, implicitly inferred from signature validity, or promoted based on agreement among events.

## 9. Cross-subject and cross-evidence relationships

Current Python and Node.js implementations resolve parent references using only exact parent event ID and signed-event digest. They do not require a parent and child to have equal `evidence_id` values or equal six-field subjects. Supplying one package indirectly requires every logical event to have the same six-field subject, but it still does not compare `evidence_id` across events.

**OPEN DESIGN DECISION — Cross-evidence continuity:** Structurally valid cross-evidence parent edges are currently permitted. A future revision must decide their evidentiary interpretation, whether continuity policy remains separate from structural verification, and whether transitions across unequal `evidence_id` values or unequal six-field subjects require an explicit signed transition claim. This document deliberately does not characterize such an edge as evidence continuity.

For compatibility with the current experimental implementations, unequal cross-event `evidence_id` or subject values alone do not create a structural graph error when no package is supplied. A successful result MUST NOT infer shared evidence identity, asset continuity, custody continuity, or semantic validity from such an edge.

**OPEN DESIGN DECISION — policy result:** A future revision should decide whether cross-subject and cross-evidence relationships are rejected, accepted with a distinct warning/result, or evaluated by an application policy layered above structural verification. That decision must not be introduced as an undocumented verifier change.

## 10. Verification pipeline

Subject to the unresolved competing-error cases in Section 11, complete verification MUST apply these conceptual stages. This list defines required acceptance dependencies, not a total cross-language order for independent checks or competing failures:

1. validate options and raw event/key input bounds;
2. deterministically parse each signed-event record and apply the pre-graph checks defined in Section 7.1, including canonical base64url validation of signature text;
3. build the logical index, reject collisions, and count duplicates;
4. resolve exact parent references, reject cycles, enforce graph limits, and produce parent-first order;
5. order the bounded raw public-key records by ascending `(SHA-256(raw bytes), raw bytes)`, validate every record in that order, and reject duplicate key IDs;
6. verify the signature of every unique logical event in parent-first order; and
7. if a package was supplied, independently verify it and bind every unique logical event to it.

A failure at any stage MUST fail the whole operation. A verifier MUST NOT return `consistent` together with an invalid, unverified, unresolved, or unbound required component.

Cryptographic verification MUST use the exact Ed25519 profile, signature input domain separation, canonical assertion bytes, 32-byte public-key encoding, 64-byte signature encoding, scalar bound, and small-order rules of the individual profile. This graph profile does not add algorithm negotiation.

## 11. Errors, precedence, and stage semantics

### 11.1 Categories and stages

Acceptance and rejection are normative for every condition specified by this profile. Implementations MUST expose a machine-readable error category and verification stage for controlled conformance failures. For an isolated single-fault case, the category and stage are normative only when this document or the shared conformance corpus explicitly specifies them and does not mark them provisional. When multiple independent failures occur within the same validation stage, the selected failure does not have mandatory cross-language precedence unless this document expressly defines it. Human-readable error messages are non-normative and need not be identical across languages.

| Stage | Meaning | Representative categories |
|---|---|---|
| `input` | Options, input type/count, or byte bounds failed before record interpretation | `configuration`, `input`, `resource_limit` |
| `record` | A signed-event byte string failed individual-format decoding or semantic validation | `json_profile`, `encoding`, `canonicalization`, `schema`, `identifier`, `parent_reference`, `resource_limit`, `unsupported_signature_profile` |
| `graph` | Logical indexing or structural resolution failed | `event_id_collision`, `signed_event_digest_collision`, `missing_parent`, `parent_digest_mismatch`, `cycle`, `resource_limit` |
| `key` | A public-key record or key selection failed | `public_key`, `key_id_mismatch`, `duplicate_key`, `missing_key`, `unsupported_algorithm` |
| `signature` | Ed25519 profile or signature verification failed | `signature` |
| `package` | Draft 0.2 verification or six-field binding failed | `package_integrity`, `subject_binding` |

Only the following precedence is established:

- raw input bounds precede deduplication and all content checks;
- the pre-graph record checks defined in Section 7.1 precede graph collision and structure checks;
- canonical base64url signature-text failure is `encoding` at the `record` stage and precedes graph resolution;
- graph resolution precedes public-key and signature verification;
- bounded raw public-key records are ordered by ascending `(SHA-256(raw bytes), raw bytes)` before key validation, and key validation precedes signature verification;
- all signature verification precedes optional package verification;
- a cycle result precedes a graph-depth result; and
- for event-record failures governed by the digest/raw-byte ordering in Section 7.1, the same input records in different sequence orders MUST select the same failure.

### 11.2 Approved and unresolved diagnostic precedence

**APPROVED AND IMPLEMENTED DIAGNOSTIC POLICY — signature text:** A signature string that is not canonical unpadded base64url for exactly 64 bytes MUST fail as category `encoding` at the `record` stage. This check is part of pre-graph record validation and MUST precede logical indexing and graph resolution, including `missing_parent` and `parent_digest_mismatch` failures. A canonical 64-byte signature that fails the Ed25519 acceptance policy remains category `signature` at the `signature` stage. Python and Node.js implement this classification, and active cross-language cases N17–N19 enforce it.

**APPROVED AND IMPLEMENTED DIAGNOSTIC POLICY — key ordering:** After key count, individual key-record byte length, and aggregate key-record byte length have been bounded, a verifier MUST compute `SHA-256(raw bytes)` for each supplied public-key record and order the records by ascending digest bytes, breaking a digest tie by ascending raw bytes. It MUST validate every record in that order. Supplied sequence position therefore does not select among competing malformed-key failures. Sorting MUST NOT occur before the input bounds, weaken any bound, permit malformed unrelated keys to be ignored, or change duplicate-key rejection. The Python and Node.js graph verifiers implement this ordering, and active cross-language cases N20–N22 enforce it.

**OPEN DESIGN DECISION — graph-structure precedence:** Python checks fanout, missing parents, and parent-digest mismatches together for each event in event-ID order. Node.js checks fanout for all events before resolving parent IDs and digests. Each isolated condition MUST be rejected with the category and graph stage specified in Section 11.1, but relative precedence among fanout, `missing_parent`, and `parent_digest_mismatch` is provisional when more than one is present.

**OPEN DESIGN DECISION — exhaustive precedence:** This draft specifies the established pipeline and tested event-record determinism but does not define a total order among every possible pair of failures within one stage. Unless this document expressly states otherwise, implementations may select different failures from inputs containing multiple independent same-stage defects. A future conformance task may adopt a compact precedence table rather than infer rules from control flow.

These open decisions concern deterministic error reporting. They do not permit either implementation to accept malformed input.

## 12. Verification results

Result names below are abstract protocol concepts. Existing public APIs may use language-idiomatic spelling, such as Python snake case or Node.js camel case, and may convey a conceptual aggregate through an unambiguous derivation from per-event fields rather than a named aggregate property.

A successful complete graph result MUST convey at least:

- graph `status = consistent`;
- declared-parent closure `closed`;
- `history_completeness = not_established`;
- the number of unique logical records;
- the number of duplicate raw inputs collapsed;
- maximum graph depth, with roots at 1;
- the deterministic parent-first logical-event sequence; and
- an individual verification result for every logical event.

Each returned logical event MUST have a valid signature. If a package was supplied, package integrity and every event's subject binding MUST be verified, and the conceptual graph-wide package status MUST be `verified`. If no package was supplied, conceptual graph-wide package status and per-event asset integrity MUST be `not_checked`. In either case, the conceptual graph-wide status MAY be an explicit aggregate property or be derived unambiguously from the uniform per-event asset-integrity results.

`consistent` means only that:

- every unique record is valid under the individual profile;
- logical identity is unambiguous;
- all declared parents are present with exact digests;
- the supplied record set is acyclic and within configured limits;
- every required public key is valid and unambiguous;
- every logical event signature is valid; and
- any requested package verification and binding succeeded.

`consistent` does **not** mean that the graph is connected, exhaustive, authoritative, temporally true, causally true, or produced by a trusted person or device.

`closed` is returned only for successful graph verification and means that every parent declared by a supplied event is also supplied and matches exactly. A `missing_parent` failure instead reports that declared-parent closure could not be established and returns no partial graph success. Neither state means that no earlier, undeclared, omitted, sibling, or unrelated event exists.

`not_established` for history completeness is mandatory for every successful, closed graph in this revision. It is distinct from the known failure of declared-parent closure reported by `missing_parent`. Detached records can be omitted without changing the package or any remaining valid signature, so neither closed declared-parent resolution nor a missing-parent failure proves that the complete historical record is available.

**OPEN DESIGN DECISION — History completeness:** No additional mechanism for proving historical completeness is adopted. No present signed object commits to the complete member set, expected roots, expected tips, or an append-only transparency mechanism. A future profile must define new signed evidence before it can report history completeness. It must not reinterpret `closed` or `consistent` as completeness.

## 13. Security and trust limitations

This profile validates cryptographic and structural consistency, not the truth or trustworthiness of claims. In particular, it does not establish:

- investigator identity or authorization;
- private-key custody, compromise status, revocation, or rotation policy;
- a trusted creation time, ordering time, or timestamp authority;
- acquisition authenticity, custody continuity, or causal truth;
- evidence continuity across different subjects or `evidence_id` values;
- absence of withheld records, roots, branches, or components;
- history completeness or append-only publication;
- trust in the machine performing verification; or
- archival persistence or discoverability of detached records and keys.

An attacker with a signing key can create cryptographically valid false assertions. A valid child signature does not endorse its parent's factual claims; it only signs a reference to exact parent bytes. A closed supplied parent set does not prove that the set is complete.

Applications MUST keep `signature_valid`, package integrity, subject binding, signer identity, authorization, semantic policy, and history completeness as separate results. User interfaces and documentation MUST NOT summarize a `consistent` graph as “authentic evidence” or “verified history.”

## 14. Conformance

A conforming implementation of this experimental profile MUST implement the individual signed-event profile and the graph rules in this document. It MUST match the accept/reject outcomes and established machine-readable error expectations in the shared corpus at [graph conformance cases](../tests/fixtures/graph_conformance/cases.json).

The active ordinary corpus contains 35 cases and includes:

- `A-signed-root-no-package` through `G-input-order-independence`;
- signature, parent, package, archive, and public-key negatives `N01` through `N12`;
- parent fanout cases `H-parent-fanout-64` and `N13-parent-fanout-65`;
- depth cases `I-graph-depth-256` and `N14-graph-depth-257`;
- individual event byte cases `H-event-bytes-at-limit` and `N-event-bytes-over-limit`;
- event count cases `H-event-count-4096` and `N-event-count-4097`; and
- deterministic malformed-record cases `N15-competing-malformed-forward` and `N16-competing-malformed-reverse`; and
- signature-text and public-key-ordering diagnostics `N17-noncanonical-signature-encoding` through `N22-competing-malformed-keys-encoding-first`.

Cases N17–N22 use independently pinned source fixtures and deterministic record construction. Their source and derived-record hashes, input construction, and expected diagnostics are part of the active manifest and are checked by both language adapters.

The independently pinned cross-language adapter and expectations are in [the cross-language test](../tests/test_graph_cross_language.py) and [Node adapter](../tests/graph_conformance_node_adapter.mjs). The corpus manifest, compressed resource bundles, and package fixtures are integrity checked; regeneration is not part of a normal conformance run.

Aggregate event-byte conformance is defined separately by [aggregate-byte-limit-cases.json](../tests/fixtures/graph_conformance/aggregate-byte-limit-cases.json):

- `H-aggregate-bytes-at-limit` contains exactly 67,108,864 event bytes and MUST be accepted; and
- `N-aggregate-bytes-over-limit` contains exactly 67,108,865 event bytes and MUST fail as `resource_limit` at the input stage.

Those records are generated only in an operating-system temporary directory by the hardened generator referenced in the manifest. The suite is opt-in through `AURAL_RUN_LARGE_GRAPH_BOUNDARY=1`. A normal test run proves that the ordinary corpus and the aggregate harness's safety/inventory checks pass; it does not freshly prove either implementation at the 64 MiB aggregate boundary. An unqualified full resource-boundary conformance claim therefore requires a successful opt-in aggregate run or equivalent independently reproducible evidence.

The signature-text and public-key-ordering expectations approved in Section 11.2 are active normative diagnostic requirements represented by cases N17–N22. Competing fanout/parent-resolution faults and other same-stage combinations whose precedence Section 11 leaves open remain provisional. Implementations MUST reject malformed input and MUST match all established diagnostics in the 35-case active ordinary corpus.

## 15. Versioning and future compatibility

This document defines revision 1 of an experimental processing profile, not a new event schema, key schema, or container version. Existing conforming signed-event bytes remain unchanged. No machine-readable graph-profile identifier is added by this revision.

Changes to maximum limits, duplicate semantics, collision handling, parent resolution, ordering, connectedness, package-binding scope, result meaning, or error precedence require an explicit revision of this profile and updated conformance evidence. They MUST NOT be deployed as silent interpretation changes under the same profile revision.

Future event or signature profile versions MUST NOT be accepted by algorithm inference or best-effort parsing. A graph-profile revision must explicitly identify which individual record profiles it accepts and how mixed versions, if any, interact.

**OPEN DESIGN DECISION — profile negotiation:** Before this experiment becomes a stable protocol, AURAL should decide whether invocations and serialized verification reports need a machine-readable graph-profile identifier. Adding such an identifier is outside this assignment and must not alter existing public APIs without a separate compatibility design.

**OPEN DESIGN DECISION — completeness mechanism:** A future revision may define a signed graph manifest, committed tips, transparency log, checkpoint, or other completeness evidence. No such mechanism is selected here, and none may be inferred from the present detached record set.
