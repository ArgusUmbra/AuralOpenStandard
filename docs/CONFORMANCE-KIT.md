# AURAL public conformance kit

The public conformance kit is a language-neutral inventory of committed inputs and expected accept/reject results. It lets an independent implementation locate exact test bytes and detect fixture drift without using the repository's Python or Node.js test harnesses. It is partial coverage, not a claim of complete profile conformance.

## Published manifests

- Core Reader Draft 0.2 cases: `tests/fixtures/conformance/core-reader-0.2-cases.v1.json`.
- Experimental signed-event provenance cases and Ed25519 primitive vectors: `tests/fixtures/provenance/provenance-cases.v1.json`.
- Experimental Signed-Event Graph Profile 1 cases: `tests/fixtures/graph_conformance/graph-cases.v1.json`.

Core Reader input paths are relative to the Core Reader manifest directory. The provenance manifest declares `path_base` as `tests/fixtures`; resolve every provenance input path beneath that repository directory. Paths are slash-separated and relative. Reject absolute paths, `.` or `..` components, symbolic links, missing inputs, and non-regular files. Read each accepted file through a stable handle, enforce the declared byte size, and compute streaming SHA-256 over the exact bytes. Do not parse, normalize, reserialize, or transcode an input before hashing it.

For each provenance case, consume `inputs` in ascending `order`. The roles are `signed-event`, zero or more `public-key-record` values, and `subject-package`. Repeated key paths are intentional in the duplicate-key case; the missing-key case intentionally has no key input. Adapt these roles to the verifier API without changing their order or multiplicity.

`expected.outcome` is the conformance result: `accept` means the applicable profile operation must succeed, while `reject` means it must not succeed or report partial success. The public provenance manifest's `informative_reason` is explanatory. Error categories in the older `expected.json` source index and implementation-specific error text are informative test-harness metadata, not portable diagnostic codes. Normative failure conditions come from the associated specification, not from a new diagnostic taxonomy in this kit.

The provenance profile `org.aural.signature.ed25519-jcs-v1` and the signed-event graph profile remain experimental. The Core Reader manifest covers a bounded public subset and does not include every dynamic, large-boundary, writer, provenance, or graph test.

## Experimental Graph Verifier profile

The graph manifest is the language-neutral discovery point for all 35 active ordinary graph cases. Its stable IDs use the `aural-signed-event-graph/1/` namespace, and `source_case` preserves the identifier in the original graph index. The inventory contains 11 accepted and 24 rejected cases and depends on experimental provenance profile `org.aural.signature.ed25519-jcs-v1`, version 1. `expected.expectation_level` identifies these results as defined by the experimental profile; it does not promote implementation error text into a portable requirement.

Resolve graph input paths beneath the declared `tests/fixtures` path base. Consume each case's `inputs` array in ascending `order`, without sorting, deduplicating, or rewriting it. The roles are `signed-event`, `public-key-record`, and optional `subject-package`. Repeated descriptors are repeated input occurrences: for example, the identical-event case supplies the same signed-event bytes three times, and the duplicate-key case supplies the same key bytes twice. An empty key sequence is represented by the absence of public-key descriptors. Evidence packages are ordinary exact-byte inputs with role `subject-package`.

Most descriptors name one input byte string directly. Resource-boundary cases use a signed-event descriptor with `occurrence = ordered-collection` and a `gzip-json-string-collection` representation. Verify the gzip file's compressed size and SHA-256, decompress it with the declared expanded-size bound, verify the expanded SHA-256, and strictly decode the JSON object. Select the named array from `collections`; `all` selects every string and `prefix` selects the first `selected_record_count` strings. Encode each selected JSON string independently as UTF-8, adding no separator, newline, or terminator. Those byte strings, in array order, are the signed-event input sequence. The representation publishes the selected count, aggregate bytes, and largest record size so it can be checked without Python or Node.js.

N18 and N19 previously required an adapter to append noncanonical `==` signature padding. Their exact final bytes are now immutable files under `tests/fixtures/graph_conformance/materialized/`; an independent runner uses those files directly and performs no transformation. The validator also pins the original source inventory, preserving all other event, key, package, order, and multiplicity choices.

For an accepted case, `expected.graph` is the normalized language-neutral result. Direct-fixture cases list the exact ordered event IDs and signed-event digests. Compressed cases use `selected-collection-order`: read each selected event's `/assertion/event_id` and compute its signed-event digest with the provenance profile's `AURAL-SIGNED-EVENT-V1` domain-separated SHA-256 rule. Other fields cover consistency, declared-parent closure, history completeness, package integrity, unique and duplicate counts, parent count, and maximum depth. For a rejected case, `expected.failure.category` and `expected.failure.stage` are the profile-defined portable diagnostic; free-form exception messages are not part of the contract.

`status = consistent` means the supplied records and their declared parent relationships are internally valid. It does not establish that no earlier, sibling, detached, or withheld record exists. Likewise, `declared_parent_closure = closed` covers only parents declared by supplied events. Every accepted case therefore reports `history_completeness = not_established`.

The manifest identifies the generated 64 MiB aggregate-event-byte suite as `opt-in-large-generated`, outside the 35-case ordinary inventory. Its index commits generation parameters and ordered-input digests, but it does not contain the generated event bytes. Routine validation and CI do not run it. Passing the ordinary pack is therefore insufficient for an unrestricted full-profile or complete resource-boundary claim; such a claim also needs a successful opt-in aggregate run or equivalent independently reproducible evidence.

## Ed25519 vectors

The provenance manifest hashes `provenance/ed25519-adversarial.json` as one immutable input and lists 13 stable records. For a record, follow its `json_pointer` (for example `/vectors/4`) or match its `source_record` to the vector file's `name`. Hex-decode that record's `message`, `public_key`, and `signature` fields as exact bytes, then apply the declared signature policy and compare with its public expected outcome. Do not regenerate the values or substitute a new Ed25519 implementation; implementations should exercise the maintained cryptographic provider they intend to ship together with the profile's required prechecks.

## Language-independent consumption example

```text
manifest = strict_json_decode(read_exact("tests/fixtures/provenance/provenance-cases.v1.json"))
fixture_root = repository_root / manifest.path_base
case = find(manifest.cases, id == requested_case_id)

for input in sort(case.inputs, by = order):
    path = confined_regular_file(fixture_root, input.path, reject_symlinks = true)
    bytes = bounded_read(path, exact_size = input.size)
    require(sha256(bytes) == input.sha256)
    verifier_input.add(input.role, bytes)  // preserve order and duplicates

actual = run_applicable_profile(verifier_input)
require(actual == case.expected.outcome)
```

For a graph case, the corresponding minimal process is:

```text
manifest = strict_json_decode(read_exact("tests/fixtures/graph_conformance/graph-cases.v1.json"))
case = find(manifest.cases, id == requested_case_id)

for descriptor in case.inputs:                 // already ordered: 0, 1, 2, ...
    stored = confined_regular_file(fixture_root, descriptor.path, reject_symlinks = true)
    require(size(stored) == descriptor.size)
    require(stream_sha256(stored) == descriptor.sha256)

    if descriptor.occurrence == "ordered-collection":
        expanded = bounded_gzip_decode(stored, descriptor.representation.expanded_size)
        require(sha256(expanded) == descriptor.representation.expanded_sha256)
        strings = strict_json_decode(expanded).collections[descriptor.representation.collection]
        strings = apply_all_or_prefix_selection(strings, descriptor.representation)
        for value in strings:
            verifier_input.add("signed-event", utf8(value))  // add no extra bytes
    else:
        verifier_input.add(descriptor.role, read_exact(stored))

actual = run_experimental_graph_profile_revision_1(verifier_input)
require(normalize(actual) == case.expected)
```

The manifest integrity checks themselves require only JSON, safe file access, byte-count, SHA-256, and—for compressed graph cases—gzip support. Run the repository validators with `python tools/validate_core_conformance_manifest.py`, `python tools/validate_provenance_conformance_manifest.py`, and `python tools/validate_graph_conformance_manifest.py` when Python 3.11 is available; other languages can implement the same metadata checks directly.

Passing this corpus is useful interoperability evidence, but it is not security certification. It does not establish implementation correctness outside the listed cases, resistance to side channels, sound key management, authenticated identity, trusted time, complete history, or fitness for a particular evidentiary process.
