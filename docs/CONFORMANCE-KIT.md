# AURAL public conformance kit

The public conformance kit is a language-neutral inventory of committed inputs and expected accept/reject results. It lets an independent implementation locate exact test bytes and detect fixture drift without using the repository's Python or Node.js test harnesses. It is partial coverage, not a claim of complete profile conformance.

## Published manifests

- Core Reader Draft 0.2 cases: `tests/fixtures/conformance/core-reader-0.2-cases.v1.json`.
- Experimental signed-event provenance cases and Ed25519 primitive vectors: `tests/fixtures/provenance/provenance-cases.v1.json`.

Core Reader input paths are relative to the Core Reader manifest directory. The provenance manifest declares `path_base` as `tests/fixtures`; resolve every provenance input path beneath that repository directory. Paths are slash-separated and relative. Reject absolute paths, `.` or `..` components, symbolic links, missing inputs, and non-regular files. Read each accepted file through a stable handle, enforce the declared byte size, and compute streaming SHA-256 over the exact bytes. Do not parse, normalize, reserialize, or transcode an input before hashing it.

For each provenance case, consume `inputs` in ascending `order`. The roles are `signed-event`, zero or more `public-key-record` values, and `subject-package`. Repeated key paths are intentional in the duplicate-key case; the missing-key case intentionally has no key input. Adapt these roles to the verifier API without changing their order or multiplicity.

`expected.outcome` is the conformance result: `accept` means the applicable profile operation must succeed, while `reject` means it must not succeed or report partial success. The public provenance manifest's `informative_reason` is explanatory. Error categories in the older `expected.json` source index and implementation-specific error text are informative test-harness metadata, not portable diagnostic codes. Normative failure conditions come from the associated specification, not from a new diagnostic taxonomy in this kit.

The provenance profile `org.aural.signature.ed25519-jcs-v1` and the signed-event graph profile remain experimental. The Core Reader manifest covers a bounded public subset and does not include every dynamic, large-boundary, writer, provenance, or graph test.

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

The manifest integrity checks themselves require only JSON, path, byte-count, and SHA-256 support. Run the repository validators with `python tools/validate_core_conformance_manifest.py` and `python tools/validate_provenance_conformance_manifest.py` when Python 3.11 is available; other languages can implement the same metadata checks directly.

Passing this corpus is useful interoperability evidence, but it is not security certification. It does not establish implementation correctness outside the listed cases, resistance to side channels, sound key management, authenticated identity, trusted time, complete history, or fitness for a particular evidentiary process.
