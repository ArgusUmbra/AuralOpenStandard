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

## Core Reader executable runner

The portable interface is [AURAL Conformance Adapter Protocol 1](CONFORMANCE-ADAPTER-PROTOCOL-1-EXPERIMENTAL.md). It is a versioned JSON-over-child-process contract that any language can implement. `tools/run_aural_conformance.py` is an optional Python 3.11 standard-library convenience runner for that contract; Python is not a requirement for the implementation being tested.

Before running cases, verify the three published manifests and all referenced input bytes:

```text
python tools/validate_core_conformance_manifest.py
python tools/validate_provenance_conformance_manifest.py
python tools/validate_graph_conformance_manifest.py
```

Each validator performs strict JSON and inventory checks, confines fixture paths, and verifies exact sizes and streaming SHA-256 digests. A non-Python consumer can implement the same public checks from the manifests. The Core Reader runner repeats the Core manifest and fixture validation before it starts any adapter.

### Implement an adapter in any language

An adapter reads one request from standard input, invokes the implementation under test on `input.path`, writes one response to standard output, and exits. The runner creates a new process for every case and never supplies `expected.outcome` to it. Logs go to standard error.

Request shape:

```json
{
  "protocol": "org.aural.conformance.adapter",
  "protocol_version": 1,
  "case_id": "aural-core-reader/0.2-draft/valid-minimal",
  "operation": "verify-package",
  "input": {
    "role": "package",
    "path": "/local/checkout/tests/fixtures/conformance/valid-minimal.aural",
    "size": 549,
    "sha256": "aae82053118bedd4ab55c32322aeab7219ac2f4fced5847eee6d07215feda6a3"
  }
}
```

Response shape:

```json
{
  "protocol": "org.aural.conformance.adapter",
  "protocol_version": 1,
  "case_id": "aural-core-reader/0.2-draft/valid-minimal",
  "outcome": "accept",
  "implementation": {
    "name": "Example Core Reader",
    "version": "1.4.0"
  }
}
```

The implementation result is exactly `accept` or `reject`. A controlled invalid-package exception should become `reject` with process exit zero. An unexpected exception, crash, unsupported operation, or inability to execute should produce a nonzero exit and no response; it is an execution error, not a rejection. Strict parsing, exact fields, duplicate-name rejection, byte limits, mismatch behavior, and extension rules are specified in the protocol document. A Rust, C++, or other native adapter needs only standard input/output, UTF-8 JSON support, and its implementation's normal verification entry point.

### Run Core Reader 0.2

The runner passes the executable and each repeated argument directly to `subprocess` with no shell. Quote paths for the shell from which you start the runner; they remain one argument when the adapter process is created.

```text
python tools/run_aural_conformance.py \
  --profile core-reader-0.2 \
  --report core-reader-report.json \
  --timeout 10 \
  --adapter /opt/example/bin/aural-adapter \
  --adapter-arg=--strict
```

PowerShell example with a spaced executable path:

```powershell
python tools/run_aural_conformance.py `
  --profile core-reader-0.2 `
  --report core-reader-report.json `
  --adapter "C:\Program Files\Example\aural-adapter.exe" `
  --adapter-arg=--strict
```

Use `--adapter-arg` once per argument. The `--adapter-arg=--flag` form is required when an adapter argument starts with a hyphen. Other options are `--manifest PATH` for a separately obtained copy of the published Core manifest, `--include-legacy` for both optional Draft 0.1 cases, `--timeout SECONDS` from 0.05 through 60, and repeatable `--skip-case CASE_ID` for an explicit development-time skip. Skipping any required case makes coverage incomplete.

The repository includes a smoke-test bridge:

```text
python tools/run_aural_conformance.py \
  --report reference-smoke-report.json \
  --adapter python \
  --adapter-arg tests/adapters/reference_core_reader_adapter.py
```

That adapter calls the existing AURAL Python Core Reader. It tests the runner and demonstrates the transport, but it is not an independent implementation and is not evidence of third-party interoperability.

### Scoring, reports, and exit status

The runner, not the adapter, compares observed and published outcomes. A negative case correctly reported as `reject` is `PASS`. A valid but wrong outcome is `FAIL`; launch, process, and protocol failures are `ERROR`; a deadline is `TIMEOUT`; and an explicitly unexecuted selected case is `SKIP`.

The overall required result is:

- `PASS` only when all 30 required Draft 0.2 cases pass;
- `FAIL` when all required cases execute but one or more return the wrong valid outcome;
- `INCOMPLETE` when required inventory or execution coverage is missing, skipped, timed out, or erroneous.

Exit status `0` means required `PASS`, `1` means required `FAIL`, `2` means `INCOMPLETE`, and `3` means the runner could not establish or record a run because invocation, manifest, fixture, or report setup failed. Optional Draft 0.1 results are reported separately. Their failure, error, timeout, or skip does not silently change the required Core Reader 0.2 result.

The versioned JSON report identifies the exact manifest digest, profile, adapter argument vector, non-secret platform/runtime metadata, timeout, optional selection, counts, and every selected case. An abridged example is:

```json
{
  "schema": "urn:aural:conformance:runner-report",
  "schema_version": 1,
  "test_kit_version": "1",
  "manifest": {
    "path": "/local/checkout/tests/fixtures/conformance/core-reader-0.2-cases.v1.json",
    "sha256": "<64 lowercase hexadecimal digits>"
  },
  "profile": {
    "id": "aural-core-reader",
    "version": "0.2-draft",
    "status": "draft"
  },
  "optional_legacy_included": false,
  "summary": {
    "required_cases": 30,
    "selected_cases": 30,
    "passed": 30,
    "failed": 0,
    "skipped": 0,
    "execution_errors": 0,
    "timeouts": 0,
    "overall_result": "PASS"
  },
  "overall_result": "PASS",
  "cases": [
    {
      "case_id": "aural-core-reader/0.2-draft/invalid-asset-hash",
      "profile_id": "aural-core-reader",
      "profile_version": "0.2-draft",
      "requirement": "required",
      "expected_outcome": "reject",
      "observed_outcome": "reject",
      "status": "PASS",
      "duration_ms": 18,
      "fixture": {
        "path": "invalid-asset-hash.aural",
        "size": 549,
        "sha256": "5c4c576216a21905fb08aafcd15155099ee09130b52f2a6f1b4df52fd9bbf250"
      }
    }
  ]
}
```

The complete report also has `adapter`, `execution`, `generated_at`, nested required/optional counts, and a certification disclaimer. The runner does not record environment variables, credentials, adapter standard error, or arbitrary adapter diagnostics. Because the adapter command is recorded for reproducibility, do not place secrets in command-line arguments.

The report output must be outside conformance fixture directories and cannot be a symbolic link. The runner writes it atomically. Treat adapters as trusted executable code: the runner is not a sandbox. It needs no network access itself, but it cannot prevent an adapter from using resources, including the network, that the operating system account permits.

The current executable operation covers only Core Reader `verify-package`. Signed provenance, signed-event graphs, excerpt proofs, and acoustic reproduction need separate protocol revisions and are not supported merely because operation names are reserved. The Core corpus also excludes dynamically generated ZIP64 cases, writer coverage, large aggregate boundaries, side-channel analysis, key management, and the unlisted input space. Passing is useful evidence, not proof of correctness outside the published cases and not security certification.

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
