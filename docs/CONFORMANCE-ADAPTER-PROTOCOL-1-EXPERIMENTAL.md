# AURAL Conformance Adapter Protocol 1 (experimental)

## 1. Purpose and status

This document defines a language-neutral process protocol between an AURAL conformance runner and an independently developed implementation. Protocol 1 supports only the AURAL Core Reader operation `verify-package`. It does not require Python, Node.js, a particular library API, or implementation-specific exception and exit-code conventions.

This protocol is experimental. A conformance report is test evidence, not official certification or security certification.

The protocol identifier is `org.aural.conformance.adapter` and the protocol version is the JSON integer `1`. Identifier, version, operation, and case ID comparisons are exact and case-sensitive.

## 2. Process transport

The runner starts one new child process for each case. It passes the executable and arguments as an operating-system argument vector and does not invoke a command shell. The adapter executable may be written in any language and may itself load any implementation under test.

For each process:

1. The runner writes one UTF-8 JSON request to standard input and then closes standard input.
2. The adapter writes one UTF-8 JSON response to standard output and exits with status zero.
3. Informative logging belongs on standard error. It must not be mixed with the response.

Protocol JSON has no byte-order mark. JSON member names must be unique at every nesting level. `NaN`, `Infinity`, and other non-JSON constants are prohibited. Leading and trailing JSON whitespace is permitted, but a second JSON value or any other non-whitespace standard-output bytes are prohibited.

Protocol 1 requests are limited to 16,384 bytes and responses to 65,536 bytes, each measured as the complete UTF-8 stream. The supplied runner also limits captured standard error to 65,536 bytes. Exceeding a limit is an execution error.

The supplied runner applies a separately configured per-case timeout, bounded from 0.05 through 60 seconds and defaulting to 10 seconds. A timeout is not a package rejection.

## 3. Request contract

The request object has exactly these top-level members:

| Member | JSON type | Meaning |
|---|---|---|
| `protocol` | string | Exactly `org.aural.conformance.adapter`. |
| `protocol_version` | integer | Exactly `1`; a Boolean is not an integer here. |
| `case_id` | nonempty string | Stable ID from the public test manifest. |
| `operation` | string | Exactly `verify-package` in protocol 1. |
| `input` | object | The package input descriptor below. |

The `input` object has exactly these members:

| Member | JSON type | Meaning |
|---|---|---|
| `role` | string | Exactly `package`. |
| `path` | nonempty string | Local operating-system path to the exact `.aural` fixture. The supplied runner uses an absolute native path. |
| `size` | non-negative integer | Exact fixture byte count from the public manifest. |
| `sha256` | string | Exactly 64 lowercase hexadecimal digits for the fixture bytes. |

Example request:

```json
{
  "protocol": "org.aural.conformance.adapter",
  "protocol_version": 1,
  "case_id": "aural-core-reader/0.2-draft/valid-minimal",
  "operation": "verify-package",
  "input": {
    "role": "package",
    "path": "/checkout/tests/fixtures/conformance/valid-minimal.aural",
    "size": 549,
    "sha256": "aae82053118bedd4ab55c32322aeab7219ac2f4fced5847eee6d07215feda6a3"
  }
}
```

The request never contains the expected accept/reject result, an informative fixture reason, or a hint that the fixture is positive or negative. The runner verifies the manifest, fixture size, and fixture SHA-256 before starting any case. The adapter must pass the package at `input.path` to the implementation under test and decide its own outcome.

## 4. Response contract

For a supported request that completes, the response object has four required members and two optional members:

| Member | JSON type | Requirement |
|---|---|---|
| `protocol` | string | Required; exactly `org.aural.conformance.adapter`. |
| `protocol_version` | integer | Required; exactly `1`. |
| `case_id` | string | Required; exactly matches the request. |
| `outcome` | string | Required; exactly `accept` or `reject`. |
| `diagnostic` | object | Optional informative data; ignored for scoring. |
| `implementation` | object | Optional; one or both of `name` and `version`, each a nonempty string of at most 256 characters. No other members are allowed. |

No other top-level response members are allowed in protocol 1. `diagnostic`, when present, may contain ordinary JSON values, subject to strict parsing and the complete response-size limit. Diagnostics are never compared with manifest reasons and cannot change the score.

Accepted package:

```json
{"protocol":"org.aural.conformance.adapter","protocol_version":1,"case_id":"aural-core-reader/0.2-draft/valid-minimal","outcome":"accept"}
```

Controlled rejection:

```json
{"protocol":"org.aural.conformance.adapter","protocol_version":1,"case_id":"aural-core-reader/0.2-draft/invalid-asset-hash","outcome":"reject","diagnostic":{"message":"asset digest did not match"}}
```

A conforming adapter reports an implementation's controlled package rejection as `outcome: "reject"` and exits zero. It must not turn a verifier exception or error object that means “invalid package” into a process crash. Conversely, an adapter crash, an unexpected implementation failure, or an inability to run the verifier must not be disguised as `reject`.

## 5. Process and protocol errors

Exit status zero means that standard output is a complete protocol response. Any nonzero exit status means that the adapter did not produce a usable result; numeric nonzero values have no further portable meaning. On such an error, the adapter should write a short explanation to standard error and should not write a response to standard output.

The runner records `ERROR`, not `PASS`, when the process exits nonzero, cannot be started, produces malformed or oversized output, uses duplicate object keys, returns an unknown field or wrong field type, gives the wrong identifier/version/case ID, omits a required member, or reports an invalid outcome. It records `TIMEOUT` when the deadline is exceeded. Standard-error text is informative and is not a package rejection.

An adapter receiving an unknown protocol identifier, version, operation, or input role must fail explicitly with a nonzero exit status and a standard-error explanation. It must not guess, silently fall back, or return `reject`. A runner receiving a version-mismatched response records `ERROR`.

## 6. Scoring belongs to the runner

The adapter never receives the expected result. After validating a response, the runner compares `outcome` with `expected.outcome` in the published manifest:

- expected `accept`, observed `accept`: `PASS`;
- expected `reject`, observed `reject`: `PASS`;
- valid but different outcomes: `FAIL`;
- process or protocol failure: `ERROR`;
- deadline exceeded: `TIMEOUT`;
- explicitly unexecuted case: `SKIP`.

A correctly rejected negative case therefore passes. A crash on a negative case does not.

Core Reader 0.2 reports `PASS` only when all 30 required Draft 0.2 cases execute and pass. A required `ERROR`, `TIMEOUT`, `SKIP`, missing case, or wrong required inventory makes the profile `INCOMPLETE`. A valid incorrect required outcome makes it `FAIL` when required execution otherwise completed. The two optional Draft 0.1 cases are reported separately and never silently alter the Core Reader 0.2 result.

## 7. Security boundary

The adapter is executable code selected by the user. The runner is not a security sandbox. An untrusted adapter can access files, processes, credentials, network interfaces, and other resources allowed by the operating system and user account. The runner itself needs no network access, but it neither prevents nor claims to prevent adapter network access.

Do not pass secrets in adapter arguments: the supplied runner records its adapter argument vector for reproducibility. It does not record environment variables, credentials, adapter standard error, or arbitrary adapter diagnostics in its report.

## 8. Versioned extension model

The envelope separates protocol version, operation, case ID, and typed inputs so a later protocol revision can define additional operations. Candidate future operations include `verify-signed-event`, `verify-signed-event-graph`, `verify-excerpt-proof`, and `reproduce-acoustic-analysis`.

Those operations are reserved names only. Protocol 1 does not define or implement them and does not support provenance or graph conformance. Their input roles, ordering and multiplicity, normalized result semantics, resource policy, and diagnostic requirements require separately versioned specifications. An adapter must fail an attempted use explicitly as described in Section 5.
