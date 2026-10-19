#!/usr/bin/env python3
"""Validate the public AURAL provenance conformance manifest.

This is an offline metadata and fixture-integrity check.  It does not parse
signed events, verify Ed25519 signatures, or import an AURAL verifier.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys
from typing import Any

try:
    from .validate_core_conformance_manifest import (
        FixtureRecord,
        MAX_FIXTURE_BYTES,
        SHA256_RE,
        ValidationError,
        _array,
        _integer,
        _mapping,
        _nonempty_string,
        _read_manifest,
        _required,
        _require_equal,
        _string,
        _verify_fixture,
    )
except ImportError:  # Direct invocation: python tools/validate_...py
    from validate_core_conformance_manifest import (
        FixtureRecord,
        MAX_FIXTURE_BYTES,
        SHA256_RE,
        ValidationError,
        _array,
        _integer,
        _mapping,
        _nonempty_string,
        _read_manifest,
        _required,
        _require_equal,
        _string,
        _verify_fixture,
    )


DEFAULT_MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "provenance"
    / "provenance-cases.v1.json"
)

SCHEMA = "urn:aural:conformance:provenance-cases"
SCHEMA_VERSION = 1
KIT_MANIFEST_VERSION = "1"
PROFILE_ID = "org.aural.signature.ed25519-jcs-v1"
PROFILE_VERSION = "1"
PROFILE_STATUS = "experimental"
CASE_COUNT = 45
ACCEPT_COUNT = 3
REJECT_COUNT = 42
VECTOR_COUNT = 13
VECTOR_ACCEPT_COUNT = 1
VECTOR_REJECT_COUNT = 12
VECTOR_POLICY = (
    "canonical points; reject small-order A and R; S < L; uncofactored equation"
)
REQUIRED_CAPABILITIES = (
    "strict-json-and-jcs",
    "ed25519-uncofactored-verification",
    "provenance-public-key-record-v1",
    "aural-draft-0.2-subject-binding",
    "signed-event-parent-references",
)

STABLE_NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
LOWER_HEX_RE = re.compile(r"[0-9a-f]*\Z")
INPUT_ROLES = {"signed-event", "public-key-record", "subject-package"}


@dataclass(frozen=True)
class ValidationSummary:
    cases: int
    accepted_cases: int
    rejected_cases: int
    vectors: int
    accepted_vectors: int
    rejected_vectors: int
    fixtures: int
    fixture_bytes: int
    case_inputs: int


def _boolean(mapping: dict[str, Any], name: str, context: str) -> bool:
    value = _required(mapping, name, context)
    if type(value) is not bool:
        raise ValidationError(f"{context}.{name} must be a boolean")
    return value


def _validate_digest_size(record: dict[str, Any], context: str) -> tuple[str, int]:
    sha256 = _string(record, "sha256", context)
    if SHA256_RE.fullmatch(sha256) is None:
        raise ValidationError(f"{context}.sha256 must be 64 lowercase hex digits")
    size = _integer(record, "size", context)
    if size < 0:
        raise ValidationError(f"{context}.size must not be negative")
    if size > MAX_FIXTURE_BYTES:
        raise ValidationError(
            f"{context}.size exceeds the {MAX_FIXTURE_BYTES}-byte safety limit"
        )
    return sha256, size


def _fixture_record(
    raw: Any,
    context: str,
    owner_id: str,
    expected_role: str | None = None,
) -> FixtureRecord:
    record = _mapping(raw, context)
    role = _string(record, "role", context)
    if expected_role is not None:
        _require_equal(role, expected_role, f"{context}.role")
    path = _nonempty_string(record, "path", context)
    sha256, size = _validate_digest_size(record, context)
    return FixtureRecord(owner_id, path, sha256, size)


def _register_fixture(
    fixture_root: Path,
    fixture: FixtureRecord,
    fixtures: dict[str, FixtureRecord],
) -> None:
    previous = fixtures.get(fixture.relative_path)
    if previous is not None:
        if (previous.sha256, previous.size) != (fixture.sha256, fixture.size):
            raise ValidationError(
                f"conflicting metadata for fixture {fixture.relative_path!r}"
            )
        return
    _verify_fixture(fixture_root, fixture)
    fixtures[fixture.relative_path] = fixture


def _validate_header(document: dict[str, Any]) -> tuple[list[Any], dict[str, Any], dict[str, Any]]:
    _require_equal(_required(document, "schema", "manifest"), SCHEMA, "manifest.schema")
    _require_equal(
        _required(document, "schema_version", "manifest"),
        SCHEMA_VERSION,
        "manifest.schema_version",
    )
    _require_equal(
        _required(document, "kit_manifest_version", "manifest"),
        KIT_MANIFEST_VERSION,
        "manifest.kit_manifest_version",
    )
    _require_equal(
        _required(document, "path_base", "manifest"),
        "tests/fixtures",
        "manifest.path_base",
    )

    specification = _mapping(
        _required(document, "specification", "manifest"), "manifest.specification"
    )
    _require_equal(
        _required(specification, "title", "manifest.specification"),
        "AURAL Experimental Provenance Signature Profile 1",
        "manifest.specification.title",
    )
    _require_equal(
        _required(specification, "version", "manifest.specification"),
        PROFILE_VERSION,
        "manifest.specification.version",
    )
    _require_equal(
        _required(specification, "status", "manifest.specification"),
        PROFILE_STATUS,
        "manifest.specification.status",
    )
    _require_equal(
        _required(specification, "path", "manifest.specification"),
        "docs/PROVENANCE-SIGNATURE-1-DRAFT.md",
        "manifest.specification.path",
    )

    profile = _mapping(_required(document, "profile", "manifest"), "manifest.profile")
    expected_profile_fields = {
        "id": PROFILE_ID,
        "version": PROFILE_VERSION,
        "status": PROFILE_STATUS,
        "event_schema": "org.aural.provenance-event",
        "event_schema_version": "1",
        "case_count": CASE_COUNT,
        "accepted_case_count": ACCEPT_COUNT,
        "rejected_case_count": REJECT_COUNT,
        "ed25519_vector_count": VECTOR_COUNT,
    }
    for field, expected in expected_profile_fields.items():
        _require_equal(
            _required(profile, field, "manifest.profile"),
            expected,
            f"manifest.profile.{field}",
        )
    capabilities = _array(
        _required(profile, "required_capabilities", "manifest.profile"),
        "manifest.profile.required_capabilities",
    )
    _require_equal(
        tuple(capabilities), REQUIRED_CAPABILITIES, "manifest.profile.required_capabilities"
    )

    scope = _mapping(_required(document, "scope", "manifest"), "manifest.scope")
    _nonempty_string(scope, "coverage", "manifest.scope")
    limitations = _array(
        _required(scope, "limitations", "manifest.scope"), "manifest.scope.limitations"
    )
    for index, limitation in enumerate(limitations):
        if type(limitation) is not str or not limitation.strip():
            raise ValidationError(
                f"manifest.scope.limitations[{index}] must be a nonempty string"
            )

    cases = _array(_required(document, "cases", "manifest"), "manifest.cases")
    source_index = _mapping(
        _required(document, "source_index", "manifest"), "manifest.source_index"
    )
    vectors = _mapping(
        _required(document, "ed25519_vectors", "manifest"), "manifest.ed25519_vectors"
    )
    return cases, source_index, vectors


def _load_indexed_fixture(
    fixture_root: Path,
    raw_record: Any,
    context: str,
    expected_role: str,
    fixtures: dict[str, FixtureRecord],
) -> tuple[FixtureRecord, dict[str, Any]]:
    fixture = _fixture_record(raw_record, context, context, expected_role)
    _register_fixture(fixture_root, fixture, fixtures)
    path = fixture_root.joinpath(*fixture.relative_path.replace("\\", "/").split("/"))
    document = _mapping(_read_manifest(path), context)
    return fixture, document


def _source_case_inputs(source_case: dict[str, Any], context: str) -> list[tuple[str, str]]:
    event = _nonempty_string(source_case, "event", context)
    keys = _array(_required(source_case, "keys", context), f"{context}.keys")
    result = [("signed-event", f"provenance/{event}")]
    for index, key in enumerate(keys):
        if type(key) is not str or not key:
            raise ValidationError(f"{context}.keys[{index}] must be a nonempty string")
        result.append(("public-key-record", f"provenance/{key}"))

    package = _nonempty_string(source_case, "package", context)
    prefix = "../conformance/"
    if not package.startswith(prefix) or package[len(prefix) :] in {"", ".", ".."}:
        raise ValidationError(f"{context}.package has an unsupported source alias")
    result.append(("subject-package", f"conformance/{package[len(prefix):]}"))
    return result


def _validate_case(
    raw_case: Any,
    index: int,
    fixture_root: Path,
    source_cases: dict[str, Any],
    fixtures: dict[str, FixtureRecord],
    seen_ids: set[str],
    seen_source_cases: set[str],
) -> tuple[str, int]:
    context = f"manifest.cases[{index}]"
    case = _mapping(raw_case, context)
    case_id = _nonempty_string(case, "id", context)
    if case_id in seen_ids:
        raise ValidationError(f"duplicate case ID {case_id!r}")
    seen_ids.add(case_id)

    source_reference = _nonempty_string(case, "source_case", context)
    if STABLE_NAME_RE.fullmatch(source_reference) is None:
        raise ValidationError(f"{context}.source_case is not a stable identifier")
    if source_reference in seen_source_cases:
        raise ValidationError(f"duplicate source case reference {source_reference!r}")
    if source_reference not in source_cases:
        raise ValidationError(f"invalid source case reference {source_reference!r}")
    seen_source_cases.add(source_reference)
    _require_equal(
        case_id,
        f"aural-provenance/1/{source_reference}",
        f"{context}.id",
    )
    _require_equal(_required(case, "status", context), "required", f"{context}.status")

    applicable = _mapping(
        _required(case, "applicable_profile", context), f"{context}.applicable_profile"
    )
    _require_equal(
        _required(applicable, "id", f"{context}.applicable_profile"),
        PROFILE_ID,
        f"{context}.applicable_profile.id",
    )
    _require_equal(
        _required(applicable, "version", f"{context}.applicable_profile"),
        PROFILE_VERSION,
        f"{context}.applicable_profile.version",
    )

    raw_inputs = _array(_required(case, "inputs", context), f"{context}.inputs")
    actual_inputs: list[tuple[str, str]] = []
    for input_index, raw_input in enumerate(raw_inputs):
        input_context = f"{context}.inputs[{input_index}]"
        input_record = _mapping(raw_input, input_context)
        _require_equal(
            _required(input_record, "order", input_context),
            input_index,
            f"{input_context}.order",
        )
        role = _string(input_record, "role", input_context)
        if role not in INPUT_ROLES:
            raise ValidationError(f"{input_context}.role has invalid value {role!r}")
        fixture = _fixture_record(input_record, input_context, case_id)
        _register_fixture(fixture_root, fixture, fixtures)
        actual_inputs.append((role, fixture.relative_path))

    source_case = _mapping(source_cases[source_reference], f"source case {source_reference!r}")
    expected_inputs = _source_case_inputs(source_case, f"source case {source_reference!r}")
    if actual_inputs != expected_inputs:
        raise ValidationError(
            f"{context}.inputs do not match the required ordered inputs for "
            f"source case {source_reference!r}"
        )

    expected = _mapping(_required(case, "expected", context), f"{context}.expected")
    outcome = _string(expected, "outcome", f"{context}.expected")
    if outcome not in {"accept", "reject"}:
        raise ValidationError(f"{context}.expected.outcome has invalid value {outcome!r}")
    _require_equal(
        outcome,
        _required(source_case, "outcome", f"source case {source_reference!r}"),
        f"{context}.expected.outcome",
    )
    _require_equal(
        _required(case, "informative_reason", context),
        _required(source_case, "reason", f"source case {source_reference!r}"),
        f"{context}.informative_reason",
    )
    return outcome, len(raw_inputs)


def _validate_hex(value: Any, octets: int | None, context: str) -> None:
    if type(value) is not str or LOWER_HEX_RE.fullmatch(value) is None or len(value) % 2:
        raise ValidationError(f"{context} must be lowercase, even-length hexadecimal")
    if octets is not None and len(value) != octets * 2:
        raise ValidationError(f"{context} must encode exactly {octets} bytes")


def _validate_vectors(
    vector_manifest: dict[str, Any],
    fixture_root: Path,
    fixtures: dict[str, FixtureRecord],
) -> tuple[int, int]:
    context = "manifest.ed25519_vectors"
    _require_equal(
        _required(vector_manifest, "signature_policy", context),
        VECTOR_POLICY,
        f"{context}.signature_policy",
    )
    _, source_document = _load_indexed_fixture(
        fixture_root,
        _required(vector_manifest, "source_file", context),
        f"{context}.source_file",
        "ed25519-vector-set",
        fixtures,
    )
    _require_equal(
        _required(source_document, "policy", "Ed25519 vector file"),
        VECTOR_POLICY,
        "Ed25519 vector file.policy",
    )
    _nonempty_string(source_document, "source", "Ed25519 vector file")
    _nonempty_string(source_document, "source_license", "Ed25519 vector file")
    source_vectors = _array(
        _required(source_document, "vectors", "Ed25519 vector file"),
        "Ed25519 vector file.vectors",
    )
    if len(source_vectors) != VECTOR_COUNT:
        raise ValidationError(
            f"Ed25519 vector file must contain exactly {VECTOR_COUNT} vectors, "
            f"got {len(source_vectors)}"
        )

    records = _array(_required(vector_manifest, "records", context), f"{context}.records")
    if len(records) != VECTOR_COUNT:
        raise ValidationError(
            f"{context}.records must contain exactly {VECTOR_COUNT} vectors, got {len(records)}"
        )

    seen_ids: set[str] = set()
    seen_references: set[str] = set()
    accept_count = 0
    for index, (raw_record, raw_source) in enumerate(zip(records, source_vectors)):
        record_context = f"{context}.records[{index}]"
        source_context = f"Ed25519 vector file.vectors[{index}]"
        record = _mapping(raw_record, record_context)
        source = _mapping(raw_source, source_context)
        required_source_fields = {
            "name", "classification", "expected", "message", "public_key", "signature"
        }
        if set(source) != required_source_fields:
            raise ValidationError(f"{source_context} has invalid fields")
        name = _nonempty_string(source, "name", source_context)
        if STABLE_NAME_RE.fullmatch(name) is None:
            raise ValidationError(f"{source_context}.name is not a stable identifier")
        _nonempty_string(source, "classification", source_context)
        source_expected = _boolean(source, "expected", source_context)
        _validate_hex(_required(source, "message", source_context), None, f"{source_context}.message")
        _validate_hex(
            _required(source, "public_key", source_context), 32, f"{source_context}.public_key"
        )
        _validate_hex(
            _required(source, "signature", source_context), 64, f"{source_context}.signature"
        )

        record_id = _nonempty_string(record, "id", record_context)
        if record_id in seen_ids:
            raise ValidationError(f"duplicate Ed25519 vector ID {record_id!r}")
        seen_ids.add(record_id)
        _require_equal(record_id, f"aural-ed25519-policy/1/{name}", f"{record_context}.id")
        reference = _nonempty_string(record, "source_record", record_context)
        if reference in seen_references:
            raise ValidationError(f"duplicate Ed25519 vector reference {reference!r}")
        seen_references.add(reference)
        _require_equal(reference, name, f"{record_context}.source_record")
        _require_equal(
            _required(record, "json_pointer", record_context),
            f"/vectors/{index}",
            f"{record_context}.json_pointer",
        )
        expected = _mapping(
            _required(record, "expected", record_context), f"{record_context}.expected"
        )
        outcome = _string(expected, "outcome", f"{record_context}.expected")
        if outcome not in {"accept", "reject"}:
            raise ValidationError(
                f"{record_context}.expected.outcome has invalid value {outcome!r}"
            )
        required_outcome = "accept" if source_expected else "reject"
        _require_equal(outcome, required_outcome, f"{record_context}.expected.outcome")
        accept_count += outcome == "accept"

    reject_count = len(records) - accept_count
    if (accept_count, reject_count) != (VECTOR_ACCEPT_COUNT, VECTOR_REJECT_COUNT):
        raise ValidationError(
            "Ed25519 vector distribution mismatch: expected "
            f"{VECTOR_ACCEPT_COUNT} accept/{VECTOR_REJECT_COUNT} reject, got "
            f"{accept_count} accept/{reject_count} reject"
        )
    return accept_count, reject_count


def validate_manifest(manifest_path: Path) -> ValidationSummary:
    manifest_path = manifest_path.expanduser()
    document = _mapping(_read_manifest(manifest_path), "manifest")
    cases, raw_source_index, vector_manifest = _validate_header(document)
    if len(cases) != CASE_COUNT:
        raise ValidationError(
            f"manifest.cases must contain exactly {CASE_COUNT} cases, got {len(cases)}"
        )

    try:
        fixture_root = manifest_path.parent.parent.resolve(strict=True)
    except OSError as exc:
        raise ValidationError(f"cannot resolve tests/fixtures path base: {exc}") from exc

    fixtures: dict[str, FixtureRecord] = {}
    _, source_index = _load_indexed_fixture(
        fixture_root,
        raw_source_index,
        "manifest.source_index",
        "source-case-index",
        fixtures,
    )
    source_cases = _mapping(
        _required(source_index, "cases", "source index"), "source index.cases"
    )
    if len(source_cases) != CASE_COUNT:
        raise ValidationError(
            f"source index.cases must contain exactly {CASE_COUNT} cases, got {len(source_cases)}"
        )

    seen_ids: set[str] = set()
    seen_source_cases: set[str] = set()
    accept_count = 0
    case_inputs = 0
    for index, raw_case in enumerate(cases):
        outcome, input_count = _validate_case(
            raw_case,
            index,
            fixture_root,
            source_cases,
            fixtures,
            seen_ids,
            seen_source_cases,
        )
        accept_count += outcome == "accept"
        case_inputs += input_count

    missing_references = set(source_cases) - seen_source_cases
    if missing_references:
        raise ValidationError(
            f"missing source case references: {sorted(missing_references)!r}"
        )
    reject_count = len(cases) - accept_count
    if (accept_count, reject_count) != (ACCEPT_COUNT, REJECT_COUNT):
        raise ValidationError(
            f"case distribution mismatch: expected {ACCEPT_COUNT} accept/{REJECT_COUNT} "
            f"reject, got {accept_count} accept/{reject_count} reject"
        )

    vector_accepts, vector_rejects = _validate_vectors(
        vector_manifest, fixture_root, fixtures
    )
    return ValidationSummary(
        cases=len(cases),
        accepted_cases=accept_count,
        rejected_cases=reject_count,
        vectors=VECTOR_COUNT,
        accepted_vectors=vector_accepts,
        rejected_vectors=vector_rejects,
        fixtures=len(fixtures),
        fixture_bytes=sum(item.size for item in fixtures.values()),
        case_inputs=case_inputs,
    )


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the public AURAL provenance conformance manifest."
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="manifest to validate (defaults to the committed public manifest)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    try:
        summary = validate_manifest(arguments.manifest)
    except ValidationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        f"OK: validated {summary.cases} provenance cases "
        f"({summary.accepted_cases} accept/{summary.rejected_cases} reject), "
        f"{summary.vectors} Ed25519 vectors "
        f"({summary.accepted_vectors} accept/{summary.rejected_vectors} reject), and "
        f"{summary.fixtures} unique files across {summary.case_inputs} ordered case inputs "
        f"({summary.fixture_bytes} bytes); all sizes and SHA-256 digests match."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
