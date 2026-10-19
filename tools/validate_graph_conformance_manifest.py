#!/usr/bin/env python3
"""Validate the public AURAL signed-event graph conformance manifest.

This offline validator checks metadata, source-inventory parity, fixture bytes,
and the portable representation of compressed resource collections.  It does
not import or implement an AURAL graph verifier.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any

try:
    from .validate_core_conformance_manifest import (
        DuplicateKeyError,
        FixtureRecord,
        MAX_FIXTURE_BYTES,
        SHA256_RE,
        ValidationError,
        _array,
        _integer,
        _mapping,
        _nonempty_string,
        _object_without_duplicates,
        _read_manifest,
        _reject_non_json_constant,
        _required,
        _require_equal,
        _string,
        _verify_fixture,
    )
except ImportError:  # Direct invocation: python tools/validate_...py
    from validate_core_conformance_manifest import (
        DuplicateKeyError,
        FixtureRecord,
        MAX_FIXTURE_BYTES,
        SHA256_RE,
        ValidationError,
        _array,
        _integer,
        _mapping,
        _nonempty_string,
        _object_without_duplicates,
        _read_manifest,
        _reject_non_json_constant,
        _required,
        _require_equal,
        _string,
        _verify_fixture,
    )


DEFAULT_MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "graph_conformance"
    / "graph-cases.v1.json"
)

SCHEMA = "urn:aural:conformance:signed-event-graph-cases"
SCHEMA_VERSION = 1
KIT_MANIFEST_VERSION = "1"
PROFILE_ID = "aural-signed-event-graph"
PROFILE_REVISION = "1"
PROFILE_STATUS = "experimental"
PROVENANCE_PROFILE_ID = "org.aural.signature.ed25519-jcs-v1"
CASE_COUNT = 35
ACCEPT_COUNT = 11
REJECT_COUNT = 24
MAX_EXPANDED_BUNDLE_BYTES = 16 * 1024 * 1024
HASH_CHUNK_BYTES = 64 * 1024

INPUT_ROLES = {"signed-event", "public-key-record", "subject-package"}
RESOURCE_TIERS = {"ordinary", "ordinary-compressed-boundary"}
EXPECTATION_LEVELS = {
    "normative",
    "experimental-profile-defined",
    "informative",
}
FAILURE_STAGES = {"input", "record", "graph", "key", "signature", "package"}
FAILURE_CATEGORIES = {
    "canonicalization",
    "duplicate_key",
    "encoding",
    "key_id_mismatch",
    "missing_key",
    "missing_parent",
    "package_integrity",
    "parent_digest_mismatch",
    "resource_limit",
    "signature",
    "subject_binding",
    "unsupported_algorithm",
    "utf8",
}
STABLE_CASE_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")

BOUNDARIES = {
    "H-parent-fanout-64": ("parent-references-per-event", 64, 64, "at-limit"),
    "N13-parent-fanout-65": ("parent-references-per-event", 64, 65, "over-limit"),
    "I-graph-depth-256": ("resolved-graph-depth", 256, 256, "at-limit"),
    "N14-graph-depth-257": ("resolved-graph-depth", 256, 257, "over-limit"),
    "H-event-bytes-at-limit": (
        "signed-event-record-bytes",
        1_048_576,
        1_048_576,
        "at-limit",
    ),
    "N-event-bytes-over-limit": (
        "signed-event-record-bytes",
        1_048_576,
        1_048_577,
        "over-limit",
    ),
    "H-event-count-4096": (
        "signed-event-input-records",
        4096,
        4096,
        "at-limit",
    ),
    "N-event-count-4097": (
        "signed-event-input-records",
        4096,
        4097,
        "over-limit",
    ),
}

MATERIALIZED_EVENTS = {
    "N18-noncanonical-signature-with-missing-parent": (
        "graph_conformance/materialized/"
        "n18-noncanonical-signature-with-missing-parent.json"
    ),
    "N19-noncanonical-signature-with-parent-digest-mismatch": (
        "graph_conformance/materialized/"
        "n19-noncanonical-signature-with-parent-digest-mismatch.json"
    ),
}


@dataclass(frozen=True)
class ValidationSummary:
    cases: int
    accepted_cases: int
    rejected_cases: int
    fixtures: int
    fixture_bytes: int
    case_inputs: int
    compressed_collections: int


def _boolean(mapping: dict[str, Any], name: str, context: str) -> bool:
    value = _required(mapping, name, context)
    if type(value) is not bool:
        raise ValidationError(f"{context}.{name} must be a boolean")
    return value


def _digest_and_size(record: dict[str, Any], context: str) -> tuple[str, int]:
    digest = _string(record, "sha256", context)
    if SHA256_RE.fullmatch(digest) is None:
        raise ValidationError(f"{context}.sha256 must be 64 lowercase hex digits")
    size = _integer(record, "size", context)
    if size < 0:
        raise ValidationError(f"{context}.size must not be negative")
    if size > MAX_FIXTURE_BYTES:
        raise ValidationError(
            f"{context}.size exceeds the {MAX_FIXTURE_BYTES}-byte safety limit"
        )
    return digest, size


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
    relative_path = _nonempty_string(record, "path", context)
    digest, size = _digest_and_size(record, context)
    return FixtureRecord(owner_id, relative_path, digest, size)


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


def _fixture_path(fixture_root: Path, fixture: FixtureRecord) -> Path:
    parts = PurePosixPath(fixture.relative_path.replace("\\", "/")).parts
    return fixture_root.joinpath(*parts)


def _strict_json_bytes(raw: bytes, context: str) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{context} is not valid UTF-8: {exc}") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_non_json_constant,
        )
    except (DuplicateKeyError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ValidationError(f"{context} is not valid strict JSON: {exc}") from exc


def _read_gzip_bundle(
    path: Path, fixture: FixtureRecord, context: str
) -> tuple[bytes, dict[str, Any]]:
    expanded = bytearray()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as compressed:
            opened = os.fstat(compressed.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ValidationError(f"{context} is not a regular file")
            if opened.st_size != fixture.size:
                raise ValidationError(f"{context} size changed while opening")

            compressed_digest = hashlib.sha256()
            compressed_count = 0
            while True:
                chunk = compressed.read(HASH_CHUNK_BYTES)
                if not chunk:
                    break
                compressed_count += len(chunk)
                if compressed_count > fixture.size:
                    raise ValidationError(f"{context} exceeds its declared size")
                compressed_digest.update(chunk)
            if compressed_count != fixture.size:
                raise ValidationError(f"{context} size changed while reading")
            if compressed_digest.hexdigest() != fixture.sha256:
                raise ValidationError(f"{context} SHA-256 changed while reading")

            compressed.seek(0)
            with gzip.GzipFile(fileobj=compressed, mode="rb") as source:
                while True:
                    chunk = source.read(HASH_CHUNK_BYTES)
                    if not chunk:
                        break
                    if len(expanded) + len(chunk) > MAX_EXPANDED_BUNDLE_BYTES:
                        raise ValidationError(
                            f"{context} exceeds the {MAX_EXPANDED_BUNDLE_BYTES}-byte "
                            "expanded-data safety limit"
                        )
                    expanded.extend(chunk)
    except ValidationError:
        raise
    except (OSError, EOFError) as exc:
        raise ValidationError(f"cannot decompress {context}: {exc}") from exc
    document = _mapping(_strict_json_bytes(bytes(expanded), context), context)
    return bytes(expanded), document


def _public_path(source_path: str) -> str:
    parts = list(PurePosixPath(source_path).parts)
    if parts[:2] == ["..", "provenance"]:
        return "provenance/" + "/".join(parts[2:])
    if parts[:2] == ["..", "conformance"]:
        return "conformance/" + "/".join(parts[2:])
    return "graph_conformance/" + "/".join(parts)


def _capability(source_case: dict[str, Any]) -> str:
    case_id = source_case["id"]
    category = source_case["expected"].get("error", {}).get("category")
    if source_case.get("package") is not None:
        return "aural-draft-0.2-subject-binding"
    if source_case.get("resource_bundle") is not None:
        return "graph-resource-limits"
    if case_id.startswith(("N17-", "N18-", "N19-")):
        return "canonical-signature-text"
    if case_id.startswith(("N20-", "N21-", "N22-")):
        return "deterministic-public-key-validation-order"
    if case_id.startswith(("N15-", "N16-")):
        return "deterministic-signed-event-validation-order"
    if category == "signature":
        return "ed25519-uncofactored-verification"
    if category in {"encoding", "key_id_mismatch", "duplicate_key", "missing_key"}:
        return "provenance-public-key-record-v1"
    return "signed-event-graph-verification"


def _expected_input_refs(
    source_case: dict[str, Any], source: dict[str, Any]
) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    case_id = source_case["id"]
    if "resource_bundle" in source_case:
        selection = source_case["resource_bundle"]
        path = source["bundles"][selection["bundle"]]["path"]
        result.append(("signed-event", f"graph_conformance/{path}"))
        key_aliases = source_case["public_keys"]
        for alias in key_aliases:
            result.append(("public-key-record", _public_path(source["public_keys"][alias])))
        return result

    if "diagnostic_input_construction" in source_case:
        construction = source_case["diagnostic_input_construction"]
        for event_index, descriptor in enumerate(construction["signed_events"]):
            if case_id in MATERIALIZED_EVENTS and event_index == 0:
                path = MATERIALIZED_EVENTS[case_id]
            else:
                path = _public_path(source["diagnostic_inputs"][descriptor["input"]]["path"])
            result.append(("signed-event", path))
        for alias in construction["public_keys"]:
            result.append((
                "public-key-record",
                _public_path(source["diagnostic_inputs"][alias]["path"]),
            ))
    else:
        for alias in source_case["signed_events"]:
            result.append(("signed-event", _public_path(source["events"][alias]["path"])))
        for alias in source_case["public_keys"]:
            result.append(("public-key-record", _public_path(source["public_keys"][alias])))
    if "package" in source_case:
        package = source["packages"][source_case["package"]]
        result.append(("subject-package", _public_path(package["path"])))
    return result


def _expected_result(
    source_case: dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    source_expected = source_case["expected"]
    expected: dict[str, Any] = {
        "outcome": "accept" if source_expected["accepted"] else "reject",
        "expectation_level": "experimental-profile-defined",
    }
    if not source_expected["accepted"]:
        expected["failure"] = dict(source_expected["error"])
        return expected

    graph = {
        key: value
        for key, value in source_expected.items()
        if key not in {"accepted", "ordered_events", "ordered_event_source"}
    }
    if "ordered_events" in source_expected:
        graph["ordered_events"] = [
            {
                "event_id": source["events"][alias]["event_id"],
                "signed_event_sha256": source["events"][alias][
                    "signed_event_sha256"
                ],
            }
            for alias in source_expected["ordered_events"]
        ]
    else:
        graph["ordered_events"] = {
            "derivation": "selected-collection-order",
            "event_id_pointer": "/assertion/event_id",
            "signed_event_sha256_algorithm": (
                "AURAL-SIGNED-EVENT-V1 domain-separated SHA-256"
            ),
        }
    expected["graph"] = graph
    return expected


def _validate_expected_shape(expected: dict[str, Any], context: str) -> None:
    outcome = _string(expected, "outcome", context)
    if outcome not in {"accept", "reject"}:
        raise ValidationError(f"{context}.outcome has invalid value {outcome!r}")
    level = _string(expected, "expectation_level", context)
    if level not in EXPECTATION_LEVELS:
        raise ValidationError(f"{context}.expectation_level has invalid value {level!r}")
    if outcome == "reject":
        failure = _mapping(_required(expected, "failure", context), f"{context}.failure")
        if set(failure) != {"category", "stage"}:
            raise ValidationError(
                f"{context}.failure must contain exactly category and stage"
            )
        category = _string(failure, "category", f"{context}.failure")
        stage = _string(failure, "stage", f"{context}.failure")
        if category not in FAILURE_CATEGORIES:
            raise ValidationError(
                f"{context}.failure.category has invalid value {category!r}"
            )
        if stage not in FAILURE_STAGES:
            raise ValidationError(f"{context}.failure.stage has invalid value {stage!r}")
        if "graph" in expected:
            raise ValidationError(f"{context}.graph is not valid for a rejected case")
        return

    graph = _mapping(_required(expected, "graph", context), f"{context}.graph")
    required_fields = {
        "status",
        "declared_parent_closure",
        "history_completeness",
        "package_integrity",
        "unique_event_count",
        "duplicate_input_count",
        "declared_parent_count",
        "maximum_depth",
        "ordered_events",
    }
    if set(graph) != required_fields:
        raise ValidationError(
            f"{context}.graph must contain exactly the normalized graph-result fields"
        )
    for field in (
        "unique_event_count",
        "duplicate_input_count",
        "declared_parent_count",
        "maximum_depth",
    ):
        value = _integer(graph, field, f"{context}.graph")
        if value < 0:
            raise ValidationError(f"{context}.graph.{field} must not be negative")
    for field in (
        "status",
        "declared_parent_closure",
        "history_completeness",
        "package_integrity",
    ):
        _nonempty_string(graph, field, f"{context}.graph")
    ordered = graph["ordered_events"]
    if type(ordered) not in {list, dict}:
        raise ValidationError(f"{context}.graph.ordered_events has invalid structure")


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
    expected_specification = {
        "title": "AURAL Experimental Signed-Event Graph Profile 1",
        "revision": PROFILE_REVISION,
        "status": PROFILE_STATUS,
        "path": "docs/SIGNED-EVENT-GRAPH-1-EXPERIMENTAL.md",
    }
    _require_equal(specification, expected_specification, "manifest.specification")

    profile = _mapping(_required(document, "profile", "manifest"), "manifest.profile")
    for field, value in {
        "id": PROFILE_ID,
        "revision": PROFILE_REVISION,
        "status": PROFILE_STATUS,
        "ordinary_case_count": CASE_COUNT,
        "accepted_case_count": ACCEPT_COUNT,
        "rejected_case_count": REJECT_COUNT,
    }.items():
        _require_equal(_required(profile, field, "manifest.profile"), value, f"manifest.profile.{field}")
    dependency = _mapping(
        _required(profile, "depends_on", "manifest.profile"),
        "manifest.profile.depends_on",
    )
    _require_equal(
        dependency,
        {"id": PROVENANCE_PROFILE_ID, "version": "1", "status": "experimental"},
        "manifest.profile.depends_on",
    )

    scope = _mapping(_required(document, "scope", "manifest"), "manifest.scope")
    _require_equal(
        _required(scope, "coverage", "manifest.scope"),
        "complete-active-ordinary-experimental-graph-case-inventory",
        "manifest.scope.coverage",
    )
    limitations = _array(
        _required(scope, "limitations", "manifest.scope"), "manifest.scope.limitations"
    )
    if not limitations:
        raise ValidationError("manifest.scope.limitations must not be empty")
    for index, value in enumerate(limitations):
        if type(value) is not str or not value.strip():
            raise ValidationError(
                f"manifest.scope.limitations[{index}] must be a nonempty string"
            )

    cases = _array(_required(document, "cases", "manifest"), "manifest.cases")
    source_index = _mapping(
        _required(document, "source_index", "manifest"), "manifest.source_index"
    )
    suites = _array(
        _required(document, "separate_resource_suites", "manifest"),
        "manifest.separate_resource_suites",
    )
    return cases, source_index, {"records": suites}


def _validate_source_index(
    raw: dict[str, Any],
    fixture_root: Path,
    fixtures: dict[str, FixtureRecord],
) -> dict[str, Any]:
    fixture = _fixture_record(raw, "manifest.source_index", "source-index", "source-case-index")
    _require_equal(
        fixture.relative_path,
        "graph_conformance/cases.json",
        "manifest.source_index.path",
    )
    _register_fixture(fixture_root, fixture, fixtures)
    source = _mapping(_read_manifest(_fixture_path(fixture_root, fixture)), "source index")
    _require_equal(
        _required(source, "schema", "source index"),
        "org.aural.graph-conformance-cases",
        "source index.schema",
    )
    _require_equal(
        _required(source, "schema_version", "source index"), "1", "source index.schema_version"
    )
    source_cases = _array(_required(source, "cases", "source index"), "source index.cases")
    if len(source_cases) != CASE_COUNT:
        raise ValidationError(
            f"source index must contain exactly {CASE_COUNT} cases, got {len(source_cases)}"
        )
    return source


def _validate_resource_representation(
    input_record: dict[str, Any],
    context: str,
    source_case: dict[str, Any],
    source: dict[str, Any],
    fixture: FixtureRecord,
    fixture_root: Path,
    bundle_cache: dict[str, tuple[bytes, dict[str, Any]]],
) -> None:
    _require_equal(
        _required(input_record, "occurrence", context),
        "ordered-collection",
        f"{context}.occurrence",
    )
    representation = _mapping(
        _required(input_record, "representation", context), f"{context}.representation"
    )
    selection = source_case["resource_bundle"]
    bundle_alias = selection["bundle"]
    source_bundle = source["bundles"][bundle_alias]
    _require_equal(
        fixture.relative_path,
        f"graph_conformance/{source_bundle['path']}",
        f"{context}.path",
    )
    _require_equal(fixture.sha256, source_bundle["sha256"], f"{context}.sha256")

    cached = bundle_cache.get(fixture.relative_path)
    if cached is None:
        cached = _read_gzip_bundle(
            _fixture_path(fixture_root, fixture),
            fixture,
            f"resource bundle {fixture.relative_path!r}",
        )
        bundle_cache[fixture.relative_path] = cached
    expanded, bundle = cached
    _require_equal(
        _required(bundle, "schema", "resource bundle"),
        "org.aural.graph-resource-fixtures",
        "resource bundle.schema",
    )
    _require_equal(
        _required(bundle, "schema_version", "resource bundle"),
        "1",
        "resource bundle.schema_version",
    )
    collections = _mapping(
        _required(bundle, "collections", "resource bundle"), "resource bundle.collections"
    )
    collection_name = selection["collection"]
    collection = _array(
        _required(collections, collection_name, "resource bundle.collections"),
        f"resource bundle.collections.{collection_name}",
    )
    for index, value in enumerate(collection):
        if type(value) is not str:
            raise ValidationError(
                f"resource bundle collection {collection_name!r}[{index}] must be a string"
            )

    count = selection.get("record_count", len(collection))
    if type(count) is not int or count <= 0 or count > len(collection):
        raise ValidationError(f"source case {source_case['id']!r} has invalid record_count")
    selected = [value.encode("utf-8") for value in collection[:count]]
    expected_representation = {
        "type": "gzip-json-string-collection",
        "compression": "gzip",
        "expanded_media_type": "application/json",
        "expanded_size": len(expanded),
        "expanded_sha256": hashlib.sha256(expanded).hexdigest(),
        "container_schema": "org.aural.graph-resource-fixtures",
        "container_schema_version": "1",
        "collection": collection_name,
        "selection": "all" if count == len(collection) else "prefix",
        "selected_record_count": count,
        "selected_aggregate_bytes": sum(map(len, selected)),
        "selected_maximum_record_bytes": max(map(len, selected)),
        "record_encoding": (
            "UTF-8 bytes of each selected JSON string, with no added separator or terminator"
        ),
    }
    _require_equal(representation, expected_representation, f"{context}.representation")


def _validate_case(
    raw_case: Any,
    index: int,
    source_case: dict[str, Any],
    source: dict[str, Any],
    fixture_root: Path,
    fixtures: dict[str, FixtureRecord],
    seen_ids: set[str],
    bundle_cache: dict[str, tuple[bytes, dict[str, Any]]],
) -> tuple[str, int, bool]:
    context = f"manifest.cases[{index}]"
    case = _mapping(raw_case, context)
    source_id = _nonempty_string(case, "source_case", context)
    _require_equal(source_id, source_case["id"], f"{context}.source_case")
    if STABLE_CASE_RE.fullmatch(source_id.lower()) is None:
        raise ValidationError(f"{context}.source_case is not a stable identifier")

    case_id = _nonempty_string(case, "id", context)
    if case_id in seen_ids:
        raise ValidationError(f"duplicate case ID {case_id!r}")
    seen_ids.add(case_id)
    _require_equal(
        case_id,
        f"{PROFILE_ID}/{PROFILE_REVISION}/{source_id.lower()}",
        f"{context}.id",
    )
    _require_equal(
        _required(case, "description", context), source_case["purpose"], f"{context}.description"
    )
    applicable = _mapping(
        _required(case, "applicable_profile", context), f"{context}.applicable_profile"
    )
    _require_equal(
        applicable,
        {"id": PROFILE_ID, "revision": PROFILE_REVISION, "status": PROFILE_STATUS},
        f"{context}.applicable_profile",
    )
    _require_equal(
        _required(case, "required_capability", context),
        _capability(source_case),
        f"{context}.required_capability",
    )
    tier = _string(case, "resource_tier", context)
    if tier not in RESOURCE_TIERS:
        raise ValidationError(f"{context}.resource_tier has invalid value {tier!r}")
    expected_tier = (
        "ordinary-compressed-boundary" if "resource_bundle" in source_case else "ordinary"
    )
    _require_equal(tier, expected_tier, f"{context}.resource_tier")

    raw_inputs = _array(_required(case, "inputs", context), f"{context}.inputs")
    actual_refs: list[tuple[str, str]] = []
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
        actual_refs.append((role, fixture.relative_path))
        if "resource_bundle" in source_case and input_index == 0:
            _require_equal(role, "signed-event", f"{input_context}.role")
            _validate_resource_representation(
                input_record,
                input_context,
                source_case,
                source,
                fixture,
                fixture_root,
                bundle_cache,
            )

    expected_refs = _expected_input_refs(source_case, source)
    if actual_refs != expected_refs:
        raise ValidationError(
            f"{context}.inputs do not match the required order and multiplicity for "
            f"source case {source_id!r}"
        )

    expected = _mapping(_required(case, "expected", context), f"{context}.expected")
    _validate_expected_shape(expected, f"{context}.expected")
    required_expected = _expected_result(source_case, source)
    if expected != required_expected:
        raise ValidationError(
            f"{context}.expected does not match source case {source_id!r}"
        )
    outcome = expected["outcome"]

    if "equivalent_to" in source_case:
        _require_equal(
            _required(case, "equivalent_to", context),
            f"{PROFILE_ID}/{PROFILE_REVISION}/{source_case['equivalent_to'].lower()}",
            f"{context}.equivalent_to",
        )
    elif "equivalent_to" in case:
        raise ValidationError(f"{context}.equivalent_to is not present in the source case")

    is_resource = source_id in BOUNDARIES
    if is_resource:
        boundary = _mapping(
            _required(case, "resource_boundary", context), f"{context}.resource_boundary"
        )
        dimension, limit, value, position = BOUNDARIES[source_id]
        _require_equal(
            boundary,
            {
                "dimension": dimension,
                "profile_limit": limit,
                "case_value": value,
                "position": position,
            },
            f"{context}.resource_boundary",
        )
    elif "resource_boundary" in case:
        raise ValidationError(f"{context}.resource_boundary is not applicable")
    return outcome, len(raw_inputs), is_resource


def _validate_separate_suite(
    suites: dict[str, Any],
    fixture_root: Path,
    fixtures: dict[str, FixtureRecord],
) -> None:
    records = suites["records"]
    if len(records) != 1:
        raise ValidationError("manifest.separate_resource_suites must contain exactly one suite")
    context = "manifest.separate_resource_suites[0]"
    suite = _mapping(records[0], context)
    _require_equal(
        _required(suite, "id", context),
        f"{PROFILE_ID}/{PROFILE_REVISION}/aggregate-event-bytes-64mib",
        f"{context}.id",
    )
    _require_equal(
        _required(suite, "resource_tier", context),
        "opt-in-large-generated",
        f"{context}.resource_tier",
    )
    _require_equal(
        _boolean(suite, "ordinary_case_inventory", context),
        False,
        f"{context}.ordinary_case_inventory",
    )
    _require_equal(
        _required(suite, "execution_environment", context),
        "AURAL_RUN_LARGE_GRAPH_BOUNDARY=1",
        f"{context}.execution_environment",
    )
    _nonempty_string(suite, "limitation", context)
    index = _mapping(_required(suite, "index", context), f"{context}.index")
    fixture = _fixture_record(index, f"{context}.index", suite["id"], "resource-suite-index")
    _require_equal(
        fixture.relative_path,
        "graph_conformance/aggregate-byte-limit-cases.json",
        f"{context}.index.path",
    )
    _register_fixture(fixture_root, fixture, fixtures)
    document = _mapping(_read_manifest(_fixture_path(fixture_root, fixture)), "aggregate suite index")
    _require_equal(
        _required(document, "schema", "aggregate suite index"),
        "org.aural.graph-aggregate-byte-limit-cases",
        "aggregate suite index.schema",
    )
    _require_equal(
        _required(document, "schema_version", "aggregate suite index"),
        "1",
        "aggregate suite index.schema_version",
    )
    aggregate_cases = _array(
        _required(document, "cases", "aggregate suite index"), "aggregate suite index.cases"
    )
    if len(aggregate_cases) != 2:
        raise ValidationError("aggregate suite index must contain exactly 2 cases")


def validate_manifest(manifest_path: Path) -> ValidationSummary:
    manifest_path = manifest_path.expanduser()
    document = _mapping(_read_manifest(manifest_path), "manifest")
    cases, source_index, suites = _validate_header(document)
    if len(cases) != CASE_COUNT:
        raise ValidationError(
            f"manifest.cases must contain exactly {CASE_COUNT} ordinary cases, got {len(cases)}"
        )

    try:
        fixture_root = manifest_path.parent.parent.resolve(strict=True)
    except OSError as exc:
        raise ValidationError(f"cannot resolve fixture directory: {exc}") from exc

    fixtures: dict[str, FixtureRecord] = {}
    source = _validate_source_index(source_index, fixture_root, fixtures)
    source_cases = _array(_required(source, "cases", "source index"), "source index.cases")
    seen_ids: set[str] = set()
    bundle_cache: dict[str, tuple[bytes, dict[str, Any]]] = {}
    accept_count = 0
    case_inputs = 0
    resource_count = 0
    for index, (raw_case, source_case) in enumerate(zip(cases, source_cases)):
        source_mapping = _mapping(source_case, f"source index.cases[{index}]")
        outcome, input_count, is_resource = _validate_case(
            raw_case,
            index,
            source_mapping,
            source,
            fixture_root,
            fixtures,
            seen_ids,
            bundle_cache,
        )
        accept_count += outcome == "accept"
        case_inputs += input_count
        resource_count += is_resource

    reject_count = len(cases) - accept_count
    if (accept_count, reject_count) != (ACCEPT_COUNT, REJECT_COUNT):
        raise ValidationError(
            "case distribution mismatch: expected "
            f"{ACCEPT_COUNT} accept/{REJECT_COUNT} reject, got "
            f"{accept_count} accept/{reject_count} reject"
        )
    if resource_count != len(BOUNDARIES):
        raise ValidationError(
            f"resource-boundary case count mismatch: expected {len(BOUNDARIES)}, got {resource_count}"
        )

    _validate_separate_suite(suites, fixture_root, fixtures)
    return ValidationSummary(
        cases=len(cases),
        accepted_cases=accept_count,
        rejected_cases=reject_count,
        fixtures=len(fixtures),
        fixture_bytes=sum(record.size for record in fixtures.values()),
        case_inputs=case_inputs,
        compressed_collections=resource_count,
    )


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the public AURAL signed-event graph conformance manifest."
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="manifest to validate (defaults to the committed public graph manifest)",
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
        f"OK: validated {summary.cases} graph cases "
        f"({summary.accepted_cases} accept/{summary.rejected_cases} reject), "
        f"{summary.case_inputs} ordered input descriptors, "
        f"{summary.compressed_collections} compressed resource selections, and "
        f"{summary.fixtures} unique fixtures ({summary.fixture_bytes} bytes); "
        "all sizes, SHA-256 digests, source expectations, ordering, and multiplicity match."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
