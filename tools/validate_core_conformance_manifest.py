#!/usr/bin/env python3
"""Validate the published AURAL Core Reader conformance case manifest.

This tool checks the test-kit inventory and its fixture bytes.  It deliberately
does not parse AURAL containers or implement any part of the AURAL format.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import sys
from typing import Any


DEFAULT_MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "conformance"
    / "core-reader-0.2-cases.v1.json"
)
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FIXTURE_BYTES = 1024 * 1024 * 1024
HASH_CHUNK_BYTES = 64 * 1024

SCHEMA = "urn:aural:conformance:core-reader-cases"
SCHEMA_VERSION = 1
KIT_MANIFEST_VERSION = "1"
PROFILE_ID = "aural-core-reader"
PROFILE_VERSION = "0.2-draft"
PROFILE_STATUS = "draft"
REQUIRED_CASES = 33
OPTIONAL_CASES = 2
TOTAL_CASES = REQUIRED_CASES + OPTIONAL_CASES

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
CASE_NAME_RE = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*\Z")


class ValidationError(Exception):
    """A manifest or fixture integrity check failed."""


class DuplicateKeyError(ValueError):
    """JSON decoding encountered a duplicate object key."""


@dataclass(frozen=True)
class FixtureRecord:
    case_id: str
    relative_path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class ValidationSummary:
    cases: int
    fixtures: int
    fixture_bytes: int
    required_accept: int
    required_reject: int
    optional_accept: int


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant {value!r}")


def _read_manifest(path: Path) -> Any:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise ValidationError(f"cannot stat manifest {path}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ValidationError(f"manifest is not a regular file: {path}")
    if metadata.st_size > MAX_MANIFEST_BYTES:
        raise ValidationError(
            f"manifest exceeds the {MAX_MANIFEST_BYTES}-byte safety limit"
        )

    try:
        with path.open("rb") as source:
            raw = source.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise ValidationError(f"cannot read manifest {path}: {exc}") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValidationError(
            f"manifest exceeds the {MAX_MANIFEST_BYTES}-byte safety limit"
        )

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"manifest is not valid UTF-8: {exc}") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_non_json_constant,
        )
    except (DuplicateKeyError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ValidationError(f"manifest is not valid strict JSON: {exc}") from exc


def _mapping(value: Any, context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValidationError(f"{context} must be a JSON object")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if type(value) is not list:
        raise ValidationError(f"{context} must be a JSON array")
    return value


def _required(mapping: dict[str, Any], name: str, context: str) -> Any:
    if name not in mapping:
        raise ValidationError(f"{context} is missing required field {name!r}")
    return mapping[name]


def _string(mapping: dict[str, Any], name: str, context: str) -> str:
    value = _required(mapping, name, context)
    if type(value) is not str:
        raise ValidationError(f"{context}.{name} must be a string")
    return value


def _nonempty_string(mapping: dict[str, Any], name: str, context: str) -> str:
    value = _string(mapping, name, context)
    if not value.strip():
        raise ValidationError(f"{context}.{name} must not be empty")
    return value


def _integer(mapping: dict[str, Any], name: str, context: str) -> int:
    value = _required(mapping, name, context)
    if type(value) is not int:
        raise ValidationError(f"{context}.{name} must be an integer")
    return value


def _require_equal(actual: Any, expected: Any, context: str) -> None:
    if actual != expected or type(actual) is not type(expected):
        raise ValidationError(f"{context} must be {expected!r}, got {actual!r}")


def _validate_header(document: dict[str, Any]) -> list[Any]:
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

    specification = _mapping(
        _required(document, "specification", "manifest"), "manifest.specification"
    )
    _require_equal(
        _required(specification, "title", "manifest.specification"),
        "AURAL Audio Evidence Container — Draft 0.2",
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
        "../../../docs/SPECIFICATION-0.2-DRAFT.md",
        "manifest.specification.path",
    )

    profile = _mapping(_required(document, "profile", "manifest"), "manifest.profile")
    _require_equal(
        _required(profile, "id", "manifest.profile"), PROFILE_ID, "manifest.profile.id"
    )
    _require_equal(
        _required(profile, "version", "manifest.profile"),
        PROFILE_VERSION,
        "manifest.profile.version",
    )
    _require_equal(
        _required(profile, "status", "manifest.profile"),
        PROFILE_STATUS,
        "manifest.profile.status",
    )
    _require_equal(
        _required(profile, "required_case_count", "manifest.profile"),
        REQUIRED_CASES,
        "manifest.profile.required_case_count",
    )
    _require_equal(
        _required(profile, "optional_case_count", "manifest.profile"),
        OPTIONAL_CASES,
        "manifest.profile.optional_case_count",
    )

    scope = _mapping(_required(document, "scope", "manifest"), "manifest.scope")
    _nonempty_string(scope, "coverage", "manifest.scope")
    limitations = _array(
        _required(scope, "limitations", "manifest.scope"),
        "manifest.scope.limitations",
    )
    for index, limitation in enumerate(limitations):
        if type(limitation) is not str or not limitation.strip():
            raise ValidationError(
                f"manifest.scope.limitations[{index}] must be a nonempty string"
            )

    return _array(_required(document, "cases", "manifest"), "manifest.cases")


def _validate_case(
    raw_case: Any,
    index: int,
    seen_ids: set[str],
    seen_paths: set[str],
) -> tuple[FixtureRecord, str, str]:
    context = f"manifest.cases[{index}]"
    case = _mapping(raw_case, context)
    case_id = _nonempty_string(case, "id", context)
    if case_id in seen_ids:
        raise ValidationError(f"duplicate case ID {case_id!r}")
    seen_ids.add(case_id)

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

    status = _string(case, "status", context)
    target_version = _string(case, "target_format_version", context)
    if status == "required":
        _require_equal(target_version, PROFILE_VERSION, f"{context}.target_format_version")
        id_group = "0.2-draft"
    elif status == "optional":
        _require_equal(target_version, "0.1-draft", f"{context}.target_format_version")
        _require_equal(
            _required(case, "optional_capability", context),
            "draft-0.1-legacy-reading",
            f"{context}.optional_capability",
        )
        id_group = "legacy-0.1-optional"
    else:
        raise ValidationError(f"{context}.status has invalid value {status!r}")

    input_record = _mapping(_required(case, "input", context), f"{context}.input")
    _require_equal(
        _required(input_record, "role", f"{context}.input"),
        "package",
        f"{context}.input.role",
    )
    relative_path = _nonempty_string(input_record, "path", f"{context}.input")
    sha256 = _string(input_record, "sha256", f"{context}.input")
    if SHA256_RE.fullmatch(sha256) is None:
        raise ValidationError(f"{context}.input.sha256 must be 64 lowercase hex digits")
    size = _integer(input_record, "size", f"{context}.input")
    if size < 0:
        raise ValidationError(f"{context}.input.size must not be negative")
    if size > MAX_FIXTURE_BYTES:
        raise ValidationError(
            f"{context}.input.size exceeds the {MAX_FIXTURE_BYTES}-byte safety limit"
        )
    if relative_path in seen_paths:
        raise ValidationError(f"duplicate fixture path {relative_path!r}")
    seen_paths.add(relative_path)

    normalized_name = relative_path.replace("\\", "/").rsplit("/", 1)[-1]
    fixture_name = normalized_name[:-6] if normalized_name.endswith(".aural") else ""
    if CASE_NAME_RE.fullmatch(fixture_name) is None:
        raise ValidationError(f"{context}.input.path does not name a stable .aural fixture")
    expected_id = f"{PROFILE_ID}/{id_group}/{fixture_name}"
    if case_id != expected_id:
        raise ValidationError(
            f"{context}.id must be the stable fixture ID {expected_id!r}"
        )

    expected = _mapping(_required(case, "expected", context), f"{context}.expected")
    outcome = _string(expected, "outcome", f"{context}.expected")
    if outcome not in {"accept", "reject"}:
        raise ValidationError(f"{context}.expected.outcome has invalid value {outcome!r}")
    indexed_outcome = _string(expected, "indexed_outcome", f"{context}.expected")
    if status == "optional":
        _require_equal(outcome, "accept", f"{context}.expected.outcome")
        required_indexed_outcome = "accept-legacy-0.1"
    elif outcome == "accept":
        required_indexed_outcome = "accept-0.2"
    else:
        required_indexed_outcome = "reject"
    _require_equal(
        indexed_outcome,
        required_indexed_outcome,
        f"{context}.expected.indexed_outcome",
    )

    # This text is descriptive only.  It is deliberately not parsed as a
    # normative diagnostic code or matched to any implementation error.
    _nonempty_string(case, "informative_reason", context)
    _require_equal(
        _required(case, "resource_tier", context),
        "ordinary",
        f"{context}.resource_tier",
    )

    return FixtureRecord(case_id, relative_path, sha256, size), status, outcome


def _safe_fixture_path(fixture_root: Path, record: FixtureRecord) -> Path:
    raw_path = record.relative_path
    if "\x00" in raw_path:
        raise ValidationError(f"fixture path for {record.case_id!r} contains NUL")
    posix_path = PurePosixPath(raw_path)
    windows_path = PureWindowsPath(raw_path)
    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or bool(windows_path.root)
    ):
        raise ValidationError(f"fixture path for {record.case_id!r} must be relative")

    parts = PurePosixPath(raw_path.replace("\\", "/")).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValidationError(
            f"fixture path for {record.case_id!r} contains unsafe traversal"
        )
    candidate = fixture_root.joinpath(*parts)

    current = fixture_root
    try:
        for part in parts:
            current = current / part
            if stat.S_ISLNK(current.lstat().st_mode):
                raise ValidationError(
                    f"fixture path for {record.case_id!r} contains a symbolic link"
                )
        resolved = candidate.resolve(strict=True)
    except ValidationError:
        raise
    except FileNotFoundError as exc:
        raise ValidationError(
            f"fixture for {record.case_id!r} does not exist: {raw_path}"
        ) from exc
    except OSError as exc:
        raise ValidationError(
            f"cannot resolve fixture for {record.case_id!r}: {exc}"
        ) from exc

    try:
        resolved.relative_to(fixture_root)
    except ValueError as exc:
        raise ValidationError(
            f"fixture path for {record.case_id!r} escapes the fixture directory"
        ) from exc
    return resolved


def _verify_fixture(fixture_root: Path, record: FixtureRecord) -> int:
    path = _safe_fixture_path(fixture_root, record)
    try:
        before = path.stat()
    except OSError as exc:
        raise ValidationError(f"cannot stat fixture {record.relative_path!r}: {exc}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ValidationError(f"fixture {record.relative_path!r} is not a regular file")
    if before.st_size != record.size:
        raise ValidationError(
            f"fixture {record.relative_path!r} size mismatch: "
            f"declared {record.size}, actual {before.st_size}"
        )

    digest = hashlib.sha256()
    byte_count = 0
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            opened = os.fstat(source.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ValidationError(
                    f"fixture {record.relative_path!r} is not a regular file"
                )
            if opened.st_size != record.size:
                raise ValidationError(
                    f"fixture {record.relative_path!r} size changed while opening"
                )
            while True:
                chunk = source.read(HASH_CHUNK_BYTES)
                if not chunk:
                    break
                byte_count += len(chunk)
                if byte_count > MAX_FIXTURE_BYTES:
                    raise ValidationError(
                        f"fixture {record.relative_path!r} exceeds the safety limit"
                    )
                digest.update(chunk)
    except ValidationError:
        raise
    except OSError as exc:
        raise ValidationError(f"cannot read fixture {record.relative_path!r}: {exc}") from exc

    if byte_count != record.size:
        raise ValidationError(
            f"fixture {record.relative_path!r} size mismatch while reading: "
            f"declared {record.size}, read {byte_count}"
        )
    actual_digest = digest.hexdigest()
    if actual_digest != record.sha256:
        raise ValidationError(
            f"fixture {record.relative_path!r} SHA-256 mismatch: "
            f"declared {record.sha256}, actual {actual_digest}"
        )
    return byte_count


def validate_manifest(manifest_path: Path) -> ValidationSummary:
    manifest_path = manifest_path.expanduser()
    document = _mapping(_read_manifest(manifest_path), "manifest")
    cases = _validate_header(document)
    if len(cases) != TOTAL_CASES:
        raise ValidationError(
            f"manifest.cases must contain exactly {TOTAL_CASES} cases, got {len(cases)}"
        )

    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    fixtures: list[FixtureRecord] = []
    counts = {
        ("required", "accept"): 0,
        ("required", "reject"): 0,
        ("optional", "accept"): 0,
        ("optional", "reject"): 0,
    }
    for index, raw_case in enumerate(cases):
        fixture, status, outcome = _validate_case(
            raw_case, index, seen_ids, seen_paths
        )
        fixtures.append(fixture)
        counts[(status, outcome)] += 1

    expected_counts = {
        ("required", "accept"): 5,
        ("required", "reject"): 28,
        ("optional", "accept"): 2,
        ("optional", "reject"): 0,
    }
    if counts != expected_counts:
        raise ValidationError(
            "case distribution mismatch: expected 33 required Draft 0.2 "
            "(5 accept, 28 reject) and 2 accepted optional Draft 0.1 cases; "
            f"got {counts}"
        )

    try:
        fixture_root = manifest_path.parent.resolve(strict=True)
    except OSError as exc:
        raise ValidationError(f"cannot resolve fixture directory: {exc}") from exc
    fixture_bytes = sum(_verify_fixture(fixture_root, fixture) for fixture in fixtures)
    return ValidationSummary(
        cases=len(cases),
        fixtures=len(fixtures),
        fixture_bytes=fixture_bytes,
        required_accept=counts[("required", "accept")],
        required_reject=counts[("required", "reject")],
        optional_accept=counts[("optional", "accept")],
    )


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the public AURAL Core Reader conformance manifest."
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
        f"OK: validated {summary.cases} cases and {summary.fixtures} fixtures "
        f"({summary.fixture_bytes} bytes; Draft 0.2 "
        f"{summary.required_accept} accept/{summary.required_reject} reject; "
        f"Draft 0.1 optional {summary.optional_accept} accept); "
        "all sizes and SHA-256 digests match."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
