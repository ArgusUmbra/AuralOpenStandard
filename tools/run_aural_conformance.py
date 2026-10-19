#!/usr/bin/env python3
"""Run the public AURAL Core Reader cases through an external adapter.

This convenience runner is test-kit tooling, not a dependency of an AURAL
implementation.  The adapter contract is language neutral and process based.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

try:  # Support both direct execution and import as tools.run_aural_conformance.
    from . import validate_core_conformance_manifest as manifest_validator
except ImportError:  # pragma: no cover - exercised by CLI subprocess tests
    import validate_core_conformance_manifest as manifest_validator


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    ROOT / "tests" / "fixtures" / "conformance"
    / "core-reader-0.2-cases.v1.json"
)
REPOSITORY_FIXTURE_ROOT = ROOT / "tests" / "fixtures"

PROTOCOL = "org.aural.conformance.adapter"
PROTOCOL_VERSION = 1
OPERATION = "verify-package"
REPORT_SCHEMA = "urn:aural:conformance:runner-report"
REPORT_SCHEMA_VERSION = 1
PROFILE_SELECTOR = "core-reader-0.2"

MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_STDERR_BYTES = 64 * 1024
MIN_TIMEOUT_SECONDS = 0.05
MAX_TIMEOUT_SECONDS = 60.0
DEFAULT_TIMEOUT_SECONDS = 10.0
POLL_SECONDS = 0.005

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INCOMPLETE = 2
EXIT_RUNNER_ERROR = 3


class RunnerError(Exception):
    """The runner could not establish or record a trustworthy run."""


class DuplicateKeyError(ValueError):
    """A JSON object contained a duplicate member name."""


class ProtocolError(ValueError):
    """An adapter response did not conform to protocol version 1."""


@dataclass(frozen=True)
class Case:
    case_id: str
    requirement: str
    profile_id: str
    profile_version: str
    expected_outcome: str
    input_role: str
    fixture_path: Path
    fixture_relative_path: str
    fixture_size: int
    fixture_sha256: str


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant {value!r}")


def _strict_json(raw: bytes, description: str) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"{description} is not UTF-8: {exc}") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (DuplicateKeyError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ProtocolError(f"{description} is not one strict JSON document: {exc}") from exc


def _read_manifest_bytes(path: Path) -> bytes:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise RunnerError(f"cannot stat manifest {path}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise RunnerError(f"manifest is not a regular file: {path}")
    if metadata.st_size > manifest_validator.MAX_MANIFEST_BYTES:
        raise RunnerError("manifest exceeds the test-kit safety limit")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise RunnerError(f"cannot read manifest {path}: {exc}") from exc


def load_cases(manifest_path: Path) -> tuple[dict[str, Any], list[Case], str]:
    """Integrity-check the public manifest and return immutable run inputs."""
    manifest_path = manifest_path.expanduser().resolve()
    before = _read_manifest_bytes(manifest_path)
    try:
        manifest_validator.validate_manifest(manifest_path)
    except manifest_validator.ValidationError as exc:
        raise RunnerError(f"manifest or fixture integrity validation failed: {exc}") from exc
    after = _read_manifest_bytes(manifest_path)
    if after != before:
        raise RunnerError("manifest changed during integrity validation")
    try:
        document = _strict_json(after, "manifest")
    except ProtocolError as exc:
        raise RunnerError(str(exc)) from exc

    fixture_root = manifest_path.parent.resolve(strict=True)
    cases: list[Case] = []
    for item in document["cases"]:
        record = manifest_validator.FixtureRecord(
            item["id"], item["input"]["path"],
            item["input"]["sha256"], item["input"]["size"],
        )
        fixture_path = manifest_validator._safe_fixture_path(fixture_root, record)
        cases.append(Case(
            case_id=item["id"],
            requirement=item["status"],
            profile_id=item["applicable_profile"]["id"],
            profile_version=item["applicable_profile"]["version"],
            expected_outcome=item["expected"]["outcome"],
            input_role=item["input"]["role"],
            fixture_path=fixture_path,
            fixture_relative_path=item["input"]["path"],
            fixture_size=item["input"]["size"],
            fixture_sha256=item["input"]["sha256"],
        ))
    return document, cases, hashlib.sha256(after).hexdigest()


def _request(case: Case) -> bytes:
    document = {
        "protocol": PROTOCOL,
        "protocol_version": PROTOCOL_VERSION,
        "case_id": case.case_id,
        "operation": OPERATION,
        "input": {
            "role": case.input_role,
            "path": str(case.fixture_path),
            "size": case.fixture_size,
            "sha256": case.fixture_sha256,
        },
    }
    raw = (json.dumps(
        document, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
    ) + "\n").encode("utf-8")
    if len(raw) > MAX_REQUEST_BYTES:
        raise RunnerError(
            f"request for {case.case_id!r} exceeds {MAX_REQUEST_BYTES} bytes"
        )
    return raw


def _validate_response(raw: bytes, case: Case) -> str:
    document = _strict_json(raw, "adapter response")
    if type(document) is not dict:
        raise ProtocolError("adapter response root must be a JSON object")
    required = {"protocol", "protocol_version", "case_id", "outcome"}
    optional = {"diagnostic", "implementation"}
    missing = required - set(document)
    unexpected = set(document) - required - optional
    if missing:
        raise ProtocolError(
            "adapter response is missing required field(s): "
            + ", ".join(sorted(missing))
        )
    if unexpected:
        raise ProtocolError(
            "adapter response has unexpected field(s): "
            + ", ".join(sorted(unexpected))
        )
    if type(document["protocol"]) is not str or document["protocol"] != PROTOCOL:
        raise ProtocolError("adapter response has the wrong protocol identifier")
    if (type(document["protocol_version"]) is not int
            or document["protocol_version"] != PROTOCOL_VERSION):
        raise ProtocolError("adapter response has the wrong protocol version")
    if type(document["case_id"]) is not str or document["case_id"] != case.case_id:
        raise ProtocolError("adapter response case_id does not match the request")
    outcome = document["outcome"]
    if type(outcome) is not str or outcome not in {"accept", "reject"}:
        raise ProtocolError("adapter response outcome must be 'accept' or 'reject'")
    if "diagnostic" in document and type(document["diagnostic"]) is not dict:
        raise ProtocolError("adapter response diagnostic must be a JSON object")
    if "implementation" in document:
        implementation = document["implementation"]
        if type(implementation) is not dict:
            raise ProtocolError("adapter response implementation must be a JSON object")
        if not implementation or set(implementation) - {"name", "version"}:
            raise ProtocolError(
                "adapter response implementation permits only name and version"
            )
        for key, value in implementation.items():
            if type(value) is not str or not value or len(value) > 256:
                raise ProtocolError(
                    f"adapter response implementation.{key} must be a 1-256 character string"
                )
    return outcome


def _error(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _case_result_base(case: Case, duration_ms: int) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "profile_id": case.profile_id,
        "profile_version": case.profile_version,
        "requirement": case.requirement,
        "expected_outcome": case.expected_outcome,
        "observed_outcome": None,
        "status": "ERROR",
        "duration_ms": duration_ms,
        "fixture": {
            "path": case.fixture_relative_path,
            "size": case.fixture_size,
            "sha256": case.fixture_sha256,
        },
    }


def skipped_case_result(case: Case) -> dict[str, Any]:
    result = _case_result_base(case, 0)
    result["status"] = "SKIP"
    result["error"] = _error("explicitly-skipped", "case was explicitly not executed")
    return result


def _write_request(stream: Any, request: bytes, errors: list[str]) -> None:
    try:
        stream.write(request)
        stream.flush()
    except (BrokenPipeError, OSError) as exc:
        errors.append(str(exc))
    finally:
        try:
            stream.close()
        except OSError:
            pass


def run_case(case: Case, adapter_command: list[str], timeout: float) -> dict[str, Any]:
    request = _request(case)
    started = time.monotonic()
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                adapter_command,
                stdin=subprocess.PIPE,
                stdout=stdout_file,
                stderr=stderr_file,
                shell=False,
            )
        except (OSError, ValueError) as exc:
            duration = round((time.monotonic() - started) * 1000)
            result = _case_result_base(case, duration)
            result["error"] = _error("adapter-launch-failed", str(exc))
            return result

        assert process.stdin is not None
        write_errors: list[str] = []
        writer = threading.Thread(
            target=_write_request,
            args=(process.stdin, request, write_errors),
            daemon=True,
        )
        writer.start()
        deadline = started + timeout
        timed_out = False
        overflow: str | None = None
        while process.poll() is None:
            if time.monotonic() >= deadline:
                timed_out = True
                process.kill()
                break
            if os.fstat(stdout_file.fileno()).st_size > MAX_RESPONSE_BYTES:
                overflow = "stdout"
                process.kill()
                break
            if os.fstat(stderr_file.fileno()).st_size > MAX_STDERR_BYTES:
                overflow = "stderr"
                process.kill()
                break
            time.sleep(POLL_SECONDS)
        try:
            return_code = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            return_code = process.wait()
        writer.join(timeout=1)
        duration = round((time.monotonic() - started) * 1000)
        stdout_size = os.fstat(stdout_file.fileno()).st_size
        stderr_size = os.fstat(stderr_file.fileno()).st_size
        if overflow is None:
            if stdout_size > MAX_RESPONSE_BYTES:
                overflow = "stdout"
            elif stderr_size > MAX_STDERR_BYTES:
                overflow = "stderr"

        result = _case_result_base(case, duration)
        if timed_out:
            result["status"] = "TIMEOUT"
            result["error"] = _error(
                "adapter-timeout", f"adapter exceeded the {timeout:g}-second limit",
            )
            return result
        if overflow is not None:
            limit = MAX_RESPONSE_BYTES if overflow == "stdout" else MAX_STDERR_BYTES
            result["error"] = _error(
                "adapter-output-too-large",
                f"adapter {overflow} exceeded the {limit}-byte limit",
            )
            return result
        if return_code != 0:
            result["error"] = _error(
                "adapter-process-failed", f"adapter exited with status {return_code}",
            )
            return result
        if write_errors:
            result["error"] = _error(
                "adapter-input-failed", "adapter did not consume the complete request",
            )
            return result

        stdout_file.seek(0)
        response = stdout_file.read(MAX_RESPONSE_BYTES + 1)
        try:
            outcome = _validate_response(response, case)
        except ProtocolError as exc:
            result["error"] = _error("invalid-adapter-response", str(exc))
            return result
        result["observed_outcome"] = outcome
        result["status"] = "PASS" if outcome == case.expected_outcome else "FAIL"
        return result


def summarize(results: list[dict[str, Any]], required_case_count: int) -> dict[str, Any]:
    counts = {name: 0 for name in ("PASS", "FAIL", "ERROR", "TIMEOUT", "SKIP")}
    required_counts = dict(counts)
    optional_counts = dict(counts)
    for result in results:
        counts[result["status"]] += 1
        target = required_counts if result["requirement"] == "required" else optional_counts
        target[result["status"]] += 1
    required_seen = sum(required_counts.values())
    if (required_seen != required_case_count
            or required_counts["ERROR"]
            or required_counts["TIMEOUT"]
            or required_counts["SKIP"]):
        overall = "INCOMPLETE"
    elif required_counts["FAIL"]:
        overall = "FAIL"
    elif required_counts["PASS"] == required_case_count:
        overall = "PASS"
    else:
        overall = "INCOMPLETE"
    return {
        "required_cases": required_case_count,
        "selected_cases": len(results),
        "passed": counts["PASS"],
        "failed": counts["FAIL"],
        "skipped": counts["SKIP"],
        "execution_errors": counts["ERROR"],
        "timeouts": counts["TIMEOUT"],
        "required": {
            "selected": required_seen,
            "passed": required_counts["PASS"],
            "failed": required_counts["FAIL"],
            "skipped": required_counts["SKIP"],
            "execution_errors": required_counts["ERROR"],
            "timeouts": required_counts["TIMEOUT"],
        },
        "optional": {
            "selected": sum(optional_counts.values()),
            "passed": optional_counts["PASS"],
            "failed": optional_counts["FAIL"],
            "skipped": optional_counts["SKIP"],
            "execution_errors": optional_counts["ERROR"],
            "timeouts": optional_counts["TIMEOUT"],
        },
        "overall_result": overall,
    }


def build_report(
    manifest: dict[str, Any], manifest_path: Path, manifest_sha256: str,
    adapter_command: list[str], timeout: float, include_legacy: bool,
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    summary = summarize(results, manifest["profile"]["required_case_count"])
    return {
        "schema": REPORT_SCHEMA,
        "schema_version": REPORT_SCHEMA_VERSION,
        "test_kit_version": manifest["kit_manifest_version"],
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "manifest": {
            "path": str(manifest_path.resolve()),
            "sha256": manifest_sha256,
        },
        "profile": {
            "id": manifest["profile"]["id"],
            "version": manifest["profile"]["version"],
            "status": manifest["profile"]["status"],
        },
        "adapter": {
            "command": adapter_command,
            "protocol": PROTOCOL,
            "protocol_version": PROTOCOL_VERSION,
        },
        "execution": {
            "platform": platform.system(),
            "architecture": platform.machine(),
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "per_case_timeout_seconds": timeout,
        },
        "optional_legacy_included": include_legacy,
        "summary": summary,
        "overall_result": summary["overall_result"],
        "cases": results,
        "notice": "Conformance-test evidence; not official certification or security certification.",
    }


def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def validate_report_path(report_path: Path, manifest_path: Path) -> Path:
    report_path = report_path.expanduser()
    try:
        parent = report_path.parent.resolve(strict=True)
    except OSError as exc:
        raise RunnerError(f"report parent directory is unavailable: {exc}") from exc
    target = parent / report_path.name
    protected = [manifest_path.parent.resolve(), REPOSITORY_FIXTURE_ROOT.resolve()]
    if any(_is_within(target, root) for root in protected):
        raise RunnerError("report path must not be inside a conformance fixture directory")
    if target.exists() or target.is_symlink():
        try:
            metadata = target.lstat()
        except OSError as exc:
            raise RunnerError(f"cannot inspect report path: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise RunnerError("report path must not be a symbolic link")
        if not stat.S_ISREG(metadata.st_mode):
            raise RunnerError("report path must identify a regular file or not yet exist")
    return target


def write_report(path: Path, report: dict[str, Any]) -> None:
    payload = (json.dumps(
        report, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False,
    ) + "\n").encode("utf-8")
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".aural-report-", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise RunnerError(f"cannot write report {path}: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if (not math.isfinite(timeout)
            or not MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS):
        raise argparse.ArgumentTypeError(
            f"timeout must be between {MIN_TIMEOUT_SECONDS:g} and "
            f"{MAX_TIMEOUT_SECONDS:g} seconds"
        )
    return timeout


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(EXIT_RUNNER_ERROR, f"{self.prog}: error: {message}\n")


def argument_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        description="Run AURAL Core Reader cases through an independent executable adapter.",
        epilog=(
            "The adapter is executed directly without a shell. It is trusted executable "
            "code, not sandboxed by this runner."
        ),
    )
    parser.add_argument(
        "--profile", choices=[PROFILE_SELECTOR], default=PROFILE_SELECTOR,
        help="test profile (default: %(default)s)",
    )
    parser.add_argument(
        "--manifest", type=Path, default=DEFAULT_MANIFEST,
        help="Core Reader public manifest (default: repository manifest)",
    )
    parser.add_argument("--report", required=True, type=Path, help="JSON report output path")
    parser.add_argument(
        "--include-legacy", action="store_true",
        help="also execute the two optional Draft 0.1 legacy cases",
    )
    parser.add_argument(
        "--timeout", type=_timeout, default=DEFAULT_TIMEOUT_SECONDS,
        help=(f"per-case seconds ({MIN_TIMEOUT_SECONDS:g}-{MAX_TIMEOUT_SECONDS:g}; "
              f"default: {DEFAULT_TIMEOUT_SECONDS:g})"),
    )
    parser.add_argument(
        "--skip-case", action="append", default=[], metavar="CASE_ID",
        help="explicitly mark a selected case SKIP (repeatable; required skips are incomplete)",
    )
    parser.add_argument("--adapter", required=True, help="adapter executable path or name")
    parser.add_argument(
        "--adapter-arg", action="append", default=[], metavar="ARG",
        help="adapter argument (repeatable; use --adapter-arg=--flag for leading hyphens)",
    )
    return parser


def execute(arguments: argparse.Namespace) -> tuple[dict[str, Any], int]:
    manifest_path = arguments.manifest.expanduser().resolve()
    report_path = validate_report_path(arguments.report, manifest_path)
    manifest, all_cases, manifest_sha256 = load_cases(manifest_path)
    cases = [
        case for case in all_cases
        if case.requirement == "required" or arguments.include_legacy
    ]
    selected_ids = {case.case_id for case in cases}
    requested_skips = set(arguments.skip_case)
    unknown_skips = requested_skips - selected_ids
    if unknown_skips:
        raise RunnerError(
            "--skip-case did not match a selected case: " + ", ".join(sorted(unknown_skips))
        )
    adapter_command = [arguments.adapter, *arguments.adapter_arg]
    results: list[dict[str, Any]] = []
    for case in cases:
        if case.case_id in requested_skips:
            result = skipped_case_result(case)
        else:
            result = run_case(case, adapter_command, arguments.timeout)
        results.append(result)
        if result["status"] != "PASS":
            print(f"{result['status']:<10} {case.case_id}")
    report = build_report(
        manifest, manifest_path, manifest_sha256, adapter_command,
        arguments.timeout, arguments.include_legacy, results,
    )
    write_report(report_path, report)
    overall = report["overall_result"]
    summary = report["summary"]
    print(
        f"{overall}: required {summary['required']['passed']}/"
        f"{summary['required_cases']} passed; failures={summary['required']['failed']}, "
        f"errors={summary['required']['execution_errors']}, "
        f"timeouts={summary['required']['timeouts']}, "
        f"skipped={summary['required']['skipped']}; report={report_path}"
    )
    if overall == "PASS":
        return report, EXIT_PASS
    if overall == "FAIL":
        return report, EXIT_FAIL
    return report, EXIT_INCOMPLETE


def main(argv: list[str] | None = None) -> int:
    arguments = argument_parser().parse_args(argv)
    try:
        _, exit_status = execute(arguments)
    except RunnerError as exc:
        print(f"RUNNER ERROR: {exc}", file=sys.stderr)
        return EXIT_RUNNER_ERROR
    return exit_status


if __name__ == "__main__":
    raise SystemExit(main())
