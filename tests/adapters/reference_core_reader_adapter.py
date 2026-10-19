#!/usr/bin/env python3
"""Test-only bridge from adapter protocol v1 to the AURAL Python verifier.

This is not an independent implementation and is not interoperability proof.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aural.core import AuralError, verify  # noqa: E402


PROTOCOL = "org.aural.conformance.adapter"
PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 16 * 1024


def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON constant {value!r}")


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request exceeds size limit")
        request = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=no_duplicate_keys,
            parse_constant=reject_constant,
        )
        if type(request) is not dict:
            raise ValueError("request root must be an object")
        if set(request) != {"protocol", "protocol_version", "case_id", "operation", "input"}:
            raise ValueError("request fields do not match protocol v1")
        if request["protocol"] != PROTOCOL or request["protocol_version"] != PROTOCOL_VERSION:
            raise ValueError("unsupported adapter protocol")
        if request["operation"] != "verify-package":
            raise ValueError(f"unsupported operation {request['operation']!r}")
        if type(request["case_id"]) is not str or not request["case_id"]:
            raise ValueError("case_id must be a nonempty string")
        package = request["input"]
        if type(package) is not dict or set(package) != {"role", "path", "size", "sha256"}:
            raise ValueError("invalid package input descriptor")
        if package["role"] != "package" or type(package["path"]) is not str:
            raise ValueError("unsupported input role or path")
        if type(package["size"]) is not int or type(package["sha256"]) is not str:
            raise ValueError("invalid input size or SHA-256")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        print(f"adapter request error: {exc}", file=sys.stderr)
        return 2

    diagnostic: dict[str, str] = {}
    try:
        verify(package["path"])
        outcome = "accept"
    except AuralError as exc:
        outcome = "reject"
        diagnostic["message"] = str(exc)
    except Exception as exc:  # An infrastructure failure is not a rejection.
        print(f"reference verifier execution error: {exc}", file=sys.stderr)
        return 3

    response: dict[str, Any] = {
        "protocol": PROTOCOL,
        "protocol_version": PROTOCOL_VERSION,
        "case_id": request["case_id"],
        "outcome": outcome,
        "implementation": {
            "name": "AURAL Python reference verifier (test-only adapter)",
            "version": "0.2.0.dev0",
        },
    }
    if diagnostic:
        response["diagnostic"] = diagnostic
    sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
