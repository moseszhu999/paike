#!/usr/bin/env python3
"""Validate sanitized opaque exact-head carrier payloads without private source."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
FORBIDDEN_KEY_PARTS = (
    "private_source",
    "source_text",
    "file_content",
    "raw_data",
    "credential",
    "secret_value",
    "strategy_parameter",
)
REQUIRED_FALSE = (
    "public_payload_contains_private_source",
    "public_payload_contains_raw_data",
    "public_payload_contains_credentials",
    "production_behavior_changed",
    "wallet_changed",
    "orders_changed",
    "positions_changed",
    "candidate_effects_read",
)
PROFILE_FILE_COUNTS = {
    "docs-contract-exact-head": 2,
    "code-fourfile-content-equivalent-exact-head": 4,
}


def _walk_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            keys.append(str(key))
            keys.extend(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.extend(_walk_keys(child))
    return keys


def validate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema") != "opaque.private_exact_head_carrier.v1":
        raise ValueError("unexpected schema")
    profile = payload.get("profile")
    if profile not in PROFILE_FILE_COUNTS:
        raise ValueError("unexpected profile")
    expected_file_count = PROFILE_FILE_COUNTS[profile]

    target = payload.get("target")
    if not isinstance(target, dict):
        raise ValueError("target must be an object")
    base_sha = target.get("base_sha")
    head_sha = target.get("head_sha")
    if not isinstance(base_sha, str) or not HEX40.fullmatch(base_sha):
        raise ValueError("invalid base_sha")
    if not isinstance(head_sha, str) or not HEX40.fullmatch(head_sha):
        raise ValueError("invalid head_sha")
    if base_sha == head_sha:
        raise ValueError("base and head must differ")
    if target.get("private_repository") is not True:
        raise ValueError("target must be marked private")
    if target.get("changed_file_count") != expected_file_count:
        raise ValueError(f"{profile} requires exactly {expected_file_count} changed files")
    if target.get("ahead_by") != 1 or target.get("behind_by") != 0:
        raise ValueError("unexpected lineage")

    bindings = payload.get("file_bindings")
    if not isinstance(bindings, list) or len(bindings) != expected_file_count:
        raise ValueError(f"exactly {expected_file_count} opaque file bindings are required")
    path_commitments: set[str] = set()
    blob_shas: set[str] = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            raise ValueError("file binding must be an object")
        path_commitment = binding.get("path_commitment_sha256")
        blob_sha = binding.get("git_blob_sha1")
        if not isinstance(path_commitment, str) or not HEX64.fullmatch(path_commitment):
            raise ValueError("invalid path commitment")
        if not isinstance(blob_sha, str) or not HEX40.fullmatch(blob_sha):
            raise ValueError("invalid git blob sha1")
        path_commitments.add(path_commitment)
        blob_shas.add(blob_sha)
    if len(path_commitments) != expected_file_count or len(blob_shas) != expected_file_count:
        raise ValueError("file bindings must be unique")

    safety = payload.get("safety")
    if not isinstance(safety, dict):
        raise ValueError("safety must be an object")
    for key in REQUIRED_FALSE:
        if safety.get(key) is not False:
            raise ValueError(f"{key} must be false")
    if safety.get("strategy_imports") != 0 or safety.get("trade_ledger_reads") != 0:
        raise ValueError("strategy and ledger reads must remain zero")

    authority = payload.get("immutable_authority")
    if not isinstance(authority, dict):
        raise ValueError("immutable_authority must be an object")
    if not isinstance(authority.get("run_id"), int) or authority["run_id"] <= 0:
        raise ValueError("invalid run_id")
    if not isinstance(authority.get("artifact_id"), int) or authority["artifact_id"] <= 0:
        raise ValueError("invalid artifact_id")
    digest = authority.get("artifact_zip_digest")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ValueError("invalid artifact digest")

    if profile == "code-fourfile-content-equivalent-exact-head":
        source_head = authority.get("source_exact_head_sha")
        if not isinstance(source_head, str) or not HEX40.fullmatch(source_head):
            raise ValueError("invalid source_exact_head_sha")
        if authority.get("implementation_blobs_unchanged") is not True:
            raise ValueError("implementation_blobs_unchanged must be true")
        if authority.get("implementation_blob_count") != expected_file_count:
            raise ValueError("implementation_blob_count drifted")

    observed = payload.get("observed_contract")
    expected = {
        "proxy_stems": 17,
        "behavior_axes": 6,
        "horizons": 4,
        "proxy_fields": 68,
        "input_rows": 144,
        "complete_profiles": 140,
        "core_complete_micro_missing": 4,
        "incomplete_core_profiles": 0,
    }
    if observed != expected:
        raise ValueError("observed contract counts drifted")

    for key in _walk_keys(payload):
        if key in REQUIRED_FALSE:
            continue
        lowered = key.lower()
        if any(part in lowered for part in FORBIDDEN_KEY_PARTS):
            raise ValueError(f"forbidden key in public carrier: {key}")

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": "opaque.private_exact_head_carrier_receipt.v1",
        "status": "PASS",
        "profile": profile,
        "target_head_sha": head_sha,
        "target_base_sha": base_sha,
        "carrier_payload_sha256": hashlib.sha256(canonical).hexdigest(),
        "changed_file_count": expected_file_count,
        "opaque_file_bindings": expected_file_count,
        "private_source_present": False,
        "raw_data_present": False,
        "credentials_present": False,
        "production_behavior_changed": False,
    }


def validate_file(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 16_384:
        raise ValueError(f"carrier payload too large: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("carrier root must be an object")
    return validate_payload(payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("carrier_dir", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("out"))
    args = parser.parse_args()

    files = sorted(args.carrier_dir.glob("*.json"))
    if not files:
        raise SystemExit("no carrier payloads found")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    receipts = []
    for path in files:
        receipt = validate_file(path)
        receipt["carrier_file"] = path.name
        receipts.append(receipt)
        print(f"PASS {path}: {receipt['target_head_sha']}")

    aggregate = {
        "schema": "opaque.private_exact_head_carrier_aggregate.v1",
        "status": "PASS",
        "carrier_count": len(receipts),
        "receipts": receipts,
    }
    output = args.output_dir / "carrier-validation-receipt.json"
    output.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
