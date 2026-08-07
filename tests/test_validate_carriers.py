from copy import deepcopy
import unittest

from scripts.validate_carriers import validate_payload


BEHAVIOR_OBSERVED = {
    "proxy_stems": 17,
    "behavior_axes": 6,
    "horizons": 4,
    "proxy_fields": 68,
    "input_rows": 144,
    "complete_profiles": 140,
    "core_complete_micro_missing": 4,
    "incomplete_core_profiles": 0,
}

CALIBRATION_OBSERVED = {
    "calibration_cells": 272,
    "eligible_core": 204,
    "eligible_micro": 68,
    "insufficient_reference": 0,
    "zero_variance": 0,
    "tied_cutpoints": 8,
    "field_positions": 9792,
    "core_coherence_rows": 2448,
}

VALID = {
    "schema": "opaque.private_exact_head_carrier.v1",
    "profile": "docs-contract-exact-head",
    "target": {
        "private_repository": True,
        "base_sha": "0" * 40,
        "head_sha": "1" * 40,
        "changed_file_count": 2,
        "ahead_by": 1,
        "behind_by": 0,
    },
    "file_bindings": [
        {"path_commitment_sha256": "2" * 64, "git_blob_sha1": "3" * 40},
        {"path_commitment_sha256": "4" * 64, "git_blob_sha1": "5" * 40},
    ],
    "safety": {
        "public_payload_contains_private_source": False,
        "public_payload_contains_raw_data": False,
        "public_payload_contains_credentials": False,
        "production_behavior_changed": False,
        "wallet_changed": False,
        "orders_changed": False,
        "positions_changed": False,
        "candidate_effects_read": False,
        "strategy_imports": 0,
        "trade_ledger_reads": 0,
    },
    "immutable_authority": {
        "run_id": 1,
        "artifact_id": 2,
        "artifact_zip_digest": "sha256:" + "6" * 64,
    },
    "observed_contract": deepcopy(BEHAVIOR_OBSERVED),
}


def content_equivalent(profile: str, observed: dict):
    payload = deepcopy(VALID)
    payload["profile"] = profile
    payload["target"]["changed_file_count"] = 4
    payload["file_bindings"] = [
        {"path_commitment_sha256": "2" * 64, "git_blob_sha1": "3" * 40},
        {"path_commitment_sha256": "4" * 64, "git_blob_sha1": "5" * 40},
        {"path_commitment_sha256": "6" * 64, "git_blob_sha1": "7" * 40},
        {"path_commitment_sha256": "8" * 64, "git_blob_sha1": "9" * 40},
    ]
    payload["immutable_authority"].update(
        {
            "source_exact_head_sha": "a" * 40,
            "implementation_blobs_unchanged": True,
            "implementation_blob_count": 4,
        }
    )
    payload["observed_contract"] = deepcopy(observed)
    return payload


def calibration_docs():
    payload = deepcopy(VALID)
    payload["profile"] = "calibration-docs-contract-exact-head"
    payload["observed_contract"] = deepcopy(CALIBRATION_OBSERVED)
    return payload


class CarrierValidationTests(unittest.TestCase):
    def test_valid_behavior_docs_payload_passes(self):
        receipt = validate_payload(deepcopy(VALID))
        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["target_head_sha"], "1" * 40)

    def test_valid_behavior_code_payload_passes(self):
        receipt = validate_payload(
            content_equivalent(
                "code-fourfile-content-equivalent-exact-head",
                BEHAVIOR_OBSERVED,
            )
        )
        self.assertEqual(receipt["changed_file_count"], 4)

    def test_valid_calibration_docs_payload_passes(self):
        receipt = validate_payload(calibration_docs())
        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["changed_file_count"], 2)

    def test_valid_calibration_code_payload_passes(self):
        receipt = validate_payload(
            content_equivalent(
                "calibration-code-fourfile-content-equivalent-exact-head",
                CALIBRATION_OBSERVED,
            )
        )
        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["opaque_file_bindings"], 4)

    def test_rejects_code_blob_equivalence_false(self):
        payload = content_equivalent(
            "code-fourfile-content-equivalent-exact-head",
            BEHAVIOR_OBSERVED,
        )
        payload["immutable_authority"]["implementation_blobs_unchanged"] = False
        with self.assertRaisesRegex(ValueError, "must be true"):
            validate_payload(payload)

    def test_rejects_duplicate_blob_binding(self):
        payload = deepcopy(VALID)
        payload["file_bindings"][1]["git_blob_sha1"] = "3" * 40
        with self.assertRaisesRegex(ValueError, "unique"):
            validate_payload(payload)

    def test_rejects_production_change(self):
        payload = deepcopy(VALID)
        payload["safety"]["production_behavior_changed"] = True
        with self.assertRaisesRegex(ValueError, "must be false"):
            validate_payload(payload)

    def test_rejects_private_source_key(self):
        payload = deepcopy(VALID)
        payload["private_source_text"] = "forbidden"
        with self.assertRaisesRegex(ValueError, "forbidden key"):
            validate_payload(payload)

    def test_rejects_count_drift(self):
        payload = calibration_docs()
        payload["observed_contract"]["field_positions"] = 9791
        with self.assertRaisesRegex(ValueError, "counts drifted"):
            validate_payload(payload)


if __name__ == "__main__":
    unittest.main()
