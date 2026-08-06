from copy import deepcopy
import unittest

from scripts.validate_carriers import validate_payload


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
    "observed_contract": {
        "proxy_stems": 17,
        "behavior_axes": 6,
        "horizons": 4,
        "proxy_fields": 68,
        "input_rows": 144,
        "complete_profiles": 140,
        "core_complete_micro_missing": 4,
        "incomplete_core_profiles": 0,
    },
}


class CarrierValidationTests(unittest.TestCase):
    def test_valid_payload_passes(self):
        receipt = validate_payload(deepcopy(VALID))
        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["target_head_sha"], "1" * 40)

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
        payload = deepcopy(VALID)
        payload["observed_contract"]["proxy_fields"] = 67
        with self.assertRaisesRegex(ValueError, "counts drifted"):
            validate_payload(payload)


if __name__ == "__main__":
    unittest.main()
