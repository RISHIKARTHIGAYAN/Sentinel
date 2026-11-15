
import json
import tempfile
import unittest
from pathlib import Path

from sentinel.evaluation.v3.dataset import (
    EXPECTED_TOTAL_CASES,
    load_dataset,
    validate_distribution,
)
from tests.test_v3_schema import make_valid_case


def make_complete_dataset():
    """Generate a structurally valid dataset with the expected distribution."""

    benign_categories = [
        "benign_order_lookup",
        "benign_internal_read",
        "benign_customer_export",
        "benign_factual",
    ]

    attack_categories = [
        "attack_direct_injection",
        "attack_indirect_injection",
        "attack_within_permission_abuse",
        "attack_final_answer_leakage",
    ]

    splits = {
        "development": 6,
        "validation": 3,
        "held_out_test": 3,
    }

    cases = []

    for split, count in splits.items():
        for category in benign_categories + attack_categories:
            for index in range(count):
                scenario_id = f"V3-{split}-{category}-{index:02d}"

                if category in benign_categories:
                    case = make_valid_case(
                        id=scenario_id,
                        split=split,
                        category=category,
                    )
                else:
                    case = make_valid_case(
                        id=scenario_id,
                        split=split,
                        category=category,
                        expected_decision="deny",
                        expected_tool=None,
                        expected_arguments={},
                        expected_execution=False,
                        attacker_goal="Achieve an unauthorized disclosure.",
                        sensitive_targets=["system_context"],
                        expected_final_disclosure=False,
                        expected_outcome="refuse",
                    )

                cases.append(case)

    return cases


class V3DatasetTests(unittest.TestCase):

    def test_complete_dataset_has_96_scenarios(self):
        cases = make_complete_dataset()

        self.assertEqual(len(cases), EXPECTED_TOTAL_CASES)
        validate_distribution(cases)

    def test_incomplete_dataset_is_rejected(self):
        cases = make_complete_dataset()
        cases.pop()

        with self.assertRaises(ValueError):
            validate_distribution(cases)

    def test_wrong_split_distribution_is_rejected(self):
        cases = make_complete_dataset()

        cases[0]["split"] = "validation"

        with self.assertRaises(ValueError):
            validate_distribution(cases)

    def test_wrong_category_distribution_is_rejected(self):
        cases = make_complete_dataset()

        cases[0]["category"] = "attack_direct_injection"

        with self.assertRaises(ValueError):
            validate_distribution(cases)

    def test_duplicate_ids_are_rejected(self):
        cases = make_complete_dataset()

        cases[1]["id"] = cases[0]["id"]

        with self.assertRaises(ValueError):
            validate_distribution(cases)

    def test_missing_dataset_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_path = Path(temp_dir) / "missing.json"

            with self.assertRaises(FileNotFoundError):
                load_dataset(missing_path)

    def test_invalid_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.json"
            path.write_text("{invalid json}", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_dataset(path)

    def test_json_object_instead_of_list_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "object.json"
            path.write_text(
                json.dumps({"scenario": "invalid"}),
                encoding="utf-8",
            )

            with self.assertRaises(TypeError):
                load_dataset(path)

    def test_partial_dataset_can_be_loaded(self):
        cases = make_complete_dataset()[:2]

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "partial.json"
            path.write_text(
                json.dumps(cases),
                encoding="utf-8",
            )

            loaded = load_dataset(path, require_complete=False)

            self.assertEqual(len(loaded), 2)

    def test_complete_dataset_can_be_loaded_from_json(self):
        cases = make_complete_dataset()

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "complete.json"
            path.write_text(
                json.dumps(cases),
                encoding="utf-8",
            )

            loaded = load_dataset(path)

            self.assertEqual(len(loaded), 96)


if __name__ == "__main__":
    unittest.main()
