
"""Dataset loading and distribution validation for Sentinel V3."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

from sentinel.evaluation.v3.schema import (
    ATTACK_CATEGORIES,
    BENIGN_CATEGORIES,
    CATEGORIES,
    SPLITS,
    validate_cases,
)


EXPECTED_SPLIT_COUNTS = {
    "development": 48,
    "validation": 24,
    "held_out_test": 24,
}

EXPECTED_CATEGORY_COUNTS = {
    "development": 6,
    "validation": 3,
    "held_out_test": 3,
}

EXPECTED_TOTAL_CASES = 96
EXPECTED_BENIGN_CASES = 48
EXPECTED_ATTACK_CASES = 48


def validate_distribution(cases: list[dict[str, Any]]) -> None:
    """Validate the complete V3 benchmark distribution."""

    validate_cases(cases)

    if len(cases) != EXPECTED_TOTAL_CASES:
        raise ValueError(
            f"Expected {EXPECTED_TOTAL_CASES} scenarios, "
            f"found {len(cases)}."
        )

    split_counts = Counter(case["split"] for case in cases)

    for split, expected in EXPECTED_SPLIT_COUNTS.items():
        actual = split_counts.get(split, 0)

        if actual != expected:
            raise ValueError(
                f"Split '{split}' must contain {expected} scenarios; "
                f"found {actual}."
            )

    category_counts = Counter(
        (case["split"], case["category"])
        for case in cases
    )

    for split, expected_per_category in EXPECTED_CATEGORY_COUNTS.items():
        for category in CATEGORIES:
            actual = category_counts.get((split, category), 0)

            if actual != expected_per_category:
                raise ValueError(
                    f"Category '{category}' in split '{split}' "
                    f"must contain {expected_per_category} scenarios; "
                    f"found {actual}."
                )

    benign_count = sum(
        case["category"] in BENIGN_CATEGORIES
        for case in cases
    )

    attack_count = sum(
        case["category"] in ATTACK_CATEGORIES
        for case in cases
    )

    if benign_count != EXPECTED_BENIGN_CASES:
        raise ValueError(
            f"Expected {EXPECTED_BENIGN_CASES} benign scenarios; "
            f"found {benign_count}."
        )

    if attack_count != EXPECTED_ATTACK_CASES:
        raise ValueError(
            f"Expected {EXPECTED_ATTACK_CASES} attack scenarios; "
            f"found {attack_count}."
        )


def load_dataset(
    path: str | Path,
    require_complete: bool = True,
) -> list[dict[str, Any]]:
    """Load and validate a V3 JSON benchmark dataset.

    Args:
        path: Path to a JSON file containing a list of scenarios.
        require_complete: If True, enforce the complete 96-case
            benchmark distribution. If False, validate only the
            individual scenario structures.

    Returns:
        Validated list of scenarios.
    """

    dataset_path = Path(path)

    if not dataset_path.is_file():
        raise FileNotFoundError(
            f"Dataset file does not exist: {dataset_path}"
        )

    try:
        with dataset_path.open("r", encoding="utf-8") as file:
            cases = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON dataset: {exc}"
        ) from exc

    if not isinstance(cases, list):
        raise TypeError(
            "Dataset JSON must contain a list of scenarios."
        )

    if require_complete:
        validate_distribution(cases)
    else:
        validate_cases(cases)

    return cases
