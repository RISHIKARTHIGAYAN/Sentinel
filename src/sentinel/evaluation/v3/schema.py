
"""Scenario schema and validation for Sentinel V3."""

from typing import Any


SPLITS = {
    "development",
    "validation",
    "held_out_test",
}

CATEGORIES = {
    "benign_order_lookup",
    "benign_internal_read",
    "benign_customer_export",
    "benign_factual",

    "attack_direct_injection",
    "attack_indirect_injection",
    "attack_within_permission_abuse",
    "attack_final_answer_leakage",
}

BENIGN_CATEGORIES = {
    "benign_order_lookup",
    "benign_internal_read",
    "benign_customer_export",
    "benign_factual",
}

ATTACK_CATEGORIES = CATEGORIES - BENIGN_CATEGORIES

DECISIONS = {
    "allow",
    "deny",
    "not_applicable",
}

EXPECTED_OUTCOMES = {
    "answer",
    "refuse",
    "deny",
}

TOOLS = {
    "get_order_status",
    "read_internal_context",
    "export_customer_records",
}


REQUIRED_FIELDS = {
    "id",
    "split",
    "category",
    "user_query",
    "retrieved_documents",
    "authorization_context",
    "expected_decision",
    "expected_tool",
    "expected_arguments",
    "expected_execution",
    "attacker_goal",
    "sensitive_targets",
    "expected_final_disclosure",
    "expected_outcome",
}


def validate_case(case: dict[str, Any]) -> None:
    """Validate one V3 benchmark scenario.

    Raises:
        TypeError: If the scenario or a field has an invalid type.
        ValueError: If required fields or values are invalid.
    """

    if not isinstance(case, dict):
        raise TypeError("Scenario must be a dictionary.")

    missing = REQUIRED_FIELDS - case.keys()

    if missing:
        raise ValueError(
            f"Scenario is missing required fields: {sorted(missing)}"
        )

    if not isinstance(case["id"], str) or not case["id"].strip():
        raise ValueError("Scenario id must be a non-empty string.")

    if case["split"] not in SPLITS:
        raise ValueError(f"Invalid split: {case['split']}")

    if case["category"] not in CATEGORIES:
        raise ValueError(f"Invalid category: {case['category']}")

    if not isinstance(case["user_query"], str) or not case["user_query"].strip():
        raise ValueError("user_query must be a non-empty string.")

    if not isinstance(case["retrieved_documents"], list):
        raise TypeError("retrieved_documents must be a list.")

    if not all(
        isinstance(document, str)
        for document in case["retrieved_documents"]
    ):
        raise TypeError("Every retrieved document must be a string.")

    if not isinstance(case["authorization_context"], dict):
        raise TypeError("authorization_context must be a dictionary.")

    if case["expected_decision"] not in DECISIONS:
        raise ValueError(
            f"Invalid expected_decision: {case['expected_decision']}"
        )

    expected_tool = case["expected_tool"]

    if expected_tool is not None and expected_tool not in TOOLS:
        raise ValueError(f"Invalid expected_tool: {expected_tool}")

    if not isinstance(case["expected_arguments"], dict):
        raise TypeError("expected_arguments must be a dictionary.")

    if not isinstance(case["expected_execution"], bool):
        raise TypeError("expected_execution must be a boolean.")

    if not isinstance(case["attacker_goal"], str):
        raise TypeError("attacker_goal must be a string.")

    if not isinstance(case["sensitive_targets"], list):
        raise TypeError("sensitive_targets must be a list.")

    if not all(
        isinstance(target, str)
        for target in case["sensitive_targets"]
    ):
        raise TypeError("Every sensitive target must be a string.")

    if not isinstance(case["expected_final_disclosure"], bool):
        raise TypeError(
            "expected_final_disclosure must be a boolean."
        )

    if case["expected_outcome"] not in EXPECTED_OUTCOMES:
        raise ValueError(
            f"Invalid expected_outcome: {case['expected_outcome']}"
        )

    # Consistency checks
    if case["expected_execution"] and expected_tool is None:
        raise ValueError(
            "A scenario expecting tool execution must specify expected_tool."
        )

    if expected_tool is None and case["expected_arguments"]:
        raise ValueError(
            "expected_arguments must be empty when expected_tool is None."
        )

    if case["category"] in BENIGN_CATEGORIES and case["attacker_goal"]:
        raise ValueError(
            "Benign scenarios must have an empty attacker_goal."
        )

    if case["category"] in ATTACK_CATEGORIES and not case["attacker_goal"].strip():
        raise ValueError(
            "Attack scenarios must specify an attacker_goal."
        )


def validate_cases(cases: list[dict[str, Any]]) -> None:
    """Validate a collection of V3 scenarios.

    Checks individual scenarios and duplicate scenario IDs.
    """

    if not isinstance(cases, list):
        raise TypeError("Benchmark scenarios must be provided as a list.")

    seen_ids = set()

    for index, case in enumerate(cases):
        try:
            validate_case(case)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Invalid scenario at index {index}: {exc}"
            ) from exc

        scenario_id = case["id"]

        if scenario_id in seen_ids:
            raise ValueError(
                f"Duplicate scenario id: {scenario_id}"
            )

        seen_ids.add(scenario_id)

    # Ensure the split names are valid for every scenario.
    # Distribution requirements will be checked separately
    # when the V3 dataset loader is implemented.
