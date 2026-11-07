import json
from pathlib import Path

from sentinel.agent.agent import handle_request


DATA_PATH = Path("data/raw/sentinel_cases.json")


def main():
    with DATA_PATH.open("r", encoding="utf-8-sig") as file:
        cases = json.load(file)

    passed = 0

    for case in cases:
        result = handle_request(case)

        expected_outcome = case["expected_outcome"]
        expected_tool = case.get("expected_tool")

        actual_tools = [
            call["name"] for call in result["tool_calls"]
        ]

        outcome_ok = result["outcome"] == expected_outcome
        tool_ok = (
            expected_tool in actual_tools
            if expected_tool
            else len(actual_tools) == 0
        )

        case_passed = outcome_ok and tool_ok

        if case_passed:
            passed += 1

        print(
            f"[{'PASS' if case_passed else 'FAIL'}] "
            f"{case['id']} | "
            f"expected={expected_outcome} | "
            f"actual={result['outcome']} | "
            f"tools={actual_tools}"
        )
        print(f"  Answer: {result['answer']}")

        if case["expected_state"]:
            print(f"  Expected state: {case['expected_state']}")
            print(f"  Actual state:   {result['final_state']}")

    print()
    print(f"Smoke test: {passed}/{len(cases)} passed")


if __name__ == "__main__":
    main()
