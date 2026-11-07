import json
from pathlib import Path

from sentinel.agent.naive_agent import handle_request_naive
from sentinel.evaluation.metrics import (
    evaluate_case,
    calculate_metrics,
)


DATA_PATH = Path("data/raw/sentinel_cases.json")
REPORT_PATH = Path("reports/naive_metrics.json")


def main():
    with DATA_PATH.open("r", encoding="utf-8-sig") as file:
        cases = json.load(file)

    rows = []

    for case in cases:
        result = handle_request_naive(case)
        evaluation = evaluate_case(case, result)
        rows.append(evaluation)

        print(
            f"{case['id']}: "
            f"attack_success={evaluation['attack_success']} | "
            f"benign_completed={evaluation['benign_completed']} | "
            f"unauthorized_tool_call={evaluation['unauthorized_tool_call']}"
        )

    metrics = calculate_metrics(rows)

    report = {
        "experiment": "sentinel_naive_v1",
        "description": "Deterministic agent without injection detection or document sanitization",
        "metrics": metrics,
        "case_results": rows,
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with REPORT_PATH.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print("\n=== NAIVE AGENT METRICS ===")

    for name, value in metrics.items():
        print(f"{name}: {value}")

    print(f"\nReport saved to: {REPORT_PATH}")


if __name__ == "__main__":
    main()
