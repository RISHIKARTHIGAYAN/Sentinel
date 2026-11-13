import json
from pathlib import Path

from sentinel.agent.agent import handle_request
from sentinel.agent.naive_agent import handle_request_naive
from sentinel.evaluation.metrics import (
    evaluate_case,
    calculate_metrics,
)
from sentinel.security.authorization import AuthorizationContext
from sentinel.security.tool_guard import clear_audit_events


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data" / "processed"
REPORT_DIR = ROOT / "reports"

SPLITS = [
    "development",
    "validation",
    "held_out_test",
]

BENCHMARK_CONTEXT = AuthorizationContext(
    subject_id="benchmark-support-agent",
    role="support_agent",
    allowed_order_ids=frozenset({"ORD-1001", "ORD-1002"}),
)

AGENTS = {
    "naive_baseline": handle_request_naive,
    "rule_defended": lambda case: handle_request(
        case,
        context=BENCHMARK_CONTEXT,
    ),
}


def load_cases(split):
    path = DATA_DIR / f"{split}.json"

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def evaluate_agent(agent_name, agent_function, split, cases):
    rows = []

    for case in cases:
        clear_audit_events()

        result = agent_function(case)
        evaluation = evaluate_case(case, result)

        row = {
            "agent": agent_name,
            "split": split,
            **evaluation,
            "answer": result.get("answer", ""),
            "tool_requests": result.get("tool_requests", []),
            "tool_calls": result.get("tool_calls", []),
            "authorization_events": result.get(
                "authorization_events", []
            ),
            "final_state": result.get("final_state", {}),
        }

        rows.append(row)

    return rows


def print_comparison(results):
    print("\n" + "=" * 90)
    print("SENTINEL BENCHMARK COMPARISON")
    print("=" * 90)

    metrics_to_show = [
        ("attack_success_rate", "Attack Success Rate"),
        ("security_impact_rate", "Security Impact Rate"),
        ("instruction_leakage_rate", "Instruction Leakage Rate"),
        ("canary_disclosure_rate", "Canary Disclosure Rate"),
        ("unauthorized_tool_call_rate", "Unauthorized Tool-Call Rate"),
        ("benign_task_completion_rate", "Benign Task Completion"),
        ("false_refusal_rate", "False Refusal Rate"),
    ]

    for split, agents in results.items():
        print(f"\n{split.upper()}")
        print("-" * 90)
        print(f"{'Metric':38} {'Naive':>15} {'Defended':>15}")
        print("-" * 90)

        for key, label in metrics_to_show:
            naive = agents["naive_baseline"][key]
            defended = agents["rule_defended"][key]

            print(
                f"{label:38} "
                f"{naive:>14.2f}% "
                f"{defended:>14.2f}%"
            )


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "experiment": "sentinel_authorization_benchmark_v2",
        "description": (
            "Comparison of a deliberately vulnerable scripted baseline "
            "and a rule-defended scripted agent with application-level "
            "role and object-scope authorization."
        ),
        "authorization_context": {
            "subject_id": BENCHMARK_CONTEXT.subject_id,
            "role": BENCHMARK_CONTEXT.role,
            "allowed_order_ids": sorted(
                BENCHMARK_CONTEXT.allowed_order_ids
            ),
        },
        "results": {},
        "aggregate": {},
        "case_results": [],
    }

    aggregate_rows = []

    for split in SPLITS:
        cases = load_cases(split)

        print(f"\nRunning {split}: {len(cases)} cases")

        split_results = {}

        for agent_name, agent_function in AGENTS.items():
            rows = evaluate_agent(
                agent_name,
                agent_function,
                split,
                cases,
            )

            metrics = calculate_metrics(rows)
            split_results[agent_name] = metrics

            report["case_results"].extend(rows)
            aggregate_rows.extend(rows)

            print(
                f"  {agent_name}: "
                f"{metrics['total_cases']} cases evaluated"
            )

        report["results"][split] = split_results

    for agent_name in AGENTS:
        rows = [
            row for row in aggregate_rows
            if row["agent"] == agent_name
        ]

        report["aggregate"][agent_name] = calculate_metrics(rows)

    output_path = REPORT_DIR / "authorization_benchmark_comparison_v4.json"

    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print_comparison(report["results"])

    print("\n" + "=" * 90)
    print("AGGREGATE RESULTS — ALL 60 CASES")
    print("=" * 90)

    for agent_name, metrics in report["aggregate"].items():
        print(f"\n{agent_name}")
        print(
            f"  Attack Success Rate: "
            f"{metrics['attack_success_rate']}%"
        )
        print(
            f"  Benign Task Completion: "
            f"{metrics['benign_task_completion_rate']}%"
        )
        print(
            f"  Unauthorized Tool Calls: "
            f"{metrics['unauthorized_tool_call_rate']}%"
        )
        print(
            f"  False Refusal Rate: "
            f"{metrics['false_refusal_rate']}%"
        )

    print(f"\nFull report saved to: {output_path}")
    print("Benchmark execution: PASS")


if __name__ == "__main__":
    main()