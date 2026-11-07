import argparse
import json
from pathlib import Path

from auditkit.agent_eval import AgentEvalRunner, AgentEvalSpec

from sentinel.agent.agent import handle_request
from sentinel.agent.naive_agent import handle_request_naive

from sentinel.evaluation.auditkit_adapter import (
    build_auditkit_inputs,
)


ROOT = Path(__file__).resolve().parents[2]

SPLITS = [
    "development",
    "validation",
    "held_out_test",
]

AGENTS = {
    "naive_baseline": handle_request_naive,
    "rule_defended": handle_request,
}

SCORERS = [
    "tool_call_f1",
    "tool_call_validity",
    "tool_permission",
]


def load_split(split_name: str) -> list[dict]:
    path = ROOT / "data" / "processed" / f"{split_name}.json"

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def run_agent(agent_name: str, agent_function, cases: list[dict]):
    print(f"\n{'=' * 65}")
    print(f"Running Sentinel agent: {agent_name}")
    print(f"Cases: {len(cases)}")
    print(f"{'=' * 65}")

    sentinel_results = [
        agent_function(case)
        for case in cases
    ]

    audit_cases, audit_episodes = build_auditkit_inputs(
        cases,
        sentinel_results,
    )

    spec = AgentEvalSpec(
        cases=audit_cases,
        mode="recorded",
        episodes=audit_episodes,
        scorers=SCORERS,
        trials=1,
    )

    result = AgentEvalRunner().run(spec)

    print("\nAuditKIT summary:")
    print(result.summary())

    print("\nCase details:")
    print(result.cases_report())

    return {
        "agent": agent_name,
        "case_count": len(cases),
        "scorers": SCORERS,
        "summary": result.summary(),
        "cases_report": result.cases_report(),
        "result": result.to_dict(),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run Sentinel agents through AuditKIT."
    )

    parser.add_argument(
        "--split",
        choices=SPLITS,
        default=None,
        help="Evaluate one benchmark split. Default: all splits.",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit the number of cases for an initial smoke test.",
    )

    parser.add_argument(
        "--agent",
        choices=["all", *AGENTS.keys()],
        default="all",
        help="Select an agent to evaluate.",
    )

    args = parser.parse_args()

    selected_splits = [args.split] if args.split else SPLITS

    cases = []

    for split_name in selected_splits:
        split_cases = load_split(split_name)

        for case in split_cases:
            case["_benchmark_split"] = split_name

        cases.extend(split_cases)

    if args.limit is not None:
        if args.limit < 1:
            raise ValueError("--limit must be greater than zero")
        cases = cases[:args.limit]

    selected_agents = (
        AGENTS.items()
        if args.agent == "all"
        else [(args.agent, AGENTS[args.agent])]
    )

    output = {
        "benchmark": "Sentinel",
        "mode": "recorded",
        "case_count": len(cases),
        "splits": selected_splits,
        "results": [],
    }

    for agent_name, agent_function in selected_agents:
        agent_result = run_agent(
            agent_name,
            agent_function,
            cases,
        )
        output["results"].append(agent_result)

    report_dir = ROOT / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    report_path = report_dir / "auditkit_comparison.json"

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=2, default=str)

    print(f"\nAuditKIT report saved to: {report_path}")


if __name__ == "__main__":
    main()
