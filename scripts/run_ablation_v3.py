"""Run Sentinel V3 application-level ablation experiments.

All seven application-level security controls are varied independently.
SafeTune/model-level steering is not measured by this runner.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from sentinel.evaluation.v3.dataset import load_dataset
from sentinel.evaluation.v3.metrics import generate_report
from run_benchmark_v3 import run_case


ROOT = Path(__file__).resolve().parents[1]

DEFAULT_DATASET = (
    ROOT / "data" / "processed_v3" / "benchmark_v3_96cases.json"
)

ALL_ON = {
    "sanitization": True,
    "permissions": True,
    "argument_validation": True,
    "scope_checks": True,
    "direct_attack_detection": True,
    "task_intent_enforcement": True,
    "output_protection": True,
}

ALL_OFF = {name: False for name in ALL_ON}

EXPERIMENTS = {
    # Reference conditions
    "controls_off": dict(ALL_OFF),
    "combined": dict(ALL_ON),

    # One-control-at-a-time ablations
    "no_sanitization": {
        **ALL_ON,
        "sanitization": False,
    },
    "no_permissions": {
        **ALL_ON,
        "permissions": False,
    },
    "no_argument_validation": {
        **ALL_ON,
        "argument_validation": False,
    },
    "no_scope_checks": {
        **ALL_ON,
        "scope_checks": False,
    },
    "no_direct_attack_detection": {
        **ALL_ON,
        "direct_attack_detection": False,
    },
    "no_task_intent_enforcement": {
        **ALL_ON,
        "task_intent_enforcement": False,
    },
    "no_output_protection": {
        **ALL_ON,
        "output_protection": False,
    },
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run Sentinel V3 seven-control application ablations."
    )
    parser.add_argument(
        "--experiments",
        nargs="+",
        choices=list(EXPERIMENTS),
        default=list(EXPERIMENTS),
        help="Experiments to run. Defaults to all nine configurations.",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "reports" / "ablations_v3_7controls",
    )
    return parser.parse_args()


def _build_comparison_entry(
    experiment_name: str,
    aggregate: dict,
    output_path: Path,
) -> dict:
    overall = aggregate["overall"]
    return {
        "experiment": experiment_name,
        "controls": EXPERIMENTS[experiment_name],
        "attack_success_rate": overall["attack_success_rate"],
        "unauthorized_execution_rate": (
            overall["unauthorized_execution_rate"]
        ),
        "final_answer_leakage_rate": (
            overall["final_answer_leakage_rate"]
        ),
        "benign_completion_rate": overall["benign_completion_rate"],
        "false_block_rate": overall["false_block_rate"],
        "report": str(output_path),
    }


def main() -> int:
    args = parse_args()

    if not args.dataset.is_file():
        print(f"Dataset not found: {args.dataset}", file=sys.stderr)
        return 1

    try:
        cases = load_dataset(args.dataset, require_complete=True)
    except Exception as exc:
        print(f"Dataset loading failed: {exc}", file=sys.stderr)
        return 1

    selected = args.experiments
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Preflight every output before running anything. This avoids producing
    # a partial batch and only then discovering an existing comparison file.
    output_paths = {
        name: args.output_dir / f"{name}_96cases.json"
        for name in selected
    }
    comparison_path = args.output_dir / "ablation_comparison.json"

    existing = [
        str(path)
        for path in [*output_paths.values(), comparison_path]
        if path.exists()
    ]
    if existing:
        print(
            "Refusing to overwrite existing output(s):\n"
            + "\n".join(existing),
            file=sys.stderr,
        )
        print(
            "Choose a new --output-dir or move the previous reports first.",
            file=sys.stderr,
        )
        return 1

    comparison = []

    for experiment_name in selected:
        controls = EXPERIMENTS[experiment_name]
        output_path = output_paths[experiment_name]

        print("\n" + "=" * 76)
        print(f"EXPERIMENT: {experiment_name}")
        print(f"CONTROLS: {json.dumps(controls, sort_keys=True)}")
        print("=" * 76)

        evaluated_records = []
        diagnostics = []
        failures = []

        for index, case in enumerate(cases, start=1):
            try:
                evaluated, diagnostic = run_case(case, controls)
                evaluated_records.append(evaluated)
                diagnostics.append(diagnostic)

                status = (
                    "PASS"
                    if evaluated["execution_correct"]
                    and evaluated["outcome_correct"]
                    and not evaluated["attack_success"]
                    and not evaluated["false_block"]
                    else "REVIEW"
                )

                print(
                    f"[{index:02d}/{len(cases):02d}] "
                    f"{case['id']} -> {status}"
                )

            except Exception as exc:
                failures.append({
                    "id": case.get("id"),
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                })
                print(f"[{index:02d}/{len(cases):02d}] ERROR: {exc}")

        if failures:
            print("Experiment failed; no report written.")
            print(json.dumps(failures, indent=2))
            return 1

        if len(evaluated_records) != len(cases):
            print(
                "Experiment produced an incomplete record set; "
                "no report written.",
                file=sys.stderr,
            )
            return 1

        aggregate = generate_report(evaluated_records)

        report = {
            "metadata": {
                "benchmark": "Sentinel V3",
                "experiment": experiment_name,
                "system_variant": "application_ablation",
                "ablation": controls,
                "dataset_path": str(args.dataset),
                "case_count": len(cases),
                "generated_at_utc": datetime.now(
                    timezone.utc
                ).isoformat(),
                "notes": [
                    "These experiments vary seven application-level controls.",
                    "The controls_off condition disables the seven switches "
                    "but is not a raw-model or SafeTune baseline.",
                    "The combined condition enables all seven switches.",
                    "One-control-at-a-time experiments disable only the "
                    "named control while leaving the other six enabled.",
                    "Retrieved documents do not independently initiate "
                    "tool calls in this simulated agent architecture.",
                    "Output protection tests exact synthetic canary matching; "
                    "it is not general-purpose DLP.",
                    "Synthetic benchmark results do not establish "
                    "general-purpose prompt-injection resistance.",
                ],
            },
            "aggregate": aggregate,
            "evaluated_records": evaluated_records,
            "case_diagnostics": diagnostics,
        }

        temporary_path = output_path.with_suffix(".json.tmp")
        temporary_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        temporary_path.replace(output_path)

        comparison.append(
            _build_comparison_entry(
                experiment_name,
                aggregate,
                output_path,
            )
        )

        print("\nRESULT:")
        print(json.dumps(aggregate["overall"], indent=2))
        print(f"Saved: {output_path}")

    comparison_report = {
        "benchmark": "Sentinel V3",
        "system_variant": "application_ablation",
        "dataset_path": str(args.dataset),
        "case_count": len(cases),
        "experiments": comparison,
        "notes": [
            "All rates are computed on the same selected dataset.",
            "controls_off is not a raw-model or SafeTune baseline.",
            "SafeTune/model-level steering is not evaluated here.",
        ],
    }

    comparison_path.write_text(
        json.dumps(comparison_report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n" + "=" * 76)
    print("ABLATION COMPARISON")
    print("=" * 76)
    print(json.dumps(comparison_report, indent=2))
    print(f"\nComparison saved: {comparison_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
