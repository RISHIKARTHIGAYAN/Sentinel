
"""Structured, auditable report generation for Sentinel V3."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.evaluation.v3.metrics import generate_report


SYSTEM_VARIANTS = {
    "baseline",
    "safetune_only",
    "authorization_only",
    "combined",
}

ABLATION_SWITCHES = {
    "sanitization",
    "permissions",
    "argument_validation",
    "scope_checks",
    "direct_attack_detection",
    "task_intent_enforcement",
    "output_protection",
}


def validate_experiment_config(config: dict[str, Any]) -> None:
    """Validate the experiment configuration stored with each report."""
    if not isinstance(config, dict):
        raise TypeError("experiment must be a dictionary")

    variant = config.get("system_variant")
    if variant not in SYSTEM_VARIANTS:
        raise ValueError(
            f"system_variant must be one of {sorted(SYSTEM_VARIANTS)}"
        )

    model = config.get("model")
    if model is not None and (
        not isinstance(model, str) or not model.strip()
    ):
        raise ValueError("model must be a non-empty string or None")

    seed = config.get("seed")
    if seed is not None and (
        isinstance(seed, bool) or not isinstance(seed, int)
    ):
        raise ValueError("seed must be an integer or None")


def validate_ablation_config(config: dict) -> dict:
    if not isinstance(config, dict):
        raise TypeError("Ablation configuration must be a dictionary")

    allowed_switches = {
        "sanitization",
        "permissions",
        "argument_validation",
        "scope_checks",
        "direct_attack_detection",
        "task_intent_enforcement",
        "output_protection",
    }

    # Preserve the original four-switch configuration contract.
    required_switches = {
        "sanitization",
        "permissions",
        "argument_validation",
        "scope_checks",
    }

    unknown = set(config) - allowed_switches
    if unknown:
        raise ValueError(
            f"Unknown ablation switches: {sorted(unknown)}"
        )

    # Validate supplied values before checking missing keys.
    for name, value in config.items():
        if not isinstance(value, bool):
            raise TypeError(
                f"Ablation switch '{name}' must be a boolean"
            )

    missing = required_switches - set(config)
    if missing:
        raise ValueError(
            f"Missing required ablation switches: {sorted(missing)}"
        )

    return dict(config)


def build_experiment_report(
    evaluated_records: list[dict[str, Any]],
    experiment: dict[str, Any],
    ablation: dict[str, Any],
) -> dict[str, Any]:
    """Build a JSON-serializable report with metrics and evaluated records."""
    if not isinstance(evaluated_records, list):
        raise TypeError("evaluated_records must be a list")

    validate_experiment_config(experiment)
    validate_ablation_config(ablation)

    metrics_report = generate_report(evaluated_records)

    report = {
        "report_version": "3.0",
        "experiment": dict(experiment),
        "ablation": dict(ablation),
        "metrics": metrics_report,
        "evaluated_records": evaluated_records,
    }

    try:
        json.dumps(
            report,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Report contains non-JSON-compatible data: {exc}"
        ) from exc

    return report


def write_experiment_report(
    report: dict[str, Any],
    output_path: str | Path,
    *,
    overwrite: bool = False,
) -> Path:
    """Write a formatted JSON report without accidental overwrites."""
    if not isinstance(report, dict):
        raise TypeError("report must be a dictionary")

    path = Path(output_path)

    if path.exists() and not overwrite:
        raise FileExistsError(
            f"Report already exists: {path}. "
            "Pass overwrite=True to replace it intentionally."
        )

    try:
        serialized = json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Report cannot be serialized to JSON: {exc}"
        ) from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized + "\n", encoding="utf-8")

    return path
