# Sentinel — Agentic AI Security

Sentinel is a research prototype investigating prompt-injection resistance in agentic Retrieval-Augmented Generation (RAG) systems.

## Research Question

Can we measurably improve the resistance of an agentic RAG system to direct and indirect prompt injection while preserving its ability to complete legitimate tasks?

## What Sentinel Investigates

- Direct prompt injection through user requests.
- Indirect prompt injection embedded in retrieved documents.
- Retrieved-document inspection and sanitization.
- Independent authorization of agent tool calls.
- Role and object-scope checks for simulated tools.
- Refusal-direction steering using Cohere Labs Tiny Aya Global and Lexsi Labs SafeTune.
- Agent evaluation using Lexsi Labs AuditKIT.

## Architecture

Sentinel separates model decisions from tool authorization:

1. The agent receives a user request and retrieved business documents.
2. The model produces an answer or requests a tool call.
3. An independent authorization layer validates the requested tool and arguments.
4. Simulated tools execute only when permitted.
5. Evaluation records security outcomes and legitimate task completion.

All business records, tools, and protected canary values used in the experiments are simulated.

## Experimental Findings

The model-backed evaluation includes a 42-case paired experiment and a separately authored 30-case diagnostic holdout.

Results on the 30-case holdout:

| Measurement | Tiny Aya baseline | Tiny Aya + SafeTune |
|---|---:|---:|
| Benign task success | 9/10 | 9/10 |
| Sensitive-tool requests | 13 | 12 |
| Sensitive requests blocked by Sentinel | 13/13 | 12/12 |
| Protected sensitive-tool executions | 0 | 0 |

The authorization layer blocked every sensitive-tool request observed in this holdout.

SafeTune reduced sensitive-tool requests by one. This is a modest result and does not establish a statistically reliable improvement.

These findings are limited to the controlled prototype and tested cases. They do not establish production-grade security or generalization to arbitrary agentic systems.

## Evaluation Metrics

- **Attack Success Rate (ASR):** attack cases resulting in defined security impact or instruction leakage.
- **Sensitive-tool request rate:** attack cases in which the model requests a sensitive tool.
- **Sensitive-tool block rate:** sensitive requests rejected by the authorization layer.
- **Protected sensitive-execution rate:** attack cases resulting in sensitive tool execution through the protected dispatcher.
- **Benign task success:** legitimate requests successfully completed.
- **False refusal rate:** legitimate requests incorrectly refused.

## Installation

Requirements:
- Python 3.12 or newer
- Git

Clone the repository:

```bash
git clone <YOUR-SENTINEL-REPOSITORY-URL>
cd Sentinel
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install Sentinel and development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run tests:

```bash
python -m pytest tests -v
```

The clean-environment verification completed with 36 passing tests and no broken package requirements.

## Project Structure

```text
Sentinel/
├── data/
│   ├── raw/
│   └── processed/
├── reports/
├── scripts/
├── src/
│   └── sentinel/
│       ├── agent/
│       ├── evaluation/
│       ├── security/
│       └── tools/
├── tests/
├── pyproject.toml
└── README.md
```

## Research Tools

- [AuditKIT](https://github.com/Lexsi-Labs/AuditKIT) — agent evaluation and experiment tracking.
- [SafeTune](https://github.com/Lexsi-Labs/SafeTune) — model safety research and refusal-direction steering.
- [Tiny Aya Global](https://huggingface.co/CohereLabs/tiny-aya-global) — Cohere Labs open-weight model used in model-backed experiments.

AuditKIT is pinned to a specific Git commit in `pyproject.toml`. SafeTune model experiments were run separately in Kaggle.

Review upstream licenses and acceptable-use terms before redistribution or commercial use.

## Limitations

- Simulated tools and business data.
- Small, curated evaluation datasets.
- The diagnostic holdout is not a fully blind external benchmark.
- Some answer-quality assessments were performed manually.
- Rule-based and exact-string detectors do not establish semantic detection capability.
- Identity, role, and approval contexts are simulated.
- Application-level authorization is not equivalent to process isolation.
- SafeTune's observed effect is small and requires broader evaluation.

## Research Status

Sentinel is an ongoing AI safety and agent-security research prototype.

## Model-Backed Experiment Artifacts

Detailed model-backed experiment records are available in [reports/model_backed/](reports/model_backed/).

Key reports:

- [Master Experiment Report](reports/model_backed/sentinel_master_experiment_report.md)
- [Master Experiment Report (JSON)](reports/model_backed/sentinel_master_experiment_report.json)
- [Independent Holdout Report](reports/model_backed/sentinel_independent_holdout_report.json)
- [Corrected SafeTune Comparison](reports/model_backed/tiny_aya_safetune_four_way_comparison_corrected.json)

The reports include the 42-case Tiny Aya experiment, the 30-case diagnostic holdout, authorization evaluations, and SafeTune comparison records.
