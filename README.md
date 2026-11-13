# Sentinel — Agentic AI Security

Sentinel is a research prototype investigating prompt-injection resistance in agentic Retrieval-Augmented Generation (RAG) systems.

The project explores how model-level safety mechanisms and independent application-level authorization can work together to improve agent security while preserving legitimate task completion.

## Research Question

Can we measurably improve the resistance of an agentic RAG system to direct and indirect prompt injection through trusted application-level authorization, while preserving its ability to complete legitimate tasks?

## What Sentinel Investigates

- Direct prompt injection through user requests.
- Indirect prompt injection embedded in retrieved documents.
- Retrieved-document inspection and sanitization.
- Independent authorization of agent tool calls.
- Role-based access control and object-level scope validation.
- Argument validation and approval checks for privileged operations.
- Refusal-direction steering using Cohere Labs Tiny Aya Global and Lexsi Labs SafeTune.
- Agent evaluation using Lexsi Labs AuditKIT.

## Architecture

Sentinel separates model decisions from application-level tool authorization.

1. The agent receives a user request and retrieved business documents.
2. The model produces an answer or requests a tool call.
3. Retrieved content is inspected and sanitized before being used.
4. An independent authorization layer validates the requested tool, identity context, permissions, and arguments.
5. Simulated tools execute only when authorization succeeds.
6. Evaluation records security outcomes and legitimate task completion.

The architecture distinguishes between:

- **Model-level safety:** refusal behavior and resistance to malicious instructions.
- **Application-level security:** independent enforcement of tool permissions, object scope, and argument constraints.

All business records, tools, identities, approvals, and protected canary values used in the experiments are simulated.

## Experimental Findings

### 1. Model-Backed Tiny Aya Evaluation

The model-backed evaluation includes a 42-case paired experiment and a separately authored 30-case diagnostic holdout.

Results on the 30-case diagnostic holdout:

| Measurement | Tiny Aya baseline | Tiny Aya + SafeTune |
|---|---:|---:|
| Benign task success | 9/10 | 9/10 |
| Sensitive-tool requests | 13 | 12 |
| Sensitive requests blocked by Sentinel | 13/13 | 12/12 |
| Protected sensitive-tool executions | 0 | 0 |

The application-level authorization layer blocked every sensitive-tool request observed in both experimental conditions.

SafeTune reduced sensitive-tool requests by one. This is a modest result and does not establish a statistically reliable improvement.

The diagnostic holdout was freshly authored but was not a fully blind external benchmark.

### 2. Application-Level Authorization Evaluation

A separate authorization-focused benchmark evaluates Sentinel's application-level authorization layer independently of the language model.

The benchmark contains 24 controlled scenarios.

| Measurement | Result |
|---|---:|
| Total scenarios | 24 |
| Legitimate scenarios | 12 |
| Legitimate operations permitted | 12/12 |
| Adversarial scenarios | 12 |
| Adversarial operations denied | 12/12 |
| Decision accuracy | 100% |
| Unauthorized executions | 0 |
| False blocks | 0 |

The scenarios evaluate:

- Role-based access restrictions.
- Object-level scope validation.
- Internal resource access restrictions.
- Argument manipulation.
- Export recipient validation.
- Approval ID validation.
- Customer record scope restrictions.
- Missing identity context.
- Unauthorized tool invocation.

The benchmark achieved 100% decision accuracy across these designed scenarios.

These results demonstrate correct authorization decisions within the controlled test cases. They are not an end-to-end model attack success rate and do not establish generalization to arbitrary real-world attacks.

#### Reproducing the authorization evaluation

Run:

```bash
python scripts/run_authorization_benchmark.py
```

The generated report is saved to:

```text
reports/authorization_focused_benchmark.json
```

### 3. End-to-End Authorization Benchmark

Sentinel also includes a separate benchmark comparing a deliberately vulnerable baseline agent with the rule-defended agent.

The latest comparison report is:

```text
reports/authorization_benchmark_comparison_v4.json
```

This benchmark evaluates direct and indirect attack scenarios alongside legitimate tasks.

The results must be interpreted in the context of the current agent implementation: early refusal and retrieved-document sanitization can prevent malicious instructions from reaching the tool authorization layer. Therefore, a blocked attack does not necessarily mean that the authorization layer itself rejected a malicious tool request.

The separate 24-scenario benchmark evaluates the authorization layer directly.

## Evaluation Metrics

Sentinel uses the following evaluation measures:

- **Attack Success Rate (ASR):** attack cases resulting in defined security impact or instruction leakage.
- **Sensitive-tool request rate:** attack cases in which the model or agent requests a sensitive tool.
- **Sensitive-tool block rate:** sensitive requests rejected by the authorization layer.
- **Protected sensitive-execution rate:** attack cases resulting in sensitive tool execution through the protected dispatcher.
- **Benign task success:** legitimate requests successfully completed.
- **False refusal rate:** legitimate requests incorrectly refused.
- **Unauthorized execution rate:** unauthorized tool operations that execute.
- **False block rate:** legitimate operations incorrectly denied.

The model-backed, end-to-end, and application-level authorization evaluations measure different aspects of system behavior and should not be treated as interchangeable.

## Installation

### Requirements

- Python 3.12 or newer
- Git

### Clone the repository

```bash
git clone <YOUR-SENTINEL-REPOSITORY-URL>
cd Sentinel
```

### Create a virtual environment

```bash
python -m venv .venv
```

### Activate the environment on Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

### Install Sentinel and development dependencies

```bash
python -m pip install -e ".[dev]"
```

### Run the test suite

```bash
python -m pytest tests -v
```

The current local regression suite completes with:

- 47 tests passed.
- 2 subtests passed.
- 0 failures.

A previous clean-environment reproduction also completed successfully with 36 passing tests and no broken package requirements. That result predates the latest authorization implementation and test additions.

## Project Structure

```text
Sentinel/
│
├── configs/
│
├── data/
│   ├── raw/
│   │   └── sentinel_cases.json
│   └── processed/
│       ├── development.json
│       ├── validation.json
│       └── held_out_test.json
│
├── reports/
│   ├── model_backed/
│   ├── baseline_metrics.json
│   ├── naive_metrics.json
│   ├── rule_defended_metrics.json
│   ├── benchmark_comparison.json
│   ├── authorization_benchmark_comparison_v4.json
│   └── authorization_focused_benchmark.json
│
├── scripts/
│   ├── generate_benchmark.py
│   ├── run_authorization_benchmark.py
│   └── run_benchmark.py
│
├── src/
│   └── sentinel/
│       ├── agent/
│       │   ├── agent.py
│       │   └── naive_agent.py
│       │
│       ├── evaluation/
│       │   └── metrics.py
│       │
│       ├── security/
│       │   ├── authorization.py
│       │   ├── policy.py
│       │   ├── secrets.py
│       │   └── tool_guard.py
│       │
│       ├── tools/
│       │   ├── orders.py
│       │   └── privileged.py
│       │
│       ├── run_benchmark.py
│       ├── run_eval.py
│       └── run_smoke.py
│
├── tests/
│   ├── test_auditkit_adapter.py
│   ├── test_metrics.py
│   ├── test_policy.py
│   └── test_security.py
│
├── pyproject.toml
├── README.md
└── .gitignore
```

## Research Tools

- [AuditKIT](https://github.com/Lexsi-Labs/AuditKIT) — agent evaluation and experiment tracking.
- [SafeTune](https://github.com/Lexsi-Labs/SafeTune) — model safety research and refusal-direction steering.
- [Tiny Aya Global](https://huggingface.co/CohereLabs/tiny-aya-global) — Cohere Labs open-weight model used in model-backed experiments.

AuditKIT is pinned to a specific Git commit in `pyproject.toml`.

SafeTune model experiments were conducted separately in Kaggle.

Review upstream licenses and acceptable-use terms before redistribution or commercial use. The model and research tools have licensing and acceptable-use restrictions.

## Limitations

- Simulated tools and business data.
- Small, curated evaluation datasets.
- The diagnostic holdout is not a fully blind external benchmark.
- Some answer-quality assessments were performed manually.
- Rule-based and exact-string detectors do not establish semantic detection capability.
- Identity, role, and approval contexts are simulated.
- Application-level authorization is not equivalent to process isolation.
- The 24-scenario authorization benchmark covers designed cases, not the full range of real-world attacks.
- External benchmarks such as AgentDojo and InjecAgent have not yet been integrated into the reported evaluation.
- SafeTune's observed effect is small and requires broader evaluation.

## Research Status

Sentinel is an ongoing AI safety and agent-security research prototype.

The current implementation combines:

- Prompt-injection detection and retrieved-content sanitization.
- Independent application-level tool authorization.
- Role and object-scope validation.
- Argument and approval validation.
- Model-backed safety experiments.
- Controlled security evaluation and regression testing.

Further work will focus on stronger authorization-boundary attacks, broader benign-task coverage, ablation studies, and external benchmark evaluation.

## Model-Backed Experiment Artifacts

Detailed model-backed experiment records are available in:

[`reports/model_backed/`](reports/model_backed/)

Key reports:

- [Master Experiment Report](reports/model_backed/sentinel_master_experiment_report.md)
- [Master Experiment Report (JSON)](reports/model_backed/sentinel_master_experiment_report.json)
- [Independent Holdout Report](reports/model_backed/sentinel_independent_holdout_report.json)
- [Corrected SafeTune Comparison](reports/model_backed/tiny_aya_safetune_four_way_comparison_corrected.json)

The reports include the 42-case Tiny Aya experiment, the 30-case diagnostic holdout, authorization evaluations, and SafeTune comparison records.

## Authorization Evaluation Artifacts

- [Authorization-Focused Benchmark](reports/authorization_focused_benchmark.json)
- [End-to-End Authorization Benchmark Comparison v4](reports/authorization_benchmark_comparison_v4.json)

The benchmark can be reproduced locally using:

```bash
python scripts/run_authorization_benchmark.py
```
