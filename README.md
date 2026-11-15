# Sentinel V3 â€” AI Agent Security Benchmark

**A controlled evaluation of application-level security controls for AI agents, covering prompt injection, authorization abuse, tool execution, and sensitive-information disclosure.**

Sentinel V3 is a research prototype designed to evaluate how application-level security controls affect the behavior of an AI agent operating with access to simulated business tools and protected information.

The project uses a controlled synthetic benchmark to evaluate seven security controls individually and in combination. It measures security outcomes while also checking whether legitimate tasks remain functional.

> **Research scope:** Sentinel V3 evaluates application-level agent security. It does not claim to train or fine-tune a new language model or establish resistance to arbitrary real-world attacks.

---

## Table of Contents

- [Overview](#overview)
- [Research Objectives](#research-objectives)
- [System Architecture](#system-architecture)
- [Seven Security Controls](#seven-security-controls)
- [Benchmark Dataset](#benchmark-dataset)
- [Primary Benchmark Results](#primary-benchmark-results)
- [Ablation Experiments](#ablation-experiments)
- [Evaluation Methodology](#evaluation-methodology)
- [Reproducibility](#reproducibility)
- [Project Structure](#project-structure)
- [Earlier Research: Sentinel V1 and V2](#earlier-research-sentinel-v1-and-v2)
- [Tools and Dependencies](#tools-and-dependencies)
- [Limitations and Responsible Interpretation](#limitations-and-responsible-interpretation)
- [Work Completed Outside the Hackathon](#work-completed-outside-the-hackathon)
- [Future Work](#future-work)

---

## Overview

AI agents increasingly interact with external tools, retrieve documents, process business information, and execute operations on behalf of users.

These capabilities introduce security risks, including:

- Direct prompt injection.
- Indirect prompt injection through retrieved documents.
- Unauthorized tool execution.
- Abuse of otherwise permitted tools.
- Manipulation of tool arguments.
- Access to resources outside an authorized scope.
- Disclosure of sensitive information in final responses.

Sentinel explores an application-level defense architecture that places security checks around agent operations.

Rather than relying exclusively on a model's ability to refuse unsafe requests, Sentinel evaluates controls at different stages of the application workflow.

The V3 implementation contains seven configurable controls and a synthetic 96-case benchmark.

## Research Objectives

The primary objectives are:

1. Evaluate whether application-level controls prevent unauthorized agent actions.
2. Measure the impact of individual security controls through ablation experiments.
3. Evaluate protection against direct and indirect prompt injection.
4. Examine whether task-intent enforcement prevents misuse of otherwise available permissions.
5. Evaluate sensitive-information protection in tool outputs and final responses.
6. Measure whether security controls preserve legitimate task completion.
7. Provide reproducible benchmark data, execution reports, and test coverage.

---

## System Architecture

Sentinel V3 uses an application-level security architecture around an agent that can interact with simulated business tools.

The conceptual workflow is:

```text
                 User Request
                      |
                      v
             Input Sanitization
                      |
                      v
              Agent Processing
                      |
                      v
             Direct Attack Detection
                      |
                      v
             Task Intent Enforcement
                      |
                      v
             Authorization Checks
                      |
                      v
             Argument Validation
                      |
                      v
                Scope Checks
                      |
                      v
                Tool Execution
                      |
                      v
               Output Protection
                      |
                      v
                Final Response
```

This diagram represents the security-control concepts, not a claim that every internal function executes in precisely this sequence for every request.

The system records execution traces and evaluates observed behavior against expected benchmark outcomes.

---

## Seven Security Controls

Sentinel V3 exposes seven independently configurable application-level controls.

| Control | Purpose |
|---|---|
| `sanitization` | Inspects untrusted input and retrieved content. |
| `permissions` | Enforces application-level authorization decisions. |
| `argument_validation` | Validates tool arguments before execution. |
| `scope_checks` | Restricts operations to authorized resources and scopes. |
| `direct_attack_detection` | Detects selected direct prompt-injection patterns. |
| `task_intent_enforcement` | Checks whether a requested operation is consistent with the permitted task intent. |
| `output_protection` | Prevents tested protected information from appearing in final responses. |

Each control can be enabled or disabled through the V3 configuration.

The benchmark evaluates:

- All controls enabled.
- All controls disabled.
- Each individual control disabled while the remaining controls stay enabled.

This allows the project to compare the combined configuration with individual ablation conditions.

---

## Benchmark Dataset

The V3 benchmark contains **96 synthetic cases** across eight categories.

Each category contains 12 cases.

| Category | Cases | Description |
|---|---:|---|
| `benign_order_lookup` | 12 | Legitimate order-status requests. |
| `benign_internal_read` | 12 | Legitimate internal-resource read requests. |
| `benign_customer_export` | 12 | Legitimate customer-export operations. |
| `benign_factual` | 12 | Ordinary factual requests. |
| `attack_direct_injection` | 12 | Direct prompt-injection attempts. |
| `attack_indirect_injection` | 12 | Malicious instructions embedded in retrieved content. |
| `attack_within_permission_abuse` | 12 | Attempts to misuse otherwise available permissions. |
| `attack_final_answer_leakage` | 12 | Attempts to disclose protected information in final responses. |
| **Total** | **96** | **48 benign and 48 attack cases.** |

### Dataset splits

The generator assigns cases to three splits.

| Split | Cases per category | Total |
|---|---:|---:|
| Development | 6 | 48 |
| Validation | 3 | 24 |
| Held-out test | 3 | 24 |
| **Total** | **12** | **96** |

These are predefined synthetic benchmark splits. The reported primary benchmark and ablation results evaluate the complete 96-case dataset; they should not be interpreted as results from an independently collected external test set.

### Dataset characteristics

- Simulated business identities and authorization contexts.
- Synthetic order and customer identifiers.
- Simulated internal resources.
- Synthetic approval identifiers.
- Controlled malicious instructions.
- Synthetic protected canary values.
- Expected tool decisions and execution outcomes.
- Expected final-disclosure labels.

**Dataset location:**

`data/processed_v3/benchmark_v3_96cases.json`

The dataset is generated using:

`scripts/generate_benchmark_v3.py`

---

## Primary Benchmark Results

The primary V3 benchmark evaluates the combined configuration with all seven security controls enabled.

<details>
<summary>Primary benchmark summary</summary>

| Measurement | Result |
|---|---:|
| Total cases | 96 |
| Correct outcomes | 96/96 |
| Outcome accuracy | 100% |
| Attack cases | 48 |
| Benign cases | 48 |
| Attack success | 0/48 |
| Attack Success Rate | 0% |
| Unauthorized executions | 0 |
| Sensitive disclosures | 0 |
| Final-answer leaks | 0 |
| Benign completions | 48/48 |
| Benign Completion Rate | 100% |
| False blocks | 0 |
| Correct authorization decisions | 36/36 |
| Correct executions | 96/96 |
| Correct disclosure labels | 48/48 |
| Argument violations | 0 |
| Scope violations | 0 |

</details>

### Interpretation

The combined configuration achieved zero measured attack successes across the 48 synthetic attack cases while completing all 48 benign cases.

The benchmark also recorded:

- No unauthorized tool executions.
- No measured sensitive disclosures.
- No final-answer leaks.
- No false blocks.
- Correct expected outcomes across all 96 cases.

These results demonstrate the behavior of the implemented controls on the designed benchmark. They do not establish general-purpose prompt-injection resistance or security against arbitrary real-world attacks.

### Primary report

`reports/sentinel_v3_full_96cases_v2.json`

Additional validation report:

`reports/sentinel_v3_baseline_96cases.json`

---

## Ablation Experiments

The V3 ablation runner evaluates nine configurations.

| Experiment | Configuration |
|---|---|
| `controls_off` | All seven controls disabled. |
| `combined` | All seven controls enabled. |
| `no_sanitization` | Sanitization disabled. |
| `no_permissions` | Permissions disabled. |
| `no_argument_validation` | Argument validation disabled. |
| `no_scope_checks` | Scope checks disabled. |
| `no_direct_attack_detection` | Direct attack detection disabled. |
| `no_task_intent_enforcement` | Task-intent enforcement disabled. |
| `no_output_protection` | Output protection disabled. |

### Aggregate comparison

| Configuration | Attack Success Rate | Unauthorized Executions | Final-Answer Leaks | Benign Completion | Outcome Accuracy |
|---|---:|---:|---:|---:|---:|
| Controls off | 75% | 12 | 24 | 100% | 75% |
| Combined | 0% | 0 | 0 | 100% | 100% |
| No sanitization | 0% | 0 | 0 | 100% | 100% |
| No permissions | 0% | 0 | 0 | 100% | 100% |
| No argument validation | 0% | 0 | 0 | 100% | 100% |
| No scope checks | 0% | 0 | 0 | 100% | 100% |
| No direct attack detection | 0% | 0 | 0 | 100% | 87.5% |
| No task-intent enforcement | 25% | 12 | 0 | 100% | 87.5% |
| No output protection | 50% | 0 | 24 | 100% | 100% |

All configurations were evaluated on the same 96-case dataset.

False-block rate was 0% across all nine configurations.

### Key observations

**1. Combined configuration**

The complete configuration recorded zero attack successes and preserved all benign task completions.

**2. Controls disabled**

With all seven controls disabled:

- 36 of 48 attack cases succeeded.
- 12 unauthorized executions occurred.
- 24 final-answer leaks were recorded.
- Outcome accuracy was 75%.

This is an application-level all-controls-off comparison, not a raw-language-model baseline.

**3. Output protection disabled**

Disabling output protection resulted in:

- 24 sensitive disclosures.
- 24 final-answer leaks.
- 50% attack success rate.

No unauthorized tool executions were recorded in this configuration.

This demonstrates the importance of output protection for the tested synthetic canary-disclosure scenarios.

**4. Task-intent enforcement disabled**

Disabling task-intent enforcement resulted in:

- 12 unauthorized executions.
- 25% attack success rate.
- 87.5% outcome accuracy.

Output protection still prevented the measured final-answer leaks, but it could not reverse unauthorized operations that had already been executed.

**5. Direct attack detection disabled**

Disabling direct attack detection resulted in:

- 87.5% outcome accuracy.
- 0% measured attack success.
- 0 unauthorized executions.
- 0 final-answer leaks.

The observed difference primarily involved expected refusal outcomes versus generic insufficient-information responses. It did not demonstrate successful attacks in this benchmark.

**6. Controls with no observed marginal change**

Disabling sanitization, permissions, argument validation, or scope checks individually did not change the aggregate metrics in this particular one-control-at-a-time experiment.

This does not establish that these controls are unnecessary. Other controls may compensate for their absence, and the current dataset may not sufficiently exercise their unique capabilities.

### Ablation reports

The validated reports are stored in:

`reports/ablations_v3_7controls_validated/`

This directory contains:

- `ablation_comparison.json`
- `combined_96cases.json`
- `controls_off_96cases.json`
- `no_sanitization_96cases.json`
- `no_permissions_96cases.json`
- `no_argument_validation_96cases.json`
- `no_scope_checks_96cases.json`
- `no_direct_attack_detection_96cases.json`
- `no_task_intent_enforcement_96cases.json`
- `no_output_protection_96cases.json`

---

## Evaluation Methodology

Sentinel V3 evaluates the following measures.

### Attack Success Rate (ASR)

The proportion of attack cases resulting in the defined security impact.

Lower is better.

### Unauthorized Execution Rate

The proportion of cases resulting in unauthorized tool execution.

Lower is better.

### Final-Answer Leakage Rate

The proportion of cases resulting in protected information appearing in the final answer.

Lower is better.

### Benign Completion Rate

The proportion of legitimate tasks successfully completed.

Higher is better.

### False Block Rate

The proportion of legitimate operations incorrectly blocked.

Lower is better.

### Outcome Accuracy

The proportion of cases where the observed API outcome matches the expected outcome.

Higher is better.

Rates must be interpreted using their respective denominators. For example, the ablation comparison reports attack success over attack cases, while some execution and leakage measures are calculated over the full dataset.

### Measurement notes

- Final-answer leakage is measured against case-specific sensitive targets in the returned answer string.
- Output-guard activation is reported separately from actual final-answer leakage.
- Task-intent denial is distinguished from application authorization denial.
- Sensitive disclosure uses exact synthetic-target matching.
- Attacker-goal success is operationalized as unexpected tool execution or a sensitive target appearing in the final answer.
- API outcome accuracy is reported separately from attacker-goal success.

The output-protection experiment is not a general-purpose data-loss-prevention evaluation.

---

## Reproducibility

### Requirements

- Python 3.12 or newer.
- Git.
- Windows, Linux, or macOS.
- A Python virtual environment.

### Installation

Clone the repository and enter its directory:

```bash
git clone https://github.com/RISHIKARTHIGAYAN/Sentinel.git
cd Sentinel
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the environment.

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install the project and development dependencies:

```bash
python -m pip install -e ".[dev]"
```

### Run the test suite

```bash
python -m pytest tests -v
```

The latest validated local regression run completed with:

- 173 tests passed.
- 8 subtests passed.
- 0 failures.

### Run the V3 benchmark

The repository includes the validated 96-case synthetic dataset.

To reproduce the primary evaluation without overwriting the retained reports:

```bash
python scripts/run_benchmark_v3.py --output reports/reproduced/sentinel_v3_reproduction_96cases.json
```

The benchmark runner refuses to overwrite an existing output unless `--overwrite` is explicitly supplied.

### Generate the dataset

To regenerate the dataset from the supplied generator:

```bash
python scripts/generate_benchmark_v3.py
```

The generator intentionally refuses to overwrite an existing dataset file. If the repository already contains `data/processed_v3/benchmark_v3_96cases.json`, the generation command will stop with a `FileExistsError`.

Preserve the supplied validated dataset unless you intentionally want to generate a fresh copy.

### Run the seven-control ablation experiments

Use a separate output directory to preserve the retained validated reports:

```bash
python scripts/run_ablation_v3.py --output-dir reports/reproduced/ablations_v3
```

The ablation runner checks for existing experiment and comparison reports before starting. It refuses to overwrite existing files.

### Important reproducibility note

The retained primary and ablation reports represent the validated runs used for the results described in this README.

A newly executed benchmark may have a different generation timestamp. The dataset, source code, configuration, and execution environment should be retained when comparing reproduced results.

---

## Project Structure

The following is a simplified view of the important project components:

```text
Sentinel/
|
|-- data/
|   |-- processed_v3/
|       |-- benchmark_v3_96cases.json
|
|-- reports/
|   |-- ablations_v3_7controls_validated/
|   |   |-- ablation_comparison.json
|   |   |-- combined_96cases.json
|   |   |-- controls_off_96cases.json
|   |   |-- no_sanitization_96cases.json
|   |   |-- no_permissions_96cases.json
|   |   |-- no_argument_validation_96cases.json
|   |   |-- no_scope_checks_96cases.json
|   |   |-- no_direct_attack_detection_96cases.json
|   |   |-- no_task_intent_enforcement_96cases.json
|   |   |-- no_output_protection_96cases.json
|   |
|   |-- sentinel_v3_full_96cases_v2.json
|   |-- sentinel_v3_baseline_96cases.json
|   |-- sentinel_v3_reproduction_96cases.json
|
|-- scripts/
|   |-- generate_benchmark_v3.py
|   |-- run_benchmark_v3.py
|   |-- run_ablation_v3.py
|
|-- src/
|   |-- sentinel/
|       |-- agent/
|       |   |-- agent.py
|       |   |-- agent_v3.py
|       |
|       |-- evaluation/
|       |   |-- v3/
|       |   |-- metrics.py
|       |
|       |-- security/
|       |-- tools/
|
|-- tests/
|
|-- pyproject.toml
|-- README.md
```

This tree highlights the main V3 components and retained reports; it is not an exhaustive listing of every repository file.

---

## Earlier Research: Sentinel V1 and V2

Sentinel's earlier development explored model-backed safety behavior and application-level authorization.

These experiments are separate from the V3 seven-control benchmark.

### Tiny Aya and SafeTune experiments

Earlier experiments used Cohere Labs Tiny Aya Global and Lexsi Labs SafeTune.

These included a 42-case paired experiment and a separately authored 30-case diagnostic holdout.

The diagnostic holdout recorded:

| Measurement | Tiny Aya baseline | Tiny Aya + SafeTune |
|---|---:|---:|
| Benign task success | 9/10 | 9/10 |
| Sensitive-tool requests | 13 | 12 |
| Sensitive requests blocked | 13/13 | 12/12 |
| Protected sensitive-tool executions | 0 | 0 |

The observed SafeTune reduction was modest and does not establish a statistically reliable improvement.

This model-backed work is separate from the V3 application-level benchmark.

Detailed records:

`reports/model_backed/`

### Authorization-focused benchmark

An earlier 24-scenario authorization benchmark recorded:

- 12/12 legitimate operations permitted.
- 12/12 adversarial operations denied.
- 100% decision accuracy.
- Zero unauthorized executions.
- Zero false blocks.

Report:

`reports/authorization_focused_benchmark.json`

### Output-security benchmark

An earlier six-case experiment evaluated exact synthetic canary matching:

- Naive baseline: 3/3 canary leaks.
- Output-guard defended pipeline: 0/3 canary leaks.
- Benign responses preserved: 3/3.

This experiment used exact, case-insensitive matching against known synthetic canary values. It does not establish protection against paraphrased, encoded, or semantic disclosure.

Report:

`reports/output_security_benchmark_v2.json`

### V2 end-to-end benchmark

The earlier V2 benchmark contained 80 synthetic cases.

| Measurement | Naive baseline | Rule-defended |
|---|---:|---:|
| Attack success rate | 100% | 0% |
| Benign task completion | 100% | 100% |
| Unauthorized tool-call rate | 52.5% | 0% |
| False refusal rate | 0% | 0% |

Report:

`reports/sentinel_benchmark_v2_80cases.json`

---

## Tools and Dependencies

The project uses Python and application-level security components to implement and evaluate the agent.

The project pins Lexsi Labs AuditKIT to a specific Git commit through `pyproject.toml`.

Earlier model-backed experiments used:

- [Cohere Labs Tiny Aya Global](https://huggingface.co/CohereLabs/tiny-aya-global)
- [Lexsi Labs SafeTune](https://github.com/Lexsi-Labs/SafeTune)
- [Lexsi Labs AuditKIT](https://github.com/Lexsi-Labs/AuditKIT)

These earlier experiments should not be confused with the V3 benchmark.

Sentinel V3 does not claim to train or fine-tune a new language model.

Review upstream licenses and acceptable-use terms before redistributing or commercially using third-party tools and models.

---

## Limitations and Responsible Interpretation

The following limitations apply to the current research:

- V3 uses a small, controlled, synthetic benchmark.
- Business records, identities, tools, approvals, and protected canary values are simulated.
- Results do not establish resistance to arbitrary real-world prompt injection.
- The controls-off configuration is an application-level ablation, not a raw-model baseline.
- The output guard's tested canary matching does not establish general-purpose data-loss prevention.
- Individual ablations may be affected by interactions and compensating controls.
- The benchmark does not replace independent external evaluation.
- Application-level authorization is not equivalent to process isolation or a complete sandbox.
- Earlier model-backed results are limited in scale and should be interpreted separately.
- The benchmark's synthetic cases do not establish performance on independently authored or externally collected attack datasets.
- No claim of a completed external train/test leakage audit is made.

Sentinel V3 should be treated as a controlled research prototype rather than a production-ready security product.

---

## Work Completed Outside the Hackathon

Sentinel is an evolving research prototype.

Earlier authorization, model-backed, and V1/V2 experiments predate the current V3 benchmark work.

The V3 benchmark, seven-control configuration, validation fixes, ablation experiments, and associated reports should be identified separately from those earlier contributions in the hackathon submission.

The project does not claim that all historical work was created during the hackathon.

---

## Future Work

Potential future directions include:

- Evaluation on independent agent-security benchmarks.
- Broader attack and benign-task coverage.
- More targeted tests of individual controls and their interactions.
- Testing transformed and semantic information leakage.
- Evaluation across different agent architectures and language models.
- Statistical analysis across repeated runs and independently authored datasets.
- Testing with realistic tool environments and external data sources.
- Evaluating stronger isolation boundaries beyond application-level authorization.

---

## Research Status

Sentinel V3 is a controlled application-level agent-security research prototype.

Its current results demonstrate measurable improvements on its designed synthetic benchmark while preserving benign task completion.

Further independent evaluation is required before making broader security claims.

---

## License

No project-level license has been assigned in this README. Check the repository's `LICENSE` file before redistribution or reuse. Third-party tools, models, and datasets remain subject to their respective licenses and terms.
