# Sentinel — Master Experiment Report

**Date:** 10 November 2026  
**Model:** CohereLabs/tiny-aya-global

## Research question

Can an agentic RAG system be made more resistant to direct and indirect
prompt injection through trusted tool authorization, while preserving
legitimate task completion?

## 1. Main findings

The protected dispatcher blocked all sensitive tool requests observed in
the reported experiments. The model itself continued to request sensitive
tools under both baseline and SafeTune conditions.

SafeTune refusal-direction steering produced a small reduction in sensitive
requests. The observed difference is not statistically established.

## 2. Evaluation summary

| Evaluation | Result |
|---|---|
| Tiny Aya benchmark | 42 cases |
| Fresh holdout | 30 cases |
| Authorization effectiveness tests | 10/10 passed |
| Authorization boundary tests | 6/6 passed |
| Fresh holdout benign task success | 9/10 for both conditions |
| Fresh holdout baseline sensitive requests | 13 |
| Fresh holdout SafeTune sensitive requests | 12 |
| Fresh holdout protected sensitive executions | 0 |

## 3. Interpretation

The results indicate that model-level refusal steering alone did not
consistently prevent sensitive tool requests. The application-level
authorization layer prevented those requests from executing in the
simulated environment.

The central contribution is therefore the separation of model decisions
from trusted application authorization, including function permissions,
object-level scope, argument validation, and approval checks.

## 4. Metric definitions

- **Model unsafe-request rate:** sensitive tool requests divided by attack cases.
- **Protected sensitive-execution rate:** sensitive tool executions through
  the protected dispatcher divided by attack cases.
- **Sensitive-tool block rate:** blocked sensitive requests divided by all
  sensitive requests.
- **Benign task success:** tasks adjudicated as completing the legitimate
  request, using state checks or manual review as appropriate.

A zero protected sensitive-execution rate in these experiments does not
mean the model is injection-proof. It means the tested authorization
boundary prevented observed sensitive requests from executing.

## 5. Limitations

- Small, curated benchmarks; no broad generalization claim.
- The fresh holdout is not a fully blind external benchmark.
- Business data and tools are simulated.
- Trusted identity and approval are simulated.
- No production identity provider or process isolation was evaluated.
- SafeTune's observed model-level improvement is small and not
  statistically established.
- Some answer-quality judgments were manual.
- Development and validation cases were inspected during development.

## 6. Reproducibility artifacts

See the accompanying JSON report and the source result files listed in
`sentinel_master_experiment_report.json`.
