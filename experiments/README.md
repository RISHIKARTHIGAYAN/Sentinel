# Sentinel V3 — Additional Experiments

This directory contains supplementary experiments conducted to evaluate Sentinel V3's agent security controls with the Cohere Labs Tiny Aya Global model.

## Tiny Aya Security Evaluation

**Notebook:** [`sentinel-tiny-aya-experiment.ipynb`](./sentinel-tiny-aya-experiment.ipynb)

The notebook documents experiments involving:

- Tiny Aya Global model evaluation.
- Direct and indirect prompt-injection scenarios.
- Tool-use and authorization boundary testing.
- Baseline and security-layer comparisons.
- SafeTune-style steering experiments.

These experiments are supplementary to the primary Sentinel V3 benchmark and should be interpreted separately from its 96-case results.

## Reproducibility

Open the notebook in Jupyter or Google Colab. Refer to the notebook for the model configuration, experiment setup, execution steps, and recorded results.

## Notes

- The experiments do not modify the original 96-case benchmark results.
- Results are specific to the documented model, test cases, and experimental setup.
- The notebook is provided for transparency and reproducibility.