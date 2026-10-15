# Contributing to NetRoute

Thank you for your interest in contributing to the **NetRoute** mathematical framework and routing verification toolkit.

## Mathematical Rigor & Code Integrity

NetRoute bridges theoretical routing algebra (semirings, order theory, spectral graph theory) with production-ready networking algorithms. All contributions must adhere to the following principles:

1. **Axiomatic Consistency**: Any new algebraic structure or semiring must satisfy formal semiring axioms ($(\oplus, \bar{0})$ monoid, $(\otimes, \bar{1})$ monoid, distributivity, and monotonicity).
2. **Zero Mandatory Heavy Dependencies**: The core algorithms (`netroute.algebra`, `netroute.checker`, `netroute.graph`, `netroute.anomaly`) are designed to run out-of-the-box on standard Python 3.9+ without third-party C-bindings.
3. **100% Test Coverage for Invariants**: Any new route invariant or anomaly detector must come accompanied by tests validating both normal conditions and adversarial counter-examples.

## Local Development Workflow

```bash
# Clone the repository
git clone https://github.com/netroute-research/netroute.git
cd netroute

# Install package in editable mode
pip install -e .

# Run all unit tests
python -m unittest discover -s tests -v

# Run the performance benchmark
netroute benchmark --k 4
```

## Pull Request Guidelines

- Ensure all existing unit tests pass on Python 3.9 through 3.13.
- If introducing a new mathematical formula or anomaly detector, provide LaTeX documentation in `docs/THEORETICAL_FOUNDATION.md`.
- Format code cleanly according to PEP 8.
