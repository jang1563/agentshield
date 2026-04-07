# Contributing to AgentShield

Thank you for your interest in contributing. This document explains how to set up a development environment and submit changes.

## Development Setup

```bash
git clone https://github.com/jang1563/agentshield
cd agentshield
pip install -e ".[dev]"
```

To use the BioGuard output classifier (recommended), also install Constitutional BioGuard:

```bash
export BIOGUARD_MODEL_DIR=/path/to/constitutional_bioguard/models/deberta_bioguard_v1
```

## Running Tests

```bash
pytest tests/ -v
```

Tests run without GPU or API key using the scripted mock agent mode.

## Code Style

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting:

```bash
ruff check .
ruff format .
```

## Project Structure

- `agentshield/threat_model/` — STRIDE threat modeling framework.
- `agentshield/attacks/` — Attack scenario definitions and runner. Adding new scenarios here is the primary way to extend coverage.
- `agentshield/detectors/` — Detection pipeline components. Each detector is independently testable.
- `agentshield/simulation/` — Mock agent framework.
- `agentshield/evaluation/` — Metrics and reporting.

## Adding Attack Scenarios

New scenarios go in the appropriate category file in `agentshield/attacks/`. Each scenario must be an `AttackScenario` with:
- A unique ID following the existing format (`DI-11`, `TM-11`, etc.)
- At least one attack message
- A target surface ID from the threat model

Run `python scripts/run_attacks.py --mode both` to verify new scenarios work.

## Adding Detectors

New detectors should subclass `DetectorBase` from `agentshield/detectors/base.py` and implement the `detect()` method. Register the detector in `DetectionPipeline` in `agentshield/detectors/pipeline.py`.

## Submitting Changes

1. Fork the repository and create a feature branch.
2. Make your changes with tests where appropriate.
3. Ensure `pytest tests/ -v` passes.
4. Open a pull request with a clear description.

## Responsible Use

AgentShield is a defensive security framework. The attack scenarios are documented to enable defenders to test their systems — not to provide a manual for attacking production AI systems. Please use this project responsibly and in accordance with applicable laws and regulations.
