# AgentShield

Security audit framework for agentic AI systems. Applies STRIDE threat modeling, a 40-scenario attack suite (prompt injection, data poisoning, multi-turn escalation, tool misuse), and a 4-component detection pipeline to [BioTeam-AI](https://github.com/jang1563/AI_Scientist_team), a 23-agent bioinformatics system with Docker sandboxing.

**Author:** JangKeun Kim, Weill Cornell Medicine (jak4013@med.cornell.edu)

## Results

| Criterion | Target | Actual | Status |
|-----------|--------|--------|--------|
| ASR reduction | >= 80% | 92.9% | PASS |
| Direct injection detection | >= 90% | 100% | PASS |
| Multi-turn escalation detection | >= 70% | 90% | PASS |
| False positive rate | < 5% | 4.0% | PASS |

### Per-Category Breakdown

| Category | Undefended ASR | Defended ASR | Reduction | Detection Rate |
|----------|---------------|-------------|-----------|----------------|
| Direct Injection | 30% | 0% | 100% | 100% |
| Indirect Injection | 50% | 0% | 100% | 70% |
| Multi-Turn Escalation | 40% | 0% | 100% | 90% |
| Tool Misuse | 20% | 10% | 50% | 70% |

## Architecture

```
User Input
    |
    v
[1. Input Classifier] -----> Block if injection detected
    |                         (18 regex patterns + encoding detection)
    v
[Mock Agent] processes input
    |
    |--- tool_calls ---> [2. Tool Auditor] --> Block if unauthorized
    |                     (allow-list + arg validation + rate limiting)
    v
Agent Response
    |
    v
[3. Output Classifier] ----> Block if unsafe content
    |                         (BioGuard DeBERTa, ~5ms/query)
    v
[4. Trajectory Monitor] ---> Block if escalation detected
    |                         (sliding window: absolute + monotonic + WMA)
    v
Delivered to User (or blocked)
```

## Threat Model

STRIDE-based analysis of BioTeam-AI identifying 9 attack surfaces:

| ID | Surface | STRIDE Categories | Risk |
|----|---------|------------------|------|
| AS-001 | Agent substitution bypass | Spoofing, EoP | Critical |
| AS-002 | Tool access leakage | EoP | Critical |
| AS-003 | Input sanitization gaps | Tampering, ID | High |
| AS-004 | Memory poisoning (ChromaDB) | Tampering | Critical |
| AS-005 | Docker sandbox escape | EoP | High |
| AS-006 | Auth bypass in dev mode | Spoofing | Critical |
| AS-007 | Workflow hijacking | Tampering | High |
| AS-008 | Rate limit evasion | DoS | Medium |
| AS-009 | Langfuse data leakage | ID | Medium |

Full details in [docs/threat_model.md](docs/threat_model.md).

## Attack Suite (40 Scenarios)

| Category | Count | Description |
|----------|-------|-------------|
| Direct Injection | 10 | System prompt leak, role override, encoding bypass, DAN, many-shot |
| Indirect Injection | 10 | Memory poisoning, API injection, cross-agent, workflow hijack |
| Multi-Turn Escalation | 10 | Gradual escalation across NSABB categories, CoSafe-inspired |
| Tool Misuse | 10 | Unauthorized access, arg injection, sandbox escape, DoS |

Full catalogue in [docs/attack_catalogue.md](docs/attack_catalogue.md).

## Quick Start

### Prerequisites

- Python >= 3.10
- Constitutional BioGuard trained model (for output classifier)

### Installation

```bash
pip install -e ".[dev]"
```

### Run Evaluation

```bash
# Generate threat model
python scripts/run_threat_model.py

# Run full evaluation (attacks + detection + metrics + figures + report)
python scripts/run_evaluation.py --agent-mode scripted

# Or run attacks separately
python scripts/run_attacks.py --mode undefended
python scripts/run_attacks.py --mode defended
```

### Key Outputs

- `data/results/evaluation_summary.json` -- All metrics
- `data/results/figures/` -- ASR comparison, escalation trajectories, detector performance
- `docs/evaluation_report.md` -- Full evaluation report
- `docs/threat_model.md` -- STRIDE threat model

## Detection Pipeline Components

### 1. Input Classifier
Pattern-based injection detector with 18 injection patterns, 5 role override patterns, 5 encoding indicators, and obfuscation detection (homoglyphs, leetspeak). Optional PromptGuard-86M integration for production use.

### 2. Output Classifier
Safety filter with 3 modes:
- **Local model** (primary): Constitutional BioGuard's DeBERTa classifier (~5ms/query)
- **LLM judge**: Claude API with 4-dimensional rubric (refusal, completeness, specificity, safety)
- **Keyword fallback**: Pattern matching for known dangerous content

### 3. Trajectory Monitor
Novel sliding-window algorithm tracking per-turn risk scores:
- **Absolute threshold**: Any single turn risk > 0.7
- **Monotonic escalation**: 3+ consecutive risk score increases
- **Weighted moving average**: WMA exceeds 0.5 over sliding window

### 4. Tool Auditor
Authorization enforcement against `AGENT_AGENTIC_TOOLS` mapping:
- Tool access allow-list enforcement
- Argument pattern validation (gene symbols, HGVS notation)
- Shell injection marker detection (13 patterns)
- Call frequency rate limiting (20 calls/minute/agent)

## Simulation Approach

All attacks run against **mock agents** (not live BioTeam-AI):
- No risk of actual safety violations during testing
- Deterministic and reproducible results
- Security audit is read-only (does not modify BioTeam-AI)

Mock agent modes: `echo` (passthrough), `scripted` (pattern-matched responses), `llm` (Claude API).

## Project Structure

```
agentshield/
├── agentshield/                  # Python package
│   ├── config.py
│   ├── threat_model/             # STRIDE framework
│   │   ├── stride.py             # Data models
│   │   ├── bioteam_surfaces.py   # 9 attack surfaces
│   │   └── risk_matrix.py        # Likelihood x impact scoring
│   ├── attacks/                  # 40 attack scenarios
│   │   ├── base.py               # AttackScenario + AttackResult
│   │   ├── direct_injection.py
│   │   ├── indirect_injection.py
│   │   ├── multi_turn_escalation.py
│   │   ├── tool_misuse.py
│   │   └── runner.py
│   ├── detectors/                # 4-component pipeline
│   │   ├── base.py               # DetectorBase ABC
│   │   ├── input_classifier.py
│   │   ├── output_classifier.py
│   │   ├── trajectory_monitor.py
│   │   ├── tool_auditor.py
│   │   └── pipeline.py
│   ├── simulation/               # Mock agent framework
│   │   ├── mock_agent.py
│   │   ├── mock_tools.py
│   │   ├── mock_memory.py
│   │   └── conversation.py
│   └── evaluation/               # Metrics + reporting
│       ├── metrics.py
│       ├── benchmarks.py
│       ├── figures.py
│       └── report_generator.py
├── data/
│   ├── attack_scenarios/
│   ├── benign_baselines/
│   └── results/
├── docs/
│   ├── threat_model.md
│   ├── attack_catalogue.md
│   ├── architecture.md
│   └── evaluation_report.md
├── scripts/
│   ├── run_threat_model.py
│   ├── run_attacks.py
│   ├── run_detection.py
│   └── run_evaluation.py
└── tests/
```

## Cross-Project Integration

AgentShield's output classifier uses [Constitutional BioGuard](../constitutional_bioguard/)'s trained DeBERTa model for real-time content classification. Set the model path via environment variable:

```bash
export BIOGUARD_MODEL_DIR=/path/to/constitutional_bioguard/models/deberta_bioguard_v1
```

## Responsible Use

AgentShield is a **defensive security research tool**. The attack scenarios are designed to probe and improve safety properties of agentic AI systems, not to enable malicious use.

Intended uses:
- Security auditing of your own agentic AI systems before deployment
- Research on prompt injection and multi-turn escalation defenses
- Building detection pipelines for production agent systems

Do not use the attack scenarios to attack systems you do not own or have explicit authorization to test. The threat model and attack catalogue describe vulnerabilities in BioTeam-AI (a research system the author built and controls) and are published to support the security research community, not to provide a playbook for unauthorized access.

The 4.0% false positive rate means legitimate requests will occasionally be blocked — calibrate thresholds for your deployment context.

## Citation

If you use this work, please cite:

```
@software{kim2025agentshield,
  author = {Kim, JangKeun},
  title  = {AgentShield: Security Audit Framework for Agentic AI Systems},
  year   = {2025},
  url    = {https://github.com/jang1563/agentshield},
}
```

## License

MIT
