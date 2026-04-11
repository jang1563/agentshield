# AgentShield Architecture

## System Overview

AgentShield is a security audit framework that evaluates agentic AI systems against prompt injection, data poisoning, multi-turn escalation, and tool misuse attacks. It wraps a target system's agent interface with a 4-component detection pipeline and measures attack success rate (ASR) reduction.

```
                    AgentShield Framework
┌──────────────────────────────────────────────────────┐
│                                                      │
│   Attack Suite ──> Simulation Layer ──> Detectors    │
│   (40 scenarios)   (mock agents)       (4 pipeline)  │
│                                                      │
│                         │                            │
│                         v                            │
│                    Evaluation                        │
│                    (metrics, figures, report)         │
│                                                      │
└──────────────────────────────────────────────────────┘
```

## Component Details

### 1. Threat Model (`agentshield/threat_model/`)

STRIDE-based analysis mapping 9 attack surfaces in BioTeam-AI to the 6 STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

- `stride.py` -- STRIDECategory enum, AttackSurface model, ThreatModel container
- `bioteam_surfaces.py` -- 9 attack surfaces with source code evidence from BioTeam-AI
- `risk_matrix.py` -- Likelihood x Impact scoring (1-5 scale, product determines risk level)

### 2. Attack Suite (`agentshield/attacks/`)

40 scenarios across 4 categories, each defined as an `AttackScenario` containing:
- Scenario ID, name, description
- Attack category and target surface
- Ordered list of attack messages
- Metadata (target agent, NSABB category, requires_poisoned_tools flag)

```python
class AttackScenario(BaseModel):
    scenario_id: str           # e.g. "DI-01"
    name: str
    description: str
    category: AttackCategory
    target_surface: str        # e.g. "AS-003"
    messages: list[str]        # Ordered attack turns
    metadata: dict             # requires_poisoned_tools, nsabb_category, etc.
```

The `runner.py` orchestrator creates per-scenario mock agents with appropriate flags (poisoned tools for indirect injection, tool call emission for tool misuse) and collects `AttackResult` objects.

### 3. Simulation Layer (`agentshield/simulation/`)

Mock agents replicate BioTeam-AI's `BaseAgent` execution flow without actual dangerous capabilities.

**MockAgent** -- 3 response modes:
- `echo` -- Returns input as-is (for testing detection passthrough)
- `scripted` -- Pattern-matched responses from a dictionary of biology topics
- `llm` -- Claude API for realistic responses (optional, costs API credits)

Per-scenario configuration:
- `poisoned=True` -- Injects poisoned tool output content into responses (for indirect injection scenarios)
- `emit_tool_calls=True` -- Generates structured tool_call dicts (for tool misuse scenarios)

**ConversationSimulator** -- Multi-turn orchestrator that:
1. Feeds each message through the agent
2. Passes input/output/tool_calls to the detection pipeline
3. Records per-turn risk scores
4. Tracks blocking and escalation detection

### 4. Detection Pipeline (`agentshield/detectors/pipeline.py`)

Chains 4 detectors in sequence. Any detector flagging triggers a block.

```
Turn Input
    │
    ├─ user_input ──────> InputClassifier
    │                      │ 18 injection patterns
    │                      │ 5 role override patterns
    │                      │ 5 encoding indicators
    │                      │ Homoglyph + leetspeak detection
    │                      └─> DetectionResult
    │
    ├─ tool_calls ──────> ToolAuditor
    │                      │ AGENT_AGENTIC_TOOLS allow-list
    │                      │ Argument regex validation
    │                      │ Shell injection markers (13 patterns)
    │                      │ Rate limiting (20 calls/min)
    │                      └─> DetectionResult
    │
    ├─ agent_output ────> OutputClassifier
    │                      │ Mode 1: BioGuard DeBERTa (~5ms)
    │                      │ Mode 2: LLM judge (Claude API)
    │                      │ Mode 3: Keyword fallback
    │                      └─> DetectionResult
    │                              │
    │                              │ risk_score
    │                              v
    └────────────────────> TrajectoryMonitor
                            │ Sliding window (size=5)
                            │ Check 1: Absolute threshold (>0.7)
                            │ Check 2: Monotonic escalation (3+ increases)
                            │ Check 3: Weighted moving average (>0.5)
                            └─> DetectionResult
```

**Aggregation logic:**
- `blocked = any(detector.flagged for detector in results)`
- `risk_score = max(detector.risk_score for detector in results)`

### 5. Evaluation (`agentshield/evaluation/`)

- `metrics.py` -- Computes ASR, detection rate, FPR, ASR reduction (per-category and overall)
- `benchmarks.py` -- 100 benign baseline queries (10 per BioTeam-AI agent type)
- `figures.py` -- ASR comparison bars, escalation trajectory plots, detector performance table
- `report_generator.py` -- Markdown report generation from evaluation summary

## Data Flow

```
1. run_threat_model.py
   └─> docs/threat_model.md + data/results/threat_model.json

2. run_evaluation.py
   ├─> Step 1: Undefended attacks (40 scenarios, no pipeline)
   │   └─> data/results/attack_results_undefended.json
   ├─> Step 2: Defended attacks (40 scenarios, full pipeline)
   │   └─> data/results/attack_results_defended.json
   ├─> Step 3: Benign baselines (100 queries through pipeline)
   │   └─> data/results/benign_baseline_results.json
   ├─> Step 4: Compute metrics
   │   └─> data/results/evaluation_summary.json
   ├─> Step 5: Generate figures
   │   └─> data/results/figures/*.png
   └─> Step 6: Generate report
       └─> docs/evaluation_report.md
```

## OWASP Top 10 for Agentic Applications (2026) Coverage

The [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) defines 10 risk categories for autonomous AI systems. AgentShield's detection pipeline explicitly addresses 5 of these:

| OWASP ASI | Risk | AgentShield Coverage | Component |
|-----------|------|----------------------|-----------|
| **ASI01** | Agent Behavior Hijacking | **Full** — blocks total agent control loss | All 4 detectors (defense in depth) |
| **ASI02** | Prompt Injection | **Full** — 18 injection patterns + encoding detection | InputClassifier |
| **ASI03** | Tool Misuse | **Partial** — allow-list, arg validation, rate limiting | ToolAuditor |
| **ASI04** | Privilege Escalation | **Partial** — role override patterns detected | InputClassifier |
| **ASI05** | Data Exfiltration | **Partial** — content flagged post-response; TM-07 remains unblocked | OutputClassifier |
| **ASI06** | Cascading Failures | **Not covered** — no cross-agent propagation monitoring | — |
| **ASI07** | Human-Agent Trust Exploitation | **Partial** — multi-turn escalation detected | TrajectoryMonitor |
| **ASI08** | Rogue Agents | **Not covered** — no agent identity verification | — |
| **ASI09** | Memory Poisoning | **Partial** — indirect injection scenarios II-01 to II-04 | InputClassifier + OutputClassifier |
| **ASI10** | Inter-Agent Communication | **Not covered** — single-agent evaluation scope | — |

**Coverage summary**: 5 full/partial, 3 not covered. The uncovered categories (ASI06, ASI08, ASI10) require multi-agent runtime infrastructure beyond the scope of a black-box audit framework.

## Cross-Project Integration

The output classifier's primary mode uses Constitutional BioGuard's trained DeBERTa model:

```
constitutional_bioguard/models/deberta_bioguard_v1/
    │
    │  BIOGUARD_MODEL_DIR env var
    v
agentshield/detectors/output_classifier.py
    │
    │  OutputClassifier(mode="local")
    │  ~5ms inference, no API cost
    v
Detection pipeline step 3
```

Fallback modes (LLM judge, keyword) are available when the BioGuard model is not present.
