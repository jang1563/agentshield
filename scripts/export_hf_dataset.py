"""Export AgentShield attack scenarios to Hugging Face dataset.

Usage:
    python scripts/export_hf_dataset.py [--repo-id jang1563/agentshield-attack-scenarios]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agentshield.attacks.direct_injection import DIRECT_INJECTION_SCENARIOS
from agentshield.attacks.indirect_injection import INDIRECT_INJECTION_SCENARIOS
from agentshield.attacks.multi_turn_escalation import MULTI_TURN_ESCALATION_SCENARIOS
from agentshield.attacks.tool_misuse import TOOL_MISUSE_SCENARIOS

ALL_SCENARIOS = (
    DIRECT_INJECTION_SCENARIOS
    + INDIRECT_INJECTION_SCENARIOS
    + MULTI_TURN_ESCALATION_SCENARIOS
    + TOOL_MISUSE_SCENARIOS
)


def scenario_to_dict(s) -> dict:
    return {
        "scenario_id": s.scenario_id,
        "name": s.name,
        "category": s.category.value,
        "description": s.description,
        "target_surface": s.target_surface,
        "messages": s.messages,
        "n_turns": len(s.messages),
        "expected_behavior": s.expected_behavior,
        "success_criteria": s.success_criteria,
        "nsabb_category": s.nsabb_category,
        "metadata": s.metadata,
    }


README = """\
---
language:
- en
license: apache-2.0
task_categories:
- text-classification
task_ids:
- multi-label-classification
tags:
- security
- agentic-ai
- biosafety
- prompt-injection
- red-teaming
- STRIDE
- NSABB
pretty_name: AgentShield Attack Scenarios
size_categories:
- n<1K
---

# AgentShield Attack Scenarios

100 structured attack scenarios for evaluating security of agentic AI systems operating in high-risk domains (biological research). Developed alongside the [AgentShield](https://github.com/jang1563/agentshield) detection pipeline.

## Dataset Description

Each scenario is a multi-turn attack sequence targeting one of four attack surfaces identified through [STRIDE](https://en.wikipedia.org/wiki/STRIDE_(security)) threat modeling of a BioTeam-AI multi-agent system:

| ID | Attack Surface |
|----|---------------|
| AS-001 | Agent-to-Agent Communication |
| AS-002 | Tool Execution Interface |
| AS-003 | External Input Processing |
| AS-004 | Memory/Knowledge Base |

## Categories (25 scenarios each)

| Category | Description |
|----------|-------------|
| `direct_injection` | Malicious instructions injected directly in user messages |
| `indirect_injection` | Payloads embedded in tool outputs, documents, or external data |
| `multi_turn_escalation` | Gradual escalation across turns to cross safety boundaries |
| `tool_misuse` | Abuse of tool interfaces including MCP tool poisoning |

## Fields

| Field | Type | Description |
|-------|------|-------------|
| `scenario_id` | string | Unique identifier (e.g., `DI-01`, `II-14`, `MT-07`, `TM-22`) |
| `name` | string | Human-readable scenario name |
| `category` | string | One of the four attack categories |
| `description` | string | What the attack attempts to do |
| `target_surface` | string | Which attack surface is targeted (AS-001 to AS-004) |
| `messages` | list[string] | Ordered attacker messages in the conversation |
| `n_turns` | int | Number of turns in the attack sequence |
| `expected_behavior` | string | What a vulnerable agent would do |
| `success_criteria` | string | How attack success is evaluated |
| `nsabb_category` | string or null | NSABB dual-use category for escalation attacks |
| `metadata` | dict | Additional flags (e.g., `emit_tool_calls`) |

## Evaluation Results

Results from running against the AgentShield 4-detector pipeline (InputClassifier + ToolAuditor + OutputClassifier + TrajectoryMonitor):

| Metric | Value |
|--------|-------|
| Attack Success Rate (defended) | 2.5% |
| Attack Success Rate (undefended) | 35% |
| ASR Reduction | 92.9% |
| Direct Injection Detection | 100% |
| Multi-Turn Escalation Detection | 100% |
| Benign FPR | 4.0% |

## Usage

```python
from datasets import load_dataset

ds = load_dataset("jang1563/agentshield-attack-scenarios")
print(ds["train"][0])
```

Filter by category:

```python
direct = ds["train"].filter(lambda x: x["category"] == "direct_injection")
```

## Related Resources

- **Detection Pipeline**: [github.com/jang1563/agentshield](https://github.com/jang1563/agentshield)
- **BioSafety Classifier**: [jang1563/constitutional-bioguard-deberta-v1](https://huggingface.co/jang1563/constitutional-bioguard-deberta-v1)

## Citation

```bibtex
@software{agentshield2025,
  author = {Jang, Jaekyung},
  title  = {{AgentShield}: Security Audit Framework for Agentic AI Systems},
  year   = {2025},
  url    = {https://github.com/jang1563/agentshield},
}
```

## License

Apache 2.0
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-id",
        default="jang1563/agentshield-attack-scenarios",
        help="HuggingFace dataset repo ID",
    )
    parser.add_argument(
        "--private", action="store_true", help="Create private repo"
    )
    args = parser.parse_args()

    records = [scenario_to_dict(s) for s in ALL_SCENARIOS]
    print(f"Loaded {len(records)} scenarios")

    # Write locally
    out_dir = PROJECT_ROOT / "data" / "hf_export"
    out_dir.mkdir(parents=True, exist_ok=True)

    jsonl_path = out_dir / "attack_scenarios.jsonl"
    with open(jsonl_path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    readme_path = out_dir / "README.md"
    readme_path.write_text(README)

    print(f"Exported to {out_dir}/")

    # Upload to HuggingFace
    try:
        from huggingface_hub import HfApi
    except ImportError:
        print("huggingface_hub not installed — data exported locally only.")
        return

    api = HfApi()
    print(f"Creating repo: {args.repo_id}")
    api.create_repo(
        repo_id=args.repo_id,
        repo_type="dataset",
        exist_ok=True,
        private=args.private,
    )

    print("Uploading files...")
    api.upload_file(
        path_or_fileobj=str(jsonl_path),
        path_in_repo="attack_scenarios.jsonl",
        repo_id=args.repo_id,
        repo_type="dataset",
        commit_message="Add 100 attack scenarios",
    )
    api.upload_file(
        path_or_fileobj=str(readme_path),
        path_in_repo="README.md",
        repo_id=args.repo_id,
        repo_type="dataset",
        commit_message="Add dataset card",
    )

    print(f"Published: https://huggingface.co/datasets/{args.repo_id}")


if __name__ == "__main__":
    main()
