#!/usr/bin/env python3
"""Ablation study: measure each detector's contribution to AgentShield performance.

For each ablation configuration (one detector removed), runs the full attack
suite in defended mode, then computes ASR and detection rate per category with
Wilson score 95% confidence intervals. Outputs a Markdown comparison table and
saves results to data/results/ablation_study.json.

Usage:
    python scripts/run_ablation.py [--agent-mode scripted] [--output-dir PATH]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agentshield.attacks.runner import get_all_scenarios, run_attack_suite
from agentshield.detectors.input_classifier import InputClassifier
from agentshield.detectors.output_classifier import OutputClassifier
from agentshield.detectors.pipeline import DetectionPipeline
from agentshield.detectors.tool_auditor import ToolAuditor
from agentshield.detectors.trajectory_monitor import TrajectoryMonitor
from agentshield.evaluation.metrics import compute_asr, compute_detection_rate, wilson_ci
from agentshield.config import RESULTS_DIR
from agentshield.simulation.mock_agent import AgentMode

logger = logging.getLogger(__name__)

# ── Ablation configurations ──────────────────────────────────────────────────
# Each entry: (config_name, description, kwargs for DetectionPipeline)
# Pass None for a detector to disable it via a sentinel approach.
# DetectionPipeline accepts Optional for each detector; we create a no-op
# stand-in by passing custom disabled detector objects.

_SENTINEL = object()  # used to detect "omit this detector"


def _make_pipeline(
    use_input: bool = True,
    use_tool: bool = True,
    use_output: bool = True,
    use_trajectory: bool = True,
) -> DetectionPipeline:
    """Construct a DetectionPipeline with specified detectors enabled.

    Disabled detectors are replaced with pass-through stubs that never flag.
    """

    class _PassThroughDetector:
        """Stub detector that always returns a non-flagging result."""

        def __init__(self, name: str):
            self.name = name

        def detect(self, **kwargs):
            from agentshield.detectors.base import DetectionResult
            return DetectionResult(
                detector_name=self.name,
                flagged=False,
                confidence=1.0,
                risk_score=0.0,
                reason="Detector disabled in ablation",
            )

        def reset(self):
            pass

        def add_risk_score(self, score: float):
            pass

        # Expose risk_history as empty deque for trajectory monitor compatibility
        @property
        def risk_history(self):
            from collections import deque
            return deque()

    # Build real or stub for each detector
    input_cls = InputClassifier() if use_input else _PassThroughDetector("input_classifier")
    tool_aud = ToolAuditor() if use_tool else _PassThroughDetector("tool_auditor")
    output_cls = OutputClassifier(mode="keyword") if use_output else _PassThroughDetector("output_classifier")
    traj_mon = TrajectoryMonitor() if use_trajectory else _PassThroughDetector("trajectory_monitor")

    # DetectionPipeline accesses trajectory_monitor.risk_history directly;
    # we need to patch the analyze method for disabled trajectory monitors.
    pipeline = DetectionPipeline(
        input_classifier=input_cls,
        output_classifier=output_cls,
        tool_auditor=tool_aud,
        trajectory_monitor=traj_mon,
    )

    # If trajectory monitor is disabled, patch analyze to skip it
    if not use_trajectory:
        _orig_analyze = pipeline.analyze

        def _patched_analyze(**kwargs):
            result = _orig_analyze(**kwargs)
            return result

        # Since DetectionPipeline.analyze checks len(self.trajectory_monitor.risk_history),
        # the stub's empty risk_history will naturally skip the trajectory check.
        # No further patching needed.

    return pipeline


ABLATION_CONFIGS = [
    {
        "name": "full",
        "description": "All 4 detectors (baseline)",
        "use_input": True,
        "use_tool": True,
        "use_output": True,
        "use_trajectory": True,
    },
    {
        "name": "no_input",
        "description": "No InputClassifier (ToolAuditor + OutputClassifier + TrajectoryMonitor)",
        "use_input": False,
        "use_tool": True,
        "use_output": True,
        "use_trajectory": True,
    },
    {
        "name": "no_tool",
        "description": "No ToolAuditor (InputClassifier + OutputClassifier + TrajectoryMonitor)",
        "use_input": True,
        "use_tool": False,
        "use_output": True,
        "use_trajectory": True,
    },
    {
        "name": "no_output",
        "description": "No OutputClassifier (InputClassifier + ToolAuditor + TrajectoryMonitor)",
        "use_input": True,
        "use_tool": True,
        "use_output": False,
        "use_trajectory": True,
    },
    {
        "name": "no_trajectory",
        "description": "No TrajectoryMonitor (InputClassifier + ToolAuditor + OutputClassifier)",
        "use_input": True,
        "use_tool": True,
        "use_output": True,
        "use_trajectory": False,
    },
]

CATEGORIES = [
    "direct_injection",
    "indirect_injection",
    "multi_turn_escalation",
    "tool_misuse",
]


def run_ablation(
    agent_mode_str: str = "scripted",
    output_dir: Path = RESULTS_DIR,
) -> dict:
    """Run ablation study across all configurations.

    Args:
        agent_mode_str: Mock agent mode ("scripted", "echo", or "llm").
        output_dir: Directory to save results JSON.

    Returns:
        Nested dict: {config_name: {"asr": {...}, "detection_rate": {...}, "results": [...]}}
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    agent_mode = AgentMode(agent_mode_str)
    scenarios = get_all_scenarios()
    logger.info("Loaded %d attack scenarios", len(scenarios))

    ablation_results: dict[str, dict] = {}

    for config in ABLATION_CONFIGS:
        name = config["name"]
        logger.info("=== Running ablation: %s ===", name)

        pipeline = _make_pipeline(
            use_input=config["use_input"],
            use_tool=config["use_tool"],
            use_output=config["use_output"],
            use_trajectory=config["use_trajectory"],
        )

        results = run_attack_suite(
            mode="defended",
            detection_pipeline=pipeline,
            agent_mode=agent_mode,
            scenarios=scenarios,
            output_dir=output_dir / "ablation" / name,
        )

        asr_data = compute_asr(results)
        det_data = compute_detection_rate(results)

        ablation_results[name] = {
            "description": config["description"],
            "asr": asr_data,
            "detection_rate": det_data,
            "n_scenarios": len(results),
            "n_success": sum(1 for r in results if r.success),
            "n_detected": sum(1 for r in results if r.detected),
        }

        logger.info(
            "  ASR=%.1f%% [%.1f%%–%.1f%%], DetRate=%.1f%% [%.1f%%–%.1f%%]",
            asr_data["overall"] * 100,
            asr_data.get("ci_lower", 0) * 100,
            asr_data.get("ci_upper", 0) * 100,
            det_data["overall"] * 100,
            det_data.get("ci_lower", 0) * 100,
            det_data.get("ci_upper", 0) * 100,
        )

    return ablation_results


def _fmt_pct(val: float, ci_lo: float, ci_hi: float) -> str:
    """Format a percentage with CI for Markdown table."""
    return f"{val*100:.1f}% [{ci_lo*100:.1f}–{ci_hi*100:.1f}%]"


def render_markdown_table(ablation_results: dict) -> str:
    """Render ablation results as a Markdown comparison table."""
    lines = []
    lines.append("## AgentShield Ablation Study Results\n")
    lines.append(
        "Each row removes one detector from the full pipeline. "
        "Values show Attack Success Rate (ASR) and Detection Rate with "
        "Wilson 95% confidence intervals.\n"
    )

    # Header
    header = "| Configuration | Description | Overall ASR (95% CI) | Overall Det. Rate (95% CI) |"
    for cat in CATEGORIES:
        short = cat.replace("_", " ").title()
        header += f" {short} ASR |"
    lines.append(header)

    sep = "|---|---|---|---|"
    for _ in CATEGORIES:
        sep += "---|"
    lines.append(sep)

    for config in ABLATION_CONFIGS:
        name = config["name"]
        if name not in ablation_results:
            continue
        data = ablation_results[name]
        asr = data["asr"]
        det = data["detection_rate"]

        overall_asr_str = _fmt_pct(
            asr["overall"],
            asr.get("ci_lower", 0),
            asr.get("ci_upper", 0),
        )
        overall_det_str = _fmt_pct(
            det["overall"],
            det.get("ci_lower", 0),
            det.get("ci_upper", 0),
        )

        row = f"| **{name}** | {data['description']} | {overall_asr_str} | {overall_det_str} |"
        for cat in CATEGORIES:
            cat_asr = asr.get("by_category", {}).get(cat, {})
            cat_val = cat_asr.get("asr", 0.0)
            cat_lo = cat_asr.get("ci_lower", 0.0)
            cat_hi = cat_asr.get("ci_upper", 0.0)
            row += f" {_fmt_pct(cat_val, cat_lo, cat_hi)} |"
        lines.append(row)

    lines.append("")
    lines.append("### Per-Category Detection Rate Breakdown\n")

    # Detection rate table per category
    det_header = "| Configuration |"
    for cat in CATEGORIES:
        short = cat.replace("_", " ").title()
        det_header += f" {short} Det. |"
    lines.append(det_header)

    det_sep = "|---|"
    for _ in CATEGORIES:
        det_sep += "---|"
    lines.append(det_sep)

    for config in ABLATION_CONFIGS:
        name = config["name"]
        if name not in ablation_results:
            continue
        det = ablation_results[name]["detection_rate"]
        det_row = f"| **{name}** |"
        for cat in CATEGORIES:
            cat_det = det.get("by_category", {}).get(cat, {})
            cat_val = cat_det.get("detection_rate", 0.0)
            cat_lo = cat_det.get("ci_lower", 0.0)
            cat_hi = cat_det.get("ci_upper", 0.0)
            det_row += f" {_fmt_pct(cat_val, cat_lo, cat_hi)} |"
        lines.append(det_row)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Run AgentShield ablation study across detector configurations"
    )
    parser.add_argument(
        "--agent-mode",
        choices=["echo", "scripted", "llm"],
        default="scripted",
        help="Mock agent response mode (default: scripted)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory (default: data/results/)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    output_dir = Path(args.output_dir) if args.output_dir else RESULTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Starting AgentShield ablation study (%d configurations)", len(ABLATION_CONFIGS))
    logger.info("Agent mode: %s", args.agent_mode)
    logger.info("Output dir: %s", output_dir)

    ablation_results = run_ablation(
        agent_mode_str=args.agent_mode,
        output_dir=output_dir,
    )

    # Save JSON
    output_json = output_dir / "ablation_study.json"
    with open(output_json, "w") as f:
        json.dump(ablation_results, f, indent=2, default=str)
    logger.info("Saved ablation results to %s", output_json)

    # Print Markdown table
    table = render_markdown_table(ablation_results)
    print("\n" + "=" * 70)
    print("ABLATION STUDY COMPLETE")
    print("=" * 70)
    print(table)
    print("=" * 70)
    logger.info("Results saved to %s", output_json)


if __name__ == "__main__":
    main()
