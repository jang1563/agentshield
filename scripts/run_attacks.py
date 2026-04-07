#!/usr/bin/env python3
"""Run AgentShield attack suite against simulated BioTeam-AI agents."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agentshield.attacks.runner import get_all_scenarios, run_attack_suite
from agentshield.simulation.mock_agent import AgentMode
from agentshield.detectors.pipeline import DetectionPipeline
from agentshield.config import RESULTS_DIR

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Run AgentShield attack suite")
    parser.add_argument(
        "--mode",
        choices=["undefended", "defended", "both"],
        default="both",
        help="Run attacks undefended, defended, or both (default: both)",
    )
    parser.add_argument(
        "--category",
        choices=["direct_injection", "indirect_injection", "multi_turn_escalation", "tool_misuse"],
        default=None,
        help="Run only a specific attack category",
    )
    parser.add_argument(
        "--agent-mode",
        choices=["echo", "scripted", "llm"],
        default="scripted",
        help="Mock agent response mode (default: scripted)",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="Run a specific scenario by ID (e.g., DI-01)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory for results (default: data/results/)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    output_dir = Path(args.output_dir) if args.output_dir else RESULTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    # Get scenarios
    all_scenarios = get_all_scenarios()
    if args.scenario:
        all_scenarios = [s for s in all_scenarios if s.scenario_id == args.scenario]
        if not all_scenarios:
            logger.error("Scenario %s not found", args.scenario)
            sys.exit(1)
    elif args.category:
        all_scenarios = [s for s in all_scenarios if s.category.value == args.category]

    logger.info("Running %d attack scenarios", len(all_scenarios))

    agent_mode = AgentMode(args.agent_mode)

    modes_to_run = []
    if args.mode in ("undefended", "both"):
        modes_to_run.append("undefended")
    if args.mode in ("defended", "both"):
        modes_to_run.append("defended")

    all_results = {}

    for mode in modes_to_run:
        logger.info("=== Running in %s mode ===", mode.upper())

        pipeline = DetectionPipeline() if mode == "defended" else None

        results = run_attack_suite(
            mode=mode,
            detection_pipeline=pipeline,
            agent_mode=agent_mode,
            scenarios=all_scenarios,
            output_dir=output_dir,
        )

        # Summarize results
        succeeded = sum(1 for r in results if r.success)
        detected = sum(1 for r in results if r.detected)
        blocked = sum(1 for r in results if r.blocked)

        logger.info(
            "%s results: %d/%d succeeded (ASR=%.1f%%), %d detected, %d blocked",
            mode.upper(),
            succeeded,
            len(results),
            100 * succeeded / len(results) if results else 0,
            detected,
            blocked,
        )

        all_results[mode] = results

    # If both modes ran, compute ASR reduction
    if "undefended" in all_results and "defended" in all_results:
        undef_results = all_results["undefended"]
        def_results = all_results["defended"]
        undef_asr = sum(1 for r in undef_results if r.success) / len(undef_results)
        def_asr = sum(1 for r in def_results if r.success) / len(def_results)
        reduction = (1 - def_asr / undef_asr) * 100 if undef_asr > 0 else 0

        comparison = {
            "undefended_asr": round(undef_asr, 4),
            "defended_asr": round(def_asr, 4),
            "asr_reduction_pct": round(reduction, 2),
            "total_scenarios": len(undef_results),
        }

        # Per-category breakdown
        categories = set(r.category for r in undef_results)
        comparison["per_category"] = {}
        for cat in sorted(categories):
            u_cat = [r for r in undef_results if r.category == cat]
            d_cat = [r for r in def_results if r.category == cat]
            u_asr = sum(1 for r in u_cat if r.success) / len(u_cat) if u_cat else 0
            d_asr = sum(1 for r in d_cat if r.success) / len(d_cat) if d_cat else 0
            red = (1 - d_asr / u_asr) * 100 if u_asr > 0 else 0
            comparison["per_category"][cat] = {
                "undefended_asr": round(u_asr, 4),
                "defended_asr": round(d_asr, 4),
                "asr_reduction_pct": round(red, 2),
                "count": len(u_cat),
            }

        with open(output_dir / "asr_comparison.json", "w") as f:
            json.dump(comparison, f, indent=2)

        logger.info(
            "ASR Reduction: %.1f%% (undefended=%.1f%% → defended=%.1f%%)",
            reduction, undef_asr * 100, def_asr * 100,
        )

    logger.info("All results saved to %s", output_dir)


if __name__ == "__main__":
    main()
