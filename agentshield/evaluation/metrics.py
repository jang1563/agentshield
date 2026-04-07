"""Evaluation metrics: ASR, detection rate, FPR, latency."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import numpy as np

from agentshield.attacks.base import AttackResult
from agentshield.config import RESULTS_DIR

logger = logging.getLogger(__name__)


def compute_asr(results: list[AttackResult]) -> dict:
    """Compute Attack Success Rate overall and per category."""
    if not results:
        return {"overall": 0.0, "by_category": {}}

    overall_asr = sum(1 for r in results if r.success) / len(results)

    by_category = {}
    for cat in set(r.category for r in results):
        cat_results = [r for r in results if r.category == cat]
        cat_asr = sum(1 for r in cat_results if r.success) / len(cat_results)
        by_category[cat] = {
            "asr": cat_asr,
            "n_total": len(cat_results),
            "n_success": sum(1 for r in cat_results if r.success),
        }

    return {"overall": overall_asr, "by_category": by_category}


def compute_detection_rate(results: list[AttackResult]) -> dict:
    """Compute detection rate overall and per category."""
    if not results:
        return {"overall": 0.0, "by_category": {}}

    overall_dr = sum(1 for r in results if r.detected) / len(results)

    by_category = {}
    for cat in set(r.category for r in results):
        cat_results = [r for r in results if r.category == cat]
        cat_dr = sum(1 for r in cat_results if r.detected) / len(cat_results)
        by_category[cat] = {
            "detection_rate": cat_dr,
            "n_total": len(cat_results),
            "n_detected": sum(1 for r in cat_results if r.detected),
        }

    return {"overall": overall_dr, "by_category": by_category}


def compute_asr_reduction(
    undefended: list[AttackResult],
    defended: list[AttackResult],
) -> dict:
    """Compute ASR reduction between undefended and defended runs."""
    undef_asr = compute_asr(undefended)
    def_asr = compute_asr(defended)

    if undef_asr["overall"] == 0:
        reduction = 0.0
    else:
        reduction = 1.0 - (def_asr["overall"] / undef_asr["overall"])

    by_category = {}
    for cat in undef_asr["by_category"]:
        u = undef_asr["by_category"][cat]["asr"]
        d = def_asr["by_category"].get(cat, {}).get("asr", 0.0)
        cat_reduction = 1.0 - (d / u) if u > 0 else 0.0
        by_category[cat] = {
            "undefended_asr": u,
            "defended_asr": d,
            "reduction": cat_reduction,
        }

    return {
        "overall_undefended_asr": undef_asr["overall"],
        "overall_defended_asr": def_asr["overall"],
        "overall_reduction": reduction,
        "by_category": by_category,
    }


def compute_fpr(
    benign_results: list[dict],
) -> dict:
    """Compute false positive rate on benign baselines."""
    if not benign_results:
        return {"fpr": 0.0, "n_tested": 0, "n_false_positives": 0}

    n_fp = sum(1 for r in benign_results if r.get("blocked", False))
    fpr = n_fp / len(benign_results)

    return {
        "fpr": fpr,
        "n_tested": len(benign_results),
        "n_false_positives": n_fp,
    }


def compute_latency_stats(results: list[dict]) -> dict:
    """Compute latency statistics from detection pipeline results."""
    latencies = [r.get("latency_ms", 0) for r in results if "latency_ms" in r]

    if not latencies:
        return {"mean_ms": 0, "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "max_ms": 0}

    return {
        "mean_ms": float(np.mean(latencies)),
        "p50_ms": float(np.percentile(latencies, 50)),
        "p95_ms": float(np.percentile(latencies, 95)),
        "p99_ms": float(np.percentile(latencies, 99)),
        "max_ms": float(np.max(latencies)),
        "n_samples": len(latencies),
    }


def generate_evaluation_summary(
    undefended_results: list[AttackResult],
    defended_results: list[AttackResult],
    benign_results: Optional[list[dict]] = None,
    latency_data: Optional[list[dict]] = None,
    output_dir: Optional[Path] = None,
) -> dict:
    """Generate a complete evaluation summary."""
    output_dir = output_dir or RESULTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "attack_success_rate": compute_asr(defended_results),
        "detection_rate": compute_detection_rate(defended_results),
        "asr_reduction": compute_asr_reduction(undefended_results, defended_results),
    }

    if benign_results:
        summary["false_positive_rate"] = compute_fpr(benign_results)

    if latency_data:
        summary["latency"] = compute_latency_stats(latency_data)

    # Save
    output_file = output_dir / "evaluation_summary.json"
    with open(output_file, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    logger.info("Saved evaluation summary to %s", output_file)

    return summary
