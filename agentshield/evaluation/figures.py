"""Visualization for AgentShield evaluation results."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

from agentshield.config import RESULTS_DIR, FIGURES_DIR

logger = logging.getLogger(__name__)

plt.rcParams.update({
    "font.size": 10,
    "figure.dpi": 300,
    "figure.facecolor": "white",
    "savefig.bbox": "tight",
})


def plot_asr_comparison(output_dir: Optional[Path] = None) -> Path:
    """Bar chart comparing undefended vs defended ASR per category."""
    output_dir = output_dir or FIGURES_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    summary_file = RESULTS_DIR / "evaluation_summary.json"
    with open(summary_file) as f:
        data = json.load(f)

    reduction = data["asr_reduction"]["by_category"]
    categories = list(reduction.keys())
    undefended = [reduction[c]["undefended_asr"] * 100 for c in categories]
    defended = [reduction[c]["defended_asr"] * 100 for c in categories]

    x = np.arange(len(categories))
    width = 0.35

    fig, ax = plt.subplots(figsize=(12, 5))
    bars1 = ax.bar(x - width / 2, undefended, width, label="Undefended", color="#EF5350")
    bars2 = ax.bar(x + width / 2, defended, width, label="Defended", color="#66BB6A")

    ax.set_ylabel("Attack Success Rate (%)")
    ax.set_title("ASR: Undefended vs Defended")
    ax.set_xticks(x)
    ax.set_xticklabels([c.replace("_", "\n") for c in categories], fontsize=8)
    ax.legend()
    ax.set_ylim(0, 105)

    filepath = output_dir / "asr_comparison.png"
    fig.savefig(filepath)
    plt.close(fig)
    return filepath


def plot_detector_performance(output_dir: Optional[Path] = None) -> Path:
    """Table/heatmap of detector performance metrics."""
    output_dir = output_dir or FIGURES_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    summary_file = RESULTS_DIR / "evaluation_summary.json"
    with open(summary_file) as f:
        data = json.load(f)

    dr = data["detection_rate"]["by_category"]
    categories = list(dr.keys())
    rates = [dr[c]["detection_rate"] * 100 for c in categories]

    fig, ax = plt.subplots(figsize=(8, 4))
    colors = ["#66BB6A" if r >= 70 else "#FFA726" if r >= 50 else "#EF5350" for r in rates]
    bars = ax.barh(categories, rates, color=colors)

    for bar, rate in zip(bars, rates):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                f"{rate:.1f}%", va="center", fontsize=9)

    ax.axvline(x=90, color="green", linestyle="--", alpha=0.4, label="Target (90%)")
    ax.axvline(x=70, color="orange", linestyle="--", alpha=0.4, label="Minimum (70%)")
    ax.set_xlabel("Detection Rate (%)")
    ax.set_title("Detection Rate by Attack Category")
    ax.legend(fontsize=8)

    filepath = output_dir / "detector_performance.png"
    fig.savefig(filepath)
    plt.close(fig)
    return filepath


def plot_escalation_trajectories(output_dir: Optional[Path] = None) -> Path:
    """Plot risk score trajectories for escalation attack scenarios."""
    output_dir = output_dir or FIGURES_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    results_file = RESULTS_DIR / "attack_results_defended.json"
    if not results_file.exists():
        logger.warning("No defended results for trajectory plot")
        return output_dir / "escalation_trajectories.png"

    with open(results_file) as f:
        results = json.load(f)

    # Filter escalation attacks
    escalation = [r for r in results if r["category"] == "multi_turn_escalation"]

    fig, ax = plt.subplots(figsize=(10, 5))
    for result in escalation:
        scores = result.get("risk_scores", [])
        if scores:
            label = result["scenario_name"][:30]
            ax.plot(range(1, len(scores) + 1), scores, marker="o",
                    alpha=0.7, label=label)

    ax.axhline(y=0.7, color="red", linestyle="--", alpha=0.5, label="Block threshold")
    ax.set_xlabel("Turn Number")
    ax.set_ylabel("Risk Score")
    ax.set_title("Multi-Turn Escalation Trajectories")
    ax.legend(fontsize=7, loc="upper left", ncol=2)

    filepath = output_dir / "escalation_trajectories.png"
    fig.savefig(filepath)
    plt.close(fig)
    return filepath


def generate_all_figures(output_dir: Optional[Path] = None) -> list[Path]:
    """Generate all evaluation figures."""
    output_dir = output_dir or FIGURES_DIR
    figures = []

    for name, fn in [
        ("asr_comparison", plot_asr_comparison),
        ("detector_performance", plot_detector_performance),
        ("escalation_trajectories", plot_escalation_trajectories),
    ]:
        try:
            path = fn(output_dir)
            figures.append(path)
        except Exception as e:
            logger.warning("Failed to generate %s: %s", name, e)

    return figures
