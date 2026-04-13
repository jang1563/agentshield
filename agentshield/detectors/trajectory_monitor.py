"""Trajectory monitor: sliding window escalation detection.

Novel algorithm that tracks per-turn risk scores and detects
multi-turn escalation patterns through three checks:
  1. Absolute threshold: Any single turn exceeds risk threshold
  2. Monotonic escalation: N consecutive risk score increases
  3. Weighted moving average: WMA exceeds threshold

Designed for multi-exchange safety monitoring in agentic AI systems
where gradual escalation across turns would evade per-turn classifiers.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Optional

from agentshield.config import (
    TRAJECTORY_ABSOLUTE_THRESHOLD,
    TRAJECTORY_ESCALATION_COUNT,
    TRAJECTORY_WINDOW_SIZE,
)
from agentshield.detectors.base import DetectionResult, DetectorBase

logger = logging.getLogger(__name__)


class TrajectoryMonitor(DetectorBase):
    """Monitor conversation trajectories for escalation patterns.

    Maintains a sliding window of risk scores and applies three
    detection heuristics to identify multi-turn escalation attacks.
    """

    name = "trajectory_monitor"

    def __init__(
        self,
        window_size: int = TRAJECTORY_WINDOW_SIZE,
        absolute_threshold: float = TRAJECTORY_ABSOLUTE_THRESHOLD,
        escalation_count: int = TRAJECTORY_ESCALATION_COUNT,
        wma_threshold: float = 0.5,
    ):
        self.window_size = window_size
        self.absolute_threshold = absolute_threshold
        self.escalation_count = escalation_count
        self.wma_threshold = wma_threshold
        self.risk_history: deque[float] = deque(maxlen=window_size)

    def detect(
        self,
        user_input: Optional[str] = None,
        agent_output: Optional[str] = None,
        conversation_history: Optional[list[dict]] = None,
        tool_calls: Optional[list[dict]] = None,
    ) -> DetectionResult:
        """Analyze trajectory for escalation patterns.

        Expects conversation_history to contain 'risk_score' in each turn,
        typically populated by the output_classifier.
        """
        # Extract risk scores from conversation history
        if conversation_history:
            for turn in conversation_history:
                score = turn.get("risk_score", 0.0)
                self.risk_history.append(score)

        if len(self.risk_history) < 2:
            return DetectionResult(
                detector_name=self.name,
                flagged=False,
                confidence=0.0,
                reason="Insufficient history for trajectory analysis",
            )

        scores = list(self.risk_history)
        checks = {}

        # Check 1: Absolute threshold
        max_score = max(scores)
        checks["absolute"] = max_score >= self.absolute_threshold

        # Check 2: Monotonic escalation
        consecutive_increases = 0
        max_consecutive = 0
        for i in range(1, len(scores)):
            if scores[i] > scores[i - 1]:
                consecutive_increases += 1
                max_consecutive = max(max_consecutive, consecutive_increases)
            else:
                consecutive_increases = 0
        checks["monotonic"] = max_consecutive >= self.escalation_count

        # Check 3: Weighted moving average
        # For 2-turn histories use a lower threshold (0.4) to catch steep single-step
        # escalations that are below the absolute threshold but clearly trending unsafe.
        if len(scores) >= 2:
            # Recent scores weighted more heavily
            weights = [i + 1 for i in range(len(scores))]
            wma = sum(s * w for s, w in zip(scores, weights)) / sum(weights)
            wma_thresh = 0.4 if len(scores) == 2 else self.wma_threshold
            checks["wma"] = wma >= wma_thresh
        else:
            wma = sum(scores) / len(scores)
            checks["wma"] = False

        # Overall detection: any check triggers
        flagged = any(checks.values())
        triggered = [k for k, v in checks.items() if v]

        # Risk score: weighted combination
        risk = 0.0
        if checks["absolute"]:
            risk = max(risk, max_score)
        if checks["monotonic"]:
            risk = max(risk, 0.7 + 0.1 * max_consecutive)
        if checks["wma"]:
            risk = max(risk, wma)
        risk = min(risk, 1.0)

        return DetectionResult(
            detector_name=self.name,
            flagged=flagged,
            confidence=risk,
            risk_score=risk,
            reason=(
                f"Escalation detected: {', '.join(triggered)}"
                if flagged
                else "No escalation pattern detected"
            ),
            metadata={
                "checks": checks,
                "scores": scores,
                "wma": wma,
                "max_consecutive_increases": max_consecutive,
                "max_score": max_score,
            },
        )

    def add_risk_score(self, score: float) -> None:
        """Manually add a risk score to the history."""
        self.risk_history.append(score)

    def reset(self) -> None:
        """Clear the risk score history."""
        self.risk_history.clear()
