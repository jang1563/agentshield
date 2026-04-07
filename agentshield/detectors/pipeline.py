"""Detection pipeline: chains all 4 detectors in sequence.

Pipeline order:
  1. Input classifier (prompt injection detection)
  2. Tool auditor (authorization + injection in tool args)
  3. Output classifier (safety filter on agent response)
  4. Trajectory monitor (multi-turn escalation detection)

Blocking logic: Any detector flagging triggers a block by default.
Risk scores are aggregated across detectors.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from agentshield.detectors.base import DetectionResult, DetectorBase
from agentshield.detectors.input_classifier import InputClassifier
from agentshield.detectors.output_classifier import OutputClassifier
from agentshield.detectors.tool_auditor import ToolAuditor
from agentshield.detectors.trajectory_monitor import TrajectoryMonitor

logger = logging.getLogger(__name__)


class DetectionPipeline:
    """Chains all 4 detectors for comprehensive safety analysis.

    Each turn is analyzed by all applicable detectors. The pipeline
    aggregates results and makes a block/allow decision.
    """

    def __init__(
        self,
        input_classifier: Optional[InputClassifier] = None,
        output_classifier: Optional[OutputClassifier] = None,
        tool_auditor: Optional[ToolAuditor] = None,
        trajectory_monitor: Optional[TrajectoryMonitor] = None,
        block_on_any: bool = True,
    ):
        self.input_classifier = input_classifier or InputClassifier()
        self.output_classifier = output_classifier or OutputClassifier(mode="local")
        self.tool_auditor = tool_auditor or ToolAuditor()
        self.trajectory_monitor = trajectory_monitor or TrajectoryMonitor()
        self.block_on_any = block_on_any

    def analyze(
        self,
        user_input: Optional[str] = None,
        agent_output: Optional[str] = None,
        conversation_history: Optional[list[dict]] = None,
        tool_calls: Optional[list[dict]] = None,
    ) -> dict:
        """Run full detection pipeline on a conversation turn.

        Returns:
            Dict with 'blocked', 'risk_score', 'detector_results', and 'latency_ms'.
        """
        start = time.time()
        results: list[DetectionResult] = []

        # 1. Input classifier
        if user_input:
            input_result = self.input_classifier.detect(
                user_input=user_input,
            )
            results.append(input_result)

        # 2. Tool auditor
        if tool_calls:
            tool_result = self.tool_auditor.detect(
                tool_calls=tool_calls,
            )
            results.append(tool_result)

        # 3. Output classifier
        if agent_output:
            output_result = self.output_classifier.detect(
                user_input=user_input,
                agent_output=agent_output,
            )
            results.append(output_result)

            # Feed risk score to trajectory monitor
            self.trajectory_monitor.add_risk_score(output_result.risk_score)

        # 4. Trajectory monitor (scores added via add_risk_score above;
        #    don't pass conversation_history to avoid double-counting)
        if len(self.trajectory_monitor.risk_history) >= 2:
            trajectory_result = self.trajectory_monitor.detect()
            results.append(trajectory_result)

        # Aggregate
        any_flagged = any(r.flagged for r in results)
        max_risk = max((r.risk_score for r in results), default=0.0)
        blocked = any_flagged if self.block_on_any else max_risk >= 0.7

        latency_ms = (time.time() - start) * 1000

        return {
            "blocked": blocked,
            "risk_score": max_risk,
            "detector_results": [r.model_dump() for r in results],
            "n_detectors_triggered": sum(1 for r in results if r.flagged),
            "latency_ms": latency_ms,
        }

    def reset(self) -> None:
        """Reset stateful detectors (trajectory monitor)."""
        self.trajectory_monitor.reset()
