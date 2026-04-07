"""Multi-turn conversation simulator with detector integration.

Orchestrates multi-turn interactions between an attacker and a mock agent,
optionally passing each turn through the detection pipeline.
"""

from __future__ import annotations

import logging
from typing import Optional

from pydantic import BaseModel, Field

from agentshield.simulation.mock_agent import AgentMessage, AgentMode, MockAgent

logger = logging.getLogger(__name__)


class ConversationTurn(BaseModel):
    """A single turn in a multi-turn conversation."""
    turn_number: int
    user_message: str
    agent_response: str
    agent_name: str = "mock_agent"
    detection_result: Optional[dict] = None
    risk_score: float = 0.0
    blocked: bool = False


class ConversationResult(BaseModel):
    """Complete result of a multi-turn conversation."""
    scenario_id: str = ""
    turns: list[ConversationTurn] = Field(default_factory=list)
    total_turns: int = 0
    blocked_at_turn: Optional[int] = None
    final_risk_score: float = 0.0
    escalation_detected: bool = False
    metadata: dict = Field(default_factory=dict)

    @property
    def was_blocked(self) -> bool:
        """Whether the conversation was blocked at any point."""
        return self.blocked_at_turn is not None

    @property
    def risk_scores(self) -> list[float]:
        """List of risk scores for each turn."""
        return [t.risk_score for t in self.turns]


class ConversationSimulator:
    """Orchestrates multi-turn conversations for attack testing.

    Supports:
      - Sequential message delivery
      - Optional detection pipeline integration
      - Automatic blocking when detector triggers
      - Risk score tracking across turns
    """

    def __init__(
        self,
        agent: Optional[MockAgent] = None,
        detection_pipeline=None,
        max_turns: int = 10,
    ):
        self.agent = agent or MockAgent(mode=AgentMode.SCRIPTED)
        self.detection_pipeline = detection_pipeline
        self.max_turns = max_turns

    def run_single_turn(self, message: str) -> ConversationResult:
        """Run a single-turn conversation (convenience method).

        Args:
            message: Single user message.

        Returns:
            ConversationResult with one turn.
        """
        return self.run_conversation(messages=[message], scenario_id="single_turn")

    def run_conversation(
        self,
        messages: list[str],
        scenario_id: str = "unnamed",
    ) -> ConversationResult:
        """Run a multi-turn conversation.

        Args:
            messages: List of user messages to send sequentially.
            scenario_id: Identifier for this conversation.

        Returns:
            ConversationResult with all turns and detection results.
        """
        self.agent.reset()
        if self.detection_pipeline is not None:
            self.detection_pipeline.reset()
        turns = []
        blocked_at = None

        for i, user_msg in enumerate(messages[: self.max_turns]):
            # Agent processes message
            agent_response = self.agent.process(user_msg)

            turn = ConversationTurn(
                turn_number=i + 1,
                user_message=user_msg,
                agent_response=agent_response.content,
                agent_name=self.agent.name,
            )

            # Run detection if pipeline available
            if self.detection_pipeline is not None:
                try:
                    detection = self.detection_pipeline.analyze(
                        user_input=user_msg,
                        agent_output=agent_response.content,
                        conversation_history=[
                            t.model_dump() for t in turns
                        ],
                        tool_calls=agent_response.tool_calls or None,
                    )
                    turn.detection_result = detection
                    turn.risk_score = detection.get("risk_score", 0.0)
                    turn.blocked = detection.get("blocked", False)
                except Exception as e:
                    logger.warning("Detection failed at turn %d: %s", i + 1, e)

            turns.append(turn)

            # Stop if blocked
            if turn.blocked:
                blocked_at = i + 1
                logger.info(
                    "Conversation %s blocked at turn %d",
                    scenario_id,
                    blocked_at,
                )
                break

        # Compute final metrics
        risk_scores = [t.risk_score for t in turns]
        final_risk = risk_scores[-1] if risk_scores else 0.0

        # Escalation detection is handled by TrajectoryMonitor in the
        # detection pipeline; check if any turn's detector results flagged it.
        escalation = any(
            t.detection_result
            and any(
                d.get("detector_name") == "trajectory_monitor" and d.get("flagged")
                for d in t.detection_result.get("detector_results", [])
            )
            for t in turns
            if t.detection_result
        )

        return ConversationResult(
            scenario_id=scenario_id,
            turns=turns,
            total_turns=len(turns),
            blocked_at_turn=blocked_at,
            final_risk_score=final_risk,
            escalation_detected=escalation,
        )
