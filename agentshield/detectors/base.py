"""Base classes for detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from pydantic import BaseModel, Field


class DetectionResult(BaseModel):
    """Result from a single detector."""
    detector_name: str
    flagged: bool
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0, default=0.0)
    reason: str = ""
    metadata: dict = Field(default_factory=dict)


class DetectorBase(ABC):
    """Abstract base class for all detectors."""

    name: str = "base_detector"

    @abstractmethod
    def detect(
        self,
        user_input: Optional[str] = None,
        agent_output: Optional[str] = None,
        conversation_history: Optional[list[dict]] = None,
        tool_calls: Optional[list[dict]] = None,
    ) -> DetectionResult:
        """Run detection and return result.

        Args:
            user_input: Current user message.
            agent_output: Current agent response.
            conversation_history: Previous turns.
            tool_calls: Tool invocations in current turn.

        Returns:
            DetectionResult with flagged status and details.
        """
        ...
