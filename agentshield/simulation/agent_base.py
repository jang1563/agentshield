"""Abstract base class for agent implementations.

Both MockAgent and LLMAgent implement this interface,
allowing ConversationSimulator to be agent-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentshield.simulation.mock_agent import AgentMessage


class AgentBase(ABC):
    """Abstract base for simulated and real LLM agents.

    Subclasses must set self.name in __init__ and implement process() and reset().
    """

    @abstractmethod
    def process(self, user_input: str) -> "AgentMessage":
        """Process a user message and return the agent response."""

    @abstractmethod
    def reset(self) -> None:
        """Reset agent state between independent conversations."""
