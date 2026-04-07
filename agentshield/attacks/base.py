"""Base models for attack scenarios and results."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class AttackCategory(str, Enum):
    """Categories of attacks."""
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    MULTI_TURN_ESCALATION = "multi_turn_escalation"
    TOOL_MISUSE = "tool_misuse"


class AttackScenario(BaseModel):
    """Definition of a single attack scenario."""
    scenario_id: str
    name: str
    category: AttackCategory
    description: str
    target_surface: str  # Attack surface ID (e.g., "AS-001")
    messages: list[str]  # User messages for the attack
    expected_behavior: str  # What the attack tries to achieve
    success_criteria: str  # How to determine if attack succeeded
    nsabb_category: Optional[str] = None  # For escalation attacks
    metadata: dict = Field(default_factory=dict)


class AttackResult(BaseModel):
    """Result of executing a single attack scenario."""
    scenario_id: str
    scenario_name: str
    category: str
    success: bool  # Did the attack achieve its goal?
    detected: bool  # Was the attack detected by the pipeline?
    blocked: bool  # Was the attack blocked before completion?
    turns_completed: int
    blocked_at_turn: Optional[int] = None
    risk_scores: list[float] = Field(default_factory=list)
    notes: str = ""
