"""STRIDE threat modeling framework for agentic AI systems.

STRIDE categories:
  S - Spoofing: Identity/authority impersonation
  T - Tampering: Data/memory modification
  R - Repudiation: Covering tracks, log manipulation
  I - Information Disclosure: Data leakage, prompt extraction
  D - Denial of Service: Resource exhaustion, blocking
  E - Elevation of Privilege: Unauthorized capability access
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class STRIDECategory(str, Enum):
    """STRIDE threat categories."""
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class Likelihood(str, Enum):
    """Attack likelihood ratings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Impact(str, Enum):
    """Attack impact ratings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackSurface(BaseModel):
    """A specific attack surface in the target system."""
    surface_id: str
    name: str
    description: str
    component: str  # Which system component
    source_file: Optional[str] = None  # Source code reference
    source_line: Optional[str] = None
    stride_categories: list[STRIDECategory]
    entry_points: list[str]  # How an attacker could access this surface
    assets_at_risk: list[str]  # What could be compromised


class Threat(BaseModel):
    """A specific threat identified through STRIDE analysis."""
    threat_id: str
    title: str
    description: str
    stride_category: STRIDECategory
    attack_surface: str  # Reference to AttackSurface.surface_id
    likelihood: Likelihood
    impact: Impact
    risk_score: int = Field(ge=1, le=16)  # likelihood x impact (1-16 grid)
    preconditions: list[str]
    attack_steps: list[str]
    mitigations: list[str]


class ThreatModel(BaseModel):
    """Complete STRIDE threat model for a system."""
    system_name: str
    version: str
    author: str
    description: str
    attack_surfaces: list[AttackSurface]
    threats: list[Threat]

    def threats_by_category(self, category: STRIDECategory) -> list[Threat]:
        return [t for t in self.threats if t.stride_category == category]

    def threats_by_surface(self, surface_id: str) -> list[Threat]:
        return [t for t in self.threats if t.attack_surface == surface_id]

    def high_risk_threats(self, min_score: int = 9) -> list[Threat]:
        return [t for t in self.threats if t.risk_score >= min_score]
