"""Risk matrix scoring: Likelihood x Impact grid.

4x4 matrix producing risk scores 1-16:
  Critical x Critical = 16
  Low x Low = 1
"""

from __future__ import annotations

from agentshield.threat_model.stride import Impact, Likelihood, ThreatModel


LIKELIHOOD_SCORES = {
    Likelihood.LOW: 1,
    Likelihood.MEDIUM: 2,
    Likelihood.HIGH: 3,
    Likelihood.CRITICAL: 4,
}

IMPACT_SCORES = {
    Impact.LOW: 1,
    Impact.MEDIUM: 2,
    Impact.HIGH: 3,
    Impact.CRITICAL: 4,
}

RISK_LEVELS = {
    range(1, 4): "Low",
    range(4, 7): "Medium",
    range(7, 10): "High",
    range(10, 17): "Critical",
}


def compute_risk_score(likelihood: Likelihood, impact: Impact) -> int:
    """Compute risk score from likelihood and impact."""
    return LIKELIHOOD_SCORES[likelihood] * IMPACT_SCORES[impact]


def get_risk_level(score: int) -> str:
    """Map numeric risk score to risk level string."""
    for score_range, level in RISK_LEVELS.items():
        if score in score_range:
            return level
    return "Unknown"


def generate_risk_summary(threat_model: ThreatModel) -> dict:
    """Generate a risk summary from the threat model."""
    threats = threat_model.threats
    surfaces = threat_model.attack_surfaces

    summary = {
        "system": threat_model.system_name,
        "total_surfaces": len(surfaces),
        "total_threats": len(threats),
        "risk_distribution": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
        "by_stride_category": {},
        "high_risk_threats": [],
    }

    for threat in threats:
        level = get_risk_level(threat.risk_score)
        summary["risk_distribution"][level] += 1

        cat = threat.stride_category.value
        if cat not in summary["by_stride_category"]:
            summary["by_stride_category"][cat] = 0
        summary["by_stride_category"][cat] += 1

        if threat.risk_score >= 9:
            summary["high_risk_threats"].append({
                "id": threat.threat_id,
                "title": threat.title,
                "score": threat.risk_score,
                "level": level,
            })

    return summary
