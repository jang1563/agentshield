#!/usr/bin/env python3
"""Generate STRIDE threat model document for BioTeam-AI."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agentshield.threat_model.bioteam_surfaces import build_bioteam_threat_model
from agentshield.threat_model.risk_matrix import generate_risk_summary
from agentshield.config import DOCS_DIR, RESULTS_DIR

logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(level=logging.INFO)

    # Build threat model
    model = build_bioteam_threat_model()
    summary = generate_risk_summary(model)

    # Save JSON
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_DIR / "threat_model.json", "w") as f:
        f.write(model.model_dump_json(indent=2))

    with open(RESULTS_DIR / "risk_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    # Generate markdown
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    md = _generate_markdown(model, summary)
    with open(DOCS_DIR / "threat_model.md", "w") as f:
        f.write(md)

    logger.info("Threat model generated: %d surfaces, %d threats",
                len(model.attack_surfaces), len(model.threats))
    logger.info("High-risk threats: %d", len(summary["high_risk_threats"]))


def _generate_markdown(model, summary) -> str:
    lines = [
        f"# STRIDE Threat Model: {model.system_name}",
        f"\n**Version**: {model.version}  ",
        f"**Author**: {model.author}  ",
        f"\n{model.description}",
        f"\n## Risk Summary",
        f"\n| Risk Level | Count |",
        f"|------------|-------|",
    ]
    for level, count in summary["risk_distribution"].items():
        lines.append(f"| {level} | {count} |")

    lines.append(f"\n## Attack Surfaces ({len(model.attack_surfaces)})\n")
    for surface in model.attack_surfaces:
        lines.append(f"### {surface.surface_id}: {surface.name}")
        lines.append(f"\n{surface.description}\n")
        lines.append(f"- **Component**: {surface.component}")
        if surface.source_file:
            lines.append(f"- **Source**: `{surface.source_file}` ({surface.source_line})")
        lines.append(f"- **STRIDE**: {', '.join(c.value for c in surface.stride_categories)}")
        lines.append(f"- **Entry Points**: {', '.join(surface.entry_points)}")
        lines.append(f"- **Assets at Risk**: {', '.join(surface.assets_at_risk)}")
        lines.append("")

    lines.append(f"\n## Threats ({len(model.threats)})\n")
    for threat in sorted(model.threats, key=lambda t: -t.risk_score):
        lines.append(f"### {threat.threat_id}: {threat.title}")
        lines.append(f"\n{threat.description}\n")
        lines.append(f"- **STRIDE**: {threat.stride_category.value}")
        lines.append(f"- **Attack Surface**: {threat.attack_surface}")
        lines.append(f"- **Likelihood**: {threat.likelihood.value}")
        lines.append(f"- **Impact**: {threat.impact.value}")
        lines.append(f"- **Risk Score**: {threat.risk_score}")
        lines.append(f"\n**Attack Steps**:")
        for step in threat.attack_steps:
            lines.append(f"1. {step}")
        lines.append(f"\n**Mitigations**:")
        for m in threat.mitigations:
            lines.append(f"- {m}")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    main()
