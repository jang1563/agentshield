"""Tool auditor: validates tool calls against authorization policies.

Enforces AGENT_AGENTIC_TOOLS as a hard allow-list and detects:
  1. Unauthorized tool access
  2. Argument pattern violations (injection detection)
  3. Shell injection markers
  4. Call frequency anomalies
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Optional
import time

from agentshield.config import (
    AGENT_AGENTIC_TOOLS,
    SHARED_READONLY_TOOLS,
    TOOL_CALL_RATE_LIMIT,
)
from agentshield.detectors.base import DetectionResult, DetectorBase

logger = logging.getLogger(__name__)

# ── Argument Validation Patterns ─────────────────────────────────────────────

GENE_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9]{1,10}$")
HGVS_PATTERN = re.compile(r"^NM_\d+\.\d+:c\.\d+[A-Z]>[A-Z]$")
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_\-\.]{1,100}$")

SHELL_INJECTION_PATTERNS = [
    r";\s*\w+",           # Command chaining
    r"\$\(",              # Command substitution
    r"`[^`]+`",           # Backtick execution
    r"\|\s*\w+",          # Pipe to command
    r"&&\s*\w+",          # AND chaining
    r"\|\|\s*\w+",        # OR chaining
    r">\s*/",             # Redirect to root paths
    r"rm\s+-",            # rm commands
    r"__import__",        # Python import injection
    r"os\.(system|popen)", # Python os execution
    r"subprocess",        # Python subprocess
    r"eval\(",            # eval execution
    r"exec\(",            # exec execution
]


class ToolAuditor(DetectorBase):
    """Audit tool calls for authorization and injection attacks."""

    name = "tool_auditor"

    def __init__(
        self,
        rate_limit: int = TOOL_CALL_RATE_LIMIT,
    ):
        self.rate_limit = rate_limit
        self._call_timestamps: dict[str, list[float]] = defaultdict(list)

    def detect(
        self,
        user_input: Optional[str] = None,
        agent_output: Optional[str] = None,
        conversation_history: Optional[list[dict]] = None,
        tool_calls: Optional[list[dict]] = None,
    ) -> DetectionResult:
        """Audit tool calls in the current turn."""
        if not tool_calls:
            return DetectionResult(
                detector_name=self.name,
                flagged=False,
                confidence=1.0,
                reason="No tool calls to audit",
            )

        violations = []
        risk_score = 0.0

        for call in tool_calls:
            tool_name = call.get("tool_name", "")
            agent_name = call.get("agent_name", "unknown")
            arguments = call.get("arguments", {})

            # Check 1: Authorization
            if not self._is_authorized(agent_name, tool_name):
                violations.append(
                    f"Unauthorized: {agent_name} called {tool_name}"
                )
                risk_score = max(risk_score, 0.9)

            # Check 2: Argument injection
            for arg_name, arg_value in arguments.items():
                if isinstance(arg_value, str):
                    injection = self._check_injection(arg_value)
                    if injection:
                        violations.append(
                            f"Injection in {tool_name}.{arg_name}: {injection}"
                        )
                        risk_score = max(risk_score, 0.8)

            # Check 3: Rate limiting
            if self._check_rate_limit(agent_name, tool_name):
                violations.append(
                    f"Rate limit exceeded: {agent_name}/{tool_name}"
                )
                risk_score = max(risk_score, 0.6)

        flagged = len(violations) > 0

        return DetectionResult(
            detector_name=self.name,
            flagged=flagged,
            confidence=risk_score if flagged else 1.0 - risk_score,
            risk_score=risk_score,
            reason="; ".join(violations) if violations else "All tool calls authorized",
            metadata={"violations": violations, "n_calls": len(tool_calls)},
        )

    def _is_authorized(self, agent_name: str, tool_name: str) -> bool:
        """Check if an agent is authorized to use a tool."""
        if tool_name in SHARED_READONLY_TOOLS:
            return True

        all_restricted_tools = set()
        for tools in AGENT_AGENTIC_TOOLS.values():
            all_restricted_tools.update(tools)

        if (
            tool_name not in all_restricted_tools
            and not tool_name.startswith(("manage_", "approve_", "assign_", "write_"))
            and "admin" not in tool_name
        ):
            logger.warning(
                "Unknown tool '%s' denied by default for agent '%s'",
                tool_name,
                agent_name,
            )
            return False

        # Check if agent has explicit access
        allowed = AGENT_AGENTIC_TOOLS.get(agent_name, [])
        return tool_name in allowed

    def _check_injection(self, value: str) -> Optional[str]:
        """Check a tool argument for injection patterns."""
        for pattern in SHELL_INJECTION_PATTERNS:
            match = re.search(pattern, value)
            if match:
                return f"Pattern '{pattern}' matched: '{match.group()[:50]}'"
        return None

    def _check_rate_limit(self, agent_name: str, tool_name: str) -> bool:
        """Check if tool call rate exceeds limit."""
        key = f"{agent_name}/{tool_name}"
        now = time.time()
        window_start = now - 60.0  # 1-minute window

        # Clean old timestamps
        self._call_timestamps[key] = [
            t for t in self._call_timestamps[key] if t > window_start
        ]

        # Record this call
        self._call_timestamps[key].append(now)

        return len(self._call_timestamps[key]) > self.rate_limit

    def reset(self) -> None:
        """Clear accumulated rate-limit state between independent runs."""
        self._call_timestamps.clear()
