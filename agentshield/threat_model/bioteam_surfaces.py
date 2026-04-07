"""BioTeam-AI attack surfaces mapped from source code analysis.

9 attack surfaces identified through code review of:
  - backend/app/agents/registry.py (agent substitution)
  - backend/app/llm/agent_tools.py (tool access control)
  - backend/app/agents/base.py (input handling)
  - backend/app/memory/semantic.py (memory poisoning)
  - backend/app/execution/docker_runner.py (sandbox)
  - backend/app/workflows/engine.py (workflow hijacking)
"""

from __future__ import annotations

from agentshield.threat_model.stride import (
    AttackSurface,
    Impact,
    Likelihood,
    STRIDECategory,
    Threat,
    ThreatModel,
)

# ── 9 Attack Surfaces ────────────────────────────────────────────────────────

ATTACK_SURFACES = [
    AttackSurface(
        surface_id="AS-001",
        name="Agent Substitution Bypass",
        description=(
            "AgentRegistry.find_substitute() allows automatic fallback to "
            "substitute agents when primary agents fail. An attacker could "
            "trigger failures to force substitution to a less-restricted agent."
        ),
        component="Agent Registry",
        source_file="backend/app/agents/registry.py",
        source_line="find_substitute() method",
        stride_categories=[STRIDECategory.SPOOFING, STRIDECategory.ELEVATION_OF_PRIVILEGE],
        entry_points=["Agent selection API", "Workflow task assignment"],
        assets_at_risk=["Agent capabilities", "Task authorization"],
    ),
    AttackSurface(
        surface_id="AS-002",
        name="Tool Access Leakage",
        description=(
            "AGENT_AGENTIC_TOOLS mapping in agent_tools.py defines which tools "
            "each agent can access, but enforcement may be incomplete. Agents "
            "not in the mapping could access tools without authorization checks."
        ),
        component="Tool Access Control",
        source_file="backend/app/llm/agent_tools.py",
        source_line="AGENT_AGENTIC_TOOLS (line 119)",
        stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE],
        entry_points=["Tool invocation API", "Agent execution loop"],
        assets_at_risk=["Docker execution", "Database access", "File system"],
    ),
    AttackSurface(
        surface_id="AS-003",
        name="Input Sanitization Gaps",
        description=(
            "Gene names, HGVS variants, and other biological identifiers are "
            "passed to external APIs (NCBI, UniProt, Ensembl) without consistent "
            "sanitization, enabling potential injection attacks."
        ),
        component="Agent Input Processing",
        source_file="backend/app/agents/base.py",
        source_line="execute() method",
        stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE],
        entry_points=["User chat input", "Workflow parameters", "Tool arguments"],
        assets_at_risk=["External API integrity", "Data accuracy", "System stability"],
    ),
    AttackSurface(
        surface_id="AS-004",
        name="Memory Poisoning via ChromaDB",
        description=(
            "Three ChromaDB collections (literature, synthesis, lab_kb) store "
            "embeddings from agent outputs. The synthesis collection mixes "
            "agent-generated and human-provided data without provenance tracking."
        ),
        component="Semantic Memory",
        source_file="backend/app/memory/semantic.py",
        source_line="ChromaDB collections",
        stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.REPUDIATION],
        entry_points=["Agent output storage", "Knowledge base updates", "Synthesis results"],
        assets_at_risk=["Memory integrity", "Future query results", "Agent decision quality"],
    ),
    AttackSurface(
        surface_id="AS-005",
        name="Docker Sandbox Escape Potential",
        description=(
            "Docker containers use --network none and --read-only flags, but "
            "tmpfs mount at /tmp and host path binding in _build_docker_cmd() "
            "could enable escape vectors through shared filesystem or resource "
            "exhaustion."
        ),
        component="Code Execution Sandbox",
        source_file="backend/app/execution/docker_runner.py",
        source_line="_build_docker_cmd()",
        stride_categories=[
            STRIDECategory.ELEVATION_OF_PRIVILEGE,
            STRIDECategory.INFORMATION_DISCLOSURE,
        ],
        entry_points=["Docker code execution", "PTC coding agent", "Bioinformatics pipeline"],
        assets_at_risk=["Host filesystem", "Host processes", "Network access"],
    ),
    AttackSurface(
        surface_id="AS-006",
        name="Auth Bypass in Dev Mode",
        description=(
            "Development mode configuration allows empty API keys, effectively "
            "disabling authentication. If dev mode is accidentally enabled in "
            "production, all API endpoints become unauthenticated."
        ),
        component="Authentication",
        source_file="backend/app/config.py",
        source_line="API key validation",
        stride_categories=[STRIDECategory.SPOOFING],
        entry_points=["API endpoints", "WebSocket connections"],
        assets_at_risk=["All system functionality", "User data", "Agent capabilities"],
    ),
    AttackSurface(
        surface_id="AS-007",
        name="Workflow Hijacking",
        description=(
            "director_notes field in workflow state is not sanitized before "
            "being passed to agents. SQLite injection possible through workflow "
            "state persistence. State machine has 17 transitions that could be "
            "manipulated."
        ),
        component="Workflow Engine",
        source_file="backend/app/workflows/engine.py",
        source_line="State transitions and director_notes",
        stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE],
        entry_points=["Workflow creation", "Director notes", "State transitions"],
        assets_at_risk=["Workflow integrity", "Agent task sequencing", "Research outputs"],
    ),
    AttackSurface(
        surface_id="AS-008",
        name="Rate Limit Evasion",
        description=(
            "Per-agent and per-tool rate limits may be circumvented by "
            "distributing requests across multiple agent identities or by "
            "exploiting the substitution mechanism to bypass per-agent limits."
        ),
        component="Rate Limiting",
        source_file="backend/app/llm/rate_limiter.py",
        source_line="Rate limiting middleware",
        stride_categories=[STRIDECategory.DENIAL_OF_SERVICE],
        entry_points=["API calls", "Agent substitution", "Parallel workflows"],
        assets_at_risk=["API budget", "System availability", "Token limits"],
    ),
    AttackSurface(
        surface_id="AS-009",
        name="Langfuse Telemetry Data Leakage",
        description=(
            "Langfuse integration traces all agent interactions including "
            "full prompts, responses, and tool outputs. Misconfigured access "
            "controls could expose sensitive research data, API keys in prompts, "
            "or proprietary agent system prompts."
        ),
        component="Observability",
        source_file="backend/app/agents/base.py",
        source_line="Langfuse tracing integration",
        stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE],
        entry_points=["Langfuse dashboard", "Telemetry API", "Log export"],
        assets_at_risk=["System prompts", "Research data", "API keys", "User conversations"],
    ),
]


def build_bioteam_threat_model() -> ThreatModel:
    """Construct the complete STRIDE threat model for BioTeam-AI."""
    threats = _build_threats()

    return ThreatModel(
        system_name="BioTeam-AI",
        version="1.0.0",
        author="Jang Kim",
        description=(
            "STRIDE-based threat model for BioTeam-AI, a 23-agent scientific "
            "research system with Docker sandbox, ChromaDB memory, and 26 "
            "integration clients. Identifies 9 attack surfaces and associated "
            "threats across all 6 STRIDE categories."
        ),
        attack_surfaces=ATTACK_SURFACES,
        threats=threats,
    )


def _build_threats() -> list[Threat]:
    """Build the threat list from identified attack surfaces."""
    threats = [
        # AS-001: Agent Substitution
        Threat(
            threat_id="T-001",
            title="Forced Agent Substitution for Privilege Escalation",
            description=(
                "Attacker triggers deliberate failures in a restricted agent "
                "to force substitution to a less-restricted agent with broader "
                "tool access or weaker safety filters."
            ),
            stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
            attack_surface="AS-001",
            likelihood=Likelihood.MEDIUM,
            impact=Impact.HIGH,
            risk_score=9,
            preconditions=[
                "Agent substitution is enabled",
                "Substitute agent has different tool permissions",
            ],
            attack_steps=[
                "Craft input that causes primary agent to fail",
                "System automatically routes to substitute agent",
                "Substitute agent processes request with elevated access",
            ],
            mitigations=[
                "Enforce same tool restrictions on substitute agents",
                "Log all substitution events for audit",
                "Require human approval for substitution to higher-privilege agents",
            ],
        ),
        # AS-002: Tool Access
        Threat(
            threat_id="T-002",
            title="Unauthorized Docker Code Execution",
            description=(
                "Agent not in AGENT_AGENTIC_TOOLS mapping gains access to "
                "run_docker_code tool due to incomplete enforcement."
            ),
            stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
            attack_surface="AS-002",
            likelihood=Likelihood.HIGH,
            impact=Impact.CRITICAL,
            risk_score=12,
            preconditions=[
                "Tool access enforcement is bypass-able",
                "Agent can invoke tools through indirect means",
            ],
            attack_steps=[
                "Identify agent with lax tool restrictions",
                "Craft prompt to invoke Docker execution tool",
                "Execute arbitrary code in container",
            ],
            mitigations=[
                "Enforce AGENT_AGENTIC_TOOLS as hard allow-list",
                "Add tool call authorization middleware",
                "Audit all tool invocations",
            ],
        ),
        # AS-003: Input Sanitization
        Threat(
            threat_id="T-003",
            title="Gene Name Injection to External APIs",
            description=(
                "Malicious gene names or HGVS strings containing injection "
                "payloads passed unsanitized to NCBI, UniProt, or Ensembl APIs."
            ),
            stride_category=STRIDECategory.TAMPERING,
            attack_surface="AS-003",
            likelihood=Likelihood.MEDIUM,
            impact=Impact.MEDIUM,
            risk_score=6,
            preconditions=[
                "Agent accepts user-provided biological identifiers",
                "Identifiers passed directly to external API queries",
            ],
            attack_steps=[
                "Provide crafted gene name with injection payload",
                "Agent passes unsanitized input to API",
                "External API returns manipulated results",
            ],
            mitigations=[
                "Validate gene names against regex patterns",
                "Sanitize all user inputs before external API calls",
                "Use parameterized queries where possible",
            ],
        ),
        # AS-004: Memory Poisoning
        Threat(
            threat_id="T-004",
            title="Synthesis Collection Memory Poisoning",
            description=(
                "Attacker stores malicious embeddings in the synthesis ChromaDB "
                "collection, which are later retrieved and influence agent "
                "responses for other users or workflows."
            ),
            stride_category=STRIDECategory.TAMPERING,
            attack_surface="AS-004",
            likelihood=Likelihood.HIGH,
            impact=Impact.HIGH,
            risk_score=12,
            preconditions=[
                "Agent stores outputs to shared memory",
                "No provenance tracking on stored embeddings",
                "Retrieval doesn't filter by trust level",
            ],
            attack_steps=[
                "Interact with agent to generate misleading outputs",
                "Outputs stored in synthesis collection",
                "Future queries retrieve poisoned memories",
                "Agents incorporate poisoned context into responses",
            ],
            mitigations=[
                "Tag all memories with source provenance",
                "Separate user-contributed and agent-generated collections",
                "Implement memory integrity verification",
            ],
        ),
        # AS-005: Docker Sandbox
        Threat(
            threat_id="T-005",
            title="Tmpfs Mount Exploitation",
            description=(
                "Exploit tmpfs mount at /tmp in Docker container to stage "
                "payloads or communicate with host through timing channels."
            ),
            stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
            attack_surface="AS-005",
            likelihood=Likelihood.LOW,
            impact=Impact.CRITICAL,
            risk_score=8,
            preconditions=[
                "Code execution access in container",
                "Tmpfs mount writable",
            ],
            attack_steps=[
                "Gain code execution through PTC coding agent",
                "Write exploit payload to /tmp",
                "Attempt container escape via kernel exploits",
            ],
            mitigations=[
                "Limit tmpfs size and inode count",
                "Use seccomp profiles to restrict syscalls",
                "Run containers with minimal capabilities",
                "Regular security updates for container runtime",
            ],
        ),
        # AS-006: Auth Bypass
        Threat(
            threat_id="T-006",
            title="Dev Mode Authentication Bypass",
            description=(
                "System deployed with dev mode enabled, allowing unauthenticated "
                "access to all API endpoints and agent capabilities."
            ),
            stride_category=STRIDECategory.SPOOFING,
            attack_surface="AS-006",
            likelihood=Likelihood.MEDIUM,
            impact=Impact.CRITICAL,
            risk_score=12,
            preconditions=[
                "Dev mode flag enabled in production config",
                "Empty API key accepted",
            ],
            attack_steps=[
                "Discover dev mode is enabled (e.g., via error messages)",
                "Send requests without API key",
                "Full access to all agent capabilities",
            ],
            mitigations=[
                "Require non-empty API key in all modes",
                "Add startup check that fails if dev mode in production",
                "Environment-based config that separates dev/prod",
            ],
        ),
        # AS-007: Workflow Hijacking
        Threat(
            threat_id="T-007",
            title="Director Notes Injection",
            description=(
                "Unsanitized director_notes field used to inject instructions "
                "that alter workflow behavior, skip safety checks, or redirect "
                "agent tasks."
            ),
            stride_category=STRIDECategory.TAMPERING,
            attack_surface="AS-007",
            likelihood=Likelihood.HIGH,
            impact=Impact.HIGH,
            risk_score=12,
            preconditions=[
                "Director notes passed to agents without sanitization",
                "Notes influence agent behavior",
            ],
            attack_steps=[
                "Inject instructions into director_notes field",
                "Workflow engine passes notes to agents",
                "Agent follows injected instructions",
            ],
            mitigations=[
                "Sanitize director_notes before agent consumption",
                "Treat notes as untrusted data",
                "Implement content safety filter on notes",
            ],
        ),
        # AS-008: Rate Limit Evasion
        Threat(
            threat_id="T-008",
            title="Rate Limit Bypass via Agent Multiplication",
            description=(
                "Attacker exploits agent substitution to distribute requests "
                "across multiple agent identities, bypassing per-agent rate limits."
            ),
            stride_category=STRIDECategory.DENIAL_OF_SERVICE,
            attack_surface="AS-008",
            likelihood=Likelihood.MEDIUM,
            impact=Impact.MEDIUM,
            risk_score=6,
            preconditions=[
                "Rate limits are per-agent, not per-user",
                "Agent substitution available",
            ],
            attack_steps=[
                "Identify per-agent rate limit implementation",
                "Trigger substitution to different agents",
                "Each agent has fresh rate limit quota",
            ],
            mitigations=[
                "Implement per-user rate limits in addition to per-agent",
                "Global token budget across all agents",
                "Monitor aggregate request patterns",
            ],
        ),
        # AS-009: Langfuse Leakage
        Threat(
            threat_id="T-009",
            title="System Prompt Extraction via Telemetry",
            description=(
                "Langfuse traces contain full system prompts, tool definitions, "
                "and agent configurations. Unauthorized access to Langfuse "
                "dashboard exposes entire agent architecture."
            ),
            stride_category=STRIDECategory.INFORMATION_DISCLOSURE,
            attack_surface="AS-009",
            likelihood=Likelihood.MEDIUM,
            impact=Impact.HIGH,
            risk_score=9,
            preconditions=[
                "Langfuse access controls misconfigured",
                "Full prompts logged in traces",
            ],
            attack_steps=[
                "Gain access to Langfuse dashboard",
                "Browse traces to find system prompts",
                "Extract agent configurations and tool definitions",
                "Use knowledge to craft targeted attacks",
            ],
            mitigations=[
                "Redact system prompts from Langfuse traces",
                "Implement strict access controls on Langfuse",
                "Separate audit logging from observability",
                "Encrypt sensitive fields in traces",
            ],
        ),
    ]

    return threats
