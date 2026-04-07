# STRIDE Threat Model: BioTeam-AI

**Version**: 1.0.0  
**Author**: Jang Kim  

STRIDE-based threat model for BioTeam-AI, a 23-agent scientific research system with Docker sandbox, ChromaDB memory, and 26 integration clients. Identifies 9 attack surfaces and associated threats across all 6 STRIDE categories.

## Risk Summary

| Risk Level | Count |
|------------|-------|
| Low | 0 |
| Medium | 2 |
| High | 3 |
| Critical | 4 |

## Attack Surfaces (9)

### AS-001: Agent Substitution Bypass

AgentRegistry.find_substitute() allows automatic fallback to substitute agents when primary agents fail. An attacker could trigger failures to force substitution to a less-restricted agent.

- **Component**: Agent Registry
- **Source**: `backend/app/agents/registry.py` (find_substitute() method)
- **STRIDE**: spoofing, elevation_of_privilege
- **Entry Points**: Agent selection API, Workflow task assignment
- **Assets at Risk**: Agent capabilities, Task authorization

### AS-002: Tool Access Leakage

AGENT_AGENTIC_TOOLS mapping in agent_tools.py defines which tools each agent can access, but enforcement may be incomplete. Agents not in the mapping could access tools without authorization checks.

- **Component**: Tool Access Control
- **Source**: `backend/app/llm/agent_tools.py` (AGENT_AGENTIC_TOOLS (line 119))
- **STRIDE**: elevation_of_privilege
- **Entry Points**: Tool invocation API, Agent execution loop
- **Assets at Risk**: Docker execution, Database access, File system

### AS-003: Input Sanitization Gaps

Gene names, HGVS variants, and other biological identifiers are passed to external APIs (NCBI, UniProt, Ensembl) without consistent sanitization, enabling potential injection attacks.

- **Component**: Agent Input Processing
- **Source**: `backend/app/agents/base.py` (execute() method)
- **STRIDE**: tampering, information_disclosure
- **Entry Points**: User chat input, Workflow parameters, Tool arguments
- **Assets at Risk**: External API integrity, Data accuracy, System stability

### AS-004: Memory Poisoning via ChromaDB

Three ChromaDB collections (literature, synthesis, lab_kb) store embeddings from agent outputs. The synthesis collection mixes agent-generated and human-provided data without provenance tracking.

- **Component**: Semantic Memory
- **Source**: `backend/app/memory/semantic.py` (ChromaDB collections)
- **STRIDE**: tampering, repudiation
- **Entry Points**: Agent output storage, Knowledge base updates, Synthesis results
- **Assets at Risk**: Memory integrity, Future query results, Agent decision quality

### AS-005: Docker Sandbox Escape Potential

Docker containers use --network none and --read-only flags, but tmpfs mount at /tmp and host path binding in _build_docker_cmd() could enable escape vectors through shared filesystem or resource exhaustion.

- **Component**: Code Execution Sandbox
- **Source**: `backend/app/execution/docker_runner.py` (_build_docker_cmd())
- **STRIDE**: elevation_of_privilege, information_disclosure
- **Entry Points**: Docker code execution, PTC coding agent, Bioinformatics pipeline
- **Assets at Risk**: Host filesystem, Host processes, Network access

### AS-006: Auth Bypass in Dev Mode

Development mode configuration allows empty API keys, effectively disabling authentication. If dev mode is accidentally enabled in production, all API endpoints become unauthenticated.

- **Component**: Authentication
- **Source**: `backend/app/config.py` (API key validation)
- **STRIDE**: spoofing
- **Entry Points**: API endpoints, WebSocket connections
- **Assets at Risk**: All system functionality, User data, Agent capabilities

### AS-007: Workflow Hijacking

director_notes field in workflow state is not sanitized before being passed to agents. SQLite injection possible through workflow state persistence. State machine has 17 transitions that could be manipulated.

- **Component**: Workflow Engine
- **Source**: `backend/app/workflows/engine.py` (State transitions and director_notes)
- **STRIDE**: tampering, elevation_of_privilege
- **Entry Points**: Workflow creation, Director notes, State transitions
- **Assets at Risk**: Workflow integrity, Agent task sequencing, Research outputs

### AS-008: Rate Limit Evasion

Per-agent and per-tool rate limits may be circumvented by distributing requests across multiple agent identities or by exploiting the substitution mechanism to bypass per-agent limits.

- **Component**: Rate Limiting
- **Source**: `backend/app/llm/rate_limiter.py` (Rate limiting middleware)
- **STRIDE**: denial_of_service
- **Entry Points**: API calls, Agent substitution, Parallel workflows
- **Assets at Risk**: API budget, System availability, Token limits

### AS-009: Langfuse Telemetry Data Leakage

Langfuse integration traces all agent interactions including full prompts, responses, and tool outputs. Misconfigured access controls could expose sensitive research data, API keys in prompts, or proprietary agent system prompts.

- **Component**: Observability
- **Source**: `backend/app/agents/base.py` (Langfuse tracing integration)
- **STRIDE**: information_disclosure
- **Entry Points**: Langfuse dashboard, Telemetry API, Log export
- **Assets at Risk**: System prompts, Research data, API keys, User conversations


## Threats (9)

### T-002: Unauthorized Docker Code Execution

Agent not in AGENT_AGENTIC_TOOLS mapping gains access to run_docker_code tool due to incomplete enforcement.

- **STRIDE**: elevation_of_privilege
- **Attack Surface**: AS-002
- **Likelihood**: high
- **Impact**: critical
- **Risk Score**: 12

**Attack Steps**:
1. Identify agent with lax tool restrictions
1. Craft prompt to invoke Docker execution tool
1. Execute arbitrary code in container

**Mitigations**:
- Enforce AGENT_AGENTIC_TOOLS as hard allow-list
- Add tool call authorization middleware
- Audit all tool invocations

### T-004: Synthesis Collection Memory Poisoning

Attacker stores malicious embeddings in the synthesis ChromaDB collection, which are later retrieved and influence agent responses for other users or workflows.

- **STRIDE**: tampering
- **Attack Surface**: AS-004
- **Likelihood**: high
- **Impact**: high
- **Risk Score**: 12

**Attack Steps**:
1. Interact with agent to generate misleading outputs
1. Outputs stored in synthesis collection
1. Future queries retrieve poisoned memories
1. Agents incorporate poisoned context into responses

**Mitigations**:
- Tag all memories with source provenance
- Separate user-contributed and agent-generated collections
- Implement memory integrity verification

### T-006: Dev Mode Authentication Bypass

System deployed with dev mode enabled, allowing unauthenticated access to all API endpoints and agent capabilities.

- **STRIDE**: spoofing
- **Attack Surface**: AS-006
- **Likelihood**: medium
- **Impact**: critical
- **Risk Score**: 12

**Attack Steps**:
1. Discover dev mode is enabled (e.g., via error messages)
1. Send requests without API key
1. Full access to all agent capabilities

**Mitigations**:
- Require non-empty API key in all modes
- Add startup check that fails if dev mode in production
- Environment-based config that separates dev/prod

### T-007: Director Notes Injection

Unsanitized director_notes field used to inject instructions that alter workflow behavior, skip safety checks, or redirect agent tasks.

- **STRIDE**: tampering
- **Attack Surface**: AS-007
- **Likelihood**: high
- **Impact**: high
- **Risk Score**: 12

**Attack Steps**:
1. Inject instructions into director_notes field
1. Workflow engine passes notes to agents
1. Agent follows injected instructions

**Mitigations**:
- Sanitize director_notes before agent consumption
- Treat notes as untrusted data
- Implement content safety filter on notes

### T-001: Forced Agent Substitution for Privilege Escalation

Attacker triggers deliberate failures in a restricted agent to force substitution to a less-restricted agent with broader tool access or weaker safety filters.

- **STRIDE**: elevation_of_privilege
- **Attack Surface**: AS-001
- **Likelihood**: medium
- **Impact**: high
- **Risk Score**: 9

**Attack Steps**:
1. Craft input that causes primary agent to fail
1. System automatically routes to substitute agent
1. Substitute agent processes request with elevated access

**Mitigations**:
- Enforce same tool restrictions on substitute agents
- Log all substitution events for audit
- Require human approval for substitution to higher-privilege agents

### T-009: System Prompt Extraction via Telemetry

Langfuse traces contain full system prompts, tool definitions, and agent configurations. Unauthorized access to Langfuse dashboard exposes entire agent architecture.

- **STRIDE**: information_disclosure
- **Attack Surface**: AS-009
- **Likelihood**: medium
- **Impact**: high
- **Risk Score**: 9

**Attack Steps**:
1. Gain access to Langfuse dashboard
1. Browse traces to find system prompts
1. Extract agent configurations and tool definitions
1. Use knowledge to craft targeted attacks

**Mitigations**:
- Redact system prompts from Langfuse traces
- Implement strict access controls on Langfuse
- Separate audit logging from observability
- Encrypt sensitive fields in traces

### T-005: Tmpfs Mount Exploitation

Exploit tmpfs mount at /tmp in Docker container to stage payloads or communicate with host through timing channels.

- **STRIDE**: elevation_of_privilege
- **Attack Surface**: AS-005
- **Likelihood**: low
- **Impact**: critical
- **Risk Score**: 8

**Attack Steps**:
1. Gain code execution through PTC coding agent
1. Write exploit payload to /tmp
1. Attempt container escape via kernel exploits

**Mitigations**:
- Limit tmpfs size and inode count
- Use seccomp profiles to restrict syscalls
- Run containers with minimal capabilities
- Regular security updates for container runtime

### T-003: Gene Name Injection to External APIs

Malicious gene names or HGVS strings containing injection payloads passed unsanitized to NCBI, UniProt, or Ensembl APIs.

- **STRIDE**: tampering
- **Attack Surface**: AS-003
- **Likelihood**: medium
- **Impact**: medium
- **Risk Score**: 6

**Attack Steps**:
1. Provide crafted gene name with injection payload
1. Agent passes unsanitized input to API
1. External API returns manipulated results

**Mitigations**:
- Validate gene names against regex patterns
- Sanitize all user inputs before external API calls
- Use parameterized queries where possible

### T-008: Rate Limit Bypass via Agent Multiplication

Attacker exploits agent substitution to distribute requests across multiple agent identities, bypassing per-agent rate limits.

- **STRIDE**: denial_of_service
- **Attack Surface**: AS-008
- **Likelihood**: medium
- **Impact**: medium
- **Risk Score**: 6

**Attack Steps**:
1. Identify per-agent rate limit implementation
1. Trigger substitution to different agents
1. Each agent has fresh rate limit quota

**Mitigations**:
- Implement per-user rate limits in addition to per-agent
- Global token budget across all agents
- Monitor aggregate request patterns
